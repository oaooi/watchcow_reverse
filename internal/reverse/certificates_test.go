package reverse

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func publicTestCertificate(t *testing.T, path string, names []string, from, to time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: from, NotAfter: to, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func certificateNative(t *testing.T) (*Native, string, string, string) {
	t.Helper()
	n := native(t)
	dir := filepath.Dir(n.Main)
	c := &CertificateFiles{Gateway: filepath.Join(dir, "vendor-gateway.json"), Store: filepath.Join(dir, "vendor-certificates.json")}
	n.Certificates = c
	write(t, n.Main, bytes.ReplaceAll([]byte(fixture), []byte("/usr/trim/etc/network_gateway_cert.conf"), []byte(c.Gateway)))
	base, wildcard, key := filepath.Join(dir, "base.crt"), filepath.Join(dir, "wildcard.crt"), filepath.Join(dir, "private.key")
	// Deliberately not a PEM key: selection may stat the file but must never
	// read/parse/copy its contents. Real loading belongs to the native module.
	write(t, key, []byte("private key must stay here"))
	now := time.Now()
	publicTestCertificate(t, base, []string{"nas.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	publicTestCertificate(t, wildcard, []string{"*.nas.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	data, _ := json.Marshal([]map[string]interface{}{
		{"host": "fallback", "cert": base, "key": key, "vendor_extra": "preserved"},
		{"host": "nas.example.com", "cert": base, "key": key},
	})
	write(t, c.Gateway, data)
	data, _ = json.Marshal([]storedCertificate{{Certificate: base, PrivateKey: key}, {Fullchain: wildcard, PrivateKey: key}})
	write(t, c.Store, data)
	return n, base, wildcard, key
}

func TestCertificateSNISelectionAndRenewal(t *testing.T) {
	n, _, wildcard, key := certificateNative(t)
	originalMain := read(t, n.Main)
	gateway, inventory, private := read(t, n.Certificates.Gateway), read(t, n.Certificates.Store), read(t, key)
	calls := 0
	n.Run = func(context.Context, string, ...string) error { calls++; return nil }
	routes := []Route{testRoute(), {Host: "ddns-go.nas.example.com", Upstream: "http://127.0.0.1:9876", Active: true}}
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(filepath.Dir(n.Main), "watchcow-r-certificates.json")
	var entries []certificateEntry
	if err := json.Unmarshal(read(t, ownedPath), &entries); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"embyserver.nas.example.com", "ddns-go.nas.example.com"} {
		found := false
		for _, entry := range entries {
			if entry.Host == host {
				found = entry.Cert == wildcard && entry.Key == key
			}
		}
		if !found {
			t.Fatalf("missing wildcard binding for %s: %+v", host, entries)
		}
	}
	if !bytes.Contains(read(t, ownedPath), []byte(`"vendor_extra": "preserved"`)) {
		t.Fatal("vendor metadata lost")
	}
	if !bytes.Contains(read(t, n.Main), []byte("trim_cert_cfg_path "+ownedPath+";")) {
		t.Fatal("native module did not select merged mapping")
	}
	if bytes.Contains(read(t, ownedPath), private) {
		t.Fatal("copied private key contents")
	}
	if !bytes.Equal(read(t, n.Certificates.Gateway), gateway) || !bytes.Equal(read(t, n.Certificates.Store), inventory) || !bytes.Equal(read(t, key), private) {
		t.Fatal("vendor certificate data changed")
	}
	beforeCalls := calls
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	if calls != beforeCalls {
		t.Fatal("unchanged certificate mapping reloaded nginx")
	}
	// A renewal can replace the public certificate in place, retaining both
	// paths. The route revision must still force a native reload.
	routePath := filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf")
	oldRoute := read(t, routePath)
	publicTestCertificate(t, wildcard, []string{"*.nas.example.com"}, time.Now().Add(-time.Minute), time.Now().Add(48*time.Hour))
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	if calls != beforeCalls+2 || bytes.Equal(oldRoute, read(t, routePath)) {
		t.Fatal("in-place renewal was not activated")
	}
	// fnOS usually renews into a versioned directory; follow new paths too.
	newPath := filepath.Join(filepath.Dir(wildcard), "renewed", "wildcard.crt")
	publicTestCertificate(t, newPath, []string{"*.nas.example.com"}, time.Now().Add(-time.Minute), time.Now().Add(72*time.Hour))
	data, _ := json.Marshal([]storedCertificate{{Fullchain: newPath, PrivateKey: key}})
	write(t, n.Certificates.Store, data)
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(read(t, ownedPath), []byte(newPath)) || bytes.Contains(read(t, ownedPath), []byte(wildcard)) {
		t.Fatal("versioned renewal paths not updated")
	}
	// Keep unrelated main-config edits on uninstall, restore only our directive.
	write(t, n.Main, append(read(t, n.Main), []byte("# administrator change\n")...))
	if err := n.Apply(nil, true, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(t, n.Main), append(originalMain, []byte("# administrator change\n")...)) {
		t.Fatal("uninstall did not preserve administrator changes")
	}
	for _, path := range []string{ownedPath, filepath.Join(n.Dir, "certificates.owned.json"), routePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("owned file survived uninstall", path, err)
		}
	}
	if err := n.Apply(nil, true, true); err != nil {
		t.Fatal("repeated removal", err)
	}
}

func TestCertificateCoverageUsesActualSANs(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"*.nas.example.com"}}
	for _, test := range []struct {
		host  string
		valid bool
	}{{"emby.nas.example.com", true}, {"nas.example.com", false}, {"a.b.nas.example.com", false}, {"evil.example.com", false}} {
		if (certificateRank(cert, test.host) >= 0) != test.valid {
			t.Fatal("wrong wildcard coverage", test)
		}
	}
	n, base, _, key := certificateNative(t)
	// Metadata is not proof of coverage: deliberately claim a wildcard while
	// referencing a leaf certificate that only covers the base hostname.
	data, _ := json.Marshal([]map[string]interface{}{{"fullchain": base, "privateKey": key, "san": []string{"*.nas.example.com"}}})
	write(t, n.Certificates.Store, data)
	if err := n.Apply([]Route{testRoute()}, false, false); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(read(t, n.Main), []byte("watchcow-r-certificates.json")) {
		t.Fatal("accepted forged SAN metadata")
	}
}

func TestCertificatePrefersExactAndRejectsExpired(t *testing.T) {
	n, _, wildcard, key := certificateNative(t)
	exact := filepath.Join(filepath.Dir(n.Main), "exact.crt")
	now := time.Now()
	publicTestCertificate(t, exact, []string{testRoute().Host}, now.Add(-time.Hour), now.Add(time.Hour))
	data, _ := json.Marshal([]storedCertificate{{Fullchain: wildcard, PrivateKey: key}, {Fullchain: exact, PrivateKey: key}})
	write(t, n.Certificates.Store, data)
	if err := n.Apply([]Route{testRoute()}, false, false); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(filepath.Dir(n.Main), "watchcow-r-certificates.json")
	if !bytes.Contains(read(t, p), []byte(exact)) {
		t.Fatal("wildcard overrode exact certificate")
	}
	publicTestCertificate(t, exact, []string{testRoute().Host}, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := n.Apply([]Route{testRoute()}, false, false); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(read(t, p), []byte(exact)) || !bytes.Contains(read(t, p), []byte(wildcard)) {
		t.Fatal("expired certificate selected")
	}
}

func TestCertificateTransactionFailureRestoresAllFiles(t *testing.T) {
	for _, failCall := range []int{1, 2} {
		t.Run(string(rune('0'+failCall)), func(t *testing.T) {
			n, _, _, _ := certificateNative(t)
			main := read(t, n.Main)
			calls := 0
			n.Run = func(context.Context, string, ...string) error {
				calls++
				if calls == failCall {
					return errors.New("injected native failure")
				}
				if calls > failCall {
					if _, err := os.Stat(filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf")); !os.IsNotExist(err) {
						t.Fatal("rollback would reload staged routes before removing them")
					}
				}
				return nil
			}
			if err := n.Apply([]Route{testRoute()}, false, false); err == nil {
				t.Fatal("expected failure")
			}
			if !bytes.Equal(main, read(t, n.Main)) {
				t.Fatal("main configuration not restored")
			}
			for _, path := range []string{filepath.Join(filepath.Dir(n.Main), "watchcow-r-certificates.json"), filepath.Join(n.Dir, "certificates.owned.json"), filepath.Join(n.Dir, "nginx.pending.json"), filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("transaction file survived rollback", path, err)
				}
			}
		})
	}
}

func TestCertificateFailureAndExternalChangesPreserveWorkingConfig(t *testing.T) {
	for _, kind := range []string{"inventory", "missing-certificate", "owned-map", "source-directive"} {
		t.Run(kind, func(t *testing.T) {
			n, _, wildcard, _ := certificateNative(t)
			if err := n.Apply([]Route{testRoute()}, false, false); err != nil {
				t.Fatal(err)
			}
			mapPath := filepath.Join(filepath.Dir(n.Main), "watchcow-r-certificates.json")
			switch kind {
			case "inventory":
				write(t, n.Certificates.Store, []byte("broken JSON"))
			case "missing-certificate":
				if err := os.Remove(wildcard); err != nil {
					t.Fatal(err)
				}
			case "owned-map":
				write(t, mapPath, []byte("administrator change"))
			case "source-directive":
				write(t, n.Main, bytes.ReplaceAll(read(t, n.Main), []byte(mapPath), []byte("/external/mapping.json")))
			}
			main, mapping := read(t, n.Main), read(t, mapPath)
			if err := n.Apply([]Route{testRoute()}, false, false); err == nil {
				t.Fatal("expected validation failure")
			}
			if !bytes.Equal(main, read(t, n.Main)) || !bytes.Equal(mapping, read(t, mapPath)) {
				t.Fatal("failed update overwrote working/external configuration")
			}
		})
	}
}

func TestCertificateCrashRecoveryAndForeignEdit(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		n, _, _, _ := certificateNative(t)
		main := read(t, n.Main)
		next, changes, _, err := n.certificatePlan(main, []Route{testRoute()}, false)
		if err != nil {
			t.Fatal(err)
		}
		mainChange, _ := nativeChange(n.Main, next, 0644, false)
		changes = append(changes, mainChange)
		pending, _ := json.Marshal(pendingNative{Files: changes})
		write(t, filepath.Join(n.Dir, "nginx.pending.json"), pending)
		if err := writeNativeChanges(changes, false); err != nil {
			t.Fatal(err)
		}
		if foreign {
			write(t, n.Main, append(next, []byte("# foreign\n")...))
		}
		err = n.recoverPending(filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf"))
		if foreign {
			if err == nil || !strings.Contains(string(read(t, n.Main)), "# foreign") {
				t.Fatal("crash recovery overwrote foreign configuration")
			}
		} else {
			if err != nil || !bytes.Equal(main, read(t, n.Main)) {
				t.Fatal("crash recovery failed", err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(n.Main), "watchcow-r-certificates.json")); !os.IsNotExist(err) {
				t.Fatal("crash recovery left staged mapping")
			}
		}
	}
}
