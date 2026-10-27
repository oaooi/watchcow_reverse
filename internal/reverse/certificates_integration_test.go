package reverse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This exercises the actual proprietary fnOS certificate module. The harness
// must bind a private Nginx tree over /usr/trim/nginx in mount/net/PID namespaces.
func TestNativeCertificateSelectionAndRenewal(t *testing.T) {
	if os.Getenv("WATCHCOW_R_NATIVE_TEST") != "1" {
		t.Skip("requires isolated fnOS namespaces")
	}
	for _, kind := range []string{"mnt", "net", "pid"} {
		self, _ := os.Readlink("/proc/self/ns/" + kind)
		host := os.Getenv("WATCHCOW_R_HOST_" + kind)
		if self == "" || host == "" || self == host {
			t.Fatalf("refusing test outside isolated %s namespace", kind)
		}
	}
	dir := os.Getenv("WATCHCOW_R_NATIVE_DIR")
	if !strings.HasPrefix(dir, "/root/.work/") {
		t.Fatal("test artifacts must be in task workspace")
	}
	// The namespace bind isolates this directory from the real NAS. Workers
	// need access to the watched map, while the app's own state stays private.
	certificateDir := "/usr/trim/nginx/conf/fixture-certificates"
	if err := os.MkdirAll(certificateDir, 0755); err != nil {
		t.Fatal(err)
	}
	issue := func(stem string, names ...string) (storedCertificate, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		crtPath, keyPath := filepath.Join(certificateDir, stem+".crt"), filepath.Join(certificateDir, stem+".key")
		write(t, crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		// Throwaway fixture keys must be readable by the native worker, as
		// fnOS's own managed certificate files are. Production keys are untouched.
		if err := atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0644); err != nil {
			t.Fatal(err)
		}
		return storedCertificate{Fullchain: crtPath, PrivateKey: keyPath}, serial.String()
	}
	base, baseSerial := issue("base", "nas.example.com")
	wildcard, wildSerial := issue("wildcard", "*.nas.example.com")
	n := NewNative(filepath.Join(dir, "state"))
	n.Extended = true
	n.Certificates = &CertificateFiles{Gateway: "/usr/trim/nginx/conf/vendor-gateway.json", Store: "/usr/trim/nginx/conf/vendor-inventory.json"}
	if err := os.MkdirAll(n.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(n.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	publishVendor := func() {
		b, _ := json.Marshal([]certificateEntry{{Host: "fallback", Cert: base.Fullchain, Key: base.PrivateKey}, {Host: "nas.example.com", Cert: base.Fullchain, Key: base.PrivateKey}})
		write(t, n.Certificates.Gateway, b)
		b, _ = json.Marshal([]storedCertificate{base, wildcard})
		write(t, n.Certificates.Store, b)
	}
	publishVendor()
	conf := fmt.Sprintf(`user www-data;
worker_processes 1;
load_module modules/ngx_http_trim_cert_module.so;
pid /run/nginx.pid;
error_log logs/error.log info;
events { worker_connections 100; }
http {
 trim_cert_cfg_path %s;
 server {
  listen 0.0.0.0:5666 default_server;
  listen 0.0.0.0:5667 ssl default_server;
  trim_hook_cert_switch on;
  ssl_certificate $ssl_server_name;
  ssl_certificate_key $ssl_server_name;
  include conf.d/*.conf;
  location / { return 200 'NAS'; }
 }
}
`, n.Certificates.Gateway)
	write(t, n.Main, []byte(conf))
	cmd := exec.Command(n.Binary)
	cmd.Env = append(os.Environ(), "NGXMODE=dev")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start isolated nginx: %v %s", err, out)
	}
	// Even dev-mode startup normalizes native listener lines from fnOS settings.
	originalMain := read(t, n.Main)
	peer := func(host string) *x509.Certificate {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", "127.0.0.1:5667", &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0]
	}
	if peer(testRoute().Host).VerifyHostname(testRoute().Host) == nil {
		t.Fatal("fixture did not reproduce missing SNI mapping")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "application") }))
	defer backend.Close()
	routes := []Route{{Host: testRoute().Host, Upstream: backend.URL, Active: true}, {Host: "ddns-go.nas.example.com", Upstream: backend.URL, Active: true}}
	verify := func(host, serial string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			cert := peer(host)
			err := cert.VerifyHostname(host)
			if err == nil && cert.SerialNumber.String() == serial {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("wrong certificate for %s: serial %s, validation %v", host, cert.SerialNumber, err)
			}
			// Old workers may briefly accept a connection during graceful reload.
			time.Sleep(30 * time.Millisecond)
		}
	}
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	verify("nas.example.com", baseSerial)
	for _, route := range routes {
		verify(route.Host, wildSerial)
	}
	// Real per-host configuration must not leak locations into another app or
	// the NAS. Exercise the user's raw root-location example over a TLS backend.
	customBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "query": r.URL.RawQuery, "host": r.Host, "proto": r.Header.Get("X-Forwarded-Proto"), "marker": r.Header.Get("X-Custom")})
	}))
	defer customBackend.Close()
	routes[0].Nginx = fmt.Sprintf(`location / {
proxy_pass %s/;
proxy_redirect http:// https://;
proxy_set_header Host $host:$server_port;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Host $http_host;
proxy_set_header X-Forwarded-Port $server_port;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Scheme $scheme;
}
error_page 497 https://$http_host$request_uri;`, customBackend.URL)
	routes[1].CustomLocations = []CustomLocation{{Path: "/api/", Upstream: customBackend.URL + "/base/", Nginx: "proxy_set_header X-Custom structured; proxy_read_timeout 10s;"}}
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	request := func(host, path string) map[string]string {
		t.Helper()
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		c := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		req, _ := http.NewRequest("GET", "https://127.0.0.1:5667"+path, nil)
		req.Host = host + ":5667"
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var got map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := request(routes[0].Host, "/original?x=a%20b")
	if got["path"] != "/original" || got["host"] != routes[0].Host+":5667" || got["proto"] != "https" || got["query"] != "x=a%20b" {
		t.Fatal("raw proxy configuration not applied", got)
	}
	got = request(routes[1].Host, "/api/example?x=1")
	if got["path"] != "/base/example" || got["marker"] != "structured" || got["host"] != routes[1].Host+":5667" {
		t.Fatal("custom location not isolated/applied", got)
	}
	// A directive accepted structurally but rejected by Nginx must restore all
	// native files and keep the last working custom host serving requests.
	workingMain := read(t, n.Main)
	hostFile := filepath.Join(filepath.Dir(n.Main), "watchcow-r-hosts.conf")
	workingHosts := read(t, hostFile)
	bad := append([]Route(nil), routes...)
	bad[0].Nginx += "\nunknown_watchcow_directive on;"
	if err := n.Apply(bad, false, false); err == nil {
		t.Fatal("invalid native directive accepted")
	}
	if string(read(t, n.Main)) != string(workingMain) || string(read(t, hostFile)) != string(workingHosts) {
		t.Fatal("failed custom config changed working files")
	}
	got = request(routes[1].Host, "/api/still-working")
	if got["marker"] != "structured" {
		t.Fatal("working route lost after failed apply")
	}
	// Same-file renewal, then fnOS's usual versioned-path renewal.
	wildcard, wildSerial = issue("wildcard", "*.nas.example.com")
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		verify(route.Host, wildSerial)
	}
	wildcard, wildSerial = issue("wildcard-renewed", "*.nas.example.com")
	publishVendor()
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		verify(route.Host, wildSerial)
	}
	// A native-domain renewal must still propagate through the merged mapping.
	base, baseSerial = issue("base-renewed", "nas.example.com")
	publishVendor()
	if err := n.Apply(routes, false, false); err != nil {
		t.Fatal(err)
	}
	verify("nas.example.com", baseSerial)
	for _, route := range routes {
		verify(route.Host, wildSerial)
	}
	if err := n.Apply(routes, true, false); err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		verify(route.Host, wildSerial)
	}
	if err := n.Apply(nil, true, true); err != nil {
		t.Fatal(err)
	}
	if string(read(t, n.Main)) != string(originalMain) {
		t.Fatal("certificate module source was not restored")
	}
	verify("nas.example.com", baseSerial)
	deadline := time.Now().Add(5 * time.Second)
	for {
		cert := peer(testRoute().Host)
		if cert.SerialNumber.String() == baseSerial && cert.VerifyHostname(testRoute().Host) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("removed app certificate binding still active")
		}
		time.Sleep(30 * time.Millisecond)
	}
}
