package reverse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"watchcow/internal/app"
)

const fixture = `# comment http { should not be selected
load_module modules/ngx_http_trim_cert_module.so;
events { worker_connections 100; }
http {
 trim_cert_cfg_path /usr/trim/etc/network_gateway_cert.conf;
 server {
 listen 0.0.0.0:5666 default_server;
 listen [::]:5666 ipv6only=on default_server;
 listen 0.0.0.0:5667 ssl http2 default_server;
 listen [::]:5667 ssl http2 ipv6only=on default_server;
 listen 0.0.0.0:80 default_server;
 listen [::]:80 ipv6only=on default_server;
 listen 0.0.0.0:443 ssl http2 default_server;
 listen [::]:443 ssl http2 ipv6only=on default_server;
 trim_hook_cert_switch  on;
 ssl_certificate      $ssl_server_name;
 ssl_certificate_key  $ssl_server_name;
 ssl_session_cache shared:SSL:1m;
 include conf.d/*.conf;
 }
}
`

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := atomicWrite(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func native(t *testing.T) *Native {
	t.Helper()
	dir := t.TempDir()
	n := &Native{Main: filepath.Join(dir, "nginx.conf"), Dir: filepath.Join(dir, "etc"), Binary: "nginx", Run: func(context.Context, string, ...string) error { return nil }}
	write(t, n.Main, []byte(fixture))
	return n
}
func testRoute() Route {
	return Route{Key: "EmbyServer/", AppName: "watchcow.embyserver", Host: "embyserver.nas.example.com", Upstream: "http://127.0.0.1:8096", Path: "/", Active: true}
}

func TestNativePortsCertificatesStreamingAndValidation(t *testing.T) {
	l, e := detectLayout(fixture)
	if e != nil {
		t.Fatal(e)
	}
	if len(l.Listeners) != 4 || l.HTTPSPort != "5667" {
		t.Fatalf("unexpected listeners: %+v", l)
	}
	r := testRoute()
	out, e := renderServer(l, []Route{r}, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"set $watchcow_r_upstream http://127.0.0.1:8096;", "error_page 599 = @watchcow_r_proxy;", "proxy_request_buffering off;", "proxy_buffering off;", "proxy_set_header Upgrade $http_upgrade;", "X-Forwarded-Proto $scheme;"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing %s", want)
		}
	}
	for _, bad := range []string{"listen ", "\nserver {", "ssl_certificate ", "/watchcow.sock", "proxy_pass http://127.0.0.1:5666"} {
		if bytes.Contains(out, []byte(bad)) {
			t.Errorf("unexpected %s", bad)
		}
	}
	for _, addr := range []string{"http://[::1]:8096", "https://[fd00::abcd]:8443", "http://172.18.0.3:80"} {
		r.Upstream = addr
		if _, e := renderServer(l, []Route{r}, false); e != nil {
			t.Fatal(e)
		}
	}
	for _, addr := range []string{"http://evil.test:80", "http://127.0.0.1:80/;return 200;", "http://127.0.0.1:99999", "ftp://127.0.0.1:80"} {
		r.Upstream = addr
		if _, e := renderServer(l, []Route{r}, false); e == nil {
			t.Fatal("accepted unsafe upstream", addr)
		}
	}
	r = testRoute()
	out, e = renderServer(l, []Route{r}, true)
	if e != nil || !bytes.Contains(out, []byte("return 503;")) || bytes.Contains(out, []byte("set $watchcow_r_upstream http")) {
		t.Fatal("disable did not fail closed")
	}
	changed := strings.ReplaceAll(strings.ReplaceAll(fixture, ":5666", ":6000"), ":5667", ":6443")
	changed = strings.Replace(changed, "include conf.d/", `if ($scheme = http) { return 301 https://$host:6443$request_uri; }
 include conf.d/`, 1)
	l, e = detectLayout(changed)
	if e != nil || l.HTTPSPort != "6443" || !l.ForceHTTPS {
		t.Fatal("failed to detect port/HTTPS change", l, e)
	}
}

func TestNativeTransactionsRollbackAndExternalChanges(t *testing.T) {
	for _, failAt := range []string{"-t", "reload"} {
		t.Run(failAt, func(t *testing.T) {
			n := native(t)
			calls := 0
			n.Run = func(_ context.Context, _ string, args ...string) error {
				calls++
				if failAt == "-t" && calls == 1 || failAt == "reload" && calls == 2 {
					return errors.New("injected failure")
				}
				return nil
			}
			if e := n.Apply([]Route{testRoute()}, false, false); e == nil {
				t.Fatal("expected failure")
			}
			if string(read(t, n.Main)) != fixture {
				t.Fatal("canonical config was not restored")
			}
			if _, e := os.Stat(filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf")); !os.IsNotExist(e) {
				t.Fatal("new route file survived rollback")
			}
		})
	}
	n := native(t)
	if e := n.Apply([]Route{testRoute()}, false, false); e != nil {
		t.Fatal(e)
	}
	// fnOS changes unrelated to the owned include survive uninstall.
	b := read(t, n.Main)
	b = append(b, []byte("# external edit\n")...)
	write(t, n.Main, b)
	if e := n.Apply(nil, true, true); e != nil {
		t.Fatal(e)
	}
	if got := string(read(t, n.Main)); got != fixture+"# external edit\n" {
		t.Fatal("uninstall overwrote an external change", got)
	}
}

func TestNativeCrashRecovery(t *testing.T) {
	n := native(t)
	path := filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf")
	p := pendingNative{Main: []byte(fixture), NextRoutes: []byte("broken")}
	data, _ := json.Marshal(p)
	write(t, filepath.Join(n.Dir, "nginx.pending.json"), data)
	write(t, path, []byte("broken"))
	if e := n.Apply(nil, true, true); e != nil {
		t.Fatal(e)
	}
	if string(read(t, n.Main)) != fixture {
		t.Fatal("crash recovery did not restore canonical file")
	}
}

func TestNamesStableAcrossRecreateAndCollisions(t *testing.T) {
	s := Settings{Domain: "nas.example.com", Names: map[string]string{}, Entries: map[string]Override{}}
	a := &app.App{ContainerName: "EmbyServer", ContainerID: "old"}
	e := app.Entry{}
	first, err := s.name(a, e)
	if err != nil || first != "embyserver.nas.example.com" {
		t.Fatal(first, err)
	}
	a.ContainerID = "new"
	again, _ := s.name(a, e)
	if again != first {
		t.Fatal("container recreation changed hostname")
	}
	other := &app.App{ContainerName: "embyserver"}
	collision, _ := s.name(other, e)
	if collision == first || !strings.HasPrefix(collision, "embyserver-") {
		t.Fatal("collision not resolved", collision)
	}
	named, _ := s.name(a, app.Entry{Name: "Admin"})
	if named != "embyserver-admin.nas.example.com" {
		t.Fatal(named)
	}
	for _, bad := range []string{"evil;return 200", "*.evil", "two.labels", "-bad", "https://bad"} {
		if _, err := s.name(a, app.Entry{ProxySubdomain: bad}); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if _, err := s.name(other, app.Entry{ProxySubdomain: "embyserver"}); err == nil {
		t.Fatal("manual collision silently renamed")
	}
	dir := t.TempDir()
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := loaded.name(a, e)
	if got != first {
		t.Fatal("name did not survive restart")
	}
}

func manager(t *testing.T) (*Manager, *app.App, string) {
	t.Helper()
	n := native(t)
	s := Settings{Domain: "nas.example.com", Names: map[string]string{}, Entries: map[string]Override{}}
	if e := s.Save(n.Dir); e != nil {
		t.Fatal(e)
	}
	m, e := New(n.Dir, app.NewRegistry())
	if e != nil {
		t.Fatal(e)
	}
	m.Native = n
	m.AppsDir = filepath.Join(t.TempDir(), "apps")
	m.oldRunning = func() bool { return false }
	m.SyncDesktop = func(context.Context, string) error { return nil }
	m.Probe = func(context.Context, string) error { return nil }
	a := &app.App{AppName: "watchcow.embyserver", ContainerName: "EmbyServer", ContainerID: "old", Status: app.StatusRunning, Entries: []app.Entry{{Protocol: "http", Port: "8096", Path: "/web/index.html?x=1", AllUsers: true}}}
	m.Registry.Register(a)
	p := filepath.Join(m.AppsDir, a.AppName, "target", "ui", "config")
	write(t, p, []byte(`{".url":{"watchcow.embyserver":{"title":"My custom title","protocol":"http","port":"8096","url":"/web/index.html?x=1","icon":"images/icon.png","type":"url","allUsers":true,"custom":"keep"}}}`))
	write(t, filepath.Join(m.AppsDir, a.AppName, "cmd", "main"), []byte("# Generated by WatchCow\n# Container: EmbyServer\n"))
	return m, a, p
}

func TestMigrationReconcileDisableAndRollback(t *testing.T) {
	m, a, p := manager(t)
	original := read(t, p)
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	b := read(t, p)
	if bytes.Contains(b, []byte(`"port"`)) || !bytes.Contains(b, []byte(`"protocol": ""`)) || !bytes.Contains(b, []byte("My custom title")) || !bytes.Contains(b, []byte(`"custom": "keep"`)) {
		t.Fatal("desktop metadata not preserved", string(b))
	}
	if _, e := os.Stat(filepath.Join(m.Dir, "backup", "packages", a.AppName+".tar.gz")); e != nil {
		t.Fatal(e)
	}
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, read(t, p)) {
		t.Fatal("reconciliation not idempotent")
	}
	if e := m.Disable(); e != nil {
		t.Fatal(e)
	}
	if cfg := string(read(t, filepath.Join(filepath.Dir(m.Native.Main), "conf.d", "watchcow-r.conf"))); !strings.Contains(cfg, "return 503;") || strings.Contains(cfg, "set $watchcow_r_upstream http") {
		t.Fatal("stop did not disable proxy")
	}
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := m.Rollback(); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(original, read(t, p)) {
		t.Fatal("rollback changed original desktop entry")
	}
	if e := m.Disable(); e != nil {
		t.Fatal(e)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(m.Native.Main), "conf.d", "watchcow-r.conf")); !os.IsNotExist(err) {
		t.Fatal("stop after rollback reinstalled native config")
	}
}

func TestManagerApplyFailureAndFileFailureRestore(t *testing.T) {
	m, a, p := manager(t)
	original := read(t, p)
	m.Native.Run = func(context.Context, string, ...string) error { return errors.New("nginx error") }
	if e := m.Reconcile(context.Background()); e == nil {
		t.Fatal("expected config failure")
	}
	if !bytes.Equal(original, read(t, p)) {
		t.Fatal("launcher changed before native validation")
	}
	m.Native.Run = func(context.Context, string, ...string) error { return nil }
	// Invalid second entry fails after the first app CGI write; the cycle must
	// restore that file and the pre-cycle native configuration.
	a.Entries = append(a.Entries, app.Entry{Name: "missing", Protocol: "http", Port: "8080", Path: "/"})
	if e := m.Reconcile(context.Background()); e == nil {
		t.Fatal("expected missing entry error")
	}
	if !bytes.Equal(original, read(t, p)) {
		t.Fatal("partial launcher update survived")
	}
}

func TestRollbackPreservesExternalEdits(t *testing.T) {
	m, _, p := manager(t)
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	write(t, p, []byte("external edit"))
	if e := m.Rollback(); e == nil {
		t.Fatal("external edit not reported")
	}
	if string(read(t, p)) != "external edit" {
		t.Fatal("external file overwritten")
	}
}

func TestReconcileThenRollbackPreservesMetadataEdits(t *testing.T) {
	m, _, p := manager(t)
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	b := strings.Replace(string(read(t, p)), "My custom title", "User changed title", 1)
	write(t, p, []byte(b))
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := m.Rollback(); e != nil {
		t.Fatal(e)
	}
	got := string(read(t, p))
	if !strings.Contains(got, "User changed title") || !strings.Contains(got, `"port": "8096"`) || strings.Contains(got, "/index.cgi/proxy/") {
		t.Fatal("metadata edit or original routing lost", got)
	}
}

func TestProbeAndOptOut(t *testing.T) {
	m, a, p := manager(t)
	original := read(t, p)
	m.Probe = func(context.Context, string) error { return errors.New("not HTTP") }
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(original, read(t, p)) {
		t.Fatal("non-HTTP endpoint was taken over")
	}
	for _, e := range []app.Entry{{Protocol: "tcp", Port: "8096"}, {Protocol: "http", Port: "3306"}, {Protocol: "http", Port: "8096", Redirect: "https://example.com"}} {
		if ok, _ := eligible(m.settings, a, e); ok {
			t.Fatal("ineligible entry accepted", e)
		}
	}
}

func TestLauncherPreservesOriginAndQueries(t *testing.T) {
	m, _, _ := manager(t)
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, scheme := range []string{"http", "https"} {
		r := httptest.NewRequest("GET", scheme+"://nas.example.com:5666/proxy/watchcow.embyserver/_?path=%2Fa%20b", nil)
		w := httptest.NewRecorder()
		m.Launch(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		html := w.Body.String()
		for _, want := range []string{"new URL(window.location.href)", "target.hostname", "embyserver.nas.example.com", "appPath.searchParams.append"} {
			if !strings.Contains(html, want) {
				t.Fatal("missing", want)
			}
		}
		if strings.Contains(html, "target.protocol =") || strings.Contains(html, "target.port =") || strings.Contains(html, "fetch(") {
			t.Fatal("launcher overrides origin/probes LAN")
		}
	}
	r := httptest.NewRequest("GET", "http://nas/proxy/missing/_", nil)
	w := httptest.NewRecorder()
	m.Launch(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestPanelRequiresCSRF(t *testing.T) {
	m, _, _ := manager(t)
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	values := url.Values{"domain": {"evil.test"}}
	r := httptest.NewRequest(http.MethodPost, "http://nas/reverse", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	m.Panel(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
}

func TestRollbackDoesNotRecreateUninstalledChild(t *testing.T) {
	m, a, _ := manager(t)
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(m.AppsDir, a.AppName)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("uninstalled child recreated", err)
	}
}

func TestBackendOverrideUsesDockerResolverAndPreservesLabels(t *testing.T) {
	m, a, _ := manager(t)
	settings, err := Load(m.Dir)
	if err != nil {
		t.Fatal(err)
	}
	settings.Entries[key(a, a.Entries[0])] = Override{Protocol: "https", Port: "9443"}
	if err := settings.Save(m.Dir); err != nil {
		t.Fatal(err)
	}
	m.Resolve = func(_ context.Context, got *app.App, entry app.Entry) (string, error) {
		if got.ContainerID != a.ContainerID || entry.Protocol != "https" || entry.Port != "9443" {
			t.Fatalf("incorrect resolver input: %+v", entry)
		}
		return "https://127.0.0.1:9443", nil
	}
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.routes["embyserver.nas.example.com"].Upstream != "https://127.0.0.1:9443" {
		t.Fatal(m.routes)
	}
	if a.Entries[0].Port != "8096" || a.Entries[0].Protocol != "http" {
		t.Fatal("override changed original labels")
	}
	for _, invalid := range []Override{{Protocol: "ftp"}, {Port: "0"}, {Port: "65536"}, {Port: "9443/path"}} {
		settings.Entries[key(a, a.Entries[0])] = invalid
		if err := settings.Save(m.Dir); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(m.Dir); err == nil {
			t.Fatalf("accepted invalid backend override: %+v", invalid)
		}
	}
}

func TestRollbackRefreshesRestoredDesktopRegistry(t *testing.T) {
	m, _, path := manager(t)
	original := read(t, path)
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.SyncDesktop = func(_ context.Context, id string) error {
		calls++
		if id != "watchcow.embyserver" {
			t.Fatal(id)
		}
		if !bytes.Equal(read(t, path), original) {
			t.Fatal("registration ran before restoring original launcher")
		}
		return nil
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("restored files without refreshing desktop registry", calls)
	}
}
