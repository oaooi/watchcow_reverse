package reverse

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustomConfigValidation(t *testing.T) {
	sample := `location / { proxy_pass https://192.0.2.10:8089/; proxy_redirect http:// https://; proxy_set_header Host $host:$server_port; } error_page 497 https://$http_host$request_uri;`
	if err := validateOverride(Override{Nginx: sample}); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{sample + sample, "} server { listen 9000; }", `include /etc/passwd;`, `location / { include /tmp/other; }`, `"listen" 1234;`, `ssl_certificate /tmp/key;`, `location / {`, "return 200 'unterminated;", "trim_hook_cert_switch off;"} {
		if err := validateOverride(Override{Nginx: src}); err == nil {
			t.Fatal("accepted invalid/protected snippet", src)
		}
	}
	if err := validateOverride(Override{CustomLocations: []CustomLocation{{Path: "/api/", Upstream: "https://[::1]:8443/backend/", Nginx: "proxy_set_header Host $host; proxy_read_timeout 10s;"}}}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://example.com:80/", "http://192.0.2.10:80/;return", "http://192.0.2.10:0/", "file:///etc/passwd", "http://192.0.2.10:80/$uri"} {
		if err := validateOverride(Override{CustomLocations: []CustomLocation{{Path: "/api/", Upstream: u}}}); err == nil {
			t.Fatal("unsafe upstream", u)
		}
	}
}

func TestCustomHostsTransactionAndRemoval(t *testing.T) {
	n := native(t)
	original := read(t, n.Main)
	r := testRoute()
	r.Nginx = "add_header X-App custom;"
	r.CustomLocations = []CustomLocation{{Path: "/api/", Upstream: "http://192.0.2.10:8080/base/", Nginx: "proxy_set_header Host $host:$server_port; proxy_read_timeout 10s;"}}
	if err := n.Apply([]Route{r}, false, false); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(filepath.Dir(n.Main), "watchcow-r-hosts.conf")
	hosts := read(t, p)
	for _, s := range []string{"server_name " + r.Host, "listen 0.0.0.0:5667 ssl;", "location /api/", "proxy_pass http://192.0.2.10:8080/base/;", "proxy_read_timeout 10s;", "location / {"} {
		if !bytes.Contains(hosts, []byte(s)) {
			t.Fatal("missing", s)
		}
	}
	if strings.Count(string(hosts), "proxy_read_timeout 3600s;") != 1 {
		t.Fatal("custom timeout duplicated")
	}
	nextMain := read(t, n.Main)
	calls := 0
	n.Run = func(context.Context, string, ...string) error { calls++; return nil }
	if err := n.Apply([]Route{r}, false, false); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("non-idempotent apply")
	}
	r.Nginx = "add_header X-App changed;"
	n.Run = func(context.Context, string, ...string) error {
		calls++
		if calls == 1 {
			return errors.New("invalid config")
		}
		return nil
	}
	if err := n.Apply([]Route{r}, false, false); err == nil {
		t.Fatal("expected rollback")
	}
	if !bytes.Equal(read(t, n.Main), nextMain) || !bytes.Equal(read(t, p), hosts) {
		t.Fatal("custom config rollback failed")
	}
	n.Run = func(context.Context, string, ...string) error { return nil }
	if err := n.Apply(nil, true, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read(t, n.Main), original) {
		t.Fatal("http include not removed")
	}
	for _, p := range []string{p, filepath.Join(n.Dir, "hosts.owned.json")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("owned custom file survived removal")
		}
	}
}

func TestCustomHostsExternalChangesRetained(t *testing.T) {
	n := native(t)
	r := testRoute()
	r.Nginx = "add_header X-App custom;"
	if err := n.Apply([]Route{r}, false, false); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(filepath.Dir(n.Main), "watchcow-r-hosts.conf")
	edited := append(read(t, p), []byte("# manual\n")...)
	write(t, p, edited)
	if err := n.Apply([]Route{r}, false, false); err == nil {
		t.Fatal("external edit overwritten")
	}
	if !bytes.Equal(read(t, p), edited) {
		t.Fatal("lost external edit")
	}
}

func TestPanelRejectsBadNginxAndRestoresSettings(t *testing.T) {
	m, _, _ := manager(t)
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := read(t, filepath.Join(m.Dir, "reverse.json"))
	beforeMain := read(t, m.Native.Main)
	first := true
	m.Native.Run = func(context.Context, string, ...string) error {
		if first {
			first = false
			return errors.New("unknown directive")
		}
		return nil
	}
	form := url.Values{"csrf": {m.csrf}, "key": {testRoute().Key}, "editor": {"full"}, "enabled": {"auto"}, "nginx": {"unknown_directive on;"}, "icon_mode": {"auto"}}
	r := httptest.NewRequest(http.MethodPost, "http://nas.example.com/reverse", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	m.Panel(w, r)
	if w.Code != 422 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !bytes.Equal(before, read(t, filepath.Join(m.Dir, "reverse.json"))) || !bytes.Equal(beforeMain, read(t, m.Native.Main)) {
		t.Fatal("bad desired/native config left behind")
	}
	if m.lastError != "" {
		t.Fatal("working routes remain blocked", m.lastError)
	}
}

func TestPanelCustomEditorPersistsPerEntry(t *testing.T) {
	m, _, _ := manager(t)
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {m.csrf}, "key": {testRoute().Key}, "editor": {"full"}, "enabled": {"auto"}, "upstream": {"https://192.0.2.10:8443/"}, "nginx": {"error_page 497 https://$http_host$request_uri;"}, "icon_mode": {"keep"}, "location_path": {"/api/"}, "location_upstream": {"http://192.0.2.20:8080/backend/"}, "location_nginx": {"proxy_read_timeout 42s;"}}
	r := httptest.NewRequest(http.MethodPost, "http://nas.example.com/reverse", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	m.Panel(w, r)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	s, err := Load(m.Dir)
	if err != nil {
		t.Fatal(err)
	}
	o := s.Entries[testRoute().Key]
	if o.Upstream != "https://192.0.2.10:8443" || len(o.CustomLocations) != 1 || o.IconMode != "keep" || o.Enabled != nil {
		t.Fatal("editor settings lost", o)
	}
	get := httptest.NewRecorder()
	m.Panel(get, httptest.NewRequest(http.MethodGet, "http://nas.example.com/reverse", nil))
	if get.Code != 200 || !strings.Contains(get.Body.String(), "自定义 Nginx 配置") || !strings.Contains(get.Body.String(), "proxy_read_timeout 42s;") {
		t.Fatal("editor not rendered", get.Code)
	}
}
