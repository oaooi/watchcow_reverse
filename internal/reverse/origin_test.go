package reverse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPanelOriginWithCGIHostRewrite(t *testing.T) {
	m, _, _ := manager(t)
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, host, origin, site, headerToken string
		missingFormToken                      bool
		want                                  int
	}{
		{name: "direct same origin", host: "nas.example.com:5667", origin: "https://nas.example.com:5667", want: 200},
		{name: "CGI rewritten host", host: "localhost", origin: "https://nas.example.com:5667", headerToken: m.csrf, want: 200},
		{name: "CGI stripped port over HTTP", host: "nas.example.com", origin: "http://nas.example.com:5666", headerToken: m.csrf, want: 200},
		{name: "CGI fetch metadata", host: "localhost", origin: "https://nas.example.com:5667", site: "same-origin", headerToken: m.csrf, want: 200},
		{name: "mismatch without header", host: "localhost", origin: "https://nas.example.com:5667", want: 403},
		{name: "incorrect header token", host: "localhost", origin: "https://nas.example.com:5667", headerToken: "wrong", want: 403},
		{name: "missing form token", host: "localhost", origin: "https://nas.example.com:5667", headerToken: m.csrf, missingFormToken: true, want: 403},
		{name: "cross site", host: "localhost", origin: "https://other.example.net", site: "cross-site", headerToken: m.csrf, want: 403},
		{name: "different same site origin", host: "localhost", origin: "https://other.example.com", site: "same-site", headerToken: m.csrf, want: 403},
		{name: "null origin", host: "localhost", origin: "null", headerToken: m.csrf, want: 403},
		{name: "origin with credentials", host: "localhost", origin: "https://user@nas.example.com:5667", headerToken: m.csrf, want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"key": {testRoute().Key}, "action": {"refresh-icon"}}
			if !tc.missingFormToken {
				form.Set("csrf", m.csrf)
			}
			r := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/reverse", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			r.Header.Set("X-Watchcow-R-CSRF", tc.headerToken)
			w := httptest.NewRecorder()
			m.Panel(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
