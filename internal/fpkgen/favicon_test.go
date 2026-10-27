package fpkgen

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWebIconDiscoveryAndConfiguredPriority(t *testing.T) {
	icon, err := os.ReadFile("testdata/test.ico")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/app/":
			http.Redirect(w, r, "/app/login", 302)
		case "/app/login":
			w.Write([]byte(`<html><head><link href="assets/icon.ico" rel="shortcut icon"></head></html>`))
		case "/app/assets/icon.ico":
			w.Write(icon)
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	img, source, err := DiscoverWebIcon(context.Background(), s.URL, "/app/")
	if err != nil || img == nil || source != s.URL+"/app/assets/icon.ico" {
		t.Fatal(source, err)
	}
	cfg := &AppConfig{Image: "test:latest", Entries: []Entry{{Port: strings.Split(s.URL, ":")[2], Path: "/app/"}}}
	if !AutomaticIcon(cfg, cfg.Entries[0]) {
		t.Fatal("missing icon not automatic")
	}
	before := calls
	cfg.Labels = map[string]string{"watchcow.icon": "http://example.com/custom.png"}
	if automaticEntryIcon(cfg, cfg.Entries[0]) != nil || calls != before {
		t.Fatal("explicit icon replaced/contacted webpage")
	}
	cfg.Labels = nil
	cfg.Icon = "uploaded-base64"
	if AutomaticIcon(cfg, cfg.Entries[0]) {
		t.Fatal("upload considered automatic")
	}
	cfg.Icon = "file:///local/icon.png"
	if AutomaticIcon(cfg, cfg.Entries[0]) {
		t.Fatal("local icon considered automatic")
	}
	cfg.Icon = DefaultIconForImage(cfg.Image)
	if !AutomaticIcon(cfg, cfg.Entries[0]) {
		t.Fatal("implicit CDN fallback blocks discovery")
	}
}

func TestWebIconFallbackAndOriginBoundary(t *testing.T) {
	icon, _ := os.ReadFile("testdata/test.png")
	remoteCalls := 0
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { remoteCalls++; w.Write(icon) }))
	defer remote.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write(icon)
			return
		}
		w.Write([]byte(`<link rel="icon" href="` + remote.URL + `/icon.png">`))
	}))
	defer s.Close()
	img, source, err := DiscoverWebIcon(context.Background(), s.URL, "/")
	if err != nil || img == nil || source != s.URL+"/favicon.ico" || remoteCalls != 0 {
		t.Fatal("origin boundary/fallback failed", source, err, remoteCalls)
	}
	empty := httptest.NewServer(http.NotFoundHandler())
	defer empty.Close()
	if _, _, err := DiscoverWebIcon(context.Background(), empty.URL, "/"); err == nil {
		t.Fatal("expected missing icon error")
	}
}
