package reverse

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"watchcow/internal/app"
)

func TestAutomaticIconsPreserveConfiguredAndRollback(t *testing.T) {
	m, a, _ := manager(t)
	image, err := os.ReadFile("../fpkgen/testdata/test.png")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/favicon.ico" {
			w.Write(image)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	images := filepath.Join(m.AppsDir, a.AppName, "target", "ui", "images")
	small := filepath.Join(images, "icon_64.png")
	large := filepath.Join(images, "icon_256.png")
	original := []byte("previous icon")
	for _, path := range []string{small, large, filepath.Join(m.AppsDir, a.AppName, "ICON.PNG"), filepath.Join(m.AppsDir, a.AppName, "ICON_256.PNG")} {
		write(t, path, original)
	}
	m.Resolve = func(context.Context, *app.App, app.Entry) (string, error) { return server.URL, nil }
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.Labels = map[string]string{"watchcow.icon": "file:///custom.png"}
	m.Registry.Register(a)
	m.SyncIcons(context.Background())
	if calls != 0 || !bytes.Equal(read(t, small), original) {
		t.Fatal("configured icon replaced")
	}
	a.Labels = nil
	m.Registry.Register(a)
	m.SyncIcons(context.Background())
	if calls == 0 || bytes.Equal(read(t, small), original) {
		t.Fatal("automatic icon not applied")
	}
	if !bytes.Equal(read(t, small), read(t, filepath.Join(m.AppsDir, a.AppName, "ICON.PNG"))) {
		t.Fatal("application and desktop icons differ")
	}
	previousCalls := calls
	m.SyncIcons(context.Background())
	if calls != previousCalls {
		t.Fatal("cached icon fetched again")
	}
	// A later user edit must survive both refresh and full rollback.
	edit := []byte("custom replacement")
	write(t, small, edit)
	state := m.icons[testRoute().Key]
	state.Checked = time.Time{}
	m.icons[testRoute().Key] = state
	m.SyncIcons(context.Background())
	if !bytes.Equal(read(t, small), edit) {
		t.Fatal("external edit overwritten")
	}
	if err := m.Rollback(); err == nil {
		t.Fatal("expected external modification report")
	}
	if !bytes.Equal(read(t, small), edit) || !bytes.Equal(read(t, large), original) {
		t.Fatal("icon rollback lost user edit or original")
	}
}
