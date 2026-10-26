package reverse

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func modeManager(t *testing.T) (*Manager, *bool, *int) {
	t.Helper()
	m, _, _ := manager(t)
	m.Native.Run = nil
	active := false
	calls := 0
	control := &ModeControl{Path: filepath.Join(t.TempDir(), "trim_nginx.service.d", "watchcow-r.conf"), Verify: func() error { return nil }, Extended: func() bool { return active }}
	control.Run = func(args ...string) error {
		calls++
		if args[0] == "restart" {
			_, e := os.Stat(control.Path)
			active = e == nil
		}
		return nil
	}
	m.Mode = control
	write(t, filepath.Join(filepath.Dir(m.Native.Main), "conf.d", "existing.conf"), []byte("# unrelated\n"))
	return m, &active, &calls
}

func TestExtensionRequiresExplicitOptIn(t *testing.T) {
	m, _, calls := modeManager(t)
	if e := m.EnsureExtensions(); e == nil {
		t.Fatal("extension enabled without consent")
	}
	if *calls != 0 {
		t.Fatal("systemd called before opt-in")
	}
	if _, e := os.Stat(m.Mode.Path); !os.IsNotExist(e) {
		t.Fatal("override created without opt-in")
	}
}

func TestExtensionEnableAndRestore(t *testing.T) {
	m, active, calls := modeManager(t)
	m.settings.NativeExtensions = true
	if e := m.EnsureExtensions(); e != nil {
		t.Fatal(e)
	}
	if !*active || *calls != 2 {
		t.Fatal("service not reloaded/restarted")
	}
	if e := m.EnsureExtensions(); e != nil {
		t.Fatal(e)
	}
	if *calls != 2 {
		t.Fatal("repeat start restarted service")
	}
	if e := m.restoreMode(true); e != nil {
		t.Fatal(e)
	}
	if *active || *calls != 4 {
		t.Fatal("original service mode not restored")
	}
	if _, e := os.Stat(m.Mode.Path); !os.IsNotExist(e) {
		t.Fatal("owned override survived rollback")
	}
}

func TestExtensionFailureRestoresOriginalMode(t *testing.T) {
	m, active, _ := modeManager(t)
	m.settings.NativeExtensions = true
	realRun := m.Mode.Run
	failed := false
	m.Mode.Run = func(args ...string) error {
		if args[0] == "restart" && !failed {
			failed = true
			return errors.New("injected restart failure")
		}
		return realRun(args...)
	}
	if e := m.EnsureExtensions(); e == nil {
		t.Fatal("restart failure not reported")
	}
	if *active {
		t.Fatal("extension stayed enabled after failure")
	}
	if _, e := os.Stat(m.Mode.Path); !os.IsNotExist(e) {
		t.Fatal("override not removed after failure")
	}
}

func TestExtensionRollbackPreservesForeignChanges(t *testing.T) {
	m, _, _ := modeManager(t)
	m.settings.NativeExtensions = true
	if e := m.EnsureExtensions(); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(filepath.Dir(m.Native.Main), "conf.d", "other-new.conf"), []byte("# user change\n"))
	if e := m.restoreMode(true); e == nil || !strings.Contains(e.Error(), "其他 Nginx") {
		t.Fatal("foreign config change not protected", e)
	}
	if _, e := os.Stat(m.Mode.Path); e != nil {
		t.Fatal("mode reset could discard other configurations")
	}
}

func TestExtensionDoesNotOverwriteForeignOverride(t *testing.T) {
	m, _, calls := modeManager(t)
	m.settings.NativeExtensions = true
	write(t, m.Mode.Path, []byte("external config"))
	if e := m.EnsureExtensions(); e == nil {
		t.Fatal("foreign override overwritten")
	}
	if string(read(t, m.Mode.Path)) != "external config" || *calls != 0 {
		t.Fatal("foreign configuration changed")
	}
}
