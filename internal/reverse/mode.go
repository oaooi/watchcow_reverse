package reverse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

const extensionOverride = "/etc/systemd/system/trim_nginx.service.d/watchcow-r.conf"
const extensionContent = "# Managed by Watchcow_R; removed on rollback.\n[Service]\nEnvironment=NGXMODE=dev\n"

var ErrExtensionConsent = errors.New("需要明确启用 Nginx 扩展模式")

// Dependencies are explicit so service transitions can be fault-tested without
// touching a developer's systemd configuration or restarting the host Nginx.
type ModeControl struct {
	Path     string
	Run      func(...string) error
	Extended func() bool
	Verify   func() error
}

func (m *Manager) modeControl() *ModeControl {
	if m.Mode != nil {
		return m.Mode
	}
	return &ModeControl{Path: extensionOverride, Run: systemctl, Extended: serviceExtended, Verify: m.Native.verifyBinary}
}

func systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("systemctl %v: %w: %s", args, e, b)
	}
	return nil
}
func serviceExtended() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "systemctl", "show", "trim_nginx", "-p", "Environment", "--value").Output()
	return e == nil && regexp.MustCompile(`(?:^|\s)"?NGXMODE=(?:dev|debug)"?(?:\s|$)`).Match(b)
}

type modeState struct {
	Owned    bool              `json:"owned"`
	Baseline map[string]string `json:"baseline"`
}

func (m *Manager) modeState() (modeState, error) {
	var state modeState
	b, e := os.ReadFile(filepath.Join(m.Dir, "backup", "nginx-mode.json"))
	if os.IsNotExist(e) {
		return state, nil
	}
	if e != nil {
		return state, e
	}
	e = json.Unmarshal(b, &state)
	return state, e
}
func (m *Manager) saveMode(state modeState) error {
	b, e := json.MarshalIndent(state, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(m.Dir, "backup", "nginx-mode.json"), b, 0600)
}
func (m *Manager) configFingerprints() (map[string]string, error) {
	files, e := os.ReadDir(filepath.Join(filepath.Dir(m.Native.Main), "conf.d"))
	if e != nil {
		return nil, e
	}
	result := map[string]string{}
	for _, f := range files {
		if f.IsDir() || f.Name() == "watchcow-r.conf" {
			continue
		}
		b, e := os.ReadFile(filepath.Join(filepath.Dir(m.Native.Main), "conf.d", f.Name()))
		if e != nil {
			return nil, e
		}
		result[f.Name()] = digest(b)
	}
	return result, nil
}

// EnsureExtensions is deliberately opt-in. The stock fnOS recovery module
// removes custom config on every master reload; dev mode preserves extensions
// and the vendor's port/certificate handling, but suspends its file recovery.
func (m *Manager) EnsureExtensions() error {
	if m.Native.Run != nil || m.Native.Extended {
		return nil
	}
	control := m.modeControl()
	if e := control.Verify(); e != nil {
		return e
	}
	state, e := m.modeState()
	if e != nil {
		return e
	}
	if control.Extended() {
		return nil
	}
	if !m.settings.NativeExtensions {
		return fmt.Errorf("%w：在应用配置将 WATCHCOW_R_NATIVE_EXTENSIONS 设为 true。这会重启一次飞牛 Web 服务，并在扩展期间暂停 Nginx 配置自恢复；卸载恢复。业务容器不重启", ErrExtensionConsent)
	}
	if b, e := os.ReadFile(control.Path); e == nil && !bytes.Equal(b, []byte(extensionContent)) {
		return fmt.Errorf("扩展模式路径存在外部配置，拒绝覆盖")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	if !state.Owned {
		baseline, e := m.configFingerprints()
		if e != nil {
			return e
		}
		state = modeState{Owned: true, Baseline: baseline}
		if e := m.saveMode(state); e != nil {
			return e
		}
	}
	if e := atomicWrite(control.Path, []byte(extensionContent), 0644); e != nil {
		return e
	}
	if e := control.Run("daemon-reload"); e != nil {
		return errors.Join(e, m.restoreMode(false))
	}
	if e := control.Run("restart", "trim_nginx"); e != nil {
		recovery := m.restoreMode(false)
		return errors.Join(e, recovery)
	}
	if !control.Extended() {
		return fmt.Errorf("Nginx 扩展环境未生效")
	}
	return nil
}

func (m *Manager) restoreMode(checkForeign bool) error {
	if m.Native.Run != nil || m.Native.Extended {
		return nil
	}
	control := m.modeControl()
	state, e := m.modeState()
	if e != nil || !state.Owned {
		return e
	}
	if checkForeign {
		current, e := m.configFingerprints()
		if e != nil {
			return e
		}
		a, _ := json.Marshal(current)
		b, _ := json.Marshal(state.Baseline)
		if !bytes.Equal(a, b) {
			return fmt.Errorf("其他 Nginx 配置在接管后发生变化，保留扩展模式以免系统自恢复清除这些修改；请检查后人工恢复")
		}
	}
	b, e := os.ReadFile(control.Path)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e == nil && !bytes.Equal(b, []byte(extensionContent)) {
		return fmt.Errorf("扩展模式配置发生外部修改，保留文件")
	}
	if e := os.Remove(control.Path); e != nil && !os.IsNotExist(e) {
		return e
	}
	if e := control.Run("daemon-reload"); e != nil {
		return e
	}
	if e := control.Run("restart", "trim_nginx"); e != nil {
		return e
	}
	return m.saveMode(modeState{})
}
