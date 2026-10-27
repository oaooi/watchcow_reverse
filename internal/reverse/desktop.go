package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"watchcow/internal/fpkgen"
)

// DesktopMigrator re-registers generated desktop packages through the official
// CLI. Changing ui/config alone does not change fnOS's persisted desktop entry.
// It never writes fnOS databases, runs unrecognised lifecycle scripts, or calls
// a Docker mutation API. Pending stages survive a daemon/process interruption.
type DesktopMigrator struct {
	Dir, AppsDir string
	Run          func(context.Context, string, ...string) ([]byte, error)
	VolumeReady  func(int) error
}

type desktopPending struct {
	AppName   string `json:"app_name"`
	Volume    int    `json:"volume"`
	AutoStart bool   `json:"auto_start"`
}

type desktopRegistration struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var desktopID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$`)

func desktopVolumeReady(volume int) error {
	path := "/vol" + strconv.Itoa(volume)
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("原安装卷不可用，保留原包: %w", err)
	}
	root, err := os.Stat("/")
	if err != nil {
		return err
	}
	if info.Sys().(*syscall.Stat_t).Dev == root.Sys().(*syscall.Stat_t).Dev {
		return fmt.Errorf("原安装卷 %s 未挂载，保留原包", path)
	}
	return nil
}

func desktopExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = "/"
	return cmd.Output()
}

func (d *DesktopMigrator) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	if d.Run != nil {
		return d.Run(ctx, name, args...)
	}
	return desktopExec(ctx, name, args...)
}

func (d *DesktopMigrator) query(ctx context.Context, db, sql string) ([]byte, error) {
	b, err := d.command(ctx, "runuser", "-u", "postgres", "--", "psql", "-d", db, "-At", "-c", sql)
	if err != nil {
		return nil, fmt.Errorf("读取飞牛桌面登记失败 (%s): %w", db, err)
	}
	return b, nil
}

func desktopConfig(path string) (map[string]map[string]interface{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg map[string]map[string]map[string]interface{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if len(cfg[".url"]) == 0 {
		return nil, fmt.Errorf("没有桌面入口")
	}
	return cfg[".url"], nil
}

func (d *DesktopMigrator) registered(ctx context.Context, id string, cfg map[string]map[string]interface{}) (bool, error) {
	raw, err := d.query(ctx, "trim_sac", "SELECT coalesce(json_agg(json_build_object('name',service_name,'url',url)),'[]') FROM entry WHERE source='trim.app-center' AND app_name='"+id+"';")
	if err != nil {
		return false, err
	}
	var rows []desktopRegistration
	if err := json.Unmarshal(raw, &rows); err != nil {
		return false, err
	}
	urls := map[string]map[string]interface{}{}
	for _, row := range rows {
		var fields map[string]interface{}
		if err := json.Unmarshal([]byte(row.URL), &fields); err != nil {
			return false, err
		}
		urls[row.Name] = fields
	}
	field := func(v map[string]interface{}, key string) string { value, _ := v[key].(string); return value }
	for name, expected := range cfg {
		actual, ok := urls[name]
		if !ok {
			return false, nil
		}
		for _, pair := range [][2]string{{"protocol", "protocol"}, {"port", "port"}, {"url", "path"}} {
			want, got := field(expected, pair[0]), field(actual, pair[1])
			// fnOS omits the protocol for relative entries with no service
			// port, including hidden database/helper icons generated upstream.
			if pair[0] == "protocol" && field(expected, "port") == "" && got == "" {
				continue
			}
			if pair[0] == "url" {
				if want == "" {
					want = "/"
				}
				if got == "" {
					got = "/"
				}
			}
			if want != got {
				return false, nil
			}
		}
	}
	return true, nil
}

func copyDesktopTree(source, dest string) error {
	root, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("拒绝复制非普通文件: %s", path)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}

// Only exact generated status-only main scripts and empty lifecycle callbacks
// may be reinstalled automatically. Modified/user-authored packages stay intact.
func safeDesktopScripts(dir string) error {
	main, err := os.ReadFile(filepath.Join(dir, "cmd", "main"))
	if err != nil {
		return err
	}
	match := regexp.MustCompile(`(?m)^# Container: ([a-zA-Z0-9][a-zA-Z0-9_.-]*)$`).FindStringSubmatch(string(main))
	if len(match) != 2 {
		return fmt.Errorf("不是受支持的 WatchCow 桌面包装包")
	}
	templates, err := fpkgen.NewTemplateEngine()
	if err != nil {
		return err
	}
	expected, err := templates.Render("cmd_main.tmpl", &fpkgen.TemplateData{ContainerName: match[1]})
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(main)) != strings.TrimSpace(string(expected)) {
		return fmt.Errorf("启动脚本已修改，保留原包")
	}
	files, err := os.ReadDir(filepath.Join(dir, "cmd"))
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.Name() == "main" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "cmd", f.Name()))
		if err != nil {
			return err
		}
		var commands []string
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				commands = append(commands, line)
			}
		}
		if strings.Join(commands, "\n") != "exit 0" {
			return fmt.Errorf("生命周期脚本已修改: %s", f.Name())
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "config", "resource")); err == nil {
		var resource map[string]interface{}
		if json.Unmarshal(b, &resource) != nil || len(resource) != 0 {
			return fmt.Errorf("保留含额外资源操作的应用包")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func safeDesktopManifest(dir, id string) error {
	b, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		return err
	}
	allowed := strings.Fields("appname version display_name desc arch platform source maintainer maintainer_url distributor distributor_url os_min_version install_type desktop_uidir desktop_applaunchname service_port checkport checksum")
	keys := map[string]bool{}
	for _, k := range allowed {
		keys[k] = true
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || !keys[key] {
			return fmt.Errorf("保留含额外安装操作的 manifest: %s", key)
		}
		if key == "appname" {
			if value != id {
				return fmt.Errorf("桌面包标识不匹配")
			}
			found = true
		}
		if key == "desktop_uidir" && value != "" && value != "ui" {
			return fmt.Errorf("不支持的桌面目录")
		}
	}
	if !found {
		return fmt.Errorf("manifest 缺少应用标识")
	}
	return nil
}

func (d *DesktopMigrator) Candidates() ([]string, error) {
	entries, err := os.ReadDir(d.AppsDir)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, e := range entries {
		if !desktopID.MatchString(e.Name()) || e.Name() == "watchcow" || e.Name() == AppID {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d.AppsDir, e.Name(), "cmd", "main"))
		if err == nil && strings.Contains(string(b), "Generated by WatchCow") {
			found[e.Name()] = true
		}
	}
	// An interrupted uninstall may have removed /var/apps/<id> entirely.
	pending, err := os.ReadDir(filepath.Join(d.Dir, "desktop", "pending"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range pending {
		if e.IsDir() && desktopID.MatchString(e.Name()) {
			found[e.Name()] = true
		}
	}
	var ids []string
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func (d *DesktopMigrator) Sync(ctx context.Context, id string) error {
	if !desktopID.MatchString(id) || id == "watchcow" || id == AppID {
		return fmt.Errorf("无效桌面包标识")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stage := filepath.Join(d.Dir, "desktop", "pending", id)
	pendingPath := filepath.Join(stage, "pending.json")
	var pending desktopPending
	if b, err := os.ReadFile(pendingPath); err == nil {
		if err := json.Unmarshal(b, &pending); err != nil {
			return err
		}
		if pending.AppName != id || pending.Volume < 1 {
			return fmt.Errorf("无效的桌面恢复记录")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		live := filepath.Join(d.AppsDir, id)
		if err := safeDesktopScripts(live); err != nil {
			return err
		}
		if err := safeDesktopManifest(live, id); err != nil {
			return err
		}
		cfg, err := desktopConfig(filepath.Join(live, "target", "ui", "config"))
		if err != nil {
			return err
		}
		same, err := d.registered(ctx, id, cfg)
		if err != nil {
			return err
		}
		if same {
			return nil
		}
		raw, err := d.query(ctx, "appcenter", "SELECT row_to_json(a) FROM app a WHERE app_name='"+id+"';")
		if err != nil {
			return err
		}
		var state struct {
			Volume int    `json:"install_volume_id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
		if state.Volume < 1 {
			return fmt.Errorf("无法确定原安装卷，保留原包")
		}
		checkVolume := d.VolumeReady
		if checkVolume == nil {
			checkVolume = desktopVolumeReady
		}
		if err := checkVolume(state.Volume); err != nil {
			return err
		}
		layout, err := d.query(ctx, "trim_sac", "SELECT coalesce(json_agg(d),'[]') FROM user_desktop_entry d WHERE app_name='"+id+"';")
		if err != nil {
			return err
		}
		backup, _ := json.MarshalIndent(struct{ App, Desktop json.RawMessage }{raw, layout}, "", "  ")
		backupPath := filepath.Join(d.Dir, "backup", "desktop", id+".json")
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := atomicWrite(backupPath, backup, 0600); err != nil {
				return err
			}
		}
		// Discard only an incomplete stage made before any CLI operation was started.
		if err := os.RemoveAll(stage); err != nil {
			return err
		}
		if err := os.MkdirAll(stage, 0700); err != nil {
			return err
		}
		for _, part := range [][2]string{{"target", "app"}, {"cmd", "cmd"}, {"config", "config"}} {
			if err := copyDesktopTree(filepath.Join(live, part[0]), filepath.Join(stage, part[1])); err != nil {
				return err
			}
		}
		for _, name := range []string{"manifest", "ICON.PNG", "ICON_256.PNG", "LICENSE"} {
			b, err := os.ReadFile(filepath.Join(live, name))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if name == "manifest" {
				b = regexp.MustCompile(`(?m)^checksum\s*=.*\n?`).ReplaceAll(b, nil)
			}
			if err := atomicWrite(filepath.Join(stage, name), b, 0644); err != nil {
				return err
			}
		}
		pending = desktopPending{AppName: id, Volume: state.Volume, AutoStart: state.Status == "running"}
		b, _ := json.Marshal(pending)
		if err := atomicWrite(pendingPath, b, 0600); err != nil {
			return err
		}
	}
	if err := safeDesktopScripts(stage); err != nil {
		return err
	}
	if err := safeDesktopManifest(stage, id); err != nil {
		return err
	}
	checkVolume := d.VolumeReady
	if checkVolume == nil {
		checkVolume = desktopVolumeReady
	}
	if err := checkVolume(pending.Volume); err != nil {
		return err
	}
	cfg, err := desktopConfig(filepath.Join(stage, "app", "ui", "config"))
	if err != nil {
		return err
	}
	// Finish the current package even if the daemon receives SIGTERM. The stop
	// script waits for this bounded operation; starting another package observes ctx.
	opCtx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	start := "no"
	if pending.AutoStart {
		start = "yes"
	}
	output, installErr := d.command(opCtx, "appcenter-cli", "install-local", "--dir", stage, "--volume", strconv.Itoa(pending.Volume), "--autostart", start)
	if installErr != nil || strings.Contains(string(output), "[Error]") {
		return fmt.Errorf("桌面登记失败，恢复包已保留在 %s: %v", stage, installErr)
	}
	var same bool
	for attempt := 0; attempt < 20; attempt++ {
		same, err = d.registered(opCtx, id, cfg)
		if same && err == nil {
			break
		}
		select {
		case <-opCtx.Done():
			return opCtx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("飞牛仍未登记新地址；恢复包已保留在 %s", stage)
	}
	// A pending package contains a frozen config. A later reconcile will apply any
	// user changes that occurred while it was being re-registered.
	return os.RemoveAll(stage)
}

// RunDesktopSync is a separate worker so a legacy CLI reinstall never blocks
// launch requests. Reconcile pauses only the package currently being registered.
func (m *Manager) RunDesktopSync(ctx context.Context) {
	d := &DesktopMigrator{Dir: m.Dir, AppsDir: m.AppsDir}
	for {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		ready := !m.lastApply.IsZero() && m.lastError == ""
		m.mu.Unlock()
		if ready {
			ids, err := d.Candidates()
			var problems []string
			if err != nil {
				problems = append(problems, err.Error())
			}
			for _, id := range ids {
				if ctx.Err() != nil {
					return
				}
				m.mu.Lock()
				if m.desktopBusy == nil {
					m.desktopBusy = map[string]bool{}
				}
				m.desktopBusy[id] = true
				m.desktopCurrent = id
				archiveErr := m.archiveApp(id)
				m.mu.Unlock()
				syncErr := archiveErr
				if syncErr == nil {
					syncErr = m.SyncDesktop(ctx, id)
				}
				m.mu.Lock()
				delete(m.desktopBusy, id)
				m.desktopCurrent = ""
				m.mu.Unlock()
				if syncErr != nil {
					problems = append(problems, id+": "+syncErr.Error())
					// A CLI operation may have removed the package before failing.
					// Recover it before touching any more desktop packages.
					if _, err := os.Stat(filepath.Join(d.Dir, "desktop", "pending", id, "pending.json")); err == nil {
						break
					}
				}
			}
			m.mu.Lock()
			m.desktopError = strings.Join(problems, "; ")
			m.mu.Unlock()
			status, _ := json.MarshalIndent(struct {
				Checked time.Time `json:"checked"`
				Errors  []string  `json:"errors"`
			}{time.Now(), problems}, "", "  ")
			_ = atomicWrite(filepath.Join(m.Dir, "desktop", "status.json"), status, 0600)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

// RecoverDesktopPending is also used before rollback, so a half-uninstalled
// package is restored before its original launcher files are put back.
func (m *Manager) RecoverDesktopPending(ctx context.Context) error {
	root := filepath.Join(m.Dir, "desktop", "pending")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !desktopID.MatchString(entry.Name()) {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, entry.Name(), "pending.json")); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := m.SyncDesktop(ctx, entry.Name()); err != nil {
			return err
		}
	}
	return nil
}
