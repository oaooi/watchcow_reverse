package reverse

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"watchcow/internal/app"
)

type probeResult struct {
	at  time.Time
	err error
}

type Manager struct {
	Mode           *ModeControl
	mu             sync.Mutex
	updateMu       sync.Mutex
	Dir            string
	AppsDir        string
	Native         *Native
	Registry       *app.Registry
	settings       Settings
	journal        journal
	routes         map[string]Route // hostname -> route, including disabled tombstones
	rows           []Route
	lastError      string
	lastApply      time.Time
	probes         map[string]probeResult
	Probe          func(context.Context, string) error
	Resolve        func(context.Context, *app.App, app.Entry) (string, error)
	LiveState      func(context.Context) (map[string]bool, error)
	csrf           string
	oldRunning     func() bool
	controlOld     func(string) error
	desktopBusy    map[string]bool
	desktopError   string
	desktopCurrent string
	SyncDesktop    func(context.Context, string) error
	icons          map[string]iconState
}

func New(dir string, registry *app.Registry) (*Manager, error) {
	s, err := Load(dir)
	if err != nil {
		return nil, err
	}
	m := &Manager{Dir: dir, AppsDir: "/var/apps", Native: NewNative(dir), Registry: registry, settings: s, journal: journal{Files: map[string]fileBackup{}}, routes: map[string]Route{}, probes: map[string]probeResult{}}
	m.oldRunning = oldWatchcowRunning
	m.controlOld = controlOld
	m.SyncDesktop = func(ctx context.Context, id string) error {
		return (&DesktopMigrator{Dir: m.Dir, AppsDir: m.AppsDir}).Sync(ctx, id)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "backup", "migration.json")); err == nil {
		if err := json.Unmarshal(data, &m.journal); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if m.journal.Files == nil {
		m.journal.Files = map[string]fileBackup{}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "routes.json")); err == nil {
		if err := json.Unmarshal(data, &m.routes); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if m.routes == nil {
		m.routes = map[string]Route{}
	}
	m.csrf, err = token()
	if err != nil {
		return nil, err
	}
	return m, nil
}

func webProbe(ctx context.Context, upstream string) error {
	// This only identifies HTTP; native Nginx performs actual data transport.
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true} // local self-signed services supported
	defer transport.CloseIdleConnections()
	c := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, upstream+"/", nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (m *Manager) probe(ctx context.Context, upstream string) error {
	if cached, ok := m.probes[upstream]; ok && time.Since(cached.at) < 30*time.Second {
		return cached.err
	}
	f := m.Probe
	if f == nil {
		f = webProbe
	}
	err := f(ctx, upstream)
	m.probes[upstream] = probeResult{time.Now(), err}
	return err
}

func routePath(path string) (string, error) {
	if path == "" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\r\n\\") {
		return "", fmt.Errorf("无效入口路径")
	}
	return path, nil
}

func (m *Manager) saveRoutes() error {
	b, err := json.MarshalIndent(m.routes, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.Dir, "routes.json"), b, 0600)
}
func (m *Manager) routeList() []Route {
	routes := make([]Route, 0, len(m.routes))
	for _, r := range m.routes {
		routes = append(routes, r)
	}
	return routes
}

func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.oldRunning() {
		return m.fail(fmt.Errorf("检测到旧 WatchCow 同时运行；请停止旧应用后重试"))
	}
	settings, err := Load(m.Dir)
	if err != nil {
		return m.fail(err)
	}
	m.settings = settings
	if m.settings.Domain == "" {
		return m.fail(fmt.Errorf("请先配置基础域名"))
	}
	previous := make(map[string]Route, len(m.routes))
	for h, r := range m.routes {
		previous[h] = r
	}
	committed := false
	defer func() {
		if !committed {
			m.routes = previous
		}
	}()
	for host, r := range m.routes {
		if m.desktopBusy[r.AppName] {
			continue
		}
		r.Active = false
		r.Message = "容器未运行或入口已移除"
		m.routes[host] = r
	}
	apps := m.Registry.List()
	sort.Slice(apps, func(i, j int) bool { return apps[i].ContainerName < apps[j].ContainerName })
	var live map[string]bool
	if m.LiveState != nil {
		var err error
		live, err = m.LiveState(ctx)
		if err != nil {
			return m.fail(err)
		}
	}
	rows := []Route{}
	for _, row := range m.rows {
		if m.desktopBusy[row.AppName] {
			rows = append(rows, row)
		}
	}
	type action struct {
		app    *app.App
		routes []Route
	}
	var actions []action
	for _, a := range apps {
		if m.desktopBusy[a.AppName] {
			continue
		}
		if live != nil {
			running, exists := live[a.ContainerName]
			if !exists {
				continue
			}
			copy := *a
			a = &copy
			a.Status = app.StatusStopped
			if running {
				a.Status = app.StatusRunning
			}
		}
		if _, err := os.Stat(filepath.Join(m.AppsDir, a.AppName, "target", "ui", "config")); os.IsNotExist(err) {
			continue
		}
		var appRoutes []Route
		for _, e := range a.Entries {
			// Correct legacy desktop labels without recreating a business
			// container. Resolution still requires an actual Docker binding.
			override := m.settings.Entries[key(a, e)]
			if override.Protocol != "" {
				e.Protocol = override.Protocol
			}
			if override.Port != "" {
				e.Port = override.Port
			}
			r := Route{Key: key(a, e), AppName: a.AppName, Entry: e.Name, Message: "待检测", Nginx: override.Nginx, CustomLocations: override.CustomLocations}
			ok, reason := eligible(m.settings, a, e)
			if !ok {
				r.Message = reason
				rows = append(rows, r)
				continue
			}
			host, err := m.settings.name(a, e)
			if err != nil {
				r.Message = err.Error()
				rows = append(rows, r)
				continue
			}
			r.Host = host
			protocol := e.Protocol
			if protocol == "" {
				protocol = "http"
			}
			r.Upstream = protocol + "://127.0.0.1:" + e.Port
			if override.Upstream != "" {
				r.Upstream = override.Upstream
			}
			if m.Resolve != nil && override.Upstream == "" {
				resolved, resolveErr := m.Resolve(ctx, a, e)
				err = resolveErr
				if err != nil {
					if previous, ok := m.routes[host]; ok {
						r.Upstream = previous.Upstream
					} else if a.Status == app.StatusRunning {
						r.Message = err.Error()
						rows = append(rows, r)
						continue
					}
				} else {
					r.Upstream = resolved
				}
			}
			r.Path, err = routePath(e.Path)
			if err != nil {
				r.Message = err.Error()
				rows = append(rows, r)
				continue
			}
			if a.Status == app.StatusRunning {
				probeTarget, _ := rootProxyOrigin(r)
				var probeErr error
				if probeTarget != "" {
					probeErr = m.probe(ctx, probeTarget)
				}
				if err := probeErr; err != nil {
					r.Message = "未检测到 HTTP 响应，暂不接管: " + err.Error()
					// Existing launchers keep a 503 vhost while the backend is down.
					if _, owned := m.routes[host]; !owned {
						rows = append(rows, r)
						continue
					}
				} else {
					r.Active = true
					r.Message = "反代已就绪"
				}
			} else {
				r.Message = "容器未运行"
			}
			m.routes[host] = r
			appRoutes = append(appRoutes, r)
			rows = append(rows, r)
		}
		// Persist names before generating any desktop or native config.
		if err := m.settings.Save(m.Dir); err != nil {
			return m.fail(err)
		}
		actions = append(actions, action{a, appRoutes})
	}
	m.rows = rows
	if err := m.Native.Apply(m.routeList(), false, false); err != nil {
		return m.fail(err)
	}
	// Native routing is validated first. If a desktop-file mutation fails,
	// restore this cycle's files and previous routes, retaining the first
	// migration backup for a later full rollback.
	var before []fileBackup
	journalBefore := map[string]fileBackup{}
	for p, b := range m.journal.Files {
		journalBefore[p] = b
	}
	rollback := func(cause error) error {
		var restoreErrors []error
		for _, f := range before {
			current, e := os.ReadFile(f.Path)
			if e != nil && !os.IsNotExist(e) {
				restoreErrors = append(restoreErrors, e)
				continue
			}
			if rec, ok := m.journal.Files[f.Path]; ok && e == nil && digest(current) != rec.WrittenHash && digest(current) != digest(f.Original) {
				restoreErrors = append(restoreErrors, fmt.Errorf("保留外部修改: %s", f.Path))
				continue
			}
			if f.Existed {
				e = atomicWrite(f.Path, f.Original, os.FileMode(f.Mode))
			} else {
				e = os.Remove(f.Path)
				if os.IsNotExist(e) {
					e = nil
				}
			}
			if e != nil {
				restoreErrors = append(restoreErrors, e)
			}
		}
		if len(restoreErrors) == 0 {
			m.journal.Files = journalBefore
			if e := m.saveJournal(); e != nil {
				restoreErrors = append(restoreErrors, e)
			}
		}
		m.routes = previous
		if e := m.Native.Apply(m.routeList(), false, false); e != nil {
			restoreErrors = append(restoreErrors, e)
		}
		return m.fail(errors.Join(append([]error{cause}, restoreErrors...)...))
	}
	for _, a := range actions {
		for _, name := range []string{"config", "index.cgi"} {
			p := filepath.Join(m.AppsDir, a.app.AppName, "target", "ui", name)
			data, e := os.ReadFile(p)
			if e != nil && !os.IsNotExist(e) {
				return rollback(e)
			}
			mode := os.FileMode(0644)
			if info, e := os.Stat(p); e == nil {
				mode = info.Mode().Perm()
			}
			before = append(before, fileBackup{Path: p, Original: data, Existed: e == nil, Mode: uint32(mode)})
		}
		if err := m.patchLauncher(a.app, a.routes); err != nil {
			return rollback(err)
		}
	}
	if err := m.saveRoutes(); err != nil {
		return rollback(err)
	}
	committed = true
	m.lastError = ""
	m.lastApply = time.Now()
	return nil
}

func (m *Manager) fail(err error) error { m.lastError = err.Error(); return err }

func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Reconcile(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("Watchcow_R reconcile", "error", err)
			}
		}
	}
}

func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Native.Apply(m.routeList(), true, false)
}

func (m *Manager) patchLauncher(a *app.App, routes []Route) error {
	path := filepath.Join(m.AppsDir, a.AppName, "target", "ui", "config")
	if len(routes) == 0 && !a.HasRedirect() {
		if _, owned := m.journal.Files[path]; !owned {
			return nil
		}
	}
	if err := m.archiveApp(a.AppName); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	var entries map[string]map[string]interface{}
	if err := json.Unmarshal(cfg[".url"], &entries); err != nil {
		return err
	}
	// Undo only our URL/protocol/port fields when a proxy override is disabled.
	var originals map[string]map[string]interface{}
	if rec, ok := m.journal.Files[path]; ok {
		var original map[string]json.RawMessage
		if json.Unmarshal(rec.Original, &original) == nil {
			_ = json.Unmarshal(original[".url"], &originals)
		}
	}
	for id, entry := range entries {
		if u, _ := entry["url"].(string); strings.HasPrefix(u, "/cgi/ThirdParty/"+a.AppName+"/index.cgi/proxy/") {
			name := ""
			if id != a.AppName {
				name = strings.TrimPrefix(id, a.AppName+".")
			}
			if desired := a.GetEntry(name); desired != nil && desired.Redirect == "" {
				protocol := desired.Protocol
				if protocol == "" {
					protocol = "http"
				}
				entry["protocol"] = protocol
				entry["port"] = desired.Port
				path := desired.Path
				if path == "" {
					path = "/"
				}
				entry["url"] = path
			} else if original := originals[id]; original != nil {
				for _, field := range []string{"url", "protocol", "port"} {
					if v, ok := original[field]; ok {
						entry[field] = v
					} else {
						delete(entry, field)
					}
				}
			}
		}
		name := ""
		if id != a.AppName {
			name = strings.TrimPrefix(id, a.AppName+".")
		}
		if desired := a.GetEntry(name); desired != nil && desired.Redirect != "" {
			entry["protocol"] = ""
			delete(entry, "port")
		}
	}
	// Preserve later title/icon/permission edits even after another reconcile
	// adopts the file. Only the URL routing fields belong to this controller.
	if rec, ok := m.journal.Files[path]; ok && rec.Existed {
		baseEntries, _ := json.Marshal(entries)
		base := map[string]json.RawMessage{}
		for k, v := range cfg {
			base[k] = v
		}
		base[".url"] = baseEntries
		baseline, _ := json.Marshal(base)
		rebased, err := mergeDesktopBaseline(rec.Original, baseline)
		if err != nil {
			return err
		}
		if string(rebased) != string(rec.Original) {
			rec.Original = rebased
			m.journal.Files[path] = rec
			if err := m.saveJournal(); err != nil {
				return err
			}
		}
	}
	for _, r := range routes {
		id := a.AppName
		name := r.Entry
		if name == "" {
			name = "_"
		} else {
			id += "." + name
		}
		entry, ok := entries[id]
		if !ok {
			return fmt.Errorf("找不到桌面入口 %s", id)
		}
		entry["protocol"] = ""
		delete(entry, "port")
		entry["url"] = "/cgi/ThirdParty/" + a.AppName + "/index.cgi/proxy/" + a.AppName + "/" + name
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	cfg[".url"] = encoded
	next, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if len(routes) > 0 || a.HasRedirect() {
		// A shared CGI dispatcher preserves legacy external redirect entries.
		cgi := []byte("#!/bin/sh\nexec \"/var/apps/watchcow-r/target/watchcow-r\" --mode cgi --cgi-app \"" + a.AppName + "\" --socket \"/var/apps/watchcow-r/var/watchcow.sock\"\n")
		if err := m.trackedWrite(filepath.Join(m.AppsDir, a.AppName, "target", "ui", "index.cgi"), cgi, 0755); err != nil {
			return err
		}
	}
	return m.trackedWrite(path, append(next, '\n'), 0644)
}

func mergeDesktopBaseline(original, baseline []byte) ([]byte, error) {
	var old, next map[string]json.RawMessage
	if err := json.Unmarshal(original, &old); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(baseline, &next); err != nil {
		return nil, err
	}
	var a, b map[string]map[string]interface{}
	if err := json.Unmarshal(old[".url"], &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(next[".url"], &b); err != nil {
		return nil, err
	}
	for id, entry := range b {
		if prior := a[id]; prior != nil {
			for _, field := range []string{"url", "port", "protocol"} {
				if value, ok := prior[field]; ok {
					entry[field] = value
				} else {
					delete(entry, field)
				}
			}
		}
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	next[".url"] = data
	data, err = json.MarshalIndent(next, "", "  ")
	if err != nil {
		return nil, err
	}
	var x, y interface{}
	_ = json.Unmarshal(original, &x)
	_ = json.Unmarshal(data, &y)
	cx, _ := json.Marshal(x)
	cy, _ := json.Marshal(y)
	if string(cx) == string(cy) {
		return original, nil
	}
	return append(data, '\n'), nil
}

// Diagnostics checks DNS and certificate selection without copying private keys.
// Verification uses the browser's front-end TLS port, not the backend protocol.
func diagnostics(ctx context.Context, host string, httpsPort string) (string, string) {
	dns := "DNS 未解析"
	if ips, err := net.DefaultResolver.LookupHost(ctx, host); err == nil && len(ips) > 0 {
		dns = strings.Join(ips, ", ")
	}
	cert := "未启用 HTTPS"
	if httpsPort != "" {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", httpsPort))
		if err != nil {
			cert = "证书未通过校验：请在飞牛证书管理配置 *.<基础域名> 证书"
		} else {
			conn.Close()
			cert = "证书有效"
		}
	}
	return dns, cert
}
