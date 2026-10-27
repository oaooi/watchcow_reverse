package reverse

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"watchcow/internal/fpkgen"
)

func token() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

var setup = template.Must(template.New("setup").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Watchcow_R</title><body style="max-width:760px;margin:60px auto;padding:24px;font:17px/1.8 system-ui"><h1>Watchcow_R 已安装</h1><p>此版本飞牛需要启用 Nginx 扩展模式才能保留反代配置。默认保持系统设置和原 WatchCow 的运行状态。</p><p>如果接受以下变化，请在应用中心打开 Watchcow_R 的配置，将「允许 Nginx 扩展模式」填写为 <code>true</code>：飞牛 Web 服务会重启一次，已有网页连接可能中断；扩展期间暂停 Nginx 配置自恢复，卸载时恢复。Docker 业务容器不会重启。</p><p>配置保存后将自动开始接管。请随后刷新本页，并在 DNS 中配置泛域名解析、在飞牛中配置覆盖子域名的 HTTPS 证书。</p></body></html>`))

func (m *Manager) SetupPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = setup.Execute(w, nil)
}

var launcher = template.Must(template.New("launcher").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Watchcow_R</title><script>
const target = new URL(window.location.href);
target.hostname = {{.Host}};
const appPath = new URL({{.Path}}, window.location.origin);
target.pathname = appPath.pathname;
// File-open parameters and application query strings are preserved.
for (const [key,value] of new URL(window.location.href).searchParams) appPath.searchParams.append(key,value);
target.search = appPath.search;
target.hash = appPath.hash || window.location.hash;
window.location.replace(target.href);
</script></html>`))

// Launch inherits scheme and port directly from the browser's current URL.
// There is no LAN probe, external-host input, or forced protocol downgrade.
func (m *Manager) Launch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/proxy/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	entry := parts[1]
	if entry == "_" {
		entry = ""
	}
	m.mu.Lock()
	var route Route
	for _, row := range m.rows {
		if row.AppName == parts[0] && row.Entry == entry && row.Host != "" {
			route = row
			break
		}
	}
	_, applied := m.routes[route.Host]
	problem := m.lastError
	m.mu.Unlock()
	if route.Host == "" || !applied || problem != "" {
		http.Error(w, "Watchcow_R 反代尚未就绪，请查看管理员控制面板", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = launcher.Execute(w, route)
}

type panelRow struct {
	Route
	Override       Override
	Title          string
	Icon           template.URL
	IconMessage    string
	IconSource     string
	ConfiguredIcon bool
}

type panelData struct {
	Domain, CSRF, Error, Applied string
	DesktopError, DesktopCurrent string
	Rows                         []panelRow
}

//go:embed panel.html
var panelHTML string
var panel = template.Must(template.New("panel").Parse(panelHTML))

func panelSaved(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
}

func (m *Manager) Panel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "无效表单", 400)
			return
		}
		if r.Form.Get("csrf") != m.csrf {
			http.Error(w, "请刷新管理页面后重试", 403)
			return
		}
		// fnOS enforces administrator access on this root package's CGI entry.
		// Reject cross-origin form submissions as an additional CSRF safeguard.
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "无效来源", 403)
				return
			}
		}
		m.updateMu.Lock()
		defer m.updateMu.Unlock()
		m.mu.Lock()
		previous, loadErr := Load(m.Dir)
		if loadErr != nil {
			m.mu.Unlock()
			http.Error(w, loadErr.Error(), 500)
			return
		}
		next, loadErr := Load(m.Dir)
		if loadErr != nil {
			m.mu.Unlock()
			http.Error(w, loadErr.Error(), 500)
			return
		}
		if k := r.Form.Get("key"); k != "" {
			found := false
			for _, row := range m.rows {
				if row.Key == k {
					found = true
				}
			}
			if !found {
				m.mu.Unlock()
				http.Error(w, "入口不存在", 404)
				return
			}
			if r.Form.Get("action") == "refresh-icon" {
				m.loadIcons()
				state := m.icons[k]
				state.Checked = time.Time{}
				m.icons[k] = state
				err := m.saveIcons()
				m.mu.Unlock()
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				panelSaved(w, r)
				return
			}
			o := next.Entries[k]
			o.Subdomain = strings.ToLower(strings.TrimSpace(r.Form.Get("subdomain")))
			if o.Subdomain != "" && !dnsLabel.MatchString(o.Subdomain) {
				m.mu.Unlock()
				http.Error(w, "无效子域名", 400)
				return
			}
			switch r.Form.Get("enabled") {
			case "auto":
				o.Enabled = nil
			case "true":
				v := true
				o.Enabled = &v
			case "false":
				v := false
				o.Enabled = &v
			default:
				m.mu.Unlock()
				http.Error(w, "无效开关", 400)
				return
			}
			if r.Form.Get("editor") == "full" {
				o.Upstream = strings.TrimSuffix(strings.TrimSpace(r.Form.Get("upstream")), "/")
				o.Protocol = r.Form.Get("protocol")
				o.Port = strings.TrimSpace(r.Form.Get("port"))
				if o.Protocol != "" && o.Protocol != "http" && o.Protocol != "https" {
					m.mu.Unlock()
					http.Error(w, "无效后端协议", 400)
					return
				}
				if o.Port != "" {
					v, e := strconv.Atoi(o.Port)
					if e != nil || v < 1 || v > 65535 {
						m.mu.Unlock()
						http.Error(w, "无效后端端口", 400)
						return
					}
				}
				o.Nginx = r.Form.Get("nginx")
				o.IconMode = r.Form.Get("icon_mode")
				if o.IconMode == "auto" {
					o.IconMode = ""
				}
				o.CustomLocations = nil
				paths, upstreams, configs := r.Form["location_path"], r.Form["location_upstream"], r.Form["location_nginx"]
				if len(paths) != len(upstreams) || len(paths) != len(configs) {
					m.mu.Unlock()
					http.Error(w, "无效位置表单", 400)
					return
				}
				for i, path := range paths {
					path = strings.TrimSpace(path)
					u := strings.TrimSpace(upstreams[i])
					if path == "" && u == "" && strings.TrimSpace(configs[i]) == "" {
						continue
					}
					o.CustomLocations = append(o.CustomLocations, CustomLocation{Path: path, Upstream: u, Nginx: configs[i]})
				}
			}
			if err := validateOverride(o); err != nil {
				m.mu.Unlock()
				http.Error(w, err.Error(), 400)
				return
			}
			if reflect.DeepEqual(o, Override{}) {
				delete(next.Entries, k)
			} else {
				next.Entries[k] = o
			}
		} else {
			domain, err := ValidateDomain(r.Form.Get("domain"))
			if err != nil {
				m.mu.Unlock()
				http.Error(w, err.Error(), 400)
				return
			}
			next.Domain = domain
		}
		err := next.Save(m.Dir)
		m.mu.Unlock()
		if err == nil {
			err = m.Reconcile(r.Context())
		}
		if err != nil {
			// A failed Nginx test must not leave an invalid desired config
			// retrying forever. Keep serving the previous, working routes.
			m.mu.Lock()
			current, e := Load(m.Dir)
			if e == nil && current.Domain == next.Domain && reflect.DeepEqual(current.Entries, next.Entries) {
				e = previous.Save(m.Dir)
			} else if e == nil {
				e = fmt.Errorf("设置发生外部修改，保留现状")
			}
			m.mu.Unlock()
			if e == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				e = m.Reconcile(ctx)
				cancel()
			}
			if e != nil {
				err = fmt.Errorf("%w；恢复设置: %v", err, e)
			}
			http.Error(w, "保存未生效，原反代配置已保留："+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		panelSaved(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	m.mu.Lock()
	data := panelData{Domain: m.settings.Domain, CSRF: m.csrf, Error: m.lastError, Applied: m.lastApply.Format("2006-01-02 15:04:05")}
	data.DesktopError, data.DesktopCurrent = m.desktopError, m.desktopCurrent
	m.loadIcons()
	for _, route := range m.rows {
		override := m.settings.Entries[route.Key]
		row := panelRow{Route: route, Override: override, Title: route.AppName, IconMessage: "等待获取网页图标"}
		row.Subdomain = override.Subdomain
		row.Mode = "auto"
		if override.Enabled != nil {
			row.Mode = "false"
			if *override.Enabled {
				row.Mode = "true"
			}
		}
		a := m.Registry.Get(route.AppName)
		if a != nil {
			row.Title = a.DisplayName
			if e := a.GetEntry(route.Entry); e != nil && !fpkgen.AutomaticIcon(a, *e) {
				row.IconMessage = "使用已设置图标"
				row.ConfiguredIcon = true
			}
		}
		if override.IconMode == "keep" {
			row.IconMessage = "保留现有图标"
		}
		state := m.icons[route.Key]
		if state.Message != "" && row.IconMessage == "等待获取网页图标" {
			row.IconMessage = state.Message
			row.IconSource = state.Source
		}
		preview := state.Preview
		if row.ConfiguredIcon || override.IconMode == "keep" {
			preview = nil
		}
		if len(preview) == 0 && desktopID.MatchString(route.AppName) && iconEntryID.MatchString(route.Entry) {
			stem := "icon"
			if route.Entry != "" {
				stem += "_" + route.Entry
			}
			if b, e := os.ReadFile(filepath.Join(m.AppsDir, route.AppName, "target", "ui", "images", stem+"_64.png")); e == nil && len(b) < 256<<10 {
				preview = b
			}
		}
		if len(preview) > 0 {
			row.Icon = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(preview))
		}
		data.Rows = append(data.Rows, row)
	}
	m.mu.Unlock()
	layout, _ := m.Native.Layout()
	// Bound total diagnostics work and parallelism so the admin CGI stays
	// responsive even when wildcard DNS has not been configured yet.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		i         int
		dns, cert string
	}
	results := make(chan result, len(data.Rows))
	sem := make(chan struct{}, 4)
	count := 0
	for i, row := range data.Rows {
		if row.Host == "" {
			continue
		}
		count++
		go func(i int, host string) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{i, "诊断超时", "未验证"}
				return
			}
			dns, cert := diagnostics(ctx, host, layout.HTTPSPort)
			results <- result{i, dns, cert}
		}(i, row.Host)
	}
	for i := 0; i < count; i++ {
		res := <-results
		data.Rows[res.i].DNS = res.dns
		data.Rows[res.i].Certificate = res.cert
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = panel.Execute(w, data)
}
