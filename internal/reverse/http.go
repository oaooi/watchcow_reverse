package reverse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
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

var launcher = template.Must(template.New("launcher").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Watchcow_R</title><p>正在打开应用…</p><script>
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

type panelData struct {
	Domain, CSRF, Error, Applied string
	Rows                         []Route
}

var panel = template.Must(template.New("panel").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Watchcow_R · 反向代理</title><style>
body{font:15px system-ui,sans-serif;margin:0;background:#f5f7fb;color:#1e293b}main{max-width:1200px;margin:36px auto;padding:0 24px}h1{margin-bottom:8px}p{line-height:1.7}section,article{background:white;border:1px solid #dbe2ed;border-radius:12px;padding:22px;margin:18px 0}input,select,button{font:inherit;padding:8px 12px;border:1px solid #cbd5e1;border-radius:6px}button{background:#245fe5;color:white;cursor:pointer}label{display:inline-block;margin:8px 18px 8px 0}.error{color:#a62222}code{overflow-wrap:anywhere}small{color:#64748b}a{color:#245fe5}.row{display:flex;flex-wrap:wrap;align-items:center;gap:12px}h2{font-size:18px}
</style></head><body><main><a href="./">← 容器管理</a><h1>Watchcow_R</h1><p>通过飞牛现有端口访问容器应用。点击桌面图标时，自动沿用当前浏览器的 HTTP/HTTPS 和端口。</p>
{{if .Error}}<section class="error">应用配置失败：{{.Error}}</section>{{end}}
<section><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>基础域名 <input name="domain" value="{{.Domain}}" required></label><button>保存并应用</button></form><p>请将 <code>*.{{.Domain}}</code> 解析到 NAS。HTTPS 证书请通过飞牛的证书管理配置，证书必须覆盖对应子域名。应用保留自己的登录认证。</p><small>最近同步：{{.Applied}} · 诊断结果在打开本页时更新</small></section>
{{range .Rows}}<article><h2>{{.AppName}}{{if .Entry}} / {{.Entry}}{{end}}</h2><p>{{.Message}}</p>{{if .Host}}<p>访问地址：<a class="app-link" data-host="{{.Host}}" data-path="{{.Path}}" target="_blank" rel="noreferrer">{{.Host}}</a><br>后端：<code>{{.Upstream}}</code><br>DNS：{{.DNS}}<br>HTTPS：{{.Certificate}}</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="key" value="{{.Key}}"><label>反代 <select name="enabled"><option value="auto"{{if eq .Mode "auto"}} selected{{end}}>自动检测</option><option value="true"{{if eq .Mode "true"}} selected{{end}}>启用</option><option value="false"{{if eq .Mode "false"}} selected{{end}}>关闭</option></select></label><label>自定义子域名 <input name="subdomain" value="{{.Subdomain}}" placeholder="留空使用容器名" pattern="[a-z0-9-]+"></label><button>应用到入口</button></form></article>{{end}}
<section><p>停止 Watchcow_R 后反代入口返回 503，业务容器保持原状态。卸载前会恢复备份的桌面入口和旧 WatchCow 的运行状态；发生外部修改时会保留文件并报告冲突。</p></section>
</main><script>document.querySelectorAll('.app-link').forEach(a=>{const u=new URL(location.href);u.hostname=a.dataset.host;u.pathname=a.dataset.path;u.search='';u.hash='';a.href=u.href;});</script></body></html>`))

func (m *Manager) Panel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
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
		m.mu.Lock()
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
			o := Override{Subdomain: strings.ToLower(strings.TrimSpace(r.Form.Get("subdomain")))}
			if o.Subdomain != "" && !dnsLabel.MatchString(o.Subdomain) {
				m.mu.Unlock()
				http.Error(w, "无效子域名", 400)
				return
			}
			switch r.Form.Get("enabled") {
			case "auto":
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
			m.settings.Entries[k] = o
		} else {
			domain, err := ValidateDomain(r.Form.Get("domain"))
			if err != nil {
				m.mu.Unlock()
				http.Error(w, err.Error(), 400)
				return
			}
			m.settings.Domain = domain
		}
		err := m.settings.Save(m.Dir)
		m.mu.Unlock()
		if err == nil {
			err = m.Reconcile(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	m.mu.Lock()
	data := panelData{Domain: m.settings.Domain, CSRF: m.csrf, Error: m.lastError, Applied: m.lastApply.Format("2006-01-02 15:04:05"), Rows: append([]Route(nil), m.rows...)}
	for i := range data.Rows {
		override := m.settings.Entries[data.Rows[i].Key]
		data.Rows[i].Subdomain = override.Subdomain
		data.Rows[i].Mode = "auto"
		if override.Enabled != nil {
			if *override.Enabled {
				data.Rows[i].Mode = "true"
			} else {
				data.Rows[i].Mode = "false"
			}
		}
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
