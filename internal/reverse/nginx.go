package reverse

import (
	"bytes"
	"context"
	"crypto/tls"
	"debug/elf"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Listener struct {
	Address string
	TLS     bool
}
type Layout struct {
	Listeners           []Listener
	TLS                 string
	ForceHTTPS          bool
	HTTPSPort           string
	CertificateRevision string
}
type Route struct {
	Mode        string `json:"-"`
	Subdomain   string `json:"-"`
	Key         string `json:"key"`
	AppName     string `json:"app_name"`
	Entry       string `json:"entry"`
	Host        string `json:"host"`
	Upstream    string `json:"upstream"`
	Path        string `json:"path"`
	Active      bool   `json:"active"`
	Message     string `json:"message"`
	DNS         string `json:"dns"`
	Certificate string `json:"certificate"`
}

func detectLayout(src string) (Layout, error) {
	l := Layout{}
	// The fnOS certificate hook is required; a different Nginx layout is never
	// silently treated as a supported stock fnOS installation.
	if !regexp.MustCompile(`\btrim_hook_cert_switch\s+on;`).MatchString(src) || !regexp.MustCompile(`\btrim_cert_cfg_path\s+`).MatchString(src) {
		return l, fmt.Errorf("未识别飞牛原生证书模块，拒绝接管 Nginx")
	}
	re := regexp.MustCompile(`(?m)^\s*listen\s+([^;]+);`)
	var defaults []Listener
	for _, match := range re.FindAllStringSubmatch(src, -1) {
		fields := strings.Fields(match[1])
		if len(fields) < 2 {
			continue
		}
		def, tls := false, false
		for _, f := range fields[1:] {
			if f == "default_server" {
				def = true
			}
			if f == "ssl" {
				tls = true
			}
		}
		if !def {
			continue
		}
		addr := fields[0]
		if !regexp.MustCompile(`^(?:\[::\]|0\.0\.0\.0):[0-9]+$`).MatchString(addr) {
			return l, fmt.Errorf("不支持的飞牛监听地址: %s", addr)
		}
		defaults = append(defaults, Listener{addr, tls})
	}
	// fnOS also has convenience redirects on 80/443; when a configured NAS
	// port exists, do not take over those convenience listeners.
	hasHTTP, hasTLS := false, false
	for _, v := range defaults {
		if !v.TLS && !strings.HasSuffix(v.Address, ":80") {
			hasHTTP = true
		}
		if v.TLS && !strings.HasSuffix(v.Address, ":443") {
			hasTLS = true
		}
	}
	seen := map[string]bool{}
	for _, v := range defaults {
		if hasHTTP && !v.TLS && strings.HasSuffix(v.Address, ":80") || hasTLS && v.TLS && strings.HasSuffix(v.Address, ":443") {
			continue
		}
		if !seen[v.Address] {
			l.Listeners = append(l.Listeners, v)
			seen[v.Address] = true
		}
		if v.TLS {
			l.HTTPSPort = v.Address[strings.LastIndex(v.Address, ":")+1:]
		}
	}
	if len(l.Listeners) == 0 {
		return l, fmt.Errorf("未发现飞牛默认监听端口")
	}
	for _, directive := range []string{"trim_hook_cert_switch", "ssl_certificate", "ssl_certificate_key", "ssl_session_cache", "ssl_session_timeout", "ssl_ciphers", "ssl_prefer_server_ciphers", "ssl_protocols"} {
		m := regexp.MustCompile(`(?m)^\s*` + directive + `\s+([^;]+);`).FindStringSubmatch(src)
		if len(m) > 0 {
			l.TLS += "    " + directive + " " + m[1] + ";\n"
		}
	}
	if l.HTTPSPort != "" && (!strings.Contains(l.TLS, "ssl_certificate $ssl_server_name;") || !strings.Contains(l.TLS, "ssl_certificate_key $ssl_server_name;")) {
		return l, fmt.Errorf("证书选择配置与已支持的飞牛布局不同")
	}
	l.ForceHTTPS = regexp.MustCompile(`(?s)if\s*\(\s*\$scheme\s*=\s*["']?http["']?\s*\)\s*\{\s*return\s+30[1278]\s+https://`).MatchString(src)
	return l, nil
}

func validateRoutes(routes []Route) error {
	seen := map[string]bool{}
	for _, r := range routes {
		if _, err := ValidateDomain(r.Host); err != nil {
			return err
		}
		if seen[r.Host] {
			return fmt.Errorf("duplicate hostname: %s", r.Host)
		}
		seen[r.Host] = true
		u, err := url.Parse(r.Upstream)
		validPort := false
		if err == nil {
			p, e := strconv.Atoi(u.Port())
			validPort = e == nil && p > 0 && p <= 65535
		}
		if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || net.ParseIP(u.Hostname()) == nil || !validPort || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("unsafe upstream %q", r.Upstream)
		}
	}
	return nil
}

// fnOS rebuilds nginx.conf from its bundled template during a master reload.
// Its existing server-level conf.d wildcard is usable in extension mode. Rewrite
// phase host dispatch runs before location selection, so application paths such
// as /websocket cannot accidentally enter the NAS's own locations.
func renderServer(l Layout, routes []Route, disabled bool) ([]byte, error) {
	// Reuse strict host/upstream validation, even though this layout uses a
	// server fragment rather than creating additional listen sockets/vhosts.
	if err := validateRoutes(routes); err != nil {
		return nil, err
	}
	var b strings.Builder
	sort.Slice(routes, func(i, j int) bool { return routes[i].Host < routes[j].Host })
	state, _ := json.Marshal(struct {
		Layout   Layout
		Routes   []Route
		Disabled bool
	}{l, routes, disabled})
	revision := digest(state)[:16]
	b.WriteString("# Generated by Watchcow_R. Native server-level host dispatch.\nset $watchcow_r_upstream '';\nset $watchcow_r_revision '';\nadd_header X-Watchcow-R-Revision $watchcow_r_revision always;\nset $watchcow_r_connection close;\nif ($http_upgrade != '') { set $watchcow_r_connection upgrade; }\nerror_page 599 = @watchcow_r_proxy;\n")
	for _, r := range routes {
		if disabled || !r.Active {
			fmt.Fprintf(&b, "if ($host = %s) { set $watchcow_r_revision %s; return 503; }\n", r.Host, revision)
		} else {
			fmt.Fprintf(&b, "if ($host = %s) { set $watchcow_r_revision %s; set $watchcow_r_upstream %s; return 599; }\n", r.Host, revision, r.Upstream)
		}
	}
	b.WriteString(`location @watchcow_r_proxy {
    if ($uri = /.__watchcow_r_check) { return 204; }
    auth_request off;
    client_max_body_size 0;
    proxy_pass $watchcow_r_upstream;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $realip_remote_addr;
    proxy_set_header X-Forwarded-For $realip_remote_addr;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $watchcow_r_connection;
    proxy_hide_header X-Watchcow-R-Revision;
    proxy_ssl_server_name on;
    proxy_ssl_name $host;
    proxy_connect_timeout 5s;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_redirect $watchcow_r_upstream/ $scheme://$http_host/;
}
`)
	return []byte(b.String()), nil
}

type Native struct {
	// Used only by the isolated test harness, which starts Nginx directly.
	Extended     bool
	Main         string
	Binary       string
	Dir          string
	Run          func(context.Context, string, ...string) error
	Certificates *CertificateFiles
}

type pendingNative struct {
	Main, Routes, NextRoutes []byte
	RoutesExisted            bool
	Files                    []nativeFileChange `json:",omitempty"`
}

type nativeFileChange struct {
	Path          string
	Before, After []byte
	Existed       bool
	Mode          uint32
	DeleteAfter   bool
}

func nativeChange(path string, after []byte, mode os.FileMode, deleteAfter bool) (nativeFileChange, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nativeFileChange{}, err
	}
	c := nativeFileChange{Path: path, Before: b, After: after, Existed: err == nil, Mode: uint32(mode.Perm()), DeleteAfter: deleteAfter}
	if info, e := os.Stat(path); e == nil {
		c.Mode = uint32(info.Mode().Perm())
	}
	return c, nil
}

func (c nativeFileChange) changed() bool {
	return c.DeleteAfter && c.Existed || !c.DeleteAfter && (!c.Existed || !bytes.Equal(c.Before, c.After))
}

// Verify every file before changing any of them. Both sides of the durable
// journal are accepted after a crash, but unrelated external edits are retained.
func checkNativeChanges(changes []nativeFileChange, allowAfter bool) error {
	for _, c := range changes {
		b, err := os.ReadFile(c.Path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		before := err == nil && c.Existed && bytes.Equal(b, c.Before) || os.IsNotExist(err) && !c.Existed
		after := err == nil && c.After != nil && bytes.Equal(b, c.After) || os.IsNotExist(err) && c.DeleteAfter
		if !before && !(allowAfter && after) {
			return fmt.Errorf("Nginx 事务文件发生外部修改，保留文件: %s", c.Path)
		}
	}
	return nil
}

func writeNativeChanges(changes []nativeFileChange, restore bool) error {
	for _, c := range changes {
		data := c.After
		if restore {
			if !c.Existed {
				continue
			}
			data = c.Before
		} else if data == nil && c.DeleteAfter {
			continue
		}
		current, err := os.ReadFile(c.Path)
		if err == nil && bytes.Equal(current, data) {
			continue
		}
		if err := atomicWrite(c.Path, data, os.FileMode(c.Mode)); err != nil {
			return err
		}
	}
	return nil
}

func deleteNativeChanges(changes []nativeFileChange, restore bool) error {
	for _, c := range changes {
		if restore && c.Existed || !restore && !c.DeleteAfter {
			continue
		}
		if err := os.Remove(c.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (n *Native) restoreNativeChanges(changes []nativeFileChange) error {
	if err := checkNativeChanges(changes, true); err != nil {
		return err
	}
	if err := writeNativeChanges(changes, true); err != nil {
		return err
	}
	// Remove newly created includes before reload: otherwise Nginx could load
	// the staged routes even though their files are deleted immediately after.
	if err := deleteNativeChanges(changes, true); err != nil {
		return err
	}
	if err := n.run("-t"); err != nil {
		return err
	}
	if err := n.run("-s", "reload"); err != nil {
		return err
	}
	return nil
}

func (n *Native) recoverPending(path string) error {
	b, err := os.ReadFile(filepath.Join(n.Dir, "nginx.pending.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var p pendingNative
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if len(p.Files) != 0 {
		if err := n.restoreNativeChanges(p.Files); err != nil {
			return err
		}
		return os.Remove(filepath.Join(n.Dir, "nginx.pending.json"))
	}
	main, err := os.ReadFile(n.Main)
	if err != nil {
		return err
	}
	if !bytes.Equal(main, p.Main) {
		return fmt.Errorf("未完成事务同时存在外部 Nginx 变更，拒绝覆盖")
	}
	routes, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !bytes.Equal(routes, p.Routes) && !bytes.Equal(routes, p.NextRoutes) {
		return fmt.Errorf("未完成事务的路由文件发生外部变更")
	}
	if p.RoutesExisted {
		if err := atomicWrite(path, p.Routes, 0644); err != nil {
			return err
		}
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := n.run("-t"); err != nil {
		return err
	}
	if err := n.run("-s", "reload"); err != nil {
		return err
	}
	return os.Remove(filepath.Join(n.Dir, "nginx.pending.json"))
}

func NewNative(dir string) *Native {
	return &Native{Main: "/usr/trim/nginx/conf/nginx.conf", Binary: "/usr/trim/nginx/sbin/nginx", Dir: dir,
		Certificates: &CertificateFiles{Gateway: "/usr/trim/etc/network_gateway_cert.conf", Store: "/usr/trim/etc/network_cert_all.conf"}}
}
func (n *Native) run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if n.Run != nil {
		return n.Run(ctx, n.Binary, args...)
	}
	cmd := exec.CommandContext(ctx, n.Binary, args...)
	// fnOS normally restores its bundled configuration on command startup.
	// Use the binary's debug mode ONLY for this short-lived test/signal command;
	// the long-running NAS master uses the explicitly configured extension mode.
	cmd.Env = append(os.Environ(), "NGXMODE=debug")
	out, err := cmd.CombinedOutput()
	if len(out) > 3000 {
		out = out[len(out)-3000:]
	}
	if err != nil {
		return fmt.Errorf("nginx %v: %w: %s", args, err, out)
	}
	return nil
}

func (n *Native) verifyBinary() error {
	f, err := elf.Open(n.Binary)
	if err != nil {
		return err
	}
	symbols, err := f.DynamicSymbols()
	f.Close()
	if err != nil {
		return err
	}
	found := map[string]bool{}
	for _, s := range symbols {
		found[s.Name] = true
	}
	for _, name := range []string{"ngx_http_trim_recover_sighandler", "NGXMODE_STOP_WATCH", "NGXMODE_DEBUG", "NGXMODE_DEV"} {
		if !found[name] {
			return fmt.Errorf("未识别飞牛 Nginx 自恢复接口: %s", name)
		}
	}
	return nil
}

// coordinateWatch verifies that reloads cannot erase our configuration. No
// realtime signals or process-memory changes are used.
func (n *Native) coordinateWatch() (func(), error) {
	if n.Run != nil {
		return func() {}, nil
	}
	if err := n.verifyBinary(); err != nil {
		return nil, err
	}
	source, err := os.ReadFile(n.Main)
	if err != nil {
		return nil, err
	}
	m := regexp.MustCompile(`(?m)^\s*pid\s+(/[^;\s]+);`).FindSubmatch(source)
	if len(m) != 2 {
		return nil, fmt.Errorf("未找到 Nginx PID 路径")
	}
	b, err := os.ReadFile(string(m[1]))
	if err != nil {
		return nil, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return nil, fmt.Errorf("无效 Nginx 主进程 PID")
	}
	actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}
	expected, err := os.Stat(n.Binary)
	if err != nil || !os.SameFile(actual, expected) {
		return nil, fmt.Errorf("PID 不属于飞牛 Nginx")
	}
	if n.Extended {
		return func() {}, nil
	}
	if serviceExtended() {
		return func() {}, nil
	}
	return nil, fmt.Errorf("飞牛 Nginx 仍处于会清除扩展配置的普通模式，请显式启用扩展模式")

}

func (n *Native) Layout() (Layout, error) {
	b, err := os.ReadFile(n.Main)
	if err != nil {
		return Layout{}, err
	}
	return detectLayout(string(b))
}

// Apply updates our route fragment and certificate mapping in one transaction.
// The only main-config edit redirects the existing native certificate module
// to the merged mapping; removal restores its vendor source. Private keys and
// the vendor's certificate inventory/bindings are never modified.
// A cross-process lock serializes lifecycle and daemon operations.
func (n *Native) Apply(routes []Route, disabled, remove bool) error {
	if err := os.MkdirAll(n.Dir, 0755); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(n.Dir, "nginx.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path := filepath.Join(filepath.Dir(n.Main), "conf.d", "watchcow-r.conf")
	main, err := os.ReadFile(n.Main)
	if err != nil {
		return err
	}
	var resume func()
	defer func() {
		if resume != nil {
			resume()
		}
	}()
	if _, e := os.Stat(filepath.Join(n.Dir, "nginx.pending.json")); e == nil {
		resume, err = n.coordinateWatch()
		if err != nil {
			return err
		}
		if err := n.recoverPending(path); err != nil {
			return err
		}
		main, err = os.ReadFile(n.Main)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, e := os.Stat(path); disabled && len(routes) == 0 && os.IsNotExist(e) {
		if _, certErr := os.Stat(filepath.Join(n.Dir, "certificates.owned.json")); os.IsNotExist(certErr) {
			return nil
		}
	}

	info, err := os.Stat(n.Main)
	if err != nil {
		return err
	}
	oldRoutes, routeErr := os.ReadFile(path)
	if routeErr != nil && !os.IsNotExist(routeErr) {
		return routeErr
	}
	if routeErr == nil && len(oldRoutes) > 0 && !bytes.HasPrefix(oldRoutes, []byte("# Generated by Watchcow_R.")) {
		return fmt.Errorf("conf.d/watchcow-r.conf 已存在外部配置，拒绝覆盖")
	}
	var nextRoutes []byte
	nextMain, certChanges, certRevision, err := n.certificatePlan(main, routes, remove)
	if err != nil {
		return err
	}
	if remove {
		nextRoutes = []byte("# Generated by Watchcow_R. Removed.\n")
	} else {
		layout, e := detectLayout(string(main))
		if e != nil {
			return e
		}
		layout.CertificateRevision = certRevision
		nextRoutes, err = renderServer(layout, routes, disabled)
	}
	if err != nil {
		return err
	}
	mainChange, err := nativeChange(n.Main, nextMain, info.Mode().Perm(), false)
	if err != nil {
		return err
	}
	routeChange, err := nativeChange(path, nextRoutes, 0644, remove)
	if err != nil {
		return err
	}
	changes := append(certChanges, mainChange, routeChange)
	changed := false
	for _, c := range changes {
		changed = changed || c.changed()
	}
	if !changed {
		return nil
	}
	if resume == nil {
		resume, err = n.coordinateWatch()
		if err != nil {
			return err
		}
	}
	// Keep the first pre-takeover copy as evidence, never overwrite it later.
	backup := filepath.Join(n.Dir, "backup", "nginx.conf.original")
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		if err := atomicWrite(backup, main, info.Mode().Perm()); err != nil {
			return err
		}
	}
	current, err := os.ReadFile(n.Main)
	if err != nil || !bytes.Equal(current, main) {
		return fmt.Errorf("Nginx 配置被其他进程修改，请重试")
	}
	if err := checkNativeChanges(changes, false); err != nil {
		return err
	}
	pending, err := json.Marshal(pendingNative{Main: main, Routes: oldRoutes, NextRoutes: nextRoutes, RoutesExisted: routeErr == nil, Files: changes})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(n.Dir, "nginx.pending.json"), pending, 0600); err != nil {
		return err
	}
	applyErr := writeNativeChanges(changes, false)
	if applyErr == nil {
		applyErr = n.run("-t")
	}
	if applyErr == nil {
		current, e := os.ReadFile(n.Main)
		if e != nil || !bytes.Equal(current, nextMain) {
			applyErr = fmt.Errorf("校验过程中 Nginx 主配置被外部修改")
		}
	}
	if applyErr == nil {
		applyErr = n.run("-s", "reload")
	}
	if applyErr == nil {
		applyErr = n.waitApplied(nextMain, nextRoutes, oldRoutes)
	}
	if applyErr != nil {
		recovery := n.restoreNativeChanges(changes)
		if recovery == nil {
			_ = os.Remove(filepath.Join(n.Dir, "nginx.pending.json"))
		}
		return fmt.Errorf("应用失败: %w (回退=%v)", applyErr, recovery)
	}
	if err := deleteNativeChanges(changes, false); err != nil {
		return err
	}
	return os.Remove(filepath.Join(n.Dir, "nginx.pending.json"))
}

// A successful signal command is insufficient: wait for a new worker to serve
// the exact rendered revision, using fresh local connections and no backend.
func (n *Native) waitApplied(main, next, old []byte) error {
	if n.Run != nil {
		return nil
	}
	hostMatch := regexp.MustCompile(`if \(\$host = ([a-z0-9.-]+)\)`).FindSubmatch(next)
	if len(hostMatch) != 2 {
		hostMatch = regexp.MustCompile(`if \(\$host = ([a-z0-9.-]+)\)`).FindSubmatch(old)
	}
	if len(hostMatch) != 2 {
		return nil
	}
	revision := ""
	if match := regexp.MustCompile(`set \$watchcow_r_revision ([0-9a-f]{16});`).FindSubmatch(next); len(match) == 2 {
		revision = string(match[1])
	}
	l, err := detectLayout(string(main))
	if err != nil {
		return err
	}
	var selected Listener
	for _, listener := range l.Listeners {
		if selected.Address == "" || listener.TLS && !selected.TLS {
			selected = listener
		}
	}
	address := selected.Address
	address = strings.Replace(address, "0.0.0.0:", "127.0.0.1:", 1)
	address = strings.Replace(address, "[::]:", "[::1]:", 1)
	scheme := "http"
	if selected.TLS {
		scheme = "https"
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: string(hostMatch[1])}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(6 * time.Second)
	for {
		req, _ := http.NewRequest("GET", scheme+"://"+address+"/.__watchcow_r_check", nil)
		req.Host = string(hostMatch[1]) + ":" + strconv.Itoa(port(address))
		resp, e := client.Do(req)
		if e == nil {
			got := resp.Header.Get("X-Watchcow-R-Revision")
			resp.Body.Close()
			if got == revision {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Nginx 重载后未提供预期的配置版本 %s", revision)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func port(address string) int {
	value, _ := strconv.Atoi(address[strings.LastIndex(address, ":")+1:])
	return value
}
