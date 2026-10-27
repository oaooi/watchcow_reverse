package reverse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Parse the structure before allowing administrator snippets into a shared
// native configuration. Nginx remains the authoritative directive validator.
type nginxToken struct {
	text       string
	start, end int
	symbol     bool
}
type nginxNode struct {
	name       string
	args       []string
	children   []nginxNode
	block      bool
	start, end int
}

func nginxTokens(src string) ([]nginxToken, error) {
	var out []nginxToken
	for i := 0; i < len(src); {
		c := src[i]
		if c == 0 {
			return nil, fmt.Errorf("Nginx 配置含 NUL 字符")
		}
		if strings.ContainsRune(" \t\r\n", rune(c)) {
			i++
			continue
		}
		if c == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		start := i
		if strings.ContainsRune(";{}", rune(c)) {
			out = append(out, nginxToken{string(c), i, i + 1, true})
			i++
			continue
		}
		var word strings.Builder
		quote := byte(0)
		for i < len(src) {
			c = src[i]
			if c == 0 {
				return nil, fmt.Errorf("Nginx 配置含 NUL 字符")
			}
			if c == '\\' && i+1 < len(src) {
				word.WriteByte(src[i+1])
				i += 2
				continue
			}
			if quote != 0 {
				if c == quote {
					quote = 0
					i++
					continue
				}
				word.WriteByte(c)
				i++
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				i++
				continue
			}
			if c == '$' && i+1 < len(src) && src[i+1] == '{' {
				end := strings.IndexByte(src[i+2:], '}')
				if end < 0 {
					return nil, fmt.Errorf("未闭合的 Nginx 变量")
				}
				end += i + 3
				word.WriteString(src[i:end])
				i = end
				continue
			}
			if strings.ContainsRune(" \t\r\n;{}#", rune(c)) {
				break
			}
			word.WriteByte(c)
			i++
		}
		if quote != 0 {
			return nil, fmt.Errorf("未闭合的 Nginx 引号")
		}
		if i == start {
			return nil, fmt.Errorf("无法解析 Nginx 配置")
		}
		out = append(out, nginxToken{word.String(), start, i, false})
	}
	return out, nil
}
func parseNginx(src string) ([]nginxNode, error) {
	ts, err := nginxTokens(src)
	if err != nil {
		return nil, err
	}
	i := 0
	var parse func(bool) ([]nginxNode, error)
	parse = func(nested bool) ([]nginxNode, error) {
		var nodes []nginxNode
		for i < len(ts) {
			t := ts[i]
			if t.symbol && t.text == "}" {
				if !nested {
					return nil, fmt.Errorf("多余的 Nginx 闭合大括号")
				}
				i++
				return nodes, nil
			}
			if t.symbol && (t.text == ";" || t.text == "{") {
				return nil, fmt.Errorf("缺少 Nginx 指令名")
			}
			node := nginxNode{name: t.text, start: t.start}
			i++
			for i < len(ts) && !ts[i].symbol {
				node.args = append(node.args, ts[i].text)
				i++
			}
			if i == len(ts) || ts[i].text == "}" {
				return nil, fmt.Errorf("指令 %s 缺少分号或配置块", node.name)
			}
			node.block = ts[i].text == "{"
			node.end = ts[i].end
			i++
			if node.block {
				node.children, err = parse(true)
				if err != nil {
					return nil, err
				}
				node.end = ts[i-1].end
			}
			nodes = append(nodes, node)
		}
		if nested {
			return nil, fmt.Errorf("未闭合的 Nginx 配置块")
		}
		return nodes, nil
	}
	return parse(false)
}

func validateSnippet(src string, locations bool) ([]nginxNode, error) {
	if len(src) > 32<<10 {
		return nil, fmt.Errorf("自定义 Nginx 配置最多 32 KiB")
	}
	nodes, err := parseNginx(src)
	if err != nil {
		return nil, err
	}
	var check func([]nginxNode) error
	check = func(ns []nginxNode) error {
		for _, n := range ns {
			switch n.name {
			case "http", "server", "events", "stream", "mail", "upstream", "map", "geo", "listen", "server_name", "include", "load_module", "pid", "user", "daemon", "master_process", "ssl_certificate", "ssl_certificate_key", "ssl_session_ticket_key", "ssl_password_file", "trim_cert_cfg_path", "trim_hook_cert_switch":
				return fmt.Errorf("%s 由系统管理，不能放入应用自定义配置", n.name)
			}
			if strings.HasPrefix(n.name, "trim_") {
				return fmt.Errorf("不能修改飞牛模块指令")
			}
			if n.name == "location" && !locations {
				return fmt.Errorf("位置内配置不能再定义 location")
			}
			if n.name == "location" && strings.Contains(strings.Join(n.args, " "), ".__watchcow_r_check") {
				return fmt.Errorf("该路径用于配置健康检查")
			}
			if err := check(n.children); err != nil {
				return err
			}
		}
		return nil
	}
	return nodes, check(nodes)
}

func validateProxyURL(value string, uri bool) error {
	u, err := url.Parse(value)
	if err != nil || u == nil {
		return fmt.Errorf("无效的后端 URL")
	}
	p, e := strconv.Atoi(u.Port())
	if (u.Scheme != "http" && u.Scheme != "https") || net.ParseIP(u.Hostname()) == nil || e != nil || p < 1 || p > 65535 || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (!uri && u.Path != "") || strings.ContainsAny(value, " \t\r\n;{}\\\"'$#<>") {
		return fmt.Errorf("后端必须为带端口的 HTTP/HTTPS IP 地址，例如 https://192.0.2.10:8089%s", map[bool]string{true: "/", false: ""}[uri])
	}
	return nil
}
func rootLocation(n nginxNode) bool {
	return n.name == "location" && (len(n.args) == 1 && n.args[0] == "/" || len(n.args) == 2 && n.args[0] == "^~" && n.args[1] == "/")
}

// Use the explicitly configured root backend for discovery/probing as well as
// for traffic. A custom root must not be gated on an unrelated default backend.
func rootProxyOrigin(r Route) (string, bool) {
	root := false
	var target string
	for _, loc := range r.CustomLocations {
		if loc.Path == "/" {
			root = true
			target = loc.Upstream
		}
	}
	nodes, _ := parseNginx(r.Nginx)
	for _, node := range nodes {
		if rootLocation(node) {
			root = true
			for _, child := range node.children {
				if child.name == "proxy_pass" && len(child.args) == 1 {
					target = child.args[0]
				}
			}
		}
	}
	if !root {
		return r.Upstream, false
	}
	if validateProxyURL(target, true) == nil {
		u, _ := url.Parse(target)
		return u.Scheme + "://" + u.Host, true
	}
	return "", true
}
func validateOverride(o Override) error {
	if o.Upstream != "" {
		if err := validateProxyURL(o.Upstream, false); err != nil {
			return err
		}
	}
	if o.IconMode != "" && o.IconMode != "auto" && o.IconMode != "keep" {
		return fmt.Errorf("无效图标模式")
	}
	nodes, err := validateSnippet(o.Nginx, true)
	if err != nil {
		return err
	}
	roots := 0
	for _, n := range nodes {
		if rootLocation(n) {
			roots++
		}
	}
	paths := map[string]bool{}
	if len(o.CustomLocations) > 32 {
		return fmt.Errorf("每个应用最多 32 个自定义位置")
	}
	for _, loc := range o.CustomLocations {
		if loc.Path == "" || !strings.HasPrefix(loc.Path, "/") || strings.ContainsAny(loc.Path, " \t\r\n;{}\\\"'$#?<>") || strings.HasPrefix(loc.Path, "/.__watchcow_r_check") {
			return fmt.Errorf("无效的位置路径 %q", loc.Path)
		}
		if paths[loc.Path] {
			return fmt.Errorf("重复的位置 %s", loc.Path)
		}
		paths[loc.Path] = true
		if loc.Path == "/" {
			roots++
		}
		if err := validateProxyURL(loc.Upstream, true); err != nil {
			return err
		}
		if _, err := validateSnippet(loc.Nginx, false); err != nil {
			return err
		}
	}
	if roots > 1 {
		return fmt.Errorf("location / 重复，只保留一份即可")
	}
	return nil
}

func renderProxyLocation(b *strings.Builder, loc CustomLocation) {
	fmt.Fprintf(b, "location %s {\n", loc.Path)
	nodes, _ := parseNginx(loc.Nginx)
	overrides := map[string]bool{}
	for _, n := range nodes {
		k := n.name
		if k == "proxy_set_header" && len(n.args) > 0 {
			k += " " + strings.ToLower(n.args[0])
		}
		overrides[k] = true
	}
	defaults := []string{"auth_request off", "client_max_body_size 0", "proxy_pass " + loc.Upstream, "proxy_http_version 1.1", "proxy_set_header Host $http_host", "proxy_set_header X-Real-IP $realip_remote_addr", "proxy_set_header X-Forwarded-For $realip_remote_addr", "proxy_set_header X-Forwarded-Host $http_host", "proxy_set_header X-Forwarded-Proto $scheme", "proxy_set_header X-Forwarded-Port $server_port", "proxy_set_header X-Forwarded-Scheme $scheme", "proxy_set_header Upgrade $http_upgrade", "proxy_set_header Connection $watchcow_r_connection", "proxy_hide_header X-Watchcow-R-Revision", "proxy_ssl_server_name on", "proxy_ssl_name $host", "proxy_connect_timeout 5s", "proxy_read_timeout 3600s", "proxy_send_timeout 3600s", "proxy_buffering off", "proxy_request_buffering off"}
	for _, line := range defaults {
		parts := strings.Fields(line)
		k := parts[0]
		if k == "proxy_set_header" {
			k += " " + strings.ToLower(parts[1])
		}
		if !overrides[k] {
			fmt.Fprintf(b, "    %s;\n", line)
		}
	}
	b.WriteString(loc.Nginx)
	b.WriteString("\n}\n")
}
func renderCustomHosts(l Layout, routes []Route, disabled bool) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Generated by Watchcow_R. Custom proxy hosts.\n")
	sort.Slice(routes, func(i, j int) bool { return routes[i].Host < routes[j].Host })
	revision := routeRevision(l, routes, disabled)
	count := 0
	for _, r := range routes {
		if r.Nginx == "" && len(r.CustomLocations) == 0 {
			continue
		}
		if err := validateOverride(Override{Nginx: r.Nginx, CustomLocations: r.CustomLocations}); err != nil {
			return nil, err
		}
		count++
		b.WriteString("server {\n")
		for _, listen := range l.Listeners {
			fmt.Fprintf(&b, "listen %s%s;\n", listen.Address, map[bool]string{true: " ssl", false: ""}[listen.TLS])
		}
		fmt.Fprintf(&b, "server_name %s;\n%s", r.Host, l.TLS)
		fmt.Fprintf(&b, "set $watchcow_r_revision %s;\nadd_header X-Watchcow-R-Revision $watchcow_r_revision always;\nset $watchcow_r_connection close;\nif ($http_upgrade != '') { set $watchcow_r_connection upgrade; }\n", revision)
		if disabled || !r.Active {
			b.WriteString("return 503;\n}\n")
			continue
		}
		if l.ForceHTTPS {
			fmt.Fprintf(&b, "if ($scheme = http) { return 301 https://$host:%s$request_uri; }\n", l.HTTPSPort)
		}
		fmt.Fprintf(&b, "location = /.__watchcow_r_check { auth_request off; add_header X-Watchcow-R-Revision %s always; return 204; }\n", revision)
		nodes, _ := parseNginx(r.Nginx)
		root := false
		for _, n := range nodes {
			root = root || rootLocation(n)
		}
		for _, loc := range r.CustomLocations {
			root = root || loc.Path == "/"
			renderProxyLocation(&b, loc)
		}
		if !root {
			renderProxyLocation(&b, CustomLocation{Path: "/", Upstream: r.Upstream})
		}
		b.WriteString(r.Nginx)
		b.WriteString("\n}\n")
	}
	if count == 0 {
		return nil, nil
	}
	return []byte(b.String()), nil
}

func (n *Native) customHostsPlan(main []byte, l Layout, routes []Route, disabled, remove bool) ([]byte, []nativeFileChange, error) {
	path := filepath.Join(filepath.Dir(n.Main), "watchcow-r-hosts.conf")
	statePath := filepath.Join(n.Dir, "hosts.owned.json")
	if !certificateConfigPath.MatchString(path) {
		return nil, nil, fmt.Errorf("自定义服务配置路径无效")
	}
	line := []byte("    include " + path + "; # Watchcow_R custom hosts\n")
	old, oe := os.ReadFile(path)
	state, se := os.ReadFile(statePath)
	for _, err := range []error{oe, se} {
		if err != nil && !os.IsNotExist(err) {
			return nil, nil, err
		}
	}
	if oe == nil || se == nil || bytes.Contains(main, []byte(path)) {
		var owned certificateOwnership
		if oe != nil || se != nil || json.Unmarshal(state, &owned) != nil || owned.Path != path || owned.Hash != digest(old) {
			return nil, nil, fmt.Errorf("自定义服务配置发生外部修改，保留文件")
		}
	}
	if bytes.Contains(main, []byte(path)) && bytes.Count(main, line) != 1 {
		return nil, nil, fmt.Errorf("自定义服务 include 发生外部变更")
	}
	next := bytes.Replace(main, line, nil, 1)
	var data []byte
	var err error
	if !remove {
		data, err = renderCustomHosts(l, routes, disabled)
		if err != nil {
			return nil, nil, err
		}
	}
	var changes []nativeFileChange
	if data != nil {
		nodes, err := parseNginx(string(next))
		if err != nil {
			return nil, nil, err
		}
		at := -1
		for _, node := range nodes {
			if node.name == "http" && node.block {
				if at != -1 {
					return nil, nil, fmt.Errorf("多个 http 配置块")
				}
				at = node.end - 1
			}
		}
		if at < 0 {
			return nil, nil, fmt.Errorf("未找到原生 http 配置块")
		}
		next = append(append(append([]byte{}, next[:at]...), line...), next[at:]...)
		owned, _ := json.Marshal(certificateOwnership{Path: path, Hash: digest(data)})
		for _, f := range []struct {
			path string
			data []byte
			mode os.FileMode
		}{{path, data, 0644}, {statePath, owned, 0600}} {
			c, e := nativeChange(f.path, f.data, f.mode, false)
			if e != nil {
				return nil, nil, e
			}
			changes = append(changes, c)
		}
	} else if oe == nil {
		for _, p := range []string{path, statePath} {
			c, e := nativeChange(p, nil, 0600, true)
			if e != nil {
				return nil, nil, e
			}
			changes = append(changes, c)
		}
	}
	return next, changes, nil
}
