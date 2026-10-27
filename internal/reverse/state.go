// Package reverse manages fnOS native Nginx routes. Application traffic never
// passes through the Watchcow_R daemon or its administrator socket.
package reverse

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"watchcow/internal/app"
)

const AppID = "watchcow-r"

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Override struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      string `json:"port,omitempty"`
}

type Settings struct {
	NativeExtensions bool                `json:"native_extensions"`
	Domain           string              `json:"domain"`
	Names            map[string]string   `json:"names"`
	Entries          map[string]Override `json:"entries"`
}

func SettingsDir() string {
	if dir := os.Getenv("TRIM_PKGETC"); dir != "" {
		return dir
	}
	return "/var/apps/" + AppID + "/etc"
}

func Load(dir string) (Settings, error) {
	s := Settings{Names: map[string]string{}, Entries: map[string]Override{}}
	b, err := os.ReadFile(filepath.Join(dir, "reverse.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	if s.Names == nil {
		s.Names = map[string]string{}
	}
	if s.Entries == nil {
		s.Entries = map[string]Override{}
	}
	if s.Domain != "" {
		s.Domain, err = ValidateDomain(s.Domain)
	}
	for key, override := range s.Entries {
		if override.Protocol != "" && override.Protocol != "http" && override.Protocol != "https" {
			return s, fmt.Errorf("入口 %s 的后端协议必须为 http 或 https", key)
		}
		if override.Port != "" {
			port, e := strconv.Atoi(override.Port)
			if e != nil || port < 1 || port > 65535 {
				return s, fmt.Errorf("入口 %s 的后端端口无效", key)
			}
		}
	}
	return s, err
}

func ValidateDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(value) > 190 || !strings.Contains(value, ".") {
		return "", fmt.Errorf("请输入基础域名，例如 nas.example.com")
	}
	for _, part := range strings.Split(value, ".") {
		if !dnsLabel.MatchString(part) {
			return "", fmt.Errorf("域名只能包含有效的 DNS 标签")
		}
	}
	return value, nil
}

func (s Settings) Save(dir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "reverse.json"), append(b, '\n'), 0600)
}

func Initialize() error {
	dir := SettingsDir()
	s, err := Load(dir)
	if err != nil {
		return err
	}
	if domain, ok := os.LookupEnv("WATCHCOW_R_DOMAIN"); ok {
		if domain == "" {
			return fmt.Errorf("基础域名不能为空")
		}
		s.Domain, err = ValidateDomain(domain)
		if err != nil {
			return err
		}
	}
	if s.Domain == "" {
		return fmt.Errorf("请在安装向导设置 WATCHCOW_R_DOMAIN")
	}
	if value, ok := os.LookupEnv("WATCHCOW_R_NATIVE_EXTENSIONS"); ok {
		if value != "true" && value != "false" {
			return fmt.Errorf("扩展模式开关必须为 true 或 false")
		}
		s.NativeExtensions = value == "true"
	}
	return s.Save(dir)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".watchcow-r-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func key(a *app.App, e app.Entry) string {
	return strings.TrimPrefix(a.ContainerName, "/") + "/" + e.Name
}

func normalize(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "app"
	}
	if len(s) > 54 {
		s = strings.TrimRight(s[:54], "-")
	}
	return s
}

func (s *Settings) name(a *app.App, e app.Entry) (string, error) {
	k := key(a, e)
	wanted := e.ProxySubdomain
	if o, ok := s.Entries[k]; ok && o.Subdomain != "" {
		wanted = o.Subdomain
	}
	manual := wanted != ""
	if manual {
		wanted = strings.ToLower(wanted)
		if !dnsLabel.MatchString(wanted) {
			return "", fmt.Errorf("无效子域名 %q", wanted)
		}
	} else if saved := s.Names[k]; saved != "" {
		wanted = saved
	} else {
		wanted = normalize(strings.TrimPrefix(a.ContainerName, "/") + func() string {
			if e.Name != "" {
				return "-" + e.Name
			}
			return ""
		}())
	}
	for owner, name := range s.Names {
		if owner != k && name == wanted {
			if manual {
				return "", fmt.Errorf("子域名 %s 已被 %s 保留", wanted, owner)
			}
			hash := sha256.Sum256([]byte(k))
			wanted = normalize(wanted) + "-" + hex.EncodeToString(hash[:4])
			break
		}
	}
	// Reserved names survive container removal/recreation and image upgrades.
	for owner, name := range s.Names {
		if owner != k && name == wanted {
			return "", fmt.Errorf("子域名冲突: %s", wanted)
		}
	}
	s.Names[k] = wanted
	return wanted + "." + s.Domain, nil
}

func eligible(s Settings, a *app.App, e app.Entry) (bool, string) {
	if e.Redirect != "" {
		return false, "保留外部跳转"
	}
	if e.Protocol != "" && e.Protocol != "http" && e.Protocol != "https" {
		return false, "非 HTTP/HTTPS 入口"
	}
	enabled := e.ProxyEnabled
	if o, ok := s.Entries[key(a, e)]; ok && o.Enabled != nil {
		enabled = o.Enabled
	}
	if enabled != nil && !*enabled {
		return false, "已关闭反代"
	}
	p, err := strconv.Atoi(e.Port)
	if err != nil || p < 1 || p > 65535 {
		return false, "没有有效的 Web 端口"
	}
	// Do not infer HTTP from a database's published TCP port. Explicit opt-in is
	// possible for unusual HTTP services on these ports.
	if enabled == nil {
		switch p {
		case 22, 25, 53, 110, 143, 445, 465, 587, 993, 995, 1433, 3306, 5432, 6379, 11211, 27017:
			return false, "非 Web 服务端口"
		}
	}
	return true, ""
}

// EligibleDefault is used when generating a new desktop package. Existing
// package rewrites additionally require a successful HTTP response probe.
func EligibleDefault(e app.Entry) bool {
	ok, _ := eligible(Settings{Entries: map[string]Override{}}, &app.App{}, e)
	return ok
}
