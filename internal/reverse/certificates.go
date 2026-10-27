package reverse

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CertificateFiles reads fnOS's public certificate inventory. Private keys stay
// in fnOS: the native certificate module opens the original paths itself.
type CertificateFiles struct {
	Gateway string
	Store   string
	Now     func() time.Time
}

type certificateEntry struct {
	Host string `json:"host"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type storedCertificate struct {
	Certificate string `json:"certificate"`
	Fullchain   string `json:"fullchain"`
	PrivateKey  string `json:"privateKey"`
}

type certificateCandidate struct {
	entry certificateEntry
	leaf  *x509.Certificate
	data  []byte
}

type certificateOwnership struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

var certificateDirective = regexp.MustCompile(`(?m)^([\t ]*trim_cert_cfg_path[\t ]+)([^;\s]+)([\t ]*;)`)
var certificateConfigPath = regexp.MustCompile(`^/[a-zA-Z0-9_./@+-]+$`)

// certificatePlan preserves all vendor bindings and adds exact SNI entries for
// our routes. Exact entries are needed even when the certificate is a wildcard:
// the installed fnOS module's lookup does not infer them from certificate SANs.
// Only our file and the single certificate-source directive are ever changed.
func (n *Native) certificatePlan(main []byte, routes []Route, remove bool) ([]byte, []nativeFileChange, string, error) {
	if n.Certificates == nil {
		return main, nil, "", nil
	}
	c := n.Certificates
	// The native module installs an inotify watch from unprivileged workers.
	// fnOS app-conf directories are private, so keep only this public path map
	// beside nginx.conf; ownership and rollback journals remain in n.Dir.
	path := filepath.Join(filepath.Dir(n.Main), "watchcow-r-certificates.json")
	statePath := filepath.Join(n.Dir, "certificates.owned.json")
	if !certificateConfigPath.MatchString(path) || filepath.Clean(path) != path {
		return nil, nil, "", fmt.Errorf("证书映射路径不适合 Nginx 配置")
	}
	matches := certificateDirective.FindAllSubmatchIndex(main, -1)
	if len(matches) != 1 {
		return nil, nil, "", fmt.Errorf("未识别唯一的飞牛证书映射配置")
	}
	match := matches[0]
	currentSource := string(main[match[4]:match[5]])
	if currentSource != c.Gateway && currentSource != path {
		return nil, nil, "", fmt.Errorf("飞牛证书映射来源发生外部变更，拒绝覆盖")
	}
	oldMap, mapErr := os.ReadFile(path)
	if mapErr != nil && !os.IsNotExist(mapErr) {
		return nil, nil, "", mapErr
	}
	state, stateErr := os.ReadFile(statePath)
	if stateErr != nil && !os.IsNotExist(stateErr) {
		return nil, nil, "", stateErr
	}
	if mapErr == nil || stateErr == nil || currentSource == path {
		var owned certificateOwnership
		if mapErr != nil || stateErr != nil || json.Unmarshal(state, &owned) != nil || owned.Path != path || owned.Hash != digest(oldMap) {
			return nil, nil, "", fmt.Errorf("Watchcow_R 证书映射发生外部修改，保留文件")
		}
	}
	var entries []json.RawMessage
	var revision bytes.Buffer
	if !remove {
		gateway, err := os.ReadFile(c.Gateway)
		if err != nil {
			return nil, nil, "", fmt.Errorf("读取飞牛证书映射: %w", err)
		}
		if err := json.Unmarshal(gateway, &entries); err != nil || entries == nil {
			return nil, nil, "", fmt.Errorf("飞牛证书映射格式无效")
		}
		revision.Write(gateway)
		existing := map[string]bool{}
		for _, raw := range entries {
			var entry certificateEntry
			if json.Unmarshal(raw, &entry) != nil || entry.Host == "" || entry.Cert == "" || entry.Key == "" {
				return nil, nil, "", fmt.Errorf("飞牛证书映射条目无效")
			}
			existing[strings.ToLower(entry.Host)] = true
		}
		candidates, err := c.candidates()
		if err != nil {
			return nil, nil, "", err
		}
		hosts := make([]string, 0, len(routes))
		for _, route := range routes {
			if _, err := ValidateDomain(route.Host); err != nil {
				return nil, nil, "", err
			}
			hosts = append(hosts, route.Host)
		}
		sort.Strings(hosts)
		added := 0
		for _, host := range hosts {
			if existing[host] {
				continue // Vendor/manual exact bindings always keep precedence.
			}
			best, score := -1, -1
			for i, candidate := range candidates {
				rank := certificateRank(candidate.leaf, host)
				if rank < 0 {
					continue
				}
				if rank > score || rank == score && (best < 0 || candidate.leaf.NotBefore.After(candidates[best].leaf.NotBefore)) {
					best, score = i, rank
				}
			}
			if best < 0 {
				continue // HTTP still works; HTTPS diagnostics reports missing coverage.
			}
			selected := candidates[best]
			selected.entry.Host = host
			raw, _ := json.Marshal(selected.entry)
			entries = append(entries, raw)
			revision.Write(selected.data) // Detect renewal even at the same filename.
			existing[host] = true
			added++
		}
		if added == 0 {
			entries = nil
		}
	}
	var changes []nativeFileChange
	nextSource := c.Gateway
	if entries != nil {
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return nil, nil, "", err
		}
		data = append(data, '\n')
		owned, _ := json.Marshal(certificateOwnership{Path: path, Hash: digest(data)})
		for _, file := range []struct {
			path string
			data []byte
			mode os.FileMode
		}{{path, data, 0644}, {statePath, owned, 0600}} {
			change, err := nativeChange(file.path, file.data, file.mode, false)
			if err != nil {
				return nil, nil, "", err
			}
			changes = append(changes, change)
		}
		revision.Write(data)
		nextSource = path
	} else if mapErr == nil {
		for _, file := range []string{path, statePath} {
			change, err := nativeChange(file, nil, 0600, true)
			if err != nil {
				return nil, nil, "", err
			}
			changes = append(changes, change)
		}
	}
	nextMain := append([]byte(nil), main[:match[4]]...)
	nextMain = append(nextMain, nextSource...)
	nextMain = append(nextMain, main[match[5]:]...)
	return nextMain, changes, digest(revision.Bytes()), nil
}

func (c *CertificateFiles) candidates() ([]certificateCandidate, error) {
	data, err := os.ReadFile(c.Store)
	if err != nil {
		return nil, fmt.Errorf("读取飞牛证书库: %w", err)
	}
	var inventory []storedCertificate
	if err := json.Unmarshal(data, &inventory); err != nil || inventory == nil {
		return nil, fmt.Errorf("飞牛证书库格式无效")
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	var candidates []certificateCandidate
	for _, item := range inventory {
		path := item.Fullchain
		if path == "" {
			path = item.Certificate
		}
		if !filepath.IsAbs(path) || !filepath.IsAbs(item.PrivateKey) {
			return nil, fmt.Errorf("飞牛证书路径无效")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取飞牛公开证书: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("飞牛公开证书格式无效")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析飞牛公开证书: %w", err)
		}
		info, err := os.Stat(item.PrivateKey) // Never open or copy the private key.
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("飞牛证书私钥路径不可用")
		}
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			continue
		}
		candidates = append(candidates, certificateCandidate{entry: certificateEntry{Cert: path, Key: item.PrivateKey}, leaf: leaf, data: data})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].entry.Cert < candidates[j].entry.Cert })
	return candidates, nil
}

func certificateRank(cert *x509.Certificate, host string) int {
	if cert.VerifyHostname(host) != nil {
		return -1
	}
	rank := 0
	for _, name := range cert.DNSNames {
		if strings.EqualFold(name, host) {
			return 10000
		}
		if strings.HasPrefix(name, "*.") && strings.HasSuffix(host, name[1:]) && len(name) > rank {
			rank = len(name)
		}
	}
	return rank
}
