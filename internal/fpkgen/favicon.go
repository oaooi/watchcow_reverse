package fpkgen

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"image"
	"image/png"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// AutomaticIcon never replaces an explicit label, local file or dashboard
// upload. Image-name CDN defaults are fallbacks rather than user selections.
func AutomaticIcon(a *AppConfig, e Entry) bool {
	prefix := "watchcow."
	if e.Name != "" {
		prefix += e.Name + "."
	}
	if a.Labels["watchcow.icon"] != "" || a.Labels[prefix+"icon"] != "" {
		return false
	}
	for _, source := range []string{a.Icon, e.Icon} {
		if source != "" && source != DefaultIconForImage(a.Image) && !(e.Name != "" && source == buildIconURL(e.Name)) {
			return false
		}
		if strings.HasPrefix(source, "file://") {
			return false
		}
	}
	return true
}

// DiscoverWebIcon contacts only the selected application's HTTP origin. Page
// redirects and icon links cannot turn discovery into unrelated network scans.
// Self-signed HTTPS is allowed only on this explicitly selected backend.
func DiscoverWebIcon(ctx context.Context, origin, path string) (image.Image, string, error) {
	base, err := url.Parse(origin)
	if err != nil || base == nil || (base.Scheme != "http" && base.Scheme != "https") || net.ParseIP(base.Hostname()) == nil || base.Port() == "" || base.User != nil {
		return nil, "", fmt.Errorf("网页图标需要有效的应用 IP 和端口")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	same := func(u *url.URL) bool { return u.Scheme == base.Scheme && u.Host == base.Host && u.User == nil }
	client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 4 || !same(r.URL) {
			return fmt.Errorf("图标跳转超出应用来源")
		}
		return nil
	}}
	fetch := func(u *url.URL, limit int64) ([]byte, *url.URL, error) {
		if !same(u) {
			return nil, nil, fmt.Errorf("图标不属于应用来源")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("User-Agent", "Watchcow_R icon discovery")
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, nil, fmt.Errorf("图标请求 HTTP %d", resp.StatusCode)
		}
		body, err := readAllLimited(resp.Body, limit)
		return body, resp.Request.URL, err
	}
	page := *base
	if ref, e := url.Parse(path); e == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
		page = *base.ResolveReference(ref)
	}
	type candidate struct {
		url  *url.URL
		rank int
	}
	var candidates []candidate
	if body, final, e := fetch(&page, 1<<20); e == nil {
		docbase := final
		z := html.NewTokenizer(bytes.NewReader(body))
		for {
			tt := z.Next()
			if tt == html.ErrorToken {
				break
			}
			if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
				continue
			}
			t := z.Token()
			attrs := map[string]string{}
			for _, a := range t.Attr {
				attrs[strings.ToLower(a.Key)] = a.Val
			}
			if t.Data == "base" && attrs["href"] != "" {
				if r, e := url.Parse(attrs["href"]); e == nil {
					u := final.ResolveReference(r)
					if same(u) {
						docbase = u
					}
				}
			}
			if t.Data != "link" || attrs["href"] == "" {
				continue
			}
			rel := " " + strings.ToLower(attrs["rel"]) + " "
			if !strings.Contains(rel, " icon ") && !strings.Contains(rel, " apple-touch-icon ") {
				continue
			}
			r, e := url.Parse(attrs["href"])
			if e != nil {
				continue
			}
			u := docbase.ResolveReference(r)
			if !same(u) {
				continue
			}
			rank := 0
			if strings.Contains(rel, "apple-touch-icon") {
				rank = 2
			}
			if strings.Contains(strings.ToLower(attrs["type"]), "svg") || strings.HasSuffix(strings.ToLower(u.Path), ".svg") {
				rank = -1
			}
			if rank >= 0 {
				candidates = append(candidates, candidate{u, rank})
			}
		}
	}
	// Prefer the site's declared icons. Raster touch icons also cover sites
	// whose favicon is SVG, which the fnOS desktop cannot use directly.
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].rank > candidates[j].rank })
	for _, p := range []string{"/favicon.ico", "/favicon.png", "/apple-touch-icon.png"} {
		u := *base
		u.Path = p
		candidates = append(candidates, candidate{&u, 0})
	}
	seen := map[string]bool{}
	attempts := 0
	for _, c := range candidates {
		if attempts >= 7 || ctx.Err() != nil {
			break
		}
		s := c.url.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		attempts++
		body, _, err := fetch(c.url, 2<<20)
		if err != nil {
			continue
		}
		img, err := decodeImageData(body)
		if err == nil {
			return img, s, nil
		}
	}
	return nil, "", fmt.Errorf("未获取到可用的网页图标，保留现有图标")
}

func IconPNGs(img image.Image) ([]byte, []byte, error) {
	small, large := prepareIcons(img)
	var a, b bytes.Buffer
	if err := png.Encode(&a, small); err != nil {
		return nil, nil, err
	}
	if err := png.Encode(&b, large); err != nil {
		return nil, nil, err
	}
	return a.Bytes(), b.Bytes(), nil
}

func automaticEntryIcon(a *AppConfig, e Entry) image.Image {
	if !AutomaticIcon(a, e) || e.Redirect != "" {
		return nil
	}
	protocol := e.Protocol
	if protocol == "" {
		protocol = "http"
	}
	if protocol != "http" && protocol != "https" {
		return nil
	}
	p, err := strconv.Atoi(e.Port)
	if err != nil || p < 1 || p > 65535 {
		return nil
	}
	img, _, _ := DiscoverWebIcon(context.Background(), protocol+"://127.0.0.1:"+e.Port, e.Path)
	return img
}
