package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"watchcow/internal/fpkgen"
)

type iconState struct {
	Origin  string    `json:"origin"`
	Source  string    `json:"source,omitempty"`
	Message string    `json:"message"`
	Checked time.Time `json:"checked"`
	Preview []byte    `json:"preview,omitempty"`
}

var iconEntryID = regexp.MustCompile(`^[a-zA-Z0-9_-]*$`)

func (m *Manager) loadIcons() {
	if m.icons != nil {
		return
	}
	m.icons = map[string]iconState{}
	if b, err := os.ReadFile(filepath.Join(m.Dir, "icons.json")); err == nil {
		_ = json.Unmarshal(b, &m.icons)
		if m.icons == nil {
			m.icons = map[string]iconState{}
		}
	}
}
func (m *Manager) saveIcons() error {
	b, err := json.Marshal(m.icons)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.Dir, "icons.json"), b, 0600)
}

func (m *Manager) iconEligible(r Route) bool {
	if m.settings.Entries[r.Key].IconMode == "keep" || !r.Active || m.desktopBusy[r.AppName] {
		return false
	}
	a := m.Registry.Get(r.AppName)
	if a == nil {
		return false
	}
	e := a.GetEntry(r.Entry)
	return e != nil && fpkgen.AutomaticIcon(a, *e)
}

func (m *Manager) SyncIcons(ctx context.Context) {
	m.mu.Lock()
	m.loadIcons()
	rows := append([]Route{}, m.rows...)
	m.mu.Unlock()
	for _, r := range rows {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		prior := m.icons[r.Key]
		webOrigin, _ := rootProxyOrigin(r)
		origin := webOrigin + r.Path
		wait := time.Hour
		if prior.Source != "" {
			wait = 24 * time.Hour
		}
		eligible := webOrigin != "" && m.iconEligible(r) && !(prior.Origin == origin && time.Since(prior.Checked) < wait)
		m.mu.Unlock()
		if !eligible {
			continue
		}
		img, source, err := fpkgen.DiscoverWebIcon(ctx, webOrigin, r.Path)
		if ctx.Err() != nil {
			return
		}
		var small, large []byte
		if err == nil {
			small, large, err = fpkgen.IconPNGs(img)
		}
		m.mu.Lock()
		current, exists := m.routes[r.Host]
		currentOrigin, _ := rootProxyOrigin(current)
		if !exists || currentOrigin != webOrigin || current.Path != r.Path || !m.iconEligible(r) {
			m.mu.Unlock()
			continue
		}
		next := iconState{Origin: origin, Checked: time.Now(), Message: "网页图标已更新", Source: source, Preview: small}
		if err == nil {
			err = m.writeIconFiles(r, small, large)
		}
		if err != nil {
			next.Message = err.Error()
			next.Source = prior.Source
			next.Preview = prior.Preview
		}
		m.icons[r.Key] = next
		if err := m.saveIcons(); err != nil {
			m.icons[r.Key] = prior
		}
		m.mu.Unlock()
	}
}

func (m *Manager) writeIconFiles(r Route, small, large []byte) error {
	if !desktopID.MatchString(r.AppName) || !iconEntryID.MatchString(r.Entry) {
		return fmt.Errorf("无效的应用图标路径")
	}
	root := filepath.Join(m.AppsDir, r.AppName, "target")
	images := filepath.Join(root, "ui", "images")
	actualRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	actualImages, err := filepath.EvalSymlinks(images)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(actualRoot, actualImages)
	if err != nil || rel == ".." || len(rel) > 3 && rel[:3] == "../" {
		return fmt.Errorf("图标目录位于应用包之外")
	}
	stem := "icon"
	if r.Entry != "" {
		stem += "_" + r.Entry
	}
	files := map[string][]byte{filepath.Join(images, stem+"_64.png"): small, filepath.Join(images, stem+"_256.png"): large}
	a := m.Registry.Get(r.AppName)
	if a != nil && a.GetDefaultEntry() != nil && a.GetDefaultEntry().Name == r.Entry {
		for name, data := range map[string][]byte{"ICON.PNG": small, "ICON_256.PNG": large} {
			path := filepath.Join(m.AppsDir, r.AppName, name)
			if _, err := os.Stat(path); err == nil {
				files[path] = data
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	for path := range files {
		if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("图标不是普通文件，保留现状")
		}
		if old, err := os.ReadFile(path); err == nil {
			if owned, ok := m.journal.Files[path]; ok && digest(old) != owned.WrittenHash && digest(old) != digest(owned.Original) {
				return fmt.Errorf("图标发生外部修改，保留现状")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := m.archiveApp(r.AppName); err != nil {
		return err
	}
	for path, data := range files {
		if err := m.trackedWrite(path, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) RunIcons(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		m.SyncIcons(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
