package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Caddy writes one file per namespace into Settings.SitesDir and makes sure
// the main Caddyfile (Settings.CaddyConfig) imports them; everything else in
// the main file belongs to the admin and stays as it is.
type Caddy struct {
	mu sync.Mutex
	st Settings
}

func NewCaddy(st Settings) *Caddy { return &Caddy{st: st} }

func (c *Caddy) Configure(st Settings) {
	c.mu.Lock()
	c.st = st
	c.mu.Unlock()
}

func (c *Caddy) Settings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

func (st Settings) siteFile(namespace string) string {
	return filepath.Join(st.SitesDir, namespace+".caddy")
}

// legacyNote replaces the content of an old single managed file.
func legacyNote(st Settings) string {
	return managedHeader + "# Nicht mehr verwendet: die Sites liegen jetzt in " + filepath.ToSlash(st.SitesDir) + "\n"
}

// FileState is one file caddy-manager writes, as shown on the admin page.
type FileState struct {
	Path     string
	Current  string
	Expected string // empty and Remove set: the file will be deleted
	Exists   bool
	Remove   bool
}

func (f FileState) InSync() bool { return !f.Remove && f.Exists && f.Current == f.Expected }

// plan computes every file that has to change for proxies. extra holds
// files setup rewrites (site blocks cut out); a managed file may only
// replace one of them if nothing but comments is left in it.
func plan(st Settings, proxies []Proxy, extra map[string]string) ([]FileState, error) {
	want := map[string]string{}
	for ns, content := range RenderSites(proxies) {
		want[st.siteFile(ns)] = content
	}
	read := func(path string) (string, bool, error) {
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return string(b), err == nil, err
	}

	var out []FileState
	add := func(path, content string, remove bool) error {
		cur, exists, err := read(path)
		if err != nil {
			return err
		}
		out = append(out, FileState{Path: path, Current: cur, Expected: content, Exists: exists, Remove: remove})
		return nil
	}

	for path, content := range extra {
		if _, ok := want[path]; ok && hasConfig(content) {
			return nil, errf("%s enthält Sites, die nicht übernommen werden können, und heißt wie ein Namespace", path)
		}
		if _, ok := want[path]; !ok && path != st.CaddyConfig {
			// an old generated file whose sites all moved into the database
			remove := strings.HasPrefix(content, managedHeader) && !hasConfig(content)
			if remove {
				content = ""
			}
			if err := add(path, content, remove); err != nil {
				return nil, err
			}
		}
	}
	existing, _ := filepath.Glob(filepath.Join(st.SitesDir, "*.caddy"))
	for _, path := range existing {
		cur, _, err := read(path)
		if err != nil {
			return nil, err
		}
		_, planned := want[path]
		_, rewritten := extra[path]
		switch {
		case !strings.HasPrefix(cur, managedHeader) && planned && !rewritten:
			return nil, errf("%s existiert bereits und wurde nicht von caddy-manager erzeugt", path)
		case strings.HasPrefix(cur, managedHeader) && !planned && !rewritten:
			if err := add(path, "", true); err != nil {
				return nil, err
			}
		}
	}
	for path, content := range want {
		if err := add(path, content, false); err != nil {
			return nil, err
		}
	}

	main, mainExists, err := read(st.CaddyConfig)
	if err != nil {
		return nil, err
	}
	if m, ok := extra[st.CaddyConfig]; ok {
		main = m
	}
	content, err := ensureMainConfig(main, st)
	if err != nil {
		return nil, err
	}
	cur, _, _ := read(st.CaddyConfig)
	out = append(out, FileState{Path: st.CaddyConfig, Current: cur, Expected: content, Exists: mainExists})

	if st.LegacyFile != "" {
		if cur, ok, _ := read(st.LegacyFile); ok && strings.HasPrefix(cur, managedHeader) {
			out = append(out, FileState{Path: st.LegacyFile, Current: cur, Expected: legacyNote(st), Exists: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Files returns the state of every file caddy-manager writes for proxies.
func (c *Caddy) Files(proxies []Proxy) ([]FileState, error) {
	return plan(c.Settings(), proxies, nil)
}

// InSync reports whether the files on disk match the database.
func (c *Caddy) InSync(proxies []Proxy) bool {
	files, err := c.Files(proxies)
	if err != nil {
		return false
	}
	for _, f := range files {
		if !f.InSync() {
			return false
		}
	}
	return true
}

// Apply writes the files for the given proxies, validates and reloads Caddy.
// On any failure the previous files are restored and Caddy keeps its old config.
func (c *Caddy) Apply(proxies []Proxy) error { return c.ApplyWith(proxies, nil) }

// ApplyWith also writes the files in extra (see plan).
func (c *Caddy) ApplyWith(proxies []Proxy, extra map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	files, err := plan(c.st, proxies, extra)
	if err != nil {
		return err
	}
	var done []FileState
	restore := func() {
		for _, f := range done {
			if f.Exists {
				_ = writeFileAtomic(f.Path, []byte(f.Current), 0o644)
			} else {
				_ = os.Remove(f.Path)
			}
		}
	}
	for _, f := range files {
		if f.InSync() || (f.Remove && !f.Exists) {
			continue
		}
		if f.Remove {
			err = os.Remove(f.Path)
		} else if err = os.MkdirAll(filepath.Dir(f.Path), 0o755); err == nil {
			err = writeFileAtomic(f.Path, []byte(f.Expected), 0o644)
		}
		if err != nil {
			restore()
			return errf("Caddyfile schreiben: %v", err)
		}
		done = append(done, f)
	}
	if len(done) == 0 || !c.st.Reload {
		return nil
	}
	if err := c.run("validate"); err != nil {
		restore()
		return errf("Caddy-Validierung fehlgeschlagen: %v", err)
	}
	if err := c.run("reload"); err != nil {
		restore()
		_ = c.run("reload") // best effort: make sure the running config matches the files again
		return errf("Caddy-Reload fehlgeschlagen: %v", err)
	}
	return nil
}

// Reload reloads Caddy with the current files without changing them.
func (c *Caddy) Reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Reload {
		return nil
	}
	return c.run("reload")
}

func (c *Caddy) run(sub string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.st.CaddyBin, sub, "--config", c.st.CaddyConfig, "--adapter", "caddyfile")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return fmt.Errorf("%v: %s", err, msg)
	}
	return nil
}

func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
