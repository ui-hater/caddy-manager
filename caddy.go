package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Caddy writes the generated site blocks to a file and reloads Caddy.
//
// Settings.CaddyFile is the file this program owns completely.
// Settings.CaddyConfig is the config Caddy is started with; it is either
// empty (same file) or a hand-written Caddyfile that contains
// `import <CaddyFile>`.
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

func (st Settings) MainConfig() string {
	if st.CaddyConfig != "" {
		return st.CaddyConfig
	}
	return st.CaddyFile
}

// Apply writes the config for the given proxies, validates and reloads Caddy.
// On any failure the previous file is restored and Caddy keeps its old config.
func (c *Caddy) Apply(proxies []Proxy) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	content := []byte(RenderCaddyfile(proxies, c.st))
	file := c.st.CaddyFile
	old, err := os.ReadFile(file)
	hadOld := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hadOld && bytes.Equal(old, content) {
		return nil
	}
	if err := writeFileAtomic(file, content, 0o644); err != nil {
		return errf("Caddyfile schreiben: %v", err)
	}
	restore := func() {
		if hadOld {
			_ = writeFileAtomic(file, old, 0o644)
		} else {
			_ = os.Remove(file)
		}
	}
	if !c.st.Reload {
		return nil
	}
	if err := c.run("validate"); err != nil {
		restore()
		return errf("Caddy-Validierung fehlgeschlagen: %v", err)
	}
	if err := c.run("reload"); err != nil {
		restore()
		_ = c.run("reload") // best effort: make sure the running config matches the file again
		return errf("Caddy-Reload fehlgeschlagen: %v", err)
	}
	return nil
}

// Reload reloads Caddy with the current file without changing it.
func (c *Caddy) Reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Reload {
		return nil
	}
	return c.run("reload")
}

func (c *Caddy) Current() string {
	b, err := os.ReadFile(c.Settings().CaddyFile)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *Caddy) run(sub string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.st.CaddyBin, sub, "--config", c.st.MainConfig(), "--adapter", "caddyfile")
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
