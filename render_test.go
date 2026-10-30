package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"golang.org/x/crypto/bcrypt"
)

// TestRenderedCaddyfileIsValid runs every feature through Caddy's own
// Caddyfile adapter and config validation.
func TestRenderedCaddyfileIsValid(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("geheim123"), bcrypt.MinCost)
	proxies := []Proxy{
		{ID: 1, Namespace: "aaronhosting.xyz", Host: "plain.aaronhosting.xyz", Upstream: "10.0.0.12:8080", Enabled: true},
		{ID: 2, Namespace: "aaronhosting.xyz", Host: "full.aaronhosting.xyz", Upstream: "10.0.0.12:8080 10.0.0.13:8080", Enabled: true,
			Opts: SiteOptions{
				LBPolicy: "least_conn", HealthURI: "/health", HostHeader: true,
				Routes: []Route{
					{Path: "/api/*", Upstream: "10.0.0.14:9000", Strip: true},
					{Path: "/static/*", Upstream: "https://10.0.0.15:443"},
				},
				TLSSkipVerify: true,
				BasicAuthUser: "leon", BasicAuthHash: string(hash),
				AllowIPs: []string{"private_ranges", "203.0.113.0/24", "2001:db8::1"},
				Compress: true, HSTS: true, AccessLog: true,
				Extra: "header X-Robots-Tag noindex\nheader -Server",
				Headers: []HeaderRule{
					{Target: HeaderResponse, Op: HeaderSet, Name: "X-Frame-Options", Value: "SAMEORIGIN"},
					{Target: HeaderResponse, Op: HeaderAdd, Name: "Link", Value: "</style.css>; rel=preload; as=style"},
					{Target: HeaderResponse, Op: HeaderDelete, Name: "X-Powered-By"},
					{Target: HeaderRequest, Op: HeaderSet, Name: "X-Real-IP", Value: "trusted-proxy"},
					{Target: HeaderRequest, Op: HeaderDelete, Name: "Cookie"},
				},
			}},
		{ID: 3, Namespace: "aaronhosting.xyz", Host: "pve.aaronhosting.xyz", Upstream: "https://10.0.0.5:8006", Enabled: true,
			Opts: SiteOptions{TLSSkipVerify: true, HostHeader: true, Headers: []HeaderRule{
				{Target: HeaderRequest, Op: HeaderAdd, Name: "X-Forwarded-Prefix", Value: "/pve"},
			}}},
		{ID: 7, Namespace: "leons.cc", Host: "hdr.leons.cc", Upstream: "10.0.0.8:80", Enabled: true,
			Opts: SiteOptions{Headers: []HeaderRule{{Target: HeaderResponse, Op: HeaderSet, Name: "Cache-Control", Value: "no-store"}}}},
		{ID: 4, Namespace: "leons.cc", Host: "leons.cc", Enabled: true,
			Opts: SiteOptions{Kind: KindRedirect, RedirectTo: "https://www.leons.cc", RedirectCode: 301, RedirectKeepPath: true}},
		{ID: 5, Namespace: "leons.cc", Host: "wartung.leons.cc", Enabled: true,
			Opts: SiteOptions{Kind: KindRespond, RespondStatus: 503, RespondBody: "Wartungsarbeiten - bald wieder da", AllowIPs: []string{"10.0.0.0/8"}}},
		{ID: 6, Namespace: "leons.cc", Host: "aus.leons.cc", Upstream: "10.0.0.9:80", Enabled: false},
	}
	dir := t.TempDir()
	st := Settings{CaddyConfig: filepath.Join(dir, "Caddyfile"), SitesDir: filepath.Join(dir, "sites"), Email: "admin@aaronhosting.xyz"}
	if err := NewCaddy(st).Apply(proxies); err != nil {
		t.Fatal(err)
	}
	sites, _ := readSites(st.SitesDir)
	main, _ := os.ReadFile(st.CaddyConfig)
	out := string(main) + string(sites)
	cfgJSON, err := validateCaddyfile(t, st.CaddyConfig)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	if _, err := os.Stat(filepath.Join(st.SitesDir, "leons.cc.caddy")); err != nil {
		t.Error("keine eigene Datei pro Namespace")
	}
	if !strings.HasPrefix(string(main), "{\n\temail admin@aaronhosting.xyz\n}\n") || strings.Contains(string(sites), "email") {
		t.Errorf("globale option email falsch:\n%s", out)
	}
	for _, want := range []string{"basic_auth", "handle_path /api/*", "redir https://www.leons.cc{uri} 301", "# deaktiviert: aus.leons.cc",
		"\t\t\tX-Frame-Options \"SAMEORIGIN\"\n", "\t\t\t+Link \"</style.css>; rel=preload; as=style\"\n", "\t\t\t-X-Powered-By\n", "\t\t\tdefer\n",
		"header_up X-Real-IP \"trusted-proxy\"", "header_up -Cookie", "header_up +X-Forwarded-Prefix \"/pve\""} {
		if !strings.Contains(out, want) {
			t.Errorf("%q fehlt in\n%s", want, out)
		}
	}
	if strings.Contains(string(cfgJSON), "aus.leons.cc") {
		t.Error("deaktivierte Subdomain ist in der Caddy-Config")
	}

	// deleting the last site of a namespace removes its file
	if err := NewCaddy(st).Apply(proxies[:3]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(st.SitesDir, "leons.cc.caddy")); err == nil {
		t.Error("datei eines leeren namespace nicht gelöscht")
	}
}

// validateCaddyfile runs the main Caddyfile (with its imports) through
// Caddy's adapter and config validation and returns the JSON config.
func validateCaddyfile(t *testing.T, main string) ([]byte, error) {
	body, err := os.ReadFile(main)
	if err != nil {
		return nil, err
	}
	cfgJSON, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt(body, map[string]any{"filename": main})
	if err != nil {
		return nil, fmt.Errorf("caddy kann die Caddyfile nicht lesen: %v", err)
	}
	for _, w := range warnings {
		t.Logf("caddy warnung: %s:%d %s", w.File, w.Line, w.Message)
	}
	var cfg caddy.Config
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return nil, err
	}
	// keep validation from touching the real certificate storage
	cfg.StorageRaw = json.RawMessage(`{"module":"file_system","root":"` + strings.ReplaceAll(t.TempDir(), `\`, `/`) + `"}`)
	if err := caddy.Validate(&cfg); err != nil {
		return nil, fmt.Errorf("caddy validate: %v", err)
	}
	return cfgJSON, nil
}

func TestValidation(t *testing.T) {
	bad := map[string]func() error{
		"respond braces":   func() error { return validateRespondBody("{env.SECRET}") },
		"respond quote":    func() error { return validateRespondBody(`a" 200`) },
		"redirect braces":  func() error { _, err := normalizeRedirect("https://x.de/{env.X}"); return err },
		"redirect scheme":  func() error { _, err := normalizeRedirect("javascript:alert(1)"); return err },
		"redirect space":   func() error { _, err := normalizeRedirect("https://x.de/a b"); return err },
		"route path":       func() error { _, err := normalizeRoutePath("/api {"); return err },
		"route root":       func() error { _, err := normalizeRoutePath("/"); return err },
		"health":           func() error { _, err := normalizeHealthURI("/h {"); return err },
		"ip":               func() error { _, err := normalizeAllowIPs("10.0.0.1 }"); return err },
		"mixed schemes":    func() error { _, err := normalizeUpstreams("10.0.0.1:80 https://10.0.0.2:443"); return err },
		"extra unbalanced": func() error { return validateExtra("}\nevil.com {") },
		"extra open":       func() error { return validateExtra("handle {") },
		"email":            func() error { return validateEmail("a b@c") },
		"header env":       hdr(HeaderResponse, HeaderSet, "X-Leak", "{env.SECRET}"),
		"header quote":     hdr(HeaderResponse, HeaderSet, "X-A", `a" }`),
		"header newline":   hdr(HeaderRequest, HeaderSet, "X-A", "a\nevil"),
		"header name":      hdr(HeaderResponse, HeaderSet, "X A {", "1"),
		"header name op":   hdr(HeaderResponse, HeaderSet, "-Server", "1"),
		"header no value":  hdr(HeaderResponse, HeaderSet, "X-A", ""),
		"header target":    hdr("both", HeaderSet, "X-A", "1"),
		"header op":        hdr(HeaderResponse, "replace", "X-A", "1"),
	}
	for name, f := range bad {
		if f() == nil {
			t.Errorf("%s: ungültige Eingabe akzeptiert", name)
		}
	}

	if got, _ := normalizeRoutePath("/api"); got != "/api/*" {
		t.Errorf("route path: %q", got)
	}
	if got, _ := normalizeUpstreams("10.0.0.1:80, 10.0.0.2:80\n10.0.0.3:80"); got != "10.0.0.1:80 10.0.0.2:80 10.0.0.3:80" {
		t.Errorf("upstreams: %q", got)
	}
	if got, _ := normalizeRedirect("HTTPS://WWW.Leons.cc/path?a=1"); got != "https://www.leons.cc/path?a=1" {
		t.Errorf("redirect: %q", got)
	}
	if got, _ := normalizeAllowIPs("private_ranges, 192.168.1.5/24"); strings.Join(got, " ") != "private_ranges 192.168.1.0/24" {
		t.Errorf("ips: %q", got)
	}
}

// TestCaddyValidationCatchesErrors makes sure the test above would notice
// broken output at all.
func TestCaddyValidationCatchesErrors(t *testing.T) {
	adapt := func(p Proxy) error {
		cfgJSON, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(RenderSites([]Proxy{p})[p.Namespace]), nil)
		if err != nil {
			return err
		}
		var cfg caddy.Config
		json.Unmarshal(cfgJSON, &cfg)
		cfg.StorageRaw = json.RawMessage(`{"module":"file_system","root":"` + strings.ReplaceAll(t.TempDir(), `\`, `/`) + `"}`)
		return caddy.Validate(&cfg)
	}
	base := Proxy{ID: 1, Host: "x.aaronhosting.xyz", Upstream: "10.0.0.1:80", Enabled: true}
	p := base
	p.Opts.Extra = "foobar_directive x"
	if adapt(p) == nil {
		t.Error("unbekannte Direktive nicht erkannt")
	}
	p = base
	p.Opts.BasicAuthUser, p.Opts.BasicAuthHash = "leon", "kaputt"
	if adapt(p) == nil {
		t.Error("kaputter Passwort-Hash nicht erkannt")
	}
}

func hdr(target, op, name, value string) func() error {
	return func() error {
		_, err := normalizeHeader(HeaderRule{Target: target, Op: op, Name: name, Value: value})
		return err
	}
}
