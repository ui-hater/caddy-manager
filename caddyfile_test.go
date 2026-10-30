package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanAndTakeOver takes over a realistic existing configuration and
// checks that Caddy still accepts the result and serves the same hosts.
func TestScanAndTakeOver(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	main := write("Caddyfile", `# meine Caddyfile
{
	admin localhost:2019
	email alt@example.com
}

(headers) {
	header X-Frame-Options DENY
}

app.example.com {
	reverse_proxy 10.0.0.1:80 10.0.0.2:80
}

https://blog.example.com:443 { # Kommentar
	import headers
	respond "Klammern im Text: { }" 200
}

a.example.com, b.example.com {
	respond "zwei"
}

http://plain.example.com {
	respond "http"
}

import conf.d/*.caddy
`)
	write("conf.d/one.caddy", `docs.example.org {
	respond <<HTML
		<h1>Hallo { }</h1>
		HTML 200
}
`)
	write("conf.d/two.caddy", `# leer bis auf einen Kommentar
shop.example.co.uk {
	reverse_proxy shop:8080
}
`)

	res, err := ScanCaddyConfig(main)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Proxy{}
	for _, p := range res.Sites {
		got[p.Host] = p
	}
	if len(got) != 4 {
		t.Fatalf("übernommen: %+v", res.Sites)
	}
	if p := got["app.example.com"]; p.Opts.Kind != "" || p.Upstream != "10.0.0.1:80 10.0.0.2:80" || p.Namespace != "example.com" {
		t.Errorf("reverse_proxy nicht als normale site übernommen: %+v", p)
	}
	if p := got["blog.example.com"]; p.Opts.Kind != KindRaw || !strings.Contains(p.Opts.Raw, `respond "Klammern im Text: { }" 200`) || !strings.Contains(p.Opts.Raw, "# Kommentar") {
		t.Errorf("roh-site falsch: %q", p.Opts.Raw)
	}
	if p := got["shop.example.co.uk"]; p.Namespace != "example.co.uk" || p.Upstream != "shop:8080" {
		t.Errorf("public suffix nicht beachtet: %+v", p)
	}
	if p := got["docs.example.org"]; !strings.Contains(p.Opts.Raw, "<h1>Hallo { }</h1>") {
		t.Errorf("heredoc verloren: %q", p.Opts.Raw)
	}
	if strings.Join(res.Kept, ";") != "a.example.com, b.example.com;http://plain.example.com" {
		t.Errorf("nicht übernommen: %q", res.Kept)
	}

	st := Settings{CaddyConfig: main, SitesDir: filepath.Join(dir, "sites"), Email: "neu@example.com"}
	for i := range res.Sites {
		res.Sites[i].ID = int64(i + 1)
	}
	if err := NewCaddy(st).ApplyWith(res.Sites, res.Files); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(main)
	m := string(b)
	for _, want := range []string{"# meine Caddyfile", "admin localhost:2019", "\temail neu@example.com\n", "(headers) {", "a.example.com, b.example.com {", "http://plain.example.com {", "import conf.d/*.caddy\n\nimport " + filepath.ToSlash(st.SitesDir) + "/*.caddy\n"} {
		if !strings.Contains(m, want) {
			t.Errorf("%q fehlt in der caddyfile:\n%s", want, m)
		}
	}
	if strings.Contains(m, "app.example.com") || strings.Contains(m, "alt@example.com") {
		t.Errorf("übernommene site oder alte e-mail noch da:\n%s", m)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "conf.d/two.caddy")); string(b) != "# leer bis auf einen Kommentar\n" {
		t.Errorf("two.caddy: %q", b)
	}
	cfgJSON, err := validateCaddyfile(t, main)
	if err != nil {
		sites, _ := readSites(st.SitesDir)
		t.Fatalf("%v\n%s\n%s", err, m, sites)
	}
	for _, host := range []string{"app.example.com", "blog.example.com", "docs.example.org", "shop.example.co.uk", "a.example.com", "plain.example.com"} {
		if !strings.Contains(string(cfgJSON), `"`+host+`"`) {
			t.Errorf("%s fehlt in der caddy-config", host)
		}
	}

	// applying again changes nothing
	files, _ := plan(st, res.Sites, nil)
	for _, f := range files {
		if !f.InSync() {
			t.Errorf("%s nach dem schreiben nicht aktuell", f.Path)
		}
	}
}

func TestEnsureMainConfig(t *testing.T) {
	st := Settings{CaddyConfig: "/etc/caddy/Caddyfile", SitesDir: "/etc/caddy/sites"}
	imp := "import /etc/caddy/sites/*.caddy\n"
	cases := []struct{ name, in, email, want string }{
		{"leer", "", "", imp},
		{"vorhanden relativ", "import sites/*.caddy\n", "", "import sites/*.caddy\n"},
		{"anhängen", "x.de {\n\trespond 1\n}", "", "x.de {\n\trespond 1\n}\n\n" + imp},
		{"alte generierte datei", managedHeader + "x.de {\n}\n", "", imp},
		{"email neu", imp, "a@b.de", "{\n\temail a@b.de\n}\n\n" + imp},
		{"email ersetzen", "{\n\tadmin off\n\temail alt@b.de # x\n}\n" + imp, "a@b.de", "{\n\tadmin off\n\temail a@b.de # x\n}\n" + imp},
		{"email ergänzen", "{\n\tadmin off\n}\n" + imp, "a@b.de", "{\n\temail a@b.de\n\tadmin off\n}\n" + imp},
	}
	for _, c := range cases {
		st.Email = c.email
		got, err := ensureMainConfig(c.in, st)
		if err != nil || got != c.want {
			t.Errorf("%s: %v\n%q\nwant %q", c.name, err, got, c.want)
		}
	}
	if _, err := ensureMainConfig("example.com\nrespond 1\n", st); err == nil {
		t.Error("caddyfile ohne klammern akzeptiert")
	}
}

func TestPlanKeepsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	st := Settings{CaddyConfig: filepath.Join(dir, "Caddyfile"), SitesDir: filepath.Join(dir, "sites")}
	os.MkdirAll(st.SitesDir, 0o755)
	os.WriteFile(filepath.Join(st.SitesDir, "eigene.caddy"), []byte("x.example.net {\n\trespond 1\n}\n"), 0o644)
	os.WriteFile(filepath.Join(st.SitesDir, "example.com.caddy"), []byte("y.example.com {\n\trespond 1\n}\n"), 0o644)
	p := Proxy{ID: 1, Namespace: "example.com", Host: "a.example.com", Upstream: "10.0.0.1:80", Enabled: true}
	if err := NewCaddy(st).Apply([]Proxy{p}); err == nil || !strings.Contains(err.Error(), "nicht von caddy-manager erzeugt") {
		t.Fatalf("fremde datei überschrieben: %v", err)
	}
	os.Remove(filepath.Join(st.SitesDir, "example.com.caddy"))
	if err := NewCaddy(st).Apply([]Proxy{p}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(st.SitesDir, "eigene.caddy")); !strings.Contains(string(b), "x.example.net") {
		t.Fatal("eigene datei angefasst")
	}
}

func TestNormalizeRaw(t *testing.T) {
	for _, bad := range []string{"", "respond \"{\"\n}\nevil.com {\n", "}\nevil.com {", "handle {", "respond \"offen"} {
		if _, err := normalizeRaw(bad); err == nil {
			t.Errorf("%q akzeptiert", bad)
		}
	}
	if got, err := normalizeRaw("\thandle /x {\r\n\t\trespond \"}\"\r\n\t}"); err != nil || got != "\thandle /x {\n\t\trespond \"}\"\n\t}\n" {
		t.Errorf("%q %v", got, err)
	}
}
