package main

import (
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, c: &http.Client{Jar: jar}}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (c *client) get(path string) string {
	resp, err := c.c.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func (c *client) csrf() string {
	m := csrfRe.FindStringSubmatch(c.get("/account"))
	if m == nil {
		c.t.Fatal("kein csrf token")
	}
	return m[1]
}

func (c *client) post(path string, form url.Values) string {
	form = maps.Clone(form)
	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf") == "" && path != "/login" && path != "/setup" {
		form.Set("csrf", c.csrf())
	}
	resp, err := c.c.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func setup(t *testing.T) (*App, *httptest.Server, string) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.MinCost)
	if _, err := store.CreateUser(User{Username: "admin", PasswordHash: string(h), IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	tfs, _ := fs.Sub(assets, ".")
	pages, err := loadPages(tfs)
	if err != nil {
		t.Fatal(err)
	}
	caddyfile := filepath.Join(dir, "Caddyfile")
	app := &App{store: store, caddy: NewCaddy(Settings{CaddyFile: caddyfile, CaddyBin: "caddy"}),
		sessions: NewSessions(), limiter: NewLoginLimiter(), pages: pages}
	srv := httptest.NewServer(app.Routes(tfs))
	t.Cleanup(srv.Close)
	return app, srv, caddyfile
}

func TestFullFlow(t *testing.T) {
	app, srv, caddyfile := setup(t)

	admin := newClient(t, srv.URL)
	if body := admin.post("/login", url.Values{"username": {"admin"}, "password": {"falsch"}}); !strings.Contains(body, "falsch") {
		t.Fatal("falsches Passwort akzeptiert?")
	}
	admin.post("/login", url.Values{"username": {"admin"}, "password": {"adminpass123"}})

	admin.post("/admin/namespaces", url.Values{"domain": {"AaronHosting.xyz"}})
	admin.post("/admin/namespaces", url.Values{"domain": {"leons.cc"}})
	if body := admin.post("/admin/namespaces", url.Values{"domain": {"sub.leons.cc"}}); !strings.Contains(body, "überschneidet") {
		t.Fatal("verschachtelter Namespace erlaubt")
	}
	admin.post("/admin/users", url.Values{"username": {"aaron"}, "password": {"startpass123"}, "namespace": {"aaronhosting.xyz"}})
	admin.post("/admin/users", url.Values{"username": {"bob"}, "password": {"startpass123"}, "namespace": {"aaronhosting.xyz"}})
	admin.post("/admin/users", url.Values{"username": {"leon"}, "password": {"startpass123"}, "namespace": {"leons.cc"}})

	// aaron: must change password first
	aaron := newClient(t, srv.URL)
	aaron.post("/login", url.Values{"username": {"aaron"}, "password": {"startpass123"}})
	if body := aaron.get("/"); !strings.Contains(body, "Einmal-Passwort") {
		t.Fatal("kein Zwang zum Passwortwechsel")
	}
	if body := aaron.post("/account/password", url.Values{"current": {"startpass123"}, "new": {"meinneuespw1"}, "confirm": {"meinneuespw1"}}); !strings.Contains(body, "Passwort geändert") {
		t.Fatalf("passwortwechsel fehlgeschlagen")
	}

	body := aaron.post("/proxies", url.Values{"subdomain": {"app"}, "upstream": {"127.0.0.1:3000"}})
	if !strings.Contains(body, "app.aaronhosting.xyz angelegt") {
		t.Fatalf("proxy nicht angelegt: %s", body)
	}
	aaron.post("/proxies", url.Values{"subdomain": {"@"}, "upstream": {"http://localhost:8080"}})
	// trying to escape the namespace via the form field must not work
	aaron.post("/proxies", url.Values{"subdomain": {"x"}, "namespace": {"leons.cc"}, "upstream": {"127.0.0.1:1"}})
	// injection attempts
	for _, up := range []string{"127.0.0.1:80\n}\nevil.com {", "127.0.0.1:80 {", "a b:80", "127.0.0.1"} {
		if b := aaron.post("/proxies", url.Values{"subdomain": {"inj"}, "upstream": {up}}); !strings.Contains(b, "flash err") {
			t.Fatalf("upstream %q akzeptiert", up)
		}
	}
	if b := aaron.post("/proxies", url.Values{"subdomain": {"a {"}, "upstream": {"127.0.0.1:1"}}); !strings.Contains(b, "flash err") {
		t.Fatal("ungültige subdomain akzeptiert")
	}
	if b := aaron.post("/proxies", url.Values{"subdomain": {"app"}, "upstream": {"127.0.0.1:1"}}); !strings.Contains(b, "bereits vergeben") {
		t.Fatal("doppelter host akzeptiert")
	}

	// bob shares the namespace and sees aaron's proxy
	bob := newClient(t, srv.URL)
	bob.post("/login", url.Values{"username": {"bob"}, "password": {"startpass123"}})
	bob.post("/account/password", url.Values{"current": {"startpass123"}, "new": {"bobsneuespw1"}, "confirm": {"bobsneuespw1"}})
	if !strings.Contains(bob.get("/"), "app.aaronhosting.xyz") {
		t.Fatal("bob sieht proxy im gemeinsamen namespace nicht")
	}

	// leon must neither see nor delete them
	leon := newClient(t, srv.URL)
	leon.post("/login", url.Values{"username": {"leon"}, "password": {"startpass123"}})
	leon.post("/account/password", url.Values{"current": {"startpass123"}, "new": {"leonsneuespw1"}, "confirm": {"leonsneuespw1"}})
	if strings.Contains(leon.get("/"), "aaronhosting") {
		t.Fatal("leon sieht fremden namespace")
	}
	var appID string
	for _, p := range app.store.Proxies("") {
		if p.Host == "app.aaronhosting.xyz" {
			appID = itoa(p.ID)
		}
	}
	leon.post("/proxies/"+appID+"/delete", url.Values{})
	if _, err := app.store.ProxyByID(atoi(appID)); err != nil {
		t.Fatal("leon konnte fremden proxy löschen")
	}
	if b := leon.get("/admin/users"); !strings.Contains(b, "Nur für Administratoren") {
		t.Fatal("leon kommt in admin bereich")
	}
	// CSRF
	if b := leon.post("/proxies", url.Values{"csrf": {"falsch"}, "subdomain": {"x"}, "upstream": {"127.0.0.1:1"}}); !strings.Contains(b, "CSRF") {
		t.Fatal("csrf nicht geprüft")
	}

	bob.post("/proxies/"+appID+"/update", url.Values{"kind": {"proxy"}, "upstream": {"127.0.0.1:4000"}})

	cf, _ := os.ReadFile(caddyfile)
	want := "app.aaronhosting.xyz {\n\treverse_proxy 127.0.0.1:4000\n}"
	if !strings.Contains(string(cf), want) || !strings.Contains(string(cf), "aaronhosting.xyz {\n\treverse_proxy http://localhost:8080\n}") {
		t.Fatalf("caddyfile unerwartet:\n%s", cf)
	}
	if strings.Contains(string(cf), "leons.cc") || strings.Contains(string(cf), "evil") {
		t.Fatalf("caddyfile enthält fremdes:\n%s", cf)
	}

	bob.post("/proxies/"+appID+"/delete", url.Values{})
	cf, _ = os.ReadFile(caddyfile)
	if strings.Contains(string(cf), "app.aaronhosting.xyz") {
		t.Fatal("proxy nach löschen noch in caddyfile")
	}

	// admin password reset logs the user out
	if b := admin.post("/admin/users/"+itoa(mustUser(t, app, "bob").ID)+"/password", url.Values{}); !strings.Contains(b, "Einmal-Passwort für bob") {
		t.Fatal("reset fehlgeschlagen")
	}
	if b := bob.get("/"); !strings.Contains(b, "Anmelden") {
		t.Fatal("bob nach reset nicht abgemeldet")
	}
}

func TestCaddyRollback(t *testing.T) {
	app, srv, caddyfile := setup(t)
	app.caddy.Configure(Settings{CaddyFile: caddyfile, CaddyBin: filepath.Join(t.TempDir(), "gibts-nicht"), Reload: true})
	os.WriteFile(caddyfile, []byte("ALT"), 0o644)

	admin := newClient(t, srv.URL)
	admin.post("/login", url.Values{"username": {"admin"}, "password": {"adminpass123"}})
	admin.post("/admin/namespaces", url.Values{"domain": {"leons.cc"}})
	if b := admin.post("/proxies", url.Values{"namespace": {"leons.cc"}, "subdomain": {"x"}, "upstream": {"127.0.0.1:1"}}); !strings.Contains(b, "fehlgeschlagen") {
		t.Fatal("fehler von caddy nicht gemeldet")
	}
	if cf, _ := os.ReadFile(caddyfile); string(cf) != "ALT" {
		t.Fatalf("caddyfile nicht zurückgerollt: %s", cf)
	}
	if len(app.store.Proxies("")) != 0 {
		t.Fatal("proxy trotz fehler gespeichert")
	}
}

func mustUser(t *testing.T, a *App, name string) User {
	u, err := a.store.UserByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func atoi(s string) int64 { i, _ := strconv.ParseInt(s, 10, 64); return i }

func TestSetup(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tfs, _ := fs.Sub(assets, ".")
	pages, _ := loadPages(tfs)
	app := &App{store: store, caddy: NewCaddy(store.Settings()), sessions: NewSessions(), limiter: NewLoginLimiter(), pages: pages}
	srv := httptest.NewServer(app.Routes(tfs))
	defer srv.Close()

	c := newClient(t, srv.URL)
	if b := c.get("/"); !strings.Contains(b, "Ersteinrichtung") || !strings.Contains(b, "/etc/caddy/Caddyfile") {
		t.Fatal("keine Setup-Seite mit Standardwerten")
	}
	if b := c.get("/login"); !strings.Contains(b, "Ersteinrichtung") {
		t.Fatal("login vor setup erreichbar")
	}
	cf := filepath.Join(dir, "managed.caddy")
	form := url.Values{"username": {"chef"}, "password": {"geheim12345"}, "confirm": {"anders12345"}, "caddy_file": {cf}}
	if b := c.post("/setup", form); !strings.Contains(b, "stimmen nicht") {
		t.Fatal("passwort-bestätigung nicht geprüft")
	}
	form.Set("confirm", "geheim12345")
	if b := c.post("/setup", form); !strings.Contains(b, "Namespaces") {
		t.Fatalf("setup fehlgeschlagen: %s", b)
	}
	u := mustUser(t, app, "chef")
	if !u.IsAdmin || u.MustChangePassword {
		t.Fatalf("admin falsch angelegt: %+v", u)
	}
	if st := store.Settings(); st.CaddyFile != cf || st.Reload {
		t.Fatalf("settings nicht gespeichert: %+v", st)
	}

	// second setup must be impossible
	other := newClient(t, srv.URL)
	form.Set("username", "boese")
	other.post("/setup", form)
	if _, err := store.UserByName("boese"); err == nil {
		t.Fatal("zweites setup möglich")
	}

	// logged in right after setup, proxies end up in the configured file
	c.post("/admin/namespaces", url.Values{"domain": {"aaronhosting.xyz"}})
	c.post("/proxies", url.Values{"namespace": {"aaronhosting.xyz"}, "subdomain": {"vm2"}, "upstream": {"10.0.0.12:80"}})
	if b, _ := os.ReadFile(cf); !strings.Contains(string(b), "vm2.aaronhosting.xyz {\n\treverse_proxy 10.0.0.12:80\n}") {
		t.Fatalf("caddyfile: %s", b)
	}
}

func TestAdminDashboard(t *testing.T) {
	app, srv, caddyfile := setup(t)
	admin := newClient(t, srv.URL)
	admin.post("/login", url.Values{"username": {"admin"}, "password": {"adminpass123"}})

	if b := admin.get("/admin"); !strings.Contains(b, "Admin-Übersicht") {
		t.Fatal("admin dashboard fehlt")
	}
	admin.post("/admin/namespaces", url.Values{"domain": {"aaronhosting.xyz"}, "back": {"/admin"}})
	b := admin.post("/admin/users", url.Values{"username": {"leon"}, "namespace": {"aaronhosting.xyz"}, "back": {"/admin"}})
	if !strings.Contains(b, "Admin-Übersicht") || !strings.Contains(b, "Einmal-Passwort: ") {
		t.Fatal("konto anlegen vom dashboard leitet nicht zurück / kein passwort")
	}

	// admin sets a specific password
	id := itoa(mustUser(t, app, "leon").ID)
	admin.post("/admin/users/"+id+"/password", url.Values{"password": {"festespasswort"}})
	pw := "festespasswort"

	leon := newClient(t, srv.URL)
	leon.post("/login", url.Values{"username": {"leon"}, "password": {pw}})
	leon.post("/account/password", url.Values{"current": {pw}, "new": {"leonsneuespw1"}, "confirm": {"leonsneuespw1"}})
	home := leon.get("/")
	if strings.Contains(home, `href="/admin"`) {
		t.Fatal("normaler user sieht admin-link")
	}
	if b := leon.get("/admin"); !strings.Contains(b, "Nur für Administratoren") {
		t.Fatal("normaler user kommt ins admin-dashboard")
	}

	// subdomains: required, full name accepted, nested allowed
	if b := leon.post("/proxies", url.Values{"subdomain": {""}, "upstream": {"10.0.0.2:80"}}); !strings.Contains(b, "Bitte eine Subdomain") {
		t.Fatal("leere subdomain akzeptiert")
	}
	leon.post("/proxies", url.Values{"subdomain": {"social"}, "upstream": {"10.0.0.2:3000"}})
	leon.post("/proxies", url.Values{"subdomain": {"tt.aaronhosting.xyz"}, "upstream": {"10.0.0.3:8080"}})
	leon.post("/proxies", url.Values{"subdomain": {"api.tt"}, "upstream": {"10.0.0.3:9000"}})
	cf, _ := os.ReadFile(caddyfile)
	for _, want := range []string{"social.aaronhosting.xyz {", "tt.aaronhosting.xyz {", "api.tt.aaronhosting.xyz {"} {
		if !strings.Contains(string(cf), want) {
			t.Fatalf("%q fehlt in caddyfile:\n%s", want, cf)
		}
	}
	if b := admin.get("/admin"); !strings.Contains(b, "api.tt.aaronhosting.xyz") {
		t.Fatal("neue subdomains nicht im dashboard")
	}

	// delete from dashboard
	if b := admin.post("/admin/users/"+id+"/delete", url.Values{"back": {"/admin"}}); !strings.Contains(b, "Admin-Übersicht") {
		t.Fatal("löschen leitet nicht zum dashboard")
	}
	if _, err := app.store.UserByName("leon"); err == nil {
		t.Fatal("konto nicht gelöscht")
	}
	// back parameter must not allow open redirects
	if adminBack(&http.Request{Form: url.Values{"back": {"https://evil.example"}}}, "/admin/users") != "/admin/users" {
		t.Fatal("open redirect")
	}
}

func TestEditSite(t *testing.T) {
	app, srv, caddyfile := setup(t)
	admin := newClient(t, srv.URL)
	admin.post("/login", url.Values{"username": {"admin"}, "password": {"adminpass123"}})
	admin.post("/admin/namespaces", url.Values{"domain": {"aaronhosting.xyz"}})
	admin.post("/admin/users", url.Values{"username": {"bob"}, "password": {"startpass123"}, "namespace": {"aaronhosting.xyz"}})
	bob := newClient(t, srv.URL)
	bob.post("/login", url.Values{"username": {"bob"}, "password": {"startpass123"}})
	bob.post("/account/password", url.Values{"current": {"startpass123"}, "new": {"bobsneuespw1"}, "confirm": {"bobsneuespw1"}})
	bob.post("/proxies", url.Values{"subdomain": {"pve"}, "upstream": {"https://10.0.0.5:8006"}})
	id := itoa(app.store.Proxies("")[0].ID)

	if b := bob.get("/proxies/" + id); !strings.Contains(b, "Pfad-Routen") || strings.Contains(b, "Eigene Caddy-Direktiven") {
		t.Fatal("bearbeiten-seite falsch (oder zeigt nicht-admins eigene direktiven)")
	}
	form := url.Values{
		"kind": {"proxy"}, "upstream": {"https://10.0.0.5:8006"}, "tls_skip_verify": {"on"},
		"route_path": {"/api", ""}, "route_upstream": {"10.0.0.6:9000", ""}, "route_strip": {"1", "0"},
		"auth_user": {"leon"}, "auth_password": {"geheim123"}, "allow_ips": {"private_ranges"},
		"compress": {"on"}, "extra": {"header X-Evil 1"},
	}
	if b := bob.post("/proxies/"+id+"/update", form); !strings.Contains(b, "gespeichert") {
		t.Fatalf("speichern fehlgeschlagen: %s", b)
	}
	p, _ := app.store.ProxyByID(atoi(id))
	if p.Opts.Extra != "" {
		t.Fatal("nicht-admin konnte eigene direktiven setzen")
	}
	hash := p.Opts.BasicAuthHash
	if hash == "" || len(p.Opts.Routes) != 1 || !p.Opts.Routes[0].Strip || !p.Opts.TLSSkipVerify {
		t.Fatalf("optionen nicht gespeichert: %+v", p.Opts)
	}
	// saving again without password keeps the hash
	form.Del("auth_password")
	bob.post("/proxies/"+id+"/update", form)
	if p, _ = app.store.ProxyByID(atoi(id)); p.Opts.BasicAuthHash != hash {
		t.Fatal("passwort-hash beim erneuten speichern verloren")
	}
	cf, _ := os.ReadFile(caddyfile)
	for _, want := range []string{"handle_path /api/*", "basic_auth", "tls_insecure_skip_verify", "not remote_ip private_ranges"} {
		if !strings.Contains(string(cf), want) {
			t.Fatalf("%q fehlt:\n%s", want, cf)
		}
	}

	// injection attempts are rejected and nothing changes
	for _, f := range []url.Values{
		{"kind": {"respond"}, "respond_status": {"200"}, "respond_body": {"{env.SECRET}"}},
		{"kind": {"redirect"}, "redirect_to": {"https://x.de/\"\n}"}},
		{"kind": {"proxy"}, "upstream": {"10.0.0.1:80"}, "route_path": {"/a {"}, "route_upstream": {"10.0.0.2:80"}},
	} {
		if b := bob.post("/proxies/"+id+"/update", f); !strings.Contains(b, "flash err") {
			t.Fatalf("injection %v akzeptiert", f)
		}
	}
	if cf2, _ := os.ReadFile(caddyfile); string(cf2) != string(cf) {
		t.Fatal("caddyfile nach abgelehnter eingabe verändert")
	}

	// admin may add raw directives
	form.Set("extra", "header X-Robots-Tag noindex")
	b := admin.post("/proxies/"+id+"/update", form)
	if cf, _ = os.ReadFile(caddyfile); !strings.Contains(string(cf), "header X-Robots-Tag noindex") {
		t.Fatalf("admin-direktive fehlt: %v\n%s", regexp.MustCompile(`<title>[^<]*<|class="flash[^<]*<`).FindAllString(b, -1), cf)
	}
	if b := admin.post("/proxies/"+id+"/update", url.Values{"kind": {"proxy"}, "upstream": {"10.0.0.1:80"}, "extra": {"}\nevil.com {"}}); !strings.Contains(b, "flash err") {
		t.Fatal("unausgeglichene klammern akzeptiert")
	}

	// HTTP headers via the form; empty name rows are ignored
	hform := url.Values{
		"kind": {"proxy"}, "upstream": {"10.0.0.1:80"},
		"hdr_target": {"response", "request", "response"},
		"hdr_op":     {"set", "delete", "set"},
		"hdr_name":   {"X-Frame-Options", "Cookie", ""},
		"hdr_value":  {"DENY", "", ""},
	}
	if b := bob.post("/proxies/"+id+"/update", hform); !strings.Contains(b, "gespeichert") {
		t.Fatalf("header speichern fehlgeschlagen: %s", regexp.MustCompile(`class="flash[^<]*<`).FindString(b))
	}
	if p, _ = app.store.ProxyByID(atoi(id)); len(p.Opts.Headers) != 2 {
		t.Fatalf("header nicht gespeichert: %+v", p.Opts.Headers)
	}
	if cf, _ = os.ReadFile(caddyfile); !strings.Contains(string(cf), `X-Frame-Options "DENY"`) || !strings.Contains(string(cf), "header_up -Cookie") {
		t.Fatalf("header fehlen in caddyfile:\n%s", cf)
	}
	hform["hdr_value"] = []string{"{env.SECRET}", "", ""}
	if b := bob.post("/proxies/"+id+"/update", hform); !strings.Contains(b, "flash err") {
		t.Fatal("platzhalter im header-wert akzeptiert")
	}
	if b := bob.get("/proxies/" + id); !strings.Contains(b, `value="X-Frame-Options"`) {
		t.Fatal("header nicht im formular")
	}

	// redirect, then disable
	bob.post("/proxies/"+id+"/update", url.Values{"kind": {"redirect"}, "redirect_to": {"https://proxmox.example.com"}, "redirect_code": {"301"}})
	if cf, _ = os.ReadFile(caddyfile); !strings.Contains(string(cf), "redir https://proxmox.example.com 301") {
		t.Fatalf("redirect fehlt:\n%s", cf)
	}
	bob.post("/proxies/"+id+"/toggle", url.Values{})
	if cf, _ = os.ReadFile(caddyfile); strings.Contains(string(cf), "pve.aaronhosting.xyz {") {
		t.Fatal("deaktivierte subdomain noch aktiv")
	}
}
