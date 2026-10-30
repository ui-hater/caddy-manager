package main

import (
	"crypto/subtle"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	store    *Store
	caddy    *Caddy
	sessions *Sessions
	limiter  *LoginLimiter
	pages    map[string]map[string]*template.Template // language -> page -> template

	setupDone atomic.Bool
}

type ctxUser struct {
	User    User
	Session *Session
	Token   string
}

type PageData struct {
	Lang  string
	Langs []string
	Title string
	User  *User
	CSRF  string
	Flash *Flash
	Path  string
	D     map[string]any
}

func loadPages(tfs fs.FS) (map[string]map[string]*template.Template, error) {
	names, err := fs.Glob(tfs, "templates/*.html")
	if err != nil {
		return nil, err
	}
	all := map[string]map[string]*template.Template{}
	for _, lang := range languages {
		pages := map[string]*template.Template{}
		for _, n := range names {
			base := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
			if base == "layout" || base == "partials" {
				continue
			}
			t, err := template.New("layout.html").Funcs(templateFuncs(lang)).ParseFS(tfs, "templates/layout.html", "templates/partials.html", n)
			if err != nil {
				return nil, err
			}
			pages[base] = t
		}
		all[lang] = pages
	}
	return all, nil
}

func (a *App) render(w http.ResponseWriter, r *http.Request, cu *ctxUser, page, title string, d map[string]any) {
	lang := langFromRequest(r)
	pd := PageData{Lang: lang, Langs: languages, Title: T(lang, title), Path: r.URL.Path, D: d}
	if cu != nil {
		pd.User = &cu.User
		pd.CSRF = cu.Session.CSRF
		pd.Flash = a.sessions.PopFlash(cu.Session)
	}
	if f, ok := d["flash"].(*Flash); ok {
		pd.Flash = f
	}
	t := a.pages[lang][page]
	if t == nil {
		http.Error(w, "template missing: "+page, 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, pd); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

// ok redirects with a translated success message.
func (a *App) ok(w http.ResponseWriter, r *http.Request, cu *ctxUser, to, format string, args ...any) {
	a.sessions.SetFlash(cu.Session, "ok", Tf(langFromRequest(r), format, args...))
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// fail redirects with a translated error message.
func (a *App) fail(w http.ResponseWriter, r *http.Request, cu *ctxUser, to string, err error) {
	a.sessions.SetFlash(cu.Session, "err", trErr(langFromRequest(r), err))
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func errFlash(r *http.Request, err error) *Flash {
	return &Flash{Kind: "err", Msg: trErr(langFromRequest(r), err)}
}

// ---- middleware ----

// requireSetup sends every request to /setup until the first admin exists.
func (a *App) requireSetup(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.setupDone.Load() && r.URL.Path != "/setup" && !strings.HasPrefix(r.URL.Path, "/static/") && !strings.HasPrefix(r.URL.Path, "/lang/") {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isHTTPS also trusts X-Forwarded-Proto, because the UI usually runs behind Caddy.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

type authedHandler func(w http.ResponseWriter, r *http.Request, cu *ctxUser)

// auth requires a logged-in user, checks CSRF on POST and enforces
// password changes. admin additionally requires the admin flag.
func (a *App) auth(admin bool, h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, sess := a.sessions.Get(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := a.store.UserByID(sess.UserID)
		if err != nil {
			a.sessions.Destroy(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(sess.CSRF)) != 1 {
				http.Error(w, T(langFromRequest(r), "ungültiges CSRF-Token"), http.StatusForbidden)
				return
			}
		}
		cu := &ctxUser{User: u, Session: sess, Token: tok}
		if u.MustChangePassword && !strings.HasPrefix(r.URL.Path, "/account") && r.URL.Path != "/logout" {
			a.fail(w, r, cu, "/account", errf("Bitte zuerst ein neues Passwort setzen."))
			return
		}
		if admin && !u.IsAdmin {
			http.Error(w, T(langFromRequest(r), "Nur für Administratoren"), http.StatusForbidden)
			return
		}
		h(w, r, cu)
	}
}

func (a *App) Routes(static fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(static))

	mux.HandleFunc("GET /lang/{lang}", a.setLang)
	mux.HandleFunc("GET /setup", a.setupPage)
	mux.HandleFunc("POST /setup", a.setupPost)
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.loginPost)
	mux.HandleFunc("POST /logout", a.auth(false, a.logout))

	mux.HandleFunc("GET /{$}", a.auth(false, a.dashboard))
	mux.HandleFunc("POST /proxies", a.auth(false, a.proxyCreate))
	mux.HandleFunc("GET /proxies/{id}", a.auth(false, a.proxyEditPage))
	mux.HandleFunc("POST /proxies/{id}/update", a.auth(false, a.proxyUpdate))
	mux.HandleFunc("POST /proxies/{id}/toggle", a.auth(false, a.proxyToggle))
	mux.HandleFunc("POST /proxies/{id}/delete", a.auth(false, a.proxyDelete))

	mux.HandleFunc("GET /account", a.auth(false, a.accountPage))
	mux.HandleFunc("POST /account/password", a.auth(false, a.accountPassword))

	mux.HandleFunc("GET /admin", a.auth(true, a.adminDashboard))
	mux.HandleFunc("GET /admin/users", a.auth(true, a.usersPage))
	mux.HandleFunc("POST /admin/users", a.auth(true, a.userCreate))
	mux.HandleFunc("POST /admin/users/{id}/password", a.auth(true, a.userResetPassword))
	mux.HandleFunc("POST /admin/users/{id}/namespace", a.auth(true, a.userSetNamespace))
	mux.HandleFunc("POST /admin/users/{id}/admin", a.auth(true, a.userToggleAdmin))
	mux.HandleFunc("POST /admin/users/{id}/delete", a.auth(true, a.userDelete))

	mux.HandleFunc("GET /admin/namespaces", a.auth(true, a.namespacesPage))
	mux.HandleFunc("POST /admin/namespaces", a.auth(true, a.namespaceCreate))
	mux.HandleFunc("POST /admin/namespaces/{domain}/delete", a.auth(true, a.namespaceDelete))

	mux.HandleFunc("GET /admin/caddy", a.auth(true, a.caddyPage))
	mux.HandleFunc("POST /admin/caddy/apply", a.auth(true, a.caddyApply))
	mux.HandleFunc("POST /admin/caddy/settings", a.auth(true, a.caddySettings))

	a.setupDone.Store(a.store.UserCount() > 0)
	return securityHeaders(a.requireSetup(mux))
}

// ---- login ----

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, sess := a.sessions.Get(r); sess != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.render(w, r, nil, "login", "Anmelden", map[string]any{})
}

// dummyHash makes logins for unknown users take as long as for known ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

func (a *App) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	loginFail := func(msg string) {
		w.WriteHeader(http.StatusUnauthorized)
		a.render(w, r, nil, "login", "Anmelden", map[string]any{
			"flash": &Flash{Kind: "err", Msg: T(langFromRequest(r), msg)}, "username": r.FormValue("username"),
		})
	}
	if a.limiter.Blocked(ip) {
		loginFail("Zu viele Fehlversuche. Bitte in einigen Minuten erneut versuchen.")
		return
	}
	u, err := a.store.UserByName(strings.TrimSpace(r.FormValue("username")))
	hash := dummyHash
	if err == nil {
		hash = []byte(u.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(r.FormValue("password"))) != nil || err != nil {
		a.limiter.Fail(ip)
		loginFail("Benutzername oder Passwort falsch.")
		return
	}
	a.limiter.Success(ip)
	a.sessions.Create(w, u.ID, isHTTPS(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	a.sessions.Destroy(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- proxies ----

func (a *App) dashboard(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	ns := cu.User.Namespace
	if cu.User.IsAdmin {
		ns = r.URL.Query().Get("ns")
	}
	var members []string
	if !cu.User.IsAdmin && ns != "" {
		for _, u := range a.store.Users() {
			if u.Namespace == ns {
				members = append(members, u.Username)
			}
		}
	}
	var proxies []Proxy
	if ns != "" || cu.User.IsAdmin {
		proxies = a.store.Proxies(ns)
	}
	a.render(w, r, cu, "dashboard", "Subdomains", map[string]any{
		"Proxies":    proxies,
		"Namespace":  ns,
		"Namespaces": a.store.Namespaces(),
		"Members":    members,
	})
}

// targetNamespace returns the namespace the user may act in for a request.
func targetNamespace(cu *ctxUser, requested string) (string, error) {
	if cu.User.IsAdmin {
		if requested != "" {
			return requested, nil
		}
		if cu.User.Namespace != "" {
			return cu.User.Namespace, nil
		}
		return "", errf("Bitte einen Namespace wählen")
	}
	if cu.User.Namespace == "" {
		return "", errf("Deinem Konto ist kein Namespace zugewiesen")
	}
	return cu.User.Namespace, nil
}

func (a *App) canEdit(cu *ctxUser, p Proxy) bool {
	return cu.User.IsAdmin || (cu.User.Namespace != "" && p.Namespace == cu.User.Namespace)
}

func backTo(r *http.Request) string {
	if ns := r.FormValue("back_ns"); ns != "" {
		return "/?ns=" + url.QueryEscape(ns)
	}
	return "/"
}

func (a *App) applyChange(c ProxyChange) (Proxy, error) {
	return a.store.ChangeProxies(c, a.caddy.Apply)
}

func (a *App) proxyCreate(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	back := backTo(r)
	ns, err := targetNamespace(cu, r.FormValue("namespace"))
	if err != nil {
		a.fail(w, r, cu, back, err)
		return
	}
	if !a.store.NamespaceExists(ns) {
		a.fail(w, r, cu, back, errf("Namespace existiert nicht"))
		return
	}
	host, err := buildHost(r.FormValue("subdomain"), ns)
	if err != nil {
		a.fail(w, r, cu, back, err)
		return
	}
	up, err := normalizeUpstreams(r.FormValue("upstream"))
	if err != nil {
		a.fail(w, r, cu, back, err)
		return
	}
	p, err := a.applyChange(ProxyChange{Add: &Proxy{Namespace: ns, Host: host, Upstream: up, Enabled: true, CreatedBy: cu.User.Username}})
	if err != nil {
		a.fail(w, r, cu, back, err)
		return
	}
	log.Printf("%s: proxy %s -> %s angelegt", cu.User.Username, p.Host, p.Upstream)
	a.ok(w, r, cu, back, "%s angelegt und Caddy neu geladen. Weitere Optionen unter „Bearbeiten“.", p.Host)
}

func (a *App) proxyFromPath(w http.ResponseWriter, r *http.Request, cu *ctxUser) (Proxy, bool) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := a.store.ProxyByID(id)
	if err != nil || !a.canEdit(cu, p) {
		a.fail(w, r, cu, backTo(r), errf("Subdomain nicht gefunden"))
		return Proxy{}, false
	}
	return p, true
}

func (a *App) proxyEditPage(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	p, ok := a.proxyFromPath(w, r, cu)
	if !ok {
		return
	}
	a.renderProxyEdit(w, r, cu, p, nil)
}

func (a *App) renderProxyEdit(w http.ResponseWriter, r *http.Request, cu *ctxUser, p Proxy, flash *Flash) {
	// two empty rows for new path routes
	routes := append(append([]Route(nil), p.Opts.Routes...), Route{}, Route{})
	headers := append(append([]HeaderRule(nil), p.Opts.Headers...),
		HeaderRule{Target: HeaderResponse, Op: HeaderSet}, HeaderRule{Target: HeaderResponse, Op: HeaderSet})
	d := map[string]any{
		"P":          p,
		"Kind":       p.Opts.KindOrDefault(),
		"Routes":     routes,
		"Headers":    headers,
		"AllowIPs":   strings.Join(p.Opts.AllowIPs, "\n"),
		"LBPolicies": lbPolicies,
		"RedirCodes": redirCodes,
		"Back":       backTo(r),
		"BackNS":     r.FormValue("back_ns"),
	}
	if flash != nil {
		d["flash"] = flash
	}
	a.render(w, r, cu, "proxy", "Subdomain bearbeiten", d)
}

// applySiteForm updates p from the edit form. Enabled is not touched here.
func applySiteForm(r *http.Request, isAdmin bool, p *Proxy) error {
	o := p.Opts
	kind := r.FormValue("kind")
	if !oneOf(kind, []string{KindProxy, KindRedirect, KindRespond, KindRaw}) {
		return errf("unbekannter Typ")
	}
	if !isAdmin && (kind == KindRaw || o.Kind == KindRaw) {
		return errf("Eigene Konfiguration kann nur ein Admin bearbeiten.")
	}
	o.Kind = kind
	if kind == KindProxy {
		o.Kind = ""
	}
	if kind == KindRaw {
		raw, err := normalizeRaw(r.FormValue("raw"))
		if err != nil {
			return err
		}
		o.Raw = raw
		p.Opts = o
		return nil
	}
	o.Raw = ""

	switch kind {
	case KindProxy:
		up, err := normalizeUpstreams(r.FormValue("upstream"))
		if err != nil {
			return err
		}
		p.Upstream = up
		o.LBPolicy = r.FormValue("lb_policy")
		if o.LBPolicy != "" && !oneOf(o.LBPolicy, lbPolicies) {
			return errf("unbekannte Load-Balancing-Strategie")
		}
		if o.HealthURI, err = normalizeHealthURI(r.FormValue("health_uri")); err != nil {
			return err
		}
		o.TLSSkipVerify = r.FormValue("tls_skip_verify") == "on"
		o.HostHeader = r.FormValue("host_header") == "on"
		o.Routes = nil
		paths, ups, strips := r.Form["route_path"], r.Form["route_upstream"], r.Form["route_strip"]
		for i := range paths {
			if strings.TrimSpace(paths[i]) == "" && (i >= len(ups) || strings.TrimSpace(ups[i]) == "") {
				continue
			}
			rp, err := normalizeRoutePath(paths[i])
			if err != nil {
				return err
			}
			if i >= len(ups) {
				return errf("Ziel für Pfad %s fehlt", rp)
			}
			ru, err := normalizeUpstreams(ups[i])
			if err != nil {
				return errf("%s: %v", rp, err)
			}
			o.Routes = append(o.Routes, Route{Path: rp, Upstream: ru, Strip: i < len(strips) && strips[i] == "1"})
		}
		if len(o.Routes) > 32 {
			return errf("Höchstens 32 Pfad-Routen")
		}
	case KindRedirect:
		to, err := normalizeRedirect(r.FormValue("redirect_to"))
		if err != nil {
			return err
		}
		o.RedirectTo = to
		o.RedirectCode, _ = strconv.Atoi(r.FormValue("redirect_code"))
		if !oneOf(o.RedirectCode, redirCodes) {
			o.RedirectCode = 302
		}
		o.RedirectKeepPath = r.FormValue("redirect_keep_path") == "on"
	case KindRespond:
		o.RespondBody = strings.TrimSpace(r.FormValue("respond_body"))
		if err := validateRespondBody(o.RespondBody); err != nil {
			return err
		}
		o.RespondStatus, _ = strconv.Atoi(r.FormValue("respond_status"))
		if o.RespondStatus < 200 || o.RespondStatus > 599 {
			return errf("Statuscode muss zwischen 200 und 599 liegen")
		}
	}

	// password protection
	user := strings.TrimSpace(r.FormValue("auth_user"))
	pw := r.FormValue("auth_password")
	switch {
	case user == "":
		o.BasicAuthUser, o.BasicAuthHash = "", ""
	case !authUserRe.MatchString(user):
		return errf("Benutzername für Passwortschutz: nur Buchstaben, Ziffern, _ . @ -")
	case pw != "":
		if len(pw) < 8 || len(pw) > 72 {
			return errf("Passwort für Passwortschutz: 8–72 Zeichen")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		o.BasicAuthUser, o.BasicAuthHash = user, string(h)
	case o.BasicAuthHash == "":
		return errf("Bitte ein Passwort für den Passwortschutz setzen")
	default:
		o.BasicAuthUser = user // keep existing hash
	}

	var err error
	if o.AllowIPs, err = normalizeAllowIPs(r.FormValue("allow_ips")); err != nil {
		return err
	}
	o.Compress = r.FormValue("compress") == "on"
	o.HSTS = r.FormValue("hsts") == "on"
	o.AccessLog = r.FormValue("access_log") == "on"

	o.Headers = nil
	targets, ops, names, values := r.Form["hdr_target"], r.Form["hdr_op"], r.Form["hdr_name"], r.Form["hdr_value"]
	for i := range names {
		if strings.TrimSpace(names[i]) == "" {
			continue
		}
		h := HeaderRule{Name: names[i]}
		if i < len(targets) {
			h.Target = targets[i]
		}
		if i < len(ops) {
			h.Op = ops[i]
		}
		if i < len(values) {
			h.Value = values[i]
		}
		h, err := normalizeHeader(h)
		if err != nil {
			return err
		}
		o.Headers = append(o.Headers, h)
	}
	if len(o.Headers) > 32 {
		return errf("Höchstens 32 Header-Regeln")
	}

	if isAdmin {
		o.Extra = strings.ReplaceAll(strings.TrimSpace(r.FormValue("extra")), "\r\n", "\n")
		if len(o.Extra) > 4000 {
			return errf("Eigene Direktiven: höchstens 4000 Zeichen")
		}
		if err := validateExtra(o.Extra); err != nil {
			return err
		}
	}
	p.Opts = o
	return nil
}

func (a *App) proxyUpdate(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	p, ok := a.proxyFromPath(w, r, cu)
	if !ok {
		return
	}
	if err := applySiteForm(r, cu.User.IsAdmin, &p); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.renderProxyEdit(w, r, cu, p, errFlash(r, err))
		return
	}
	if _, err := a.applyChange(ProxyChange{Update: &p}); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.renderProxyEdit(w, r, cu, p, errFlash(r, err))
		return
	}
	log.Printf("%s: %s geändert", cu.User.Username, p.Host)
	a.ok(w, r, cu, backTo(r), "%s gespeichert und Caddy neu geladen.", p.Host)
}

func (a *App) proxyToggle(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	p, ok := a.proxyFromPath(w, r, cu)
	if !ok {
		return
	}
	p.Enabled = !p.Enabled
	if _, err := a.applyChange(ProxyChange{Update: &p}); err != nil {
		a.fail(w, r, cu, backTo(r), err)
		return
	}
	log.Printf("%s: %s enabled=%v", cu.User.Username, p.Host, p.Enabled)
	if p.Enabled {
		a.ok(w, r, cu, backTo(r), "%s aktiviert.", p.Host)
	} else {
		a.ok(w, r, cu, backTo(r), "%s deaktiviert.", p.Host)
	}
}

func (a *App) proxyDelete(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	p, ok := a.proxyFromPath(w, r, cu)
	if !ok {
		return
	}
	if _, err := a.applyChange(ProxyChange{Delete: p.ID}); err != nil {
		a.fail(w, r, cu, backTo(r), err)
		return
	}
	log.Printf("%s: proxy %s gelöscht", cu.User.Username, p.Host)
	a.ok(w, r, cu, backTo(r), "%s gelöscht.", p.Host)
}

// ---- account ----

func (a *App) accountPage(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	a.render(w, r, cu, "account", "Konto", map[string]any{})
}

func (a *App) accountPassword(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	if bcrypt.CompareHashAndPassword([]byte(cu.User.PasswordHash), []byte(r.FormValue("current"))) != nil {
		a.fail(w, r, cu, "/account", errf("Aktuelles Passwort ist falsch."))
		return
	}
	pw := r.FormValue("new")
	if pw != r.FormValue("confirm") {
		a.fail(w, r, cu, "/account", errf("Die neuen Passwörter stimmen nicht überein."))
		return
	}
	if pw == r.FormValue("current") {
		a.fail(w, r, cu, "/account", errf("Das neue Passwort muss sich vom alten unterscheiden."))
		return
	}
	if err := a.setPassword(cu.User.ID, pw, false); err != nil {
		a.fail(w, r, cu, "/account", err)
		return
	}
	a.sessions.DestroyUser(cu.User.ID, cu.Token)
	a.ok(w, r, cu, "/", "Passwort geändert.")
}

func (a *App) setPassword(id int64, pw string, mustChange bool) error {
	if err := validatePassword(pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return a.store.UpdateUser(id, func(u *User) error {
		u.PasswordHash = string(h)
		u.MustChangePassword = mustChange
		return nil
	})
}

// adminBack lets forms on the admin dashboard return there instead of to
// the detail page. Only known paths are accepted (no open redirect).
func adminBack(r *http.Request, def string) string {
	if r.FormValue("back") == "/admin" {
		return "/admin"
	}
	return def
}

// ---- admin: dashboard ----

func (a *App) adminDashboard(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	users := a.store.Users()
	proxies := a.store.Proxies("")
	namespaces := a.store.Namespaces()

	type nsRow struct {
		Domain  string
		Users   int
		Proxies int
	}
	rows := make([]nsRow, 0, len(namespaces))
	for _, n := range namespaces {
		row := nsRow{Domain: n.Domain}
		for _, u := range users {
			if u.Namespace == n.Domain {
				row.Users++
			}
		}
		for _, p := range proxies {
			if p.Namespace == n.Domain {
				row.Proxies++
			}
		}
		rows = append(rows, row)
	}

	admins, pending := 0, 0
	for _, u := range users {
		if u.IsAdmin {
			admins++
		}
		if u.MustChangePassword {
			pending++
		}
	}

	recent := append([]Proxy(nil), proxies...)
	sort.Slice(recent, func(i, j int) bool { return recent[i].CreatedAt.After(recent[j].CreatedAt) })
	if len(recent) > 8 {
		recent = recent[:8]
	}

	a.render(w, r, cu, "admin", "Admin", map[string]any{
		"Users":       users,
		"Namespaces":  namespaces,
		"NsRows":      rows,
		"ProxyCount":  len(proxies),
		"Admins":      admins,
		"Pending":     pending,
		"Recent":      recent,
		"CaddyInSync": a.caddy.InSync(proxies),
		"Settings":    a.caddy.Settings(),
	})
}

// ---- admin: users ----

func (a *App) usersPage(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	a.render(w, r, cu, "users", "Benutzer", map[string]any{
		"Users":      a.store.Users(),
		"Namespaces": a.store.Namespaces(),
	})
}

func randomPassword() string { return randToken()[:16] }

func (a *App) userCreate(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	name := strings.TrimSpace(r.FormValue("username"))
	if !usernameRe.MatchString(name) {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), errf("Benutzername: 3–32 Zeichen, nur Buchstaben, Ziffern, _ . -"))
		return
	}
	pw := r.FormValue("password")
	generated := pw == ""
	if generated {
		pw = randomPassword()
	}
	if err := validatePassword(pw); err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), err)
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), err)
		return
	}
	_, err = a.store.CreateUser(User{
		Username: name, PasswordHash: string(h), IsAdmin: r.FormValue("is_admin") == "on",
		Namespace: r.FormValue("namespace"), MustChangePassword: true,
	})
	if err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), errf("Benutzer anlegen: %v", err))
		return
	}
	if generated {
		a.ok(w, r, cu, adminBack(r, "/admin/users"), "Benutzer %s angelegt. Einmal-Passwort: %s", name, pw)
		return
	}
	a.ok(w, r, cu, adminBack(r, "/admin/users"), "Benutzer %s angelegt.", name)
}

func (a *App) userFromPath(w http.ResponseWriter, r *http.Request, cu *ctxUser) (User, bool) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := a.store.UserByID(id)
	if err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), errf("Benutzer nicht gefunden"))
		return User{}, false
	}
	return u, true
}

func (a *App) userResetPassword(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	u, ok := a.userFromPath(w, r, cu)
	if !ok {
		return
	}
	pw := r.FormValue("password")
	generated := pw == ""
	if generated {
		pw = randomPassword()
	}
	if err := a.setPassword(u.ID, pw, true); err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), err)
		return
	}
	keep := ""
	if u.ID == cu.User.ID {
		keep = cu.Token
	}
	a.sessions.DestroyUser(u.ID, keep)
	if generated {
		a.ok(w, r, cu, adminBack(r, "/admin/users"), "Neues Einmal-Passwort für %s: %s", u.Username, pw)
		return
	}
	a.ok(w, r, cu, adminBack(r, "/admin/users"), "Passwort von %s gesetzt; es muss beim nächsten Login geändert werden.", u.Username)
}

func (a *App) userSetNamespace(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	u, ok := a.userFromPath(w, r, cu)
	if !ok {
		return
	}
	ns := r.FormValue("namespace")
	if err := a.store.UpdateUser(u.ID, func(x *User) error { x.Namespace = ns; return nil }); err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), err)
		return
	}
	a.ok(w, r, cu, adminBack(r, "/admin/users"), "Namespace von %s geändert.", u.Username)
}

func (a *App) userToggleAdmin(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	u, ok := a.userFromPath(w, r, cu)
	if !ok {
		return
	}
	if u.ID == cu.User.ID {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), errf("Du kannst dir selbst die Admin-Rechte nicht entziehen."))
		return
	}
	if err := a.store.UpdateUser(u.ID, func(x *User) error { x.IsAdmin = !x.IsAdmin; return nil }); err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), err)
		return
	}
	a.ok(w, r, cu, adminBack(r, "/admin/users"), "Rechte von %s geändert.", u.Username)
}

func (a *App) userDelete(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	u, ok := a.userFromPath(w, r, cu)
	if !ok {
		return
	}
	if u.ID == cu.User.ID {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), errf("Du kannst dich nicht selbst löschen."))
		return
	}
	if err := a.store.DeleteUser(u.ID); err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/users"), err)
		return
	}
	a.sessions.DestroyUser(u.ID, "")
	a.ok(w, r, cu, adminBack(r, "/admin/users"), "Benutzer %s gelöscht. Seine Subdomains bleiben im Namespace erhalten.", u.Username)
}

// ---- admin: namespaces ----

func (a *App) namespacesPage(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	type row struct {
		Namespace
		Users   []string
		Proxies int
	}
	var rows []row
	users := a.store.Users()
	for _, n := range a.store.Namespaces() {
		rw := row{Namespace: n, Proxies: len(a.store.Proxies(n.Domain))}
		for _, u := range users {
			if u.Namespace == n.Domain {
				rw.Users = append(rw.Users, u.Username)
			}
		}
		rows = append(rows, rw)
	}
	a.render(w, r, cu, "namespaces", "Namespaces", map[string]any{"Rows": rows})
}

func (a *App) namespaceCreate(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	d, err := normalizeDomain(r.FormValue("domain"))
	if err == nil {
		err = a.store.CreateNamespace(d)
	}
	if err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/namespaces"), err)
		return
	}
	a.ok(w, r, cu, adminBack(r, "/admin/namespaces"), "Namespace %s angelegt.", d)
}

func (a *App) namespaceDelete(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	d := r.PathValue("domain")
	if err := a.store.DeleteNamespace(d); err != nil {
		a.fail(w, r, cu, adminBack(r, "/admin/namespaces"), err)
		return
	}
	a.ok(w, r, cu, adminBack(r, "/admin/namespaces"), "Namespace %s gelöscht.", d)
}

// ---- admin: caddy ----

func (a *App) caddyPage(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	files, err := a.caddy.Files(a.store.Proxies(""))
	d := map[string]any{"Files": files, "Settings": a.caddy.Settings()}
	if err != nil {
		d["flash"] = errFlash(r, err)
	}
	a.render(w, r, cu, "caddy", "Caddy", d)
}

func (a *App) caddyApply(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	err := a.caddy.Apply(a.store.Proxies(""))
	if err == nil {
		err = a.caddy.Reload()
	}
	if err != nil {
		a.fail(w, r, cu, "/admin/caddy", err)
		return
	}
	a.ok(w, r, cu, "/admin/caddy", "Caddyfile geschrieben und Caddy neu geladen.")
}

func settingsFromForm(r *http.Request) (Settings, error) {
	st := Settings{
		CaddyConfig: strings.TrimSpace(r.FormValue("caddy_config")),
		SitesDir:    strings.TrimRight(strings.TrimSpace(r.FormValue("sites_dir")), `/\`),
		CaddyBin:    strings.TrimSpace(r.FormValue("caddy_bin")),
		Reload:      r.FormValue("reload") == "on",
		Email:       strings.TrimSpace(r.FormValue("email")),
	}
	if err := validateEmail(st.Email); err != nil {
		return st, err
	}
	if st.CaddyConfig == "" {
		return st, errf("Pfad zur Caddyfile fehlt")
	}
	if st.SitesDir == "" {
		return st, errf("Verzeichnis für die Site-Dateien fehlt")
	}
	// the path ends up unquoted in the import line
	if strings.ContainsAny(st.SitesDir, " \t\r\n\"`{}#*?[") {
		return st, errf("Verzeichnis für die Site-Dateien darf keine Leer- oder Sonderzeichen enthalten")
	}
	if st.CaddyBin == "" {
		st.CaddyBin = "caddy"
	}
	return st, nil
}

func (a *App) caddySettings(w http.ResponseWriter, r *http.Request, cu *ctxUser) {
	st, err := settingsFromForm(r)
	if err == nil {
		st.LegacyFile = a.caddy.Settings().LegacyFile
		err = a.store.SaveSettings(st)
	}
	if err != nil {
		a.fail(w, r, cu, "/admin/caddy", err)
		return
	}
	a.caddy.Configure(st)
	a.ok(w, r, cu, "/admin/caddy", "Einstellungen gespeichert. Mit „Neu schreiben“ werden die Dateien am neuen Ort erzeugt.")
}

// ---- setup ----

func (a *App) setupPage(w http.ResponseWriter, r *http.Request) {
	if a.setupDone.Load() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	a.render(w, r, nil, "setup", "Ersteinrichtung", map[string]any{"Settings": a.caddy.Settings(), "Username": "admin", "Adopt": true})
}

func (a *App) setupPost(w http.ResponseWriter, r *http.Request) {
	if a.setupDone.Load() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	st, err := settingsFromForm(r)
	name := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")
	switch {
	case err != nil:
	case !usernameRe.MatchString(name):
		err = errf("Benutzername: 3–32 Zeichen, nur Buchstaben, Ziffern, _ . -")
	case pw != r.FormValue("confirm"):
		err = errf("Die Passwörter stimmen nicht überein.")
	default:
		err = validatePassword(pw)
	}
	// take over the site blocks of the existing configuration
	adopt := r.FormValue("adopt") == "on"
	var scan ScanResult
	if err == nil && adopt {
		scan, err = ScanCaddyConfig(st.CaddyConfig)
	}
	var u User
	if err == nil {
		var h []byte
		if h, err = bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost); err == nil {
			var created bool
			apply := func(ps []Proxy) error { return NewCaddy(st).ApplyWith(ps, scan.Files) }
			u, created, err = a.store.Setup(User{Username: name, PasswordHash: string(h), IsAdmin: true}, st, scan.Sites, apply)
			if err == nil && !created {
				a.setupDone.Store(true)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, r, nil, "setup", "Ersteinrichtung", map[string]any{
			"Settings": st, "Username": name, "Adopt": adopt, "flash": errFlash(r, err),
		})
		return
	}
	a.caddy.Configure(st)
	a.setupDone.Store(true)
	log.Printf("setup: admin %q angelegt, Caddyfile %s, %d Sites übernommen, %d unverändert gelassen", u.Username, st.CaddyConfig, len(scan.Sites), len(scan.Kept))
	sess := a.sessions.Create(w, u.ID, isHTTPS(r))
	switch {
	case len(scan.Kept) > 0:
		a.sessions.SetFlash(sess, "ok", Tf(langFromRequest(r), "%d Sites übernommen. Nicht übernommen (bleiben unverändert in ihrer Datei): %s", len(scan.Sites), strings.Join(scan.Kept, "; ")))
	case len(scan.Sites) > 0:
		a.sessions.SetFlash(sess, "ok", Tf(langFromRequest(r), "%d Sites aus der bestehenden Konfiguration übernommen.", len(scan.Sites)))
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
