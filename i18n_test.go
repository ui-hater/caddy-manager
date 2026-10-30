package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// translatable lists functions whose argument at the given index is a
// German text that must exist in the catalog.
var translatable = map[string]int{
	"errf":      0,
	"T":         1,
	"Tf":        1,
	"ok":        4, // a.ok(w, r, cu, to, format, ...)
	"render":    4, // a.render(w, r, cu, page, title, ...)
	"loginFail": 0,
}

var templateKeyRe = regexp.MustCompile("\\{\\{-?\\s*(?:t|th|tf)\\s+(\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`)")

// usedKeys collects every translatable literal from the Go code and the templates.
func usedKeys(t *testing.T) map[string]string {
	keys := map[string]string{} // key -> where it was found
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			idx, ok := translatable[name]
			if !ok || idx >= len(call.Args) {
				return true
			}
			if lit, ok := call.Args[idx].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, _ := strconv.Unquote(lit.Value)
				keys[s] = fset.Position(lit.Pos()).String()
			}
			return true
		})
	}
	tmpls, _ := fs.Glob(assets, "templates/*.html")
	for _, f := range tmpls {
		b, _ := fs.ReadFile(assets, f)
		for _, m := range templateKeyRe.FindAllStringSubmatch(string(b), -1) {
			s, err := strconv.Unquote(m[1])
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			keys[s] = f
		}
	}
	return keys
}

var verbRe = regexp.MustCompile(`%[a-z]`)

func TestCatalogComplete(t *testing.T) {
	keys := usedKeys(t)
	if len(keys) < 100 {
		t.Fatalf("nur %d Schlüssel gefunden – Extraktion kaputt?", len(keys))
	}
	var missing []string
	for k, where := range keys {
		en, ok := catalogEN[k]
		if !ok {
			missing = append(missing, strconv.Quote(k)+": \"\", // "+where)
			continue
		}
		if !slices.Equal(verbRe.FindAllString(k, -1), verbRe.FindAllString(en, -1)) {
			t.Errorf("Platzhalter passen nicht: %q -> %q", k, en)
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("%d Texte ohne englische Übersetzung:\n%s", len(missing), strings.Join(missing, "\n"))
	}
	for k := range catalogEN {
		if _, ok := keys[k]; !ok {
			t.Errorf("unbenutzter Katalogeintrag: %q", k)
		}
	}
}

func TestEnglishUI(t *testing.T) {
	_, srv, _ := setup(t)
	c := newClient(t, srv.URL)
	// switch language via the link in the footer
	resp, err := c.c.Get(srv.URL + "/lang/en?next=/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if b := c.get("/login"); !strings.Contains(b, `<html lang="en">`) || !strings.Contains(b, "Sign in") {
		t.Fatal("Login nicht auf Englisch")
	}
	if b := c.post("/login", url.Values{"username": {"admin"}, "password": {"falsch"}}); !strings.Contains(b, "Wrong username or password.") {
		t.Fatal("Fehlermeldung nicht übersetzt")
	}
	c.post("/login", url.Values{"username": {"admin"}, "password": {"adminpass123"}})
	if b := c.post("/admin/namespaces", url.Values{"domain": {"bad_label.xyz"}}); !strings.Contains(b, "invalid domain part: bad_label") {
		t.Fatal("Validierungsfehler nicht übersetzt")
	}
	if b := c.post("/admin/namespaces", url.Values{"domain": {"aaronhosting.xyz"}}); !strings.Contains(b, "Namespace aaronhosting.xyz created.") {
		t.Fatal("Erfolgsmeldung nicht übersetzt")
	}
	c.post("/proxies", url.Values{"namespace": {"aaronhosting.xyz"}, "subdomain": {"social"}, "upstream": {"10.0.0.2:80"}})

	// every page renders in English without untranslated texts
	missingKeys.Clear()
	for _, p := range []string{"/", "/account", "/admin", "/admin/users", "/admin/namespaces", "/admin/caddy", "/proxies/1"} {
		if b := c.get(p); strings.Contains(b, "Abmelden") {
			t.Errorf("%s enthält noch Deutsch", p)
		}
	}
	missingKeys.Range(func(k, _ any) bool {
		t.Errorf("zur Laufzeit fehlende Übersetzung: %q", k)
		return true
	})

	// open redirect via ?next is not possible
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, next := range []string{"//evil.example", "https://evil.example", "/\\evil.example"} {
		resp, err := noFollow.Get(srv.URL + "/lang/de?next=" + url.QueryEscape(next))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Errorf("next=%q leitet nach %q", next, loc)
		}
	}
}

func TestLangFromRequest(t *testing.T) {
	for header, want := range map[string]string{
		"":                        LangDE,
		"en-US,en;q=0.9":          LangEN,
		"de-DE,de;q=0.9,en;q=0.8": LangDE,
		"fr-FR,fr;q=0.9,en;q=0.5": LangEN,
		"fr":                      LangDE,
	} {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Language", header)
		if got := langFromRequest(r); got != want {
			t.Errorf("%q: %s, erwartet %s", header, got, want)
		}
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "de")
	r.AddCookie(&http.Cookie{Name: langCookie, Value: LangEN})
	if langFromRequest(r) != LangEN {
		t.Error("Cookie hat keinen Vorrang")
	}
}
