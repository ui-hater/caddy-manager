package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

// German is the source language: every user-facing text is written in German
// in the code and templates, and the German text is the key into the
// translation catalog (see i18n_en.go).

const (
	LangDE = "de"
	LangEN = "en"

	langCookie = "cm_lang"
)

var languages = []string{LangDE, LangEN}

var catalogs = map[string]map[string]string{
	LangEN: catalogEN,
}

// missingKeys collects texts without a translation (checked by tests).
var missingKeys sync.Map

// T translates a text.
func T(lang, s string) string {
	cat := catalogs[lang]
	if cat == nil {
		return s
	}
	if v, ok := cat[s]; ok {
		return v
	}
	missingKeys.Store(s, true)
	return s
}

// Tf translates a format string and fills in the arguments.
func Tf(lang, format string, args ...any) string {
	return fmt.Sprintf(T(lang, format), args...)
}

// uiError is an error meant for the user. Its format string is translated
// when it is shown, so it can be created without knowing the language.
type uiError struct {
	format string
	args   []any
}

func (e *uiError) Error() string { return fmt.Sprintf(e.format, e.args...) }

func errf(format string, args ...any) error { return &uiError{format: format, args: args} }

// trErr translates a uiError (including nested uiError arguments). Other
// errors come from the system or Caddy and are shown as they are.
func trErr(lang string, err error) string {
	ue, ok := err.(*uiError)
	if !ok {
		return err.Error()
	}
	args := make([]any, len(ue.args))
	for i, a := range ue.args {
		if e, ok := a.(error); ok {
			a = trErr(lang, e)
		}
		args[i] = a
	}
	return Tf(lang, ue.format, args...)
}

// langFromRequest picks the language from the cookie, then from the
// browser's Accept-Language header, and falls back to German.
func langFromRequest(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && oneOf(c.Value, languages) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		for _, l := range languages {
			if tag == l || strings.HasPrefix(tag, l+"-") {
				return l
			}
		}
	}
	return LangDE
}

func (a *App) setLang(w http.ResponseWriter, r *http.Request) {
	l := r.PathValue("lang")
	if oneOf(l, languages) {
		http.SetCookie(w, &http.Cookie{Name: langCookie, Value: l, Path: "/", MaxAge: 365 * 24 * 3600, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r)})
	}
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// templateFuncs returns the functions available in templates for one language.
func templateFuncs(lang string) template.FuncMap {
	timeFmt := "02.01.2006 15:04"
	if lang == LangEN {
		timeFmt = "2006-01-02 15:04"
	}
	return template.FuncMap{
		"t":  func(s string) string { return T(lang, s) },
		"tf": func(format string, args ...any) string { return Tf(lang, format, args...) },
		// th is for catalog texts that contain markup (<code> etc.). Only
		// literal texts from the templates are passed in, never user input.
		"th":          func(s string) template.HTML { return template.HTML(T(lang, s)) },
		"fmtTime":     func(t time.Time) string { return t.Local().Format(timeFmt) },
		"hasPrefix":   strings.HasPrefix,
		"splitFields": strings.Fields,
	}
}
