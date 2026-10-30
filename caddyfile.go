package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// This file reads existing Caddyfiles just far enough to take over their site
// blocks: it splits a file into its top-level entries (global options,
// snippets, imports, sites) with exact byte ranges, so a site block can be
// cut out while everything else stays byte for byte as it was.

type cfToken struct {
	text       string
	quoted     bool // "…", `…` or heredoc; never a brace token
	start, end int  // byte offsets in the source
	line       int
}

var heredocRe = regexp.MustCompile(`^<<([A-Za-z0-9_-]+)\r?\n`)

// lexCaddyfile splits src into tokens the way Caddy's lexer does: comments
// start with # at the beginning of a token, quotes and backticks group text,
// heredocs (<<MARKER) run until the closing marker line.
func lexCaddyfile(src string) ([]cfToken, error) {
	var toks []cfToken
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r':
			i++
			continue
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		tk := cfToken{start: i, line: line}
		switch {
		case c == '"':
			tk.quoted = true
			for i++; i < len(src) && src[i] != '"'; i++ {
				if src[i] == '\\' && i+1 < len(src) {
					i++
				}
				if src[i] == '\n' {
					line++
				}
			}
			if i >= len(src) {
				return nil, errf("Zeile %d: Anführungszeichen nicht geschlossen", tk.line)
			}
			i++
		case c == '`':
			tk.quoted = true
			for i++; i < len(src) && src[i] != '`'; i++ {
				if src[i] == '\n' {
					line++
				}
			}
			if i >= len(src) {
				return nil, errf("Zeile %d: Anführungszeichen nicht geschlossen", tk.line)
			}
			i++
		case heredocRe.MatchString(src[i:]):
			m := heredocRe.FindStringSubmatch(src[i:])
			tk.quoted = true
			i += len(m[0])
			line++
			for {
				end := strings.IndexByte(src[i:], '\n')
				l := src[i:]
				if end >= 0 {
					l = src[i : i+end]
				}
				// the closing marker may be followed by more tokens ("HTML 200")
				if rest, ok := strings.CutPrefix(strings.TrimLeft(l, " \t"), m[1]); ok && (rest == "" || strings.ContainsRune(" \t\r", rune(rest[0]))) {
					i += len(l) - len(rest)
					break
				}
				if end < 0 {
					return nil, errf("Zeile %d: Heredoc nicht geschlossen", tk.line)
				}
				i += end + 1
				line++
			}
		default:
			for i < len(src) && !strings.ContainsRune(" \t\r\n", rune(src[i])) {
				i++
			}
		}
		tk.end = i
		tk.text = src[tk.start:tk.end]
		toks = append(toks, tk)
	}
	return toks, nil
}

func (t cfToken) is(s string) bool { return !t.quoted && t.text == s }

// value returns the token text without quotes.
func (t cfToken) value() string {
	if t.quoted && len(t.text) >= 2 && (t.text[0] == '"' || t.text[0] == '`') {
		return t.text[1 : len(t.text)-1]
	}
	return t.text
}

type cfEntry struct {
	head       []cfToken // tokens before the block: addresses, "import x", "(snippet)", "{"
	toks       []cfToken // all tokens of the entry
	start, end int       // whole lines, including the trailing newline
	block      bool
	global     bool // global options block
	bodyStart  int  // between "{" and the closing "}"
	bodyEnd    int
}

func (e cfEntry) isImport() bool { return !e.block && e.head[0].is("import") }

func (e cfEntry) isSite() bool {
	h := e.head[0].text
	return e.block && !e.global && !strings.HasPrefix(h, "(") && !strings.HasPrefix(h, "&(")
}

func lineStart(src string, i int) int { return strings.LastIndexByte(src[:i], '\n') + 1 }

func lineEnd(src string, i int) int {
	if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
		return i + j + 1
	}
	return len(src)
}

// parseCaddyfile splits src into its top-level entries.
func parseCaddyfile(src string) ([]cfEntry, error) {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return nil, err
	}
	var entries []cfEntry
	for i := 0; i < len(toks); {
		first := i
		// the head runs to the end of the line; a trailing comma continues it
		for i++; i < len(toks) && (toks[i].line == toks[i-1].line || strings.HasSuffix(toks[i-1].text, ",")); i++ {
		}
		e := cfEntry{head: toks[first:i], start: lineStart(src, toks[first].start)}
		for _, t := range e.head[:len(e.head)-1] {
			if t.is("{") || t.is("}") {
				return nil, errf("Zeile %d: nach { muss eine neue Zeile beginnen", t.line)
			}
		}
		last := e.head[len(e.head)-1]
		switch {
		case last.is("{"):
			e.head = e.head[:len(e.head)-1]
			e.block = true
			depth := 1
			for ; i < len(toks) && depth > 0; i++ {
				if toks[i].is("{") {
					depth++
				} else if toks[i].is("}") {
					depth--
				}
			}
			if depth > 0 {
				return nil, errf("Zeile %d: { wird nicht geschlossen", last.line)
			}
			e.bodyStart, e.bodyEnd = last.end, toks[i-1].start
			e.end = lineEnd(src, toks[i-1].end)
			if len(e.head) == 0 {
				e.head, e.global = []cfToken{last}, true
			}
		case last.is("}"):
			return nil, errf("Zeile %d: unerwartete }", last.line)
		case !e.head[0].is("import"):
			return nil, errf("Zeile %d: nur Site-Blöcke mit { } werden unterstützt", e.head[0].line)
		default:
			e.end = lineEnd(src, last.end)
		}
		e.toks = toks[first:i]
		entries = append(entries, e)
	}
	return entries, nil
}

// siteBody returns the raw content of a block without the line of the
// opening brace, ready to be written into a new site block.
func siteBody(src string, e cfEntry) string {
	body := strings.TrimRight(src[e.bodyStart:e.bodyEnd], " \t")
	rest := strings.TrimLeft(body, " \t")
	switch {
	case strings.HasPrefix(rest, "\n"):
		body = rest[1:]
	case strings.HasPrefix(rest, "\r\n"):
		body = rest[2:]
	default: // a comment after the brace moves to its own line
		body = "\t" + rest
	}
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body
}

// siteHost returns the host of a site address that caddy-manager can manage:
// a plain domain, optionally with https:// or :443.
func siteHost(addr string) (string, bool) {
	a := strings.ToLower(addr)
	a = strings.TrimPrefix(a, "https://")
	a = strings.TrimSuffix(a, ":443")
	if strings.ContainsAny(a, "/:*{}\"`") {
		return "", false
	}
	h, err := normalizeDomain(a)
	return h, err == nil
}

// siteAddresses splits the head of a site block ("a.com, b.com") into addresses.
func siteAddresses(head []cfToken) []string {
	var out []string
	for _, t := range head {
		for _, a := range strings.Split(t.text, ",") {
			if a = strings.TrimSpace(a); a != "" {
				out = append(out, a)
			}
		}
	}
	return out
}

// proxyFromBlock turns a site body into a Proxy: a lone reverse_proxy line
// becomes a normal site, everything else is kept as raw configuration.
func proxyFromBlock(host, body string) Proxy {
	p := Proxy{Host: host, Enabled: true, Opts: SiteOptions{Kind: KindRaw, Raw: body}}
	toks, err := lexCaddyfile(body)
	if err != nil || strings.Contains(body, "#") || len(toks) < 2 || !toks[0].is("reverse_proxy") {
		return p
	}
	var ups []string
	for _, t := range toks[1:] {
		if t.line != toks[0].line || t.quoted {
			return p
		}
		ups = append(ups, t.text)
	}
	up, err := normalizeUpstreams(strings.Join(ups, " "))
	if err != nil {
		return p
	}
	return Proxy{Host: host, Upstream: up, Enabled: true}
}

// ScanResult describes what setup takes over from an existing configuration.
type ScanResult struct {
	Sites []Proxy           // site blocks moved into the database
	Files map[string]string // files that lose those blocks -> new content
	Kept  []string          // site addresses left where they are
}

// ScanCaddyConfig reads the main Caddyfile and every file it imports and
// collects all site blocks for a single plain domain. Snippets, global
// options and sites caddy-manager can't represent (several addresses,
// wildcards, ports, http://) stay untouched in their files.
func ScanCaddyConfig(main string) (ScanResult, error) {
	res := ScanResult{Files: map[string]string{}}
	seen := map[string]bool{}
	hosts := map[string]bool{}
	snippets := map[string]bool{}

	var scan func(path string) error
	scan = func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seen[abs] {
			return nil
		}
		seen[abs] = true
		b, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && len(seen) == 1 {
				return nil // no config yet
			}
			return err
		}
		src := string(b)
		if strings.HasPrefix(src, managedHeader) && path == main {
			return nil // main file written by an old version, sites are in the database
		}
		entries, err := parseCaddyfile(src)
		if err != nil {
			return errf("%s: %v", path, err)
		}
		var out strings.Builder
		pos := 0
		for _, e := range entries {
			switch {
			case e.block && !e.global && !e.isSite():
				snippets[strings.Trim(e.head[0].text, "&()")] = true
			case e.isImport():
				if len(e.head) != 2 || snippets[e.head[1].value()] {
					continue // snippet or import with arguments
				}
				matches, _ := filepath.Glob(importPath(path, e.head[1].value()))
				sort.Strings(matches)
				for _, m := range matches {
					if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
						if err := scan(m); err != nil {
							return err
						}
					}
				}
			case e.isSite():
				addrs := siteAddresses(e.head)
				host, ok := "", len(addrs) == 1
				if ok {
					host, ok = siteHost(addrs[0])
				}
				ns, err := publicsuffix.EffectiveTLDPlusOne(host)
				if !ok || err != nil || hosts[host] {
					res.Kept = append(res.Kept, strings.Join(addrs, ", "))
					continue
				}
				hosts[host] = true
				p := proxyFromBlock(host, siteBody(src, e))
				p.Namespace = ns
				res.Sites = append(res.Sites, p)
				out.WriteString(src[pos:e.start])
				pos = e.end
			}
		}
		if pos > 0 {
			out.WriteString(src[pos:])
			res.Files[path] = out.String()
		}
		return nil
	}
	return res, scan(main)
}

// hasConfig reports whether a file contains anything but comments.
func hasConfig(src string) bool {
	toks, err := lexCaddyfile(src)
	return err != nil || len(toks) > 0
}

// importPath resolves the argument of an import in file like Caddy does:
// relative to the directory of the importing file.
func importPath(file, arg string) string {
	if filepath.IsAbs(arg) || strings.HasPrefix(arg, "/") {
		return filepath.Clean(arg)
	}
	return filepath.Join(filepath.Dir(file), arg)
}

// sitesImport is the line that includes all managed files.
func sitesImport(st Settings) string {
	return "import " + filepath.ToSlash(filepath.Join(st.SitesDir, "*.caddy"))
}

// ensureMainConfig makes sure the main Caddyfile imports the managed files
// and, if an e-mail is configured, sets it as global option. Everything else
// in the file stays as it is.
func ensureMainConfig(src string, st Settings) (string, error) {
	if strings.HasPrefix(src, managedHeader) {
		src = "" // generated completely by an old version
	}
	entries, err := parseCaddyfile(src)
	if err != nil {
		return "", errf("%s: %v", st.CaddyConfig, err)
	}
	want := filepath.Clean(filepath.Join(st.SitesDir, "*.caddy"))
	found := false
	for _, e := range entries {
		if e.isImport() && len(e.head) == 2 {
			found = found || importPath(st.CaddyConfig, e.head[1].value()) == want
		}
	}
	if !found {
		if src != "" && !strings.HasSuffix(src, "\n") {
			src += "\n"
		}
		if strings.TrimSpace(src) != "" {
			src += "\n"
		}
		src += sitesImport(st) + "\n"
	}
	if st.Email == "" {
		return src, nil
	}
	email := "email " + st.Email
	if len(entries) == 0 || !entries[0].global {
		return "{\n\t" + email + "\n}\n\n" + src, nil
	}
	g := entries[0]
	toks := g.toks[1 : len(g.toks)-1]
	for i, t := range toks {
		if t.is("email") && (i == 0 || toks[i-1].line < t.line) {
			end := t.end
			for _, u := range toks[i+1:] {
				if u.line != t.line {
					break
				}
				end = u.end
			}
			return src[:t.start] + email + src[end:], nil
		}
	}
	at := lineEnd(src, g.bodyStart)
	return src[:at] + "\t" + email + "\n" + src[at:], nil
}
