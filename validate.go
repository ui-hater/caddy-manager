package main

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	labelRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tldRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)
)

func normalizeDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) == 0 || len(s) > 253 {
		return "", errf("ungültige Domain")
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", errf("Domain braucht mindestens eine TLD, z.B. example.com")
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", errf("ungültiger Domain-Teil: %s", l)
		}
	}
	if !tldRe.MatchString(labels[len(labels)-1]) {
		return "", errf("ungültige TLD")
	}
	return s, nil
}

// buildHost turns a subdomain ("social", "a.b", or "@" for the bare domain)
// into a fully qualified host inside the namespace.
func buildHost(sub, namespace string) (string, error) {
	sub = strings.ToLower(strings.TrimSpace(sub))
	// tolerate users typing the full name, e.g. "social.aaronhosting.xyz"
	sub = strings.Trim(strings.TrimSuffix(sub, "."+namespace), ".")
	if sub == "" {
		return "", errf("Bitte eine Subdomain angeben, z.B. social")
	}
	if sub == "@" {
		return namespace, nil
	}
	for _, l := range strings.Split(sub, ".") {
		if !labelRe.MatchString(l) {
			return "", errf("ungültige Subdomain: %s", l)
		}
	}
	host := sub + "." + namespace
	if len(host) > 253 {
		return "", errf("Hostname zu lang")
	}
	return host, nil
}

// normalizeUpstream accepts "host:port", "http://host:port" or
// "https://host:port" and nothing else.
func normalizeUpstream(s string) (string, error) {
	s = strings.TrimSpace(s)
	scheme := ""
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			scheme, s = p, s[len(p):]
		}
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", errf("Upstream muss die Form host:port haben, z.B. 127.0.0.1:8080")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errf("ungültiger Port")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			host = "[" + ip.String() + "]"
		} else {
			host = ip.String()
		}
	} else {
		host = strings.ToLower(host)
		for _, l := range strings.Split(host, ".") {
			if !labelRe.MatchString(l) {
				return "", errf("ungültiger Upstream-Host")
			}
		}
	}
	return scheme + host + ":" + strconv.Itoa(n), nil
}

func validatePassword(pw string) error {
	if len(pw) < 10 {
		return errf("Passwort muss mindestens 10 Zeichen lang sein")
	}
	if len(pw) > 72 {
		return errf("Passwort darf höchstens 72 Bytes lang sein")
	}
	return nil
}

// normalizeUpstreams accepts one or more upstreams separated by spaces,
// commas or newlines. All of them must use the same scheme.
func normalizeUpstreams(s string) (string, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
	if len(fields) == 0 {
		return "", errf("Mindestens ein Ziel angeben, z.B. 10.0.0.12:8080")
	}
	if len(fields) > 16 {
		return "", errf("Höchstens 16 Ziele")
	}
	out := make([]string, 0, len(fields))
	https := strings.HasPrefix(strings.ToLower(fields[0]), "https://")
	for _, f := range fields {
		u, err := normalizeUpstream(f)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(u, "https://") != https {
			return "", errf("Alle Ziele müssen entweder http oder https verwenden")
		}
		out = append(out, u)
	}
	return strings.Join(out, " "), nil
}

var (
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	healthRe   = regexp.MustCompile(`^/[A-Za-z0-9._~/?=&-]*$`)
	urlRestRe  = regexp.MustCompile(`^[A-Za-z0-9._~/?=&%:+#@!,;-]*$`)
	authUserRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	lbPolicies = []string{"round_robin", "least_conn", "ip_hash", "first", "random"}
	redirCodes = []int{301, 302, 307, 308}
)

// normalizeRoutePath turns "/api" or "/api/" into "/api/*".
func normalizeRoutePath(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), "*")
	if !pathRe.MatchString(s) || s == "/" {
		return "", errf("ungültiger Pfad: %s (z.B. /api)", s)
	}
	return strings.TrimSuffix(s, "/") + "/*", nil
}

func normalizeHealthURI(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if !healthRe.MatchString(s) {
		return "", errf("ungültiger Health-Check-Pfad (z.B. /health)")
	}
	return s, nil
}

// normalizeRedirect accepts http(s)://host[:port][/path?query].
func normalizeRedirect(s string) (string, error) {
	s = strings.TrimSpace(s)
	rest, scheme := "", ""
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			scheme, rest = p, s[len(p):]
		}
	}
	if scheme == "" {
		return "", errf("Ziel-URL muss mit http:// oder https:// beginnen")
	}
	host, path := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host += ":1" // validate host part only
		if _, err := normalizeUpstream(host); err != nil {
			return "", errf("ungültiger Host in der Ziel-URL")
		}
		host = strings.TrimSuffix(host, ":1")
	} else if _, err := normalizeUpstream(host); err != nil {
		return "", errf("ungültiger Host in der Ziel-URL")
	}
	if !urlRestRe.MatchString(path) {
		return "", errf("ungültige Zeichen im Pfad der Ziel-URL")
	}
	return scheme + strings.ToLower(host) + path, nil
}

// validateRespondBody allows plain text only: no quotes, backslashes or
// braces (which Caddy would evaluate as placeholders, e.g. {env.SECRET}).
func validateRespondBody(s string) error {
	if len(s) > 500 {
		return errf("Antworttext darf höchstens 500 Zeichen lang sein")
	}
	for _, r := range s {
		if r < 0x20 || strings.ContainsRune("{}\"\\`", r) {
			return errf("Antworttext darf keine Zeilenumbrüche, Anführungszeichen, Backslashes oder { } enthalten")
		}
	}
	return nil
}

// normalizeAllowIPs accepts IPs, CIDRs and the Caddy shortcut private_ranges.
func normalizeAllowIPs(s string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		switch {
		case f == "private_ranges":
			out = append(out, f)
		case strings.Contains(f, "/"):
			_, n, err := net.ParseCIDR(f)
			if err != nil {
				return nil, errf("ungültiges Netz: %s", f)
			}
			out = append(out, n.String())
		default:
			ip := net.ParseIP(f)
			if ip == nil {
				return nil, errf("ungültige IP: %s", f)
			}
			out = append(out, ip.String())
		}
	}
	if len(out) > 64 {
		return nil, errf("Höchstens 64 IP-Einträge")
	}
	return out, nil
}

// validateExtra checks admin-supplied raw directives at least for balanced
// braces, so they cannot close the site block early. Caddy validates the rest.
func validateExtra(s string) error {
	depth := 0
	for _, r := range s {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return errf("Eigene Direktiven: unerwartete }")
			}
		case 0:
			return errf("Eigene Direktiven: ungültiges Zeichen")
		}
	}
	if depth != 0 {
		return errf("Eigene Direktiven: { und } sind nicht ausgeglichen")
	}
	return nil
}

func validateEmail(s string) error {
	if s != "" && !emailRe.MatchString(s) {
		return errf("ungültige E-Mail-Adresse")
	}
	return nil
}

func oneOf[T comparable](v T, allowed []T) bool {
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// normalizeHeader checks one header rule. Values are plain text: no quotes,
// backslashes or braces, so they can neither break the Caddyfile nor use
// placeholders such as {env.SECRET}.
func normalizeHeader(h HeaderRule) (HeaderRule, error) {
	h.Name = strings.TrimSpace(h.Name)
	h.Value = strings.TrimSpace(h.Value)
	if !oneOf(h.Target, []string{HeaderResponse, HeaderRequest}) || !oneOf(h.Op, []string{HeaderSet, HeaderAdd, HeaderDelete}) {
		return h, errf("ungültige Header-Regel")
	}
	if !headerNameRe.MatchString(h.Name) {
		return h, errf("ungültiger Header-Name: %s", h.Name)
	}
	if h.Op == HeaderDelete {
		h.Value = ""
		return h, nil
	}
	if h.Value == "" {
		return h, errf("Header %s: Wert fehlt", h.Name)
	}
	if len(h.Value) > 1000 {
		return h, errf("Header %s: Wert darf höchstens 1000 Zeichen lang sein", h.Name)
	}
	for _, r := range h.Value {
		if r < 0x20 || strings.ContainsRune("{}\"\\`", r) {
			return h, errf("Header %s: Wert darf keine Anführungszeichen, Backslashes oder { } enthalten", h.Name)
		}
	}
	return h, nil
}
