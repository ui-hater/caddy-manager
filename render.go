package main

import (
	"fmt"
	"sort"
	"strings"
)

const managedHeader = "# Generiert von caddy-manager – NICHT VON HAND BEARBEITEN.\n# Änderungen werden beim nächsten Speichern überschrieben.\n\n"

// RenderCaddyfile builds the managed file. Every value written here has been
// validated against strict patterns (see validate.go) so it cannot inject
// Caddyfile syntax; only the admin-only Extra field is passed through raw.
func RenderCaddyfile(proxies []Proxy, st Settings) string {
	ps := append([]Proxy(nil), proxies...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].Host < ps[j].Host })

	var b strings.Builder
	b.WriteString(managedHeader)
	// Global options must be the first block of the main Caddyfile, so they
	// are only written when the managed file is the main config.
	if st.Email != "" && st.CaddyConfig == "" {
		fmt.Fprintf(&b, "{\n\temail %s\n}\n\n", st.Email)
	}
	for _, p := range ps {
		if !p.Enabled {
			fmt.Fprintf(&b, "# deaktiviert: %s (%s, id %d)\n\n", p.Host, p.Namespace, p.ID)
			continue
		}
		fmt.Fprintf(&b, "# %s (id %d, von %s)\n", p.Namespace, p.ID, p.CreatedBy)
		renderSite(&b, p)
		b.WriteString("\n")
	}
	return b.String()
}

type blockWriter struct {
	b     *strings.Builder
	depth int
}

func (w *blockWriter) line(format string, args ...any) {
	w.b.WriteString(strings.Repeat("\t", w.depth))
	fmt.Fprintf(w.b, format, args...)
	w.b.WriteString("\n")
}

func (w *blockWriter) open(format string, args ...any) {
	w.line(format+" {", args...)
	w.depth++
}

func (w *blockWriter) close() {
	w.depth--
	w.line("}")
}

func renderSite(b *strings.Builder, p Proxy) {
	o := p.Opts
	w := &blockWriter{b: b}
	w.open("%s", p.Host)
	if o.AccessLog {
		w.line("log")
	}
	// route keeps the handlers in exactly this order instead of Caddy's
	// default directive order (IP check -> auth -> headers -> handler).
	// A site with only a handler doesn't need it.
	respHeaders := o.HeadersFor(HeaderResponse)
	useRoute := len(o.AllowIPs) > 0 || o.BasicAuthHash != "" || o.HSTS || o.Compress || len(o.Routes) > 0 || len(respHeaders) > 0
	if useRoute {
		w.open("route")
	}
	if len(o.AllowIPs) > 0 {
		w.line("@blocked not remote_ip %s", strings.Join(o.AllowIPs, " "))
		w.line(`respond @blocked "Forbidden" 403`)
	}
	if o.BasicAuthUser != "" && o.BasicAuthHash != "" {
		w.open("basic_auth")
		w.line("%s %s", o.BasicAuthUser, o.BasicAuthHash)
		w.close()
	}
	if o.HSTS {
		w.line(`header Strict-Transport-Security "max-age=31536000; includeSubDomains"`)
	}
	if len(respHeaders) > 0 {
		// defer applies the changes after the upstream answered, so they
		// also override or remove headers set by the upstream.
		w.open("header")
		for _, h := range respHeaders {
			w.line("%s", headerOp(h))
		}
		w.line("defer")
		w.close()
	}
	if o.Compress {
		w.line("encode zstd gzip")
	}

	switch o.KindOrDefault() {
	case KindRedirect:
		target := o.RedirectTo
		if o.RedirectKeepPath {
			target = strings.TrimSuffix(target, "/") + "{uri}"
		}
		w.line("redir %s %d", target, o.RedirectCode)
	case KindRespond:
		w.line(`respond "%s" %d`, o.RespondBody, o.RespondStatus)
	default:
		for _, r := range o.Routes {
			if r.Strip {
				w.open("handle_path %s", r.Path)
			} else {
				w.open("handle %s", r.Path)
			}
			renderProxy(w, r.Upstream, o)
			w.close()
		}
		if len(o.Routes) > 0 {
			w.open("handle")
			renderProxy(w, p.Upstream, o)
			w.close()
		} else {
			renderProxy(w, p.Upstream, o)
		}
	}
	if useRoute {
		w.close()
	}

	if o.Extra != "" {
		for _, l := range strings.Split(strings.TrimSpace(o.Extra), "\n") {
			w.line("%s", strings.TrimRight(l, " \t\r"))
		}
	}
	w.close() // site
}

func renderProxy(w *blockWriter, upstreams string, o SiteOptions) {
	ups := strings.Fields(upstreams)
	multi := len(ups) > 1
	tls := strings.HasPrefix(upstreams, "https://") && o.TLSSkipVerify
	reqHeaders := o.HeadersFor(HeaderRequest)
	if !multi && o.HealthURI == "" && !o.HostHeader && !tls && len(reqHeaders) == 0 {
		w.line("reverse_proxy %s", upstreams)
		return
	}
	w.open("reverse_proxy %s", upstreams)
	if multi && o.LBPolicy != "" {
		w.line("lb_policy %s", o.LBPolicy)
	}
	if o.HealthURI != "" {
		w.line("health_uri %s", o.HealthURI)
	}
	if o.HostHeader {
		w.line("header_up Host {upstream_hostport}")
	}
	for _, h := range reqHeaders {
		w.line("header_up %s", headerOp(h))
	}
	if tls {
		w.open("transport http")
		w.line("tls_insecure_skip_verify")
		w.close()
	}
	w.close()
}

// headerOp renders one rule in the field syntax shared by header and header_up.
func headerOp(h HeaderRule) string {
	switch h.Op {
	case HeaderDelete:
		return "-" + h.Name
	case HeaderAdd:
		return fmt.Sprintf(`+%s "%s"`, h.Name, h.Value)
	default:
		return fmt.Sprintf(`%s "%s"`, h.Name, h.Value)
	}
}
