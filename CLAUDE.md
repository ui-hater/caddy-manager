# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build -trimpath -ldflags="-s -w" -o caddy-manager .                                  # local build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o caddy-manager .   # deploy target (Caddy VM)
go vet ./... && gofmt -l .
go test ./...
go test -run TestEditSite ./...            # single test
./caddy-manager                            # defaults: -listen :8090 -db caddy-manager.db
./caddy-manager -reset-password <user>     # one-time password, then exit
```

Caddy is installed neither locally nor needed for tests: `render_test.go` imports Caddy as a library (test-only dependency, not in the binary) and runs the generated Caddyfile through Caddy's real adapter and `caddy.Validate`. Test output is noisy with Caddy JSON logs; filter with `grep -v '^{"level'`.

## What it is

Single-binary Go web app (stdlib `net/http` + `html/template`, `go:embed` for `templates/` and `static/`, SQLite via pure-Go `modernc.org/sqlite`) that manages subdomains in a Caddyfile. Admins create accounts and assign each a domain namespace (e.g. `aaronhosting.xyz`); several accounts can share a namespace; members manage `<sub>.<namespace>` sites. First start with an empty DB shows a Gitea-style `/setup` page (admin account + Caddy paths); every request is redirected there until a user exists.

## Architecture

**Change pipeline (the core invariant).** Every proxy mutation goes through `Store.ChangeProxies(change, caddy.Apply)` (`store.go`): the change is executed inside a SQLite transaction, the full resulting proxy list is passed to `Caddy.Apply` (`caddy.go`), which renders the file, writes it atomically, runs `caddy validate` then `caddy reload`. On any error the old file is restored and the transaction rolls back — DB and Caddyfile never diverge. Don't write proxies to the DB outside this path. Caddy settings (file paths, binary, reload toggle, ACME email) live in the `settings` table, not flags; `Caddy.Configure` swaps them at runtime.

**Rendering (`render.go`).** `RenderCaddyfile` is deterministic (sorted by host) because the admin dashboard detects drift by comparing it to the file on disk. Sites only get a `route { }` wrapper when there is something whose order matters (IP filter → basic_auth → headers → encode → handlers); simple sites are a bare `reverse_proxy`. Response headers use `header { … defer }`, request headers `header_up` inside `reverse_proxy`. Global options are only emitted when the managed file is the main config (`CaddyConfig == ""`).

**Injection safety.** All user values are written into the Caddyfile unquoted or in `"…"`, so `validate.go` is the security boundary: hosts, upstreams, paths, IPs etc. use strict allow-list patterns, and free-text values (respond body, header values) reject `{ } " \` and control chars — braces would otherwise be Caddy placeholders (e.g. `{env.SECRET}`). Only the admin-only `Extra` field is passed through raw (brace-balance checked, then `caddy validate`). New per-site options must get the same treatment plus a case in `TestValidation`/`TestEditSite`.

**Data model.** `Proxy` has fixed columns (host, upstream, enabled) plus `SiteOptions` stored as a JSON column, so new Caddy features usually need no schema change. Schema changes go in the append-only `migrations` slice (tracked via `PRAGMA user_version`); never edit existing entries.

**Auth.** In-memory sessions (restart logs everyone out), per-session CSRF token checked in `App.auth` for every POST, `MustChangePassword` forces `/account`. `clientIP`/`isHTTPS` trust `X-Forwarded-*` because the UI normally runs behind the Caddy it manages.

## i18n — German is the source language

All user-facing text is written in German and the German string is the key into `catalogEN` (`i18n_en.go`).

- Go: return errors via `errf("format %s", x)` (a `uiError`, translated when displayed by `trErr`); flash messages via `a.ok(w, r, cu, to, "format", args…)` / `a.fail(w, r, cu, to, err)`; page titles passed to `a.render` are translated automatically. Don't use `errors.New` or string concatenation for user-facing messages.
- Templates: `{{t "…"}}`, `{{tf "format" args}}`, `{{th "…"}}` for catalog texts containing HTML. Use backtick strings for texts with quotes. Templates are parsed once per language at startup (`loadPages`), each with its own func map.
- `TestCatalogComplete` extracts keys from Go code (AST, function names/arg positions in `translatable`) and templates (regex) and fails on missing translations, unused catalog entries, or mismatched `%` verbs — its output lists missing keys ready to paste. If you add a new helper that takes a translatable literal, register it in `translatable`.

## Testing notes

`app_test.go` drives the real HTTP handlers through `httptest` with cookie-jar clients (`newClient`, `setup`); Caddy reload is off there, so tests assert on the written Caddyfile. Assertions match German UI strings (default language when no `Accept-Language` is sent).
