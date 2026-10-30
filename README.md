# caddy-manager

Web-UI zum Verwalten von Subdomains in [Caddy](https://caddyserver.com), z.B. wenn Caddy auf einer VM läuft und auf die anderen VMs weiterleitet.
Ein einzelnes Binary: Templates, CSS und JS sind per `go:embed` eingebettet, die Datenbank ist SQLite (reines Go, kein cgo).

## Funktionen

- **Konten & Namespaces:** Konten legt nur der Admin an. Jedes Konto bekommt einen Namespace (z.B. `aaronhosting.xyz`), mehrere Konten können sich einen Namespace teilen. Mitglieder verwalten beliebige Subdomains darunter (`social.aaronhosting.xyz`, `tt.aaronhosting.xyz`, …).
- **Admin-Dashboard** (`/admin`, nur für Admins): Übersicht, Konten anlegen/löschen/bearbeiten, Passwörter setzen, Namespaces, Caddy-Einstellungen.
- **Pro Subdomain:**
  - **Reverse Proxy** zu einem oder mehreren Zielen, mit Load-Balancing (`round_robin`, `least_conn`, `ip_hash`, …) und Health-Check
  - HTTPS-Ziele mit selbstsigniertem Zertifikat (z.B. Proxmox), Host-Header ans Ziel durchreichen
  - **Pfad-Routen:** z.B. `/api` → andere VM, Präfix wahlweise entfernen
  - **Weiterleitung** (301/302/307/308, optional mit Pfad)
  - **Feste Antwort**, z.B. als Wartungsseite
  - **Passwortschutz** (`basic_auth`) und **IP-Freigabe** (z.B. `private_ranges` = nur LAN/VPN)
  - **HTTP-Header** setzen, hinzufügen oder entfernen – für die Antwort an den Besucher (überschreibt auch Header vom Ziel) oder für die Anfrage ans Ziel
  - Komprimierung (zstd/gzip), HSTS, Zugriffslog, an/aus schalten
  - Eigene Caddy-Direktiven (nur Admins)
- **Sicher speichern:** Jede Änderung schreibt die Caddyfile, prüft sie mit `caddy validate` und lädt sie mit `caddy reload`. Schlägt das fehl, werden Datei und Datenbank zurückgerollt.
- **Deutsch & Englisch:** Die Sprache folgt dem Browser und lässt sich unten auf jeder Seite umschalten.
- Alle Eingaben werden streng geprüft, damit niemand eigene Caddyfile-Syntax oder Platzhalter (z.B. `{env.SECRET}`) einschleusen kann.

## Bauen

```sh
go build -trimpath -ldflags="-s -w" -o caddy-manager .
# von Windows für Linux:
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o caddy-manager .
```

## Starten

```sh
./caddy-manager
```

Danach `http://<server>:8090/` öffnen. Beim ersten Start erscheint die **Ersteinrichtung**: Dort legst du den Admin an und gibst an, welche Caddyfile verwaltet wird. Die Einstellungen landen in der Datenbank und sind später unter *Admin → Caddy* änderbar. Bis die Einrichtung abgeschlossen ist, kann sie jeder aufrufen, der den Port erreicht. Also direkt nach dem ersten Start erledigen.

Optionale Flags:

| Flag | Standard | Bedeutung |
|---|---|---|
| `-listen` | `:8090` | Adresse des UI |
| `-db` | `caddy-manager.db` | SQLite-Datei (relativ zum Arbeitsverzeichnis) |
| `-reset-password <user>` | | neues Einmal-Passwort setzen und beenden |

### Eigene Caddyfile behalten

Standardmäßig wird `/etc/caddy/Caddyfile` komplett generiert. Wenn du eigene Einträge brauchst (z.B. für das UI selbst), trag im Setup eine eigene Datei als *verwaltete Caddyfile* ein und deine echte Caddyfile als *Haupt-Caddyfile*:

```caddy
# /etc/caddy/Caddyfile
manager.example.com {
	reverse_proxy 127.0.0.1:8090
}

import /etc/caddy/managed.caddy
```

Die globale Option `email` (Let's Encrypt) wird nur geschrieben, wenn die verwaltete Datei auch die Haupt-Caddyfile ist. Sonst trägst du sie selbst in deine Caddyfile ein.

### Als systemd-Dienst

[`caddy-manager.service`](caddy-manager.service) startet das UI als Benutzer `caddy` auf `127.0.0.1:8090` (also nur über Caddy erreichbar, siehe oben) und legt die Datenbank unter `/var/lib/caddy-manager/` ab:

```sh
install -m 755 caddy-manager /usr/local/bin/
install -m 644 caddy-manager.service /etc/systemd/system/
chown caddy:caddy /etc/caddy   # Schreibrechte für die verwaltete Caddyfile
systemctl daemon-reload
systemctl enable --now caddy-manager
```

Liegt die verwaltete Caddyfile woanders als in `/etc/caddy`, passe `ReadWritePaths=` in der Unit an. Für die Ersteinrichtung vorher kurz `manager.example.com { reverse_proxy 127.0.0.1:8090 }` in die Caddyfile eintragen oder per SSH-Tunnel auf Port 8090 zugreifen.

Passwort zurücksetzen:

```sh
sudo -u caddy /usr/local/bin/caddy-manager -db /var/lib/caddy-manager/caddy-manager.db -reset-password <user>
```

### Voraussetzungen

- Caddy ≥ 2.8 (wegen `basic_auth`)
- caddy-manager läuft auf der Caddy-VM: Er braucht Schreibrechte auf die verwaltete Datei, und `caddy reload` muss die Admin-API (`localhost:2019`) erreichen.
- DNS: am einfachsten ein Wildcard-Eintrag `*.aaronhosting.xyz` auf die Caddy-VM.
- Hinter Caddy werden `X-Forwarded-Proto` (Secure-Cookies) und `X-Forwarded-For` (Login-Sperre nach Fehlversuchen) ausgewertet.

## Tests

```sh
go test ./...
```

Die Tests prüfen die erzeugte Caddyfile mit Caddys eigenem Parser und `caddy.Validate`. Caddy ist dafür nur eine Test-Abhängigkeit und landet nicht im Binary.

### Übersetzungen

Deutsch ist die Quellsprache: Texte stehen auf Deutsch im Code (`errf`, `a.ok`, …) und in den Templates (`{{t "…"}}`, `{{th "…"}}` für Texte mit HTML, `{{tf "…" args}}`). Die englischen Übersetzungen liegen in `i18n_en.go`. `TestCatalogComplete` schlägt fehl, wenn ein Text keine Übersetzung hat, ein Eintrag nicht mehr benutzt wird oder die `%`-Platzhalter nicht übereinstimmen.

## Lizenz

[MIT](LICENSE)
