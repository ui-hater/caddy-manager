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
- **Eine Datei pro Namespace:** Die Sites landen in `/etc/caddy/sites/<domain>.caddy`, die Caddyfile bindet per `import /etc/caddy/sites/*.caddy` alles ein, was auf `.caddy` endet.
- **Bestehende Konfiguration übernehmen:** Die Ersteinrichtung durchsucht die Caddyfile samt aller importierten Dateien und übernimmt vorhandene Sites, damit nichts verloren geht.
- **Sicher speichern:** Jede Änderung schreibt die Dateien, prüft sie mit `caddy validate` und lädt sie mit `caddy reload`. Schlägt das fehl, werden Dateien und Datenbank zurückgerollt.
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

Danach `http://<server>:8090/` öffnen. Beim ersten Start erscheint die **Ersteinrichtung**: Dort legst du den Admin an und gibst die Caddyfile und das Verzeichnis für die Site-Dateien an. Die Einstellungen landen in der Datenbank und sind später unter *Admin → Caddy* änderbar. Bis die Einrichtung abgeschlossen ist, kann sie jeder aufrufen, der den Port erreicht. Also direkt nach dem ersten Start erledigen.

Optionale Flags:

| Flag | Standard | Bedeutung |
|---|---|---|
| `-listen` | `:8090` | Adresse des UI |
| `-db` | `caddy-manager.db` | SQLite-Datei (relativ zum Arbeitsverzeichnis) |
| `-reset-password <user>` | | neues Einmal-Passwort setzen und beenden |

### Dateien

```
/etc/caddy/Caddyfile                     # deine Datei; caddy-manager ergänzt nur die import-Zeile (und ggf. email)
/etc/caddy/sites/aaronhosting.xyz.caddy  # generiert: alle Subdomains von aaronhosting.xyz
/etc/caddy/sites/leons.cc.caddy          # generiert: alle Subdomains von leons.cc
```

```caddy
# /etc/caddy/Caddyfile
{
	email admin@aaronhosting.xyz
}

(common) {
	encode gzip
}

import /etc/caddy/sites/*.caddy
```

Die generierten Dateien beginnen mit dem Kommentar `# Generiert von caddy-manager`. Nur solche Dateien werden überschrieben oder gelöscht (wenn ein Namespace keine Subdomains mehr hat). Eigene `.caddy`-Dateien im selben Verzeichnis werden mit eingebunden und nicht angefasst. Die E-Mail für Let's Encrypt wird als globale Option `email` in die Caddyfile geschrieben.

### Bestehende Sites übernehmen

Ist bei der Ersteinrichtung *Bestehende Sites übernehmen* angehakt (Standard), liest caddy-manager die Caddyfile und alle per `import` eingebundenen Dateien:

- Site-Blöcke für **eine einzelne Domain** (`app.example.com`, auch mit `https://` oder `:443`) wandern in die Datenbank und in die passende Site-Datei und werden aus ihrer alten Datei entfernt. Der Namespace ergibt sich aus der registrierbaren Domain (`app.example.com` → `example.com`, `shop.example.co.uk` → `example.co.uk`) und wird automatisch angelegt.
- Besteht der Block nur aus `reverse_proxy <ziel>`, wird er eine normale Subdomain. Alles andere wird unverändert als **eigene Konfiguration** übernommen; die kann nur ein Admin bearbeiten.
- Globale Optionen, Snippets und Sites mit mehreren Adressen, Wildcards, Ports oder `http://` bleiben, wo sie sind. Welche das sind, zeigt die Meldung nach der Einrichtung.

Danach prüft `caddy validate` das Ergebnis. Schlägt das fehl, wird nichts geändert.

### Als systemd-Dienst

[`caddy-manager.service`](caddy-manager.service) startet das UI als Benutzer `caddy` auf `127.0.0.1:8090` (also nur über Caddy erreichbar, siehe oben) und legt die Datenbank unter `/var/lib/caddy-manager/` ab:

```sh
install -m 755 caddy-manager /usr/local/bin/
install -m 644 caddy-manager.service /etc/systemd/system/
chown caddy:caddy /etc/caddy /etc/caddy/Caddyfile   # Schreibrechte für Caddyfile und sites/
systemctl daemon-reload
systemctl enable --now caddy-manager
```

Liegen Caddyfile oder Site-Verzeichnis woanders als unter `/etc/caddy`, passe `ReadWritePaths=` in der Unit an. Für die Ersteinrichtung vorher `manager.example.com { reverse_proxy 127.0.0.1:8090 }` in die Caddyfile eintragen (wird bei der Einrichtung mit übernommen) oder per SSH-Tunnel auf Port 8090 zugreifen.

Passwort zurücksetzen:

```sh
sudo -u caddy /usr/local/bin/caddy-manager -db /var/lib/caddy-manager/caddy-manager.db -reset-password <user>
```

### Voraussetzungen

- Caddy ≥ 2.8 (wegen `basic_auth`)
- caddy-manager läuft auf der Caddy-VM: Er braucht Schreibrechte auf die Caddyfile und das Site-Verzeichnis, und `caddy reload` muss die Admin-API (`localhost:2019`) erreichen.
- DNS: am einfachsten ein Wildcard-Eintrag `*.aaronhosting.xyz` auf die Caddy-VM.
- Hinter Caddy werden `X-Forwarded-Proto` (Secure-Cookies) und `X-Forwarded-For` (Login-Sperre nach Fehlversuchen) ausgewertet.

## Tests

```sh
go test ./...
```

Die Tests prüfen die erzeugten Dateien (inklusive Übernahme einer bestehenden Konfiguration) mit Caddys eigenem Parser und `caddy.Validate`. Caddy ist dafür nur eine Test-Abhängigkeit und landet nicht im Binary.

### Übersetzungen

Deutsch ist die Quellsprache: Texte stehen auf Deutsch im Code (`errf`, `a.ok`, …) und in den Templates (`{{t "…"}}`, `{{th "…"}}` für Texte mit HTML, `{{tf "…" args}}`). Die englischen Übersetzungen liegen in `i18n_en.go`. `TestCatalogComplete` schlägt fehl, wenn ein Text keine Übersetzung hat, ein Eintrag nicht mehr benutzt wird oder die `%`-Platzhalter nicht übereinstimmen.

## Lizenz

[MIT](LICENSE)
