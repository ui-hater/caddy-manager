package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"
)

//go:embed templates/*.html static
var assets embed.FS

func main() {
	listen := flag.String("listen", ":8090", "Adresse des Webinterfaces")
	dbPath := flag.String("db", "caddy-manager.db", "SQLite-Datenbank")
	resetPw := flag.String("reset-password", "", "setzt für diesen Benutzer ein neues Einmal-Passwort und beendet sich")
	flag.Parse()

	store, err := OpenStore(*dbPath)
	if err != nil {
		log.Fatalf("datenbank öffnen: %v", err)
	}
	defer store.Close()

	if *resetPw != "" {
		u, err := store.UserByName(*resetPw)
		if err != nil {
			log.Fatalf("benutzer %q: %v", *resetPw, err)
		}
		pw := randomPassword()
		if err := (&App{store: store}).setPassword(u.ID, pw, true); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Neues Einmal-Passwort für %s: %s\n", u.Username, pw)
		return
	}

	tfs, _ := fs.Sub(assets, ".")
	pages, err := loadPages(tfs)
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	app := &App{
		store:    store,
		caddy:    NewCaddy(store.Settings()),
		sessions: NewSessions(),
		limiter:  NewLoginLimiter(),
		pages:    pages,
	}
	handler := app.Routes(tfs)
	if !app.setupDone.Load() {
		log.Printf("Noch kein Admin vorhanden – Ersteinrichtung unter http://%s/setup öffnen", displayAddr(*listen))
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	log.Printf("caddy-manager läuft auf %s (Datenbank %s)", *listen, *dbPath)
	log.Fatal(srv.ListenAndServe())
}

func displayAddr(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "localhost" + addr
	}
	return addr
}
