package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	IsAdmin            bool
	Namespace          string
	MustChangePassword bool
	CreatedAt          time.Time
}

type Namespace struct {
	Domain    string
	CreatedAt time.Time
}

type Proxy struct {
	ID        int64
	Namespace string
	Host      string
	Upstream  string // space separated list of upstreams (kind proxy)
	Enabled   bool
	Opts      SiteOptions
	CreatedBy string
	CreatedAt time.Time
}

const (
	KindProxy    = "proxy"
	KindRedirect = "redirect"
	KindRespond  = "respond"
)

// SiteOptions holds everything beyond host and upstream. It is stored as JSON
// so new Caddy features don't need schema changes.
type SiteOptions struct {
	Kind string `json:"kind,omitempty"` // "" means KindProxy

	// reverse proxy
	LBPolicy      string  `json:"lb_policy,omitempty"`
	HealthURI     string  `json:"health_uri,omitempty"`
	TLSSkipVerify bool    `json:"tls_skip_verify,omitempty"`
	HostHeader    bool    `json:"host_header,omitempty"`
	Routes        []Route `json:"routes,omitempty"`

	// redirect
	RedirectTo       string `json:"redirect_to,omitempty"`
	RedirectCode     int    `json:"redirect_code,omitempty"`
	RedirectKeepPath bool   `json:"redirect_keep_path,omitempty"`

	// static response
	RespondStatus int    `json:"respond_status,omitempty"`
	RespondBody   string `json:"respond_body,omitempty"`

	// common
	BasicAuthUser string   `json:"basic_auth_user,omitempty"`
	BasicAuthHash string   `json:"basic_auth_hash,omitempty"`
	AllowIPs      []string `json:"allow_ips,omitempty"`
	Compress      bool     `json:"compress,omitempty"`
	HSTS          bool     `json:"hsts,omitempty"`
	AccessLog     bool     `json:"access_log,omitempty"`
	Extra         string   `json:"extra,omitempty"` // raw directives, admins only
}

// Route sends a path prefix to a different upstream.
type Route struct {
	Path     string `json:"path"`
	Upstream string `json:"upstream"`
	Strip    bool   `json:"strip,omitempty"`
}

func (o SiteOptions) KindOrDefault() string {
	if o.Kind == "" {
		return KindProxy
	}
	return o.Kind
}

// Settings are configured on the setup page and editable by admins.
type Settings struct {
	CaddyFile   string // file this program generates completely
	CaddyConfig string // main config for validate/reload; empty = CaddyFile
	CaddyBin    string
	Reload      bool
	Email       string // ACME e-mail, written as global option
}

func DefaultSettings() Settings {
	return Settings{CaddyFile: "/etc/caddy/Caddyfile", CaddyBin: "caddy", Reload: true}
}

var (
	ErrNotFound = errors.New("nicht gefunden")
	ErrExists   = errors.New("existiert bereits")
)

const schema = `
CREATE TABLE IF NOT EXISTS namespaces (
	domain     TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	id                   INTEGER PRIMARY KEY,
	username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash        TEXT NOT NULL,
	is_admin             INTEGER NOT NULL DEFAULT 0,
	namespace            TEXT REFERENCES namespaces(domain),
	must_change_password INTEGER NOT NULL DEFAULT 0,
	created_at           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proxies (
	id         INTEGER PRIMARY KEY,
	namespace  TEXT NOT NULL REFERENCES namespaces(domain),
	host       TEXT NOT NULL UNIQUE,
	upstream   TEXT NOT NULL,
	created_by TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);`

// migrations run in order; PRAGMA user_version stores how many have been applied.
var migrations = []string{
	`ALTER TABLE proxies ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;
	 ALTER TABLE proxies ADD COLUMN options TEXT NOT NULL DEFAULT '{}';`,
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			return err
		}
	}
	return nil
}

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(60000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

func unix(t int64) time.Time { return time.Unix(t, 0) }

// ---- users ----

const userCols = `id, username, password_hash, is_admin, COALESCE(namespace, ''), must_change_password, created_at`

type scanner interface{ Scan(...any) error }

// dbtx is implemented by both *sql.DB and *sql.Tx.
type dbtx interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func scanUser(r scanner) (User, error) {
	var u User
	var ts int64
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &u.Namespace, &u.MustChangePassword, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.CreatedAt = unix(ts)
	return u, err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) UserCount() int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (s *Store) Users() []User {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		if u, err := scanUser(rows); err == nil {
			out = append(out, u)
		}
	}
	return out
}

func (s *Store) UserByID(id int64) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) UserByName(name string) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

// checkNamespace gives a clear error instead of a foreign key failure.
func checkNamespace(q dbtx, ns string) error {
	var x int
	if ns != "" && q.QueryRow(`SELECT 1 FROM namespaces WHERE domain = ?`, ns).Scan(&x) != nil {
		return errors.New("Namespace existiert nicht")
	}
	return nil
}

func insertUser(q dbtx, u User) (User, error) {
	if err := checkNamespace(q, u.Namespace); err != nil {
		return User{}, err
	}
	u.CreatedAt = time.Now()
	res, err := q.Exec(`INSERT INTO users (username, password_hash, is_admin, namespace, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, u.IsAdmin, nullable(u.Namespace), u.MustChangePassword, u.CreatedAt.Unix())
	if isUnique(err) {
		return User{}, ErrExists
	}
	if err != nil {
		return User{}, err
	}
	u.ID, _ = res.LastInsertId()
	return u, nil
}

func (s *Store) CreateUser(u User) (User, error) {
	return insertUser(s.db, u)
}

// Setup creates the first admin and stores the settings, but only if there
// are no users yet. It returns false if setup was already done.
func (s *Store) Setup(admin User, st Settings) (User, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return User{}, false, err
	}
	if n > 0 {
		return User{}, false, nil
	}
	u, err := insertUser(tx, admin)
	if err != nil {
		return User{}, false, err
	}
	if err := saveSettings(tx, st); err != nil {
		return User{}, false, err
	}
	return u, true, tx.Commit()
}

// UpdateUser applies fn to the stored user and persists the result.
func (s *Store) UpdateUser(id int64, fn func(u *User) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, err := scanUser(tx.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if err != nil {
		return err
	}
	if err := fn(&u); err != nil {
		return err
	}
	if err := checkNamespace(tx, u.Namespace); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET password_hash = ?, is_admin = ?, namespace = ?, must_change_password = ? WHERE id = ?`,
		u.PasswordHash, u.IsAdmin, nullable(u.Namespace), u.MustChangePassword, u.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- namespaces ----

func (s *Store) Namespaces() []Namespace {
	rows, err := s.db.Query(`SELECT domain, created_at FROM namespaces ORDER BY domain`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Namespace
	for rows.Next() {
		var n Namespace
		var ts int64
		if rows.Scan(&n.Domain, &ts) == nil {
			n.CreatedAt = unix(ts)
			out = append(out, n)
		}
	}
	return out
}

func (s *Store) NamespaceExists(domain string) bool {
	var x int
	return s.db.QueryRow(`SELECT 1 FROM namespaces WHERE domain = ?`, domain).Scan(&x) == nil
}

func (s *Store) CreateNamespace(domain string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Nested namespaces would make host ownership ambiguous.
	var other string
	err = tx.QueryRow(`SELECT domain FROM namespaces WHERE domain = ? OR ? LIKE '%.' || domain OR domain LIKE '%.' || ? LIMIT 1`,
		domain, domain, domain).Scan(&other)
	if err == nil {
		return errors.New("überschneidet sich mit Namespace " + other)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO namespaces (domain, created_at) VALUES (?, ?)`, domain, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteNamespace(domain string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	tx.QueryRow(`SELECT COUNT(*) FROM users WHERE namespace = ?`, domain).Scan(&n)
	if n > 0 {
		return errors.New("Namespace hat noch Benutzer")
	}
	tx.QueryRow(`SELECT COUNT(*) FROM proxies WHERE namespace = ?`, domain).Scan(&n)
	if n > 0 {
		return errors.New("Namespace hat noch Reverse Proxies")
	}
	res, err := tx.Exec(`DELETE FROM namespaces WHERE domain = ?`, domain)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// ---- proxies ----

const proxyCols = `id, namespace, host, upstream, enabled, options, created_by, created_at`

func scanProxy(r scanner) (Proxy, error) {
	var p Proxy
	var ts int64
	var opts string
	err := r.Scan(&p.ID, &p.Namespace, &p.Host, &p.Upstream, &p.Enabled, &opts, &p.CreatedBy, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.CreatedAt = unix(ts)
	return p, json.Unmarshal([]byte(opts), &p.Opts)
}

func queryProxies(q dbtx, namespace string) ([]Proxy, error) {
	rows, err := q.Query(`SELECT `+proxyCols+` FROM proxies WHERE ? = '' OR namespace = ? ORDER BY host`, namespace, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Proxy{}
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Proxies returns the proxies of a namespace, or all for namespace "".
func (s *Store) Proxies(namespace string) []Proxy {
	ps, _ := queryProxies(s.db, namespace)
	return ps
}

func (s *Store) ProxyByID(id int64) (Proxy, error) {
	return scanProxy(s.db.QueryRow(`SELECT `+proxyCols+` FROM proxies WHERE id = ?`, id))
}

// ProxyChange describes one modification of the proxy list.
type ProxyChange struct {
	Add    *Proxy
	Update *Proxy
	Delete int64
}

// ChangeProxies performs c inside a transaction, hands the resulting full
// proxy list to apply (which writes the Caddyfile and reloads Caddy) and only
// commits when apply succeeded.
func (s *Store) ChangeProxies(c ProxyChange, apply func([]Proxy) error) (Proxy, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Proxy{}, err
	}
	defer tx.Rollback()

	var p Proxy
	var res sql.Result
	switch {
	case c.Add != nil:
		p = *c.Add
		p.CreatedAt = time.Now()
		opts, _ := json.Marshal(p.Opts)
		res, err = tx.Exec(`INSERT INTO proxies (namespace, host, upstream, enabled, options, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			p.Namespace, p.Host, p.Upstream, p.Enabled, string(opts), p.CreatedBy, p.CreatedAt.Unix())
		if isUnique(err) {
			return Proxy{}, errors.New("Host " + p.Host + " ist bereits vergeben")
		}
		if err == nil {
			p.ID, _ = res.LastInsertId()
		}
	case c.Update != nil:
		p = *c.Update
		opts, _ := json.Marshal(p.Opts)
		res, err = tx.Exec(`UPDATE proxies SET upstream = ?, enabled = ?, options = ? WHERE id = ?`, p.Upstream, p.Enabled, string(opts), p.ID)
	default:
		if p, err = scanProxy(tx.QueryRow(`SELECT `+proxyCols+` FROM proxies WHERE id = ?`, c.Delete)); err != nil {
			return Proxy{}, err
		}
		res, err = tx.Exec(`DELETE FROM proxies WHERE id = ?`, c.Delete)
	}
	if err != nil {
		return Proxy{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Proxy{}, ErrNotFound
	}

	list, err := queryProxies(tx, "")
	if err != nil {
		return Proxy{}, err
	}
	if err := apply(list); err != nil {
		return Proxy{}, err
	}
	return p, tx.Commit()
}

// ---- settings ----

func (s *Store) Settings() Settings {
	st := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return st
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		switch k {
		case "caddy_file":
			st.CaddyFile = v
		case "caddy_config":
			st.CaddyConfig = v
		case "caddy_bin":
			st.CaddyBin = v
		case "reload":
			st.Reload, _ = strconv.ParseBool(v)
		case "email":
			st.Email = v
		}
	}
	return st
}

func saveSettings(tx dbtx, st Settings) error {
	for k, v := range map[string]string{
		"caddy_file":   st.CaddyFile,
		"caddy_config": st.CaddyConfig,
		"caddy_bin":    st.CaddyBin,
		"reload":       strconv.FormatBool(st.Reload),
		"email":        st.Email,
	} {
		if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SaveSettings(st Settings) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveSettings(tx, st); err != nil {
		return err
	}
	return tx.Commit()
}
