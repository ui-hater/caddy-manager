package main

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "cm_session"
	sessionTTL    = 12 * time.Hour
)

type Session struct {
	UserID  int64
	CSRF    string
	Expires time.Time
	Flash   *Flash
}

type Flash struct {
	Kind string // "ok" or "err"
	Msg  string
}

// Sessions are kept in memory; a restart logs everyone out.
type Sessions struct {
	mu sync.Mutex
	m  map[string]*Session
}

func NewSessions() *Sessions {
	s := &Sessions{m: map[string]*Session{}}
	go func() {
		for range time.Tick(10 * time.Minute) {
			s.mu.Lock()
			for k, v := range s.m {
				if time.Now().After(v.Expires) {
					delete(s.m, k)
				}
			}
			s.mu.Unlock()
		}
	}()
	return s
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Sessions) Create(w http.ResponseWriter, userID int64, secure bool) *Session {
	tok := randToken()
	sess := &Session{UserID: userID, CSRF: randToken(), Expires: time.Now().Add(sessionTTL)}
	s.mu.Lock()
	s.m[tok] = sess
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
	return sess
}

func (s *Sessions) Get(r *http.Request) (string, *Session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.m[c.Value]
	if sess == nil || time.Now().After(sess.Expires) {
		delete(s.m, c.Value)
		return "", nil
	}
	return c.Value, sess
}

func (s *Sessions) Destroy(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.m, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
}

// DestroyUser logs out all sessions of a user except keep (may be "").
func (s *Sessions) DestroyUser(userID int64, keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.UserID == userID && k != keep {
			delete(s.m, k)
		}
	}
}

func (s *Sessions) SetFlash(sess *Session, kind, msg string) {
	s.mu.Lock()
	sess.Flash = &Flash{Kind: kind, Msg: msg}
	s.mu.Unlock()
}

func (s *Sessions) PopFlash(sess *Session) *Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := sess.Flash
	sess.Flash = nil
	return f
}

// LoginLimiter blocks an IP for a while after too many failed logins.
type LoginLimiter struct {
	mu sync.Mutex
	m  map[string]*attempts
}

type attempts struct {
	n     int
	until time.Time
}

func NewLoginLimiter() *LoginLimiter { return &LoginLimiter{m: map[string]*attempts{}} }

// clientIP returns the real client address. When the request comes from a
// local or private address (i.e. through Caddy), the last X-Forwarded-For
// entry is used, which is the one the proxy itself appended.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		parts := strings.Split(xff, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
			return last
		}
	}
	return host
}

func (l *LoginLimiter) Blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	return a != nil && time.Now().Before(a.until)
}

func (l *LoginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil {
		a = &attempts{}
		l.m[ip] = a
	}
	a.n++
	if a.n >= 5 {
		a.until = time.Now().Add(5 * time.Minute)
		a.n = 0
	}
}

func (l *LoginLimiter) Success(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}
