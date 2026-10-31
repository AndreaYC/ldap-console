// Package server exposes the directory over a local, read-only JSON API and
// serves the embedded browser UI. The only state it changes is which server
// it is connected to.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/session"
	"github.com/AndreaYC/ldap-console/web"
)

// Info describes the connection, shown in the UI header. Profile pre-fills
// the connect page: the current settings, or the saved ones when disconnected.
type Info struct {
	Connected      bool             `json:"connected"`
	URL            string           `json:"url,omitempty"`
	BindDN         string           `json:"bindDN,omitempty"`
	BaseDN         string           `json:"baseDN,omitempty"`
	NamingContexts []string         `json:"namingContexts,omitempty"`
	Vendor         string           `json:"vendor,omitempty"`
	IsAD           bool             `json:"isAD,omitempty"`
	ReadOnly       bool             `json:"readOnly"`
	Profile        *session.Profile `json:"profile,omitempty"`
	// Token must accompany every POST. Only this console's own page can read
	// it: other origins get no CORS access and foreign Host headers are refused.
	Token string `json:"token"`
}

// Options configures the handler.
type Options struct {
	// ListenAddr is the host:port the server is bound to; requests whose
	// Host header names a host other than it or a loopback name are refused
	// (DNS-rebinding defence).
	ListenAddr string
	// Loc is the time zone for decoded timestamps.
	Loc *time.Location
	// RequestTimeout bounds each API call; 0 means one minute.
	RequestTimeout time.Duration
	// Defaults supplies the flag-only settings (certificate checks, cleartext
	// policy, paging, timeout) for connections opened from the connect page.
	Defaults session.Settings
	// ProfilePath is where the last successful connect page settings are
	// saved; empty means they are not remembered.
	ProfilePath string
}

// Server is the HTTP handler for the API and UI. It holds at most one
// directory session, which the connect page can replace.
type Server struct {
	http.Handler
	mu       sync.RWMutex
	sess     *session.Session
	render   attr.Renderer
	timeout  time.Duration
	token    string
	defaults session.Settings
	profile  string
}

// New returns the server. initial may be nil, in which case the UI starts
// on the connect page.
func New(initial *session.Session, opts Options) *Server {
	s := &Server{
		sess: initial, render: attr.Renderer{Loc: opts.Loc}, timeout: opts.RequestTimeout,
		token: newToken(), defaults: opts.Defaults, profile: opts.ProfilePath,
	}
	if s.timeout == 0 {
		s.timeout = time.Minute
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.HandleFunc("POST /api/connect", s.handleConnect)
	mux.HandleFunc("POST /api/disconnect", s.handleDisconnect)
	mux.HandleFunc("POST /api/check-login", s.withSession(s.handleCheckLogin))
	mux.HandleFunc("GET /api/children", s.withSession(s.handleChildren))
	mux.HandleFunc("GET /api/entry", s.withSession(s.handleEntry))
	mux.HandleFunc("GET /api/search", s.withSession(s.handleSearch))
	mux.HandleFunc("GET /api/find", s.withSession(s.handleFind))
	mux.HandleFunc("GET /api/groups", s.withSession(s.handleGroups))
	mux.HandleFunc("GET /api/user-groups", s.withSession(s.handleUserGroups))
	mux.HandleFunc("GET /api/user-groups-bulk", s.withSession(s.handleBulkUserGroups))
	mux.HandleFunc("GET /api/group-members", s.withSession(s.handleGroupMembers))

	static, err := fs.Sub(web.Static, "static")
	if err != nil {
		panic(err) // embedded at build time; cannot fail at runtime
	}
	mux.Handle("GET /", http.FileServerFS(static))

	s.Handler = logRequests(securityHeaders(onlyHosts(allowedHosts(opts.ListenAddr), guardWrites(s.token, mux))))
	return s
}

// Close releases the current session, if any.
func (s *Server) Close() error {
	old := s.swap(nil)
	if old == nil {
		return nil
	}
	return old.Close()
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

// allowedHosts lists the host names (without port) a request may address.
// Only the name matters against DNS rebinding: an attacker's page reaches us
// under its own name. The port is not checked because Docker may publish
// the console on a different host port than it listens on.
func allowedHosts(listen string) map[string]bool {
	hosts := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	if h, _, err := net.SplitHostPort(listen); err == nil {
		if ip := net.ParseIP(h); h != "" && (ip == nil || !ip.IsUnspecified()) {
			hosts[h] = true
		}
	}
	return hosts
}

func onlyHosts(allowed map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if !allowed[host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// postPaths are the only endpoints that accept POST: they carry passwords or
// change which server the console talks to. None changes the directory.
var postPaths = map[string]bool{"/api/connect": true, "/api/disconnect": true, "/api/check-login": true}

// guardWrites lets GET and HEAD through. A POST must go to one of postPaths
// and come from this console's own page: same Origin, a JSON body (which a
// cross-site form cannot send without a CORS preflight we never answer), and
// the per-launch token from /api/info.
func guardWrites(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost || !postPaths[r.URL.Path] {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only console", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Origin") != "http://"+r.Host {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
			http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Console-Token")), []byte(token)) != 1 {
			http.Error(w, "missing or wrong console token; reload the page", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests logs method, path and status; never the query string, which
// carries DNs and filters.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "took", time.Since(start))
	})
}
