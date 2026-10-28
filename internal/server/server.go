// Package server exposes the directory over a local, read-only JSON API and
// serves the embedded browser UI.
package server

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/AndreaYC/ldap-console/web"
	"github.com/go-ldap/ldap/v3"
)

// LDAP is the client surface the handlers need.
type LDAP interface {
	Search(ctx context.Context, q ldapclient.Query) (ldapclient.Result, error)
	Entry(ctx context.Context, dn string, attrs ...string) (*ldap.Entry, error)
}

// Info describes the connection, shown in the UI header.
type Info struct {
	URL            string   `json:"url"`
	BindDN         string   `json:"bindDN"`
	BaseDN         string   `json:"baseDN"`
	NamingContexts []string `json:"namingContexts"`
	Vendor         string   `json:"vendor"`
	IsAD           bool     `json:"isAD"`
	ReadOnly       bool     `json:"readOnly"`
}

// Options configures the handler.
type Options struct {
	// ListenAddr is the host:port the server is bound to; requests whose
	// Host header names anything else are refused (DNS-rebinding defence).
	ListenAddr string
	// Loc is the time zone for decoded timestamps.
	Loc *time.Location
	// RequestTimeout bounds each API call; 0 means one minute.
	RequestTimeout time.Duration
}

type handler struct {
	ldap    LDAP
	dir     *directory.Service
	info    Info
	render  attr.Renderer
	timeout time.Duration
}

// New returns the HTTP handler for the API and UI.
func New(c LDAP, dir *directory.Service, info Info, opts Options) http.Handler {
	info.ReadOnly = true
	h := &handler{ldap: c, dir: dir, info: info, render: attr.Renderer{Loc: opts.Loc}, timeout: opts.RequestTimeout}
	if h.timeout == 0 {
		h.timeout = time.Minute
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", h.handleInfo)
	mux.HandleFunc("GET /api/children", h.handleChildren)
	mux.HandleFunc("GET /api/entry", h.handleEntry)
	mux.HandleFunc("GET /api/search", h.handleSearch)
	mux.HandleFunc("GET /api/find", h.handleFind)
	mux.HandleFunc("GET /api/groups", h.handleGroups)
	mux.HandleFunc("GET /api/user-groups", h.handleUserGroups)
	mux.HandleFunc("GET /api/group-members", h.handleGroupMembers)

	static, err := fs.Sub(web.Static, "static")
	if err != nil {
		panic(err) // embedded at build time; cannot fail at runtime
	}
	mux.Handle("GET /", http.FileServerFS(static))

	return logRequests(securityHeaders(onlyHosts(allowedHosts(opts.ListenAddr), readOnly(mux))))
}

func allowedHosts(listen string) map[string]bool {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return map[string]bool{listen: true}
	}
	hosts := map[string]bool{listen: true}
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		hosts[net.JoinHostPort(h, port)] = true
	}
	return hosts
}

func onlyHosts(allowed map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// readOnly refuses every method that could change state. Phase 1 has no
// write endpoints; this keeps it that way even if one is added by mistake.
func readOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only console", http.StatusMethodNotAllowed)
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
