package ldaptest

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
)

// Server is a running fake LDAP server.
type Server struct {
	URL string

	// Searches counts search operations received, one per page.
	Searches atomic.Int64

	cfg   Config
	srv   *gldap.Server
	mu    sync.Mutex
	bound map[int]bool // connection ID -> authenticated
}

// Config describes the fake directory.
type Config struct {
	BindDN, Password string
	Entries          []*Entry
	RootDSE          *Entry
	// RangeLimit caps values per multi-valued attribute (AD uses 1500). 0 = unlimited.
	RangeLimit int
	// MaxPageSize caps entries per page regardless of the client's request.
	MaxPageSize int
	// ReferralSuffixes are naming contexts held by another domain: a search
	// based at or under one answers with a referral, as an AD DC does.
	ReferralSuffixes []string
	// SizeLimit makes the server return only this many entries per search
	// with sizeLimitExceeded, as an OpenLDAP per-user limit does. 0 = none.
	SizeLimit int
}

// Start runs a fake LDAP server on a free loopback port until the test ends.
func Start(t testing.TB, cfg Config) *Server {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	s, err := Serve(cfg, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

// Serve runs a fake LDAP server on addr until Stop is called.
func Serve(cfg Config, addr string) (*Server, error) {
	s := &Server{cfg: cfg, bound: map[int]bool{}}
	srv, err := gldap.NewServer()
	if err != nil {
		return nil, err
	}
	mux, err := gldap.NewMux()
	if err != nil {
		return nil, err
	}
	if err := errors.Join(mux.Bind(s.handleBind), mux.Search(s.handleSearch), srv.Router(mux)); err != nil {
		return nil, err
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Run(addr) }()
	for deadline := time.Now().Add(5 * time.Second); !srv.Ready(); {
		select {
		case err := <-errc:
			return nil, fmt.Errorf("ldaptest: serve %s: %w", addr, err)
		default:
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("ldaptest: server on %s did not start", addr)
		}
		time.Sleep(time.Millisecond)
	}
	s.srv = srv
	s.URL = "ldap://" + addr
	return s, nil
}

// Stop shuts the server down.
func (s *Server) Stop() error { return s.srv.Stop() }

func (s *Server) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		return
	}
	if m.UserName == s.cfg.BindDN && string(m.Password) == s.cfg.Password {
		s.mu.Lock()
		s.bound[r.ConnectionID()] = true
		s.mu.Unlock()
		resp.SetResultCode(gldap.ResultSuccess)
	}
}

func (s *Server) isBound(connID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.BindDN == "" || s.bound[connID]
}

func (s *Server) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	s.Searches.Add(1)
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultOperationsError))
	defer func() { _ = w.Write(done) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		return
	}
	if !s.isBound(r.ConnectionID()) {
		done.SetResultCode(gldap.ResultInsufficientAccessRights)
		return
	}
	if m.BaseDN == "" && m.Scope == gldap.BaseObject {
		if s.cfg.RootDSE != nil {
			s.writeEntry(w, r, s.cfg.RootDSE, m.Attributes)
		}
		done.SetResultCode(gldap.ResultSuccess)
		return
	}
	matches, code := s.find(m)
	if code != gldap.ResultSuccess {
		done.SetResultCode(code)
		return
	}
	if s.cfg.SizeLimit > 0 && len(matches) > s.cfg.SizeLimit {
		for _, e := range matches[:s.cfg.SizeLimit] {
			s.writeEntry(w, r, e, m.Attributes)
		}
		done.SetResultCode(gldap.ResultSizeLimitExceeded)
		return
	}
	page, next := s.paginate(m, matches)
	for _, e := range page {
		s.writeEntry(w, r, e, m.Attributes)
	}
	if next != nil {
		done.SetControls(next)
	}
	done.SetResultCode(gldap.ResultSuccess)
}

func (s *Server) find(m *gldap.SearchMessage) ([]*Entry, int) {
	base, err := ldap.ParseDN(m.BaseDN)
	if err != nil {
		return nil, gldap.ResultInvalidDNSyntax
	}
	for _, suffix := range s.cfg.ReferralSuffixes {
		if sfx, err := ldap.ParseDN(suffix); err == nil && (sfx.EqualFold(base) || sfx.AncestorOfFold(base)) {
			return nil, gldap.ResultReferral
		}
	}
	filter, err := ldap.CompileFilter(m.Filter)
	if err != nil {
		return nil, gldap.ResultProtocolError
	}
	baseExists := false
	var out []*Entry
	for _, e := range s.cfg.Entries {
		if e.parsedDN().EqualFold(base) {
			baseExists = true
		}
		if e.inScope(base, int(m.Scope)) && match(filter, e) {
			out = append(out, e)
		}
	}
	if !baseExists {
		return nil, gldap.ResultNoSuchObject
	}
	return out, gldap.ResultSuccess
}

// paginate honours the paging control; the cookie is the next offset.
func (s *Server) paginate(m *gldap.SearchMessage, all []*Entry) ([]*Entry, gldap.Control) {
	var req *gldap.ControlPaging
	for _, c := range m.Controls {
		if p, ok := c.(*gldap.ControlPaging); ok {
			req = p
		}
	}
	if req == nil {
		return all, nil
	}
	offset, _ := strconv.Atoi(string(req.Cookie))
	size := int(req.PagingSize)
	if s.cfg.MaxPageSize > 0 && (size == 0 || size > s.cfg.MaxPageSize) {
		size = s.cfg.MaxPageSize
	}
	offset = min(offset, len(all))
	end := len(all)
	if size > 0 {
		end = min(end, offset+size)
	}
	resp, _ := gldap.NewControlPaging(uint32(size))
	if end < len(all) {
		resp.Cookie = []byte(strconv.Itoa(end))
	}
	return all[offset:end], resp
}

func (s *Server) writeEntry(w *gldap.ResponseWriter, r *gldap.Request, e *Entry, attrs []string) {
	resp := r.NewSearchResponseEntry(e.DN)
	for name, vals := range e.selectAttrs(attrs, s.cfg.RangeLimit) {
		resp.AddAttribute(name, vals)
	}
	_ = w.Write(resp)
}
