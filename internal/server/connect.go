package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/AndreaYC/ldap-console/internal/session"
)

var errNotConnected = errors.New("not connected to a directory server")

type connectRequest struct {
	session.Profile
	Password string `json:"password"`
}

// withSession runs fn with the current session, or answers 503 when the
// console is not connected.
func (s *Server) withSession(fn func(http.ResponseWriter, *http.Request, *session.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		sess := s.sess
		s.mu.RUnlock()
		if sess == nil {
			writeError(w, errNotConnected)
			return
		}
		fn(w, r, sess)
	}
}

func (s *Server) swap(next *session.Session) *session.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.sess
	s.sess = next
	return old
}

func (s *Server) info() Info {
	s.mu.RLock()
	sess := s.sess
	s.mu.RUnlock()
	info := Info{ReadOnly: true, Token: s.token}
	if sess == nil {
		p := s.savedProfile()
		info.Profile = &p
		return info
	}
	info.Connected = true
	p := session.ProfileOf(sess.Settings)
	info.Profile = &p
	info.URL, info.BindDN, info.BaseDN = sess.Settings.URL, sess.Settings.BindDN, sess.BaseDN
	info.NamingContexts, info.Vendor, info.IsAD = sess.Root.NamingContexts, sess.Root.Vendor, sess.Root.IsAD
	return info
}

func (s *Server) savedProfile() session.Profile {
	if s.profile == "" {
		return session.Profile{}
	}
	p, err := session.LoadProfile(s.profile)
	if err != nil {
		slog.Warn("ignoring unreadable profile", "path", s.profile, "err", err)
	}
	return p
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.info())
}

// handleConnect opens a session from the connect page and, once it works,
// replaces the current one. The password is used for this bind only.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, badRequest("invalid connect request: %v", err))
		return
	}
	settings := s.defaults
	settings.URL, settings.BindDN, settings.BaseDN = req.URL, req.BindDN, req.BaseDN
	settings.StartTLS, settings.CAFile = req.StartTLS, req.CAFile
	if err := settings.Validate(); err != nil {
		writeError(w, badRequest("%v", err))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	sess, err := session.Open(ctx, settings, req.Password)
	if err != nil {
		writeError(w, err)
		return
	}
	if old := s.swap(sess); old != nil {
		_ = old.Close()
	}
	slog.Info("connected", "server", settings.URL, "vendor", sess.Root.Vendor, "base", sess.BaseDN, "bind", settings.BindDN)
	if s.profile != "" {
		if err := session.SaveProfile(s.profile, req.Profile); err != nil {
			slog.Warn("could not remember connection settings", "path", s.profile, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, s.info())
}

func (s *Server) handleDisconnect(w http.ResponseWriter, _ *http.Request) {
	if old := s.swap(nil); old != nil {
		_ = old.Close()
	}
	writeJSON(w, http.StatusOK, s.info())
}
