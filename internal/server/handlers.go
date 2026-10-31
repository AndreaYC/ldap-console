package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/AndreaYC/ldap-console/internal/session"
	"github.com/go-ldap/ldap/v3"
)

type attribute struct {
	Name   string       `json:"name"`
	Values []attr.Value `json:"values"`
}

type entryResponse struct {
	DN         string         `json:"dn"`
	Kind       directory.Kind `json:"kind"`
	Attributes []attribute    `json:"attributes"`
}

type searchResponse struct {
	Entries   []entryResponse `json:"entries"`
	Truncated bool            `json:"truncated,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// adConstructedAttrs are computed by AD on base-scope reads and never
// returned for "*"; they answer "when does this password expire / is it locked".
var adConstructedAttrs = []string{"msDS-UserPasswordExpiryTimeComputed", "msDS-User-Account-Control-Computed"}

func (s *Server) handleChildren(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.Children(ctx, dn)
	respond(w, res, err)
}

func (s *Server) handleEntry(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	attrs := []string{"*", "+"}
	if sess.Root.IsAD {
		attrs = append(attrs, adConstructedAttrs...)
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	e, err := sess.Client.Entry(ctx, dn, attrs...)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.toEntryResponse(e))
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	q, err := parseSearch(r, sess.BaseDN)
	if err != nil {
		writeError(w, err)
		return
	}
	// Kind needs objectClass; fetch it even when not asked for, then hide it.
	hideObjectClass := len(q.Attrs) > 0 && !slices.ContainsFunc(q.Attrs, func(a string) bool {
		return a == "*" || strings.EqualFold(a, "objectClass")
	})
	if hideObjectClass {
		q.Attrs = append(q.Attrs, "objectClass")
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Client.Search(ctx, q)
	if err != nil {
		writeError(w, err)
		return
	}
	out := searchResponse{Entries: make([]entryResponse, 0, len(res.Entries)), Truncated: res.Truncated}
	for _, e := range res.Entries {
		er := s.toEntryResponse(e)
		if hideObjectClass {
			er.Attributes = slices.DeleteFunc(er.Attributes, func(a attribute) bool { return strings.EqualFold(a.Name, "objectClass") })
		}
		out.Entries = append(out.Entries, er)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleFind(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeError(w, badRequest("q is required"))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.Find(ctx, q)
	respond(w, res, err)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	base := ""
	if r.URL.Query().Get("base") != "" {
		var err error
		if base, err = dnParam(r, "base"); err != nil {
			writeError(w, err)
			return
		}
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.Groups(ctx, base)
	respond(w, res, err)
}

func (s *Server) handleUserGroups(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.GroupsOf(ctx, dn)
	respond(w, res, err)
}

// handleBulkUserGroups resolves a list of names (repeated name parameters)
// and returns each one's groups. It stays a GET: it reads only, and the
// list fits in a query string.
func (s *Server) handleBulkUserGroups(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	names, err := bulkNames(r)
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.GroupsOfMany(ctx, names)
	respond(w, res, err)
}

type explainResponse struct {
	directory.Explanation
	Values []attribute `json:"values,omitempty"`
}

// handleExplain checks one account against a filter, part by part.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	p := r.URL.Query()
	who := strings.TrimSpace(p.Get("who"))
	switch {
	case who == "":
		writeError(w, badRequest("enter the person to check"))
		return
	case len(who) > maxNameLen || strings.HasPrefix(who, "("):
		writeError(w, badRequest("%.40q is not a login name, email or DN", who))
		return
	}
	filter := strings.TrimSpace(p.Get("filter"))
	if filter == "" {
		writeError(w, badRequest("filter is required"))
		return
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		writeError(w, badRequest("invalid filter: %v", err))
		return
	}
	base := ""
	if p.Get("base") != "" {
		var err error
		if base, err = dnParam(r, "base"); err != nil {
			writeError(w, err)
			return
		}
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.Explain(ctx, who, filter, base)
	if errors.Is(err, directory.ErrFilterTooLarge) {
		err = badRequest("%v", err)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	out := explainResponse{Explanation: res}
	for _, v := range res.Values {
		out.Values = append(out.Values, attribute{Name: v.Name, Values: s.render.Render(v.Name, v.Values)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	nested := r.URL.Query().Get("nested") == "true"
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := sess.Dir.MembersOf(ctx, dn, nested)
	respond(w, res, err)
}

func (s *Server) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.timeout)
}

// toEntryResponse renders attributes with objectClass first, then by name.
func (s *Server) toEntryResponse(e *ldap.Entry) entryResponse {
	out := entryResponse{
		DN:         e.DN,
		Kind:       directory.KindOf(e.GetAttributeValues("objectClass")),
		Attributes: make([]attribute, 0, len(e.Attributes)),
	}
	for _, a := range e.Attributes {
		out.Attributes = append(out.Attributes, attribute{Name: a.Name, Values: s.render.Render(a.Name, a.ByteValues)})
	}
	slices.SortFunc(out.Attributes, func(a, b attribute) int {
		if ao, bo := strings.EqualFold(a.Name, "objectClass"), strings.EqualFold(b.Name, "objectClass"); ao != bo {
			if ao {
				return -1
			}
			return 1
		}
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out
}

func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("write response", "err", err)
	}
}

// writeError maps errors to status codes. LDAP diagnostics are passed through:
// this is a local admin tool and the operator needs them to fix filters/ACLs.
func writeError(w http.ResponseWriter, err error) {
	var bad *badRequestError
	status := http.StatusBadGateway
	switch {
	case errors.As(err, &bad):
		status = http.StatusBadRequest
	case errors.Is(err, ldapclient.ErrNotFound), ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		status = http.StatusNotFound
	case errors.Is(err, errNotConnected):
		status = http.StatusServiceUnavailable
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		status = http.StatusUnauthorized
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case ldap.IsErrorWithCode(err, ldap.LDAPResultFilterError), ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidDNSyntax):
		status = http.StatusBadRequest
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}
