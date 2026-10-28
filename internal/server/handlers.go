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

func (h *handler) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.info)
}

func (h *handler) handleChildren(w http.ResponseWriter, r *http.Request) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	res, err := h.dir.Children(ctx, dn)
	respond(w, res, err)
}

func (h *handler) handleEntry(w http.ResponseWriter, r *http.Request) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	attrs := []string{"*", "+"}
	if h.info.IsAD {
		attrs = append(attrs, adConstructedAttrs...)
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	e, err := h.ldap.Entry(ctx, dn, attrs...)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toEntryResponse(e))
}

func (h *handler) handleSearch(w http.ResponseWriter, r *http.Request) {
	q, err := parseSearch(r, h.info.BaseDN)
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
	ctx, cancel := h.ctx(r)
	defer cancel()
	res, err := h.ldap.Search(ctx, q)
	if err != nil {
		writeError(w, err)
		return
	}
	out := searchResponse{Entries: make([]entryResponse, 0, len(res.Entries)), Truncated: res.Truncated}
	for _, e := range res.Entries {
		er := h.toEntryResponse(e)
		if hideObjectClass {
			er.Attributes = slices.DeleteFunc(er.Attributes, func(a attribute) bool { return strings.EqualFold(a.Name, "objectClass") })
		}
		out.Entries = append(out.Entries, er)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) handleFind(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeError(w, badRequest("q is required"))
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	res, err := h.dir.Find(ctx, q)
	respond(w, res, err)
}

func (h *handler) handleGroups(w http.ResponseWriter, r *http.Request) {
	base := ""
	if r.URL.Query().Get("base") != "" {
		var err error
		if base, err = dnParam(r, "base"); err != nil {
			writeError(w, err)
			return
		}
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	res, err := h.dir.Groups(ctx, base)
	respond(w, res, err)
}

func (h *handler) handleUserGroups(w http.ResponseWriter, r *http.Request) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	res, err := h.dir.GroupsOf(ctx, dn)
	respond(w, res, err)
}

func (h *handler) handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	dn, err := dnParam(r, "dn")
	if err != nil {
		writeError(w, err)
		return
	}
	nested := r.URL.Query().Get("nested") == "true"
	ctx, cancel := h.ctx(r)
	defer cancel()
	res, err := h.dir.MembersOf(ctx, dn, nested)
	respond(w, res, err)
}

func (h *handler) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), h.timeout)
}

// toEntryResponse renders attributes with objectClass first, then by name.
func (h *handler) toEntryResponse(e *ldap.Entry) entryResponse {
	out := entryResponse{
		DN:         e.DN,
		Kind:       directory.KindOf(e.GetAttributeValues("objectClass")),
		Attributes: make([]attribute, 0, len(e.Attributes)),
	}
	for _, a := range e.Attributes {
		out.Attributes = append(out.Attributes, attribute{Name: a.Name, Values: h.render.Render(a.Name, a.ByteValues)})
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
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case ldap.IsErrorWithCode(err, ldap.LDAPResultFilterError), ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidDNSyntax):
		status = http.StatusBadRequest
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}
