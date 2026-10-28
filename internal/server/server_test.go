package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

const testHost = "127.0.0.1:8389"

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg := ldaptest.CorpAD()
	srv := ldaptest.Start(t, cfg)
	c, err := ldapclient.New(ldapclient.Config{URL: srv.URL, BindDN: cfg.BindDN, Password: cfg.Password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	info := Info{URL: srv.URL, BindDN: cfg.BindDN, BaseDN: ldaptest.BaseDN, IsAD: true}
	return New(c, directory.New(c, ldaptest.BaseDN, true), info, Options{ListenAddr: testHost, Loc: time.UTC})
}

func get(t *testing.T, h http.Handler, path string, params ...string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{}
	for i := 0; i+1 < len(params); i += 2 {
		q.Set(params[i], params[i+1])
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) T {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, wantStatus, rec.Body)
	}
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return v
}

func TestInfoReportsConnectionAndReadOnlyMode(t *testing.T) {
	got := decode[Info](t, get(t, newTestHandler(t), "/api/info"), http.StatusOK)
	if got.BaseDN != ldaptest.BaseDN || !got.IsAD || got.BindDN != ldaptest.BindDN || !got.ReadOnly {
		t.Errorf("info = %+v", got)
	}
}

func TestEntryRendersDecodedAttributesAndKind(t *testing.T) {
	got := decode[entryResponse](t, get(t, newTestHandler(t), "/api/entry", "dn", ldaptest.BobDN), http.StatusOK)
	if got.Kind != directory.KindUser {
		t.Errorf("kind = %q", got.Kind)
	}
	if got.Attributes[0].Name != "objectClass" {
		t.Errorf("first attribute = %q, want objectClass", got.Attributes[0].Name)
	}
	byName := map[string]attribute{}
	for _, a := range got.Attributes {
		byName[a.Name] = a
	}
	if v := byName["objectSid"].Values[0].Text; v != "S-1-5-21-1-2-3-1102" {
		t.Errorf("objectSid = %q", v)
	}
	if n := byName["userAccountControl"].Values[0].Note; !strings.Contains(n, "ACCOUNTDISABLE") {
		t.Errorf("userAccountControl note = %q", n)
	}
	if !byName["memberOf"].Values[0].DN {
		t.Error("memberOf value not marked as DN")
	}
}

func TestEntryReturns404ForMissingDN(t *testing.T) {
	rec := get(t, newTestHandler(t), "/api/entry", "dn", "CN=ghost,"+ldaptest.BaseDN)
	if got := decode[errorResponse](t, rec, http.StatusNotFound); got.Error == "" {
		t.Error("empty error message")
	}
}

func TestEndpointsRejectInvalidInput(t *testing.T) {
	h := newTestHandler(t)
	tests := []struct {
		name   string
		path   string
		params []string
	}{
		{"missing dn", "/api/entry", nil},
		{"unparseable dn", "/api/children", []string{"dn", "not a dn"}},
		{"bad filter", "/api/search", []string{"filter", "(cn=a"}},
		{"bad scope", "/api/search", []string{"filter", "(cn=a)", "scope", "everything"}},
		{"bad limit", "/api/search", []string{"filter", "(cn=a)", "limit", "0"}},
		{"bad attr name", "/api/search", []string{"filter", "(cn=a)", "attrs", "cn,)("}},
		{"empty find", "/api/find", []string{"q", "  "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decode[errorResponse](t, get(t, h, tt.path, tt.params...), http.StatusBadRequest)
		})
	}
}

func TestChildrenListsTreeLevel(t *testing.T) {
	got := decode[directory.ListResult](t, get(t, newTestHandler(t), "/api/children", "dn", ldaptest.BaseDN), http.StatusOK)
	if len(got.Items) != 4 || got.Items[0].Name != "Computers" {
		t.Errorf("children = %+v", got.Items)
	}
}

func TestSearchReturnsRenderedEntries(t *testing.T) {
	rec := get(t, newTestHandler(t), "/api/search", "filter", "(sAMAccountName=carol)", "attrs", "cn,userAccountControl", "scope", "sub")
	got := decode[searchResponse](t, rec, http.StatusOK)
	if len(got.Entries) != 1 || got.Entries[0].DN != ldaptest.CarolDN {
		t.Fatalf("entries = %+v", got.Entries)
	}
	if n := len(got.Entries[0].Attributes); n != 2 {
		t.Errorf("got %d attributes, want only the 2 requested", n)
	}
	if got.Entries[0].Kind != directory.KindUser {
		t.Errorf("kind = %q without objectClass requested, want user", got.Entries[0].Kind)
	}
}

func TestUserGroupsAndGroupMembers(t *testing.T) {
	h := newTestHandler(t)
	groups := decode[directory.MembershipResult](t, get(t, h, "/api/user-groups", "dn", ldaptest.CarolDN), http.StatusOK)
	if len(groups.Items) != 4 {
		t.Errorf("carol groups = %+v", groups.Items)
	}

	direct := decode[directory.MembershipResult](t, get(t, h, "/api/group-members", "dn", ldaptest.AllStaffDN), http.StatusOK)
	nested := decode[directory.MembershipResult](t, get(t, h, "/api/group-members", "dn", ldaptest.AllStaffDN, "nested", "true"), http.StatusOK)
	if len(direct.Items) != 2 || len(nested.Items) != 6 {
		t.Errorf("direct=%d nested=%d, want 2 and 6", len(direct.Items), len(nested.Items))
	}
}

func TestFindAndGroups(t *testing.T) {
	h := newTestHandler(t)
	found := decode[directory.ListResult](t, get(t, h, "/api/find", "q", "bob"), http.StatusOK)
	if len(found.Items) != 1 || found.Items[0].DN != ldaptest.BobDN {
		t.Errorf("find = %+v", found.Items)
	}
	groups := decode[directory.ListResult](t, get(t, h, "/api/groups"), http.StatusOK)
	if len(groups.Items) != 7 {
		t.Errorf("groups = %d, want 7", len(groups.Items))
	}
}

func TestRejectsForeignHostHeader(t *testing.T) {
	// A DNS-rebinding page reaches us with its own hostname in Host.
	req := httptest.NewRequest(http.MethodGet, "http://evil.example:8389/api/info", nil)
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestAcceptsLocalhostAlias(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8389/api/info", nil)
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRejectsNonGETMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/info", nil)
	rec := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestServesUIWithRestrictiveHeaders(t *testing.T) {
	rec := get(t, newTestHandler(t), "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>") {
		t.Fatalf("index: %d %.80s", rec.Code, rec.Body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
}
