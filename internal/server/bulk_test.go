package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

func getBulk(t *testing.T, h http.Handler, names ...string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"name": names}
	req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/api/user-groups-bulk?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBulkUserGroupsDedupesAndResolves(t *testing.T) {
	got := decode[directory.BulkResult](t, getBulk(t, newTestHandler(t), " carol ", "Carol", "", "bob", "nobody"), http.StatusOK)
	if len(got.People) != 3 {
		t.Fatalf("people = %+v, want carol, bob, nobody", got.People)
	}
	if p := got.People[0]; p.Query != "carol" || p.Status != directory.NameFound || len(p.Groups) != 4 {
		t.Errorf("carol = %+v", p)
	}
	if p := got.People[1]; p.Status != directory.NameFound || p.Matches[0].DN != ldaptest.BobDN {
		t.Errorf("bob = %+v", p)
	}
	if p := got.People[2]; p.Status != directory.NameNotFound {
		t.Errorf("nobody = %+v", p)
	}
}

func TestBulkUserGroupsRejectsBadInput(t *testing.T) {
	h := newTestHandler(t)
	tooMany := make([]string, directory.MaxBulkNames+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("user%d", i)
	}
	for name, names := range map[string][]string{
		"none":     {"", "  "},
		"filter":   {"(cn=*)"},
		"too long": {strings.Repeat("a", maxNameLen+1)},
		"too many": tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			decode[errorResponse](t, getBulk(t, h, names...), http.StatusBadRequest)
		})
	}
}
