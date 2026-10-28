package ldapclient

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
	"github.com/go-ldap/ldap/v3"
)

func newTestClient(t *testing.T, cfg ldaptest.Config) (*Client, *ldaptest.Server) {
	t.Helper()
	srv := ldaptest.Start(t, cfg)
	c, err := New(context.Background(), Config{URL: srv.URL, BindDN: cfg.BindDN, Password: cfg.Password, PageSize: 100})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, srv
}

func TestNewRejectsWrongPassword(t *testing.T) {
	srv := ldaptest.Start(t, ldaptest.CorpAD())
	_, err := New(context.Background(), Config{URL: srv.URL, BindDN: ldaptest.BindDN, Password: "wrong"})
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("err = %v, want invalid credentials", err)
	}
}

func TestNewRejectsUnreachableServer(t *testing.T) {
	if _, err := New(context.Background(), Config{URL: "ldap://127.0.0.1:1"}); err == nil {
		t.Fatal("dial to closed port succeeded")
	}
}

func manyUsers(n int) ldaptest.Config {
	cfg := ldaptest.Config{Entries: []*ldaptest.Entry{ldaptest.NewEntry("DC=x", "dc", "x")}}
	for i := range n {
		cfg.Entries = append(cfg.Entries, ldaptest.NewEntry(fmt.Sprintf("CN=u%d,DC=x", i), "objectClass", "user"))
	}
	return cfg
}

func TestSearchFollowsPagingCookieUntilExhausted(t *testing.T) {
	cfg := manyUsers(7)
	cfg.MaxPageSize = 2
	c, srv := newTestClient(t, cfg)

	res, err := c.Search(context.Background(), Query{Base: "DC=x", Scope: ldap.ScopeSingleLevel, Filter: "(objectClass=user)"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 7 || res.Truncated {
		t.Errorf("got %d entries (truncated=%v), want all 7", len(res.Entries), res.Truncated)
	}
	if n := srv.Searches.Load(); n < 4 {
		t.Errorf("server saw %d searches, want >= 4 pages", n)
	}
}

func TestSearchStopsAtLimitAndReportsTruncation(t *testing.T) {
	cfg := manyUsers(7)
	cfg.MaxPageSize = 2
	c, _ := newTestClient(t, cfg)

	res, err := c.Search(context.Background(), Query{Base: "DC=x", Scope: ldap.ScopeSingleLevel, Filter: "(objectClass=user)", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 3 || !res.Truncated {
		t.Errorf("got %d entries (truncated=%v), want 3 truncated", len(res.Entries), res.Truncated)
	}
}

func TestSearchHonoursCancelledContext(t *testing.T) {
	c, _ := newTestClient(t, manyUsers(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Search(ctx, Query{Base: "DC=x", Filter: "(objectClass=*)"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestEntryReassemblesRangedAttribute(t *testing.T) {
	cfg := manyUsers(0)
	g := ldaptest.NewEntry("CN=big,DC=x", "objectClass", "group")
	for i := range 7 {
		g.Attrs["member"] = append(g.Attrs["member"], fmt.Sprintf("CN=u%d,DC=x", i))
	}
	cfg.Entries = append(cfg.Entries, g)
	cfg.RangeLimit = 3
	c, _ := newTestClient(t, cfg)

	e, err := c.Entry(context.Background(), "CN=big,DC=x", "member", "objectClass")
	if err != nil {
		t.Fatal(err)
	}
	if got := e.GetAttributeValues("member"); len(got) != 7 || got[6] != "CN=u6,DC=x" {
		t.Errorf("member = %v, want 7 values", got)
	}
	if got := len(e.GetRawAttributeValues("member")); got != 7 {
		t.Errorf("raw member values = %d, want 7", got)
	}
	for _, a := range e.Attributes {
		if a.Name != "member" && a.Name != "objectClass" {
			t.Errorf("leftover attribute %q", a.Name)
		}
	}
}

func TestEntryReturnsErrNotFoundForMissingDN(t *testing.T) {
	c, _ := newTestClient(t, ldaptest.CorpAD())
	_, err := c.Entry(context.Background(), "CN=ghost,"+ldaptest.BaseDN)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRootDSEDetectsActiveDirectory(t *testing.T) {
	c, _ := newTestClient(t, ldaptest.CorpAD())
	root, err := c.RootDSE(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsAD || root.DefaultNamingContext != ldaptest.BaseDN || len(root.NamingContexts) != 1 {
		t.Errorf("root = %+v", root)
	}
}

func TestRootDSEReportsNonADServer(t *testing.T) {
	cfg := manyUsers(0)
	cfg.RootDSE = ldaptest.NewEntry("", "namingContexts", "DC=x", "vendorName", "OpenLDAP")
	c, _ := newTestClient(t, cfg)
	root, err := c.RootDSE(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if root.IsAD || root.DefaultNamingContext != "DC=x" || root.Vendor != "OpenLDAP" {
		t.Errorf("root = %+v", root)
	}
}

func TestClientReconnectsAfterConnectionDrops(t *testing.T) {
	c, _ := newTestClient(t, ldaptest.CorpAD())
	c.mu.Lock()
	_ = c.conn.Close()
	c.mu.Unlock()

	if _, err := c.Entry(context.Background(), ldaptest.AliceDN); err != nil {
		t.Fatalf("Entry after drop: %v", err)
	}
}

func TestSearchKeepsPartialResultsWhenServerSizeLimitHits(t *testing.T) {
	cfg := manyUsers(5)
	cfg.SizeLimit = 3
	c, _ := newTestClient(t, cfg)

	res, err := c.Search(context.Background(), Query{Base: "DC=x", Scope: ldap.ScopeSingleLevel, Filter: "(objectClass=user)"})
	if err != nil {
		t.Fatalf("err = %v, want partial result", err)
	}
	if len(res.Entries) != 3 || !res.Truncated {
		t.Errorf("got %d entries (truncated=%v), want 3 truncated", len(res.Entries), res.Truncated)
	}
}

func TestEntryCapsRangedRetrievalAndMarksTruncation(t *testing.T) {
	old := maxAttributeValues
	maxAttributeValues = 7
	t.Cleanup(func() { maxAttributeValues = old })

	cfg := manyUsers(0)
	g := ldaptest.NewEntry("CN=huge,DC=x", "objectClass", "group")
	for i := range 30 {
		g.Attrs["member"] = append(g.Attrs["member"], fmt.Sprintf("CN=u%d,DC=x", i))
	}
	cfg.Entries = append(cfg.Entries, g)
	cfg.RangeLimit = 3
	c, srv := newTestClient(t, cfg)
	before := srv.Searches.Load()

	e, err := c.Entry(context.Background(), "CN=huge,DC=x", "member")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(e.GetAttributeValues("member")); n < 7 || n > 9 {
		t.Errorf("member values = %d, want capped near 7", n)
	}
	if !IsTruncated(e, "member") {
		t.Error("capped attribute not marked truncated")
	}
	if n := srv.Searches.Load() - before; n > 4 {
		t.Errorf("issued %d searches, want <= 4 once the cap is reached", n)
	}
}

func TestEntryNotTruncatedWhenComplete(t *testing.T) {
	c, _ := newTestClient(t, ldaptest.CorpAD())
	e, err := c.Entry(context.Background(), ldaptest.EngineeringDN, "member")
	if err != nil {
		t.Fatal(err)
	}
	if IsTruncated(e, "member") {
		t.Error("complete attribute marked truncated")
	}
}

func TestEntryReturnsErrReferralForOtherDomain(t *testing.T) {
	cfg := ldaptest.CorpAD()
	cfg.ReferralSuffixes = []string{"DC=other,DC=local"}
	c, _ := newTestClient(t, cfg)
	_, err := c.Entry(context.Background(), "CN=Zed,OU=Users,DC=other,DC=local")
	if !errors.Is(err, ErrReferral) {
		t.Fatalf("err = %v, want ErrReferral", err)
	}
}
