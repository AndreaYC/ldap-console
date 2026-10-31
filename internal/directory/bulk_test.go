package directory

import (
	"context"
	"fmt"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

func TestGroupsOfManyResolvesEachNameAndKeepsInputOrder(t *testing.T) {
	res, err := corp(t).GroupsOfMany(context.Background(), []string{
		"carol",            // sAMAccountName
		"ALICE@corp.local", // mail, any case
		`CORP\bob`,         // DOMAIN\login
		ldaptest.CarolDN,   // full DN
		"nobody",
		"Engineering", // a group, not a person
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		status NameStatus
		name   string
	}{{NameFound, "Carol"}, {NameFound, "Alice"}, {NameFound, "Bob"}, {NameFound, "Carol"}, {NameNotFound, ""}, {NameNotFound, ""}}
	if len(res.People) != len(want) {
		t.Fatalf("got %d rows, want %d", len(res.People), len(want))
	}
	for i, w := range want {
		p := res.People[i]
		if p.Status != w.status || (w.name != "" && (len(p.Matches) != 1 || p.Matches[0].Name != w.name)) {
			t.Errorf("row %d (%q) = %s %+v, want %s %s", i, p.Query, p.Status, p.Matches, w.status, w.name)
		}
	}
	assertItems(t, res.People[0].Groups,
		"Backend[direct]", "Engineering<Backend", "AllStaff<Backend<Engineering", "Domain Users[primary][direct]")
	if !res.People[2].Matches[0].Disabled {
		t.Error("disabled account Bob not flagged")
	}
}

func TestGroupsOfManyReportsAmbiguousNamesWithCandidates(t *testing.T) {
	cfg := ldaptest.CorpAD()
	cfg.Entries = append(cfg.Entries, ldaptest.NewEntry("CN=Alice Wong,OU=Users,"+ldaptest.BaseDN,
		"objectClass", "user", "objectClass", "person", "cn", "Alice Wong", "displayName", "alice", "sAMAccountName", "awong"))
	res, err := newService(t, cfg, ldaptest.BaseDN, true).GroupsOfMany(context.Background(), []string{"alice", "awong"})
	if err != nil {
		t.Fatal(err)
	}
	if p := res.People[0]; p.Status != NameAmbiguous || len(p.Matches) != 2 || p.Groups != nil {
		t.Errorf("alice = %s %+v, want ambiguous with 2 candidates and no groups", p.Status, p.Matches)
	}
	if p := res.People[1]; p.Status != NameFound || p.Matches[0].Name != "alice" {
		t.Errorf("awong = %s %+v", p.Status, p.Matches)
	}
}

func TestGroupsOfManySplitsLongListsIntoSeveralSearches(t *testing.T) {
	names := make([]string, 0, 3*nameChunk)
	for i := range 3*nameChunk - 1 {
		names = append(names, fmt.Sprintf("missing-%d", i))
	}
	names = append(names, "carol")
	s, srv := newServiceWithServer(t, ldaptest.CorpAD(), ldaptest.BaseDN, true)
	before := srv.Searches.Load()
	res, err := s.GroupsOfMany(context.Background(), names)
	if err != nil {
		t.Fatal(err)
	}
	if last := res.People[len(names)-1]; last.Status != NameFound || last.Matches[0].Name != "Carol" {
		t.Errorf("last row = %+v", last)
	}
	if res.People[0].Status != NameNotFound {
		t.Errorf("first row = %+v", res.People[0])
	}
	if n := srv.Searches.Load() - before; n < 3 {
		t.Errorf("%d searches, want one per chunk of %d names at least", n, nameChunk)
	}
}

func TestGroupsOfManyRefusesTooManyNames(t *testing.T) {
	if _, err := corp(t).GroupsOfMany(context.Background(), make([]string, MaxBulkNames+1)); err == nil {
		t.Error("want an error above MaxBulkNames")
	}
}

func TestLoginKeyStripsDomainButNotDNs(t *testing.T) {
	for in, want := range map[string]string{`CORP\Alice`: "alice", " bob ": "bob", `CN=a\,b,DC=x`: `cn=a\,b,dc=x`} {
		if got := loginKey(in); got != want {
			t.Errorf("loginKey(%q) = %q, want %q", in, got, want)
		}
	}
}
