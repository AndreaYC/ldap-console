package directory

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

func newService(t *testing.T, cfg ldaptest.Config, base string, isAD bool) *Service {
	t.Helper()
	srv := ldaptest.Start(t, cfg)
	c, err := ldapclient.New(ldapclient.Config{URL: srv.URL, BindDN: cfg.BindDN, Password: cfg.Password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return New(c, base, isAD)
}

func corp(t *testing.T) *Service {
	return newService(t, ldaptest.CorpAD(), ldaptest.BaseDN, true)
}

// summary renders memberships as "Name[flags]<via1<via2" for compact assertions.
func summary(items []Membership) []string {
	out := make([]string, 0, len(items))
	for _, m := range items {
		s := m.Name
		if m.Primary {
			s += "[primary]"
		}
		if m.Direct {
			s += "[direct]"
		}
		for _, v := range m.Via {
			s += "<" + rdnValue(v)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func assertItems(t *testing.T, got []Membership, want ...string) {
	t.Helper()
	slices.Sort(want)
	if g := summary(got); !slices.Equal(g, want) {
		t.Errorf("got  %q\nwant %q", g, want)
	}
}

func TestGroupsOfResolvesDirectNestedAndPrimaryGroups(t *testing.T) {
	res, err := corp(t).GroupsOf(context.Background(), ldaptest.CarolDN)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items,
		"Backend[direct]",
		"Engineering<Backend",
		"AllStaff<Backend<Engineering",
		"Domain Users[primary][direct]",
	)
	if res.Subject.Name != "Carol" || res.Subject.Kind != KindUser {
		t.Errorf("subject = %+v", res.Subject)
	}
}

func TestGroupsOfTerminatesOnMembershipCycles(t *testing.T) {
	res, err := corp(t).GroupsOf(context.Background(), ldaptest.AliceDN)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items,
		"Engineering[direct]",
		"CycleB[direct]",
		"AllStaff<Engineering",
		"CycleA<CycleB",
		"Domain Users[primary][direct]",
	)
}

func TestMembersOfListsDirectMembersWithKinds(t *testing.T) {
	res, err := corp(t).MembersOf(context.Background(), ldaptest.EngineeringDN, false)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items, "Alice[direct]", "Backend[direct]")
	kinds := map[string]Kind{}
	for _, m := range res.Items {
		kinds[m.Name] = m.Kind
	}
	if kinds["Alice"] != KindUser || kinds["Backend"] != KindGroup {
		t.Errorf("kinds = %v", kinds)
	}
}

func TestMembersOfNestedExpandsSubgroupsWithPath(t *testing.T) {
	res, err := corp(t).MembersOf(context.Background(), ldaptest.AllStaffDN, true)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items,
		"Engineering[direct]", "Ops[direct]",
		"Alice<Engineering", "Backend<Engineering", "Bob<Ops",
		"Carol<Engineering<Backend",
	)
	for _, m := range res.Items {
		if m.Name == "Bob" && !m.Disabled {
			t.Error("disabled account Bob not flagged")
		}
		if m.Name == "Alice" && m.Disabled {
			t.Error("enabled account Alice flagged disabled")
		}
	}
}

func TestMembersOfIncludesPrimaryGroupMembersOnAD(t *testing.T) {
	res, err := corp(t).MembersOf(context.Background(), ldaptest.DomainUsersDN, false)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items, "Alice[primary][direct]", "Bob[primary][direct]", "Carol[primary][direct]")
}

func TestMembersOfNestedTerminatesOnCycles(t *testing.T) {
	res, err := corp(t).MembersOf(context.Background(), ldaptest.CycleADN, true)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items, "CycleB[direct]", "Alice<CycleB")
}

func TestMembersOfKeepsDanglingMemberDNs(t *testing.T) {
	cfg := ldaptest.CorpAD()
	ghost := "CN=Deleted User,OU=Users," + ldaptest.BaseDN
	for _, e := range cfg.Entries {
		if e.DN == ldaptest.OpsDN {
			e.Attrs["member"] = append(e.Attrs["member"], ghost)
		}
	}
	res, err := newService(t, cfg, ldaptest.BaseDN, true).MembersOf(context.Background(), ldaptest.OpsDN, false)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items, "Bob[direct]", "Deleted User[direct]")
	for _, m := range res.Items {
		if m.DN == ghost && m.Kind != KindUnknown {
			t.Errorf("dangling member kind = %q", m.Kind)
		}
	}
}

const ldapBase = "dc=example,dc=org"

// openLDAP has no memberOf overlay and no primary groups: membership must be
// discovered by searching member/uniqueMember/memberUid.
func openLDAP() ldaptest.Config {
	return ldaptest.Config{Entries: []*ldaptest.Entry{
		ldaptest.NewEntry(ldapBase, "objectClass", "dcObject", "dc", "example"),
		ldaptest.NewEntry("ou=people,"+ldapBase, "objectClass", "organizationalUnit", "ou", "people"),
		ldaptest.NewEntry("ou=groups,"+ldapBase, "objectClass", "organizationalUnit", "ou", "groups"),
		ldaptest.NewEntry("uid=dave,ou=people,"+ldapBase, "objectClass", "inetOrgPerson", "objectClass", "posixAccount", "uid", "dave", "cn", "Dave"),
		ldaptest.NewEntry("uid=erin,ou=people,"+ldapBase, "objectClass", "inetOrgPerson", "uid", "erin", "cn", "Erin"),
		ldaptest.NewEntry("cn=devs,ou=groups,"+ldapBase, "objectClass", "groupOfNames", "cn", "devs", "member", "uid=dave,ou=people,"+ldapBase),
		ldaptest.NewEntry("cn=staff,ou=groups,"+ldapBase, "objectClass", "groupOfUniqueNames", "cn", "staff",
			"uniqueMember", "cn=devs,ou=groups,"+ldapBase+"#'0101'B", "uniqueMember", "uid=erin,ou=people,"+ldapBase),
		ldaptest.NewEntry("cn=unix,ou=groups,"+ldapBase, "objectClass", "posixGroup", "cn", "unix", "memberUid", "dave"),
	}}
}

func TestGroupsOfOnOpenLDAPUsesMemberSearches(t *testing.T) {
	s := newService(t, openLDAP(), ldapBase, false)
	res, err := s.GroupsOf(context.Background(), "uid=dave,ou=people,"+ldapBase)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, res.Items, "devs[direct]", "unix[direct]", "staff<devs")
}

func TestMembersOfOnOpenLDAPResolvesUniqueMemberAndMemberUid(t *testing.T) {
	s := newService(t, openLDAP(), ldapBase, false)
	staff, err := s.MembersOf(context.Background(), "cn=staff,ou=groups,"+ldapBase, true)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, staff.Items, "devs[direct]", "Erin[direct]", "Dave<devs")

	unix, err := s.MembersOf(context.Background(), "cn=unix,ou=groups,"+ldapBase, false)
	if err != nil {
		t.Fatal(err)
	}
	assertItems(t, unix.Items, "Dave[direct]")
}

func TestChildrenListsContainersBeforeLeaves(t *testing.T) {
	res, err := corp(t).Children(context.Background(), ldaptest.BaseDN)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range res.Items {
		names = append(names, o.Name)
		if o.Kind != KindContainer {
			t.Errorf("%s kind = %q, want container", o.Name, o.Kind)
		}
	}
	if want := []string{"Computers", "Groups", "Service", "Users"}; !slices.Equal(names, want) {
		t.Errorf("children = %v, want %v", names, want)
	}

	users, err := corp(t).Children(context.Background(), "OU=Users,"+ldaptest.BaseDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(users.Items) != 3 || users.Items[0].Name != "Alice" {
		t.Errorf("users = %+v", users.Items)
	}
}

func TestFindMatchesSubstringsAcrossNamingAttributes(t *testing.T) {
	res, err := corp(t).Find(context.Background(), "ali")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].DN != ldaptest.AliceDN {
		t.Errorf("find ali = %+v", res.Items)
	}
}

func TestFindEscapesFilterMetacharacters(t *testing.T) {
	res, err := corp(t).Find(context.Background(), "*)(objectClass=*")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 {
		t.Errorf("injected filter matched %d entries", len(res.Items))
	}
}

func TestGroupsListsEveryGroupFlavour(t *testing.T) {
	res, err := newService(t, openLDAP(), ldapBase, false).Groups(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range res.Items {
		names = append(names, g.Name)
	}
	if got := strings.Join(names, ","); got != "devs,staff,unix" {
		t.Errorf("groups = %s", got)
	}
}

func TestGroupsDecodesADGroupType(t *testing.T) {
	res, err := corp(t).Groups(context.Background(), "OU=Groups,"+ldaptest.BaseDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 7 || res.Items[0].GroupType != "Security · Global" {
		t.Errorf("groups = %+v", res.Items)
	}
}
