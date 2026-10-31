package directory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
	"github.com/go-ldap/ldap/v3"
)

// builderFilter is what the filter builder writes for AD with AllStaff
// allowed (nested), disabled accounts left out and mail required.
const builderFilter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username})" +
	"(memberOf:1.2.840.113556.1.4.1941:=" + ldaptest.AllStaffDN + ")" +
	"(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*))"

// marks renders each node as "✓ say" / "✗ say", depth-first.
func marks(n *ExplainNode) []string {
	m := "✗ "
	if n.Match {
		m = "✓ "
	}
	out := []string{m + n.Say}
	for _, c := range n.Children {
		out = append(out, marks(c)...)
	}
	return out
}

func TestExplainShowsWhichPartRejectsAnAccount(t *testing.T) {
	res, err := corp(t).Explain(context.Background(), "bob", builderFilter, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != NameFound || res.Match || !res.InBase {
		t.Fatalf("status=%s match=%v inBase=%v", res.Status, res.Match, res.InBase)
	}
	if !strings.Contains(res.Filter, "(sAMAccountName=bob)") {
		t.Errorf("placeholder not filled: %s", res.Filter)
	}
	want := []string{
		"✗ All of these",
		"✓ Is a person (objectCategory)",
		"✓ Is a user entry (objectClass)",
		"✓ sAMAccountName is bob",
		"✓ Is in group AllStaff, directly or through sub-groups (memberOf, LDAP_MATCHING_RULE_IN_CHAIN)",
		"✗ Not: the account is disabled (userAccountControl ACCOUNTDISABLE)",
		"✓ The account is disabled (userAccountControl ACCOUNTDISABLE)",
		"✓ Has a mail value (mail=*)",
	}
	if got := marks(res.Root); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var uac bool
	for _, v := range res.Values {
		uac = uac || strings.EqualFold(v.Name, "userAccountControl")
	}
	if !uac {
		t.Errorf("values %+v lack userAccountControl", res.Values)
	}
}

// The login placeholder is filled with what the person would type, so an
// email typed where the filter compares sAMAccountName fails exactly there.
func TestExplainShowsALoginTypedInTheWrongForm(t *testing.T) {
	res, err := corp(t).Explain(context.Background(), "carol@corp.local", builderFilter, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != NameFound || res.Matches[0].Name != "Carol" || res.Match {
		t.Fatalf("status=%s matches=%+v match=%v", res.Status, res.Matches, res.Match)
	}
	if got := marks(res.Root)[3]; got != "✗ sAMAccountName is carol@corp.local" {
		t.Errorf("login part = %q", got)
	}
}

func TestExplainAcceptsAMatchingAccountByLoginOrDN(t *testing.T) {
	for _, who := range []string{"carol", `CORP\carol`, ldaptest.CarolDN} {
		res, err := corp(t).Explain(context.Background(), who, builderFilter, "")
		if err != nil {
			t.Fatal(err)
		}
		if !res.Match || !strings.Contains(res.Filter, "(sAMAccountName=carol)") {
			t.Errorf("%s: match=%v filter=%s", who, res.Match, res.Filter)
		}
	}
}

func TestExplainHintsAtSubGroupsWhenDirectMemberOfFails(t *testing.T) {
	res, err := corp(t).Explain(context.Background(), "carol", "(memberOf="+ldaptest.EngineeringDN+")", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "(memberOf:1.2.840.113556.1.4.1941:=" + ldaptest.EngineeringDN + ")"
	if res.Match || !strings.Contains(res.Root.Hint, want) {
		t.Errorf("match=%v hint=%q, want one suggesting %s", res.Match, res.Root.Hint, want)
	}
	res, err = corp(t).Explain(context.Background(), "bob", "(memberOf="+ldaptest.EngineeringDN+")", "")
	if err != nil || res.Root.Hint != "" {
		t.Errorf("bob is not in Engineering at all, yet hint=%q (err %v)", res.Root.Hint, err)
	}
}

func TestExplainReportsAnAccountOutsideTheSearchBase(t *testing.T) {
	res, err := corp(t).Explain(context.Background(), "carol", builderFilter, "OU=Groups,"+ldaptest.BaseDN)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Root.Match || res.InBase || res.Match {
		t.Errorf("root=%v inBase=%v match=%v; want the filter to match but the base to exclude her", res.Root.Match, res.InBase, res.Match)
	}
}

func TestExplainFillsDNAndGiteaPlaceholders(t *testing.T) {
	res, err := corp(t).Explain(context.Background(), "alice", "(|(sAMAccountName=%[1]s)(distinguishedName={dn}))", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Filter != "(|(sAMAccountName=alice)(distinguishedName="+ldap.EscapeFilter(ldaptest.AliceDN)+"))" || !res.Match {
		t.Errorf("filter=%s match=%v", res.Filter, res.Match)
	}
}

func TestExplainReportsUnknownAndAmbiguousNames(t *testing.T) {
	res, err := corp(t).Explain(context.Background(), "nobody", "(objectClass=*)", "")
	if err != nil || res.Status != NameNotFound || res.Root != nil {
		t.Errorf("nobody: %+v, %v", res, err)
	}
	cfg := ldaptest.CorpAD()
	cfg.Entries = append(cfg.Entries, ldaptest.NewEntry("CN=Alice Wong,OU=Users,"+ldaptest.BaseDN,
		"objectClass", "user", "objectClass", "person", "cn", "Alice Wong", "displayName", "alice"))
	res, err = newService(t, cfg, ldaptest.BaseDN, true).Explain(context.Background(), "alice", "(objectClass=*)", "")
	if err != nil || res.Status != NameAmbiguous || len(res.Matches) != 2 {
		t.Errorf("alice: %+v, %v", res, err)
	}
}

func TestExplainRefusesHugeFilters(t *testing.T) {
	f := "(|" + strings.Repeat("(cn=x)", maxExplainNodes) + ")"
	if _, err := corp(t).Explain(context.Background(), "alice", f, ""); !errors.Is(err, ErrFilterTooLarge) {
		t.Errorf("err = %v, want ErrFilterTooLarge", err)
	}
}

func TestDescribeCoversCommonComparisons(t *testing.T) {
	for filter, want := range map[string]string{
		"(cn=j*doe*)":                      "cn looks like j*doe*",
		"(cn=*admin)":                      "cn looks like *admin",
		"(lockoutTime>=1)":                 "lockoutTime is at least 1",
		"(memberOf=CN=Ops,OU=Groups,DC=x)": "Is directly in group Ops (memberOf)",
		"(userAccountControl:1.2.840.113556.1.4.803:=65536)": "userAccountControl has all of the flags DONT_EXPIRE_PASSWORD",
		"(userAccountControl:1.2.840.113556.1.4.804:=18)":    "userAccountControl has any of the flags ACCOUNTDISABLE, LOCKOUT",
		"(|(a=1)(b=2))": "Any of these",
	} {
		p, err := ldap.CompileFilter(filter)
		if err != nil {
			t.Fatal(err)
		}
		if got := describe(p); got != want {
			t.Errorf("describe(%s) = %q, want %q", filter, got, want)
		}
	}
}
