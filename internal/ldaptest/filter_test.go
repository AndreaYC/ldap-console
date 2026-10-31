package ldaptest

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestMatcherSupportsADExtensibleRules(t *testing.T) {
	cfg := CorpAD()
	m := matcher{entries: cfg.Entries}
	byDN := map[string]*Entry{}
	for _, e := range cfg.Entries {
		byDN[e.DN] = e
	}
	cases := []struct {
		filter string
		dn     string
		want   bool
	}{
		{"(userAccountControl:1.2.840.113556.1.4.803:=2)", BobDN, true},    // 514 has ACCOUNTDISABLE
		{"(userAccountControl:1.2.840.113556.1.4.803:=2)", AliceDN, false}, // 512
		{"(userAccountControl:1.2.840.113556.1.4.803:=65538)", CarolDN, false},
		{"(userAccountControl:1.2.840.113556.1.4.804:=65538)", CarolDN, true}, // 66048 has DONT_EXPIRE_PASSWORD
		{"(groupType:1.2.840.113556.1.4.803:=2147483648)", OpsDN, true},       // negative value, security bit
		{"(memberOf:1.2.840.113556.1.4.1941:=" + AllStaffDN + ")", CarolDN, true},
		{"(memberOf:1.2.840.113556.1.4.1941:=" + OpsDN + ")", CarolDN, false},
		{"(memberOf:1.2.840.113556.1.4.1941:=" + CycleADN + ")", AliceDN, true}, // through a cycle, terminates
		{"(member:1.2.840.113556.1.4.1941:=" + CarolDN + ")", AllStaffDN, true},
		{"(memberOf:1.2.840.113556.1.4.1941:=" + AllStaffDN + ")", BobDN, true},
		{"(memberOf=" + AllStaffDN + ")", CarolDN, false}, // plain equality stays direct-only
		{"(&(objectCategory=person)(objectClass=user))", AliceDN, true},
		{"(objectCategory=CN=Person,CN=Schema,CN=Configuration," + BaseDN + ")", AliceDN, true},
		{"(objectCategory=person)", WS01DN, false},
	}
	for _, c := range cases {
		p, err := ldap.CompileFilter(c.filter)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.match(p, byDN[c.dn]); got != c.want {
			t.Errorf("%s on %s = %v, want %v", c.filter, c.dn, got, c.want)
		}
	}
}
