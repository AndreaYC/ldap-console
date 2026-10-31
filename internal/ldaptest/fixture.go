package ldaptest

import (
	"strings"

	"github.com/AndreaYC/ldap-console/internal/attr"
)

// Fixture credentials and well-known DNs of the CorpAD directory.
const (
	BaseDN   = "DC=corp,DC=local"
	BindDN   = "CN=svc-ldap,OU=Service,DC=corp,DC=local"
	Password = "test-only-password"
	// AlicePassword lets tests bind as Alice, as an application would.
	AlicePassword = "alice-test-password"

	AliceDN       = "CN=Alice,OU=Users,DC=corp,DC=local"
	BobDN         = "CN=Bob,OU=Users,DC=corp,DC=local"
	CarolDN       = "CN=Carol,OU=Users,DC=corp,DC=local"
	EngineeringDN = "CN=Engineering,OU=Groups,DC=corp,DC=local"
	BackendDN     = "CN=Backend,OU=Groups,DC=corp,DC=local"
	AllStaffDN    = "CN=AllStaff,OU=Groups,DC=corp,DC=local"
	OpsDN         = "CN=Ops,OU=Groups,DC=corp,DC=local"
	DomainUsersDN = "CN=Domain Users,OU=Groups,DC=corp,DC=local"
	CycleADN      = "CN=CycleA,OU=Groups,DC=corp,DC=local"
	CycleBDN      = "CN=CycleB,OU=Groups,DC=corp,DC=local"
	WS01DN        = "CN=WS01,OU=Computers,DC=corp,DC=local"
)

const domainSID = "S-1-5-21-1-2-3"

// CorpAD returns an AD-shaped directory:
//
//	AllStaff ⊃ Engineering ⊃ Backend ⊃ Carol
//	AllStaff ⊃ Engineering ⊃ Alice
//	AllStaff ⊃ Ops ⊃ Bob (disabled)
//	Domain Users is Alice's and Bob's primary group (no member values)
//	CycleA ⊃ CycleB ⊃ CycleA, and CycleB ⊃ Alice
//
// memberOf is derived from member, as AD maintains it.
func CorpAD() Config {
	user := func(dn, sam, rid, uac string) *Entry {
		return NewEntry(dn,
			"objectClass", "top", "objectClass", "person", "objectClass", "organizationalPerson", "objectClass", "user",
			"objectCategory", "CN=Person,CN=Schema,CN=Configuration,"+BaseDN,
			"cn", cnOf(dn), "sAMAccountName", sam, "mail", sam+"@corp.local", "userAccountControl", uac,
			"primaryGroupID", "513", "objectSid", sidBytes(domainSID+"-"+rid))
	}
	group := func(dn, rid string, members ...string) *Entry {
		e := NewEntry(dn, "objectClass", "top", "objectClass", "group",
			"cn", cnOf(dn), "sAMAccountName", cnOf(dn), "groupType", "-2147483646",
			"objectSid", sidBytes(domainSID+"-"+rid))
		if len(members) > 0 {
			e.Attrs["member"] = members
		}
		return e
	}
	ou := func(dn string) *Entry {
		return NewEntry(dn, "objectClass", "top", "objectClass", "organizationalUnit", "ou", cnOf(dn))
	}

	entries := []*Entry{
		NewEntry(BaseDN, "objectClass", "top", "objectClass", "domain", "dc", "corp"),
		ou("OU=Users," + BaseDN), ou("OU=Groups," + BaseDN), ou("OU=Computers," + BaseDN), ou("OU=Service," + BaseDN),
		NewEntry(BindDN, "objectClass", "user", "cn", "svc-ldap"),
		user(AliceDN, "alice", "1101", "512"),
		user(BobDN, "bob", "1102", "514"),
		user(CarolDN, "carol", "1103", "66048"),
		group(EngineeringDN, "2001", AliceDN, BackendDN),
		group(BackendDN, "2002", CarolDN),
		group(AllStaffDN, "2003", EngineeringDN, OpsDN),
		group(OpsDN, "2004", BobDN),
		group(DomainUsersDN, "513"),
		group(CycleADN, "2005", CycleBDN),
		group(CycleBDN, "2006", CycleADN, AliceDN),
		NewEntry(WS01DN, "objectClass", "top", "objectClass", "user", "objectClass", "computer", "cn", "WS01"),
	}
	linkMemberOf(entries)

	root := NewEntry("",
		"namingContexts", BaseDN,
		"defaultNamingContext", BaseDN,
		"supportedCapabilities", "1.2.840.113556.1.4.800",
		"dnsHostName", "dc01.corp.local")

	return Config{BindDN: BindDN, Password: Password, Entries: entries, RootDSE: root,
		UserPasswords: map[string]string{AliceDN: AlicePassword}}
}

func linkMemberOf(entries []*Entry) {
	byDN := map[string]*Entry{}
	for _, e := range entries {
		byDN[strings.ToLower(e.DN)] = e
	}
	for _, g := range entries {
		for _, m := range g.Attrs["member"] {
			if target := byDN[strings.ToLower(m)]; target != nil {
				target.Attrs["memberOf"] = append(target.Attrs["memberOf"], g.DN)
			}
		}
	}
}

func cnOf(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	_, v, _ := strings.Cut(first, "=")
	return v
}

func sidBytes(s string) string {
	b, err := attr.EncodeSID(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
