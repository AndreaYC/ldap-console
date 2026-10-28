// Package directory answers the questions an administrator asks of a
// directory: what is under this node, which groups is this account in
// (directly, nested, or via its AD primary group), and who is in this group.
package directory

import (
	"context"
	"strconv"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// Searcher is the subset of ldapclient.Client the service needs.
type Searcher interface {
	Search(ctx context.Context, q ldapclient.Query) (ldapclient.Result, error)
	Entry(ctx context.Context, dn string, attrs ...string) (*ldap.Entry, error)
}

// Service resolves directory structure and group membership.
type Service struct {
	dir  Searcher
	base string
	isAD bool
}

// New returns a Service searching under base. isAD enables AD-only
// behaviour (memberOf-based member lookup, primary groups).
func New(dir Searcher, base string, isAD bool) *Service {
	return &Service{dir: dir, base: base, isAD: isAD}
}

// Kind classifies an entry by its objectClass.
type Kind string

const (
	KindUser      Kind = "user"
	KindGroup     Kind = "group"
	KindComputer  Kind = "computer"
	KindContact   Kind = "contact"
	KindForeign   Kind = "foreignSecurityPrincipal"
	KindContainer Kind = "container"
	KindOther     Kind = "other"
	KindUnknown   Kind = "unknown" // referenced DN that could not be read
)

// Object is the summary of an entry shown in lists.
type Object struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	Description string `json:"description,omitempty"`
	GroupType   string `json:"groupType,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	// Members is set only by Groups.
	Members *MemberCount `json:"members,omitempty"`
}

// MemberCount is a group's number of direct member values. More means the
// server sent only the first range of them (AD: 1500), so Count is a lower
// bound. Members through AD's primaryGroupID are never listed and not counted.
type MemberCount struct {
	Count int  `json:"count"`
	More  bool `json:"more,omitempty"`
}

// objectAttrs are fetched for every listed entry.
var objectAttrs = []string{
	"objectClass", "cn", "ou", "dc", "displayName", "sAMAccountName", "uid",
	"description", "groupType", "userAccountControl", "memberOf",
}

const groupFilter = "(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"

func toObject(e *ldap.Entry) Object {
	if len(e.GetAttributeValues("objectClass")) == 0 {
		o := unknownObject(e.DN)
		o.Description = e.GetAttributeValue("description")
		return o
	}
	o := Object{
		DN:          e.DN,
		Name:        firstNonEmpty(e.GetAttributeValue("displayName"), e.GetAttributeValue("cn"), e.GetAttributeValue("ou"), e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("uid"), rdnValue(e.DN)),
		Kind:        KindOf(e.GetAttributeValues("objectClass")),
		Description: e.GetAttributeValue("description"),
		GroupType:   attr.DescribeGroupType(e.GetAttributeValue("groupType")),
	}
	if uac, err := strconv.ParseUint(e.GetAttributeValue("userAccountControl"), 10, 32); err == nil {
		o.Disabled = uac&0x2 != 0
	}
	return o
}

func unknownObject(dn string) Object {
	return Object{DN: dn, Name: rdnValue(dn), Kind: KindUnknown}
}

// KindOf classifies an entry from its objectClass values.
func KindOf(classes []string) Kind {
	has := map[string]bool{}
	for _, c := range classes {
		has[strings.ToLower(c)] = true
	}
	switch {
	case has["computer"]:
		return KindComputer
	case has["group"] || has["groupofnames"] || has["groupofuniquenames"] || has["posixgroup"]:
		return KindGroup
	case has["foreignsecurityprincipal"]:
		return KindForeign
	case has["contact"]:
		return KindContact
	case has["user"] || has["person"] || has["inetorgperson"] || has["posixaccount"]:
		return KindUser
	case has["organizationalunit"] || has["container"] || has["domain"] || has["domaindns"] ||
		has["builtindomain"] || has["dcobject"] || has["organization"]:
		return KindContainer
	}
	return KindOther
}

func rdnValue(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return dn
	}
	return parsed.RDNs[0].Attributes[0].Value
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func dnKey(dn string) string {
	if parsed, err := ldap.ParseDN(dn); err == nil {
		return strings.ToLower(parsed.String())
	}
	return strings.ToLower(dn)
}
