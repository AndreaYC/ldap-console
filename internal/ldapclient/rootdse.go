package ldapclient

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-ldap/ldap/v3"
)

// adCapabilityOID is LDAP_CAP_ACTIVE_DIRECTORY_OID, advertised by every AD DC.
const adCapabilityOID = "1.2.840.113556.1.4.800"

// RootDSE summarises what the server advertises about itself.
type RootDSE struct {
	NamingContexts       []string
	DefaultNamingContext string
	Vendor               string
	IsAD                 bool
	Entry                *ldap.Entry
}

// RootDSE reads the server's root DSE.
func (c *Client) RootDSE(ctx context.Context) (RootDSE, error) {
	res, err := c.Search(ctx, Query{Base: "", Scope: ldap.ScopeBaseObject, Filter: "(objectClass=*)", Attrs: []string{"*", "+"}, Limit: 1})
	if err != nil {
		return RootDSE{}, fmt.Errorf("read root DSE: %w", err)
	}
	if len(res.Entries) == 0 {
		return RootDSE{}, fmt.Errorf("read root DSE: server returned no entry")
	}
	e := res.Entries[0]
	r := RootDSE{
		NamingContexts:       e.GetAttributeValues("namingContexts"),
		DefaultNamingContext: e.GetAttributeValue("defaultNamingContext"),
		Vendor:               e.GetAttributeValue("vendorName"),
		IsAD:                 slices.Contains(e.GetAttributeValues("supportedCapabilities"), adCapabilityOID),
		Entry:                e,
	}
	if r.DefaultNamingContext == "" && len(r.NamingContexts) > 0 {
		r.DefaultNamingContext = r.NamingContexts[0]
	}
	if r.IsAD && r.Vendor == "" {
		r.Vendor = "Microsoft Active Directory"
	}
	return r, nil
}
