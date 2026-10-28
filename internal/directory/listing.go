package directory

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// ListResult is a list of objects; Truncated means a size cap was hit.
type ListResult struct {
	Items     []Object `json:"items"`
	Truncated bool     `json:"truncated,omitempty"`
}

const (
	childrenLimit = 2000
	findLimit     = 200
	groupsLimit   = 10000
)

// Children lists the immediate children of dn, containers first, then by name.
func (s *Service) Children(ctx context.Context, dn string) (ListResult, error) {
	res, err := s.dir.Search(ctx, ldapclient.Query{
		Base: dn, Scope: ldap.ScopeSingleLevel, Filter: "(objectClass=*)", Attrs: objectAttrs, Limit: childrenLimit,
	})
	if err != nil {
		return ListResult{}, err
	}
	out := toList(res)
	slices.SortFunc(out.Items, func(a, b Object) int {
		if ac, bc := a.Kind == KindContainer, b.Kind == KindContainer; ac != bc {
			if ac {
				return -1
			}
			return 1
		}
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out, nil
}

// Find does a substring match of q against the usual naming attributes.
func (s *Service) Find(ctx context.Context, q string) (ListResult, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return ListResult{}, fmt.Errorf("empty query")
	}
	v := ldap.EscapeFilter(q)
	var f strings.Builder
	f.WriteString("(|")
	for _, a := range []string{"cn", "sAMAccountName", "displayName", "mail", "uid", "userPrincipalName"} {
		f.WriteString("(" + a + "=*" + v + "*)")
	}
	f.WriteString(")")
	res, err := s.dir.Search(ctx, ldapclient.Query{
		Base: s.base, Scope: ldap.ScopeWholeSubtree, Filter: f.String(), Attrs: objectAttrs, Limit: findLimit,
	})
	if err != nil {
		return ListResult{}, err
	}
	return sortedByName(toList(res)), nil
}

// Groups lists every group under base (the service base when empty).
func (s *Service) Groups(ctx context.Context, base string) (ListResult, error) {
	if base == "" {
		base = s.base
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{
		Base: base, Scope: ldap.ScopeWholeSubtree, Filter: groupFilter, Attrs: objectAttrs, Limit: groupsLimit,
	})
	if err != nil {
		return ListResult{}, err
	}
	return sortedByName(toList(res)), nil
}

func toList(res ldapclient.Result) ListResult {
	out := ListResult{Items: make([]Object, 0, len(res.Entries)), Truncated: res.Truncated}
	for _, e := range res.Entries {
		out.Items = append(out.Items, toObject(e))
	}
	return out
}

func sortedByName(l ListResult) ListResult {
	slices.SortFunc(l.Items, func(a, b Object) int {
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return l
}
