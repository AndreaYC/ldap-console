package directory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// MaxBulkNames caps the names one bulk lookup may resolve: each costs a
// GroupsOf walk, and all of them share one request timeout.
const MaxBulkNames = 200

const (
	bulkConcurrency = 4
	// nameChunk bounds how many names go into one OR filter.
	nameChunk = 20
	// nameChunkLimit bounds the entries one chunk's search may return.
	nameChunkLimit = 1000
)

// NameStatus says how one bulk input resolved.
type NameStatus string

const (
	NameFound     NameStatus = "found"
	NameNotFound  NameStatus = "notFound"
	NameAmbiguous NameStatus = "ambiguous"
	NameError     NameStatus = "error"
)

// PersonGroups is one input name, the account it resolved to and that
// account's groups. Matches holds the account when found, or every
// candidate when ambiguous; Groups is set only when found.
type PersonGroups struct {
	Query     string       `json:"query"`
	Status    NameStatus   `json:"status"`
	Matches   []Object     `json:"matches,omitempty"`
	Groups    []Membership `json:"groups,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// BulkResult answers GroupsOfMany, one row per input name in input order.
type BulkResult struct {
	People []PersonGroups `json:"people"`
}

// nameAttrs are compared exactly (case-insensitively) with each input name.
var nameAttrs = []string{"sAMAccountName", "userPrincipalName", "mail", "uid", "cn", "displayName"}

// accountFilter limits name matches to accounts: AD users and computers,
// inetOrgPerson and posixAccount entries. Groups are never people.
const accountFilter = "(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=posixAccount))"

// GroupsOfMany resolves each name to one account and returns its groups as
// GroupsOf does. A name is a full DN, DOMAIN\login, or an exact
// sAMAccountName, userPrincipalName, mail, uid, cn or displayName. Names
// that match nothing or several accounts are reported, not guessed. Errors
// are recorded per name, so one unreadable account does not hide the rest.
func (s *Service) GroupsOfMany(ctx context.Context, names []string) (BulkResult, error) {
	if len(names) > MaxBulkNames {
		return BulkResult{}, fmt.Errorf("at most %d names per lookup", MaxBulkNames)
	}
	matches, err := s.resolveNames(ctx, names)
	if err != nil {
		return BulkResult{}, err
	}
	out := BulkResult{People: make([]PersonGroups, len(names))}
	sem := make(chan struct{}, bulkConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		p := &out.People[i]
		p.Query, p.Matches, p.Truncated = name, matches[i].objects, matches[i].truncated
		switch len(p.Matches) {
		case 0:
			p.Status = NameNotFound
			continue
		case 1:
		default:
			p.Status = NameAmbiguous
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			res, err := s.GroupsOf(ctx, p.Matches[0].DN)
			if err != nil {
				p.Status, p.Error = NameError, err.Error()
				return
			}
			p.Status, p.Matches, p.Groups = NameFound, []Object{res.Subject}, res.Items
			p.Truncated = p.Truncated || res.Truncated
		}()
	}
	wg.Wait()
	return out, nil
}

type nameMatches struct {
	objects   []Object
	truncated bool
}

// resolveNames returns the accounts matching each name, in input order.
func (s *Service) resolveNames(ctx context.Context, names []string) ([]nameMatches, error) {
	out := make([]nameMatches, len(names))
	var plain []int // indexes of names that are not DNs
	for i, name := range names {
		if !looksLikeDN(name) {
			plain = append(plain, i)
			continue
		}
		e, err := s.lookup(ctx, name)
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidDNSyntax) {
			continue // not a DN after all: reported as not found
		}
		if err != nil {
			return nil, err
		}
		if isAccount(e) { // a group's or OU's DN is not a person, as by name
			out[i].objects = []Object{toObject(e)}
		}
	}

	for chunk := range slices.Chunk(plain, nameChunk) {
		byKey := map[string][]int{} // lower-cased login -> indexes into names
		var f strings.Builder
		f.WriteString("(&" + accountFilter + "(|")
		for _, i := range chunk {
			key := loginKey(names[i])
			if _, dup := byKey[key]; !dup {
				v := ldap.EscapeFilter(key)
				for _, a := range nameAttrs {
					f.WriteString("(" + a + "=" + v + ")")
				}
			}
			byKey[key] = append(byKey[key], i)
		}
		f.WriteString("))")
		res, err := s.dir.Search(ctx, ldapclient.Query{
			Base: s.base, Scope: ldap.ScopeWholeSubtree, Filter: f.String(),
			Attrs: slices.Concat(objectAttrs, []string{"mail", "userPrincipalName"}), Limit: nameChunkLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("resolve names: %w", err)
		}
		for _, e := range res.Entries {
			hit := map[string]bool{}
			for _, a := range nameAttrs {
				for _, v := range e.GetAttributeValues(a) {
					hit[strings.ToLower(v)] = true
				}
			}
			for key, idxs := range byKey {
				if !hit[key] {
					continue
				}
				o := toObject(e)
				for _, i := range idxs {
					out[i].objects = append(out[i].objects, o)
				}
			}
		}
		if res.Truncated {
			for _, i := range chunk {
				out[i].truncated = true
			}
		}
	}
	return out, nil
}

// isAccount applies accountFilter to an entry read by DN.
func isAccount(e *ldap.Entry) bool {
	for _, c := range e.GetAttributeValues("objectClass") {
		switch strings.ToLower(c) {
		case "person", "inetorgperson", "posixaccount":
			return true
		}
	}
	return false
}

// loginKey is the value compared with the naming attributes: DOMAIN\login
// becomes login, and case is folded as LDAP's matching rules fold it.
func loginKey(name string) string {
	name = strings.TrimSpace(name)
	if _, login, ok := strings.Cut(name, `\`); ok && !strings.Contains(name, "=") {
		name = login
	}
	return strings.ToLower(name)
}

// looksLikeDN accepts "CN=Alice,OU=Users,..." but not a display name that
// happens to contain "=" without parsing as a DN.
func looksLikeDN(name string) bool {
	if !strings.Contains(name, "=") {
		return false
	}
	dn, err := ldap.ParseDN(name)
	return err == nil && len(dn.RDNs) > 0
}
