package directory

import (
	"context"
	"errors"
	"fmt"

	"slices"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// Membership is one group an account belongs to, or one member of a group.
type Membership struct {
	Object
	Direct  bool     `json:"direct"`
	Primary bool     `json:"primary,omitempty"` // via AD primaryGroupID, invisible to memberOf
	Via     []string `json:"via,omitempty"`     // intermediate group DNs, nearest to the subject first
}

// MembershipResult is the answer to GroupsOf or MembersOf.
type MembershipResult struct {
	Subject   Object       `json:"subject"`
	Items     []Membership `json:"items"`
	Truncated bool         `json:"truncated,omitempty"`
}

// Bounds on the LDAP work one request may cause, so a huge or pathological
// directory cannot hang a request or flood the DC. Variables so tests can lower them.
var (
	maxDepth       = 32
	maxMemberships = 20000 // items in one result, and entries per sub-search
	maxLookups     = 1000  // individual entry reads per resolve step
)

// GroupsOf returns every group dn belongs to: direct, nested (with the path
// that grants it), and — on AD — the primary group.
func (s *Service) GroupsOf(ctx context.Context, dn string) (MembershipResult, error) {
	e, err := s.dir.Entry(ctx, dn, slices.Concat(objectAttrs, []string{"primaryGroupID", "objectSid"})...)
	if err != nil {
		return MembershipResult{}, err
	}
	res := MembershipResult{Subject: toObject(e)}
	seen := map[string]bool{dnKey(dn): true}

	direct, truncated, err := s.parentGroups(ctx, e)
	if err != nil {
		return MembershipResult{}, err
	}
	res.Truncated = truncated
	if primary, ok, err := s.primaryGroup(ctx, e); err != nil {
		return MembershipResult{}, err
	} else if ok {
		direct = append(direct, primary)
	}

	type item struct {
		m     Membership
		entry *ldap.Entry
	}
	queue := make([]item, 0, len(direct))
	for _, g := range direct {
		if seen[dnKey(g.DN)] {
			continue
		}
		seen[dnKey(g.DN)] = true
		m := Membership{Object: toObject(g.Entry), Direct: true, Primary: g.primary}
		queue = append(queue, item{m, g.Entry})
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		res.Items = append(res.Items, cur.m)
		if len(res.Items) >= maxMemberships {
			res.Truncated = true
			break
		}
		if len(cur.m.Via) >= maxDepth {
			continue
		}
		if len(res.Items)+len(queue) >= maxMemberships {
			res.Truncated = true
			continue // budget spent: finish emitting what is queued, expand nothing more
		}
		parents, truncated, err := s.parentGroups(ctx, cur.entry)
		if err != nil {
			return MembershipResult{}, err
		}
		res.Truncated = res.Truncated || truncated
		for _, p := range parents {
			if seen[dnKey(p.DN)] {
				continue
			}
			seen[dnKey(p.DN)] = true
			via := append(append([]string{}, cur.m.Via...), cur.m.DN)
			queue = append(queue, item{Membership{Object: toObject(p.Entry), Via: via}, p.Entry})
		}
	}
	return res, nil
}

type groupEntry struct {
	*ldap.Entry
	primary bool
}

// parentGroups finds groups listing e as a member: by searching member,
// uniqueMember and memberUid (works without a memberOf overlay), plus any
// memberOf values the search missed (e.g. groups outside the search base).
func (s *Service) parentGroups(ctx context.Context, e *ldap.Entry) ([]groupEntry, bool, error) {
	dn := ldap.EscapeFilter(e.DN)
	clauses := "(member=" + dn + ")(uniqueMember=" + dn + ")"
	if uid := e.GetAttributeValue("uid"); uid != "" {
		clauses += "(memberUid=" + ldap.EscapeFilter(uid) + ")"
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{
		Base: s.base, Scope: ldap.ScopeWholeSubtree,
		Filter: "(&" + groupFilter + "(|" + clauses + "))", Attrs: objectAttrs, Limit: maxMemberships,
	})
	if err != nil {
		return nil, false, fmt.Errorf("groups containing %s: %w", e.DN, err)
	}
	truncated := res.Truncated
	found := map[string]bool{}
	out := make([]groupEntry, 0, len(res.Entries))
	for _, g := range res.Entries {
		found[dnKey(g.DN)] = true
		out = append(out, groupEntry{Entry: g})
	}
	lookups := 0
	for _, m := range e.GetAttributeValues("memberOf") {
		if found[dnKey(m)] {
			continue
		}
		if lookups >= maxLookups {
			truncated = true
			break
		}
		lookups++
		g, err := s.lookup(ctx, m)
		if err != nil {
			return nil, false, err
		}
		out = append(out, groupEntry{Entry: g})
	}
	return out, truncated, nil
}

// primaryGroup resolves an AD account's primaryGroupID to its group entry.
func (s *Service) primaryGroup(ctx context.Context, e *ldap.Entry) (groupEntry, bool, error) {
	rid := e.GetAttributeValue("primaryGroupID")
	raw := e.GetRawAttributeValue("objectSid")
	if !s.isAD || rid == "" || len(raw) == 0 {
		return groupEntry{}, false, nil
	}
	userSID, err := attr.ParseSID(raw)
	if err != nil {
		return groupEntry{}, false, fmt.Errorf("objectSid of %s: %w", e.DN, err)
	}
	groupSID, err := attr.PrimaryGroupSID(userSID, rid)
	if err != nil {
		return groupEntry{}, false, err
	}
	bin, err := attr.EncodeSID(groupSID)
	if err != nil {
		return groupEntry{}, false, err
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{
		Base: s.base, Scope: ldap.ScopeWholeSubtree,
		Filter: "(objectSid=" + attr.EscapeBinary(bin) + ")", Attrs: objectAttrs, Limit: 1,
	})
	if err != nil {
		return groupEntry{}, false, fmt.Errorf("primary group %s of %s: %w", groupSID, e.DN, err)
	}
	if len(res.Entries) == 0 {
		return groupEntry{}, false, nil
	}
	return groupEntry{Entry: res.Entries[0], primary: true}, true, nil
}

// lookup reads a referenced entry. When the reference cannot be read here —
// deleted, hidden from the bind DN, or held by another domain — it returns a
// placeholder instead of failing the whole request.
func (s *Service) lookup(ctx context.Context, dn string) (*ldap.Entry, error) {
	e, err := s.dir.Entry(ctx, dn, objectAttrs...)
	switch {
	case err == nil:
		return e, nil
	case errors.Is(err, ldapclient.ErrNotFound):
		return placeholder(dn, "not found (deleted, or not readable by the bind account)"), nil
	case errors.Is(err, ldapclient.ErrReferral):
		return placeholder(dn, "in another domain; not readable from this server"), nil
	}
	return nil, err
}

// placeholder is an entry with only a description, which toObject renders
// as KindUnknown.
func placeholder(dn, why string) *ldap.Entry {
	return &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{
		{Name: "description", Values: []string{why}, ByteValues: [][]byte{[]byte(why)}},
	}}
}
