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

// Bounds on graph walks, so a pathological directory cannot hang a request.
const (
	maxDepth       = 32
	maxMemberships = 20000
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

	direct, err := s.parentGroups(ctx, e)
	if err != nil {
		return MembershipResult{}, err
	}
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
		parents, err := s.parentGroups(ctx, cur.entry)
		if err != nil {
			return MembershipResult{}, err
		}
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
func (s *Service) parentGroups(ctx context.Context, e *ldap.Entry) ([]groupEntry, error) {
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
		return nil, fmt.Errorf("groups containing %s: %w", e.DN, err)
	}
	found := map[string]bool{}
	out := make([]groupEntry, 0, len(res.Entries))
	for _, g := range res.Entries {
		found[dnKey(g.DN)] = true
		out = append(out, groupEntry{Entry: g})
	}
	for _, m := range e.GetAttributeValues("memberOf") {
		if found[dnKey(m)] {
			continue
		}
		g, err := s.lookup(ctx, m)
		if err != nil {
			return nil, err
		}
		out = append(out, groupEntry{Entry: g})
	}
	return out, nil
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

// lookup reads a referenced entry, standing in a placeholder when the
// reference dangles (deleted object, or outside what the bind DN can read).
func (s *Service) lookup(ctx context.Context, dn string) (*ldap.Entry, error) {
	e, err := s.dir.Entry(ctx, dn, objectAttrs...)
	if err == nil {
		return e, nil
	}
	if errors.Is(err, ldapclient.ErrNotFound) {
		return &ldap.Entry{DN: dn}, nil
	}
	return nil, err
}
