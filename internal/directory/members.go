package directory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// lookupConcurrency bounds parallel per-DN reads when resolving members.
const lookupConcurrency = 8

// memberUIDChunk bounds how many uids go into one OR filter.
const memberUIDChunk = 50

// MembersOf lists the members of group dn. With nested, members of member
// groups are included too, each with the chain of groups that brings it in.
func (s *Service) MembersOf(ctx context.Context, dn string, nested bool) (MembershipResult, error) {
	e, err := s.dir.Entry(ctx, dn, slices.Concat(objectAttrs, []string{"member", "uniqueMember", "memberUid", "objectSid"})...)
	if err != nil {
		return MembershipResult{}, err
	}
	res := MembershipResult{Subject: toObject(e)}
	seen := map[string]bool{dnKey(dn): true}

	type item struct {
		m     Membership
		group *ldap.Entry
	}
	var queue []item
	enqueue := func(members []Membership, via []string) {
		for _, m := range members {
			if seen[dnKey(m.DN)] {
				continue
			}
			seen[dnKey(m.DN)] = true
			m.Via, m.Direct = via, len(via) == 0
			queue = append(queue, item{m: m})
		}
	}

	direct, err := s.directMembers(ctx, e)
	if err != nil {
		return MembershipResult{}, err
	}
	enqueue(direct, nil)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		res.Items = append(res.Items, cur.m)
		if len(res.Items) >= maxMemberships {
			res.Truncated = true
			break
		}
		if !nested || cur.m.Kind != KindGroup || len(cur.m.Via) >= maxDepth {
			continue
		}
		g, err := s.dir.Entry(ctx, cur.m.DN, slices.Concat(objectAttrs, []string{"member", "uniqueMember", "memberUid", "objectSid"})...)
		if err != nil {
			return MembershipResult{}, err
		}
		sub, err := s.directMembers(ctx, g)
		if err != nil {
			return MembershipResult{}, err
		}
		enqueue(sub, append(slices.Clone(cur.m.Via), cur.m.DN))
	}
	return res, nil
}

// directMembers resolves a group's member, uniqueMember and memberUid
// values, plus AD primary-group members, to Objects.
func (s *Service) directMembers(ctx context.Context, g *ldap.Entry) ([]Membership, error) {
	dns := slices.Clone(g.GetAttributeValues("member"))
	for _, um := range g.GetAttributeValues("uniqueMember") {
		dn, _, _ := strings.Cut(um, "#'") // strip optional UID: dn#'0101'B
		dns = append(dns, dn)
	}
	objs, err := s.resolveDNs(ctx, g.DN, dns)
	if err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(objs))
	for _, o := range objs {
		out = append(out, Membership{Object: o})
	}

	byUID, err := s.resolveUIDs(ctx, g.GetAttributeValues("memberUid"))
	if err != nil {
		return nil, err
	}
	for _, o := range byUID {
		out = append(out, Membership{Object: o})
	}

	primary, err := s.primaryMembers(ctx, g)
	if err != nil {
		return nil, err
	}
	for _, o := range primary {
		out = append(out, Membership{Object: o, Primary: true})
	}
	return out, nil
}

// resolveDNs returns an Object per DN, in input order. On AD one
// (memberOf=group) search covers nearly all of them; the rest, and every DN
// on other servers, are read individually.
func (s *Service) resolveDNs(ctx context.Context, groupDN string, dns []string) ([]Object, error) {
	known := map[string]Object{}
	if s.isAD && len(dns) > 0 {
		res, err := s.dir.Search(ctx, ldapclient.Query{
			Base: s.base, Scope: ldap.ScopeWholeSubtree,
			Filter: "(memberOf=" + ldap.EscapeFilter(groupDN) + ")", Attrs: objectAttrs, Limit: maxMemberships,
		})
		if err != nil {
			return nil, fmt.Errorf("members of %s: %w", groupDN, err)
		}
		for _, e := range res.Entries {
			known[dnKey(e.DN)] = toObject(e)
		}
	}
	var missing []string
	for _, dn := range dns {
		if _, ok := known[dnKey(dn)]; !ok {
			missing = append(missing, dn)
		}
	}
	looked, err := s.lookupMany(ctx, missing)
	if err != nil {
		return nil, err
	}
	for i, dn := range missing {
		known[dnKey(dn)] = looked[i]
	}
	out := make([]Object, len(dns))
	for i, dn := range dns {
		out[i] = known[dnKey(dn)]
	}
	return out, nil
}

func (s *Service) lookupMany(ctx context.Context, dns []string) ([]Object, error) {
	out := make([]Object, len(dns))
	errs := make([]error, len(dns))
	sem := make(chan struct{}, lookupConcurrency)
	var wg sync.WaitGroup
	for i, dn := range dns {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			e, err := s.lookup(ctx, dn)
			if err != nil {
				errs[i] = err
				return
			}
			out[i] = toObject(e)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// resolveUIDs maps posixGroup memberUid values to accounts.
func (s *Service) resolveUIDs(ctx context.Context, uids []string) ([]Object, error) {
	var out []Object
	for chunk := range slices.Chunk(uids, memberUIDChunk) {
		var f strings.Builder
		f.WriteString("(&(uid=*)(|")
		for _, u := range chunk {
			f.WriteString("(uid=" + ldap.EscapeFilter(u) + ")")
		}
		f.WriteString("))")
		res, err := s.dir.Search(ctx, ldapclient.Query{Base: s.base, Scope: ldap.ScopeWholeSubtree, Filter: f.String(), Attrs: objectAttrs})
		if err != nil {
			return nil, fmt.Errorf("resolve memberUid: %w", err)
		}
		for _, e := range res.Entries {
			out = append(out, toObject(e))
		}
	}
	return out, nil
}

// primaryMembers finds AD accounts whose primaryGroupID is this group's RID.
// AD never lists these in the group's member attribute.
func (s *Service) primaryMembers(ctx context.Context, g *ldap.Entry) ([]Object, error) {
	raw := g.GetRawAttributeValue("objectSid")
	if !s.isAD || len(raw) == 0 {
		return nil, nil
	}
	sid, err := attr.ParseSID(raw)
	if err != nil {
		return nil, fmt.Errorf("objectSid of %s: %w", g.DN, err)
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{
		Base: s.base, Scope: ldap.ScopeWholeSubtree,
		Filter: "(primaryGroupID=" + ldap.EscapeFilter(attr.RID(sid)) + ")", Attrs: objectAttrs, Limit: maxMemberships,
	})
	if err != nil {
		return nil, fmt.Errorf("primary-group members of %s: %w", g.DN, err)
	}
	out := make([]Object, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, toObject(e))
	}
	return out, nil
}
