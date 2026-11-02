package ldaptest

import (
	"bytes"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// AD extensible matching rules the fake understands.
const (
	ruleBitAnd  = "1.2.840.113556.1.4.803"  // LDAP_MATCHING_RULE_BIT_AND
	ruleBitOr   = "1.2.840.113556.1.4.804"  // LDAP_MATCHING_RULE_BIT_OR
	ruleInChain = "1.2.840.113556.1.4.1941" // LDAP_MATCHING_RULE_IN_CHAIN
)

// matcher evaluates compiled filters; entries resolves DN references for
// the in-chain rule.
type matcher struct {
	entries []*Entry
}

// match evaluates a compiled LDAP filter against e. It covers and/or/not,
// equality, presence, substrings and AD's bitwise and in-chain extensible
// matches; anything else (ordering, other rules) never matches, which is
// enough for a test double.
func (m matcher) match(p *ber.Packet, e *Entry) bool {
	switch p.Tag {
	case ldap.FilterAnd:
		for _, c := range p.Children {
			if !m.match(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range p.Children {
			if m.match(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(p.Children) == 1 && !m.match(p.Children[0], e)
	case ldap.FilterPresent:
		return len(e.values(p.Data.String())) > 0
	case ldap.FilterEqualityMatch:
		name, want := p.Children[0].Data.String(), p.Children[1].Data.Bytes()
		for _, v := range e.values(name) {
			if strings.EqualFold(name, "objectCategory") && !bytes.ContainsRune(want, '=') {
				// AD accepts a class's short name for its objectCategory DN: (objectCategory=person).
				v = cnOf(v)
			}
			if strings.EqualFold(name, "uniqueMember") {
				// uniqueMemberMatch: an assertion without the optional #'bits'B UID matches any UID.
				v, _, _ = strings.Cut(v, "#'")
			}
			if bytes.EqualFold([]byte(v), want) {
				return true
			}
		}
		return false
	case ldap.FilterSubstrings:
		for _, v := range e.values(p.Children[0].Data.String()) {
			if matchSubstrings(strings.ToLower(v), p.Children[1].Children) {
				return true
			}
		}
		return false
	case ldap.FilterExtensibleMatch:
		return m.extensible(p, e)
	}
	return false
}

func (m matcher) extensible(p *ber.Packet, e *Entry) bool {
	var rule, name, value string
	for _, c := range p.Children {
		switch c.Tag {
		case ldap.MatchingRuleAssertionMatchingRule:
			rule = c.Data.String()
		case ldap.MatchingRuleAssertionType:
			name = c.Data.String()
		case ldap.MatchingRuleAssertionMatchValue:
			value = c.Data.String()
		}
	}
	switch rule {
	case ruleBitAnd, ruleBitOr:
		want, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return false
		}
		for _, v := range e.values(name) {
			n, err := strconv.ParseInt(v, 10, 64) // AD sends flags as signed 32-bit
			if err != nil {
				continue
			}
			got := uint64(uint32(n))
			if (rule == ruleBitAnd && got&want == want) || (rule == ruleBitOr && got&want != 0) {
				return true
			}
		}
	case ruleInChain:
		return m.inChain(e, name, value)
	}
	return false
}

// inChain reports whether target is reachable from e by following the DN
// values of attribute name transitively, e.g. memberOf up through nested
// groups or member down through them.
func (m matcher) inChain(e *Entry, name, target string) bool {
	want, err := ldap.ParseDN(target)
	if err != nil {
		return false
	}
	seen := map[string]bool{}
	queue := []*Entry{e}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, v := range cur.values(name) {
			dn, err := ldap.ParseDN(v)
			if err != nil {
				continue
			}
			if dn.EqualFold(want) {
				return true
			}
			key := strings.ToLower(dn.String())
			if seen[key] {
				continue
			}
			seen[key] = true
			if next := m.byDN(dn); next != nil {
				queue = append(queue, next)
			}
		}
	}
	return false
}

func (m matcher) byDN(dn *ldap.DN) *Entry {
	for _, e := range m.entries {
		if e.parsedDN().EqualFold(dn) {
			return e
		}
	}
	return nil
}

func matchSubstrings(v string, parts []*ber.Packet) bool {
	for _, part := range parts {
		s := strings.ToLower(part.Data.String())
		switch part.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(v, s) {
				return false
			}
			v = v[len(s):]
		case ldap.FilterSubstringsAny:
			i := strings.Index(v, s)
			if i < 0 {
				return false
			}
			v = v[i+len(s):]
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(v, s) {
				return false
			}
		}
	}
	return true
}
