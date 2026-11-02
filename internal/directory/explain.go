package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/attr"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// maxExplainNodes bounds the searches one explanation may run: one per node
// of the filter tree.
const maxExplainNodes = 64

// ErrFilterTooLarge is returned for filters with more than maxExplainNodes parts.
var ErrFilterTooLarge = fmt.Errorf("the filter has more than %d parts; explain a smaller piece of it", maxExplainNodes)

// Explanation says whether one account matches a filter, and why: every
// part of the filter with the server's own answer for that account.
type Explanation struct {
	Query   string     `json:"query"`
	Status  NameStatus `json:"status"`
	Matches []Object   `json:"matches,omitempty"` // the account, or the candidates when ambiguous

	Filter string        `json:"filter,omitempty"` // with placeholders filled in
	Base   string        `json:"base,omitempty"`
	InBase bool          `json:"inBase"`
	Match  bool          `json:"match"` // InBase and Root.Match: a search would return the account
	Root   *ExplainNode  `json:"root,omitempty"`
	Values []NamedValues `json:"-"` // the account's values of attributes the filter tests; the server renders them
}

// NamedValues is one attribute of the account, raw; the server renders it.
type NamedValues struct {
	Name   string   `json:"name"`
	Values [][]byte `json:"-"`
}

// ExplainNode is one part of the filter. Op is and, or, not, or test (a
// single comparison). Match is the server's answer for the account.
type ExplainNode struct {
	Op       string         `json:"op"`
	Filter   string         `json:"filter"`
	Say      string         `json:"say"`
	Attr     string         `json:"attr,omitempty"` // tests: the attribute compared
	Match    bool           `json:"match"`
	Hint     string         `json:"hint,omitempty"` // how to make a failed test match, when known
	Children []*ExplainNode `json:"children,omitempty"`
}

// Explain resolves who as GroupsOfMany does, fills the filter's
// placeholders for that account ({username}, %s, %[1]s, {dn}), and asks
// the server about every part of the filter with a base-scope search on
// the account. Each answer is the server's own, so AD matching rules and
// NOT over missing attributes come out as a real search would.
func (s *Service) Explain(ctx context.Context, who, filter, base string) (Explanation, error) {
	out := Explanation{Query: who, Base: s.baseOr(base)}
	matches, err := s.resolveNames(ctx, []string{who})
	if err != nil {
		return out, err
	}
	switch out.Matches = matches[0].objects; len(out.Matches) {
	case 0:
		out.Status = NameNotFound
		return out, nil
	case 1:
		out.Status = NameFound
	default:
		out.Status = NameAmbiguous
		return out, nil
	}
	account := out.Matches[0].DN

	// Read the account once for the login to fill in and the values to show.
	packet, err := ldap.CompileFilter(filter)
	if err != nil {
		return out, err
	}
	names := testedAttrs(packet)
	e, err := s.dir.Entry(ctx, account, slices.Concat(names, []string{"sAMAccountName", "uid"})...)
	if err != nil {
		return out, err
	}
	login := loginKey(who)
	if looksLikeDN(who) {
		login = firstNonEmpty(e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("uid"))
	}
	out.Filter = expandPlaceholders(filter, login, account)
	if packet, err = ldap.CompileFilter(out.Filter); err != nil {
		return out, err
	}
	if countNodes(packet) > maxExplainNodes {
		return out, ErrFilterTooLarge
	}
	for _, n := range names {
		if raw := e.GetRawAttributeValues(n); len(raw) > 0 {
			out.Values = append(out.Values, NamedValues{Name: n, Values: raw})
		}
	}

	out.InBase = within(account, out.Base)
	if out.Root, err = s.explainNode(ctx, account, packet); err != nil {
		return out, err
	}
	out.Match = out.InBase && out.Root.Match
	return out, nil
}

func (s *Service) explainNode(ctx context.Context, dn string, p *ber.Packet) (*ExplainNode, error) {
	text, err := ldap.DecompileFilter(p)
	if err != nil {
		return nil, err
	}
	n := &ExplainNode{Filter: text, Say: describe(p)}
	switch p.Tag {
	case ldap.FilterAnd:
		n.Op = "and"
	case ldap.FilterOr:
		n.Op = "or"
	case ldap.FilterNot:
		n.Op = "not"
	default:
		n.Op, n.Attr = "test", testedAttr(p)
	}
	if n.Op != "test" {
		for _, c := range p.Children {
			child, err := s.explainNode(ctx, dn, c)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
		}
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{Base: dn, Scope: ldap.ScopeBaseObject, Filter: text, Attrs: []string{"1.1"}, Limit: 1})
	if err != nil && !errors.Is(err, ldapclient.ErrNotFound) {
		return nil, fmt.Errorf("check %s: %w", text, err)
	}
	n.Match = err == nil && len(res.Entries) > 0
	if !n.Match {
		if n.Hint, err = s.nestedHint(ctx, dn, p); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// nestedHint explains the usual surprise with (memberOf=group) on AD: it
// sees direct members only. When the account is in the group through a
// sub-group, it says so and gives the condition that counts that too.
func (s *Service) nestedHint(ctx context.Context, dn string, p *ber.Packet) (string, error) {
	if !s.isAD || p.Tag != ldap.FilterEqualityMatch || !strings.EqualFold(p.Children[0].Data.String(), "memberOf") {
		return "", nil
	}
	group := p.Children[1].Data.String()
	chain := "(memberOf:" + ruleInChain + ":=" + ldap.EscapeFilter(group) + ")"
	res, err := s.dir.Search(ctx, ldapclient.Query{Base: dn, Scope: ldap.ScopeBaseObject, Filter: chain, Attrs: []string{"1.1"}, Limit: 1})
	if err != nil || len(res.Entries) == 0 {
		return "", nil // no hint is better than a failed explanation
	}
	return fmt.Sprintf("In %s through a sub-group, which memberOf alone does not count. To include sub-groups (LDAP_MATCHING_RULE_IN_CHAIN), use %s",
		rdnValue(group), chain), nil
}

// within reports whether dn is base or below it.
func within(dn, base string) bool {
	d, err1 := ldap.ParseDN(dn)
	b, err2 := ldap.ParseDN(base)
	return err1 == nil && err2 == nil && (d.EqualFold(b) || b.AncestorOfFold(d))
}

func countNodes(p *ber.Packet) int {
	n := 1
	if p.Tag == ldap.FilterAnd || p.Tag == ldap.FilterOr || p.Tag == ldap.FilterNot {
		for _, c := range p.Children {
			n += countNodes(c)
		}
	}
	return n
}

// testedAttrs lists the attributes the filter compares, once each.
func testedAttrs(p *ber.Packet) []string {
	var out []string
	var walk func(*ber.Packet)
	walk = func(p *ber.Packet) {
		switch p.Tag {
		case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
			for _, c := range p.Children {
				walk(c)
			}
		default:
			if a := testedAttr(p); a != "" && !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, a) }) {
				out = append(out, a)
			}
		}
	}
	walk(p)
	return out
}

// testedAttr is the attribute one comparison tests, without options.
func testedAttr(p *ber.Packet) string {
	var a string
	switch p.Tag {
	case ldap.FilterPresent:
		a = p.Data.String()
	case ldap.FilterExtensibleMatch:
		for _, c := range p.Children {
			if c.Tag == ldap.MatchingRuleAssertionType {
				a = c.Data.String()
			}
		}
	default:
		if len(p.Children) > 0 {
			a = p.Children[0].Data.String()
		}
	}
	a, _, _ = strings.Cut(a, ";")
	return a
}

const (
	ruleBitAnd  = "1.2.840.113556.1.4.803"
	ruleBitOr   = "1.2.840.113556.1.4.804"
	ruleInChain = "1.2.840.113556.1.4.1941"
)

// describe says what one part of a filter asks, in plain words with the
// original term in parentheses, as the UI's labels do.
func describe(p *ber.Packet) string {
	switch p.Tag {
	case ldap.FilterAnd:
		return "All of these"
	case ldap.FilterOr:
		return "Any of these"
	case ldap.FilterNot:
		if len(p.Children) == 1 {
			return "Not: " + lowerFirst(describe(p.Children[0]))
		}
		return "None of these"
	case ldap.FilterPresent:
		a := p.Data.String()
		if strings.EqualFold(a, "objectClass") {
			return "Is any entry (objectClass=*)"
		}
		return fmt.Sprintf("Has a %s value (%s=*)", a, a)
	case ldap.FilterSubstrings:
		a := p.Children[0].Data.String()
		var pattern strings.Builder
		parts := p.Children[1].Children
		for i, part := range parts {
			if i == 0 && part.Tag != ldap.FilterSubstringsInitial {
				pattern.WriteString("*")
			}
			pattern.WriteString(part.Data.String())
			if i < len(parts)-1 || part.Tag != ldap.FilterSubstringsFinal {
				pattern.WriteString("*")
			}
		}
		return fmt.Sprintf("%s looks like %s", a, pattern.String())
	case ldap.FilterGreaterOrEqual:
		return fmt.Sprintf("%s is at least %s", p.Children[0].Data.String(), p.Children[1].Data.String())
	case ldap.FilterLessOrEqual:
		return fmt.Sprintf("%s is at most %s", p.Children[0].Data.String(), p.Children[1].Data.String())
	case ldap.FilterApproxMatch:
		return fmt.Sprintf("%s sounds like %s", p.Children[0].Data.String(), p.Children[1].Data.String())
	case ldap.FilterEqualityMatch:
		return describeEquality(p.Children[0].Data.String(), p.Children[1].Data.String())
	case ldap.FilterExtensibleMatch:
		return describeExtensible(p)
	}
	return "A condition this console cannot describe"
}

func describeEquality(a, v string) string {
	switch strings.ToLower(a) {
	case "objectclass":
		return fmt.Sprintf("Is a %s entry (objectClass)", v)
	case "objectcategory":
		return fmt.Sprintf("Is a %s (objectCategory)", strings.ToLower(rdnValue(v)))
	case "memberof":
		return fmt.Sprintf("Is directly in group %s (memberOf)", rdnValue(v))
	case "member", "uniquemember":
		return fmt.Sprintf("Lists %s as a member (%s)", rdnValue(v), a)
	}
	return fmt.Sprintf("%s is %s", a, v)
}

func describeExtensible(p *ber.Packet) string {
	var rule, a, v string
	for _, c := range p.Children {
		switch c.Tag {
		case ldap.MatchingRuleAssertionMatchingRule:
			rule = c.Data.String()
		case ldap.MatchingRuleAssertionType:
			a = c.Data.String()
		case ldap.MatchingRuleAssertionMatchValue:
			v = c.Data.String()
		}
	}
	switch rule {
	case ruleInChain:
		if strings.EqualFold(a, "memberOf") {
			return fmt.Sprintf("Is in group %s, directly or through sub-groups (memberOf, LDAP_MATCHING_RULE_IN_CHAIN)", rdnValue(v))
		}
		return fmt.Sprintf("%s reaches %s through a chain of entries (LDAP_MATCHING_RULE_IN_CHAIN)", a, rdnValue(v))
	case ruleBitAnd, ruleBitOr:
		flags := v
		if strings.EqualFold(a, "userAccountControl") {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				if names := attr.UACFlags(uint32(n)); len(names) > 0 {
					flags = strings.Join(names, ", ")
				}
			}
		}
		if rule == ruleBitAnd {
			if strings.EqualFold(a, "userAccountControl") && v == "2" {
				return "The account is disabled (userAccountControl ACCOUNTDISABLE)"
			}
			return fmt.Sprintf("%s has all of the flags %s", a, flags)
		}
		return fmt.Sprintf("%s has any of the flags %s", a, flags)
	}
	return fmt.Sprintf("%s matches %s by rule %s", a, v, rule)
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
