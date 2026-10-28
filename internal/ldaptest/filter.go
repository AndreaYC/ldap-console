package ldaptest

import (
	"bytes"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// match evaluates a compiled LDAP filter against e. It covers and/or/not,
// equality, presence and substrings; anything else (extensible match,
// ordering) never matches, which is enough for a test double.
func match(p *ber.Packet, e *Entry) bool {
	switch p.Tag {
	case ldap.FilterAnd:
		for _, c := range p.Children {
			if !match(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range p.Children {
			if match(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(p.Children) == 1 && !match(p.Children[0], e)
	case ldap.FilterPresent:
		return len(e.values(p.Data.String())) > 0
	case ldap.FilterEqualityMatch:
		name, want := p.Children[0].Data.String(), p.Children[1].Data.Bytes()
		for _, v := range e.values(name) {
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
	}
	return false
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
