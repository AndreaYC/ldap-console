// Package ldaptest provides an in-process LDAP server backed by an in-memory
// directory, for exercising the real client over the wire in tests.
//
// It emulates the AD behaviours the console depends on: paged results,
// ranged retrieval of large multi-valued attributes, and refusing
// unauthenticated searches. It does not emulate AD's extensible matching
// rules (e.g. LDAP_MATCHING_RULE_IN_CHAIN).
package ldaptest

import (
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Entry is one directory object. Attribute names are matched case-insensitively.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// NewEntry builds an Entry from alternating name, value pairs; repeated
// names accumulate values.
func NewEntry(dn string, kv ...string) *Entry {
	e := &Entry{DN: dn, Attrs: map[string][]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		e.Attrs[kv[i]] = append(e.Attrs[kv[i]], kv[i+1])
	}
	return e
}

func (e *Entry) values(name string) []string {
	if strings.EqualFold(name, "distinguishedName") {
		return []string{e.DN}
	}
	for k, v := range e.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func (e *Entry) parsedDN() *ldap.DN {
	dn, err := ldap.ParseDN(e.DN)
	if err != nil {
		panic("ldaptest: invalid fixture DN " + e.DN + ": " + err.Error())
	}
	return dn
}

// inScope reports whether e is within base at the given LDAP scope.
func (e *Entry) inScope(base *ldap.DN, scope int) bool {
	dn := e.parsedDN()
	switch scope {
	case ldap.ScopeBaseObject:
		return dn.EqualFold(base)
	case ldap.ScopeSingleLevel:
		return len(dn.RDNs) == len(base.RDNs)+1 && base.AncestorOfFold(dn)
	default:
		return dn.EqualFold(base) || base.AncestorOfFold(dn)
	}
}

// selectAttrs returns the attributes to send for the requested list,
// splitting values larger than rangeLimit the way AD does.
func (e *Entry) selectAttrs(requested []string, rangeLimit int) map[string][]string {
	all := len(requested) == 0
	want := map[string]string{} // lower(name) -> range spec ("" when none)
	for _, r := range requested {
		if r == "*" {
			all = true
			continue
		}
		name, spec, _ := strings.Cut(r, ";range=")
		want[strings.ToLower(name)] = spec
	}
	out := map[string][]string{}
	for name, vals := range e.Attrs {
		spec, ok := want[strings.ToLower(name)]
		if !ok && !all {
			continue
		}
		if spec == "" && (rangeLimit <= 0 || len(vals) <= rangeLimit) {
			out[name] = vals
			continue
		}
		rangedName, slice := rangeSlice(name, vals, spec, rangeLimit)
		out[rangedName] = slice
	}
	return out
}

// rangeSlice serves one window of a ranged attribute: "low-*" or "low-high".
func rangeSlice(name string, vals []string, spec string, limit int) (string, []string) {
	low, high := 0, len(vals)
	if spec != "" {
		l, h, _ := strings.Cut(spec, "-")
		low, _ = strconv.Atoi(l)
		if n, err := strconv.Atoi(h); err == nil {
			high = min(high, n+1)
		}
	}
	low = min(low, len(vals))
	high = max(high, low)
	if limit > 0 {
		high = min(high, low+limit)
	}
	end := "*"
	if high < len(vals) {
		end = strconv.Itoa(high - 1)
	}
	return name + ";range=" + strconv.Itoa(low) + "-" + end, vals[low:high]
}
