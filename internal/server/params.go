package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

type badRequestError struct{ msg string }

func (e *badRequestError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &badRequestError{msg: fmt.Sprintf(format, args...)}
}

const maxSearchLimit = 10000

// attrNameRE accepts attribute descriptions (name or OID, options such as
// ;binary or ;range=0-*) and the special selectors * and +.
var attrNameRE = regexp.MustCompile(`^(\*|\+|[A-Za-z0-9][A-Za-z0-9.\-]*(;[A-Za-z0-9=\-*]+)*)$`)

var scopes = map[string]int{
	"base": ldap.ScopeBaseObject,
	"one":  ldap.ScopeSingleLevel,
	"sub":  ldap.ScopeWholeSubtree,
}

// attrTypeRE is an RDN attribute type: a name or a numeric OID.
var attrTypeRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)*)$`)

// validDN reports whether dn parses with a proper attribute type in every
// RDN. ldap.ParseDN alone accepts a pasted filter such as "(&(cn=x)...)".
func validDN(dn string) bool {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 {
		return false
	}
	for _, rdn := range parsed.RDNs {
		if len(rdn.Attributes) == 0 {
			return false
		}
		for _, a := range rdn.Attributes {
			if !attrTypeRE.MatchString(a.Type) {
				return false
			}
		}
	}
	return true
}

func dnParam(r *http.Request, name string) (string, error) {
	dn := strings.TrimSpace(r.URL.Query().Get(name))
	if dn == "" {
		return "", badRequest("%s is required", name)
	}
	if !validDN(dn) {
		return "", badRequest("%s is not a valid DN: %q", name, dn)
	}
	return dn, nil
}

const maxNameLen = 256

// bulkNames reads the repeated name parameter: trimmed, blanks dropped,
// duplicates (ignoring case) removed, order kept.
func bulkNames(r *http.Request) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, n := range r.URL.Query()["name"] {
		n = strings.TrimSpace(n)
		key := strings.ToLower(n)
		if n == "" || seen[key] {
			continue
		}
		seen[key] = true
		switch {
		case len(n) > maxNameLen:
			return nil, badRequest("name %.40q… is longer than %d characters", n, maxNameLen)
		case strings.HasPrefix(n, "("):
			return nil, badRequest("%q looks like a filter; enter login names, e-mail addresses or DNs", n)
		}
		out = append(out, n)
	}
	switch {
	case len(out) == 0:
		return nil, badRequest("enter at least one name")
	case len(out) > directory.MaxBulkNames:
		return nil, badRequest("%d names; look up at most %d at a time", len(out), directory.MaxBulkNames)
	}
	return out, nil
}

func parseSearch(r *http.Request, defaultBase string) (ldapclient.Query, error) {
	p := r.URL.Query()
	q := ldapclient.Query{Base: defaultBase, Scope: ldap.ScopeWholeSubtree, Limit: 1000}

	if p.Get("base") != "" {
		base, err := dnParam(r, "base")
		if err != nil {
			return q, err
		}
		q.Base = base
	}
	q.Filter = strings.TrimSpace(p.Get("filter"))
	if q.Filter == "" {
		q.Filter = "(objectClass=*)"
	}
	if _, err := ldap.CompileFilter(q.Filter); err != nil {
		return q, badRequest("invalid filter: %v", err)
	}
	if s := p.Get("scope"); s != "" {
		scope, ok := scopes[s]
		if !ok {
			return q, badRequest("scope must be base, one or sub")
		}
		q.Scope = scope
	}
	if s := p.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxSearchLimit {
			return q, badRequest("limit must be 1..%d", maxSearchLimit)
		}
		q.Limit = n
	}
	for _, a := range strings.Split(p.Get("attrs"), ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !attrNameRE.MatchString(a) {
			return q, badRequest("invalid attribute name %q", a)
		}
		q.Attrs = append(q.Attrs, a)
	}
	return q, nil
}
