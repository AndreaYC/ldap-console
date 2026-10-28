package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

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

func dnParam(r *http.Request, name string) (string, error) {
	dn := strings.TrimSpace(r.URL.Query().Get(name))
	if dn == "" {
		return "", badRequest("%s is required", name)
	}
	if _, err := ldap.ParseDN(dn); err != nil || !strings.Contains(dn, "=") {
		return "", badRequest("%s is not a valid DN: %q", name, dn)
	}
	return dn, nil
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
