package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

func TestExplainRendersTheAccountsValues(t *testing.T) {
	filter := "(&(memberOf=" + ldaptest.OpsDN + ")(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	got := decode[explainResponse](t, get(t, newTestHandler(t), "/api/explain", "who", "bob", "filter", filter), http.StatusOK)
	if got.Match || got.Root == nil || len(got.Root.Children) != 2 || !got.Root.Children[0].Match || got.Root.Children[1].Match {
		t.Fatalf("explanation = %+v", got)
	}
	byName := map[string]attribute{}
	for _, a := range got.Values {
		byName[strings.ToLower(a.Name)] = a
	}
	if n := byName["useraccountcontrol"].Values; len(n) != 1 || !strings.Contains(n[0].Note, "ACCOUNTDISABLE") {
		t.Errorf("userAccountControl = %+v", n)
	}
	if m := byName["memberof"].Values; len(m) != 1 || !m[0].DN {
		t.Errorf("memberOf = %+v, want one DN value", m)
	}
}

func TestExplainRejectsBadInput(t *testing.T) {
	h := newTestHandler(t)
	for name, params := range map[string][]string{
		"no who":     {"filter", "(cn=x)"},
		"who filter": {"who", "(cn=x)", "filter", "(cn=x)"},
		"no filter":  {"who", "bob"},
		"bad filter": {"who", "bob", "filter", "(cn=x"},
		"bad base":   {"who", "bob", "filter", "(cn=x)", "base", "(cn=x)"},
		"too large":  {"who", "bob", "filter", "(|" + strings.Repeat("(cn=x)", 70) + ")"},
	} {
		t.Run(name, func(t *testing.T) {
			decode[errorResponse](t, get(t, h, "/api/explain", params...), http.StatusBadRequest)
		})
	}
}
