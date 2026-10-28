package directory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// App selects whose login procedure CheckLogin reproduces.
type App string

const (
	AppGeneric   App = "generic"
	AppGitea     App = "gitea"
	AppOpenWebUI App = "openwebui"
)

// LoginCheck holds an application's LDAP login settings plus a test login.
// Which fields matter depends on App; the others are ignored.
type LoginCheck struct {
	App      App    `json:"app"`
	Username string `json:"username"`
	Password string `json:"password"` // optional; used for one bind, never stored

	UserBase   string `json:"userBase"`
	UserFilter string `json:"userFilter"` // generic, Gitea: {username}, %s or %[1]s
	EmailAttr  string `json:"emailAttr"`  // Gitea, Open WebUI

	GroupBase   string `json:"groupBase"`   // generic, Gitea
	GroupFilter string `json:"groupFilter"` // generic: {username}/{dn}; Gitea: restricts groups

	// Gitea
	AdminFilter      string `json:"adminFilter"`
	RestrictedFilter string `json:"restrictedFilter"`
	GroupMemberAttr  string `json:"groupMemberAttr"` // group attribute listing members, e.g. member
	UserAttrInGroup  string `json:"userAttrInGroup"` // user attribute listed there; empty = DN

	// Open WebUI
	UsernameAttr  string `json:"usernameAttr"`
	SearchFilters string `json:"searchFilters"`
	GroupAttr     string `json:"groupAttr"` // user attribute holding group DNs, e.g. memberOf
}

// Status is a step's outcome.
type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

// Step is one stage of the login as the application performs it.
type Step struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Status    Status   `json:"status"`
	Message   string   `json:"message"`
	Filter    string   `json:"filter,omitempty"` // the filter actually sent
	Base      string   `json:"base,omitempty"`
	Items     []Object `json:"items,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// LoginReport lists the steps in the order the application runs them.
type LoginReport struct {
	Steps []Step `json:"steps"`
}

// Binder authenticates as dn on a connection of its own, never the
// console's shared one.
type Binder func(ctx context.Context, dn, password string) error

const maxGroupResults = 1000

// CheckLogin reproduces an application's LDAP login for c.Username and
// reports each step, so a misconfigured filter shows where it goes wrong.
func (s *Service) CheckLogin(ctx context.Context, c LoginCheck, bind Binder) LoginReport {
	switch c.App {
	case AppGitea:
		return s.checkGitea(ctx, c, bind)
	case AppOpenWebUI:
		return s.checkOpenWebUI(ctx, c, bind)
	}
	return s.checkGeneric(ctx, c, bind)
}

func (s *Service) checkGeneric(ctx context.Context, c LoginCheck, bind Binder) LoginReport {
	user, entry := s.findUser(ctx, c.UserBase, c.UserFilter, c.Username)
	steps := []Step{user, bindStep(ctx, entry, c.Password, bind)}
	g := Step{ID: "groups", Title: "Find the user's groups with the group filter"}
	switch {
	case entry == nil:
		g = skipped(g, "needs exactly one user")
	case c.GroupFilter == "":
		g = skipped(g, "no group filter entered")
	default:
		filter := expandPlaceholders(c.GroupFilter, c.Username, entry.DN)
		g = s.searchGroups(ctx, g, s.baseOr(c.GroupBase), filter)
		if g.Status == StatusOK && filter == c.GroupFilter {
			g.Status, g.Message = StatusWarn, g.Message+"; the filter has no {username} or {dn}, so every user gets these same groups"
		}
	}
	return LoginReport{Steps: append(steps, g)}
}

// findUser expands the username into filter and requires exactly one match.
// Extra attributes the caller needs are fetched with it.
func (s *Service) findUser(ctx context.Context, base, filter, username string, extra ...string) (Step, *ldap.Entry) {
	st := Step{ID: "user", Title: "Find the user with the user filter", Base: s.baseOr(base)}
	expanded := expandPlaceholders(filter, username, "")
	if expanded == filter {
		return fail(st, "the user filter has no {username} placeholder (or %s / %[1]s), so it finds the same entries for every login"), nil
	}
	return s.searchUser(ctx, st, expanded, false, extra...)
}

// searchUser requires exactly one match, unless firstWins: then, like Open
// WebUI, several matches log in as the first and only earn a warning.
func (s *Service) searchUser(ctx context.Context, st Step, filter string, firstWins bool, extra ...string) (Step, *ldap.Entry) {
	st.Filter = filter
	if _, err := ldap.CompileFilter(filter); err != nil {
		return fail(st, "the user filter is not a valid LDAP filter: "+err.Error()), nil
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{Base: st.Base, Scope: ldap.ScopeWholeSubtree, Filter: filter,
		Attrs: append(slices.Clone(objectAttrs), extra...), Limit: 10})
	if err != nil {
		return fail(st, "search failed: "+err.Error()), nil
	}
	for _, e := range res.Entries {
		st.Items = append(st.Items, toObject(e))
	}
	switch n := len(res.Entries); {
	case n == 0:
		return fail(st, "no entry matches; check the search base, the login attribute (sAMAccountName, userPrincipalName or uid) and the objectClass condition"), nil
	case (n > 1 || res.Truncated) && !firstWins:
		return fail(st, fmt.Sprintf("%d entries match; a login must match exactly one, so applications refuse it", n)), nil
	}
	st.Status, st.Message = StatusOK, "found "+res.Entries[0].DN
	if len(res.Entries) > 1 {
		st.Status, st.Message = StatusWarn, fmt.Sprintf("%d entries match; the application takes the first, %s", len(res.Entries), res.Entries[0].DN)
	}
	if st.Items[0].Disabled {
		st.Status, st.Message = StatusWarn, st.Message+", but the account is disabled, so AD will refuse its password"
	}
	return st, res.Entries[0]
}

func bindStep(ctx context.Context, user *ldap.Entry, password string, bind Binder) Step {
	st := Step{ID: "bind", Title: "Sign in as the user with the password"}
	switch {
	case user == nil:
		return skipped(st, "needs exactly one user")
	case password == "":
		return skipped(st, "no password entered")
	}
	if err := bind(ctx, user.DN, password); err != nil {
		return fail(st, err.Error())
	}
	st.Status, st.Message = StatusOK, "the server accepted the password"
	return st
}

func (s *Service) searchGroups(ctx context.Context, st Step, base, filter string) Step {
	st.Base, st.Filter = base, filter
	if _, err := ldap.CompileFilter(filter); err != nil {
		return fail(st, "the group filter is not a valid LDAP filter: "+err.Error())
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{Base: base, Scope: ldap.ScopeWholeSubtree, Filter: filter, Attrs: objectAttrs, Limit: maxGroupResults})
	if err != nil {
		return fail(st, "search failed: "+err.Error())
	}
	for _, e := range res.Entries {
		st.Items = append(st.Items, toObject(e))
	}
	st.Truncated = res.Truncated
	if len(st.Items) == 0 {
		st.Status, st.Message = StatusWarn, "no groups match; on AD, member holds full DNs, so compare it with {dn}"
		return st
	}
	st.Status, st.Message = StatusOK, fmt.Sprintf("%d groups", len(st.Items))
	return st
}

// expandPlaceholders substitutes the escaped username and user DN.
func expandPlaceholders(filter, username, dn string) string {
	u := ldap.EscapeFilter(username)
	return strings.NewReplacer("{username}", u, "%[1]s", u, "%s", u, "{dn}", ldap.EscapeFilter(dn)).Replace(filter)
}

func (s *Service) baseOr(base string) string {
	if strings.TrimSpace(base) == "" {
		return s.base
	}
	return base
}

func fail(st Step, msg string) Step {
	st.Status, st.Message = StatusFail, msg
	return st
}

func skipped(st Step, msg string) Step {
	st.Status, st.Message = StatusSkipped, msg
	return st
}
