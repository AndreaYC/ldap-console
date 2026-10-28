package directory

import (
	"context"
	"fmt"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/go-ldap/ldap/v3"
)

// giteaBadChars are refused in usernames by Gitea before any search.
const giteaBadChars = "\x00()*\\"

// checkGitea follows Gitea's "LDAP (via BindDN)" source: find the user with
// the filter, bind as them, read attributes, apply the admin and restricted
// filters to the user entry, then verify group membership.
func (s *Service) checkGitea(ctx context.Context, c LoginCheck, bind Binder) LoginReport {
	var user Step
	var entry *ldap.Entry
	if strings.ContainsAny(c.Username, giteaBadChars) {
		user = fail(Step{ID: "user", Title: "Find the user with the user filter"}, "Gitea refuses usernames containing ( ) * \\ or NUL")
	} else {
		user, entry = s.findGiteaUser(ctx, c)
	}
	return LoginReport{Steps: []Step{
		user,
		bindStep(ctx, entry, c.Password, bind),
		attributeStep(entry, c.EmailAttr, StatusWarn, "Gitea may refuse to create the account"),
		s.userFilterStep(ctx, entry, "admin", "Admin filter", c.AdminFilter, "is an admin", "is not an admin"),
		s.userFilterStep(ctx, entry, "restricted", "Restricted filter", c.RestrictedFilter, "is restricted", "is not restricted"),
		s.giteaGroups(ctx, entry, c),
	}}
}

// findGiteaUser fills the filter as Gitea does: fmt.Sprintf with the login
// name as its one argument, unescaped because the characters that would
// need escaping were refused above. So %[1]s may repeat but %s may not, and
// {username} is not substituted at all.
func (s *Service) findGiteaUser(ctx context.Context, c LoginCheck) (Step, *ldap.Entry) {
	st := Step{ID: "user", Title: "Find the user with the user filter", Base: s.baseOr(c.UserBase)}
	if !strings.Contains(c.UserFilter, "%") {
		return fail(st, "the user filter has no %[1]s, so Gitea finds the same entries for every login"), nil
	}
	filter := fmt.Sprintf(c.UserFilter, c.Username)
	if strings.Contains(filter, "%!") {
		st.Filter = filter
		return fail(st, "Gitea fills the filter with fmt.Sprintf and would send this broken filter; use %[1]s for every place the login name goes"), nil
	}
	return s.searchUser(ctx, st, filter, false, nonEmpty(c.EmailAttr, c.UserAttrInGroup)...)
}

// userFilterStep checks whether filter matches the user entry itself, as
// Gitea does for its admin and restricted filters.
func (s *Service) userFilterStep(ctx context.Context, user *ldap.Entry, id, title, filter, yes, no string) Step {
	st := Step{ID: id, Title: title}
	switch {
	case user == nil:
		return skipped(st, "needs exactly one user")
	case filter == "":
		return skipped(st, "no filter entered")
	}
	st.Base, st.Filter = user.DN, filter
	if _, err := ldap.CompileFilter(filter); err != nil {
		return fail(st, "not a valid LDAP filter: "+err.Error())
	}
	res, err := s.dir.Search(ctx, ldapclient.Query{Base: user.DN, Scope: ldap.ScopeBaseObject, Filter: filter, Attrs: []string{"1.1"}, Limit: 1})
	if err != nil {
		return fail(st, "search failed: "+err.Error())
	}
	st.Status, st.Message = StatusOK, "the user "+no
	if len(res.Entries) > 0 {
		st.Message = "the user " + yes
	}
	return st
}

func (s *Service) giteaGroups(ctx context.Context, user *ldap.Entry, c LoginCheck) Step {
	st := Step{ID: "groups", Title: "Verify group membership"}
	switch {
	case user == nil:
		return skipped(st, "needs exactly one user")
	case c.GroupBase == "" || c.GroupMemberAttr == "":
		return skipped(st, "group verification is off (no group search base or member attribute)")
	}
	uid := user.DN
	if c.UserAttrInGroup != "" {
		if uid = user.GetAttributeValue(c.UserAttrInGroup); uid == "" {
			return fail(st, fmt.Sprintf("the user has no %s, so Gitea cannot match it against %s", c.UserAttrInGroup, c.GroupMemberAttr))
		}
	}
	filter := fmt.Sprintf("(%s=%s)", c.GroupMemberAttr, ldap.EscapeFilter(uid))
	if c.GroupFilter != "" {
		filter = fmt.Sprintf("(&%s%s)", c.GroupFilter, filter)
	}
	st = s.searchGroups(ctx, st, c.GroupBase, filter)
	if st.Status == StatusWarn && c.GroupFilter != "" {
		st.Status, st.Message = StatusFail, "the user is in none of the groups the group filter allows, so Gitea will refuse the login"
	}
	return st
}

// checkOpenWebUI follows Open WebUI's LDAP login: it searches for
// (&(<username attribute>=<lower-cased login>)<additional filters>), takes
// the first entry, requires the mail attribute, then binds as the user.
// With group management on, group names are the CNs of the user's memberOf.
func (s *Service) checkOpenWebUI(ctx context.Context, c LoginCheck, bind Binder) LoginReport {
	st := Step{ID: "user", Title: "Find the user", Base: s.baseOr(c.UserBase)}
	var entry *ldap.Entry
	extra := strings.TrimSpace(c.SearchFilters)
	switch {
	case c.UsernameAttr == "":
		st = fail(st, "enter the username attribute (Open WebUI's default is uid; AD uses sAMAccountName)")
	case extra != "" && !strings.HasPrefix(extra, "("):
		st = fail(st, "additional search filters must be wrapped in parentheses, e.g. (objectClass=user)")
	default:
		filter := fmt.Sprintf("(&(%s=%s)%s)", c.UsernameAttr, ldap.EscapeFilter(strings.ToLower(c.Username)), extra)
		st, entry = s.searchUser(ctx, st, filter, true, nonEmpty(c.EmailAttr, c.GroupAttr)...)
	}
	attrs := attributeStep(entry, c.EmailAttr, StatusFail, "Open WebUI refuses the login")
	if attrs.Status == StatusFail {
		entry = nil // Open WebUI stops before the password check
	}
	return LoginReport{Steps: []Step{st, attrs, bindStep(ctx, entry, c.Password, bind), memberOfGroups(entry, c.GroupAttr)}}
}

// attributeStep reports the email attribute; missing gives status absent.
func attributeStep(user *ldap.Entry, emailAttr string, absent Status, consequence string) Step {
	st := Step{ID: "attributes", Title: "Read the email attribute"}
	switch {
	case user == nil:
		return skipped(st, "needs exactly one user")
	case emailAttr == "":
		return skipped(st, "no email attribute entered")
	}
	if v := user.GetAttributeValue(emailAttr); v != "" {
		st.Status, st.Message = StatusOK, emailAttr+" = "+v
		return st
	}
	st.Status, st.Message = absent, fmt.Sprintf("the user has no %s; %s", emailAttr, consequence)
	return st
}

func memberOfGroups(user *ldap.Entry, attr string) Step {
	st := Step{ID: "groups", Title: "Read the user's groups"}
	switch {
	case user == nil:
		return skipped(st, "needs the user")
	case attr == "":
		return skipped(st, "group management is off (no group attribute)")
	}
	for _, dn := range user.GetAttributeValues(attr) {
		st.Items = append(st.Items, Object{DN: dn, Name: rdnValue(dn), Kind: KindGroup})
	}
	if len(st.Items) == 0 {
		st.Status, st.Message = StatusWarn, "the user has no "+attr+" values"
		return st
	}
	st.Status, st.Message = StatusOK, fmt.Sprintf("%d groups; %s lists direct groups only, not nested ones or the AD primary group", len(st.Items), attr)
	return st
}

func nonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
