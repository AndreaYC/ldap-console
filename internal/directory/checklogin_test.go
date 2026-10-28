package directory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

const adUserFilter = "(&(objectClass=user)(sAMAccountName={username}))"

type bindCall struct{ dn, password string }

// recordingBinder accepts password "right" and records every call.
func recordingBinder(calls *[]bindCall) Binder {
	return func(_ context.Context, dn, password string) error {
		*calls = append(*calls, bindCall{dn, password})
		if password != "right" {
			return errors.New("invalid credentials")
		}
		return nil
	}
}

func checkLogin(t *testing.T, c LoginCheck) (LoginReport, []bindCall) {
	t.Helper()
	var calls []bindCall
	r := newService(t, ldaptest.CorpAD(), ldaptest.BaseDN, true).CheckLogin(context.Background(), c, recordingBinder(&calls))
	return r, calls
}

func step(t *testing.T, r LoginReport, id string) Step {
	t.Helper()
	for _, s := range r.Steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no %q step in %+v", id, r.Steps)
	return Step{}
}

func names(items []Object) []string {
	var out []string
	for _, o := range items {
		out = append(out, o.Name)
	}
	slices.Sort(out)
	return out
}

// --- generic ---

func TestGenericCheckFindsUserBindsAndListsGroups(t *testing.T) {
	r, calls := checkLogin(t, LoginCheck{App: AppGeneric, Username: "alice", Password: "right",
		UserFilter: adUserFilter, GroupFilter: "(&(objectClass=group)(member={dn}))"})
	user := step(t, r, "user")
	if user.Status != StatusOK || len(user.Items) != 1 || user.Items[0].DN != ldaptest.AliceDN {
		t.Fatalf("user step = %+v", user)
	}
	if user.Filter != "(&(objectClass=user)(sAMAccountName=alice))" {
		t.Errorf("filter sent = %q", user.Filter)
	}
	if b := step(t, r, "bind"); b.Status != StatusOK || !slices.Equal(calls, []bindCall{{ldaptest.AliceDN, "right"}}) {
		t.Errorf("bind step = %+v, calls = %v", b, calls)
	}
	if g := step(t, r, "groups"); g.Status != StatusOK || !slices.Equal(names(g.Items), []string{"CycleB", "Engineering"}) {
		t.Errorf("groups step = %s %v", g.Status, names(g.Items))
	}
}

func TestCheckReportsWrongPassword(t *testing.T) {
	r, _ := checkLogin(t, LoginCheck{App: AppGeneric, Username: "alice", Password: "wrong", UserFilter: adUserFilter})
	if b := step(t, r, "bind"); b.Status != StatusFail || !strings.Contains(b.Message, "invalid credentials") {
		t.Errorf("bind step = %+v", b)
	}
}

func TestCheckSkipsBindWithoutPassword(t *testing.T) {
	r, calls := checkLogin(t, LoginCheck{App: AppGeneric, Username: "alice", UserFilter: adUserFilter})
	if b := step(t, r, "bind"); b.Status != StatusSkipped || len(calls) != 0 {
		t.Errorf("bind step = %+v, calls = %v", b, calls)
	}
	if g := step(t, r, "groups"); g.Status != StatusSkipped {
		t.Errorf("groups step = %+v, want skipped without a group filter", g)
	}
}

func TestGenericCheckFailsUnlessFilterMatchesExactlyOneUser(t *testing.T) {
	tests := []struct {
		name, username, filter, want string
	}{
		{"no match", "nobody", adUserFilter, "no entry"},
		{"several matches", "alice", "(|(sAMAccountName={username})(objectClass=user))", "entries match"},
		{"no placeholder", "alice", "(sAMAccountName=alice)", "{username}"},
		{"syntax error", "alice", "(sAMAccountName={username}", "filter"},
		{"wildcard is escaped", "*", adUserFilter, "no entry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, calls := checkLogin(t, LoginCheck{App: AppGeneric, Username: tt.username, Password: "right", UserFilter: tt.filter})
			if u := step(t, r, "user"); u.Status != StatusFail || !strings.Contains(u.Message, tt.want) {
				t.Errorf("user step = %+v, want fail containing %q", u, tt.want)
			}
			if b := step(t, r, "bind"); b.Status != StatusSkipped || len(calls) != 0 {
				t.Errorf("bound without a single user: %+v %v", b, calls)
			}
		})
	}
}

func TestCheckAcceptsOtherPlaceholderStyles(t *testing.T) {
	for _, f := range []string{"(sAMAccountName=%s)", "(sAMAccountName=%[1]s)"} {
		r, _ := checkLogin(t, LoginCheck{App: AppGeneric, Username: "alice", UserFilter: f})
		if u := step(t, r, "user"); u.Status != StatusOK {
			t.Errorf("%s: %+v", f, u)
		}
	}
}

func TestCheckWarnsOnDisabledUserAndEmptyGroups(t *testing.T) {
	r, _ := checkLogin(t, LoginCheck{App: AppGeneric, Username: "bob", UserFilter: adUserFilter, GroupFilter: "(&(objectClass=group)(member=CN=nobody))"})
	if u := step(t, r, "user"); u.Status != StatusWarn || !strings.Contains(u.Message, "disabled") {
		t.Errorf("user step = %+v", u)
	}
	if g := step(t, r, "groups"); g.Status != StatusWarn {
		t.Errorf("groups step = %+v, want warn for no groups", g)
	}
}

// --- Gitea ---

func giteaCheck() LoginCheck {
	return LoginCheck{App: AppGitea, Username: "alice", Password: "right",
		UserBase: "OU=Users," + ldaptest.BaseDN, UserFilter: "(&(objectClass=user)(sAMAccountName=%[1]s))",
		EmailAttr: "mail", GroupBase: "OU=Groups," + ldaptest.BaseDN, GroupMemberAttr: "member"}
}

func TestGiteaCheckMirrorsGiteaLogin(t *testing.T) {
	c := giteaCheck()
	c.AdminFilter = "(memberOf=" + ldaptest.EngineeringDN + ")"
	c.RestrictedFilter = "(memberOf=" + ldaptest.OpsDN + ")"
	r, _ := checkLogin(t, c)
	if a := step(t, r, "attributes"); a.Status != StatusOK || !strings.Contains(a.Message, "alice@corp.local") {
		t.Errorf("attributes step = %+v", a)
	}
	if a := step(t, r, "admin"); a.Status != StatusOK || !strings.Contains(a.Message, "is an admin") {
		t.Errorf("admin step = %+v", a)
	}
	if rs := step(t, r, "restricted"); rs.Status != StatusOK || !strings.Contains(rs.Message, "not restricted") {
		t.Errorf("restricted step = %+v", rs)
	}
	g := step(t, r, "groups")
	if g.Status != StatusOK || !slices.Equal(names(g.Items), []string{"CycleB", "Engineering"}) {
		t.Errorf("groups step = %s %v", g.Status, names(g.Items))
	}
	if g.Filter != "(member="+ldaptest.AliceDN+")" {
		t.Errorf("group filter sent = %q", g.Filter)
	}
}

func TestGiteaRefusesLoginOutsideFilteredGroups(t *testing.T) {
	c := giteaCheck()
	c.GroupFilter = "(cn=Ops)"
	r, _ := checkLogin(t, c)
	if g := step(t, r, "groups"); g.Status != StatusFail || !strings.Contains(g.Message, "refuse") {
		t.Errorf("groups step = %+v", g)
	}
	c.GroupFilter = "(cn=Engineering)"
	r, _ = checkLogin(t, c)
	if g := step(t, r, "groups"); g.Status != StatusOK || !slices.Equal(names(g.Items), []string{"Engineering"}) {
		t.Errorf("groups step = %s %v", g.Status, names(g.Items))
	}
}

func TestGiteaMatchesGroupsByUserAttribute(t *testing.T) {
	c := giteaCheck()
	c.GroupMemberAttr, c.UserAttrInGroup = "memberUid", "sAMAccountName"
	r, _ := checkLogin(t, c)
	if g := step(t, r, "groups"); g.Filter != "(memberUid=alice)" {
		t.Errorf("group filter sent = %q", g.Filter)
	}
}

func TestGiteaRejectsUsernamesItWouldRefuse(t *testing.T) {
	c := giteaCheck()
	c.Username = "ali(ce"
	r, _ := checkLogin(t, c)
	if u := step(t, r, "user"); u.Status != StatusFail || !strings.Contains(u.Message, "Gitea") {
		t.Errorf("user step = %+v", u)
	}
}

// --- Open WebUI ---

func TestOpenWebUICheckBuildsItsFilterAndReadsMemberOf(t *testing.T) {
	r, _ := checkLogin(t, LoginCheck{App: AppOpenWebUI, Username: "Alice", Password: "right",
		UserBase: ldaptest.BaseDN, UsernameAttr: "sAMAccountName", EmailAttr: "mail",
		SearchFilters: "(objectClass=user)", GroupAttr: "memberOf"})
	u := step(t, r, "user")
	if u.Status != StatusOK || u.Filter != "(&(sAMAccountName=alice)(objectClass=user))" {
		t.Errorf("user step = %+v", u)
	}
	if a := step(t, r, "attributes"); a.Status != StatusOK {
		t.Errorf("attributes step = %+v", a)
	}
	if g := step(t, r, "groups"); g.Status != StatusOK || !slices.Equal(names(g.Items), []string{"CycleB", "Engineering"}) {
		t.Errorf("groups step = %s %v", g.Status, names(g.Items))
	}
}

func TestOpenWebUIRefusesUserWithoutEmail(t *testing.T) {
	r, calls := checkLogin(t, LoginCheck{App: AppOpenWebUI, Username: "alice", Password: "right",
		UsernameAttr: "sAMAccountName", EmailAttr: "otherMailbox"})
	if a := step(t, r, "attributes"); a.Status != StatusFail || !strings.Contains(a.Message, "otherMailbox") {
		t.Errorf("attributes step = %+v", a)
	}
	if len(calls) != 0 {
		t.Errorf("bound although Open WebUI would stop before the password: %v", calls)
	}
}

func TestOpenWebUIRejectsMalformedSearchFilters(t *testing.T) {
	r, _ := checkLogin(t, LoginCheck{App: AppOpenWebUI, Username: "alice", UsernameAttr: "sAMAccountName", EmailAttr: "mail", SearchFilters: "objectClass=user"})
	if u := step(t, r, "user"); u.Status != StatusFail {
		t.Errorf("user step = %+v", u)
	}
}

func TestGiteaFillsTheUserFilterTheWayGiteaDoes(t *testing.T) {
	tests := []struct {
		name, filter string
		want         Status
	}{
		{"indexed verb", "(&(objectClass=user)(sAMAccountName=%[1]s))", StatusOK},
		{"single %s", "(&(objectClass=user)(sAMAccountName=%s))", StatusOK},
		{"indexed verb twice", "(|(sAMAccountName=%[1]s)(cn=%[1]s))", StatusOK},
		{"%s twice leaves the second one missing", "(|(sAMAccountName=%s)(cn=%s))", StatusFail},
		{"{username} is not Gitea syntax", "(sAMAccountName={username})", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := giteaCheck()
			c.UserFilter = tt.filter
			r, _ := checkLogin(t, c)
			u := step(t, r, "user")
			if u.Status != tt.want {
				t.Errorf("user step = %+v, want %s", u, tt.want)
			}
			if tt.want == StatusFail && !strings.Contains(u.Message, "%[1]s") {
				t.Errorf("message %q does not point to %%[1]s", u.Message)
			}
		})
	}
}

func TestGiteaEscapesTheUserAttributeInTheGroupFilter(t *testing.T) {
	cfg := ldaptest.CorpAD()
	for _, e := range cfg.Entries {
		if e.DN == ldaptest.AliceDN {
			e.Attrs["uid"] = []string{"a*"}
		}
	}
	c := giteaCheck()
	c.GroupMemberAttr, c.UserAttrInGroup = "memberUid", "uid"
	var calls []bindCall
	r := newService(t, cfg, ldaptest.BaseDN, true).CheckLogin(context.Background(), c, recordingBinder(&calls))
	if g := step(t, r, "groups"); g.Filter != `(memberUid=a\2a)` {
		t.Errorf("group filter sent = %q", g.Filter)
	}
}

func TestOpenWebUITakesTheFirstOfSeveralMatches(t *testing.T) {
	r, calls := checkLogin(t, LoginCheck{App: AppOpenWebUI, Username: "user", Password: "right",
		UsernameAttr: "objectClass", EmailAttr: "objectClass"})
	u := step(t, r, "user")
	if u.Status != StatusWarn || !strings.Contains(u.Message, "first") {
		t.Errorf("user step = %+v", u)
	}
	if len(calls) != 1 || calls[0].dn != u.Items[0].DN {
		t.Errorf("bind calls = %v, want one bind as the first entry %s", calls, u.Items[0].DN)
	}
}

func TestOpenWebUIEscapesTheUsername(t *testing.T) {
	r, _ := checkLogin(t, LoginCheck{App: AppOpenWebUI, Username: "*", UsernameAttr: "sAMAccountName", EmailAttr: "mail"})
	if u := step(t, r, "user"); u.Status != StatusFail || u.Filter != `(&(sAMAccountName=\2a))` {
		t.Errorf("user step = %+v", u)
	}
}
