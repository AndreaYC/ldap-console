package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/session"
)

var apps = map[directory.App]bool{directory.AppGeneric: true, directory.AppGitea: true, directory.AppOpenWebUI: true}

// handleCheckLogin replays an application's LDAP login for one user. It is
// a POST because the request may carry that user's password.
func (s *Server) handleCheckLogin(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	var c directory.LoginCheck
	if err := decodeJSON(w, r, &c); err != nil {
		writeError(w, err)
		return
	}
	if err := validateLoginCheck(&c); err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	bind := func(ctx context.Context, dn, password string) error {
		return session.VerifyBind(ctx, sess.Settings, dn, password)
	}
	writeJSON(w, http.StatusOK, sess.Dir.CheckLogin(ctx, c, bind))
}

func validateLoginCheck(c *directory.LoginCheck) error {
	c.Username = strings.TrimSpace(c.Username)
	if c.Username == "" {
		return badRequest("enter the username to test")
	}
	if !apps[c.App] {
		return badRequest("unknown application %q", c.App)
	}
	for name, dn := range map[string]string{"user search base": c.UserBase, "group search base": c.GroupBase} {
		if strings.TrimSpace(dn) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(dn), "(") {
			return badRequest("%s looks like a filter; enter a DN such as DC=corp,DC=local", name)
		}
		if !validDN(dn) {
			return badRequest("%s is not a valid DN: %q", name, dn)
		}
	}
	for name, a := range map[string]string{"email": c.EmailAttr, "username": c.UsernameAttr, "group member": c.GroupMemberAttr,
		"user attribute in group": c.UserAttrInGroup, "group": c.GroupAttr} {
		if a != "" && !attrNameRE.MatchString(a) {
			return badRequest("%s attribute %q is not an attribute name", name, a)
		}
	}
	return nil
}
