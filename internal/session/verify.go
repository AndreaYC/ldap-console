package session

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/AndreaYC/ldap-console/internal/ldapclient"
)

// VerifyBind checks dn's password the way an application does at login:
// a bind on a fresh connection to the same server, closed straight after.
//
// The console's own settings were validated for the console's bind, which
// may be anonymous and so allowed over plain ldap://. This bind sends a real
// user's password, so the cleartext policy is checked again for it.
func VerifyBind(ctx context.Context, s Settings, dn, password string) error {
	if password == "" {
		return errors.New("refusing an empty password: AD treats it as an anonymous bind and reports success for any user")
	}
	s.BindDN = dn
	if err := s.Validate(); err != nil {
		return err
	}
	tlsCfg, err := s.TLSConfig()
	if err != nil {
		return err
	}
	c, err := ldapclient.New(ctx, ldapclient.Config{URL: s.URL, BindDN: dn, Password: password,
		StartTLS: s.StartTLS, TLS: tlsCfg, Timeout: s.Timeout, PageSize: s.PageSize})
	if err != nil {
		return errors.New(explainBindError(err))
	}
	return c.Close()
}

var adDataCode = regexp.MustCompile(`data ([0-9a-f]{3,4}),`)

// adBindReasons are the "data" sub-codes AD puts in an invalid-credentials error.
var adBindReasons = map[string]string{
	"525": "user not found",
	"52e": "wrong password",
	"530": "not permitted to log on at this time",
	"531": "not permitted to log on from this workstation",
	"532": "password expired",
	"533": "account disabled",
	"701": "account expired",
	"773": "user must change the password before logging on",
	"775": "account locked out",
}

// explainBindError prefixes AD's cryptic bind error with its meaning.
func explainBindError(err error) string {
	m := adDataCode.FindStringSubmatch(err.Error())
	if m == nil || adBindReasons[m[1]] == "" {
		return err.Error()
	}
	return fmt.Sprintf("%s (AD code %s): %v", adBindReasons[m[1]], m[1], err)
}
