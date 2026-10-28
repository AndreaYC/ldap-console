package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldaptest"
	"github.com/AndreaYC/ldap-console/internal/session"
)

// newDisconnected returns a server with no session, a running fake AD, and
// the profile path it remembers settings in.
func newDisconnected(t *testing.T) (*Server, *ldaptest.Server, string) {
	t.Helper()
	srv := ldaptest.Start(t, ldaptest.CorpAD())
	profile := filepath.Join(t.TempDir(), "profile.json")
	h := New(nil, Options{ListenAddr: testHost, Loc: time.UTC, ProfilePath: profile})
	t.Cleanup(func() { _ = h.Close() })
	return h, srv, profile
}

type postOpt func(*http.Request)

func withHeader(k, v string) postOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

// post sends what the console's own page sends; opts override headers.
func post(t *testing.T, h *Server, path, body string, opts ...postOpt) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://"+testHost+path, strings.NewReader(body))
	req.Header.Set("Origin", "http://"+testHost)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Console-Token", h.token)
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func connectBody(url, password string) string {
	return `{"url":"` + url + `","bindDN":"` + ldaptest.BindDN + `","password":"` + password + `"}`
}

func TestInfoWhenDisconnectedOffersSavedProfile(t *testing.T) {
	h, _, profile := newDisconnected(t)
	if err := session.SaveProfile(profile, session.Profile{URL: "ldaps://dc01:636", BindDN: "me@corp.local"}); err != nil {
		t.Fatal(err)
	}
	got := decode[Info](t, get(t, h, "/api/info"), http.StatusOK)
	if got.Connected || got.Profile == nil || got.Profile.URL != "ldaps://dc01:636" || got.Token == "" {
		t.Errorf("info = %+v", got)
	}
}

func TestDirectoryEndpointsNeedAConnection(t *testing.T) {
	h, _, _ := newDisconnected(t)
	decode[errorResponse](t, get(t, h, "/api/children", "dn", ldaptest.BaseDN), http.StatusServiceUnavailable)
}

func TestConnectOpensSessionAndRemembersSettingsWithoutPassword(t *testing.T) {
	h, srv, profile := newDisconnected(t)
	info := decode[Info](t, post(t, h, "/api/connect", connectBody(srv.URL, ldaptest.Password)), http.StatusOK)
	if !info.Connected || info.BaseDN != ldaptest.BaseDN || !info.IsAD {
		t.Fatalf("info = %+v", info)
	}
	if got := decode[directory.ListResult](t, get(t, h, "/api/children", "dn", ldaptest.BaseDN), http.StatusOK); len(got.Items) == 0 {
		t.Error("no children after connect")
	}
	b, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), srv.URL) || strings.Contains(string(b), ldaptest.Password) {
		t.Errorf("profile = %s", b)
	}
}

func TestConnectReportsBadPasswordAndStaysDisconnected(t *testing.T) {
	h, srv, profile := newDisconnected(t)
	decode[errorResponse](t, post(t, h, "/api/connect", connectBody(srv.URL, "wrong")), http.StatusUnauthorized)
	if decode[Info](t, get(t, h, "/api/info"), http.StatusOK).Connected {
		t.Error("connected after failed bind")
	}
	if _, err := os.Stat(profile); err == nil {
		t.Error("profile saved for a failed connect")
	}
}

func TestConnectRejectsInvalidRequests(t *testing.T) {
	h, _, _ := newDisconnected(t)
	for name, body := range map[string]string{
		"not json":      `url=ldap://x`,
		"unknown field": `{"url":"ldaps://dc01:636","insecureSkipVerify":true}`,
		"cleartext":     `{"url":"ldap://dc01:389","bindDN":"me@corp.local","password":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			decode[errorResponse](t, post(t, h, "/api/connect", body), http.StatusBadRequest)
		})
	}
}

// A malicious page open in the same browser must not be able to point the
// console at its own server (it would then receive the next bind password).
func TestConnectRefusesRequestsNotFromTheConsolePage(t *testing.T) {
	h, srv, _ := newDisconnected(t)
	body := connectBody(srv.URL, ldaptest.Password)
	tests := []struct {
		name string
		opt  postOpt
		want int
	}{
		{"foreign origin", withHeader("Origin", "http://evil.example"), http.StatusForbidden},
		{"no origin", withHeader("Origin", ""), http.StatusForbidden},
		{"form content type", withHeader("Content-Type", "text/plain"), http.StatusUnsupportedMediaType},
		{"no token", withHeader("X-Console-Token", ""), http.StatusForbidden},
		{"wrong token", withHeader("X-Console-Token", strings.Repeat("0", 64)), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := post(t, h, "/api/connect", body, tt.opt); rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if decode[Info](t, get(t, h, "/api/info"), http.StatusOK).Connected {
				t.Fatal("refused request still connected the console")
			}
		})
	}
}

func TestDisconnectDropsSession(t *testing.T) {
	h, srv, _ := newDisconnected(t)
	decode[Info](t, post(t, h, "/api/connect", connectBody(srv.URL, ldaptest.Password)), http.StatusOK)
	if decode[Info](t, post(t, h, "/api/disconnect", `{}`), http.StatusOK).Connected {
		t.Error("still connected")
	}
	decode[errorResponse](t, get(t, h, "/api/entry", "dn", ldaptest.BaseDN), http.StatusServiceUnavailable)
}

func TestInfoFillsUnsavedFieldsFromLaunchDefaults(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile.json")
	if err := session.SaveProfile(profile, session.Profile{URL: "ldaps://dc01:636"}); err != nil {
		t.Fatal(err)
	}
	h := New(nil, Options{ListenAddr: testHost, ProfilePath: profile,
		Defaults: session.Settings{URL: "ldaps://other:636", CAFile: "/certs/ca.pem"}})
	got := decode[Info](t, get(t, h, "/api/info"), http.StatusOK).Profile
	if got.URL != "ldaps://dc01:636" || got.CAFile != "/certs/ca.pem" {
		t.Errorf("profile = %+v, want saved URL and default CA file", got)
	}
}
