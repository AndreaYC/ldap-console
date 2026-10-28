package session

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

func TestValidateRejectsUnsafeOrMalformedSettings(t *testing.T) {
	tests := []struct {
		name string
		s    Settings
		want string
	}{
		{"empty url", Settings{}, "must look like"},
		{"wrong scheme", Settings{URL: "http://dc01"}, "must look like"},
		{"starttls on ldaps", Settings{URL: "ldaps://dc01:636", StartTLS: true}, "only applies"},
		{"cleartext bind", Settings{URL: "ldap://dc01:389", BindDN: "svc@corp.local"}, "cleartext"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateAllowsCleartextOnlyWhenSafeOrExplicit(t *testing.T) {
	for _, s := range []Settings{
		{URL: "ldap://dc01:389", BindDN: "svc@corp.local", StartTLS: true},
		{URL: "ldaps://dc01:636", BindDN: "svc@corp.local"},
		{URL: "ldap://127.0.0.1:3389", BindDN: "CN=svc"},
		{URL: "ldap://dc01:389"}, // anonymous: no password to leak
		{URL: "ldap://dc01:389", BindDN: "svc@corp.local", AllowCleartext: true},
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
}

func TestTLSConfigUsesHostAsServerName(t *testing.T) {
	for url, want := range map[string]string{"ldaps://dc01.corp.local:636": "dc01.corp.local", "ldaps://[::1]:636": "::1"} {
		tc, err := Settings{URL: url}.TLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		if tc.ServerName != want || tc.InsecureSkipVerify {
			t.Errorf("%s: ServerName=%q insecure=%v", url, tc.ServerName, tc.InsecureSkipVerify)
		}
	}
}

func TestTLSConfigRejectsCAFileWithoutCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Settings{URL: "ldaps://dc01:636", CAFile: path}.TLSConfig()
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Errorf("err = %v", err)
	}
}

func TestOpenBindsAndUsesDefaultNamingContext(t *testing.T) {
	srv := ldaptest.Start(t, ldaptest.CorpAD())
	s, err := Open(context.Background(), Settings{URL: srv.URL, BindDN: ldaptest.BindDN}, ldaptest.Password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.BaseDN != ldaptest.BaseDN || !s.Root.IsAD {
		t.Errorf("base=%q isAD=%v", s.BaseDN, s.Root.IsAD)
	}
}

func TestOpenFailsOnWrongPassword(t *testing.T) {
	srv := ldaptest.Start(t, ldaptest.CorpAD())
	if _, err := Open(context.Background(), Settings{URL: srv.URL, BindDN: ldaptest.BindDN}, "wrong"); err == nil {
		t.Fatal("bind with wrong password succeeded")
	}
}

func TestProfileRoundTripsPrivatelyWithoutPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "profile.json")
	if p, err := LoadProfile(path); err != nil || p != (Profile{}) {
		t.Fatalf("missing profile: %+v, %v", p, err)
	}
	want := ProfileOf(Settings{URL: "ldaps://dc01:636", BindDN: "me@corp.local", CAFile: "/ca.pem", InsecureSkipVerify: true})
	if err := SaveProfile(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProfile(path)
	if err != nil || got != want {
		t.Errorf("loaded %+v, %v; want %+v", got, err, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); strings.Contains(strings.ToLower(string(b)), "password") || strings.Contains(string(b), "insecure") {
		t.Errorf("profile file holds more than connection settings: %s", b)
	}
}
