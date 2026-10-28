package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func TestParseFlagsReadsEnvironmentDefaults(t *testing.T) {
	env := map[string]string{"LDAP_URL": "ldaps://dc01.corp.local:636", "LDAP_BIND_DN": "svc@corp.local"}
	c, err := parseFlags(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.URL != env["LDAP_URL"] || c.BindDN != env["LDAP_BIND_DN"] || c.Listen != "127.0.0.1:8389" {
		t.Errorf("config = %+v", c)
	}
}

func TestParseFlagsRejectsInvalidSettings(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing url", nil, "-url is required"},
		{"wrong scheme", []string{"-url", "http://dc01"}, "must look like"},
		{"starttls on ldaps", []string{"-url", "ldaps://dc01:636", "-start-tls"}, "only applies"},
		{"zero page size", []string{"-url", "ldap://dc01", "-page-size", "0"}, "page-size"},
		{"public listen", []string{"-url", "ldap://dc01", "-listen", "0.0.0.0:8389"}, "not a loopback"},
		{"lan listen", []string{"-url", "ldap://dc01", "-listen", "10.0.0.5:8389"}, "not a loopback"},
		{"cleartext bind", []string{"-url", "ldap://dc01:389", "-bind-dn", "svc@corp.local"}, "cleartext"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFlags(tt.args, noEnv)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestCheckLoopbackAcceptsLocalAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8389", "localhost:9000", "[::1]:8389", "127.0.0.2:80"} {
		if err := checkLoopback(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestTLSConfigUsesHostAsServerName(t *testing.T) {
	c := config{URL: "ldaps://dc01.corp.local:636"}
	tc, err := c.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tc.ServerName != "dc01.corp.local" || tc.InsecureSkipVerify {
		t.Errorf("tls = %+v", tc)
	}
}

func TestTLSConfigRejectsCAFileWithoutCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config{URL: "ldaps://dc01:636", CAFile: path}.tlsConfig()
	if err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Errorf("err = %v", err)
	}
}

func TestParseFlagsAllowsCleartextOnlyWhenSafeOrExplicit(t *testing.T) {
	for _, args := range [][]string{
		{"-url", "ldap://dc01:389", "-bind-dn", "svc@corp.local", "-start-tls"},
		{"-url", "ldaps://dc01:636", "-bind-dn", "svc@corp.local"},
		{"-url", "ldap://127.0.0.1:3389", "-bind-dn", "CN=svc"},
		{"-url", "ldap://dc01:389"}, // anonymous: no password to leak
		{"-url", "ldap://dc01:389", "-bind-dn", "svc@corp.local", "-allow-cleartext"},
	} {
		if _, err := parseFlags(args, noEnv); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestTLSConfigHandlesIPv6Literal(t *testing.T) {
	tc, err := config{URL: "ldaps://[::1]:636"}.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tc.ServerName != "::1" {
		t.Errorf("ServerName = %q, want ::1", tc.ServerName)
	}
}

func TestWarningsListRiskyOptIns(t *testing.T) {
	if w := (config{}).warnings(); len(w) != 0 {
		t.Errorf("default config warns: %v", w)
	}
	if w := (config{InsecureSkipVerify: true, AllowCleartext: true}).warnings(); len(w) != 2 {
		t.Errorf("warnings = %v, want 2", w)
	}
}
