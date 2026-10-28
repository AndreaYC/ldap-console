// Package session turns connection settings into a bound LDAP client and a
// directory service, and remembers the last settings (never the password).
package session

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"
)

// Settings describe how to reach and bind to a directory server.
type Settings struct {
	URL      string `json:"url"`
	BindDN   string `json:"bindDN"`
	BaseDN   string `json:"baseDN,omitempty"`
	StartTLS bool   `json:"startTLS,omitempty"`
	CAFile   string `json:"caFile,omitempty"`

	// The fields below come from command-line flags only; the UI cannot set them.
	InsecureSkipVerify bool          `json:"-"`
	AllowCleartext     bool          `json:"-"`
	PageSize           uint32        `json:"-"`
	Timeout            time.Duration `json:"-"`
}

// Validate checks the URL and refuses a password bind that would travel
// unencrypted to another host.
func (s Settings) Validate() error {
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("server URL %q must look like ldap://host:389 or ldaps://host:636", s.URL)
	}
	if s.StartTLS && u.Scheme == "ldaps" {
		return errors.New("StartTLS only applies to ldap:// URLs")
	}
	if s.sendsCleartextPassword(u) && !s.AllowCleartext {
		return errors.New("refusing to send the bind password in cleartext over ldap://; " +
			"use ldaps://, enable StartTLS, or start the console with -allow-cleartext for a lab server")
	}
	return nil
}

func (s Settings) sendsCleartextPassword(u *url.URL) bool {
	if u.Scheme != "ldap" || s.StartTLS || s.BindDN == "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())
}

// TLSConfig verifies the server certificate against the system roots plus
// CAFile, unless InsecureSkipVerify was set on the command line.
func (s Settings) TLSConfig() (*tls.Config, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:         u.Hostname(),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: s.InsecureSkipVerify, // #nosec G402 -- explicit opt-in flag for lab servers
	}
	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificates", s.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
