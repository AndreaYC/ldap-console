package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	URL                string
	BindDN             string
	BaseDN             string
	StartTLS           bool
	CAFile             string
	InsecureSkipVerify bool
	Listen             string
	PageSize           uint
	Timeout            time.Duration
	Debug              bool
}

// parseFlags reads flags, falling back to LDAP_* environment variables.
// The bind password is deliberately not a flag: it would leak via ps/history.
func parseFlags(args []string, getenv func(string) string) (config, error) {
	var c config
	fs := flag.NewFlagSet("ldap-console", flag.ContinueOnError)
	fs.StringVar(&c.URL, "url", getenv("LDAP_URL"), "server URL, e.g. ldaps://dc01.corp.local:636 (env LDAP_URL)")
	fs.StringVar(&c.BindDN, "bind-dn", getenv("LDAP_BIND_DN"), "bind DN or AD UPN (user@corp.local); empty = anonymous (env LDAP_BIND_DN)")
	fs.StringVar(&c.BaseDN, "base-dn", getenv("LDAP_BASE_DN"), "search base; default = server's defaultNamingContext (env LDAP_BASE_DN)")
	fs.BoolVar(&c.StartTLS, "start-tls", false, "upgrade ldap:// with StartTLS")
	fs.StringVar(&c.CAFile, "ca-file", getenv("LDAP_CA_FILE"), "PEM CA bundle to trust for the server certificate (env LDAP_CA_FILE)")
	fs.BoolVar(&c.InsecureSkipVerify, "insecure-skip-verify", false, "do not verify the server certificate (testing only)")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8389", "UI listen address; must be loopback")
	fs.UintVar(&c.PageSize, "page-size", 500, "LDAP paged-results page size")
	fs.DurationVar(&c.Timeout, "timeout", 30*time.Second, "LDAP operation timeout")
	fs.BoolVar(&c.Debug, "debug", false, "log every HTTP request")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ldap-console -url ldaps://host:636 -bind-dn user@corp.local\n\n"+
			"The bind password is read from LDAP_BIND_PASSWORD or prompted for.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c config) validate() error {
	if c.URL == "" {
		return errors.New("-url is required (or set LDAP_URL)")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("-url %q must look like ldap://host:389 or ldaps://host:636", c.URL)
	}
	if c.StartTLS && u.Scheme == "ldaps" {
		return errors.New("-start-tls only applies to ldap:// URLs")
	}
	if c.PageSize == 0 || c.PageSize > 10000 {
		return errors.New("-page-size must be 1..10000")
	}
	return checkLoopback(c.Listen)
}

// checkLoopback refuses non-loopback listen addresses: the UI has no login
// of its own and acts with the bind DN's privileges.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-listen %q is not a loopback address; the console has no authentication of its own", addr)
}

func (c config) tlsConfig() (*tls.Config, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:         strings.Split(u.Host, ":")[0],
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.InsecureSkipVerify, // #nosec G402 -- explicit opt-in flag for lab servers
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read -ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-ca-file %s contains no PEM certificates", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
