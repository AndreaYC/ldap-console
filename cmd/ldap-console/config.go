package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/AndreaYC/ldap-console/internal/session"
)

type config struct {
	URL                string
	BindDN             string
	BaseDN             string
	StartTLS           bool
	CAFile             string
	InsecureSkipVerify bool
	AllowCleartext     bool
	Listen             string
	Container          bool
	PageSize           uint
	Timeout            time.Duration
	Debug              bool
}

// parseFlags reads flags, falling back to LDAP_* environment variables.
// The bind password is deliberately not a flag: it would leak via ps/history.
func parseFlags(args []string, getenv func(string) string) (config, error) {
	var c config
	fs := flag.NewFlagSet("ldap-console", flag.ContinueOnError)
	fs.StringVar(&c.URL, "url", getenv("LDAP_URL"), "server URL, e.g. ldaps://dc01.corp.local:636; empty = choose it in the UI (env LDAP_URL)")
	fs.StringVar(&c.BindDN, "bind-dn", getenv("LDAP_BIND_DN"), "bind DN or AD UPN (user@corp.local); empty = anonymous (env LDAP_BIND_DN)")
	fs.StringVar(&c.BaseDN, "base-dn", getenv("LDAP_BASE_DN"), "search base; default = server's defaultNamingContext (env LDAP_BASE_DN)")
	fs.BoolVar(&c.StartTLS, "start-tls", false, "upgrade ldap:// with StartTLS")
	fs.StringVar(&c.CAFile, "ca-file", getenv("LDAP_CA_FILE"), "PEM CA bundle to trust for the server certificate (env LDAP_CA_FILE)")
	fs.BoolVar(&c.InsecureSkipVerify, "insecure-skip-verify", false, "do not verify the server certificate (testing only)")
	fs.BoolVar(&c.AllowCleartext, "allow-cleartext", false, "permit a password bind over unencrypted ldap:// (testing only)")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8389", "UI listen address; must be loopback unless -container")
	fs.BoolVar(&c.Container, "container", false, "running in a container: allow a non-loopback -listen; publish the port on 127.0.0.1 only (make docker-run does)")
	fs.UintVar(&c.PageSize, "page-size", 500, "LDAP paged-results page size")
	fs.DurationVar(&c.Timeout, "timeout", 30*time.Second, "LDAP operation timeout")
	fs.BoolVar(&c.Debug, "debug", false, "log every HTTP request")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ldap-console [-url ldaps://host:636 -bind-dn user@corp.local]\n\n"+
			"Without -url the browser UI asks for the server and password.\n"+
			"With -url the bind password is read from LDAP_BIND_PASSWORD or prompted for.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c config) validate() error {
	if c.PageSize == 0 || c.PageSize > 10000 {
		return errors.New("-page-size must be 1..10000")
	}
	if !c.Container {
		if err := checkLoopback(c.Listen); err != nil {
			return err
		}
	}
	if c.URL == "" {
		return nil // the UI starts on its connect page
	}
	return c.settings().Validate()
}

// settings returns the connection settings. Without -url, the flag-only
// fields still apply to connections made from the connect page.
func (c config) settings() session.Settings {
	return session.Settings{
		URL: c.URL, BindDN: c.BindDN, BaseDN: c.BaseDN, StartTLS: c.StartTLS, CAFile: c.CAFile,
		InsecureSkipVerify: c.InsecureSkipVerify, AllowCleartext: c.AllowCleartext,
		PageSize: uint32(c.PageSize), // #nosec G115 -- validate() caps it at 10000
		Timeout:  c.Timeout,
	}
}

// warnings lists risky settings the operator opted into.
func (c config) warnings() []string {
	var w []string
	if c.InsecureSkipVerify {
		w = append(w, "-insecure-skip-verify: the server certificate is NOT verified; anyone on the network path can impersonate the DC")
	}
	if c.AllowCleartext {
		w = append(w, "-allow-cleartext: the bind password may travel unencrypted")
	}
	if c.Container && checkLoopback(c.Listen) != nil {
		w = append(w, "-container: listening on "+c.Listen+"; publish it with -p 127.0.0.1:PORT:PORT, "+
			"or anyone on your network can browse the directory as you")
	}
	return w
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
