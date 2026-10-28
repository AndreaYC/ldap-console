// Command ldap-demo runs an in-memory, AD-shaped LDAP server for trying the
// console without a real domain controller. Never expose it beyond loopback.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:3389", "LDAP listen address")
	flag.Parse()

	srv, err := ldaptest.Serve(ldaptest.CorpAD(), *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ldap-demo:", err)
		os.Exit(1)
	}
	defer srv.Stop()

	fmt.Fprintf(os.Stderr, "Demo directory on %s. In another shell:\n\n"+
		"  LDAP_BIND_PASSWORD=%s go run ./cmd/ldap-console -url %s -bind-dn %q\n\n",
		srv.URL, ldaptest.Password, srv.URL, ldaptest.BindDN)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}
