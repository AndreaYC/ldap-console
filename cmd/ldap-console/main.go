// Command ldap-console serves a local, read-only web UI for browsing an LDAP
// or Active Directory server and inspecting group membership.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
	"github.com/AndreaYC/ldap-console/internal/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "ldap-console:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := parseFlags(args, os.Getenv)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	password, err := bindPassword(cfg.BindDN)
	if err != nil {
		return err
	}
	tlsCfg, err := cfg.tlsConfig()
	if err != nil {
		return err
	}
	client, err := ldapclient.New(ldapclient.Config{
		URL: cfg.URL, BindDN: cfg.BindDN, Password: password,
		StartTLS: cfg.StartTLS, TLS: tlsCfg, Timeout: cfg.Timeout, PageSize: uint32(cfg.PageSize), // #nosec G115 -- validate() caps it at 10000
	})
	if err != nil {
		return err
	}
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root, err := client.RootDSE(ctx)
	if err != nil {
		return err
	}
	base := cfg.BaseDN
	if base == "" {
		base = root.DefaultNamingContext
	}
	if base == "" {
		return errors.New("server advertises no naming context; set -base-dn")
	}

	info := server.Info{
		URL: cfg.URL, BindDN: cfg.BindDN, BaseDN: base,
		NamingContexts: root.NamingContexts, Vendor: root.Vendor, IsAD: root.IsAD,
	}
	handler := server.New(client, directory.New(client, base, root.IsAD), info,
		server.Options{ListenAddr: cfg.Listen, Loc: time.Local})
	return serve(ctx, cfg.Listen, handler, info)
}

func serve(ctx context.Context, addr string, h http.Handler, info server.Info) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("connected", "server", info.URL, "vendor", info.Vendor, "base", info.BaseDN, "bind", info.BindDN)
	fmt.Fprintf(os.Stderr, "\n  LDAP Console ready → http://%s\n\n", addr)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// bindPassword reads LDAP_BIND_PASSWORD, or prompts on a terminal.
func bindPassword(bindDN string) (string, error) {
	if bindDN == "" {
		return "", nil
	}
	if p, ok := os.LookupEnv("LDAP_BIND_PASSWORD"); ok {
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal to prompt for the password; set LDAP_BIND_PASSWORD")
	}
	fmt.Fprintf(os.Stderr, "Password for %s: ", bindDN)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(b), nil
}
