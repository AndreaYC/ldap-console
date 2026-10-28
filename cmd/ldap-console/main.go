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

	"github.com/AndreaYC/ldap-console/internal/server"
	"github.com/AndreaYC/ldap-console/internal/session"
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
	for _, w := range cfg.warnings() {
		slog.Warn(w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var initial *session.Session
	if cfg.URL != "" {
		password, err := bindPassword(cfg.BindDN)
		if err != nil {
			return err
		}
		if initial, err = session.Open(ctx, cfg.settings(), password); err != nil {
			return err
		}
		slog.Info("connected", "server", cfg.URL, "vendor", initial.Root.Vendor, "base", initial.BaseDN, "bind", cfg.BindDN)
	}
	profile, err := session.DefaultProfilePath()
	if err != nil {
		slog.Warn("connection settings will not be remembered", "err", err)
		profile = ""
	}
	handler := server.New(initial, server.Options{ListenAddr: cfg.Listen, Loc: time.Local, Defaults: cfg.settings(), ProfilePath: profile})
	defer func() { _ = handler.Close() }()
	return serve(ctx, cfg.Listen, handler)
}

func serve(ctx context.Context, addr string, h http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
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
