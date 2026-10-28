package session

import (
	"context"
	"errors"

	"github.com/AndreaYC/ldap-console/internal/directory"
	"github.com/AndreaYC/ldap-console/internal/ldapclient"
)

// Session is a bound connection plus what the server said about itself.
type Session struct {
	Settings Settings
	Client   *ldapclient.Client
	Dir      *directory.Service
	BaseDN   string
	Root     ldapclient.RootDSE
}

// Open validates s, connects, binds and reads the root DSE. BaseDN defaults
// to the server's defaultNamingContext.
func Open(ctx context.Context, s Settings, password string) (*Session, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	tlsCfg, err := s.TLSConfig()
	if err != nil {
		return nil, err
	}
	client, err := ldapclient.New(ctx, ldapclient.Config{
		URL: s.URL, BindDN: s.BindDN, Password: password,
		StartTLS: s.StartTLS, TLS: tlsCfg, Timeout: s.Timeout, PageSize: s.PageSize,
	})
	if err != nil {
		return nil, err
	}
	root, err := client.RootDSE(ctx)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	base := s.BaseDN
	if base == "" {
		base = root.DefaultNamingContext
	}
	if base == "" {
		_ = client.Close()
		return nil, errors.New("server advertises no naming context; set the base DN")
	}
	return &Session{Settings: s, Client: client, Dir: directory.New(client, base, root.IsAD), BaseDN: base, Root: root}, nil
}

// Close releases the connection.
func (s *Session) Close() error { return s.Client.Close() }
