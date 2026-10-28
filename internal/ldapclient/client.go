// Package ldapclient is a small, reconnecting, read-oriented LDAP client
// that handles the paging and ranged retrieval large AD directories need.
package ldapclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrNotFound is returned when a requested DN does not exist.
var ErrNotFound = errors.New("entry not found")

// Config holds connection settings. An empty BindDN means anonymous bind.
type Config struct {
	URL      string // ldap://host:389 or ldaps://host:636
	BindDN   string // DN or, for AD, a UPN such as user@corp.local
	Password string
	StartTLS bool
	TLS      *tls.Config
	Timeout  time.Duration
	PageSize uint32
}

const (
	defaultTimeout  = 30 * time.Second
	defaultPageSize = 500
)

// Client is safe for concurrent use. It redials and rebinds once if the
// underlying connection has dropped.
type Client struct {
	cfg  Config
	mu   sync.Mutex
	conn *ldap.Conn
}

// New connects and binds immediately so bad settings fail at startup.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = defaultPageSize
	}
	c := &Client{cfg: cfg}
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return c, nil
}

func (c *Client) dial() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(c.cfg.URL, ldap.DialWithTLSConfig(c.cfg.TLS))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.cfg.URL, err)
	}
	conn.SetTimeout(c.cfg.Timeout)
	if c.cfg.StartTLS {
		if err := conn.StartTLS(c.cfg.TLS); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.Password); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("bind as %s: %w", c.cfg.BindDN, err)
		}
	}
	return conn, nil
}

// BindDN reports the identity the client is bound as ("" for anonymous).
func (c *Client) BindDN() string { return c.cfg.BindDN }

// URL reports the server URL.
func (c *Client) URL() string { return c.cfg.URL }

// Close releases the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) current() (*ldap.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil && !c.conn.IsClosing() {
		return c.conn, nil
	}
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) discard(conn *ldap.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == conn {
		_ = conn.Close()
		c.conn = nil
	}
}

// do runs fn on a live connection, retrying once on a fresh connection if
// the first attempt failed at the network layer.
func (c *Client) do(fn func(*ldap.Conn) error) error {
	for attempt := 0; ; attempt++ {
		conn, err := c.current()
		if err != nil {
			return err
		}
		err = fn(conn)
		if attempt == 0 && isConnectionError(err) {
			c.discard(conn)
			continue
		}
		return err
	}
}

func isConnectionError(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || errors.Is(err, ldap.ErrConnUnbound)
}
