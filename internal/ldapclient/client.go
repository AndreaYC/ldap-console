// Package ldapclient is a small, reconnecting, read-oriented LDAP client
// that handles the paging and ranged retrieval large AD directories need.
package ldapclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	// ErrNotFound is returned when a requested DN does not exist.
	ErrNotFound = errors.New("entry not found")
	// ErrReferral is returned when the DN is held by another domain or
	// partition and the server answered with a referral instead of the entry.
	ErrReferral = errors.New("entry is in another domain (referral)")
)

// Config holds connection settings. An empty BindDN means anonymous bind.
type Config struct {
	URL      string // ldap://host:389 or ldaps://host:636
	BindDN   string // DN or, for AD, a UPN such as user@corp.local
	Password string
	StartTLS bool
	TLS      *tls.Config
	Timeout  time.Duration
	PageSize uint32
	// DialTimeout bounds connecting, StartTLS and bind together, so an
	// unreachable or silent server fails fast instead of after Timeout.
	DialTimeout time.Duration
}

const (
	defaultTimeout     = 30 * time.Second
	defaultDialTimeout = 10 * time.Second
	defaultPageSize    = 500
)

var errClosed = errors.New("ldap client closed")

// Client is safe for concurrent use. It redials and rebinds once if the
// underlying connection has dropped.
type Client struct {
	cfg     Config
	mu      sync.Mutex
	conn    *ldap.Conn
	closed  bool
	dialing chan struct{} // non-nil while a redial runs; closed when it ends
	dialErr error         // result of the last redial
}

// New connects and binds immediately so bad settings fail at startup.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = defaultPageSize
	}
	c := &Client{cfg: cfg}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return c, nil
}

// dial connects and binds within DialTimeout or ctx's deadline, whichever
// comes first. go-ldap takes no context, so the deadline is all it honours.
func (c *Client) dial(ctx context.Context) (*ldap.Conn, error) {
	setup := c.cfg.DialTimeout
	if dl, ok := ctx.Deadline(); ok {
		setup = min(setup, time.Until(dl))
	}
	if setup <= 0 {
		return nil, fmt.Errorf("dial %s: %w", c.cfg.URL, context.DeadlineExceeded)
	}
	conn, err := ldap.DialURL(c.cfg.URL, ldap.DialWithDialer(&net.Dialer{Timeout: setup}), ldap.DialWithTLSConfig(c.cfg.TLS))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.cfg.URL, err)
	}
	conn.SetTimeout(setup)
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
	conn.SetTimeout(c.cfg.Timeout)
	return conn, nil
}

// BindDN reports the identity the client is bound as ("" for anonymous).
func (c *Client) BindDN() string { return c.cfg.BindDN }

// URL reports the server URL.
func (c *Client) URL() string { return c.cfg.URL }

// Close releases the connection. Requests still in flight fail.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// current returns the live connection, or waits for a redial. Only one
// redial runs at a time and it is not done under the lock, so a server that
// stops answering costs each request at most its own context deadline.
func (c *Client) current(ctx context.Context) (*ldap.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.conn != nil && !c.conn.IsClosing() {
		conn := c.conn
		c.mu.Unlock()
		return conn, nil
	}
	if c.dialing == nil {
		c.dialing = make(chan struct{})
		go c.redial(c.dialing)
	}
	done := c.dialing
	c.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closed:
		return nil, errClosed
	case c.conn != nil:
		return c.conn, nil
	case c.dialErr != nil:
		return nil, c.dialErr
	}
	return nil, errors.New("ldap connection lost during reconnect")
}

// redial runs detached from any request, bounded by DialTimeout, so a
// cancelled request does not abort the reconnect others are waiting on.
func (c *Client) redial(done chan struct{}) {
	conn, err := c.dial(context.Background())
	c.mu.Lock()
	if c.closed && conn != nil {
		_ = conn.Close()
		conn, err = nil, errClosed
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.dialErr, c.dialing = conn, err, nil
	c.mu.Unlock()
	close(done)
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
// the first attempt failed because the connection was lost.
func (c *Client) do(ctx context.Context, fn func(*ldap.Conn) error) error {
	for attempt := 0; ; attempt++ {
		conn, err := c.current(ctx)
		if err != nil {
			return err
		}
		err = fn(conn)
		// A server-side close (AD drops idle connections after 15 minutes)
		// surfaces as a plain read error; the closing connection is the tell.
		// Every operation here is a read, so retrying it is safe.
		if attempt == 0 && err != nil && (isConnectionError(err) || conn.IsClosing()) {
			c.discard(conn)
			continue
		}
		return err
	}
}

func isConnectionError(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || errors.Is(err, ldap.ErrConnUnbound)
}
