package ldapclient

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndreaYC/ldap-console/internal/ldaptest"
)

// stallProxy forwards LDAP traffic to target, or, once stalled, accepts
// connections and never answers: what a firewalled or hung DC looks like.
type stallProxy struct {
	ln       net.Listener
	target   string
	stalled  atomic.Bool
	accepted atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
}

func newStallProxy(t *testing.T, target string) *stallProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stallProxy{ln: ln, target: target}
	t.Cleanup(func() { _ = ln.Close(); p.dropAll() })
	go p.serve()
	return p
}

func (p *stallProxy) url() string { return "ldap://" + p.ln.Addr().String() }

func (p *stallProxy) serve() {
	for {
		in, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepted.Add(1)
		p.track(in)
		if p.stalled.Load() {
			continue
		}
		out, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = in.Close()
			continue
		}
		p.track(out)
		go func() { _, _ = io.Copy(out, in) }()
		go func() { _, _ = io.Copy(in, out) }()
	}
}

func (p *stallProxy) track(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = append(p.conns, c)
}

func (p *stallProxy) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

func TestNewGivesUpOnSilentServerAfterDialTimeout(t *testing.T) {
	p := newStallProxy(t, "unused")
	p.stalled.Store(true)

	start := time.Now()
	_, err := New(context.Background(), Config{URL: p.url(), BindDN: "CN=x", Password: "x", DialTimeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("bind to a silent server succeeded")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("New took %v, want about the 200ms dial timeout", took)
	}
}

func TestNewHonoursContextDeadline(t *testing.T) {
	p := newStallProxy(t, "unused")
	p.stalled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := New(ctx, Config{URL: p.url(), BindDN: "CN=x", Password: "x"}); err == nil {
		t.Fatal("bind to a silent server succeeded")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("New took %v, want about the 200ms context deadline", took)
	}
}

// When the DC stops answering, every request used to queue behind one
// reconnect held under the client lock. Now one reconnect runs, and each
// request gives up when its own context does.
func TestStalledReconnectIsSharedAndDoesNotBlockRequests(t *testing.T) {
	cfg := ldaptest.CorpAD()
	srv := ldaptest.Start(t, cfg)
	p := newStallProxy(t, srv.URL[len("ldap://"):])
	c, err := New(context.Background(), Config{URL: p.url(), BindDN: cfg.BindDN, Password: cfg.Password, DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	p.stalled.Store(true)
	p.dropAll()
	before := p.accepted.Load()

	var wg sync.WaitGroup
	start := time.Now()
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if _, err := c.Entry(ctx, ldaptest.AliceDN); err == nil {
				t.Error("Entry succeeded against a stalled server")
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 700*time.Millisecond {
		t.Errorf("requests took %v, want each to stop at its own 150ms deadline", took)
	}
	if n := p.accepted.Load() - before; n != 1 {
		t.Errorf("%d reconnect attempts for 5 concurrent requests, want 1", n)
	}

	p.stalled.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, err := c.Entry(ctx, ldaptest.AliceDN); err == nil {
			return
		} else if ctx.Err() != nil {
			t.Fatalf("client did not recover once the server answered: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRequestRetriesWhenServerDropsConnection(t *testing.T) {
	cfg := ldaptest.CorpAD()
	srv := ldaptest.Start(t, cfg)
	p := newStallProxy(t, srv.URL[len("ldap://"):])
	c, err := New(context.Background(), Config{URL: p.url(), BindDN: cfg.BindDN, Password: cfg.Password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	p.dropAll() // e.g. the DC's idle timeout closed our connection
	if _, err := c.Entry(context.Background(), ldaptest.AliceDN); err != nil {
		t.Fatalf("Entry after server-side drop: %v", err)
	}
}
