package ldapclient

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Query is a search request. Scope uses the ldap.Scope* constants
// (zero value = base object). Limit <= 0 means DefaultLimit.
type Query struct {
	Base   string
	Scope  int
	Filter string
	Attrs  []string
	Limit  int
}

// DefaultLimit bounds a search that does not set Query.Limit.
const DefaultLimit = 5000

// Result holds search entries; Truncated is set when Limit cut it short.
type Result struct {
	Entries   []*ldap.Entry
	Truncated bool
}

// Search runs a paged search, so servers that cap result sizes (AD: 1000)
// still return everything up to q.Limit.
func (c *Client) Search(ctx context.Context, q Query) (Result, error) {
	if q.Limit <= 0 {
		q.Limit = DefaultLimit
	}
	var res Result
	err := c.do(ctx, func(conn *ldap.Conn) error {
		var err error
		res, err = c.searchPaged(ctx, conn, q)
		return err
	})
	if err != nil {
		return Result{}, fmt.Errorf("search %q under %q: %w", q.Filter, q.Base, err)
	}
	return res, nil
}

func (c *Client) searchPaged(ctx context.Context, conn *ldap.Conn, q Query) (Result, error) {
	paging := ldap.NewControlPaging(c.cfg.PageSize)
	var res Result
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		req := ldap.NewSearchRequest(q.Base, q.Scope, ldap.NeverDerefAliases, 0, 0, false,
			q.Filter, q.Attrs, []ldap.Control{paging})
		page, err := conn.Search(req)
		if isLimitError(err) && page != nil {
			// The server's own size/admin limit cut us off: keep what arrived.
			res.Entries = append(res.Entries, page.Entries...)
			res.Truncated = true
			if len(res.Entries) > q.Limit {
				res.Entries = res.Entries[:q.Limit]
			}
			return res, nil
		}
		if err != nil {
			return Result{}, err
		}
		res.Entries = append(res.Entries, page.Entries...)
		cookie := pagingCookie(page)
		if len(res.Entries) >= q.Limit {
			res.Truncated = len(res.Entries) > q.Limit || len(cookie) > 0
			res.Entries = res.Entries[:q.Limit]
			if len(cookie) > 0 {
				abandonPaging(conn, req, cookie)
			}
			return res, nil
		}
		if len(cookie) == 0 {
			return res, nil
		}
		paging.SetCookie(cookie)
	}
}

func isLimitError(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultAdminLimitExceeded)
}

func pagingCookie(r *ldap.SearchResult) []byte {
	if ctrl, ok := ldap.FindControl(r.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok {
		return ctrl.Cookie
	}
	return nil
}

// abandonPaging tells the server to release a paged-search cursor (RFC 2696:
// page size 0). Best effort: servers expire idle cursors on their own, so a
// failure here does not affect the result already collected.
func abandonPaging(conn *ldap.Conn, req *ldap.SearchRequest, cookie []byte) {
	stop := ldap.NewControlPaging(0)
	stop.SetCookie(cookie)
	req.Controls = []ldap.Control{stop}
	_, _ = conn.Search(req)
}

// Entry reads one entry. With no attrs it requests all user and operational
// attributes. Ranged values (AD's member;range=0-1499) are fetched in full
// and returned under the plain attribute name.
func (c *Client) Entry(ctx context.Context, dn string, attrs ...string) (*ldap.Entry, error) {
	if len(attrs) == 0 {
		attrs = []string{"*", "+"}
	}
	res, err := c.Search(ctx, Query{Base: dn, Scope: ldap.ScopeBaseObject, Filter: "(objectClass=*)", Attrs: attrs, Limit: 1})
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, fmt.Errorf("%s: %w", dn, ErrNotFound)
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
		return nil, fmt.Errorf("%s: %w", dn, ErrReferral)
	}
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("%s: %w", dn, ErrNotFound)
	}
	e := res.Entries[0]
	if err := c.resolveRanges(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

// maxAttributeValues caps how many values of one ranged attribute Entry
// collects, so opening a group with hundreds of thousands of members cannot
// tie up the server or this process.
var maxAttributeValues = 50000

// TruncatedAttribute is a pseudo-attribute Entry adds, listing the names of
// attributes whose values were cut at maxAttributeValues.
const TruncatedAttribute = "ldap-console-truncated"

// IsTruncated reports whether Entry cut attribute name short.
func IsTruncated(e *ldap.Entry, name string) bool {
	for _, n := range e.GetAttributeValues(TruncatedAttribute) {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

func (c *Client) resolveRanges(ctx context.Context, e *ldap.Entry) error {
	out := e.Attributes[:0:0]
	var truncated []string
	for _, a := range e.Attributes {
		name, spec, ranged := strings.Cut(a.Name, ";range=")
		if !ranged {
			out = append(out, a)
			continue
		}
		full, complete, err := c.fetchRemainingRange(ctx, e.DN, name, spec, a)
		if err != nil {
			return err
		}
		out = append(out, full)
		if !complete {
			truncated = append(truncated, name)
		}
	}
	if len(truncated) > 0 {
		out = append(out, &ldap.EntryAttribute{Name: TruncatedAttribute, Values: truncated, ByteValues: toBytes(truncated)})
	}
	e.Attributes = out
	return nil
}

func toBytes(vals []string) [][]byte {
	out := make([][]byte, len(vals))
	for i, v := range vals {
		out[i] = []byte(v)
	}
	return out
}

// fetchRemainingRange keeps requesting name;range=<next>-* until the server
// answers with a range ending in "*", or maxAttributeValues is reached
// (complete = false).
func (c *Client) fetchRemainingRange(ctx context.Context, dn, name, spec string, first *ldap.EntryAttribute) (full *ldap.EntryAttribute, complete bool, err error) {
	full = &ldap.EntryAttribute{Name: name}
	cur := first
	for {
		full.Values = append(full.Values, cur.Values...)
		full.ByteValues = append(full.ByteValues, cur.ByteValues...)
		_, end, _ := strings.Cut(spec, "-")
		if end == "*" {
			return full, true, nil
		}
		if len(full.Values) >= maxAttributeValues {
			return full, false, nil
		}
		hi, err := strconv.Atoi(end)
		if err != nil {
			return nil, false, fmt.Errorf("%s: bad range %q on %s", dn, spec, name)
		}
		want := fmt.Sprintf("%s;range=%d-*", name, hi+1)
		res, err := c.Search(ctx, Query{Base: dn, Scope: ldap.ScopeBaseObject, Filter: "(objectClass=*)", Attrs: []string{want}, Limit: 1})
		if err != nil {
			return nil, false, err
		}
		cur, spec = nil, ""
		if len(res.Entries) == 1 {
			for _, a := range res.Entries[0].Attributes {
				if n, s, ok := strings.Cut(a.Name, ";range="); ok && strings.EqualFold(n, name) {
					cur, spec = a, s
				}
			}
		}
		if cur == nil {
			return nil, false, fmt.Errorf("%s: server stopped returning %s after range %d", dn, name, hi)
		}
	}
}
