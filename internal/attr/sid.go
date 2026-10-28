// Package attr decodes and renders LDAP attribute values for display,
// with special handling for Active Directory binary and encoded attributes.
package attr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrMalformed is returned when a binary or encoded value cannot be decoded.
var ErrMalformed = errors.New("malformed value")

// ParseSID converts a binary Windows security identifier to its S-R-I-S... form.
func ParseSID(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("sid of %d bytes: %w", len(b), ErrMalformed)
	}
	count := int(b[1])
	if len(b) != 8+4*count {
		return "", fmt.Errorf("sid declares %d sub-authorities in %d bytes: %w", count, len(b), ErrMalformed)
	}
	var authority uint64
	for _, v := range b[2:8] {
		authority = authority<<8 | uint64(v)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", b[0], authority)
	for i := range count {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String(), nil
}

// EncodeSID converts an S-R-I-S... string back to its binary form, e.g. for
// use in an (objectSid=...) filter.
func EncodeSID(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("sid %q: %w", s, ErrMalformed)
	}
	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("sid %q revision: %w", s, ErrMalformed)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("sid %q authority: %w", s, ErrMalformed)
	}
	subs := parts[3:]
	out := make([]byte, 8, 8+4*len(subs))
	out[0], out[1] = byte(rev), byte(len(subs))
	for i := range 6 {
		out[7-i] = byte(authority >> (8 * i))
	}
	for _, p := range subs {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sid %q sub-authority %q: %w", s, p, ErrMalformed)
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(v))
	}
	return out, nil
}

// RID returns the relative identifier (last sub-authority) of a SID string,
// or "" when s is not a SID.
func RID(s string) string {
	i := strings.LastIndexByte(s, '-')
	if !strings.HasPrefix(s, "S-") || i < 0 {
		return ""
	}
	return s[i+1:]
}

// PrimaryGroupSID derives the SID of an AD account's primary group from the
// account's own SID and its primaryGroupID: same domain, different RID.
func PrimaryGroupSID(accountSID, primaryGroupID string) (string, error) {
	if _, err := strconv.ParseUint(primaryGroupID, 10, 32); err != nil {
		return "", fmt.Errorf("primaryGroupID %q: %w", primaryGroupID, ErrMalformed)
	}
	i := strings.LastIndexByte(accountSID, '-')
	if i < 0 {
		return "", fmt.Errorf("sid %q: %w", accountSID, ErrMalformed)
	}
	return accountSID[:i+1] + primaryGroupID, nil
}

// EscapeBinary escapes every byte for use as an LDAP filter assertion value.
func EscapeBinary(b []byte) string {
	var sb strings.Builder
	sb.Grow(3 * len(b))
	for _, v := range b {
		fmt.Fprintf(&sb, `\%02x`, v)
	}
	return sb.String()
}
