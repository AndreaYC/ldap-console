package attr

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// ParseGUID converts a 16-byte AD objectGUID to its canonical string form.
// The first three groups are little-endian, as in Windows' GUID struct.
func ParseGUID(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("guid of %d bytes: %w", len(b), ErrMalformed)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%x-%x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8:10], b[10:]), nil
}

// filetimeEpochOffset is the number of 100ns ticks between 1601-01-01 and 1970-01-01.
const filetimeEpochOffset = 116444736000000000

// formatFiletime renders an AD FILETIME integer (100ns ticks since 1601).
// It returns "never" for the 0 / max sentinels and "" for non-numeric input.
func formatFiletime(s string, loc *time.Location) string {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return ""
	}
	if v == 0 || v == math.MaxInt64 {
		return "never"
	}
	ticks := v - filetimeEpochOffset
	t := time.Unix(ticks/1e7, (ticks%1e7)*100).In(loc)
	return t.Format(time.RFC3339)
}

var uacFlagNames = []struct {
	bit  uint32
	name string
}{
	{0x0001, "SCRIPT"},
	{0x0002, "ACCOUNTDISABLE"},
	{0x0008, "HOMEDIR_REQUIRED"},
	{0x0010, "LOCKOUT"},
	{0x0020, "PASSWD_NOTREQD"},
	{0x0040, "PASSWD_CANT_CHANGE"},
	{0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED"},
	{0x0100, "TEMP_DUPLICATE_ACCOUNT"},
	{0x0200, "NORMAL_ACCOUNT"},
	{0x0800, "INTERDOMAIN_TRUST_ACCOUNT"},
	{0x1000, "WORKSTATION_TRUST_ACCOUNT"},
	{0x2000, "SERVER_TRUST_ACCOUNT"},
	{0x10000, "DONT_EXPIRE_PASSWORD"},
	{0x20000, "MNS_LOGON_ACCOUNT"},
	{0x40000, "SMARTCARD_REQUIRED"},
	{0x80000, "TRUSTED_FOR_DELEGATION"},
	{0x100000, "NOT_DELEGATED"},
	{0x200000, "USE_DES_KEY_ONLY"},
	{0x400000, "DONT_REQ_PREAUTH"},
	{0x800000, "PASSWORD_EXPIRED"},
	{0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
	{0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

// UACFlags lists the userAccountControl flag names set in v, lowest bit first.
func UACFlags(v uint32) []string {
	var out []string
	for _, f := range uacFlagNames {
		if v&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

const (
	groupTypeBuiltin     = 0x1
	groupTypeGlobal      = 0x2
	groupTypeDomainLocal = 0x4
	groupTypeUniversal   = 0x8
	groupTypeSecurity    = 0x80000000
)

// DescribeGroupType renders an AD groupType (a signed 32-bit integer) as
// "Security · Global" style text, or "" when s is not a number.
func DescribeGroupType(s string) string {
	n, err := strconv.ParseInt(s, 10, 32) // AD stores groupType as a signed 32-bit integer
	if err != nil {
		return ""
	}
	v := uint32(int32(n)) // #nosec G115 -- intentional bit reinterpretation: the security flag is the sign bit
	parts := []string{"Distribution"}
	if v&groupTypeSecurity != 0 {
		parts[0] = "Security"
	}
	switch {
	case v&groupTypeGlobal != 0:
		parts = append(parts, "Global")
	case v&groupTypeDomainLocal != 0:
		parts = append(parts, "Domain Local")
	case v&groupTypeUniversal != 0:
		parts = append(parts, "Universal")
	}
	if v&groupTypeBuiltin != 0 {
		parts = append(parts, "Builtin")
	}
	return strings.Join(parts, " · ")
}
