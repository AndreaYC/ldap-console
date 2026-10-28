package attr

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// Value is one attribute value prepared for display.
type Value struct {
	Text   string `json:"text"`
	Note   string `json:"note,omitempty"`   // decoded meaning, e.g. UAC flags or a timestamp
	Binary bool   `json:"binary,omitempty"` // Text is a hex preview of raw bytes
	DN     bool   `json:"dn,omitempty"`     // Text is a DN the UI can navigate to
}

// maxHexPreview caps how many raw bytes of a binary value are rendered.
const maxHexPreview = 64

var (
	sidAttrs      = set("objectsid", "sidhistory", "securityidentifier", "tokengroups")
	guidAttrs     = set("objectguid", "msexchmailboxguid", "ms-ds-consistencyguid")
	filetimeAttrs = set("pwdlastset", "lastlogon", "lastlogontimestamp", "lastlogoff",
		"accountexpires", "badpasswordtime", "lockouttime", "msds-userpasswordexpirytimecomputed")
	uacAttrs = set("useraccountcontrol", "msds-user-account-control-computed")
	dnAttrs  = set("member", "memberof", "uniquemember", "manager", "directreports",
		"owner", "managedby", "seealso", "distinguishedname", "objectcategory",
		"creatorsname", "modifiersname", "subschemasubentry", "defaultnamingcontext",
		"namingcontexts", "rootdomainnamingcontext", "configurationnamingcontext",
		"schemanamingcontext", "dsservicename", "serverreferencebl", "msds-memberof")
)

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Renderer turns raw attribute values into display Values. Loc is the
// time zone for decoded timestamps; nil means UTC.
type Renderer struct {
	Loc *time.Location
}

// Render prepares every raw value of attribute name for display.
func (r Renderer) Render(name string, raw [][]byte) []Value {
	key := strings.ToLower(name)
	out := make([]Value, len(raw))
	for i, b := range raw {
		out[i] = r.renderOne(key, b)
	}
	return out
}

func (r Renderer) renderOne(key string, b []byte) Value {
	switch {
	case sidAttrs[key]:
		if s, err := ParseSID(b); err == nil {
			return Value{Text: s}
		}
		return binaryValue(b)
	case guidAttrs[key]:
		if s, err := ParseGUID(b); err == nil {
			return Value{Text: s}
		}
		return binaryValue(b)
	}
	if !isPrintable(b) {
		return binaryValue(b)
	}
	s := string(b)
	v := Value{Text: s}
	switch {
	case filetimeAttrs[key]:
		v.Note = formatFiletime(s, r.loc())
	case uacAttrs[key]:
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			v.Note = strings.Join(UACFlags(uint32(n)), ", ")
		}
	case key == "grouptype":
		v.Note = DescribeGroupType(s)
	case dnAttrs[key]:
		_, err := ldap.ParseDN(s)
		v.DN = err == nil && strings.Contains(s, "=")
	}
	return v
}

func (r Renderer) loc() *time.Location {
	if r.Loc == nil {
		return time.UTC
	}
	return r.Loc
}

func binaryValue(b []byte) Value {
	preview := b
	suffix := ""
	if len(b) > maxHexPreview {
		preview, suffix = b[:maxHexPreview], "…"
	}
	return Value{Text: hex.EncodeToString(preview) + suffix, Note: fmt.Sprintf("%d bytes", len(b)), Binary: true}
}

func isPrintable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
