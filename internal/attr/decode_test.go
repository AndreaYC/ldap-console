package attr

import (
	"strings"
	"testing"
	"time"
)

func TestParseGUIDUsesMixedEndian(t *testing.T) {
	in := []byte{
		0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	got, err := ParseGUID(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := "00112233-4455-6677-8899-aabbccddeeff"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if _, err := ParseGUID(in[:15]); err == nil {
		t.Error("15-byte GUID accepted")
	}
}

func TestParseFiletime(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"unix epoch", "116444736000000000", "1970-01-01T00:00:00Z"},
		{"real timestamp", "133000000000000000", "2022-06-18T04:26:40Z"},
		{"zero means never set", "0", "never"},
		{"max int64 means never", "9223372036854775807", "never"},
		{"not a number", "abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFiletime(tt.in, time.UTC)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUACFlags(t *testing.T) {
	// 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE; 66048 = NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
	if got := strings.Join(UACFlags(514), ","); got != "ACCOUNTDISABLE,NORMAL_ACCOUNT" {
		t.Errorf("514 -> %q", got)
	}
	if got := strings.Join(UACFlags(66048), ","); got != "NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD" {
		t.Errorf("66048 -> %q", got)
	}
	if got := UACFlags(0); len(got) != 0 {
		t.Errorf("0 -> %v", got)
	}
}

func TestDescribeGroupType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"-2147483646", "Security · Global"},
		{"-2147483644", "Security · Domain Local"},
		{"-2147483640", "Security · Universal"},
		{"8", "Distribution · Universal"},
		{"2", "Distribution · Global"},
		{"-2147483643", "Security · Domain Local · Builtin"},
		{"nope", ""},
	}
	for _, tt := range tests {
		if got := DescribeGroupType(tt.in); got != tt.want {
			t.Errorf("DescribeGroupType(%s) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRenderDecodesKnownADAttributes(t *testing.T) {
	r := Renderer{Loc: time.UTC}

	sid := r.Render("objectSid", [][]byte{domainAdminsSID})
	if sid[0].Text != "S-1-5-21-1004336348-1177238915-682003330-512" || sid[0].Binary {
		t.Errorf("objectSid rendered as %+v", sid[0])
	}

	uac := r.Render("userAccountControl", [][]byte{[]byte("514")})
	if uac[0].Text != "514" || uac[0].Note != "ACCOUNTDISABLE, NORMAL_ACCOUNT" {
		t.Errorf("userAccountControl rendered as %+v", uac[0])
	}

	pwd := r.Render("pwdLastSet", [][]byte{[]byte("116444736000000000")})
	if pwd[0].Note != "1970-01-01T00:00:00Z" {
		t.Errorf("pwdLastSet note = %q", pwd[0].Note)
	}

	gt := r.Render("groupType", [][]byte{[]byte("-2147483646")})
	if gt[0].Note != "Security · Global" {
		t.Errorf("groupType note = %q", gt[0].Note)
	}
}

func TestRenderAttributeNameMatchingIsCaseInsensitive(t *testing.T) {
	got := Renderer{}.Render("OBJECTSID", [][]byte{domainAdminsSID})
	if got[0].Text != "S-1-5-21-1004336348-1177238915-682003330-512" {
		t.Errorf("got %+v", got[0])
	}
}

func TestRenderMarksDNValuedAttributes(t *testing.T) {
	got := Renderer{}.Render("memberOf", [][]byte{[]byte("CN=Admins,DC=corp,DC=local"), []byte("not a dn")})
	if !got[0].DN {
		t.Error("valid DN in memberOf not flagged")
	}
	if got[1].DN {
		t.Error("unparseable value flagged as DN")
	}
	if (Renderer{}).Render("description", [][]byte{[]byte("CN=x,DC=y")})[0].DN {
		t.Error("DN-looking value in a non-DN attribute flagged")
	}
}

func TestRenderShowsNonUTF8AsBinary(t *testing.T) {
	got := Renderer{}.Render("jpegPhoto", [][]byte{{0xff, 0xd8, 0xff, 0x00}})
	if !got[0].Binary || got[0].Text != "ffd8ff00" || got[0].Note != "4 bytes" {
		t.Errorf("got %+v", got[0])
	}

	long := make([]byte, 200)
	long[0] = 0xff
	got = Renderer{}.Render("thumbnailPhoto", [][]byte{long})
	if !strings.HasSuffix(got[0].Text, "…") || got[0].Note != "200 bytes" {
		t.Errorf("long binary not truncated: %+v", got[0])
	}
}

func TestRenderFallsBackWhenDecoderFails(t *testing.T) {
	got := Renderer{}.Render("objectGUID", [][]byte{{0x01, 0x02}})
	if !got[0].Binary || got[0].Text != "0102" {
		t.Errorf("got %+v", got[0])
	}
}
