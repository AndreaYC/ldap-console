package attr

import (
	"bytes"
	"testing"
)

// S-1-5-21-1004336348-1177238915-682003330-512 (a typical Domain Admins SID).
var domainAdminsSID = []byte{
	0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x15, 0x00, 0x00, 0x00,
	0xdc, 0xf4, 0xdc, 0x3b,
	0x83, 0x3d, 0x2b, 0x46,
	0x82, 0x8b, 0xa6, 0x28,
	0x00, 0x02, 0x00, 0x00,
}

func TestParseSID(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{"domain group sid", domainAdminsSID, "S-1-5-21-1004336348-1177238915-682003330-512", false},
		{"well-known everyone", []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0}, "S-1-1-0", false},
		{"too short", []byte{0x01, 0x05, 0x00}, "", true},
		{"sub-authority count exceeds data", []byte{0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x15, 0, 0, 0}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSID(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeSIDRoundTripsParseSID(t *testing.T) {
	got, err := EncodeSID("S-1-5-21-1004336348-1177238915-682003330-512")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, domainAdminsSID) {
		t.Errorf("got % x, want % x", got, domainAdminsSID)
	}
}

func TestEncodeSIDRejectsMalformedInput(t *testing.T) {
	for _, in := range []string{"", "S-1", "X-1-5-21", "S-1-5-abc", "S-1-5-99999999999"} {
		if _, err := EncodeSID(in); err == nil {
			t.Errorf("EncodeSID(%q) succeeded, want error", in)
		}
	}
}

func TestPrimaryGroupSIDReplacesRID(t *testing.T) {
	user := "S-1-5-21-1004336348-1177238915-682003330-1105"
	got, err := PrimaryGroupSID(user, "513")
	if err != nil {
		t.Fatal(err)
	}
	if want := "S-1-5-21-1004336348-1177238915-682003330-513"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if _, err := PrimaryGroupSID(user, "x"); err == nil {
		t.Error("non-numeric RID accepted")
	}
}

func TestRIDReturnsLastSubAuthority(t *testing.T) {
	if got := RID("S-1-5-21-1-2-3-513"); got != "513" {
		t.Errorf("got %q", got)
	}
	if got := RID("garbage"); got != "" {
		t.Errorf("got %q for garbage", got)
	}
}

func TestEscapeBinaryFilterValue(t *testing.T) {
	if got := EscapeBinary([]byte{0x01, 0xab, 0x00}); got != `\01\ab\00` {
		t.Errorf("got %q", got)
	}
}
