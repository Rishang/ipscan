// SPDX-License-Identifier: GPL-2.0-or-later

package netutil

import (
	"math"
	"net/netip"
	"testing"
)

var A = netip.MustParseAddr

func TestParseMask(t *testing.T) {
	tests := map[string]string{
		"255.255.255.255": "255.255.255.255",
		"255...255":       "255.255.255.255",
		"255.0..255":      "255.0.255.255",
		"255...192":       "255.255.255.192",
		"255.0..0":        "255.0.255.0",
		"0.0.0.0":         "0.0.0.0",
		"/0":              "0.0.0.0",
		"/1":              "128.0.0.0",
		"/16":             "255.255.0.0",
		"/24":             "255.255.255.0",
		"/25":             "255.255.255.128",
		"/29":             "255.255.255.248",
		"/32":             "255.255.255.255",
		"/64":             "ffff:ffff:ffff:ffff::",
	}
	for in, want := range tests {
		m, err := ParseMask(in)
		if err != nil {
			t.Errorf("ParseMask(%q): %v", in, err)
			continue
		}
		if m.String() != want {
			t.Errorf("ParseMask(%q) = %s, want %s", in, m, want)
		}
	}
	for _, bad := range []string{"", "/", "/x", "/-1", "/129", "1.2.3", "256.0.0.0", "a.b.c.d", "example.com"} {
		if _, err := ParseMask(bad); err == nil {
			t.Errorf("ParseMask(%q) should fail", bad)
		}
	}
}

func TestRangeByMask(t *testing.T) {
	tests := []struct{ addr, mask, start, end string }{
		{"127.0.1.92", "255.255.255.192", "127.0.1.64", "127.0.1.127"},
		{"127.0.0.15", "255.255.255.255", "127.0.0.15", "127.0.0.15"},
		{"192.10.11.13", "255.255.0.0", "192.10.0.0", "192.10.255.255"},
		{"2001:db8::1234", "/64", "2001:db8::", "2001:db8::ffff:ffff:ffff:ffff"},
	}
	for _, tt := range tests {
		m, _ := ParseMask(tt.mask)
		s, err := StartOfRange(A(tt.addr), m)
		if err != nil || s.String() != tt.start {
			t.Errorf("StartOfRange(%s,%s) = %s,%v", tt.addr, tt.mask, s, err)
		}
		e, err := EndOfRange(A(tt.addr), m)
		if err != nil || e.String() != tt.end {
			t.Errorf("EndOfRange(%s,%s) = %s,%v", tt.addr, tt.mask, e, err)
		}
	}
	m, _ := ParseMask("/24")
	if _, err := StartOfRange(A("::1"), m); err == nil {
		t.Error("expected family mismatch error")
	}
}

// Regression for the Java decrement() borrow bug: netip.Addr.Prev must borrow.
func TestPrevBorrows(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1": "10.0.0.0", "10.0.1.0": "10.0.0.255", "128.0.0.0": "127.255.255.255"} {
		if got := A(in).Prev().String(); got != want {
			t.Errorf("Prev(%s) = %s, want %s", in, got, want)
		}
	}
	if got := A("127.255.255.255").Next().String(); got != "128.0.0.0" {
		t.Errorf("Next = %s", got)
	}
}

func TestMaskPrototype(t *testing.T) {
	tests := []struct{ rnd, mask, proto, want string }{
		{"32.23.34.254", "255.0.0.255", "29.1.2.255", "29.23.34.255"},
		{"250.250.250.250", "0.0.0.0", "29.1.2.255", "250.250.250.250"},
		{"250.250.250.250", "255.255.255.255", "29.128.127.73", "29.128.127.73"},
	}
	for _, tt := range tests {
		b := A(tt.rnd).AsSlice()
		MaskPrototype(b, A(tt.mask).AsSlice(), A(tt.proto).AsSlice())
		if got, _ := netip.AddrFromSlice(b); got.String() != tt.want {
			t.Errorf("MaskPrototype = %s, want %s", got, tt.want)
		}
	}
}

func TestIsLikelyBroadcast(t *testing.T) {
	none := netip.Prefix{}
	p25 := netip.MustParsePrefix("192.168.0.1/25")
	tests := []struct {
		addr   string
		prefix netip.Prefix
		want   bool
	}{
		{"127.0.2.0", none, true},
		{"127.6.32.255", none, true},
		{"127.4.5.6", none, false},
		{"192.168.0.127", p25, true},
		{"192.168.0.0", p25, true},
		{"192.168.0.1", p25, false},
		{"192.168.0.126", p25, false},
		{"10.0.1.0", netip.MustParsePrefix("10.0.0.5/16"), false}, // .0 inside a /16 is a valid host
		{"10.0.0.0", netip.MustParsePrefix("10.0.0.0/31"), false},
		{"10.0.0.1", netip.MustParsePrefix("10.0.0.1/32"), false},
		{"2001:db8::ff", none, false},
		{"2001:db8::", netip.MustParsePrefix("2001:db8::1/64"), false},
	}
	for _, tt := range tests {
		if got := IsLikelyBroadcast(A(tt.addr), tt.prefix); got != tt.want {
			t.Errorf("IsLikelyBroadcast(%s, %v) = %v", tt.addr, tt.prefix, got)
		}
	}
}

func TestDistance(t *testing.T) {
	if d := Distance(A("10.0.0.0"), A("10.0.1.0")); d != 256 {
		t.Errorf("Distance = %v", d)
	}
	if d := Distance(A("10.0.1.0"), A("10.0.0.0")); d != 256 {
		t.Errorf("reverse Distance = %v", d)
	}
	if d := Distance(A("::"), A("::1:0:0:0:0")); d != math.Pow(2, 64) {
		t.Errorf("v6 Distance = %v", d)
	}
	if !math.IsInf(Distance(A("::1"), A("1.2.3.4")), 1) {
		t.Error("mixed families should be +Inf")
	}
}

func TestFindLocal(t *testing.T) {
	ifs := []IfaceAddr{
		{Name: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8"), Up: true, Loopback: true},
		{Name: "eth0", Prefix: netip.MustParsePrefix("192.168.1.10/24"), Up: true},
		{Name: "down0", Prefix: netip.MustParsePrefix("10.9.0.1/16"), Up: false},
	}
	if ia, ok := FindLocal(ifs, A("192.168.1.200")); !ok || ia.Name != "eth0" {
		t.Errorf("FindLocal = %v,%v", ia, ok)
	}
	if _, ok := FindLocal(ifs, A("8.8.8.8")); ok {
		t.Error("8.8.8.8 is not local")
	}
	if _, ok := FindLocal(ifs, A("10.9.0.5")); ok {
		t.Error("down interface must be ignored")
	}
	if ia, ok := DefaultLocal(ifs); !ok || ia.Name != "eth0" {
		t.Errorf("DefaultLocal = %v", ia)
	}
	if _, err := Interfaces(); err != nil {
		t.Errorf("Interfaces: %v", err)
	}
}
