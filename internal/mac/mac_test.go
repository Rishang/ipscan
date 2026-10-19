// SPDX-License-Identifier: GPL-2.0-or-later

package mac

import (
	"context"
	"net/netip"
	"testing"
)

func TestExtract(t *testing.T) {
	tests := map[string]string{
		"? (192.168.0.1) at e4:48:c7:ee:28:c2 [ether] on wlan0":                  "E4:48:C7:EE:28:C2",
		"? (192.168.0.1) at 4:48:7:ee:28:2 [ether] on wlan0":                     "04:48:07:EE:28:02",
		"? (10.10.10.96) at c4:2c:3:8:1e:89 on en0 ifscope permanent [ethernet]": "C4:2C:03:08:1E:89",
		"  192.168.1.1           00-11-22-aa-bb-cc     dynamic":                  "00:11:22:AA:BB:CC",
	}
	for in, want := range tests {
		if got, ok := Extract(in); !ok || got != want {
			t.Errorf("Extract(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := Extract("? (10.0.0.1) at (incomplete) on en0"); ok {
		t.Error("incomplete entry must not match")
	}
}

func TestFromBytesAndSeparator(t *testing.T) {
	if FromBytes(nil) != "" || FromBytes([]byte{0, 1, 2, 13}) != "00:01:02:0D" {
		t.Error("FromBytes")
	}
	if WithSeparator("00:01:02:03:04:05", "-") != "00-01-02-03-04-05" {
		t.Error("WithSeparator")
	}
}

func TestVendor(t *testing.T) {
	tests := map[string]string{
		"00:00:01:00:00:00": "XEROX",
		"FC:E5:57:11:22:33": "Nokia",
		"fc-e5-57-11-22-33": "Nokia",
		"fce5.5711.2233":    "Nokia",
	}
	for in, want := range tests {
		if got, ok := Vendor(in); !ok || got != want {
			t.Errorf("Vendor(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "00:00", "zz:zz:zz:zz:zz:zz"} {
		if _, ok := Vendor(bad); ok {
			t.Errorf("Vendor(%q) should not match", bad)
		}
	}
	if n := len(vendors()); n < 30000 {
		t.Errorf("only %d vendors loaded", n)
	}
}

func TestLookupDoesNotPanic(t *testing.T) {
	// Results depend on the host; just exercise the platform code path.
	_, _ = Lookup(context.Background(), netip.MustParseAddr("127.0.0.1"))
	_, _ = Lookup(context.Background(), netip.MustParseAddr("192.0.2.1"))
	_, _ = Lookup(context.Background(), netip.MustParseAddr("2001:db8::1"))
}
