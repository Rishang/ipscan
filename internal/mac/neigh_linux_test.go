// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package mac

import (
	"net/netip"
	"strings"
	"testing"
)

const procARP = `IP address       HW type     Flags       HW address            Mask     Device
192.168.29.33    0x1         0x2         22:7b:d4:eb:6a:f1     *        wlo1
192.168.29.3     0x1         0x0         00:00:00:00:00:00     *        wlo1
192.168.29.1     0x1         0x2         b4:a7:c6:e5:1c:1c     *        wlo1
`

func TestParseProcARP(t *testing.T) {
	tests := map[string]string{"192.168.29.1": "B4:A7:C6:E5:1C:1C", "192.168.29.33": "22:7B:D4:EB:6A:F1"}
	for ip, want := range tests {
		if got, ok := parseProcARP(strings.NewReader(procARP), netip.MustParseAddr(ip)); !ok || got != want {
			t.Errorf("%s = %q,%v", ip, got, ok)
		}
	}
	// incomplete entry, and prefix of another address
	for _, ip := range []string{"192.168.29.3", "192.168.29.2"} {
		if _, ok := parseProcARP(strings.NewReader(procARP), netip.MustParseAddr(ip)); ok {
			t.Errorf("%s should not be found", ip)
		}
	}
}
