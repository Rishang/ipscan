// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package mac

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"os"
	"strings"
)

// neighbour reads the kernel ARP cache. Entries are filled by the preceding
// ping/port probes. Incomplete entries (flags 0x0) are ignored.
func neighbour(_ context.Context, addr netip.Addr) (string, bool) {
	if !addr.Is4() {
		return "", false // /proc/net/arp has IPv4 only
	}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return "", false
	}
	defer f.Close()
	return parseProcARP(f, addr)
}

// parseProcARP parses /proc/net/arp:
// IP address  HW type  Flags  HW address  Mask  Device
func parseProcARP(r io.Reader, addr netip.Addr) (string, bool) {
	sc := bufio.NewScanner(r)
	ip := addr.String()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[0] != ip || f[2] == "0x0" {
			continue
		}
		return Extract(f[3])
	}
	return "", false
}
