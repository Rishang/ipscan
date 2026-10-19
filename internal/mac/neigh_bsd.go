// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package mac

import (
	"context"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// neighbour reads the ARP/NDP table via the routing socket sysctl
// (NET_RT_FLAGS with RTF_LLINFO), without spawning `arp`.
func neighbour(_ context.Context, addr netip.Addr) (string, bool) {
	af := unix.AF_INET
	if addr.Is6() {
		af = unix.AF_INET6
	}
	rib, err := route.FetchRIB(af, unix.NET_RT_FLAGS, unix.RTF_LLINFO)
	if err != nil {
		return "", false
	}
	msgs, err := route.ParseRIB(unix.NET_RT_FLAGS, rib)
	if err != nil {
		return "", false
	}
	want := addr.WithZone("")
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		var dst netip.Addr
		switch a := rm.Addrs[unix.RTAX_DST].(type) {
		case *route.Inet4Addr:
			dst = netip.AddrFrom4(a.IP)
		case *route.Inet6Addr:
			dst = netip.AddrFrom16(a.IP)
		default:
			continue
		}
		if dst != want {
			continue
		}
		if la, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr); ok && len(la.Addr) == 6 {
			return FromBytes(la.Addr), true
		}
	}
	return "", false
}
