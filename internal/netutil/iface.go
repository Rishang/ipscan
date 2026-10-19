// SPDX-License-Identifier: GPL-2.0-or-later

// Package netutil provides IP range, netmask, broadcast and local interface helpers.
package netutil

import (
	"net"
	"net/netip"
	"slices"
	"sync"
)

// IfaceAddr is one address of a local network interface.
type IfaceAddr struct {
	Name         string
	HardwareAddr net.HardwareAddr
	Prefix       netip.Prefix // interface address with its prefix length
	Up           bool
	Loopback     bool
}

// Interfaces returns a snapshot of all local interface addresses.
// The default-route interface (if any) is listed first.
func Interfaces() ([]IfaceAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IfaceAddr
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			out = append(out, IfaceAddr{
				Name:         ifc.Name,
				HardwareAddr: ifc.HardwareAddr,
				Prefix:       netip.PrefixFrom(ip.Unmap().WithZone(""), ones),
				Up:           ifc.Flags&net.FlagUp != 0,
				Loopback:     ifc.Flags&net.FlagLoopback != 0,
			})
		}
	}
	if def, ok := defaultRouteAddr(); ok {
		slices.SortStableFunc(out, func(a, b IfaceAddr) int {
			return boolRank(b.Prefix.Addr() == def) - boolRank(a.Prefix.Addr() == def)
		})
	}
	return out, nil
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// defaultRouteAddr finds the local IPv4 address used for the default route.
// Dialing UDP does not send any packets.
func defaultRouteAddr() (netip.Addr, bool) {
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1, never actually contacted
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

var (
	cacheMu sync.Mutex
	cache   []IfaceAddr
)

// CachedInterfaces returns a process-wide snapshot of interfaces, taken once.
func CachedInterfaces() []IfaceAddr {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cache == nil {
		cache, _ = Interfaces()
		if cache == nil {
			cache = []IfaceAddr{}
		}
	}
	return cache
}

// FindLocal returns the interface address whose subnet contains addr,
// i.e. addr is on a directly attached network. Loopback is included.
func FindLocal(ifaces []IfaceAddr, addr netip.Addr) (IfaceAddr, bool) {
	addr = addr.Unmap().WithZone("")
	for _, ia := range ifaces {
		if ia.Up && ia.Prefix.Masked().Contains(addr) {
			return ia, true
		}
	}
	return IfaceAddr{}, false
}

// DefaultLocal returns the preferred non-loopback IPv4 interface address,
// used to suggest a default scan range.
func DefaultLocal(ifaces []IfaceAddr) (IfaceAddr, bool) {
	for _, ia := range ifaces {
		if ia.Up && !ia.Loopback && ia.Prefix.Addr().Is4() {
			return ia, true
		}
	}
	return IfaceAddr{}, false
}
