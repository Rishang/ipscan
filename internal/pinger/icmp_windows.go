// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package pinger

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows ICMP API (iphlpapi.dll) works without administrator rights.
var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmp6SendEcho2  = iphlpapi.NewProc("Icmp6SendEcho2")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

type winICMP struct{ timeout time.Duration }

func newICMP(timeout time.Duration) (Pinger, error) {
	if err := procIcmpSendEcho.Find(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrICMPUnavailable, err)
	}
	return &winICMP{timeout: timeout}, nil
}

func (p *winICMP) Name() string { return ICMP }

func (p *winICMP) Ping(ctx context.Context, addr netip.Addr, count int, _ []uint16) (*Result, error) {
	addr = addr.Unmap()
	create := procIcmpCreateFile
	if addr.Is6() {
		create = procIcmp6CreateFile
	}
	h, _, callErr := create.Call()
	if windows.Handle(h) == windows.InvalidHandle || h == 0 {
		return nil, fmt.Errorf("IcmpCreateFile: %w", callErr)
	}
	defer procIcmpCloseHandle.Call(h)

	// Reply buffer: reply struct + request data + 8 bytes ICMP error + IO_STATUS_BLOCK.
	reply := make([]byte, 128+len(payload))
	timeoutMs := uintptr(max(1, p.timeout.Milliseconds()))
	res := &Result{}
	for i := 0; i < count && ctx.Err() == nil; i++ {
		res.Sent++
		var ok bool
		var rtt time.Duration
		var ttl int
		if addr.Is4() {
			ok, rtt, ttl = echo4(h, addr, reply, timeoutMs)
		} else {
			ok, rtt = echo6(h, addr, reply, timeoutMs)
		}
		if ok {
			res.addReply(rtt)
			if ttl > 0 {
				res.TTL = ttl
			}
		}
	}
	return res, nil
}

// echo4 calls IcmpSendEcho and parses ICMP_ECHO_REPLY:
// Address u32, Status u32, RoundTripTime u32, DataSize u16, Reserved u16,
// Data ptr, Options{Ttl u8, Tos u8, Flags u8, OptionsSize u8, OptionsData ptr}.
func echo4(h uintptr, addr netip.Addr, reply []byte, timeoutMs uintptr) (bool, time.Duration, int) {
	a := addr.As4()
	n, _, _ := procIcmpSendEcho.Call(h,
		uintptr(binary.LittleEndian.Uint32(a[:])), // IPAddr in network byte order
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), timeoutMs)
	if n == 0 {
		return false, 0, 0
	}
	status := binary.LittleEndian.Uint32(reply[4:8])
	if status != 0 || [4]byte(reply[0:4]) != a { // reject relayed errors from routers
		return false, 0, 0
	}
	rtt := time.Duration(binary.LittleEndian.Uint32(reply[8:12])) * time.Millisecond
	ttlOff := 16 + unsafe.Sizeof(uintptr(0))
	return true, rtt, int(reply[ttlOff])
}

// echo6 calls Icmp6SendEcho2 and parses ICMPV6_ECHO_REPLY: a packed
// IPV6_ADDRESS_EX (port u16, flowinfo u32, addr [16]byte, scope u32) followed
// by Status u32 at offset 28 and RoundTripTime u32 at offset 32.
func echo6(h uintptr, addr netip.Addr, reply []byte, timeoutMs uintptr) (bool, time.Duration) {
	src := windows.RawSockaddrInet6{Family: windows.AF_INET6}
	dst := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: addr.As16(), Scope_id: zoneIndex(addr.Zone())}
	n, _, _ := procIcmp6SendEcho2.Call(h, 0, 0, 0,
		uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), timeoutMs)
	if n == 0 {
		return false, 0
	}
	if binary.LittleEndian.Uint32(reply[28:32]) != 0 || [16]byte(reply[6:22]) != addr.As16() {
		return false, 0
	}
	return true, time.Duration(binary.LittleEndian.Uint32(reply[32:36])) * time.Millisecond
}

func zoneIndex(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if n, err := strconv.Atoi(zone); err == nil {
		return uint32(n)
	}
	if ifc, err := net.InterfaceByName(zone); err == nil {
		return uint32(ifc.Index)
	}
	return 0
}
