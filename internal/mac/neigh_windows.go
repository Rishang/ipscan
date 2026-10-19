// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package mac

import (
	"context"
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procSendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

// neighbour uses SendARP, which consults the ARP cache and sends an ARP
// request if needed (blocking up to a few seconds). IPv4 only.
func neighbour(_ context.Context, addr netip.Addr) (string, bool) {
	if !addr.Is4() {
		return "", false
	}
	a := addr.As4()
	var buf [8]byte
	size := uint32(len(buf))
	r, _, _ := procSendARP.Call(uintptr(binary.LittleEndian.Uint32(a[:])), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 || size < 6 {
		return "", false
	}
	return FromBytes(buf[:min(size, 8)]), true
}
