// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package pinger

import (
	"errors"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func errno(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

const (
	errorNetworkUnreachable = 1231
	errorHostUnreachable    = 1232
	errorConnectionRefused  = 1225
)

func isRefused(err error) bool {
	switch errno(err) {
	case windows.WSAECONNREFUSED, windows.WSAECONNRESET, errorConnectionRefused:
		return true
	}
	return false
}

func isUnreachable(err error) bool {
	switch errno(err) {
	case windows.WSAEHOSTUNREACH, windows.WSAENETUNREACH, windows.WSAEHOSTDOWN,
		errorHostUnreachable, errorNetworkUnreachable:
		return true
	}
	return false
}

// enableConnReset re-enables reporting of ICMP port unreachable on UDP sockets
// (as WSAECONNRESET), which the Go runtime disables by default.
func enableConnReset(c net.Conn) {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		flag, ret := uint32(1), uint32(0)
		_ = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&flag)), uint32(unsafe.Sizeof(flag)), nil, 0, &ret, nil, 0)
	})
}
