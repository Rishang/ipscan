// SPDX-License-Identifier: GPL-2.0-or-later

//go:build unix

package pinger

import (
	"errors"
	"net"
	"syscall"
)

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTDOWN)
}

// enableConnReset is only needed on Windows.
func enableConnReset(net.Conn) {}
