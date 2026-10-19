// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !windows && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package mac

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

// neighbour falls back to the `arp` command on other platforms.
func neighbour(ctx context.Context, addr netip.Addr) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "arp", "-n", addr.String()).Output()
	if err != nil {
		return "", false
	}
	return Extract(string(out))
}
