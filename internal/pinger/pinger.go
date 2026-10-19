// SPDX-License-Identifier: GPL-2.0-or-later

// Package pinger implements ICMP, TCP, UDP, combined and ARP host liveness probes.
package pinger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Pinger checks whether a host is alive. Implementations are safe for
// concurrent use and return promptly when ctx is cancelled.
type Pinger interface {
	// Ping sends count probes to addr. ports are ports requested for this
	// host, which some pingers may probe first. A returned error means the
	// probe could not be performed at all (not that the host is dead).
	Ping(ctx context.Context, addr netip.Addr, count int, ports []uint16) (*Result, error)
}

// Pinger names accepted by New.
const (
	Auto     = "auto"
	ICMP     = "icmp"
	UDP      = "udp"
	TCP      = "tcp"
	Combined = "combined"
)

// Names lists all selectable pingers.
var Names = []string{Auto, ICMP, UDP, TCP, Combined}

// Descriptions of the pingers, for help output.
var Descriptions = map[string]string{
	Auto:     "ICMP if permitted, otherwise combined UDP+TCP",
	ICMP:     "ICMP echo (unprivileged ping socket, raw socket or Windows ICMP API)",
	UDP:      "UDP probe to a closed port, alive on ICMP port unreachable or any reply",
	TCP:      "TCP connect to ports 80, 7, 443, 139, 22; refused connections count as alive",
	Combined: "UDP first, falling back to TCP; works without privileges",
}

// ErrICMPUnavailable is returned when ICMP sockets cannot be opened.
var ErrICMPUnavailable = errors.New("ICMP is not permitted for this user " +
	"(on Linux allow it via sysctl net.ipv4.ping_group_range or `sudo setcap cap_net_raw+ep $(command -v ipscan)`; " +
	"or use --pinger combined)")

// New creates a pinger by name with the given per-probe timeout.
func New(name string, timeout time.Duration) (Pinger, error) {
	switch strings.ToLower(name) {
	case "", Auto:
		p, err := newICMP(timeout)
		if err == nil {
			return p, nil
		}
		slog.Info("ICMP unavailable, falling back to combined UDP+TCP pinger", "reason", err)
		return newCombined(timeout), nil
	case ICMP:
		return newICMP(timeout)
	case UDP:
		return &udpPinger{timeout: timeout}, nil
	case TCP:
		return &tcpPinger{timeout: timeout}, nil
	case Combined:
		return newCombined(timeout), nil
	}
	return nil, fmt.Errorf("unknown pinger %q (available: %s)", name, strings.Join(Names, ", "))
}

// payload is the data sent in ICMP echo requests.
var payload = []byte("ipscan-go ping payload 0123456789")

func randID() int { return rand.IntN(0x10000) }

// ---------------------------------------------------------------- error classification

type errKind int

const (
	errNone errKind = iota
	errRefused
	errTimeout
	errUnreachable
	errCanceled
	errOther
)

// classify maps socket errors to probe outcomes using error codes rather than
// (locale-dependent) message text.
func classify(err error) errKind {
	var ne net.Error
	switch {
	case err == nil:
		return errNone
	case isRefused(err):
		return errRefused
	case isUnreachable(err):
		return errUnreachable
	case errors.Is(err, context.Canceled):
		return errCanceled
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return errTimeout
	}
	return errOther
}

// ---------------------------------------------------------------- combined

type combinedPinger struct {
	udp *udpPinger
	tcp *tcpPinger
}

func newCombined(timeout time.Duration) *combinedPinger {
	return &combinedPinger{udp: &udpPinger{timeout: timeout}, tcp: &tcpPinger{timeout: timeout}}
}

func (p *combinedPinger) Ping(ctx context.Context, addr netip.Addr, count int, ports []uint16) (*Result, error) {
	n1 := max(1, count/2)
	r, err := p.udp.Ping(ctx, addr, n1, ports)
	if err == nil && r.Alive() {
		if count > n1 {
			if r2, err := p.udp.Ping(ctx, addr, count-n1, ports); err == nil {
				r.Merge(r2)
			}
		}
		return r, nil
	}
	if ctx.Err() != nil {
		return &Result{}, nil
	}
	return p.tcp.Ping(ctx, addr, count, ports)
}

// ---------------------------------------------------------------- ARP

// MACLookup returns the MAC address of addr from the neighbour table.
type MACLookup func(ctx context.Context, addr netip.Addr) (string, bool)

type arpPinger struct {
	trigger Pinger
	lookup  MACLookup
}

// WithARP wraps a pinger for hosts on a directly attached network: a host is
// also considered alive when it answered ARP (has a neighbour table entry),
// even if it drops the trigger probes.
func WithARP(trigger Pinger, lookup MACLookup) Pinger {
	return &arpPinger{trigger: trigger, lookup: lookup}
}

func (p *arpPinger) Ping(ctx context.Context, addr netip.Addr, count int, ports []uint16) (*Result, error) {
	n := max(1, count-count/2)
	res := &Result{}
	for i := 0; i < n && ctx.Err() == nil; i++ {
		start := time.Now()
		tr, _ := p.trigger.Ping(ctx, addr, 1, ports)
		res.Sent++
		if tr.Alive() {
			res.addReply(tr.Sum)
			if tr.TTL > 0 {
				res.TTL = tr.TTL
			}
			continue
		}
		if _, found := p.lookup(ctx, addr); found {
			res.addReply(time.Since(start))
		}
	}
	return res, nil
}
