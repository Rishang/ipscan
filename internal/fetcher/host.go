// SPDX-License-Identifier: GPL-2.0-or-later

package fetcher

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/noobi/ipscan-go/internal/config"
	"github.com/noobi/ipscan-go/internal/feeder"
	"github.com/noobi/ipscan-go/internal/mac"
	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/netutil"
	"github.com/noobi/ipscan-go/internal/pinger"
)

// Env is the immutable, shared environment of one scan.
type Env struct {
	Cfg       *config.Config
	Ports     model.PortList
	Pinger    pinger.Pinger // nil disables pinging
	LANPinger pinger.Pinger // Pinger wrapped with ARP detection for local IPv4 hosts
	Ifaces    []netutil.IfaceAddr
	Resolver  *net.Resolver
	MACLookup pinger.MACLookup
}

// NewEnv prepares a scan environment. With noPing, hosts are not pinged and
// all fetchers run for every host.
func NewEnv(cfg *config.Config, noPing bool) (*Env, error) {
	ports, err := model.ParsePorts(cfg.Scanner.Ports)
	if err != nil {
		return nil, err
	}
	env := &Env{
		Cfg:       cfg,
		Ports:     ports,
		Ifaces:    netutil.CachedInterfaces(),
		Resolver:  net.DefaultResolver,
		MACLookup: mac.Lookup,
	}
	if !noPing {
		if env.Pinger, err = pinger.New(cfg.Scanner.Pinger, cfg.Scanner.PingTimeout()); err != nil {
			return nil, err
		}
		env.LANPinger = pinger.WithARP(env.Pinger, env.MACLookup)
	}
	return env, nil
}

// Host is the per-host scan state shared between fetchers. A Host is used by
// a single goroutine; results of expensive probes are computed lazily once.
type Host struct {
	env       *Env
	Addr      netip.Addr
	Requested []uint16
	Iface     netutil.IfaceAddr
	Local     bool // on a directly attached network
	Type      model.ResultType
	Aborted   bool

	ping                 *pinger.Result
	pinged               bool
	open, filtered       []uint16
	portsDone, portsSome bool
	mac                  string
	macDone              bool
}

// NewHost creates the state for one subject.
func NewHost(env *Env, s feeder.Subject) *Host {
	h := &Host{env: env, Addr: s.Addr.Unmap(), Requested: s.Ports}
	h.Iface, h.Local = netutil.FindLocal(env.Ifaces, h.Addr)
	return h
}

// Env returns the scan environment.
func (h *Host) Env() *Env { return h.env }

func (h *Host) setType(t model.ResultType) {
	if t > h.Type {
		h.Type = t
	}
}

// Ping pings the host once and caches the result; nil if pinging is disabled.
func (h *Host) Ping(ctx context.Context) *pinger.Result {
	if h.pinged || h.env.Pinger == nil {
		return h.ping
	}
	h.pinged = true
	p := h.env.Pinger
	if h.Local && !h.Iface.Loopback && h.Addr.Is4() {
		p = h.env.LANPinger
	}
	r, err := p.Ping(ctx, h.Addr, h.env.Cfg.Scanner.PingCount, h.Requested)
	if err != nil {
		slog.Debug("ping failed", "addr", h.Addr, "err", err)
		r = &pinger.Result{Sent: 1}
	}
	h.ping = r
	if r.Alive() {
		h.setType(model.Alive)
	} else {
		h.setType(model.Dead)
	}
	return r
}

// PortTimeout is the connect timeout, adapted to the measured ping RTT if
// enabled and a trustworthy ping result exists.
func (h *Host) PortTimeout() time.Duration {
	s := &h.env.Cfg.Scanner
	if s.AdaptPortTimeout && h.ping.TimeoutAdaptable() {
		return min(max(h.ping.Max*3, s.MinPortTimeout()), s.PortTimeout())
	}
	return s.PortTimeout()
}

// portsToScan returns configured ports followed by requested ones, deduplicated.
func (h *Host) portsToScan() []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	add := func(p uint16) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for p := range h.env.Ports.All() {
		add(p)
	}
	if h.env.Cfg.Scanner.UseRequestedPorts {
		for _, p := range h.Requested {
			add(p)
		}
	}
	return out
}

// ScanPorts probes TCP ports once and caches open and filtered (timed out)
// ports. ok is false if there were no ports to scan.
func (h *Host) ScanPorts(ctx context.Context) (open, filtered []uint16, ok bool) {
	if h.portsDone {
		return h.open, h.filtered, h.portsSome
	}
	h.portsDone = true
	ports := h.portsToScan()
	if len(ports) == 0 {
		return nil, nil, false
	}
	h.portsSome = true
	timeout := h.PortTimeout()
	jobs := make(chan uint16)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range min(h.env.Cfg.Scanner.PortConcurrency, len(ports)) {
		wg.Go(func() {
			for p := range jobs {
				switch probeTCP(ctx, h.Addr, p, timeout) {
				case portOpen:
					mu.Lock()
					h.open = append(h.open, p)
					mu.Unlock()
				case portFiltered:
					mu.Lock()
					h.filtered = append(h.filtered, p)
					mu.Unlock()
				}
			}
		})
	}
feed:
	for _, p := range ports {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	slices.Sort(h.open)
	slices.Sort(h.filtered)
	if len(h.open) > 0 {
		h.setType(model.WithPorts)
	}
	return h.open, h.filtered, true
}

type portState int

const (
	portClosed portState = iota
	portOpen
	portFiltered
)

func probeTCP(ctx context.Context, addr netip.Addr, port uint16, timeout time.Duration) portState {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, port).String())
	if err == nil {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
		return portOpen
	}
	var ne net.Error
	if ctx.Err() == nil && (errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()) {
		return portFiltered
	}
	return portClosed
}

// MAC returns the host's MAC address (canonical form) for local hosts.
func (h *Host) MAC(ctx context.Context) string {
	if !h.macDone {
		h.macDone = true
		if h.Local {
			h.mac, _ = h.env.MACLookup(ctx, h.Addr)
		}
	}
	return h.mac
}
