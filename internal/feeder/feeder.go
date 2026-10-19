// SPDX-License-Identifier: GPL-2.0-or-later

// Package feeder produces scan targets from ranges, random addresses, files and target expressions.
package feeder

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"

	"github.com/noobi/ipscan-go/internal/netutil"
)

// Subject is a single host to be scanned.
type Subject struct {
	Addr netip.Addr
	// Ports explicitly requested for this host (e.g. "10.0.0.1:8080" in a file).
	Ports []uint16
}

// Feeder produces scan subjects. Feeders are not safe for concurrent use.
type Feeder interface {
	// Next returns the next subject, or false when exhausted.
	Next() (Subject, bool)
	// Size is the total number of subjects (may be approximate/huge for IPv6).
	Size() float64
	// Name is a short identifier such as "range" or "file".
	Name() string
	// Info is a human readable description, e.g. "10.0.0.1 - 10.0.0.254".
	Info() string
}

// Resolver resolves hostnames to addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultResolver uses the system resolver and prefers IPv4 results.
func DefaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Unmap().Is4() {
			out = append(out, a.Unmap())
		}
	}
	for _, a := range addrs {
		if !a.Unmap().Is4() {
			out = append(out, a)
		}
	}
	return out, nil
}

// Percent computes progress as a 0..100 integer.
func Percent(done, size float64) int {
	if size <= 0 || math.IsInf(size, 0) {
		return 0
	}
	return int(math.Min(100, math.Round(done*100/size)))
}

// ---------------------------------------------------------------- Range

// Range iterates inclusively from Start to End; if Start > End it iterates backwards.
type Range struct {
	start, end netip.Addr
	cur        netip.Addr
	reverse    bool
	done       bool
}

// NewRange creates a range feeder. Both addresses must be of the same family.
func NewRange(start, end netip.Addr) (*Range, error) {
	start, end = start.Unmap(), end.Unmap()
	if !start.IsValid() || !end.IsValid() {
		return nil, errors.New("malformed IP address")
	}
	if start.BitLen() != end.BitLen() {
		return nil, errors.New("start and end addresses must be of the same IP version")
	}
	return &Range{start: start, end: end, cur: start, reverse: start.Compare(end) > 0}, nil
}

func (r *Range) Next() (Subject, bool) {
	if r.done {
		return Subject{}, false
	}
	a := r.cur
	if a == r.end {
		r.done = true
	} else if r.reverse {
		r.cur = a.Prev()
	} else {
		r.cur = a.Next()
	}
	return Subject{Addr: a}, true
}

func (r *Range) Size() float64 { return netutil.Distance(r.start, r.end) + 1 }
func (r *Range) Name() string  { return "range" }
func (r *Range) Info() string  { return r.start.String() + " - " + r.end.String() }

// ---------------------------------------------------------------- Random

// Random generates Count random addresses; bits set in Mask are taken from Prototype.
type Random struct {
	proto netip.Addr
	mask  netutil.Mask
	count int
	n     int
}

// NewRandom creates a random feeder. Duplicates are possible, as in the original.
func NewRandom(proto netip.Addr, mask netutil.Mask, count int) (*Random, error) {
	proto = proto.Unmap()
	if !proto.IsValid() {
		return nil, errors.New("malformed IP address")
	}
	if len(mask) != len(proto.AsSlice()) {
		return nil, errors.New("netmask and base IP belong to different IP versions")
	}
	if count <= 0 {
		return nil, errors.New("count of random addresses must be positive")
	}
	return &Random{proto: proto, mask: mask, count: count}, nil
}

func (r *Random) Next() (Subject, bool) {
	if r.n >= r.count {
		return Subject{}, false
	}
	r.n++
	b := make([]byte, len(r.mask))
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	netutil.MaskPrototype(b, r.mask, r.proto.AsSlice())
	a, _ := netip.AddrFromSlice(b)
	return Subject{Addr: a}, true
}

func (r *Random) Size() float64 { return float64(r.count) }
func (r *Random) Name() string  { return "random" }
func (r *Random) Info() string {
	return fmt.Sprintf("%d: %s / %s", r.count, r.proto, r.mask)
}

// ---------------------------------------------------------------- List

// List feeds a fixed list of subjects (file contents, single hosts).
type List struct {
	name, info string
	items      []Subject
	i          int
}

// NewList creates a list feeder.
func NewList(name, info string, items []Subject) *List {
	return &List{name: name, info: info, items: items}
}

func (l *List) Next() (Subject, bool) {
	if l.i >= len(l.items) {
		return Subject{}, false
	}
	l.i++
	return l.items[l.i-1], true
}

func (l *List) Size() float64 { return float64(len(l.items)) }
func (l *List) Name() string  { return l.name }
func (l *List) Info() string  { return l.info }

// ---------------------------------------------------------------- Multi

// Multi chains several feeders.
type Multi struct {
	feeders []Feeder
	i       int
}

// NewMulti chains feeders; with a single feeder it returns that feeder.
func NewMulti(fs ...Feeder) Feeder {
	if len(fs) == 1 {
		return fs[0]
	}
	return &Multi{feeders: fs}
}

func (m *Multi) Next() (Subject, bool) {
	for m.i < len(m.feeders) {
		if s, ok := m.feeders[m.i].Next(); ok {
			return s, true
		}
		m.i++
	}
	return Subject{}, false
}

func (m *Multi) Size() float64 {
	t := 0.0
	for _, f := range m.feeders {
		t += f.Size()
	}
	return t
}

func (m *Multi) Name() string { return "targets" }

func (m *Multi) Info() string {
	parts := make([]string, len(m.feeders))
	for i, f := range m.feeders {
		parts[i] = f.Info()
	}
	return strings.Join(parts, ", ")
}
