// SPDX-License-Identifier: GPL-2.0-or-later

package feeder

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/noobi/ipscan-go/internal/netutil"
)

// ParseTargets builds a feeder from target expressions. Each argument may hold
// several comma-separated targets. Supported forms:
//
//	10.0.0.1                single address (IPv4 or IPv6)
//	10.0.0.1-10.0.0.50      full range (reverse order allowed)
//	10.0.0.1-50             last-octet range
//	10.0-3.1-5.1, 10.0.0.*  per-octet ranges / wildcards (IPv4)
//	10.0.0.0/24             CIDR (also 2001:db8::/120)
//	10.0.0.7/255.255.255.0  address with netmask
//	example.com[/24]        hostname, optionally expanded with a netmask
func ParseTargets(ctx context.Context, args []string, resolve Resolver) (Feeder, error) {
	var feeders []Feeder
	for _, arg := range args {
		for _, tok := range strings.FieldsFunc(arg, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
			f, err := parseTarget(ctx, tok, resolve)
			if err != nil {
				return nil, fmt.Errorf("invalid target %q: %w", tok, err)
			}
			feeders = append(feeders, f)
		}
	}
	if len(feeders) == 0 {
		return nil, fmt.Errorf("no scan targets given")
	}
	return NewMulti(feeders...), nil
}

func parseTarget(ctx context.Context, tok string, resolve Resolver) (Feeder, error) {
	// address or host with netmask / prefix
	if base, mask, ok := strings.Cut(tok, "/"); ok {
		addr, err := hostAddr(ctx, base, resolve)
		if err != nil {
			return nil, err
		}
		m, err := parseMaskFor(addr, mask)
		if err != nil {
			return nil, err
		}
		start, err := netutil.StartOfRange(addr, m)
		if err != nil {
			return nil, err
		}
		end, _ := netutil.EndOfRange(addr, m)
		return NewRange(start, end)
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return NewRange(a, a)
	}
	// full range a-b (IPv6 addresses never contain '-')
	if lo, hi, ok := strings.Cut(tok, "-"); ok {
		a, errA := netip.ParseAddr(lo)
		b, errB := netip.ParseAddr(hi)
		if errA == nil && errB == nil {
			return NewRange(a, b)
		}
	}
	if f, ok, err := parseOctets(tok); ok {
		return f, err
	}
	addr, err := hostAddr(ctx, tok, resolve)
	if err != nil {
		return nil, err
	}
	return NewList("host", tok, []Subject{{Addr: addr}}), nil
}

// ParseRandom builds a random feeder from "BASE/MASK" (e.g. 10.0.0.0/8 or
// 10.0.0.1/255.0.0.255): bits set in the mask are kept from BASE, the rest
// are random.
func ParseRandom(ctx context.Context, spec string, count int, resolve Resolver) (Feeder, error) {
	base, mask, ok := strings.Cut(spec, "/")
	if !ok {
		return nil, fmt.Errorf("random target %q must be BASE/MASK, e.g. 10.0.0.0/8", spec)
	}
	addr, err := hostAddr(ctx, base, resolve)
	if err != nil {
		return nil, err
	}
	m, err := parseMaskFor(addr, mask)
	if err != nil {
		return nil, err
	}
	return NewRandom(addr, m, count)
}

func parseMaskFor(addr netip.Addr, s string) (netutil.Mask, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > addr.BitLen() {
			return nil, fmt.Errorf("prefix length /%d out of range", n)
		}
		return netutil.PrefixMask(n, addr.BitLen()/8), nil
	}
	m, err := netutil.ParseMask(s)
	if err != nil {
		return nil, err
	}
	if len(m) != addr.BitLen()/8 {
		return nil, fmt.Errorf("netmask %s does not match address %s", s, addr)
	}
	return m, nil
}

func hostAddr(ctx context.Context, host string, resolve Resolver) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	if host == "" || strings.ContainsAny(host, "*-") && !isHostnameSyntax(host) {
		return netip.Addr{}, fmt.Errorf("malformed address")
	}
	addrs, err := resolve(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("cannot resolve %s", host)
	}
	return addrs[0], nil
}

func isHostnameSyntax(h string) bool {
	for _, c := range h {
		if !(c == '-' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return !strings.HasPrefix(h, "-") && !strings.HasSuffix(h, "-")
}

// parseOctets handles IPv4 per-octet ranges like 10.0.0.1-50, 10.1-2.*.1.
// ok=false means tok is not in octet syntax at all.
func parseOctets(tok string) (Feeder, bool, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 {
		return nil, false, nil
	}
	var ranges [4][2]int
	for i, p := range parts {
		if p == "*" {
			ranges[i] = [2]int{0, 255}
			continue
		}
		lo, hi, isRange := strings.Cut(p, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, false, nil
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, false, nil
			}
		}
		if a < 0 || a > 255 || b < 0 || b > 255 {
			return nil, true, fmt.Errorf("octet %q out of range 0-255", p)
		}
		if a > b {
			a, b = b, a
		}
		ranges[i] = [2]int{a, b}
	}
	return &octets{tok: tok, r: ranges, cur: [4]int{ranges[0][0], ranges[1][0], ranges[2][0], ranges[3][0]}}, true, nil
}

// octets iterates the cartesian product of per-octet ranges.
type octets struct {
	tok  string
	r    [4][2]int
	cur  [4]int
	done bool
}

func (o *octets) Next() (Subject, bool) {
	if o.done {
		return Subject{}, false
	}
	a := netip.AddrFrom4([4]byte{byte(o.cur[0]), byte(o.cur[1]), byte(o.cur[2]), byte(o.cur[3])})
	i := 3
	for ; i >= 0; i-- {
		if o.cur[i] < o.r[i][1] {
			o.cur[i]++
			break
		}
		o.cur[i] = o.r[i][0]
	}
	o.done = i < 0
	return Subject{Addr: a}, true
}

func (o *octets) Size() float64 {
	n := 1.0
	for _, r := range o.r {
		n *= float64(r[1] - r[0] + 1)
	}
	return n
}

func (o *octets) Name() string { return "range" }
func (o *octets) Info() string { return o.tok }
