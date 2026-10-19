// SPDX-License-Identifier: GPL-2.0-or-later

package netutil

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// Mask is a network mask in byte form. It may be non-contiguous
// (e.g. 255.0.0.255), which is useful for the random feeder.
type Mask []byte

// ParseMask parses "/N" CIDR notation (4-byte mask for N<=32, 16-byte above)
// or dotted IPv4 notation where an empty octet means 255 ("255...0").
// It never performs DNS lookups.
func ParseMask(s string) (Mask, error) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "/"); ok {
		n, err := strconv.Atoi(rest)
		if err != nil || n < 0 || n > 128 {
			return nil, fmt.Errorf("invalid netmask %q", s)
		}
		size := 4
		if n > 32 {
			size = 16
		}
		return PrefixMask(n, size), nil
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid netmask %q", s)
	}
	m := make(Mask, 4)
	for i, p := range parts {
		if p == "" {
			m[i] = 255
			continue
		}
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid netmask %q", s)
		}
		m[i] = byte(n)
	}
	return m, nil
}

// PrefixMask builds a mask of the given byte size with the first bits set.
func PrefixMask(bits, size int) Mask {
	m := make(Mask, size)
	for i := range m {
		switch {
		case bits >= 8:
			m[i] = 0xFF
			bits -= 8
		case bits > 0:
			m[i] = byte(0xFF << (8 - bits))
			bits = 0
		}
	}
	return m
}

// String renders the mask as an address.
func (m Mask) String() string {
	if a, ok := netip.AddrFromSlice(m); ok {
		return a.String()
	}
	return fmt.Sprintf("%x", []byte(m))
}

var errMaskSize = errors.New("netmask and address belong to different IP versions")

func applyMask(addr netip.Addr, m Mask, op func(a, m byte) byte) (netip.Addr, error) {
	b := addr.AsSlice()
	if len(b) != len(m) {
		return netip.Addr{}, errMaskSize
	}
	for i := range b {
		b[i] = op(b[i], m[i])
	}
	out, _ := netip.AddrFromSlice(b)
	return out, nil
}

// StartOfRange returns addr & mask.
func StartOfRange(addr netip.Addr, m Mask) (netip.Addr, error) {
	return applyMask(addr.Unmap(), m, func(a, m byte) byte { return a & m })
}

// EndOfRange returns addr | ^mask.
func EndOfRange(addr netip.Addr, m Mask) (netip.Addr, error) {
	return applyMask(addr.Unmap(), m, func(a, m byte) byte { return a | ^m })
}

// MaskPrototype combines bytes: where a mask bit is 1 the prototype bit is used,
// otherwise the bit from random is kept. All slices must have equal length.
func MaskPrototype(random, mask, proto []byte) {
	for i := range random {
		random[i] = random[i]&^mask[i] | proto[i]&mask[i]
	}
}

// IsLikelyBroadcast reports whether addr is a network or broadcast address and
// so is probably not assigned to a host. With a known local prefix the check is
// exact (and never skips /31 or /32); otherwise IPv4 addresses ending in .0 or
// .255 are considered broadcast. IPv6 has no broadcast and always returns false.
func IsLikelyBroadcast(addr netip.Addr, prefix netip.Prefix) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	if prefix.IsValid() && prefix.Addr().Is4() {
		if prefix.Bits() > 30 || !prefix.Contains(addr) {
			return false
		}
		net := prefix.Masked().Addr()
		end, _ := EndOfRange(net, PrefixMask(prefix.Bits(), 4))
		return addr == net || addr == end
	}
	last := addr.As4()[3]
	return last == 0 || last == 255
}

// Distance returns |b - a| as a float64, suitable for progress computation of
// arbitrarily large (IPv6) ranges. Addresses of different families return +Inf.
func Distance(a, b netip.Addr) float64 {
	a, b = a.Unmap(), b.Unmap()
	if a.BitLen() != b.BitLen() {
		return math.Inf(1)
	}
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	ab, bb := a.As16(), b.As16()
	var diff [16]byte
	borrow := 0
	for i := 15; i >= 0; i-- {
		d := int(bb[i]) - int(ab[i]) - borrow
		borrow = 0
		if d < 0 {
			d += 256
			borrow = 1
		}
		diff[i] = byte(d)
	}
	f := 0.0
	for _, x := range diff {
		f = f*256 + float64(x)
	}
	return f
}
