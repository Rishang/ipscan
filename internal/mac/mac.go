// SPDX-License-Identifier: GPL-2.0-or-later

package mac

import (
	"bufio"
	"context"
	_ "embed"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/noobi/ipscan-go/internal/netutil"
)

// Lookup returns the MAC address of addr in canonical form (uppercase,
// colon separated), using the OS neighbour (ARP/NDP) table. Hosts on remote
// networks have no MAC entry. The scanned host's own addresses are resolved
// from the local interfaces.
func Lookup(ctx context.Context, addr netip.Addr) (string, bool) {
	addr = addr.Unmap()
	for _, ia := range netutil.CachedInterfaces() {
		if ia.Prefix.Addr() == addr.WithZone("") && len(ia.HardwareAddr) > 0 {
			return FromBytes(ia.HardwareAddr), true
		}
	}
	m, ok := neighbour(ctx, addr)
	if !ok || m == "00:00:00:00:00:00" {
		return "", false
	}
	return m, true
}

// FromBytes formats raw hardware address bytes.
func FromBytes(b []byte) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(hex[x>>4])
		sb.WriteByte(hex[x&0xF])
	}
	return sb.String()
}

var macPattern = regexp.MustCompile(`(?i)\b([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}\b`)

// Extract finds a MAC address in text (e.g. `arp` output) and canonicalises
// it, adding the leading zeros omitted by BSD tools ("4:48:7:ee:28:2").
func Extract(text string) (string, bool) {
	m := macPattern.FindString(text)
	if m == "" {
		return "", false
	}
	parts := strings.FieldsFunc(strings.ToUpper(m), func(r rune) bool { return r == ':' || r == '-' })
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":"), true
}

// WithSeparator renders a canonical MAC with a different separator.
func WithSeparator(mac, sep string) string { return strings.ReplaceAll(mac, ":", sep) }

//go:embed mac-vendors.txt
var vendorData string

// vendors maps uppercase OUI hex prefixes ("FCE557") to vendor names.
var vendors = sync.OnceValue(func() map[string]string {
	m := make(map[string]string, 40000)
	sc := bufio.NewScanner(strings.NewReader(vendorData))
	for sc.Scan() {
		if line := sc.Text(); len(line) > 6 {
			m[line[:6]] = line[6:]
		}
	}
	return m
})

// Vendor returns the hardware vendor for a MAC address in any common notation.
func Vendor(mac string) (string, bool) {
	var hex []byte
	for i := 0; i < len(mac) && len(hex) < 6; i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			hex = append(hex, c)
		case c >= 'a' && c <= 'f':
			hex = append(hex, c-'a'+'A')
		}
	}
	if len(hex) < 6 {
		return "", false
	}
	v, ok := vendors()[string(hex)]
	return v, ok
}
