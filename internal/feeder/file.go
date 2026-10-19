// SPDX-License-Identifier: GPL-2.0-or-later

package feeder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ownHost is skipped when extracting hosts, so the header of TXT exports
// ("https://angryip.org") does not end up being scanned.
const ownHost = "angryip.org"

// candidate finds things that may be IPv4 addresses, IPv6 addresses or
// hostnames. RE2 has no lookaround, so boundaries are validated in code.
var candidate = regexp.MustCompile(
	`(?i)(\d{1,3}(?:\.\d{1,3}){3})` + // 1: IPv4
		`|([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}(?:%[0-9a-z]+)?)` + // 2: IPv6
		`|((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]{2,}\.?)`) // 3: hostname

var portSuffix = regexp.MustCompile(`^:(\d{1,5})`)

// Found is a host extracted from text, with ports requested via host:port.
type Found struct {
	Host  string // as written in the text (address or hostname)
	Addr  netip.Addr
	Ports []uint16
}

// ExtractHosts finds IPv4/IPv6 addresses and hostnames in arbitrary text,
// e.g. logs, CSV or previous exports. Duplicates are merged, order preserved.
// Hostnames are returned with an invalid Addr; resolve them separately.
func ExtractHosts(text string) []Found {
	var out []Found
	index := map[string]int{}
	for _, m := range candidate.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[0], m[1]
		host := text[start:end]
		var addr netip.Addr
		switch {
		case m[2] >= 0:
			if !ipv4Boundary(text, start, end) {
				continue
			}
			var ok bool
			if addr, ok = parseIPv4Lenient(host); !ok {
				continue
			}
		case m[4] >= 0:
			if !wordBoundary(text, start, end, ":") {
				continue
			}
			a, err := netip.ParseAddr(host)
			if err != nil || !a.Is6() {
				continue
			}
			addr = a
		default:
			if !wordBoundary(text, start, end, ".") || !isHostname(host) {
				continue
			}
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if host == ownHost {
				continue
			}
		}
		var port uint16
		if addr.Is4() || !addr.IsValid() {
			if pm := portSuffix.FindStringSubmatch(text[end:]); pm != nil && !isDigitAt(text, end+len(pm[0])) {
				if n, _ := strconv.Atoi(pm[1]); n >= 1 && n <= 65535 {
					port = uint16(n)
				}
			}
		} else if start > 0 && text[start-1] == '[' {
			if pm := portSuffix.FindStringSubmatch(strings.TrimPrefix(text[end:], "]")); pm != nil {
				if n, _ := strconv.Atoi(pm[1]); n >= 1 && n <= 65535 {
					port = uint16(n)
				}
			}
		}
		key := host
		if addr.IsValid() {
			key = addr.String()
		}
		i, seen := index[key]
		if !seen {
			i = len(out)
			index[key] = i
			out = append(out, Found{Host: host, Addr: addr})
		}
		if port != 0 {
			out[i].Ports = append(out[i].Ports, port)
		}
	}
	return out
}

func isDigitAt(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }

func isWordAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ipv4Boundary rejects matches that are part of longer dotted numbers like 3.3.3.3.3.
func ipv4Boundary(s string, start, end int) bool {
	if isWordAt(s, start-1) || isWordAt(s, end) {
		return false
	}
	if start > 0 && s[start-1] == '.' && isDigitAt(s, start-2) {
		return false
	}
	return !(end < len(s) && s[end] == '.' && isDigitAt(s, end+1))
}

// wordBoundary checks that the match is not glued to word characters or extra.
func wordBoundary(s string, start, end int, extra string) bool {
	if isWordAt(s, start-1) || isWordAt(s, end) {
		return false
	}
	if start > 0 && strings.IndexByte(extra, s[start-1]) >= 0 {
		return false
	}
	return !(end < len(s) && strings.IndexByte(extra, s[end]) >= 0)
}

// parseIPv4Lenient parses dotted quads allowing leading zeros (decimal, not octal).
func parseIPv4Lenient(s string) (netip.Addr, bool) {
	var b [4]byte
	for i, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// isHostname requires a non-numeric top-level label so that things like
// "3.3.3.3.3" or "9.9.9.9999" are not treated as hostnames.
func isHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	tld := h[strings.LastIndexByte(h, '.')+1:]
	for _, c := range tld {
		if c < '0' || c > '9' {
			return true
		}
	}
	return false
}

// maxFileSize guards against accidentally feeding huge files.
const maxFileSize = 64 << 20

// NewFile reads a file, extracts hosts and resolves hostnames.
func NewFile(ctx context.Context, path string, resolve Resolver) (*List, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("file %q does not exist or is not a regular file", path)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return NewFromReader(ctx, f, path, resolve)
}

// NewFromReader extracts hosts from r. name is used as feeder info.
func NewFromReader(ctx context.Context, r io.Reader, name string, resolve Resolver) (*List, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize))
	if err != nil {
		return nil, fmt.Errorf("error while reading %s: %w", name, err)
	}
	found := ExtractHosts(string(data))
	items := make([]Subject, 0, len(found))
	seen := map[netip.Addr]int{}
	for _, f := range found {
		addr := f.Addr
		if !addr.IsValid() {
			addrs, err := resolve(ctx, f.Host)
			if err != nil || len(addrs) == 0 {
				slog.Warn("cannot resolve host", "host", f.Host, "err", err)
				continue
			}
			addr = addrs[0]
		}
		if i, ok := seen[addr]; ok {
			items[i].Ports = append(items[i].Ports, f.Ports...)
			continue
		}
		seen[addr] = len(items)
		items = append(items, Subject{Addr: addr, Ports: f.Ports})
	}
	if len(items) == 0 {
		return nil, errors.New("no IP addresses or hostnames found in " + name)
	}
	return NewList("file", fmt.Sprintf("%s (%d hosts)", name, len(items)), items), nil
}
