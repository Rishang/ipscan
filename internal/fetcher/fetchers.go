// SPDX-License-Identifier: GPL-2.0-or-later

// Package fetcher collects per-host information such as ping time, hostname and open ports.
package fetcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/noobi/ipscan-go/internal/config"
	"github.com/noobi/ipscan-go/internal/mac"
	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/resolve"
)

// Fetcher obtains one piece of information (a column) about a host.
type Fetcher interface {
	ID() string
	Name() string // column header
	Description() string
	Scan(ctx context.Context, h *Host) model.Value
}

type simple struct {
	id, name, desc string
	scan           func(ctx context.Context, h *Host) model.Value
}

func (f *simple) ID() string                                    { return f.id }
func (f *simple) Name() string                                  { return f.name }
func (f *simple) Description() string                           { return f.desc }
func (f *simple) Scan(ctx context.Context, h *Host) model.Value { return f.scan(ctx, h) }

// All returns every available fetcher, configured from cfg, in display order.
func All(cfg *config.Config) []Fetcher {
	return []Fetcher{
		&simple{"ip", "IP", "the scanned IP address (always the first column)", scanIP},
		&simple{"ping", "Ping", "average ping round-trip time", scanPing},
		&simple{"ttl", "TTL", "TTL of ping replies (ICMP only); hints at the hop distance", scanTTL},
		&simple{"packetloss", "Packet Loss", "ping packets lost out of those sent", scanLoss},
		&simple{"hostname", "Hostname", "reverse DNS name (forward-confirmed), then mDNS and NetBIOS on local networks", scanHostname},
		newPorts(cfg),
		&simple{"filtered", "Filtered Ports", "ports that did not respond within the timeout (likely firewalled)", scanFiltered},
		&simple{"mac", "MAC Address", "MAC address from the ARP table (local networks only)", scanMAC(cfg.Fetcher.MACSeparator)},
		&simple{"vendor", "MAC Vendor", "network card vendor derived from the MAC address", scanVendor},
		&simple{"netbios", "NetBIOS Info", `NetBIOS node status as DOMAIN\USER@COMPUTER [MAC]`, scanNetBIOS},
		newPortText("webdetect", "Web detect", "web server software from the HTTP Server header", cfg.Fetcher.WebDetect, false),
		newPortText("httpsender", "HTTP Sender", "sends custom text to a TCP port and extracts a regexp group", cfg.Fetcher.HTTPSender, false),
		newPortText("httpproxy", "HTTP Proxy", "detects open HTTP proxies on port 3128 and on open ports", cfg.Fetcher.HTTPProxy, true),
	}
}

// aliases maps Angry IP Scanner fetcher IDs to the short IDs used here.
var aliases = map[string]string{
	"ping.ttl": "ttl", "ports.filtered": "filtered", "mac.vendor": "vendor",
	"comment": "", "comments": "",
}

// Normalize maps an ID or Java-style "fetcher.xyz" ID to a canonical ID.
func Normalize(id string) string {
	id = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(id), "fetcher."))
	if a, ok := aliases[id]; ok {
		return a
	}
	return id
}

// Select returns the fetchers with the given IDs in order, with "ip" forced
// to be first and duplicates removed.
func Select(all []Fetcher, ids []string) ([]Fetcher, error) {
	byID := map[string]Fetcher{}
	for _, f := range all {
		byID[f.ID()] = f
	}
	out := []Fetcher{byID["ip"]}
	seen := map[string]bool{"ip": true}
	for _, raw := range ids {
		id := Normalize(raw)
		if id == "" || seen[id] {
			continue
		}
		f, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("unknown fetcher %q (see 'ipscan list-fetchers')", raw)
		}
		seen[id] = true
		out = append(out, f)
	}
	return out, nil
}

func textOrNA(s string) model.Value {
	if s == "" {
		return model.NotAvailable
	}
	return model.Text(s)
}

func scanIP(_ context.Context, h *Host) model.Value { return model.IPValue(h.Addr) }

func scanPing(ctx context.Context, h *Host) model.Value {
	r := h.Ping(ctx)
	if !r.Alive() {
		return model.NotAvailable
	}
	return model.Millis(int(r.Avg().Milliseconds()))
}

func scanTTL(ctx context.Context, h *Host) model.Value {
	if r := h.Ping(ctx); r.Alive() && r.TTL > 0 {
		return model.Int(r.TTL)
	}
	return model.NotAvailable
}

func scanLoss(ctx context.Context, h *Host) model.Value {
	r := h.Ping(ctx)
	if r == nil {
		return model.NotAvailable
	}
	return model.Loss(r.Lost(), r.Sent)
}

func scanFiltered(ctx context.Context, h *Host) model.Value {
	_, filtered, ok := h.ScanPorts(ctx)
	if !ok {
		return model.NotScanned
	}
	if len(filtered) == 0 {
		return model.NotAvailable
	}
	return model.PortsValue(filtered)
}

func scanMAC(sep string) func(context.Context, *Host) model.Value {
	return func(ctx context.Context, h *Host) model.Value {
		return textOrNA(mac.WithSeparator(h.MAC(ctx), sep))
	}
}

func scanVendor(ctx context.Context, h *Host) model.Value {
	v, _ := mac.Vendor(h.MAC(ctx))
	return textOrNA(v)
}

func scanNetBIOS(ctx context.Context, h *Host) model.Value {
	info, err := resolve.NetBIOS(ctx, h.Addr, h.PortTimeout())
	if err != nil {
		return model.NotAvailable
	}
	return textOrNA(info.String())
}

func scanHostname(ctx context.Context, h *Host) model.Value {
	if name := reverseDNS(ctx, h); name != "" {
		return model.Text(name)
	}
	if !h.Local || h.Iface.Loopback {
		return model.NotAvailable
	}
	if name, err := resolve.MDNS(ctx, h.Addr, h.PortTimeout()); err == nil {
		return model.Text(name)
	}
	if info, err := resolve.NetBIOS(ctx, h.Addr, h.PortTimeout()); err == nil && info.Computer != "" {
		return model.Text(info.Computer)
	}
	return model.NotAvailable
}

// reverseDNS returns a PTR name only if it resolves back to the address,
// so that attacker-controlled PTR records cannot claim arbitrary names.
func reverseDNS(ctx context.Context, h *Host) string {
	ctx, cancel := context.WithTimeout(ctx, max(h.env.Cfg.Scanner.PortTimeout(), 2*time.Second))
	defer cancel()
	names, err := h.env.Resolver.LookupAddr(ctx, h.Addr.String())
	if err != nil {
		return ""
	}
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		if n == "" {
			continue
		}
		if addrs, err := h.env.Resolver.LookupNetIP(ctx, "ip", n); err == nil {
			if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == h.Addr.WithZone("") }) {
				return n
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- ports

type portsFetcher struct{ count int }

func newPorts(cfg *config.Config) *portsFetcher {
	l, _ := model.ParsePorts(cfg.Scanner.Ports)
	return &portsFetcher{count: l.Len()}
}

func (f *portsFetcher) ID() string { return "ports" }
func (f *portsFetcher) Name() string {
	return "Ports [" + strconv.Itoa(f.count) + "]"
}
func (f *portsFetcher) Description() string { return "open TCP ports out of those scanned" }

func (f *portsFetcher) Scan(ctx context.Context, h *Host) model.Value {
	open, _, ok := h.ScanPorts(ctx)
	if !ok {
		return model.NotScanned
	}
	if len(open) == 0 {
		return model.NotAvailable
	}
	return model.PortsValue(open)
}

// ---------------------------------------------------------------- port text

const (
	maxResponseLines = 100
	maxResponseBytes = 64 << 10
)

type portText struct {
	id, name, desc string
	cfg            config.PortText
	re             *regexp.Regexp
	openPorts      bool // also try ports found open by the ports fetcher
}

func newPortText(id, name, desc string, cfg config.PortText, openPorts bool) *portText {
	re, err := regexp.Compile(cfg.Match)
	if err != nil {
		re = regexp.MustCompile(`$^`) // validated in config; never matches
	}
	return &portText{id: id, name: name, desc: desc, cfg: cfg, re: re, openPorts: openPorts}
}

func (f *portText) ID() string          { return f.id }
func (f *portText) Name() string        { return f.name }
func (f *portText) Description() string { return f.desc }

func (f *portText) ports(ctx context.Context, h *Host) []uint16 {
	def := uint16(f.cfg.Port)
	if f.openPorts {
		open, _, _ := h.ScanPorts(ctx)
		ps := append([]uint16{def}, open...)
		slices.Sort(ps)
		return slices.Compact(ps)
	}
	if len(h.Requested) > 0 {
		return h.Requested
	}
	return []uint16{def}
}

func (f *portText) Scan(ctx context.Context, h *Host) model.Value {
	for _, p := range f.ports(ctx, h) {
		if ctx.Err() != nil {
			break
		}
		if res, ok := f.probe(ctx, h, p); ok {
			h.setType(model.WithPorts)
			if f.openPorts {
				res = strconv.Itoa(int(p)) + ": " + res
			}
			return model.Text(res)
		}
	}
	return model.NotAvailable
}

func (f *portText) probe(ctx context.Context, h *Host, port uint16) (string, bool) {
	d := net.Dialer{Timeout: h.PortTimeout()}
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(h.Addr, port).String())
	if err != nil {
		return "", false
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(2 * h.env.Cfg.Scanner.PortTimeout()))
	if _, err := io.WriteString(c, f.cfg.Send); err != nil {
		return "", false
	}
	sc := bufio.NewScanner(io.LimitReader(c, maxResponseBytes))
	sc.Buffer(make([]byte, 4096), maxResponseBytes)
	for i := 0; i < maxResponseLines && sc.Scan(); i++ {
		line := strings.TrimRight(sc.Text(), "\r")
		m := f.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if f.cfg.Group < len(m) && m[f.cfg.Group] != "" {
			return strings.TrimSpace(m[f.cfg.Group]), true
		}
		return strconv.Itoa(int(port)), true
	}
	return "", false
}
