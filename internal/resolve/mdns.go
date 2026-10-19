// SPDX-License-Identifier: GPL-2.0-or-later

package resolve

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

var mdnsGroup4 = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// ReverseName returns the PTR query name for addr, e.g. "2.0.168.192.in-addr.arpa.".
func ReverseName(addr netip.Addr) string {
	addr = addr.Unmap()
	var sb strings.Builder
	if addr.Is4() {
		b := addr.As4()
		for i := 3; i >= 0; i-- {
			sb.WriteString(strconv.Itoa(int(b[i])))
			sb.WriteByte('.')
		}
		sb.WriteString("in-addr.arpa.")
		return sb.String()
	}
	const hex = "0123456789abcdef"
	b := addr.As16()
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xF])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// buildPTRQuery builds a standard DNS PTR query for name with the given ID.
func buildPTRQuery(id uint16, name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parsePTRResponse extracts the PTR target for name from a DNS response,
// validating the message ID and that the answer is for the queried name.
func parsePTRResponse(msg []byte, id uint16, name string) (string, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return "", false
	}
	// mDNS responders may set ID 0 in multicast responses; accept only exact IDs
	// for unicast replies (legacy unicast echoes the ID).
	if h.ID != id {
		return "", false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", false
	}
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return "", false
		}
		if ah.Type != dnsmessage.TypePTR || !strings.EqualFold(ah.Name.String(), name) {
			if err := p.SkipAnswer(); err != nil {
				return "", false
			}
			continue
		}
		r, err := p.PTRResource()
		if err != nil {
			return "", false
		}
		host := strings.TrimSuffix(r.PTR.String(), ".")
		return host, host != ""
	}
}

// MDNS resolves the hostname of addr via multicast DNS (e.g. "macbook.local").
// The query is sent from an ephemeral port as a "legacy unicast" query, both to
// the mDNS group (IPv4) and directly to the host.
func MDNS(ctx context.Context, addr netip.Addr, timeout time.Duration) (string, error) {
	addr = addr.Unmap()
	network := "udp4"
	if addr.Is6() {
		network = "udp6"
	}
	c, err := net.ListenUDP(network, nil)
	if err != nil {
		return "", err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()

	id := uint16(rand.UintN(0x10000))
	name := ReverseName(addr)
	q, err := buildPTRQuery(id, name)
	if err != nil {
		return "", err
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	direct := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 5353))
	sent := false
	if _, err := c.WriteToUDP(q, direct); err == nil {
		sent = true
	}
	if addr.Is4() {
		_ = ipv4.NewPacketConn(c).SetMulticastTTL(1)
		if _, err := c.WriteToUDP(q, mdnsGroup4); err == nil {
			sent = true
		}
	}
	if !sent {
		return "", errors.New("mdns: cannot send query")
	}
	buf := make([]byte, 9000)
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return "", err
		}
		if host, ok := parsePTRResponse(buf[:n], id, name); ok {
			return host, nil
		}
	}
}
