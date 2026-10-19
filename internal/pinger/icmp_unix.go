// SPDX-License-Identifier: GPL-2.0-or-later

//go:build unix

package pinger

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protoICMP   = 1
	protoICMPv6 = 58
)

// icmpPinger sends ICMP echo requests using unprivileged datagram ICMP
// sockets where available (Linux ping_group_range, macOS) or raw sockets.
type icmpPinger struct {
	timeout time.Duration
	dgram   bool
}

func newICMP(timeout time.Duration) (Pinger, error) {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		c.Close()
		return &icmpPinger{timeout: timeout, dgram: true}, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrICMPUnavailable, err)
	}
	c.Close()
	return &icmpPinger{timeout: timeout}, nil
}

func (p *icmpPinger) Name() string { return ICMP }

func (p *icmpPinger) Ping(ctx context.Context, addr netip.Addr, count int, _ []uint16) (*Result, error) {
	addr = addr.Unmap()
	v6 := addr.Is6()
	network, laddr, proto := "ip4:icmp", "0.0.0.0", protoICMP
	var reqType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if v6 {
		network, laddr, proto = "ip6:ipv6-icmp", "::", protoICMPv6
		reqType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	if p.dgram {
		network = map[bool]string{false: "udp4", true: "udp6"}[v6]
	}
	conn, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	var dst net.Addr = &net.IPAddr{IP: addr.AsSlice(), Zone: addr.Zone()}
	if p.dgram {
		dst = &net.UDPAddr{IP: addr.AsSlice(), Zone: addr.Zone()}
	}
	p4, p6 := conn.IPv4PacketConn(), conn.IPv6PacketConn()
	if p4 != nil {
		_ = p4.SetControlMessage(ipv4.FlagTTL, true)
	}
	if p6 != nil {
		_ = p6.SetControlMessage(ipv6.FlagHopLimit, true)
	}

	// Linux rewrites the echo ID of datagram sockets and filters replies itself.
	checkID := !(p.dgram && runtime.GOOS == "linux")
	id, seqBase := randID(), randID()
	res := &Result{}
	buf := make([]byte, 1500)
	for i := 0; i < count && ctx.Err() == nil; i++ {
		seq := (seqBase + i) & 0xFFFF
		msg := icmp.Message{Type: reqType, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return res, err
		}
		res.Sent++
		sent := time.Now()
		if _, err := conn.WriteTo(b, dst); err != nil {
			slog.Debug("icmp send failed", "addr", addr, "err", err)
			return res, nil
		}
		_ = conn.SetReadDeadline(sent.Add(p.timeout))
		if ctx.Err() != nil {
			break
		}
		for {
			n, ttl, src, err := readICMP(conn, p4, p6, buf)
			if err != nil {
				break // timeout or cancellation
			}
			if !sameAddr(src, addr) {
				continue
			}
			m, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || m.Type != replyType {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if !ok || echo.Seq != seq || checkID && echo.ID != id {
				continue
			}
			res.addReply(time.Since(sent))
			if ttl > 0 {
				res.TTL = ttl
			}
			break
		}
	}
	return res, nil
}

func readICMP(conn *icmp.PacketConn, p4 *ipv4.PacketConn, p6 *ipv6.PacketConn, buf []byte) (n, ttl int, src net.Addr, err error) {
	switch {
	case p4 != nil:
		var cm *ipv4.ControlMessage
		n, cm, src, err = p4.ReadFrom(buf)
		if cm != nil {
			ttl = cm.TTL
		}
	case p6 != nil:
		var cm *ipv6.ControlMessage
		n, cm, src, err = p6.ReadFrom(buf)
		if cm != nil {
			ttl = cm.HopLimit
		}
	default:
		n, src, err = conn.ReadFrom(buf)
	}
	return
}

func sameAddr(src net.Addr, want netip.Addr) bool {
	var ip net.IP
	switch a := src.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		return false
	}
	got, ok := netip.AddrFromSlice(ip)
	return ok && got.Unmap() == want.WithZone("")
}
