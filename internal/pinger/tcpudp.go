// SPDX-License-Identifier: GPL-2.0-or-later

package pinger

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// probePorts are tried in order by the TCP pinger.
var probePorts = []uint16{80, 7, 443, 139, 22}

// minAdaptedTimeout keeps adapted timeouts from becoming unrealistically short
// (LAN RTTs are often below 1ms).
const minAdaptedTimeout = 100 * time.Millisecond

type tcpPinger struct{ timeout time.Duration }

func (p *tcpPinger) Name() string { return TCP }

func (p *tcpPinger) Ping(ctx context.Context, addr netip.Addr, count int, ports []uint16) (*Result, error) {
	res := &Result{}
	var working uint16
	for i := 0; i < count && ctx.Err() == nil; i++ {
		port := probePorts[i%len(probePorts)]
		switch {
		case working != 0:
			port = working
		case i == 0 && len(ports) > 0:
			port = ports[0]
		}
		timeout := p.timeout
		if res.TimeoutAdaptable() {
			timeout = min(max(res.Max*2, minAdaptedTimeout), p.timeout)
		}
		d := net.Dialer{Timeout: timeout}
		res.Sent++
		start := time.Now()
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, port).String())
		rtt := time.Since(start)
		switch classify(err) {
		case errNone:
			closeRST(c)
			working = port
			res.addReply(rtt)
			res.adaptForced = true
		case errRefused: // RST received: the host is up
			res.addReply(rtt)
			res.adaptForced = true
		case errTimeout:
		case errUnreachable, errCanceled:
			return res, nil
		default:
			slog.Debug("tcp ping error", "addr", addr, "port", port, "err", err)
		}
	}
	return res, nil
}

// closeRST closes a TCP connection with a reset to avoid TIME_WAIT buildup.
func closeRST(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// udpProbePort is the classic traceroute base port, normally closed.
const udpProbePort = 33435

type udpPinger struct{ timeout time.Duration }

func (p *udpPinger) Name() string { return UDP }

func (p *udpPinger) Ping(ctx context.Context, addr netip.Addr, count int, _ []uint16) (*Result, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", netip.AddrPortFrom(addr, udpProbePort).String())
	if err != nil {
		if k := classify(err); k == errUnreachable || k == errCanceled {
			return &Result{Sent: 1}, nil
		}
		return nil, err
	}
	defer c.Close()
	enableConnReset(c)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()

	res := &Result{}
	probe := make([]byte, 8)
	buf := make([]byte, 512)
	for i := 0; i < count && ctx.Err() == nil; i++ {
		res.Sent++
		start := time.Now()
		binary.BigEndian.PutUint64(probe, uint64(start.UnixMilli()))
		_ = c.SetDeadline(start.Add(p.timeout))
		if ctx.Err() != nil {
			break
		}
		_, err := c.Write(probe)
		if err == nil {
			_, err = c.Read(buf)
		}
		switch classify(err) {
		case errNone, errRefused: // a reply, or ICMP port unreachable: the host is up
			res.addReply(time.Since(start))
		case errTimeout:
		case errUnreachable, errCanceled:
			return res, nil
		default:
			slog.Debug("udp ping error", "addr", addr, "err", err)
		}
	}
	return res, nil
}
