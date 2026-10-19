// SPDX-License-Identifier: GPL-2.0-or-later

package pinger

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestResultStats(t *testing.T) {
	r := &Result{Sent: 3}
	if r.Alive() || r.Avg() != 0 || r.LossPercent() != 100 || r.TimeoutAdaptable() {
		t.Errorf("empty result: %+v", r)
	}
	r.addReply(10 * time.Millisecond)
	r.addReply(30 * time.Millisecond)
	if !r.Alive() || r.Avg() != 20*time.Millisecond || r.Min != 10*time.Millisecond || r.Max != 30*time.Millisecond {
		t.Errorf("stats: %+v avg=%v", r, r.Avg())
	}
	if r.Lost() != 1 || r.LossPercent() != 33 || r.TimeoutAdaptable() {
		t.Errorf("loss: %d %d", r.Lost(), r.LossPercent())
	}
	r.Sent++
	r.addReply(20 * time.Millisecond)
	if !r.TimeoutAdaptable() {
		t.Error("3 replies should allow timeout adaptation")
	}
}

// Regression: the Java version merged only packet counts, dropping timings and TTL.
func TestMergeKeepsAllFields(t *testing.T) {
	a := &Result{Sent: 1}
	a.addReply(10 * time.Millisecond)
	b := &Result{Sent: 2, TTL: 64}
	b.addReply(4 * time.Millisecond)
	b.addReply(50 * time.Millisecond)
	a.Merge(b)
	if a.Sent != 3 || a.Recv != 3 || a.Min != 4*time.Millisecond || a.Max != 50*time.Millisecond ||
		a.Sum != 64*time.Millisecond || a.TTL != 64 {
		t.Errorf("merged: %+v", a)
	}
	empty := &Result{Sent: 1}
	empty.Merge(&Result{Sent: 1})
	if empty.Sent != 2 || empty.Alive() {
		t.Errorf("merged empty: %+v", empty)
	}
}

func TestNew(t *testing.T) {
	for _, n := range []string{"", Auto, UDP, TCP, Combined} {
		if _, err := New(n, time.Second); err != nil {
			t.Errorf("New(%q): %v", n, err)
		}
	}
	if _, err := New("bogus", time.Second); err == nil {
		t.Error("unknown pinger must fail")
	}
}

func TestClassify(t *testing.T) {
	if classify(nil) != errNone || classify(context.Canceled) != errCanceled {
		t.Error("basic classification")
	}
	_, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Second)
	if classify(err) != errRefused {
		t.Errorf("connection to closed port: %v -> %v", err, classify(err))
	}
	if classify(errors.New("weird")) != errOther {
		t.Error("other")
	}
}

var loopback = netip.MustParseAddr("127.0.0.1")

func TestTCPPingerLocalhost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	p := &tcpPinger{timeout: time.Second}
	r, err := p.Ping(context.Background(), loopback, 3, []uint16{port})
	if err != nil || r.Recv != 3 || r.Sent != 3 {
		t.Errorf("tcp localhost: %+v %v", r, err)
	}
	// No listener on the probe ports: refusals still mean alive.
	r, _ = p.Ping(context.Background(), loopback, 2, nil)
	if !r.Alive() {
		t.Errorf("refused connections should count as alive: %+v", r)
	}
}

func TestUDPPingerLocalhost(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	r, err := (&udpPinger{timeout: time.Second}).Ping(context.Background(), loopback, 2, nil)
	if err != nil || !r.Alive() {
		t.Errorf("udp localhost: %+v %v", r, err)
	}
}

func TestICMPLocalhost(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	p, err := newICMP(time.Second)
	if err != nil {
		t.Skipf("ICMP not permitted here: %v", err)
	}
	r, err := p.Ping(context.Background(), loopback, 2, nil)
	if err != nil || r.Recv != 2 {
		t.Errorf("icmp localhost: %+v %v", r, err)
	}
	if r.TTL == 0 {
		t.Log("TTL not reported on this platform")
	}
}

func TestDeadHost(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	// TEST-NET-1 is never routed; the host must be reported dead quickly.
	dead := netip.MustParseAddr("192.0.2.253")
	for _, name := range []string{UDP, TCP, Combined} {
		p, _ := New(name, 300*time.Millisecond)
		r, err := p.Ping(context.Background(), dead, 2, nil)
		if err == nil && r.Alive() {
			t.Errorf("%s: dead host reported alive: %+v", name, r)
		}
	}
}

func TestPingCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	p, _ := New(Combined, 5*time.Second)
	_, _ = p.Ping(ctx, netip.MustParseAddr("192.0.2.253"), 3, nil)
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("cancellation took %v", el)
	}
}

func TestARPWrapper(t *testing.T) {
	never := MACLookup(func(context.Context, netip.Addr) (string, bool) { return "", false })
	always := MACLookup(func(context.Context, netip.Addr) (string, bool) { return "00:11:22:33:44:55", true })
	dead := &stubPinger{}
	r, _ := WithARP(dead, always).Ping(context.Background(), loopback, 3, nil)
	if !r.Alive() || r.Sent != 2 {
		t.Errorf("arp found: %+v", r)
	}
	r, _ = WithARP(dead, never).Ping(context.Background(), loopback, 3, nil)
	if r.Alive() {
		t.Errorf("arp not found: %+v", r)
	}
	r, _ = WithARP(&stubPinger{alive: true}, never).Ping(context.Background(), loopback, 3, nil)
	if r.Recv != 2 || r.TTL != 64 {
		t.Errorf("trigger alive: %+v", r)
	}
}

type stubPinger struct{ alive bool }

func (s *stubPinger) Name() string { return "stub" }
func (s *stubPinger) Ping(_ context.Context, _ netip.Addr, count int, _ []uint16) (*Result, error) {
	r := &Result{Sent: count}
	if s.alive {
		for range count {
			r.addReply(time.Millisecond)
		}
		r.TTL = 64
	}
	return r, nil
}
