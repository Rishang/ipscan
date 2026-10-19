// SPDX-License-Identifier: GPL-2.0-or-later

package fetcher

import (
	"context"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/noobi/ipscan-go/internal/config"
	"github.com/noobi/ipscan-go/internal/feeder"
	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/netutil"
	"github.com/noobi/ipscan-go/internal/pinger"
)

type fakePinger struct{ alive bool }

func (p *fakePinger) Ping(_ context.Context, _ netip.Addr, count int, _ []uint16) (*pinger.Result, error) {
	r := &pinger.Result{Sent: count}
	if p.alive {
		r.Recv, r.Sum, r.Min, r.Max, r.TTL = count, time.Duration(count)*5*time.Millisecond, 5*time.Millisecond, 5*time.Millisecond, 64
	}
	return r, nil
}

func testEnv(t *testing.T, cfg *config.Config, alive bool) *Env {
	t.Helper()
	env, err := NewEnv(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	env.Pinger = &fakePinger{alive: alive}
	env.LANPinger = env.Pinger
	env.Ifaces = []netutil.IfaceAddr{{Name: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8"), Up: true, Loopback: true}}
	env.MACLookup = func(context.Context, netip.Addr) (string, bool) { return "FC:E5:57:11:22:33", true }
	return env
}

func listen(t *testing.T, handler func(net.Conn)) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handler(c) }()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

var lo = netip.MustParseAddr("127.0.0.1")

func TestSelect(t *testing.T) {
	all := All(config.Default())
	fs, err := Select(all, []string{"fetcher.hostname", "ping", "ports.filtered", "ip", "ping", "comment"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID())
	}
	if !slices.Equal(ids, []string{"ip", "hostname", "ping", "filtered"}) {
		t.Errorf("ids = %v", ids)
	}
	if _, err := Select(all, []string{"bogus"}); err == nil {
		t.Error("unknown fetcher must fail")
	}
}

func TestRunAliveWithPorts(t *testing.T) {
	open := listen(t, func(net.Conn) {})
	cfg := config.Default()
	cfg.Scanner.Ports = "1," + itoa(open)
	env := testEnv(t, cfg, true)
	fs, _ := Select(All(cfg), []string{"ping", "ttl", "packetloss", "ports", "mac", "vendor"})
	r := Run(context.Background(), NewHost(env, feeder.Subject{Addr: lo}), fs)
	got := make([]string, len(r.Values))
	for i, v := range r.Values {
		got[i] = v.String()
	}
	want := []string{"127.0.0.1", "5 ms", "64", "0/3 (0%)", itoa(open), "FC:E5:57:11:22:33", "Nokia"}
	if !slices.Equal(got, want) || r.Type != model.WithPorts || r.MAC != "FC:E5:57:11:22:33" {
		t.Errorf("got %v type %v, want %v", got, r.Type, want)
	}
}

func TestRunDeadHostSkipsFetchers(t *testing.T) {
	cfg := config.Default()
	env := testEnv(t, cfg, false)
	fs, _ := Select(All(cfg), []string{"ping", "packetloss", "hostname", "ports"})
	r := Run(context.Background(), NewHost(env, feeder.Subject{Addr: lo}), fs)
	if r.Type != model.Dead || r.Values[1].Kind != model.KindNotAvailable || r.Values[2].String() != "3/3 (100%)" ||
		r.Values[3].Kind != model.KindNotScanned || r.Values[4].Kind != model.KindNotScanned {
		t.Errorf("dead: %v %v", r.Values, r.Type)
	}
	cfg.Scanner.ScanDeadHosts = true
	r = Run(context.Background(), NewHost(env, feeder.Subject{Addr: lo}), fs)
	if r.Values[4].Kind == model.KindNotScanned {
		t.Error("scan_dead_hosts must run the ports fetcher")
	}
}

func TestRunWithoutPinger(t *testing.T) {
	cfg := config.Default()
	env := testEnv(t, cfg, false)
	env.Pinger = nil
	fs, _ := Select(All(cfg), []string{"ping"})
	r := Run(context.Background(), NewHost(env, feeder.Subject{Addr: lo}), fs)
	if r.Type != model.Alive || r.Values[1].Kind != model.KindNotAvailable {
		t.Errorf("no pinger: %v %v", r.Values, r.Type)
	}
}

func TestRequestedPortsAndFiltered(t *testing.T) {
	open := listen(t, func(net.Conn) {})
	cfg := config.Default()
	cfg.Scanner.Ports = "1"
	env := testEnv(t, cfg, true)
	h := NewHost(env, feeder.Subject{Addr: lo, Ports: []uint16{open}})
	o, f, ok := h.ScanPorts(context.Background())
	if !ok || !slices.Equal(o, []uint16{open}) || len(f) != 0 {
		t.Errorf("open %v filtered %v", o, f)
	}
	cfg.Scanner.UseRequestedPorts = false
	h = NewHost(env, feeder.Subject{Addr: lo, Ports: []uint16{open}})
	if o, _, _ := h.ScanPorts(context.Background()); len(o) != 0 {
		t.Errorf("requested ports must be ignored: %v", o)
	}
}

func TestAdaptedPortTimeout(t *testing.T) {
	cfg := config.Default()
	env := testEnv(t, cfg, true)
	h := NewHost(env, feeder.Subject{Addr: lo})
	if h.PortTimeout() != 2*time.Second {
		t.Error("no ping yet: full timeout")
	}
	h.Ping(context.Background()) // 3 replies of 5ms: 15ms, clamped to min 100ms
	if h.PortTimeout() != 100*time.Millisecond {
		t.Errorf("adapted = %v", h.PortTimeout())
	}
	cfg.Scanner.AdaptPortTimeout = false
	if h.PortTimeout() != 2*time.Second {
		t.Error("adaptation disabled")
	}
}

func TestPortTextFetchers(t *testing.T) {
	port := listen(t, func(c net.Conn) {
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "HEAD") {
			_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nDate: today\r\nServer: nginx/1.2\r\n\r\n")
		}
	})
	cfg := config.Default()
	// No port scan: httpproxy also probes open ports, and CI hosts (e.g.
	// Windows runners) may have a real web server on 127.0.0.1:80.
	cfg.Scanner.Ports = ""
	cfg.Fetcher.WebDetect.Port = int(port)
	cfg.Fetcher.HTTPSender.Port = int(port)
	cfg.Fetcher.HTTPProxy.Port = int(port)
	env := testEnv(t, cfg, true)
	fs, _ := Select(All(cfg), []string{"webdetect", "httpsender", "httpproxy"})
	r := Run(context.Background(), NewHost(env, feeder.Subject{Addr: lo}), fs)
	want := []string{"nginx/1.2", "today", itoa(port) + ": HTTP/1.0 200 OK"}
	for i, w := range want {
		if r.Values[i+1].String() != w {
			t.Errorf("%s = %q, want %q", fs[i+1].ID(), r.Values[i+1], w)
		}
	}
	if r.Type != model.WithPorts {
		t.Errorf("type %v", r.Type)
	}
}

func TestPortTextLimitsResponse(t *testing.T) {
	port := listen(t, func(c net.Conn) {
		_, _ = c.Read(make([]byte, 64))
		big := strings.Repeat("x", 1<<20) // one huge line without newline
		_, _ = io.WriteString(c, big)
	})
	cfg := config.Default()
	cfg.Fetcher.WebDetect.Port = int(port)
	env := testEnv(t, cfg, true)
	fs, _ := Select(All(cfg), []string{"webdetect"})
	start := time.Now()
	r := Run(context.Background(), NewHost(env, feeder.Subject{Addr: lo}), fs)
	if r.Values[1].Kind != model.KindNotAvailable || time.Since(start) > 3*time.Second {
		t.Errorf("value %v after %v", r.Values[1], time.Since(start))
	}
}

func TestCancelledContextMarksNotScanned(t *testing.T) {
	cfg := config.Default()
	env := testEnv(t, cfg, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fs, _ := Select(All(cfg), []string{"ping", "ports"})
	r := Run(ctx, NewHost(env, feeder.Subject{Addr: lo}), fs)
	if r.Values[2].Kind != model.KindNotScanned {
		t.Errorf("values %v", r.Values)
	}
}

func itoa(p uint16) string { return model.FormatPorts([]uint16{p}, false) }
