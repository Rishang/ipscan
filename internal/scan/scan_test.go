// SPDX-License-Identifier: GPL-2.0-or-later

package scan

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noobi/ipscan-go/internal/config"
	"github.com/noobi/ipscan-go/internal/feeder"
	"github.com/noobi/ipscan-go/internal/fetcher"
	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/netutil"
)

// slowFetcher blocks for d or until ctx is cancelled and tracks concurrency.
type slowFetcher struct {
	d              time.Duration
	active, peak   atomic.Int64
	completed, cut atomic.Int64
}

func (f *slowFetcher) ID() string          { return "slow" }
func (f *slowFetcher) Name() string        { return "Slow" }
func (f *slowFetcher) Description() string { return "" }
func (f *slowFetcher) Scan(ctx context.Context, _ *fetcher.Host) model.Value {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-time.After(f.d):
		f.completed.Add(1)
		return model.Text("done")
	case <-ctx.Done():
		f.cut.Add(1)
		return model.NotScanned
	}
}

func setup(t *testing.T, target string, slow *slowFetcher) Options {
	t.Helper()
	env, err := fetcher.NewEnv(config.Default(), true) // no pinger: hosts are "alive"
	if err != nil {
		t.Fatal(err)
	}
	env.Ifaces = []netutil.IfaceAddr{{Name: "eth0", Prefix: netip.MustParsePrefix("10.0.0.1/27"), Up: true}}
	env.MACLookup = func(context.Context, netip.Addr) (string, bool) { return "", false }
	f, err := feeder.ParseTargets(context.Background(), []string{target}, feeder.DefaultResolver)
	if err != nil {
		t.Fatal(err)
	}
	ip, _ := fetcher.Select(fetcher.All(env.Cfg), nil)
	return Options{Feeder: f, Env: env, Fetchers: append(ip, slow), MaxThreads: 4, SkipBroadcast: true}
}

func TestRunScansAllAndLimitsConcurrency(t *testing.T) {
	slow := &slowFetcher{d: 20 * time.Millisecond}
	o := setup(t, "10.0.0.0/27", slow)
	var got []*model.Result
	var progressCalls int
	o.OnResult = func(r *model.Result) { got = append(got, r) }
	o.OnProgress = func(Progress) { progressCalls++ }
	stats := Run(context.Background(), context.Background(), o).Snapshot()
	// 32 addresses minus network (.0) and broadcast (.31) of the local /27
	if len(got) != 30 || stats.Scanned != 30 || stats.Alive != 30 || !stats.CompletedNormally() {
		t.Errorf("results %d stats %+v", len(got), stats)
	}
	if p := slow.peak.Load(); p > 4 || p < 2 {
		t.Errorf("peak concurrency %d, limit 4", p)
	}
	if progressCalls == 0 {
		t.Error("final progress callback missing")
	}
	for _, r := range got {
		if r.Addr == netip.MustParseAddr("10.0.0.0") || r.Addr == netip.MustParseAddr("10.0.0.31") {
			t.Errorf("broadcast address %s scanned", r.Addr)
		}
	}
}

func TestSingleHostIsNeverSkipped(t *testing.T) {
	o := setup(t, "10.0.0.255", &slowFetcher{})
	n := 0
	o.OnResult = func(*model.Result) { n++ }
	Run(context.Background(), context.Background(), o)
	if n != 1 {
		t.Errorf("explicit single address skipped")
	}
}

func TestStopLetsInFlightFinish(t *testing.T) {
	slow := &slowFetcher{d: 300 * time.Millisecond}
	o := setup(t, "10.0.0.1-200", slow)
	o.Delay = 10 * time.Millisecond
	stop, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	stats := Run(stop, context.Background(), o).Snapshot()
	if stats.Scanned == 0 || stats.Scanned > 10 || !stats.Aborted {
		t.Errorf("stats %+v", stats)
	}
	if slow.cut.Load() != 0 || slow.completed.Load() != int64(stats.Scanned) {
		t.Errorf("in-flight hosts must complete on stop: completed %d cut %d", slow.completed.Load(), slow.cut.Load())
	}
}

func TestKillAbortsInFlight(t *testing.T) {
	slow := &slowFetcher{d: 10 * time.Second}
	o := setup(t, "10.0.0.1-200", slow)
	kill, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	var notScanned int
	o.OnResult = func(r *model.Result) {
		if r.Values[1].Kind == model.KindNotScanned {
			notScanned++
		}
	}
	stats := Run(context.Background(), kill, o).Snapshot()
	if time.Since(start) > 2*time.Second {
		t.Errorf("kill took %v", time.Since(start))
	}
	if stats.Scanned == 0 || notScanned != stats.Scanned || !stats.Aborted {
		t.Errorf("stats %+v notScanned %d", stats, notScanned)
	}
}

func TestDelayRateLimits(t *testing.T) {
	o := setup(t, "10.0.0.1-5", &slowFetcher{})
	o.Delay = 30 * time.Millisecond
	start := time.Now()
	Run(context.Background(), context.Background(), o)
	if el := time.Since(start); el < 120*time.Millisecond {
		t.Errorf("5 hosts with 30ms delay finished in %v", el)
	}
}
