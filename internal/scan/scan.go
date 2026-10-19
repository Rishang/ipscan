// SPDX-License-Identifier: GPL-2.0-or-later

package scan

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noobi/ipscan-go/internal/feeder"
	"github.com/noobi/ipscan-go/internal/fetcher"
	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/netutil"
)

// AutoMaxThreads is the concurrency limit used when MaxThreads is 0.
const AutoMaxThreads = 1024

// ProgressInterval throttles progress callbacks.
const ProgressInterval = 150 * time.Millisecond

// Progress describes the state of a running scan.
type Progress struct {
	Current    netip.Addr // last dispatched address
	Active     int        // hosts being scanned right now
	MaxThreads int
	Percent    int
	Done       bool // dispatching has finished; waiting for in-flight hosts
}

// Options configures a scan.
type Options struct {
	Feeder        feeder.Feeder
	Env           *fetcher.Env
	Fetchers      []fetcher.Fetcher
	MaxThreads    int           // 0 = AutoMaxThreads
	Delay         time.Duration // pause between starting hosts (rate limiting)
	SkipBroadcast bool
	// OnResult receives every finished host. Calls are serialised on one goroutine.
	OnResult func(*model.Result)
	// OnProgress is called periodically from the same goroutine as OnResult.
	OnProgress func(Progress)
}

// Run executes a scan and returns its statistics.
//
// Cancelling stop ends dispatching of new hosts but lets in-flight hosts finish
// (Angry IP Scanner's "Stop"). Cancelling kill additionally aborts all in-flight
// network I/O; remaining columns of those hosts are NotScanned ("Stop!" / kill).
func Run(stop, kill context.Context, o Options) *model.Stats {
	stats := model.NewStats()
	maxThreads := o.MaxThreads
	if maxThreads <= 0 {
		maxThreads = AutoMaxThreads
	}
	stop, cancelStop := context.WithCancel(stop)
	defer cancelStop()
	defer context.AfterFunc(kill, cancelStop)()

	var (
		active     atomic.Int64
		current    atomic.Pointer[netip.Addr]
		dispatched atomic.Int64
		finished   atomic.Bool
	)
	size := o.Feeder.Size()
	progress := func() Progress {
		p := Progress{Active: int(active.Load()), MaxThreads: maxThreads, Done: finished.Load(),
			Percent: feeder.Percent(float64(dispatched.Load()), size)}
		if c := current.Load(); c != nil {
			p.Current = *c
		}
		if p.Done {
			p.Percent = 100
		}
		return p
	}

	results := make(chan *model.Result, 256)
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		tick := time.NewTicker(ProgressInterval)
		defer tick.Stop()
		for {
			select {
			case r, ok := <-results:
				if !ok {
					return
				}
				stats.Record(r.Type)
				if o.OnResult != nil {
					o.OnResult(r)
				}
			case <-tick.C:
				if o.OnProgress != nil {
					o.OnProgress(progress())
				}
			}
		}
	}()

	sem := make(chan struct{}, maxThreads)
	var wg sync.WaitGroup
	skipBroadcast := o.SkipBroadcast && size > 1
	delay := time.NewTimer(0)
	<-delay.C
loop:
	for stop.Err() == nil {
		s, ok := o.Feeder.Next()
		if !ok {
			break
		}
		dispatched.Add(1)
		if skipBroadcast {
			ia, _ := netutil.FindLocal(o.Env.Ifaces, s.Addr)
			if netutil.IsLikelyBroadcast(s.Addr, ia.Prefix) {
				continue
			}
		}
		select {
		case sem <- struct{}{}:
		case <-stop.Done():
			break loop
		}
		addr := s.Addr
		current.Store(&addr)
		active.Add(1)
		wg.Go(func() {
			defer func() { active.Add(-1); <-sem }()
			h := fetcher.NewHost(o.Env, s)
			results <- fetcher.Run(kill, h, o.Fetchers)
		})
		if o.Delay > 0 {
			delay.Reset(o.Delay)
			select {
			case <-delay.C:
			case <-stop.Done():
				break loop
			}
		}
	}
	aborted := stop.Err() != nil && (kill.Err() != nil || feederHasMore(o.Feeder))
	finished.Store(true)
	wg.Wait()
	close(results)
	<-collected
	if o.OnProgress != nil {
		o.OnProgress(progress())
	}
	stats.Finish(aborted)
	return stats
}

// feederHasMore reports whether the scan was stopped before the end. It may
// consume one subject, which is fine as the feeder is not used afterwards.
func feederHasMore(f feeder.Feeder) bool {
	_, ok := f.Next()
	return ok
}
