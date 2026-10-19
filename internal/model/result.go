// SPDX-License-Identifier: GPL-2.0-or-later

package model

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// ResultType classifies a scanned host. Order matters: higher means "more alive".
type ResultType uint8

const (
	Unknown ResultType = iota
	Dead
	Alive
	WithPorts
)

func (t ResultType) String() string {
	switch t {
	case Dead:
		return "dead"
	case Alive:
		return "alive"
	case WithPorts:
		return "ports"
	}
	return "unknown"
}

// Matches reports whether other belongs to the category t, as used by
// display filtering: Alive matches Alive and WithPorts, Dead matches Dead and Unknown.
func (t ResultType) Matches(other ResultType) bool {
	if t <= Dead {
		return other <= Dead
	}
	return other >= t
}

// Result is the outcome of scanning a single host.
type Result struct {
	Addr   netip.Addr
	MAC    string
	Values []Value
	Type   ResultType
}

// NewResult creates a result with all values NotScanned except the IP column.
func NewResult(addr netip.Addr, columns int) *Result {
	r := &Result{Addr: addr, Values: make([]Value, columns)}
	for i := range r.Values {
		r.Values[i] = NotScanned
	}
	if columns > 0 {
		r.Values[0] = IPValue(addr)
	}
	return r
}

// Compare orders two results by the given column. Empty values always sort
// last (n/a before n/s) regardless of direction; ties fall back to the address.
func Compare(a, b *Result, col int, asc bool) int {
	va, vb := valueAt(a, col), valueAt(b, col)
	ra, rb := emptyRank(va), emptyRank(vb)
	if ra != 0 || rb != 0 {
		if ra != rb {
			return cmp.Compare(ra, rb)
		}
		return directed(a.Addr.Compare(b.Addr), asc)
	}
	c, ok := 0, false
	if va.Kind == vb.Kind {
		c, ok = compareSameKind(va, vb)
	}
	if !ok {
		c = compareText(va, vb)
	}
	if c == 0 && col != 0 {
		c = a.Addr.Compare(b.Addr)
	}
	return directed(c, asc)
}

func directed(c int, asc bool) int {
	if asc {
		return c
	}
	return -c
}

func valueAt(r *Result, col int) Value {
	if col < 0 || col >= len(r.Values) {
		return NotAvailable
	}
	return r.Values[col]
}

// SortResults sorts results in place, stably, by the given column.
func SortResults(rs []*Result, col int, asc bool) {
	slices.SortStableFunc(rs, func(a, b *Result) int { return Compare(a, b, col, asc) })
}

// Stats holds aggregate statistics of a scan. It is safe for concurrent use.
type Stats struct {
	mu        sync.Mutex
	start     time.Time
	end       time.Time
	scanned   int
	alive     int
	withPorts int
	finished  bool
	aborted   bool
}

// NewStats starts a statistics record at the current time.
func NewStats() *Stats { return &Stats{start: time.Now()} }

// Record accounts for one completed host.
func (s *Stats) Record(t ResultType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanned++
	if t >= Alive {
		s.alive++
	}
	if t == WithPorts {
		s.withPorts++
	}
}

// Finish marks the scan as ended; aborted means it was stopped by the user.
func (s *Stats) Finish(aborted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.end, s.finished, s.aborted = time.Now(), true, aborted
}

// Snapshot is an immutable copy of Stats.
type Snapshot struct {
	Duration          time.Duration
	Scanned           int
	Alive             int
	WithPorts         int
	Finished, Aborted bool
}

// CompletedNormally reports whether the scan ran to the end without being stopped.
func (s Snapshot) CompletedNormally() bool { return s.Finished && !s.Aborted }

// PerHost is the average time spent per scanned host.
func (s Snapshot) PerHost() time.Duration {
	if s.Scanned == 0 {
		return 0
	}
	return s.Duration / time.Duration(s.Scanned)
}

func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.end
	if !s.finished {
		end = time.Now()
	}
	return Snapshot{
		Duration: end.Sub(s.start), Scanned: s.scanned, Alive: s.alive,
		WithPorts: s.withPorts, Finished: s.finished, Aborted: s.aborted,
	}
}

// FindText returns the index of the first result at or after start that has a
// value containing text (case-insensitive), or -1.
func FindText(rs []*Result, text string, start int) int {
	text = strings.ToLower(text)
	for i := max(start, 0); i < len(rs); i++ {
		for _, v := range rs[i].Values {
			if strings.Contains(strings.ToLower(v.String()), text) {
				return i
			}
		}
	}
	return -1
}
