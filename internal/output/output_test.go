// SPDX-License-Identifier: GPL-2.0-or-later

package output

import (
	"bytes"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/scan"
)

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	tb := NewTable(&buf, []string{"IP", "Ping", "Hostname"}, model.DefaultLabels, false, &sync.Mutex{})
	_ = tb.Header()
	a := netip.MustParseAddr("192.168.100.200")
	_ = tb.Row(&model.Result{Addr: a, Type: model.Alive, Values: []model.Value{
		model.IPValue(a), model.Millis(3), model.Text("a-very-long-hostname.example.com")}})
	_ = tb.Row(&model.Result{Addr: a, Type: model.Dead, Values: []model.Value{model.IPValue(a), model.NotAvailable, model.NotScanned}})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	want := []string{
		"  IP              Ping            Hostname",
		"* 192.168.100.200 3 ms            a-very-long-hostname.example.com",
		"- 192.168.100.200 [n/a]           [n/s]",
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d = %q, want %q", i, lines[i], w)
		}
	}
	buf.Reset()
	tb.color = true
	_ = tb.Row(&model.Result{Addr: a, Type: model.WithPorts, Values: []model.Value{model.IPValue(a), model.NotAvailable, model.Text("x")}})
	if !strings.Contains(buf.String(), ansiCyan+"+"+ansiReset) || !strings.Contains(buf.String(), ansiDim+"[n/a]") {
		t.Errorf("color row %q", buf.String())
	}
}

func TestProgress(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, false, &sync.Mutex{})
	p.Update(scan.Progress{Current: netip.MustParseAddr("10.0.0.5"), Active: 4, MaxThreads: 4, Percent: 50})
	s := buf.String()
	if !strings.Contains(s, "[##########..........]  50%") || !strings.Contains(s, "threads: 4 (max)") || !strings.Contains(s, "10.0.0.5") {
		t.Errorf("progress %q", s)
	}
	buf.Reset()
	p.Message("hello %d", 1)
	if buf.String() != clearLine+"hello 1\n" {
		t.Errorf("message %q", buf.String())
	}
	buf.Reset()
	p.Clear()
	if buf.Len() != 0 {
		t.Error("clear when hidden must write nothing")
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		250 * time.Millisecond: "250 ms", 1500 * time.Millisecond: "1.50 sec",
		90 * time.Second: "1.50 min", 3 * time.Hour: "3.00 h",
	} {
		if got := FormatDuration(d); got != want {
			t.Errorf("%v = %s", d, got)
		}
	}
}

func TestSummary(t *testing.T) {
	var buf bytes.Buffer
	Summary(&buf, model.Snapshot{Duration: 2 * time.Second, Scanned: 4, Alive: 2, WithPorts: 1, Finished: true}, "10.0.0.0/30")
	s := buf.String()
	for _, w := range []string{"Scan completed: 10.0.0.0/30", "2.00 sec", "500 ms", "Hosts scanned:     4", "With open ports:   1"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in\n%s", w, s)
		}
	}
	buf.Reset()
	Summary(&buf, model.Snapshot{Finished: true, Aborted: true}, "x")
	if !strings.Contains(buf.String(), "incomplete") || strings.Contains(buf.String(), "open ports") {
		t.Errorf("aborted summary %s", buf.String())
	}
}
