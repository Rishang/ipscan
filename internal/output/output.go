// SPDX-License-Identifier: GPL-2.0-or-later

package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/scan"
)

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// ColorEnabled reports whether ANSI colors should be used for f.
func ColorEnabled(f *os.File) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return IsTerminal(f) && os.Getenv("TERM") != "dumb"
}

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiCyan   = "\x1b[36m"
	ansiRed    = "\x1b[31m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
	clearLine  = "\r\x1b[K"
	markerCols = 2
)

// marker replaces the GUI status icons.
func marker(t model.ResultType) (string, string) {
	switch t {
	case model.WithPorts:
		return "+", ansiCyan
	case model.Alive:
		return "*", ansiGreen
	case model.Dead:
		return "-", ansiRed
	}
	return "?", ansiDim
}

// Table streams results as aligned, fixed-width rows.
type Table struct {
	w      *bufio.Writer
	names  []string
	widths []int
	labels model.Labels
	color  bool
	mu     *sync.Mutex // shared with Progress so lines never interleave
	header bool
}

// NewTable creates a table writer. Column widths follow the TXT export
// (at least 16, or three times the header length, capped at 40).
func NewTable(w io.Writer, names []string, labels model.Labels, color bool, mu *sync.Mutex) *Table {
	widths := make([]int, len(names))
	for i, n := range names {
		widths[i] = min(max(16, utf8.RuneCountInString(n)+2), 40)
	}
	if len(widths) > 0 {
		widths[0] = max(widths[0], 16)
	}
	return &Table{w: bufio.NewWriter(w), names: names, widths: widths, labels: labels, color: color, mu: mu}
}

func (t *Table) cell(sb *strings.Builder, i int, s, color string) {
	if i < len(t.widths)-1 {
		if n := utf8.RuneCountInString(s); n < t.widths[i] {
			s += strings.Repeat(" ", t.widths[i]-n)
		} else {
			s += "  "
		}
	}
	if t.color && color != "" {
		s = color + s + ansiReset
	}
	sb.WriteString(s)
}

// Header writes the column titles.
func (t *Table) Header() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var sb strings.Builder
	sb.WriteString(strings.Repeat(" ", markerCols))
	for i, n := range t.names {
		t.cell(&sb, i, n, ansiBold)
	}
	sb.WriteByte('\n')
	t.header = true
	t.w.WriteString(sb.String())
	return t.w.Flush()
}

// Row writes one result line.
func (t *Table) Row(r *model.Result) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var sb strings.Builder
	m, c := marker(r.Type)
	if t.color {
		sb.WriteString(c + m + ansiReset + " ")
	} else {
		sb.WriteString(m + " ")
	}
	for i, v := range r.Values {
		color := ""
		if v.IsEmpty() {
			color = ansiDim
		}
		t.cell(&sb, i, v.Format(t.labels), color)
	}
	sb.WriteByte('\n')
	if _, err := t.w.WriteString(sb.String()); err != nil {
		return err
	}
	return t.w.Flush()
}

// Progress renders a single updating status line on a terminal.
type Progress struct {
	w       io.Writer
	mu      *sync.Mutex
	visible bool
	color   bool
}

// NewProgress creates a progress renderer writing to w (normally stderr).
func NewProgress(w io.Writer, color bool, mu *sync.Mutex) *Progress {
	return &Progress{w: w, color: color, mu: mu}
}

// Update redraws the progress line.
func (p *Progress) Update(pr scan.Progress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	const barLen = 20
	filled := pr.Percent * barLen / 100
	bar := strings.Repeat("#", filled) + strings.Repeat(".", barLen-filled)
	threads := fmt.Sprintf("threads: %d", pr.Active)
	if pr.Active >= pr.MaxThreads {
		threads += " (max)"
		if p.color {
			threads = ansiRed + threads + ansiReset
		}
	}
	status := "scanning " + pr.Current.String()
	if pr.Done {
		status = "waiting for threads to finish"
	} else if !pr.Current.IsValid() {
		status = "starting"
	}
	fmt.Fprintf(p.w, "%s[%s] %3d%%  %s  %s", clearLine, bar, pr.Percent, threads, status)
	p.visible = true
}

// Clear removes the progress line, e.g. before printing a result row.
func (p *Progress) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
}

func (p *Progress) clearLocked() {
	if p.visible {
		io.WriteString(p.w, clearLine)
		p.visible = false
	}
}

// Message prints a line on the progress stream, keeping the progress line intact.
func (p *Progress) Message(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
	fmt.Fprintf(p.w, format+"\n", args...)
}

// Writer returns a writer that clears the progress line before each write,
// suitable for log output.
func (p *Progress) Writer() io.Writer { return progressWriter{p} }

type progressWriter struct{ p *Progress }

func (w progressWriter) Write(b []byte) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	w.p.clearLocked()
	return w.p.w.Write(b)
}

// FormatDuration renders durations like the original statistics dialog.
func FormatDuration(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%.2f h", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.2f min", d.Minutes())
	case d >= time.Second:
		return fmt.Sprintf("%.2f sec", d.Seconds())
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}

// Summary writes scan statistics.
func Summary(w io.Writer, s model.Snapshot, feederInfo string) {
	state := "Scan completed"
	if !s.CompletedNormally() {
		state = "Scan incomplete (stopped)"
	}
	fmt.Fprintf(w, "\n%s: %s\n", state, feederInfo)
	fmt.Fprintf(w, "  Total time:        %s\n", FormatDuration(s.Duration))
	fmt.Fprintf(w, "  Average per host:  %s\n", FormatDuration(s.PerHost()))
	fmt.Fprintf(w, "  Hosts scanned:     %d\n", s.Scanned)
	fmt.Fprintf(w, "  Hosts alive:       %d\n", s.Alive)
	if s.WithPorts > 0 {
		fmt.Fprintf(w, "  With open ports:   %d\n", s.WithPorts)
	}
}
