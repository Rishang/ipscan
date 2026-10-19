// SPDX-License-Identifier: GPL-2.0-or-later

package model

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
)

// Kind identifies the type of a fetched value.
type Kind uint8

const (
	// KindNotAvailable means the fetcher ran but produced no result ("[n/a]").
	KindNotAvailable Kind = iota
	// KindNotScanned means the fetcher did not run, e.g. host was dead ("[n/s]").
	KindNotScanned
	KindIP
	KindMillis
	KindInt
	KindText
	KindPorts
	KindLoss
)

// Value is a single cell of a scan result. The zero value is NotAvailable.
type Value struct {
	Kind  Kind
	IP    netip.Addr
	Int   int // Millis, Int, Loss (lost packets)
	Int2  int // Loss (sent packets)
	Text  string
	Ports []uint16
}

// Labels holds the configurable texts for empty values.
type Labels struct {
	NotAvailable string
	NotScanned   string
}

// DefaultLabels matches the original Angry IP Scanner texts.
var DefaultLabels = Labels{NotAvailable: "[n/a]", NotScanned: "[n/s]"}

var (
	NotAvailable = Value{Kind: KindNotAvailable}
	NotScanned   = Value{Kind: KindNotScanned}
)

func IPValue(a netip.Addr) Value  { return Value{Kind: KindIP, IP: a} }
func Millis(ms int) Value         { return Value{Kind: KindMillis, Int: ms} }
func Int(n int) Value             { return Value{Kind: KindInt, Int: n} }
func Text(s string) Value         { return Value{Kind: KindText, Text: s} }
func Loss(lost, sent int) Value   { return Value{Kind: KindLoss, Int: lost, Int2: sent} }
func PortsValue(p []uint16) Value { return Value{Kind: KindPorts, Ports: p} }

// IsEmpty reports whether the value is NotAvailable or NotScanned.
func (v Value) IsEmpty() bool { return v.Kind == KindNotAvailable || v.Kind == KindNotScanned }

// String renders the value using DefaultLabels.
func (v Value) String() string { return v.Format(DefaultLabels) }

// Format renders the value using the given labels for empty values.
func (v Value) Format(l Labels) string {
	switch v.Kind {
	case KindNotAvailable:
		return l.NotAvailable
	case KindNotScanned:
		return l.NotScanned
	case KindIP:
		return v.IP.String()
	case KindMillis:
		return strconv.Itoa(v.Int) + " ms"
	case KindInt:
		return strconv.Itoa(v.Int)
	case KindLoss:
		pct := 100
		if v.Int2 > 0 {
			pct = v.Int * 100 / v.Int2
		}
		return strconv.Itoa(v.Int) + "/" + strconv.Itoa(v.Int2) + " (" + strconv.Itoa(pct) + "%)"
	case KindPorts:
		return FormatPorts(v.Ports, true)
	default:
		return v.Text
	}
}

// MarshalJSON emits empty values as null, numbers as numbers and everything else as text.
func (v Value) MarshalJSON() ([]byte, error) {
	switch v.Kind {
	case KindNotAvailable, KindNotScanned:
		return []byte("null"), nil
	case KindMillis, KindInt:
		return []byte(strconv.Itoa(v.Int)), nil
	case KindPorts:
		if v.Ports == nil {
			return []byte("[]"), nil
		}
		return json.Marshal(v.Ports)
	default:
		return json.Marshal(v.String())
	}
}

// FormatPorts renders sorted port numbers; with ranges, runs of 3+ consecutive
// numbers are collapsed into "a-b".
func FormatPorts(ports []uint16, asRanges bool) string {
	var b strings.Builder
	for i := 0; i < len(ports); i++ {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(ports[i])))
		if !asRanges {
			continue
		}
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j-i >= 2 {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(int(ports[j])))
			i = j
		}
	}
	return b.String()
}

// compareSameKind compares two non-empty values of the same comparable kind.
func compareSameKind(a, b Value) (int, bool) {
	switch a.Kind {
	case KindIP:
		return a.IP.Compare(b.IP), true
	case KindMillis, KindInt:
		return cmp.Compare(a.Int, b.Int), true
	case KindLoss:
		return cmp.Compare(lossRatio(a), lossRatio(b)), true
	case KindPorts:
		if c := cmp.Compare(len(a.Ports), len(b.Ports)); c != 0 {
			return c, true
		}
		for i := range a.Ports {
			if c := cmp.Compare(a.Ports[i], b.Ports[i]); c != 0 {
				return c, true
			}
		}
		return 0, true
	}
	return 0, false
}

func lossRatio(v Value) float64 {
	if v.Int2 == 0 {
		return 1
	}
	return float64(v.Int) / float64(v.Int2)
}

// compareText is a case-insensitive comparison of rendered values.
func compareText(a, b Value) int {
	return strings.Compare(strings.ToLower(a.String()), strings.ToLower(b.String()))
}

// emptyRank orders values so that real values come first, then n/a, then n/s.
func emptyRank(v Value) int {
	switch v.Kind {
	case KindNotAvailable:
		return 1
	case KindNotScanned:
		return 2
	}
	return 0
}
