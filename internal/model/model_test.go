// SPDX-License-Identifier: GPL-2.0-or-later

package model

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		in     []uint16
		ranges bool
		want   string
	}{
		{nil, true, ""},
		{[]uint16{1}, true, "1"},
		{[]uint16{1, 2}, true, "1,2"},
		{[]uint16{1, 2, 3}, true, "1-3"},
		{[]uint16{1, 2, 3}, false, "1,2,3"},
		{[]uint16{1, 5, 6, 15}, true, "1,5,6,15"},
		{[]uint16{1, 5, 6, 7, 8, 15}, true, "1,5-8,15"},
		{[]uint16{103, 85, 89, 1}, true, "103,85,89,1"},
	}
	for _, tt := range tests {
		if got := FormatPorts(tt.in, tt.ranges); got != tt.want {
			t.Errorf("FormatPorts(%v,%v) = %q, want %q", tt.in, tt.ranges, got, tt.want)
		}
	}
}

func TestValueFormat(t *testing.T) {
	tests := []struct {
		v    Value
		want string
	}{
		{NotAvailable, "[n/a]"},
		{NotScanned, "[n/s]"},
		{Value{}, "[n/a]"},
		{IPValue(netip.MustParseAddr("10.0.0.1")), "10.0.0.1"},
		{Millis(12), "12 ms"},
		{Int(64), "64"},
		{Text("host"), "host"},
		{Loss(1, 3), "1/3 (33%)"},
		{Loss(0, 0), "0/0 (100%)"},
		{PortsValue([]uint16{22, 80, 81, 82}), "22,80-82"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("%#v.String() = %q, want %q", tt.v, got, tt.want)
		}
	}
	if got := NotAvailable.Format(Labels{NotAvailable: "-", NotScanned: "?"}); got != "-" {
		t.Errorf("custom label = %q", got)
	}
}

var localhost = netip.MustParseAddr("127.0.0.1")

func res(vals ...Value) *Result { return resAt(localhost, vals...) }

func resAt(addr netip.Addr, vals ...Value) *Result {
	return &Result{Addr: addr, Values: vals}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestCompareDifferentKinds(t *testing.T) {
	ports := func(p ...uint16) Value { return PortsValue(p) }
	tests := []struct {
		name string
		a, b Value
		want int
	}{
		{"text before n/a", Text("a"), NotAvailable, -1},
		{"n/a after int", NotAvailable, Int(12), 1},
		{"n/a equals n/a", NotAvailable, NotAvailable, 0},
		{"n/s after n/a", NotScanned, NotAvailable, 1},
		{"n/a before n/s", NotAvailable, NotScanned, -1},
		{"int before n/s", Int(125), NotScanned, -1},
		{"int vs single port", Int(9090), ports(9090), 0},
		{"single port vs int", ports(154), Int(155), -1},
		{"more ports sorts higher", ports(1, 2, 3), ports(5, 6), 1},
		{"port element-wise", ports(22, 25, 27, 28), ports(22, 25, 26, 300), 1},
		{"text", Text("abc"), Text("def"), -1},
		{"numeric text vs int", Text("123"), Int(123), 0},
		{"text vs int", Text("ZZZ"), Int(99), 1},
		{"numeric text is lexicographic", Text("125"), Text("13"), -1},
		{"ints numeric", Int(125), Int(13), 1},
		{"millis numeric", Millis(125), Millis(13), 1},
		{"case-insensitive equal", Text("a"), Text("A"), 0},
		{"case-insensitive prefix", Text("Anton"), Text("ANT"), 1},
		{"case-insensitive order", Text("Z"), Text("a"), 1},
	}
	for _, tt := range tests {
		if got := sign(Compare(res(tt.a), res(tt.b), 0, true)); got != tt.want {
			t.Errorf("%s: Compare = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestCompareColumnsAndDirection(t *testing.T) {
	a, z := Text("a"), Text("z")
	if sign(Compare(res(a, z), res(z, a), 0, true)) != -1 {
		t.Error("column 0")
	}
	if sign(Compare(res(a, z), res(z, a), 1, true)) != 1 {
		t.Error("column 1")
	}
	// Descending: empty values still last; real values reversed.
	if sign(Compare(res(a), res(NotAvailable), 0, false)) != -1 {
		t.Error("desc: text before n/a")
	}
	if sign(Compare(res(NotScanned), res(NotAvailable), 0, false)) != 1 {
		t.Error("desc: n/s after n/a")
	}
	if sign(Compare(res(Int(2)), res(Int(1)), 0, false)) != -1 {
		t.Error("desc ints")
	}
}

func TestCompareFallsBackToAddress(t *testing.T) {
	ip1 := netip.MustParseAddr("127.0.0.25")
	ip2 := netip.MustParseAddr("127.0.0.30")
	ip3 := netip.MustParseAddr("128.0.0.25")
	if Compare(resAt(ip1, IPValue(ip1), Text("a")), resAt(ip1, IPValue(ip1), Text("A")), 1, true) != 0 {
		t.Error("same address, equal text")
	}
	if sign(Compare(resAt(ip1, IPValue(ip1), Text("a")), resAt(ip2, IPValue(ip2), Text("a")), 1, true)) != -1 {
		t.Error("tie broken by ip asc")
	}
	if sign(Compare(resAt(ip3, IPValue(ip3), Text("a")), resAt(ip2, IPValue(ip2), Text("a")), 1, true)) != 1 {
		t.Error("tie broken by ip asc (2)")
	}
	if sign(Compare(resAt(ip1, IPValue(ip1), NotAvailable), resAt(ip2, IPValue(ip2), NotAvailable), 1, false)) != 1 {
		t.Error("tie broken by ip desc")
	}
	// 10.0.0.10 must sort after 10.0.0.2 (numeric, not lexicographic).
	a, b := netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.2")
	if sign(Compare(resAt(a, IPValue(a)), resAt(b, IPValue(b)), 0, true)) != 1 {
		t.Error("ip column must sort numerically")
	}
}

func TestSortResultsBothDirections(t *testing.T) {
	rs := []*Result{res(NotScanned), res(NotAvailable), res(Int(15)), res(NotScanned), res(Int(1)), res(NotAvailable), res(Text("a"))}
	col := func() []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = r.Values[0].String()
		}
		return out
	}
	SortResults(rs, 0, true)
	if want := []string{"1", "15", "a", "[n/a]", "[n/a]", "[n/s]", "[n/s]"}; !slices.Equal(col(), want) {
		t.Errorf("asc = %v, want %v", col(), want)
	}
	SortResults(rs, 0, false)
	if want := []string{"a", "15", "1", "[n/a]", "[n/a]", "[n/s]", "[n/s]"}; !slices.Equal(col(), want) {
		t.Errorf("desc = %v, want %v", col(), want)
	}
}

func TestResultTypeMatches(t *testing.T) {
	tests := []struct {
		t, other ResultType
		want     bool
	}{
		{Alive, Alive, true}, {Alive, WithPorts, true}, {Alive, Dead, false}, {Alive, Unknown, false},
		{WithPorts, WithPorts, true}, {WithPorts, Alive, false},
		{Dead, Dead, true}, {Dead, Unknown, true}, {Dead, Alive, false},
	}
	for _, tt := range tests {
		if got := tt.t.Matches(tt.other); got != tt.want {
			t.Errorf("%v.Matches(%v) = %v", tt.t, tt.other, got)
		}
	}
}

func TestNewResult(t *testing.T) {
	r := NewResult(localhost, 3)
	if r.Values[0].Kind != KindIP || r.Values[1].Kind != KindNotScanned || r.Type != Unknown {
		t.Errorf("unexpected new result %+v", r)
	}
}

func TestStats(t *testing.T) {
	s := NewStats()
	for _, rt := range []ResultType{Dead, Alive, WithPorts, Dead} {
		s.Record(rt)
	}
	time.Sleep(time.Millisecond)
	snap := s.Snapshot()
	if snap.Scanned != 4 || snap.Alive != 2 || snap.WithPorts != 1 || snap.Finished {
		t.Errorf("unexpected snapshot %+v", snap)
	}
	if snap.Duration <= 0 || snap.PerHost() <= 0 {
		t.Error("duration should be running")
	}
	s.Finish(true)
	if snap = s.Snapshot(); !snap.Finished || !snap.Aborted || snap.CompletedNormally() {
		t.Errorf("unexpected finished snapshot %+v", snap)
	}
}

func TestFindText(t *testing.T) {
	rs := []*Result{res(Text("alpha")), res(NotAvailable), res(Text("Beta")), res(Text("alphabet"))}
	tests := []struct {
		text  string
		start int
		want  int
	}{
		{"alpha", 0, 0}, {"alpha", 1, 3}, {"BETA", 0, 2}, {"[n/a]", 0, 1}, {"zzz", 0, -1}, {"alpha", 4, -1},
	}
	for _, tt := range tests {
		if got := FindText(rs, tt.text, tt.start); got != tt.want {
			t.Errorf("FindText(%q,%d) = %d, want %d", tt.text, tt.start, got, tt.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		spec string
		want []uint16
	}{
		{"1,2,3,5,7", []uint16{1, 2, 3, 5, 7}},
		{"1,\n2,   3,\t\t5,7", []uint16{1, 2, 3, 5, 7}},
		{"27, 1;65535", []uint16{27, 1, 65535}},
		{"16", []uint16{16}},
		{"", nil},
		{"   12", []uint16{12}},
		{"12, ", []uint16{12}},
		{"1-3", []uint16{1, 2, 3}},
		{"65530-65535", []uint16{65530, 65531, 65532, 65533, 65534, 65535}},
		{"100,13-14,17-20", []uint16{100, 13, 14, 17, 18, 19, 20}},
		{"9-7", []uint16{7, 8, 9}},
	}
	for _, tt := range tests {
		l, err := ParsePorts(tt.spec)
		if err != nil {
			t.Fatalf("ParsePorts(%q): %v", tt.spec, err)
		}
		if got := slices.Collect(l.All()); !slices.Equal(got, tt.want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
		}
		if l.Len() != len(tt.want) {
			t.Errorf("ParsePorts(%q).Len() = %d", tt.spec, l.Len())
		}
	}
	if n := MustParsePorts("1-65000").Len(); n != 65000 {
		t.Errorf("Len = %d", n)
	}
	if s := MustParsePorts("80, 1-3").String(); s != "80,1-3" {
		t.Errorf("String = %q", s)
	}
}

func TestParsePortsInvalid(t *testing.T) {
	for _, spec := range []string{"foo", "65536", "1,2,0,3", "-3", "5-", "1-70000"} {
		if _, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) should fail", spec)
		}
	}
}
