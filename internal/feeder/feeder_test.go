// SPDX-License-Identifier: GPL-2.0-or-later

package feeder

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/noobi/ipscan-go/internal/netutil"
)

func drain(t *testing.T, f Feeder) []string {
	t.Helper()
	var out []string
	for s, ok := f.Next(); ok; s, ok = f.Next() {
		out = append(out, s.Addr.String())
		if len(out) > 100000 {
			t.Fatal("feeder does not terminate")
		}
	}
	return out
}

func fakeResolver(hosts map[string]string) Resolver {
	return func(_ context.Context, h string) ([]netip.Addr, error) {
		if a, ok := hosts[h]; ok {
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		return nil, errors.New("no such host")
	}
}

func TestRange(t *testing.T) {
	tests := []struct {
		start, end string
		want       []string
	}{
		{"10.11.12.13", "10.11.12.15", []string{"10.11.12.13", "10.11.12.14", "10.11.12.15"}},
		{"10.11.12.13", "10.11.12.11", []string{"10.11.12.13", "10.11.12.12", "10.11.12.11"}},
		{"10.0.1.1", "10.0.0.254", []string{"10.0.1.1", "10.0.1.0", "10.0.0.255", "10.0.0.254"}},
		{"0.0.0.0", "0.0.0.0", []string{"0.0.0.0"}},
		{"255.255.255.255", "255.255.255.255", []string{"255.255.255.255"}},
		{"254.255.255.255", "255.0.0.0", []string{"254.255.255.255", "255.0.0.0"}},
		{"::1", "::3", []string{"::1", "::2", "::3"}},
	}
	for _, tt := range tests {
		r, err := NewRange(netip.MustParseAddr(tt.start), netip.MustParseAddr(tt.end))
		if err != nil {
			t.Fatal(err)
		}
		if got := drain(t, r); !slices.Equal(got, tt.want) {
			t.Errorf("range %s-%s = %v, want %v", tt.start, tt.end, got, tt.want)
		}
		if int(r.Size()) != len(tt.want) {
			t.Errorf("range %s-%s Size = %v", tt.start, tt.end, r.Size())
		}
	}
	r, _ := NewRange(netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"))
	if r.Info() != "0.0.0.0 - 255.255.255.255" || r.Size() != 1<<32 {
		t.Errorf("info %q size %v", r.Info(), r.Size())
	}
	if _, err := NewRange(netip.MustParseAddr("::1"), netip.MustParseAddr("1.2.3.4")); err == nil {
		t.Error("mixed families must fail")
	}
}

func TestPercent(t *testing.T) {
	for _, tt := range []struct {
		done, size float64
		want       int
	}{{0, 3, 0}, {1, 3, 33}, {2, 3, 67}, {3, 3, 100}, {1, 1, 100}, {5, 0, 0}} {
		if got := Percent(tt.done, tt.size); got != tt.want {
			t.Errorf("Percent(%v,%v) = %d", tt.done, tt.size, got)
		}
	}
}

func TestRandom(t *testing.T) {
	mask := func(s string) netutil.Mask { m, _ := netutil.ParseMask(s); return m }
	ip := netip.MustParseAddr

	r, err := NewRandom(ip("255.255.255.255"), mask("255...0"), 2)
	if err != nil {
		t.Fatal(err)
	}
	got := drain(t, r)
	if len(got) != 2 || !strings.HasPrefix(got[0], "255.255.255.") || !strings.HasPrefix(got[1], "255.255.255.") {
		t.Errorf("random = %v", got)
	}
	r, _ = NewRandom(ip("1.2.3.45"), mask("255.255.255.255"), 1)
	if got := drain(t, r); !slices.Equal(got, []string{"1.2.3.45"}) {
		t.Errorf("full mask = %v", got)
	}
	r, _ = NewRandom(ip("1.2.3.45"), mask("255.0.0.255"), 50)
	for _, a := range drain(t, r) {
		if !strings.HasPrefix(a, "1.") || !strings.HasSuffix(a, ".45") {
			t.Errorf("masked random = %s", a)
		}
	}
	r, _ = NewRandom(ip("1.2.3.45"), mask("0.0.0.0"), 20)
	if got := drain(t, r); slices.Equal(got[:2], []string{"1.2.3.45", "1.2.3.45"}) {
		t.Error("empty mask should randomise")
	}
	if _, err := NewRandom(ip("1.1.1.1"), mask("/32"), 0); err == nil {
		t.Error("count 0 must fail")
	}
	if _, err := NewRandom(ip("::1"), mask("/24"), 1); err == nil {
		t.Error("mask/address family mismatch must fail")
	}
}

func TestExtractHostsFormats(t *testing.T) {
	tests := []struct {
		text string
		want []string
	}{
		{"10.11.12.13 10.11.12.14 10.11.12.15", []string{"10.11.12.13", "10.11.12.14", "10.11.12.15"}},
		{"The 127.0.0.1 is the localhost IP,\n but 192.168.255.255 is probably a broadcast IP", []string{"127.0.0.1", "192.168.255.255"}},
		{"1.1.1.,1245\n2.2.2.2:123\n3.3.3.3.3.3\n\n\n9.9.9.9999", []string{"2.2.2.2"}},
		{"255.255.255.255\n\n\n\t0.0.0.0", []string{"255.255.255.255", "0.0.0.0"}},
		{"09.001.005.006", []string{"9.1.5.6"}},
		{"999.999.999.999,1.1.1.1", []string{"1.1.1.1"}},
		{"<xml>66.87.99.128</xml>\n<xml>10.87.99.129</xml>", []string{"66.87.99.128", "10.87.99.129"}},
		{"Hello, my IP is 10.10.10.123, not 128.92.34.56. Isn't it cool?", []string{"10.10.10.123", "128.92.34.56"}},
		{"site https://angryip.org, not http://www.angryziber.com. Isn't it cool?", []string{"www.angryziber.com"}},
		{"angryip.org, hello.xyz.com www.google.ee", []string{"hello.xyz.com", "www.google.ee"}},
		{"me.local example.dn42 beta.wiki.dn42 A.B.CD", []string{"me.local", "example.dn42", "beta.wiki.dn42", "a.b.cd"}},
		{"3.5 3.5.1 a.b abc 123 127.0.0.256", nil},
		{"v6: ::1, fe80::1234 and 2001:db8::1; not std::cout or 12:30:45", []string{"::1", "fe80::1234", "2001:db8::1"}},
		{"dup 1.2.3.4 1.2.3.4 01.2.3.4", []string{"1.2.3.4"}},
	}
	for _, tt := range tests {
		var got []string
		for _, f := range ExtractHosts(tt.text) {
			if f.Addr.IsValid() {
				got = append(got, f.Addr.String())
			} else {
				got = append(got, f.Host)
			}
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("ExtractHosts(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
}

func TestExtractHostsPorts(t *testing.T) {
	found := ExtractHosts("1.2.3.4:1234\n2.3.4.5:\n 7.6.5.4:789004\n 1.2.3.5:80  1.2.3.5:3128 [2001:db8::1]:8443 web.example.com:8080 ")
	want := map[string][]uint16{
		"1.2.3.4": {1234}, "2.3.4.5": nil, "7.6.5.4": nil, "1.2.3.5": {80, 3128},
		"2001:db8::1": {8443}, "web.example.com": {8080},
	}
	if len(found) != len(want) {
		t.Fatalf("found %d hosts: %+v", len(found), found)
	}
	for _, f := range found {
		key := f.Host
		if f.Addr.IsValid() {
			key = f.Addr.String()
		}
		if !slices.Equal(f.Ports, want[key]) {
			t.Errorf("%s ports = %v, want %v", key, f.Ports, want[key])
		}
	}
}

func TestFromReader(t *testing.T) {
	res := fakeResolver(map[string]string{"hello.xyz.com": "10.0.0.7", "alias.xyz.com": "10.0.0.7"})
	l, err := NewFromReader(context.Background(), strings.NewReader("hello.xyz.com:22 unknown.invalid 10.0.0.1 alias.xyz.com:80"), "list", res)
	if err != nil {
		t.Fatal(err)
	}
	if got := drain(t, l); !slices.Equal(got, []string{"10.0.0.7", "10.0.0.1"}) {
		t.Errorf("got %v", got)
	}
	if l.items[0].Ports[0] != 22 || l.items[0].Ports[1] != 80 {
		t.Errorf("merged ports = %v", l.items[0].Ports)
	}
	if _, err := NewFromReader(context.Background(), strings.NewReader("no ip addresses here"), "x", res); err == nil {
		t.Error("expected nothing found error")
	}
	if _, err := NewFile(context.Background(), "no_such_file.txt", res); err == nil {
		t.Error("expected missing file error")
	}
	l, err = NewFile(context.Background(), "../../testdata/import.txt", res)
	if err != nil || l.Size() == 0 {
		t.Errorf("import.txt: %v", err)
	}
}

func TestRescan(t *testing.T) {
	l, err := NewRescan([]netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("::1")})
	if err != nil {
		t.Fatal(err)
	}
	if got := drain(t, l); !slices.Equal(got, []string{"1.2.3.4", "::1"}) {
		t.Errorf("rescan = %v", got)
	}
	if _, err := NewRescan(nil); err == nil {
		t.Error("empty rescan must fail")
	}
}

func TestParseTargets(t *testing.T) {
	res := fakeResolver(map[string]string{"router.lan": "192.168.1.1", "v6.lan": "2001:db8::5"})
	tests := []struct {
		args []string
		want []string
	}{
		{[]string{"10.0.0.1"}, []string{"10.0.0.1"}},
		{[]string{"10.0.0.1-3"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{[]string{"10.0.0.3-1"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{[]string{"10.0.0.254-10.0.1.1"}, []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"}},
		{[]string{"10.0.0.3-10.0.0.1"}, []string{"10.0.0.3", "10.0.0.2", "10.0.0.1"}},
		{[]string{"10.0.0.0/30"}, []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{[]string{"10.0.0.6/255.255.255.252"}, []string{"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"}},
		{[]string{"10.1-2.0.5-6"}, []string{"10.1.0.5", "10.1.0.6", "10.2.0.5", "10.2.0.6"}},
		{[]string{"10.0.0.1,10.0.0.9", "10.0.0.5"}, []string{"10.0.0.1", "10.0.0.9", "10.0.0.5"}},
		{[]string{"2001:db8::/127"}, []string{"2001:db8::", "2001:db8::1"}},
		{[]string{"::1-::2"}, []string{"::1", "::2"}},
		{[]string{"router.lan"}, []string{"192.168.1.1"}},
		{[]string{"router.lan/31"}, []string{"192.168.1.0", "192.168.1.1"}},
		{[]string{"v6.lan/127"}, []string{"2001:db8::4", "2001:db8::5"}},
	}
	for _, tt := range tests {
		f, err := ParseTargets(context.Background(), tt.args, res)
		if err != nil {
			t.Errorf("ParseTargets(%v): %v", tt.args, err)
			continue
		}
		if got := drain(t, f); !slices.Equal(got, tt.want) {
			t.Errorf("ParseTargets(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
	f, _ := ParseTargets(context.Background(), []string{"10.0.0.*"}, res)
	if f.Size() != 256 {
		t.Errorf("wildcard size = %v", f.Size())
	}
	for _, bad := range []string{"10.0.0.256", "10.0.0.1/33", "10.0.0.1/255.0.255.x", "unknown.host", "::1/24.0.0.0", ""} {
		if _, err := ParseTargets(context.Background(), []string{bad}, res); err == nil {
			t.Errorf("ParseTargets(%q) should fail", bad)
		}
	}
}
