// SPDX-License-Identifier: GPL-2.0-or-later

package resolve

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestReverseName(t *testing.T) {
	if got := ReverseName(netip.MustParseAddr("192.168.0.2")); got != "2.0.168.192.in-addr.arpa." {
		t.Errorf("v4 = %s", got)
	}
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	if got := ReverseName(netip.MustParseAddr("2001:db8::1")); got != want {
		t.Errorf("v6 = %s", got)
	}
}

func ptrResponse(t *testing.T, id uint16, qname, target string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, Authoritative: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(qname), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	other := dnsmessage.MustNewName("other.local.")
	_ = b.AResource(dnsmessage.ResourceHeader{Name: other, Class: dnsmessage.ClassINET}, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}})
	_ = b.PTRResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(qname), Class: dnsmessage.ClassINET},
		dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(target)})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestPTRQueryAndResponse(t *testing.T) {
	name := "2.0.168.192.in-addr.arpa."
	q, err := buildPTRQuery(0x1234, name)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, _ := p.Start(q)
	qq, _ := p.Question()
	if h.ID != 0x1234 || qq.Type != dnsmessage.TypePTR || qq.Name.String() != name {
		t.Errorf("query %+v %+v", h, qq)
	}
	resp := ptrResponse(t, 0x1234, name, "macbook.local.")
	if host, ok := parsePTRResponse(resp, 0x1234, name); !ok || host != "macbook.local" {
		t.Errorf("parse = %q,%v", host, ok)
	}
	if _, ok := parsePTRResponse(resp, 0x1235, name); ok {
		t.Error("wrong ID must be rejected")
	}
	if _, ok := parsePTRResponse(resp, 0x1234, "3.0.168.192.in-addr.arpa."); ok {
		t.Error("wrong name must be rejected")
	}
	for i := range resp {
		_, _ = parsePTRResponse(resp[:i], 0x1234, name) // truncated input must not panic
	}
}

func TestNBSTATRequest(t *testing.T) {
	r := nbstatRequest(0xA248)
	if len(r) != 50 || r[0] != 0xA2 || r[1] != 0x48 || r[12] != 0x20 || r[13] != 'C' || r[14] != 'K' || r[47] != 0x21 {
		t.Errorf("request % x", r)
	}
}

// Fixtures from the Java NetBIOSResolverTest: 56 filler bytes, then NUM_NAMES.
func fixture(count byte, body string) []byte {
	b := []byte("01234567890123456789012345678901234567890123456789012345")
	b = append(b, count)
	for _, r := range body {
		b = append(b, byte(r))
	}
	return b
}

func TestParseNodeNames(t *testing.T) {
	tests := []struct {
		resp []byte
		want NetBIOSInfo
	}{
		{fixture(1, "ComputerName   XYY\u00DE\u00AD\u00BE\u00EF\u0000\u0000         XYY"),
			NetBIOSInfo{Computer: "ComputerName", MAC: "DE:AD:BE:EF:00:00"}},
		{fixture(2, "ComputerName   XYYGroupName      \u0000\u0080\u0000\u0001\u0002\u0003\u0004\u0005\u0006"),
			NetBIOSInfo{Computer: "ComputerName", Group: "GroupName", MAC: "01:02:03:04:05:06"}},
		{fixture(7, "ComputerName   XYY"+
			"SomeName       X\u007F\u0000"+
			"SomeName       X\u0085\u0000"+
			"GroupName      \u0000\u0085\u0000"+
			"WrongUserName  \u0003YY"+
			"UserName       \u0003YY"+
			"SomeName       XYY"+
			"\u00DE\u00AD\u00BE\u00EF\u0000\u0000"),
			NetBIOSInfo{Computer: "ComputerName", User: "UserName", Group: "GroupName", MAC: "DE:AD:BE:EF:00:00"}},
		// MAC bytes missing: no out-of-bounds read
		{fixture(1, "ComputerName   XYY"), NetBIOSInfo{Computer: "ComputerName"}},
	}
	for i, tt := range tests {
		got, err := parseNodeNames(tt.resp, 56)
		if err != nil || got != tt.want {
			t.Errorf("%d: %+v %v, want %+v", i, got, err, tt.want)
		}
	}
	if _, err := parseNodeNames(fixture(3, "ComputerName   XYY"), 56); err == nil {
		t.Error("truncated name table must fail")
	}
	if s := (NetBIOSInfo{Computer: "PC", User: "bob", Group: "WORK", MAC: "AA"}).String(); s != `WORK\bob@PC [AA]` {
		t.Errorf("String = %s", s)
	}
}

func TestParseNBSTAT(t *testing.T) {
	resp := []byte{0xA2, 0x48, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	resp = append(resp, nbstatRequest(0)[12:46]...) // encoded name incl. terminator
	resp = append(resp, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41)
	resp = append(resp, 1)
	resp = append(resp, []byte("MYPC           \x00\x04\x00")...)
	resp = append(resp, 1, 2, 3, 4, 5, 6)
	info, err := parseNBSTAT(resp, 0xA248)
	if err != nil || info.Computer != "MYPC" || info.MAC != "01:02:03:04:05:06" {
		t.Errorf("%+v %v", info, err)
	}
	if _, err := parseNBSTAT(resp, 0x1111); err == nil {
		t.Error("wrong transaction ID must be rejected")
	}
	for i := range resp {
		_, _ = parseNBSTAT(resp[:i], 0xA248)
	}
	binary.BigEndian.PutUint16(resp[46:], 0x20)
	if _, err := parseNBSTAT(resp, 0xA248); err == nil {
		t.Error("wrong record type must be rejected")
	}
}

func TestQueriesTimeOut(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx := context.Background()
	start := time.Now()
	if _, err := MDNS(ctx, netip.MustParseAddr("127.0.0.1"), 200*time.Millisecond); err == nil {
		t.Log("mDNS responder on localhost answered")
	}
	if _, err := NetBIOS(ctx, netip.MustParseAddr("127.0.0.1"), 200*time.Millisecond); err == nil {
		t.Log("NetBIOS responder on localhost answered")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("queries took %v", el)
	}
}
