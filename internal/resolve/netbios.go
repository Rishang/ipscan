// SPDX-License-Identifier: GPL-2.0-or-later

package resolve

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/noobi/ipscan-go/internal/mac"
)

// NetBIOSInfo is the result of a NetBIOS node status (NBSTAT) query.
type NetBIOSInfo struct {
	Computer, User, Group, MAC string
}

// String renders the info as DOMAIN\USER@COMPUTER [MAC], omitting absent parts.
func (n NetBIOSInfo) String() string {
	var sb strings.Builder
	if n.Group != "" {
		sb.WriteString(n.Group + `\`)
	}
	if n.User != "" {
		sb.WriteString(n.User + "@")
	}
	sb.WriteString(n.Computer)
	if n.MAC != "" {
		sb.WriteString(" [" + n.MAC + "]")
	}
	return sb.String()
}

const (
	nbNameLen      = 18 // 15 chars + suffix + 2 flag bytes
	nbSuffixMsgr   = 0x03
	nbSuffixWkst   = 0x00
	nbGroupFlag    = 0x8000
	nbTypeNBSTAT   = 0x21
	nbHeaderLength = 12
)

// nbstatRequest builds a node status request for the wildcard name "*".
func nbstatRequest(id uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) // flags, QD=1
	b = append(b, 0x20, 'C', 'K')               // first-level encoded "*"
	for range 30 {
		b = append(b, 'A') // remaining 15 NUL bytes, encoded
	}
	b = append(b, 0, 0, nbTypeNBSTAT, 0, 1)
	return b
}

// parseNBSTAT validates and parses a node status response.
func parseNBSTAT(resp []byte, id uint16) (NetBIOSInfo, error) {
	bad := errors.New("netbios: malformed response")
	if len(resp) < nbHeaderLength+2 || binary.BigEndian.Uint16(resp) != id || resp[2]&0x80 == 0 {
		return NetBIOSInfo{}, bad
	}
	off := nbHeaderLength
	// skip answer name: labels or compression pointer
	for off < len(resp) {
		l := int(resp[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			off += 2
			break
		}
		off += 1 + l
	}
	// type(2) class(2) ttl(4) rdlength(2)
	if off+10 > len(resp) || binary.BigEndian.Uint16(resp[off:]) != nbTypeNBSTAT {
		return NetBIOSInfo{}, bad
	}
	return parseNodeNames(resp, off+10)
}

// parseNodeNames parses the NBSTAT RDATA starting at the NUM_NAMES byte.
func parseNodeNames(resp []byte, start int) (NetBIOSInfo, error) {
	if start >= len(resp) {
		return NetBIOSInfo{}, errors.New("netbios: truncated response")
	}
	count := int(resp[start])
	names := resp[start+1:]
	if count == 0 || len(names) < count*nbNameLen {
		return NetBIOSInfo{}, errors.New("netbios: truncated name table")
	}
	entry := func(i int) (name string, suffix byte, flags uint16) {
		e := names[i*nbNameLen : (i+1)*nbNameLen]
		return decodeName(e[:15]), e[15], binary.BigEndian.Uint16(e[16:])
	}
	var info NetBIOSInfo
	info.Computer, _, _ = entry(0)
	for i := 1; i < count; i++ {
		if name, suffix, flags := entry(i); suffix == nbSuffixWkst && flags&nbGroupFlag != 0 {
			info.Group = name
			break
		}
	}
	for i := count - 1; i > 0; i-- {
		if name, suffix, _ := entry(i); suffix == nbSuffixMsgr {
			info.User = name
			break
		}
	}
	if macOff := count * nbNameLen; len(names) >= macOff+6 {
		if m := names[macOff : macOff+6]; string(m) != "\x00\x00\x00\x00\x00\x00" {
			info.MAC = mac.FromBytes(m)
		}
	}
	return info, nil
}

// decodeName converts an OEM (treated as Latin-1) padded name to a string.
func decodeName(b []byte) string {
	r := make([]rune, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c != 0x7F {
			r = append(r, rune(c))
		}
	}
	return strings.TrimSpace(string(r))
}

// NetBIOS queries the NetBIOS name service (UDP 137) of addr. IPv4 only.
func NetBIOS(ctx context.Context, addr netip.Addr, timeout time.Duration) (NetBIOSInfo, error) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return NetBIOSInfo{}, errors.New("netbios: IPv4 only")
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp4", netip.AddrPortFrom(addr, 137).String())
	if err != nil {
		return NetBIOSInfo{}, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	id := uint16(rand.UintN(0x10000))
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return NetBIOSInfo{}, err
	}
	if _, err := c.Write(nbstatRequest(id)); err != nil {
		return NetBIOSInfo{}, err
	}
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return NetBIOSInfo{}, err
		}
		if info, err := parseNBSTAT(buf[:n], id); err == nil {
			return info, nil
		}
	}
}
