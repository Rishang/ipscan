// SPDX-License-Identifier: GPL-2.0-or-later

package model

import (
	"fmt"
	"iter"
	"regexp"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of TCP/UDP ports.
type PortRange struct{ Start, End uint16 }

// PortList is a parsed port specification such as "22,80-90,443".
// Order is preserved; duplicates are not removed.
type PortList []PortRange

var portSeparators = regexp.MustCompile(`[\s,;]+`)

// ParsePorts parses a port specification. Ports must be within 1..65535;
// reversed ranges ("90-80") are accepted and normalised.
func ParsePorts(spec string) (PortList, error) {
	var list PortList
	for _, tok := range portSeparators.Split(strings.TrimSpace(spec), -1) {
		if tok == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(tok, "-")
		start, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		end := start
		if isRange {
			if end, err = parsePort(hi); err != nil {
				return nil, err
			}
		}
		if start > end {
			start, end = end, start
		}
		list = append(list, PortRange{start, end})
	}
	return list, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q: must be a number between 1 and 65535", s)
	}
	return uint16(n), nil
}

// Len returns the total number of ports in the list.
func (l PortList) Len() int {
	n := 0
	for _, r := range l {
		n += int(r.End) - int(r.Start) + 1
	}
	return n
}

// All iterates over every port in specification order.
func (l PortList) All() iter.Seq[uint16] {
	return func(yield func(uint16) bool) {
		for _, r := range l {
			for p := int(r.Start); p <= int(r.End); p++ {
				if !yield(uint16(p)) {
					return
				}
			}
		}
	}
}
