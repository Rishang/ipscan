// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
)

// rewriteLegacyArgs translates the Angry IP Scanner command line
//
//	ipscan -f:range 10.0.0.1 10.0.0.254 -o out.txt -s -q -a
//
// into the native syntax. It only applies when a "-f:<feeder>" argument is
// present; -s (start) and -q (quit after export) are implied for a CLI.
func rewriteLegacyArgs(args []string) ([]string, bool) {
	legacy := false
	for _, a := range args {
		if strings.HasPrefix(a, "-f:") {
			legacy = true
			break
		}
	}
	if !legacy {
		return args, false
	}
	var out []string
	take := func(i, n int) []string {
		end := min(i+1+n, len(args))
		return args[i+1 : end]
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f:range":
			p := take(i, 2)
			i += len(p)
			if len(p) == 2 {
				out = append(out, p[0]+"-"+p[1])
			} else {
				out = append(out, p...)
			}
		case a == "-f:random":
			p := take(i, 3)
			i += len(p)
			if len(p) == 3 {
				out = append(out, "--random", p[2], p[0]+"/"+p[1])
			} else {
				out = append(out, p...)
			}
		case a == "-f:file":
			p := take(i, 1)
			i += len(p)
			out = append(out, "--file")
			out = append(out, p...)
		case strings.HasPrefix(a, "-f:"):
			out = append(out, "--legacy-feeder", strings.TrimPrefix(a, "-f:"))
		case a == "-o":
			out = append(out, "--output")
		case len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.Trim(a[1:], "sqa") == "":
			// -s (start) and -q (quit) are implied; only -a (append) matters.
			if strings.Contains(a, "a") {
				out = append(out, "--append")
			}
		default:
			out = append(out, a)
		}
	}
	return out, true
}
