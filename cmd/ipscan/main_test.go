// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRewriteLegacyArgs(t *testing.T) {
	tests := []struct {
		in, want []string
		legacy   bool
	}{
		{[]string{"10.0.0.0/24", "-o", "x.csv"}, []string{"10.0.0.0/24", "-o", "x.csv"}, false},
		{[]string{"-f:range", "1.2.3.4", "1.2.3.9", "-o", "x.txt", "-sq"}, []string{"1.2.3.4-1.2.3.9", "--output", "x.txt"}, true},
		{[]string{"-f:random", "10.0.0.0", "255.0.0.0", "50", "-s"}, []string{"--random", "50", "10.0.0.0/255.0.0.0"}, true},
		{[]string{"-f:file", "hosts.txt", "-o", "a.csv", "-a"}, []string{"--file", "hosts.txt", "--output", "a.csv", "--append"}, true},
		{[]string{"-f:range", "1.2.3.4"}, []string{"1.2.3.4"}, true},
		{[]string{"-f:bogus", "x"}, []string{"--legacy-feeder", "bogus", "x"}, true},
	}
	for _, tt := range tests {
		got, legacy := rewriteLegacyArgs(tt.in)
		if !slices.Equal(got, tt.want) || legacy != tt.legacy {
			t.Errorf("rewrite(%v) = %v,%v want %v", tt.in, got, legacy, tt.want)
		}
	}
}

func TestApplyFetchers(t *testing.T) {
	cur := []string{"ip", "ping"}
	if got := applyFetchers(cur, []string{"+mac", "vendor"}); !slices.Equal(got, []string{"ip", "ping", "mac", "vendor"}) {
		t.Errorf("additive = %v", got)
	}
	if got := applyFetchers(cur, []string{"mac"}); !slices.Equal(got, []string{"mac"}) {
		t.Errorf("replace = %v", got)
	}
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("IPSCAN_CONFIG", filepath.Join(t.TempDir(), "config.toml"))
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--bogus"}, {"10.0.0.300"}, {"127.0.0.1", "-f", "nope"}, {"127.0.0.1", "-p", "0"},
		{"127.0.0.1", "--display", "x"}, {"127.0.0.1", "--sort", "nope"}, {"127.0.0.1", "--format", "pdf"},
		{"127.0.0.1", "--profile", "missing"}, {"-f:bogus", "x"},
	} {
		if code, _, stderr := runCLI(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, stderr %s", args, code, stderr)
		}
	}
}

func TestCLIScanLocalhost(t *testing.T) {
	code, stdout, stderr := runCLI(t, "127.0.0.1-2", "--pinger", "tcp", "--display", "all", "-p", "1", "--no-color")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "  IP") || !strings.Contains(lines[1], "127.0.0.1") {
		t.Errorf("stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "Scan completed") || !strings.Contains(stderr, "Hosts scanned:     2") {
		t.Errorf("stderr:\n%s", stderr)
	}
}

func TestCLIJSONToStdoutAndSort(t *testing.T) {
	code, stdout, stderr := runCLI(t, "127.0.0.3,127.0.0.1,127.0.0.2", "--no-ping", "-f", "+mac,vendor",
		"--format", "json", "--sort", "ip:desc", "-q")
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var doc struct {
		Hosts []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	var ips []string
	for _, h := range doc.Hosts {
		ips = append(ips, h["ip"].(string))
		if _, ok := h["vendor"]; !ok {
			t.Error("vendor column missing")
		}
	}
	if !slices.Equal(ips, []string{"127.0.0.3", "127.0.0.2", "127.0.0.1"}) {
		t.Errorf("sorted ips = %v", ips)
	}
}

func TestCLIExportFileAndProfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.toml")
	_ = os.WriteFile(cfgPath, []byte("[profiles.lo]\ntargets = [\"127.0.0.1\"]\nfetchers = [\"ip\", \"ping\"]\n"), 0o600)
	out := filepath.Join(dir, "r.csv")
	var so, se bytes.Buffer
	code := run([]string{"--config", cfgPath, "--profile", "lo", "--pinger", "tcp", "-o", out, "-q"}, &so, &se)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "IP,Ping\n127.0.0.1,") {
		t.Errorf("csv = %q", b)
	}
	if so.Len() != 0 {
		t.Errorf("quiet must not print a table: %q", so.String())
	}
}

func TestCLISubcommands(t *testing.T) {
	for _, args := range [][]string{{"list-fetchers"}, {"list-pingers"}, {"list-interfaces"}, {"config", "path"}, {"config", "show"}, {"--version"}, {"--help"}} {
		if code, stdout, stderr := runCLI(t, args...); code != exitOK || stdout == "" {
			t.Errorf("%v: exit %d stdout %q stderr %s", args, code, stdout, stderr)
		}
	}
	t.Setenv("IPSCAN_CONFIG", filepath.Join(t.TempDir(), "new", "config.toml"))
	var o, e bytes.Buffer
	if code := run([]string{"config", "init"}, &o, &e); code != exitOK {
		t.Fatalf("init: %s", e.String())
	}
	if code := run([]string{"config", "init"}, &o, &e); code != exitUsage {
		t.Error("second init without --force must fail")
	}
	if code := run([]string{"--profile", "example", "--help"}, &o, &e); code != exitOK {
		t.Error("written config must be loadable")
	}
}
