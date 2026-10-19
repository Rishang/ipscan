// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from Angry IP Scanner (https://angryip.org/), Copyright Anton Keks and contributors.

// Command ipscan is a fast, friendly command-line network scanner.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = ""

// Exit codes.
const (
	exitOK          = 0
	exitUsage       = 1
	exitRuntime     = 2
	exitInterrupted = 130
)

// usageError marks errors caused by invalid command-line input.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

// errInterrupted is returned when the user stopped the scan with a signal.
var errInterrupted = errors.New("interrupted")

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func newRootCmd() *cobra.Command {
	o := &scanOpts{}
	root := &cobra.Command{
		Use:   "ipscan [flags] <target>...",
		Short: "Fast and friendly network scanner",
		Long: `ipscan scans networks for alive hosts and collects information about them:
ping time, hostname, open ports, MAC address and vendor, NetBIOS info and more.

Targets:
  10.0.0.1                single address (IPv4 or IPv6)
  10.0.0.1-10.0.0.50      range (may be reversed)
  10.0.0.1-50             last-octet range
  10.0-3.1-5.1, 10.0.0.*  per-octet ranges and wildcards
  10.0.0.0/24             CIDR (also 2001:db8::/120)
  10.0.0.7/255.255.255.0  address with netmask
  example.com[/24]        hostname, optionally with a netmask
Several targets may be given, separated by spaces or commas.`,
		Example: `  ipscan 192.168.1.0/24
  ipscan --local -f +mac,vendor
  ipscan 10.0.0.1-254 -p 22,80,443,8000-8100 --display ports
  ipscan 10.0.0.0/24 -o results.csv
  ipscan --file hosts.txt --format ndjson -o - | jq .
  ipscan --random 100 10.0.0.0/8`,
		Version:       resolveVersion(),
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, o, args)
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })
	o.register(root)
	root.AddCommand(newListFetchersCmd(o), newListPingersCmd(), newListInterfacesCmd(), newConfigCmd(o))
	return root
}

func run(args []string, stdout, stderr io.Writer) int {
	args, legacy := rewriteLegacyArgs(args)
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if legacy {
		fmt.Fprintln(stderr, "ipscan: note: translated Angry IP Scanner style arguments to:", args)
	}
	err := root.Execute()
	var ue usageError
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errInterrupted):
		return exitInterrupted
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, "ipscan:", err)
		fmt.Fprintln(stderr, "Run 'ipscan --help' for usage.")
		return exitUsage
	default:
		fmt.Fprintln(stderr, "ipscan:", err)
		return exitRuntime
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
