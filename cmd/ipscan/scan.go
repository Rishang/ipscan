// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/noobi/ipscan-go/internal/config"
	"github.com/noobi/ipscan-go/internal/export"
	"github.com/noobi/ipscan-go/internal/feeder"
	"github.com/noobi/ipscan-go/internal/fetcher"
	"github.com/noobi/ipscan-go/internal/model"
	"github.com/noobi/ipscan-go/internal/netutil"
	"github.com/noobi/ipscan-go/internal/output"
	"github.com/noobi/ipscan-go/internal/pinger"
	"github.com/noobi/ipscan-go/internal/scan"
)

type scanOpts struct {
	configPath   string
	profile      string
	fetchers     []string
	ports        string
	pinger       string
	pingCount    int
	pingTimeout  time.Duration
	portTimeout  time.Duration
	threads      int
	delay        time.Duration
	scanDead     bool
	noPing       bool
	noSkipBcast  bool
	display      string
	output       string
	format       string
	appendOut    bool
	file         string
	random       int
	local        bool
	sortSpec     string
	noProgress   bool
	quiet        bool
	noColor      bool
	verbose      int
	legacyFeeder string
}

func (o *scanOpts) register(c *cobra.Command) {
	pf := c.PersistentFlags()
	pf.StringVar(&o.configPath, "config", "", "configuration file (default: $"+config.EnvPath+" or the user config dir)")

	f := c.Flags()
	f.SortFlags = false
	f.StringSliceVarP(&o.fetchers, "fetchers", "f", nil, "columns to show, e.g. ping,hostname,ports; prefix all with + to add to the defaults (see list-fetchers)")
	f.StringVarP(&o.ports, "ports", "p", "", "ports to scan, e.g. 22,80,443,8000-8100")
	f.StringVar(&o.display, "display", "", "which hosts to show: all, alive or ports")
	f.StringVar(&o.profile, "profile", "", "use a named profile from the configuration file")
	f.StringVar(&o.file, "file", "", "read targets (IPs, hostnames, host:port) from a text file")
	f.IntVar(&o.random, "random", 0, "scan N random addresses within each BASE/MASK target")
	f.BoolVar(&o.local, "local", false, "scan the local network of the default interface")

	f.StringVar(&o.pinger, "pinger", "", "pinging method: "+strings.Join(pinger.Names, ", "))
	f.IntVar(&o.pingCount, "ping-count", 0, "ping probes per host")
	f.DurationVar(&o.pingTimeout, "ping-timeout", 0, "timeout per ping probe (e.g. 500ms)")
	f.BoolVar(&o.noPing, "no-ping", false, "do not ping; treat every host as alive")
	f.BoolVar(&o.scanDead, "scan-dead", false, "run all fetchers even for hosts that do not reply to ping")
	f.DurationVar(&o.portTimeout, "port-timeout", 0, "TCP connect timeout")
	f.IntVarP(&o.threads, "threads", "t", 0, "maximum hosts scanned concurrently (0 = automatic)")
	f.DurationVar(&o.delay, "delay", 0, "delay between starting hosts (e.g. 20ms)")
	f.BoolVar(&o.noSkipBcast, "no-skip-broadcast", false, "also scan network and broadcast addresses")

	f.StringVarP(&o.output, "output", "o", "", "export results to a file ('-' for stdout); format from extension")
	f.StringVar(&o.format, "format", "", "export format: "+strings.Join(export.Formats, ", "))
	f.BoolVarP(&o.appendOut, "append", "a", false, "append to an existing export file")
	f.StringVar(&o.sortSpec, "sort", "", "sort results by column when done, e.g. ping or ping:desc")
	f.BoolVar(&o.noProgress, "no-progress", false, "do not show the progress line")
	f.BoolVar(&o.noColor, "no-color", false, "disable colors")
	f.BoolVarP(&o.quiet, "quiet", "q", false, "no table, progress or summary (errors only)")
	f.CountVarP(&o.verbose, "verbose", "v", "log more details (repeat for debug)")
	f.StringVar(&o.legacyFeeder, "legacy-feeder", "", "")
	_ = f.MarkHidden("legacy-feeder")
}

func (o *scanOpts) loadConfig() (*config.Config, string, error) {
	path := o.configPath
	if path == "" {
		var err error
		if path, err = config.Path(); err != nil {
			return nil, "", err
		}
	}
	cfg, err := config.Load(path)
	return cfg, path, err
}

// applyFetchers handles "+x,y" (add to current) vs. a full replacement list.
// A leading + on any item switches to additive mode.
func applyFetchers(current, given []string) []string {
	if slices.ContainsFunc(given, func(s string) bool { return strings.HasPrefix(s, "+") }) {
		out := slices.Clone(current)
		for _, g := range given {
			out = append(out, strings.TrimPrefix(g, "+"))
		}
		return out
	}
	return given
}

// effectiveConfig merges defaults, config file, profile and flags (in that order).
func (o *scanOpts) effectiveConfig(cmd *cobra.Command) (*config.Config, []string, error) {
	cfg, _, err := o.loadConfig()
	if err != nil {
		return nil, nil, err
	}
	var targets []string
	if o.profile != "" {
		p, ok := cfg.Profiles[o.profile]
		if !ok {
			return nil, nil, usagef("unknown profile %q", o.profile)
		}
		targets = p.Targets
		if len(p.Fetchers) > 0 {
			cfg.Selected = applyFetchers(cfg.Selected, p.Fetchers)
		}
		if p.Ports != "" {
			cfg.Scanner.Ports = p.Ports
		}
		if p.Pinger != "" {
			cfg.Scanner.Pinger = p.Pinger
		}
		if p.Display != "" {
			cfg.Display = p.Display
		}
	}
	fl := cmd.Flags()
	s := &cfg.Scanner
	if fl.Changed("fetchers") {
		cfg.Selected = applyFetchers(cfg.Selected, o.fetchers)
	}
	if fl.Changed("ports") {
		s.Ports = o.ports
	}
	if fl.Changed("display") {
		cfg.Display = o.display
	}
	if fl.Changed("pinger") {
		s.Pinger = o.pinger
	}
	if fl.Changed("ping-count") {
		s.PingCount = o.pingCount
	}
	if fl.Changed("ping-timeout") {
		s.PingTimeoutMs = int(o.pingTimeout.Milliseconds())
	}
	if fl.Changed("port-timeout") {
		s.PortTimeoutMs = int(o.portTimeout.Milliseconds())
		s.MinPortTimeoutMs = min(s.MinPortTimeoutMs, s.PortTimeoutMs)
	}
	if fl.Changed("threads") {
		s.MaxThreads = o.threads
	}
	if fl.Changed("delay") {
		s.ThreadDelayMs = int(o.delay.Milliseconds())
	}
	if o.scanDead {
		s.ScanDeadHosts = true
	}
	if o.noSkipBcast {
		s.SkipBroadcast = false
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, usageError{err}
	}
	return cfg, targets, nil
}

func (o *scanOpts) buildFeeder(ctx context.Context, args []string) (feeder.Feeder, error) {
	if o.legacyFeeder != "" {
		return nil, usagef("unknown Angry IP Scanner feeder -f:%s (supported: range, random, file)", o.legacyFeeder)
	}
	var feeders []feeder.Feeder
	if o.local {
		ia, ok := netutil.DefaultLocal(netutil.CachedInterfaces())
		if !ok {
			return nil, errors.New("no local IPv4 network found")
		}
		p := ia.Prefix
		if p.Bits() < 16 {
			slog.Warn("local network is large, scanning only the surrounding /24", "network", p.Masked())
			p = netip.PrefixFrom(p.Addr(), 24)
		}
		args = append(args, p.Masked().String())
	}
	if o.random > 0 {
		for _, a := range args {
			for _, spec := range strings.Split(a, ",") {
				f, err := feeder.ParseRandom(ctx, spec, o.random, feeder.DefaultResolver)
				if err != nil {
					return nil, usageError{err}
				}
				feeders = append(feeders, f)
			}
		}
	} else if len(args) > 0 {
		f, err := feeder.ParseTargets(ctx, args, feeder.DefaultResolver)
		if err != nil {
			return nil, usageError{err}
		}
		feeders = append(feeders, f)
	}
	if o.file != "" {
		f, err := feeder.NewFile(ctx, o.file, feeder.DefaultResolver)
		if err != nil {
			return nil, err
		}
		feeders = append(feeders, f)
	}
	if len(feeders) == 0 {
		return nil, usagef("no scan targets given (e.g. 'ipscan 192.168.1.0/24' or 'ipscan --local')")
	}
	return feeder.NewMulti(feeders...), nil
}

func parseSort(spec string, fetchers []fetcher.Fetcher) (col int, asc bool, err error) {
	name, dir, _ := strings.Cut(spec, ":")
	switch strings.ToLower(dir) {
	case "", "asc":
		asc = true
	case "desc":
	default:
		return 0, false, usagef("invalid sort direction %q (asc or desc)", dir)
	}
	if n, err := strconv.Atoi(name); err == nil && n >= 1 && n <= len(fetchers) {
		return n - 1, asc, nil
	}
	id := fetcher.Normalize(name)
	for i, f := range fetchers {
		if f.ID() == id {
			return i, asc, nil
		}
	}
	return 0, false, usagef("cannot sort by %q: not a selected column", name)
}

func keep(display string, t model.ResultType) bool {
	switch display {
	case config.DisplayAll:
		return true
	case config.DisplayPorts:
		return t == model.WithPorts
	}
	return t >= model.Alive
}

func setupLogging(stderr io.Writer, verbose int) {
	level := slog.LevelWarn
	switch {
	case verbose >= 2:
		level = slog.LevelDebug
	case verbose == 1:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})))
}

func asFile(w io.Writer) *os.File {
	f, _ := w.(*os.File)
	return f
}

func runScan(cmd *cobra.Command, o *scanOpts, args []string) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	setupLogging(stderr, o.verbose)
	cfg, profileTargets, err := o.effectiveConfig(cmd)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		args = profileTargets
	}

	ctx := cmd.Context()
	resolveCtx, cancelResolve := context.WithTimeout(ctx, 30*time.Second)
	fd, err := o.buildFeeder(resolveCtx, args)
	cancelResolve()
	if err != nil {
		return err
	}

	env, err := fetcher.NewEnv(cfg, o.noPing)
	if err != nil {
		return usageError{err}
	}
	fetchers, err := fetcher.Select(fetcher.All(cfg), cfg.Selected)
	if err != nil {
		return usageError{err}
	}
	sortCol, sortAsc, sorting := 0, true, o.sortSpec != ""
	if sorting {
		if sortCol, sortAsc, err = parseSort(o.sortSpec, fetchers); err != nil {
			return err
		}
	}

	// Export destination.
	format := o.format
	outPath := o.output
	if outPath == "" && format != "" {
		outPath = "-"
	}
	var exp export.Exporter
	var out *export.Output
	if outPath != "" {
		if format == "" {
			if outPath == "-" {
				format = "txt"
			} else if format, err = export.FormatFromPath(outPath); err != nil {
				return usageError{err}
			}
		}
		if exp, err = export.New(format); err != nil {
			return usageError{err}
		}
		if out, err = export.Open(outPath, format, o.appendOut, stdout); err != nil {
			return err
		}
		defer out.Close()
	}

	labels := cfg.Scanner.Labels()
	cols := make([]export.Column, len(fetchers))
	names := make([]string, len(fetchers))
	for i, f := range fetchers {
		cols[i] = export.Column{ID: f.ID(), Name: f.Name()}
		names[i] = f.Name()
	}
	if exp != nil {
		meta := export.Meta{Version: resolveVersion(), FeederName: fd.Name(), FeederInfo: fd.Info(),
			Time: time.Now(), Columns: cols, Labels: labels}
		if err := exp.Start(out, meta, out.Appending); err != nil {
			return err
		}
	}

	var mu sync.Mutex
	showTable := !o.quiet && outPath != "-"
	color := !o.noColor && asFile(stdout) != nil && output.ColorEnabled(asFile(stdout))
	table := output.NewTable(stdout, names, labels, color, &mu)
	var progress *output.Progress
	if !o.quiet && !o.noProgress && asFile(stderr) != nil && output.IsTerminal(asFile(stderr)) {
		progress = output.NewProgress(stderr, !o.noColor && output.ColorEnabled(asFile(stderr)), &mu)
		setupLogging(progress.Writer(), o.verbose)
	}
	if showTable {
		if err := table.Header(); err != nil {
			return err
		}
	}

	var emitErr error
	emit := func(r *model.Result) {
		if showTable {
			if progress != nil {
				progress.Clear()
			}
			if err := table.Row(r); err != nil && emitErr == nil {
				emitErr = err
			}
		}
		if exp != nil {
			if err := exp.Row(r); err != nil && emitErr == nil {
				emitErr = err
			}
		}
	}
	var buffered []*model.Result

	// First Ctrl-C stops dispatching, second kills in-flight probes, third exits.
	stop, cancelStop := context.WithCancel(ctx)
	defer cancelStop()
	kill, cancelKill := context.WithCancel(ctx)
	defer cancelKill()
	interrupted := false
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	defer signal.Stop(sigs)
	go func() {
		for n := 1; ; n++ {
			if _, ok := <-sigs; !ok {
				return
			}
			interrupted = true
			switch n {
			case 1:
				cancelStop()
				msg(progress, stderr, o.quiet, "Stopping: waiting for running hosts to finish (Ctrl-C again to abort them)")
			case 2:
				cancelKill()
				msg(progress, stderr, o.quiet, "Aborting all running hosts")
			default:
				os.Exit(exitInterrupted)
			}
		}
	}()

	stats := scan.Run(stop, kill, scan.Options{
		Feeder: fd, Env: env, Fetchers: fetchers,
		MaxThreads: cfg.Scanner.MaxThreads, Delay: cfg.Scanner.ThreadDelay(),
		SkipBroadcast: cfg.Scanner.SkipBroadcast,
		OnResult: func(r *model.Result) {
			if !keep(cfg.Display, r.Type) {
				return
			}
			if sorting {
				buffered = append(buffered, r)
			} else {
				emit(r)
			}
		},
		OnProgress: func(p scan.Progress) {
			if progress != nil {
				progress.Update(p)
			}
		},
	})
	if progress != nil {
		progress.Clear()
	}
	signal.Stop(sigs)
	close(sigs)
	if sorting {
		model.SortResults(buffered, sortCol, sortAsc)
		for _, r := range buffered {
			emit(r)
		}
	}
	if exp != nil {
		if err := exp.End(); err != nil && emitErr == nil {
			emitErr = err
		}
		if emitErr == nil {
			emitErr = out.Commit()
		}
	}
	if emitErr != nil {
		return fmt.Errorf("writing results: %w", emitErr)
	}
	if !o.quiet {
		output.Summary(stderr, stats.Snapshot(), fd.Info())
		if outPath != "" && outPath != "-" {
			fmt.Fprintf(stderr, "Saved results to %s\n", outPath)
		}
	}
	if interrupted {
		return errInterrupted
	}
	return nil
}

func msg(p *output.Progress, w io.Writer, quiet bool, s string) {
	if quiet {
		return
	}
	if p != nil {
		p.Message("%s", s)
		return
	}
	fmt.Fprintln(w, s)
}
