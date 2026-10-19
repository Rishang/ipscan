// SPDX-License-Identifier: GPL-2.0-or-later

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/noobi/ipscan-go/internal/model"
)

// Scanner holds scanning and pinging settings. Defaults match Angry IP Scanner.
type Scanner struct {
	MaxThreads        int    `toml:"max_threads" comment:"maximum concurrent hosts; 0 = automatic (up to 1024)"`
	ThreadDelayMs     int    `toml:"thread_delay_ms" comment:"delay between starting hosts, in ms"`
	ScanDeadHosts     bool   `toml:"scan_dead_hosts" comment:"run all fetchers even for hosts that do not reply to ping"`
	Pinger            string `toml:"pinger" comment:"auto, icmp, udp, tcp or combined"`
	PingTimeoutMs     int    `toml:"ping_timeout_ms"`
	PingCount         int    `toml:"ping_count"`
	SkipBroadcast     bool   `toml:"skip_broadcast" comment:"skip network and broadcast addresses"`
	PortTimeoutMs     int    `toml:"port_timeout_ms"`
	AdaptPortTimeout  bool   `toml:"adapt_port_timeout" comment:"shorten port timeout based on ping round-trip time"`
	MinPortTimeoutMs  int    `toml:"min_port_timeout_ms"`
	Ports             string `toml:"ports" comment:"ports to scan, e.g. 22,80,443,8000-8100"`
	UseRequestedPorts bool   `toml:"use_requested_ports" comment:"also scan ports given as host:port in target files"`
	PortConcurrency   int    `toml:"port_concurrency" comment:"ports probed in parallel per host"`
	NotAvailableText  string `toml:"not_available_text"`
	NotScannedText    string `toml:"not_scanned_text"`
}

// PortText configures a fetcher that sends text to a TCP port and extracts a
// regular expression group from the response.
type PortText struct {
	Port  int    `toml:"port"`
	Send  string `toml:"send"`
	Match string `toml:"match"`
	Group int    `toml:"group"`
}

// Fetchers holds per-fetcher preferences.
type Fetchers struct {
	MACSeparator string   `toml:"mac_separator"`
	WebDetect    PortText `toml:"web_detect"`
	HTTPSender   PortText `toml:"http_sender"`
	HTTPProxy    PortText `toml:"http_proxy"`
}

// Profile is a named set of targets and option overrides (the CLI
// equivalent of GUI favorites). Empty fields do not override anything.
type Profile struct {
	Targets  []string `toml:"targets"`
	Fetchers []string `toml:"fetchers,omitempty"`
	Ports    string   `toml:"ports,omitempty"`
	Pinger   string   `toml:"pinger,omitempty"`
	Display  string   `toml:"display,omitempty"`
}

// Config is the whole configuration file.
type Config struct {
	Scanner  Scanner            `toml:"scanner"`
	Selected []string           `toml:"fetchers" comment:"default columns; see 'ipscan list-fetchers'"`
	Display  string             `toml:"display" comment:"all, alive or ports"`
	Fetcher  Fetchers           `toml:"fetcher"`
	Profiles map[string]Profile `toml:"profiles,omitempty"`
}

// Display methods.
const (
	DisplayAll   = "all"
	DisplayAlive = "alive"
	DisplayPorts = "ports"
)

// Default returns the default configuration.
func Default() *Config {
	return &Config{
		Scanner: Scanner{
			ThreadDelayMs:     20,
			Pinger:            "auto",
			PingTimeoutMs:     2000,
			PingCount:         3,
			SkipBroadcast:     true,
			PortTimeoutMs:     2000,
			AdaptPortTimeout:  true,
			MinPortTimeoutMs:  100,
			Ports:             "80,443,8080",
			UseRequestedPorts: true,
			PortConcurrency:   8,
			NotAvailableText:  model.DefaultLabels.NotAvailable,
			NotScannedText:    model.DefaultLabels.NotScanned,
		},
		Selected: []string{"ip", "ping", "hostname", "ports"},
		Display:  DisplayAlive,
		Fetcher: Fetchers{
			MACSeparator: ":",
			WebDetect:    PortText{Port: 80, Send: "HEAD /robots.txt HTTP/1.0\r\n\r\n", Match: `^[Ss]erver:\s+(.*)$`, Group: 1},
			HTTPSender:   PortText{Port: 80, Send: "HEAD / HTTP/1.0\r\n\r\n", Match: `^Date: (.*)$`, Group: 1},
			HTTPProxy:    PortText{Port: 3128, Send: "HEAD http://www.google.com HTTP/1.0\r\n\r\n", Match: `^(HTTP/[\d.]+ [23].*)$`, Group: 1},
		},
	}
}

// Validate checks value ranges and syntax.
func (c *Config) Validate() error {
	s := &c.Scanner
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(s.MaxThreads >= 0 && s.MaxThreads <= 65535, "max_threads must be between 0 and 65535")
	check(s.ThreadDelayMs >= 0, "thread_delay_ms must not be negative")
	check(s.PingTimeoutMs > 0, "ping_timeout_ms must be positive")
	check(s.PingCount > 0 && s.PingCount <= 100, "ping_count must be between 1 and 100")
	check(s.PortTimeoutMs > 0, "port_timeout_ms must be positive")
	check(s.PortConcurrency > 0 && s.PortConcurrency <= 1024, "port_concurrency must be between 1 and 1024")
	check(s.MinPortTimeoutMs > 0 && s.MinPortTimeoutMs <= s.PortTimeoutMs, "min_port_timeout_ms must be positive and not above port_timeout_ms")
	if _, err := model.ParsePorts(s.Ports); err != nil {
		errs = append(errs, fmt.Errorf("ports: %w", err))
	}
	check(slices.Contains([]string{DisplayAll, DisplayAlive, DisplayPorts}, c.Display), "display must be all, alive or ports")
	for name, pt := range map[string]PortText{"web_detect": c.Fetcher.WebDetect, "http_sender": c.Fetcher.HTTPSender, "http_proxy": c.Fetcher.HTTPProxy} {
		check(pt.Port > 0 && pt.Port <= 65535, "fetcher.%s.port out of range", name)
		check(pt.Group >= 0, "fetcher.%s.group must not be negative", name)
		if re, err := regexp.Compile(pt.Match); err != nil {
			errs = append(errs, fmt.Errorf("fetcher.%s.match: %w", name, err))
		} else {
			check(pt.Group <= re.NumSubexp(), "fetcher.%s.group exceeds number of groups in match", name)
		}
	}
	return errors.Join(errs...)
}

// Labels returns the configured texts for empty values.
func (s *Scanner) Labels() model.Labels {
	return model.Labels{NotAvailable: s.NotAvailableText, NotScanned: s.NotScannedText}
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func (s *Scanner) ThreadDelay() time.Duration    { return ms(s.ThreadDelayMs) }
func (s *Scanner) PingTimeout() time.Duration    { return ms(s.PingTimeoutMs) }
func (s *Scanner) PortTimeout() time.Duration    { return ms(s.PortTimeoutMs) }
func (s *Scanner) MinPortTimeout() time.Duration { return ms(s.MinPortTimeoutMs) }

// EnvPath names the environment variable overriding the config file location.
const EnvPath = "IPSCAN_CONFIG"

// Path returns the configuration file location.
func Path() (string, error) {
	if p := os.Getenv(EnvPath); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ipscan", "config.toml"), nil
}

// Load reads the configuration at path over the defaults. A missing file
// yields the defaults. Unknown keys are rejected to catch typos.
func Load(path string) (*Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		var sme *toml.StrictMissingError
		if errors.As(err, &sme) {
			return nil, fmt.Errorf("%s: %s", path, strings.TrimSpace(sme.String()))
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Marshal renders the configuration as TOML.
func (c *Config) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# ipscan configuration\n\n")
	enc := toml.NewEncoder(&buf).SetIndentTables(true)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save writes the configuration atomically with owner-only permissions.
func (c *Config) Save(path string) error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
