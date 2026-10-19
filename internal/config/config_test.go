// SPDX-License-Identifier: GPL-2.0-or-later

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Scanner.PingTimeout().Milliseconds() != 2000 || c.Scanner.ThreadDelay().Milliseconds() != 20 {
		t.Error("duration helpers")
	}
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil || c.Scanner.Ports != "80,443,8080" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLoadMergesOverDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.toml")
	data := `
display = "all"
[scanner]
ports = "22"
ping_count = 1
[fetcher.http_proxy]
port = 8080
[profiles.home]
targets = ["192.168.1.0/24"]
fetchers = ["ip", "mac"]
`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Display != "all" || c.Scanner.Ports != "22" || c.Scanner.PingCount != 1 || c.Scanner.PingTimeoutMs != 2000 {
		t.Errorf("scanner: %+v", c.Scanner)
	}
	if c.Fetcher.HTTPProxy.Port != 8080 || !strings.HasPrefix(c.Fetcher.HTTPProxy.Send, "HEAD http://") {
		t.Errorf("partial table must keep defaults: %+v", c.Fetcher.HTTPProxy)
	}
	if pr := c.Profiles["home"]; len(pr.Targets) != 1 || pr.Fetchers[1] != "mac" {
		t.Errorf("profile: %+v", pr)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	for _, data := range []string{
		"[scanner]\nprots = \"22\"",           // typo
		"[scanner]\nports = \"70000\"",        // invalid ports
		"[scanner]\nping_count = 0",           // range
		"display = \"some\"",                  // enum
		"[fetcher.web_detect]\nmatch = \"(\"", // regex
		"not toml",
	} {
		p := filepath.Join(t.TempDir(), "c.toml")
		_ = os.WriteFile(p, []byte(data), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("Load(%q) should fail", data)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config.toml")
	c := Default()
	c.Scanner.Ports = "1-1024"
	c.Profiles = map[string]Profile{"lan": {Targets: []string{"10.0.0.0/24"}}}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
	}
	c2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Scanner.Ports != "1-1024" || c2.Profiles["lan"].Targets[0] != "10.0.0.0/24" || c2.Fetcher.WebDetect.Send != c.Fetcher.WebDetect.Send {
		t.Errorf("round trip: %+v", c2)
	}
}

func TestPathEnvOverride(t *testing.T) {
	t.Setenv(EnvPath, "/tmp/x.toml")
	if p, _ := Path(); p != "/tmp/x.toml" {
		t.Errorf("Path = %s", p)
	}
}
