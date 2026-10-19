# ipscan-go

Command-line network scanner, a Go port of Angry IP Scanner (without the GUI). It builds as one static binary (`CGO_ENABLED=0`) for Linux, macOS and Windows on amd64 and arm64. The license is GPL-2.0-or-later, and every Go file starts with `// SPDX-License-Identifier: GPL-2.0-or-later`.

The original Java sources live in `.local/ipscan/` (untracked, read-only reference). Use them when you need to check the original behavior, and do not edit them.

## Commands

Build and checks go through [Task](https://taskfile.dev) (`Taskfile.yml`), not Make:

```bash
task build        # bin/ipscan for the current platform
task all          # fmt-check, vet (6 targets), test -race, build
task test         # go test -race ./...  (needs CGO for -race)
task test-short   # skips network tests
task lint         # staticcheck, pinned version
task fmt          # gofmt -w .
task run -- 127.0.0.1-5
task dist VERSION=v0.1.0   # dist/*.tar.gz, *.zip, SHA256SUMS
```

Always run `task vet` after touching OS-specific files. It vets all six release targets, and Windows and macOS code can't be run on Linux.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/ipscan/` | CLI (cobra): `scan.go` is the main flow, `cmds.go` the subcommands, `legacy.go` rewrites old `-f:range ...` arguments |
| `internal/model` | `Value`, `Result`, `ResultType`, `Stats`, sorting, port lists |
| `internal/netutil` | netmask parsing, range math, broadcast detection, interface snapshot |
| `internal/feeder` | target sources: range, random, file, target-expression parser |
| `internal/pinger` | ICMP (unix and Windows API), TCP, UDP, combined, ARP wrapper |
| `internal/mac` | neighbour-table lookup per OS, embedded OUI vendor list |
| `internal/resolve` | mDNS and NetBIOS queries |
| `internal/fetcher` | per-host state (`Host`), the fetchers (columns), `Run` |
| `internal/scan` | concurrent engine with stop/kill |
| `internal/export` | txt, csv, xml, sql, lst, json, ndjson exporters and safe file output |
| `internal/output` | terminal table, progress line, summary |
| `internal/config` | TOML config, profiles, validation |
| `testdata/` | fixtures taken from the Java tests |

## Conventions

- Standard library first. The only third-party modules are cobra, go-toml, `golang.org/x/{net,sys,term}`.
- OS-specific code goes in files with `_linux`, `_windows`, `_bsd` or `_unix` suffixes or build tags. Every platform must compile.
- Don't use cgo. Use `context` cancellation for all network I/O, so the "kill" action can abort in-flight probes.
- Tests are table-driven. Network tests use `testing.Short()` to skip, and ICMP tests skip when sockets aren't permitted. Run `-race` on anything concurrent.
- Don't copy known Java bugs. Examples that have regression tests: range stepping backwards, merging ping results, SQL `NULL`, mDNS/NetBIOS reply validation, and unlimited TCP timeouts.

## Gotchas

- `model.Value` contains a slice, so it is **not comparable** with `==`. Compare `v.Kind`, as in `v.Kind == model.KindNotAvailable`.
- Fetcher column order matters only for display. Shared work (ping, ports, MAC) is cached lazily on `fetcher.Host`, and `ip` is always forced first by `fetcher.Select`.
- Dead hosts skip all fetchers except `ping`, `ttl` and `packetloss`, unless `scan_dead_hosts` is set. A run with `--no-ping` treats every host as alive.
- The scan engine has two contexts. The `stop` context only ends dispatching, and the `kill` context also aborts in-flight I/O. The first Ctrl-C cancels `stop` and the second cancels `kill`.
- `--display` filters rows before they reach the table or exporters. Rows that are filtered out are dropped, not hidden.
- Exports write new files to a temp file and rename them on success. Appending is refused for symlinks and for files that don't look like an ipscan export of the same format.
- Config lookup order is defaults, then the file (`$IPSCAN_CONFIG` or the user config dir), then `--profile`, then CLI flags. Unknown TOML keys are errors.
- Exit codes: 0 ok, 1 usage error, 2 runtime error, 130 interrupted.

## Release

CI is in `.github/workflows/ci.yml`. Pushing a `v*` tag runs `release.yml`, which builds all six targets and publishes a GitHub release. The module path is `github.com/noobi/ipscan-go`.
