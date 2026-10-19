# ipscan-go

A fast, friendly command-line network scanner. It is a Go port of
[Angry IP Scanner](https://angryip.org/) without the GUI, and it builds as a
single static binary for Linux, macOS and Windows (amd64/arm64).

```console
$ ipscan 192.168.1.0/24 -f +mac,vendor
  IP              Ping            Hostname        Ports [3]       MAC Address       MAC Vendor
+ 192.168.1.1     2 ms            router.lan      80,443          B4:A7:C6:E5:1C:1C ServercomIn
* 192.168.1.20    5 ms            laptop.local    [n/a]           22:7B:D4:EB:6A:F1 [n/a]

Scan completed: 192.168.1.0 - 192.168.1.255
  Total time:        6.41 sec
  ...
```

Markers: `+` alive with open ports, `*` alive, `-` dead (shown with `--display all`).

## Install

Download an archive from the [releases](../../releases) page and put `ipscan`
on your `PATH`. Or, with Go 1.26 or later:

```sh
go install github.com/noobi/ipscan-go/cmd/ipscan@latest
```

To build from source, install [Task](https://taskfile.dev) and run `task build`
(output in `bin/`). `task dist` builds release archives for all platforms, and
`task --list` shows the other tasks (`test`, `vet`, `lint`, `fmt`, `cross`, `clean`).

## Usage

```sh
ipscan 10.0.0.1-254                      # last-octet range
ipscan 10.0.0.0/24 172.16.0.1-172.16.1.9 # several targets
ipscan --local                           # the network of the default interface
ipscan example.com/28                    # hostname with a netmask
ipscan --file hosts.txt                  # IPs, hostnames and host:port from any text
ipscan --random 100 10.0.0.0/8           # 100 random addresses
ipscan 10.0.0.0/24 -p 22,80,443,8000-8100 --display ports
ipscan 10.0.0.0/24 -o scan.csv           # export: txt csv xml sql lst json ndjson
ipscan 10.0.0.0/24 --format ndjson -o - | jq .
ipscan 10.0.0.0/24 --sort ping:desc
```

Target forms: a single address (IPv4 or IPv6), `a-b` ranges (which may be
reversed), `10.0.0.1-50`, per-octet ranges and `*`, CIDR, `addr/255.255.255.0`,
and hostnames.

Pressing Ctrl-C once stops starting new hosts and waits for the running ones.
Pressing it twice aborts them. The exit codes are `0` ok, `1` usage error,
`2` runtime error and `130` interrupted.

Run `ipscan --help` for all flags. These subcommands are available:
`list-fetchers`, `list-pingers`, `list-interfaces`, `config path|show|init`
and `completion bash|zsh|fish|powershell`.

### Columns (fetchers)

`ip`, `ping`, `ttl`, `packetloss`, `hostname`, `ports`, `filtered`, `mac`, `vendor`,
`netbios`, `webdetect`, `httpsender`, `httpproxy`. The default set is
`ip,ping,hostname,ports`. Use `-f ping,mac` to replace the defaults, or
`-f +mac,vendor` to add to them.

### Configuration

`ipscan config init` writes a commented TOML file to the user config directory.
You can override the location with `IPSCAN_CONFIG` or `--config`. Settings are
applied in this order, with later ones taking precedence: built-in defaults,
the config file, `--profile NAME` (a named target list with option overrides),
then command-line flags.

### The old Angry IP Scanner command line

`ipscan -f:range 10.0.0.1 10.0.0.254 -o out.txt -s -q` and the `-f:random` and
`-f:file` forms are translated automatically.

## Privileges

ICMP ping is used when it is permitted, and otherwise the scanner falls back to
UDP and TCP probes. Run `ipscan list-pingers` to see which applies.

- **Linux:** unprivileged ICMP works when your group is in
  `net.ipv4.ping_group_range`, which is the default on many distributions.
  Otherwise, run `sudo setcap cap_net_raw+ep "$(command -v ipscan)"`.
- **macOS:** works without privileges.
- **Windows:** uses the system ICMP API, so no administrator rights are needed.

MAC addresses come from the OS neighbour table, so they are only available for
hosts on directly attached networks.

## Differences from Angry IP Scanner

- The GUI features are gone: comments, openers, the details window and Java plugins.
- Several bugs found while porting are fixed:
  - stepping a range backwards gave wrong addresses;
  - merged ping statistics dropped timings and TTL;
  - the TCP probe timeout could end up unlimited;
  - a host that answered the UDP probe was counted as dead;
  - mDNS and NetBIOS replies were not validated;
  - SQL export wrote the string `'NULL'` instead of a real NULL;
  - XML export broke on values containing `]]>`;
  - broadcast detection only worked for `/24` networks.
- Exports refuse to append to files that are not ipscan exports. New files are
  written atomically.
- There is no telemetry.

## License

GPL-2.0-or-later. This is a derivative of Angry IP Scanner, Copyright Anton Keks
and contributors. The MAC vendor list is derived from the IEEE OUI registry.
