# Configuration reference

Configuration can come from a JSON config file, CLI flags, or both. **CLI
flags take precedence over JSON file values.** Defaults are applied for
anything not supplied. Both binaries accept `-c, --config <PATH>`.

## Common fields (server + client)

| JSON field    | CLI flag          | Meaning                                                         | Required | Default              |
|---------------|-------------------|-----------------------------------------------------------------|----------|----------------------|
| `server`      | `-l, --listen` (server) / `-s, --server` (client) | server: UDP bind address; client: remote `host:port` | yes | — |
| `password`    | `-k, --password`  | pre-shared password; master key derived from it                 | yes      | —                    |
| `cipher`      | `-m, --cipher`    | `aes-128-gcm` \| `aes-256-gcm` \| `chacha20-poly1305`           | no       | `chacha20-poly1305`  |
| `tun_name`    | `--tun-name`      | explicit TUN interface name (e.g. `utun7`, `tun0`)              | no       | OS picks             |
| `tun_ip`      | `--tun-ip`        | local IPv4 address on the TUN interface                         | server: yes; client: both-or-neither with `peer_ip` | — |
| `tun_netmask` | `--tun-netmask`   | IPv4 netmask for the TUN interface                              | no       | `255.255.255.0`      |
| `peer_ip`     | `--peer-ip`       | point-to-point peer IPv4 (server: reserved static client IP; client: server IP) | server: yes; client: both-or-neither with `tun_ip` | — |
| `mtu`         | `--mtu`           | TUN interface MTU                                               | no       | `1400`               |
| `tun_ip6`     | `--tun-ip6`       | optional IPv6 address + prefix on the TUN, CIDR form (e.g. `fd07:7::2/64`) — used by [mesh routing](/guide/mesh-routing) | no | none |
| `obfs`        | *(config only)*   | carrier obfuscation: `none` \| `quic` \| `base64` — both ends must match | no | `none`        |

The alias `chacha20-ietf-poly1305` is accepted for `cipher` and treated as
`chacha20-poly1305`.

## Server-only fields

| JSON field       | CLI flag           | Meaning                                                             | Default |
|------------------|--------------------|---------------------------------------------------------------------|---------|
| `nat`            | `--nat`            | tell clients apart by UDP endpoint and NAT them onto internal IPs, so all clients can share one config ([NAT mode](/guide/multi-client)). Exclusive with assignment and mesh. | `false` |
| `lease_ttl_secs` | `--lease-ttl-secs` | NAT mode: reclaim a client's internal-IP lease after this many idle seconds; also the expiry for advertised [mesh routes](/guide/mesh-routing) whose owner went quiet, and for learned inner-IP → UDP mappings | `120` |
| `approve_routes` | `--approve-routes` | allowlist of CIDRs: an advertised route is approved when it equals, or is a subnet of, an entry ([mesh routing](/guide/mesh-routing)) | none |
| `auto_approve_routes` | `--auto-approve-routes` | approve every advertised route                             | `false` |
| `assign_pool`    | `--assign-pool`    | IPv4 CIDR the assigner may hand out (subset of the TUN network). Allocator-only; the Assign reply still carries the TUN netmask ([auto-assign](/guide/auto-assign)) | TUN host range |
| `reserved_ips`   | `--reserved-ips`   | extra IPv4s never auto-assigned (unioned with `peer_ip`, which is always reserved — typically `.2`) | `[peer_ip]` |
| `assign_ttl_secs` | `--assign-ttl-secs` | idle time before an assignment lease is reclaimed        | `604800` (7d) |
| `lease_file`     | `--lease-file`     | assignment lease persist path. `"-"` disables. Default: `<config>.leases.json` next to `--config`, else `/var/lib/shadowvpn/leases.json` (`%PROGRAMDATA%\shadowvpn\leases.json` on Windows) | see left |

Mesh routing (`approve_routes` / `auto_approve_routes` / `tun_ip6`) and
[automatic assignment](/guide/auto-assign) require the default learning
mode and cannot be combined with `nat`. On the client, omit both `tun_ip`
and `peer_ip` to request an assignment; setting only one is an error.

## Client-only fields

### Tunnel behaviour

| JSON field       | CLI flag            | Meaning                                                          | Default |
|------------------|---------------------|-------------------------------------------------------------------|---------|
| `keepalive_secs` | `--keepalive-secs`  | keepalive interval in seconds — keep it below the path's UDP NAT timeout. Auto-assign clients send `AssignRequest` on this tick. | `15` |
| `state_file`     | `--state-file`      | persisted `node_id` + last assignment ([auto-assign](/guide/auto-assign)). Default: `<config>.state` next to `-c`, else a hash of the `server` string under the platform state dir. **Not** carried in a URI/QR. | see left |
| `advertise_routes` | `--advertise-routes` | IPv4/IPv6 subnets behind this client to advertise to the server (comma-separated CIDRs on the CLI, array in JSON) | none |
| `accept_routes`  | `--accept-routes`   | install subnet routes pushed by the server onto the TUN; removed on withdrawal and exit | `false` |

### Policy routing

| JSON field      | CLI flag        | Meaning                                                    | Default              |
|-----------------|-----------------|------------------------------------------------------------|----------------------|
| `mode`          | `--mode`        | `full` \| `gfwlist` \| `chinadns`                          | `full`               |
| `dns_listen`    | `--dns-listen`  | address the split-DNS proxy listens on                     | `127.0.0.1:53`       |
| `dns_local`     | `--dns-local`   | domestic / direct DNS upstream                             | `114.114.114.114:53` |
| `dns_remote`    | `--dns-remote`  | clean DNS upstream (reached through the tunnel)            | `8.8.8.8:53`         |
| `gfwlist`       | `--gfwlist`     | domain-suffix file (gfwlist mode; optional force-tunnel list in chinadns mode) | auto-discovers a bundled `gfwlist.txt` |
| `chnroute`      | `--chnroute`    | China CIDR file (chinadns mode)                            | —                    |
| `geoip`         | `--geoip`       | GeoLite2/GeoIP2 `.mmdb`; builds the China set from it (takes precedence over `chnroute`) | auto-discovers a bundled `GeoLite2-Country.mmdb` |
| `geoip_country` | `--geoip-country` | ISO country code to select from the GeoIP database       | `CN`                 |
| `set_dns`       | `--set-dns` / `--no-set-dns` | point the system resolver at the proxy (auto-restored on exit) | `true` (needs `dns_listen` port 53) |
| `prewarm`       | `--no-prewarm` (disable) | list of domains to pre-resolve into the cache on startup | built-in list       |
| `cache_file`    | `--cache-file` / `--no-cache-persist` | persist the DNS cache across restarts     | `dns-cache.json` (next to the binary) |
| `dns_timeout_ms` | *(config only)* | upstream DNS query timeout in milliseconds                | `3000`               |

### Maintenance flags

| CLI flag        | Meaning |
|-----------------|---------|
| `--restore-dns` | restore the system resolver from the journal left by a run that did not exit cleanly, then exit (no tunnel is brought up). Used by the desktop app to heal DNS after a crashed client. |

## Full examples

Annotated server and client examples, including NAT mode and policy routing,
live in the guides:

- [Configuration guide](/guide/configuration) — basic server/client pairs
- [Policy routing](/guide/policy-routing) — split-tunnel setups
- [Automatic tunnel IPs](/guide/auto-assign) — omit `tun_ip` / `peer_ip`
- [Multiple clients](/guide/multi-client) — shared-config NAT mode
