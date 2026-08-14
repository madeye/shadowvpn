# Automatic tunnel-IP assignment

Omit `tun_ip` and `peer_ip` on a client and the server hands it a unique
address from the tunnel subnet. The client programs that address onto its
TUN; [learning mode](./multi-client#without-nat-mode-distinct-tunnel-ips)
plus the [hub relay](./mesh-routing) then make every other client reachable —
no per-device config editing, and no `--nat` rewrite.

`--nat` stays the zero-handshake, rewrite-only mode. It is mutually exclusive
with assignment: a NAT server answers `AssignRequest` with `NatMode`, and
clients **cannot address each other**.

## Setup

**Server** — learning mode (the default). Do **not** set `"nat": true`.
`tun_ip` and `peer_ip` are still required on the server: `peer_ip` (typically
`.2`) is the point-to-point dest on the server TUN and is **reserved**, so a
mixed fleet's static client at `.2` is never handed to an auto laptop.

```json [server.json]
{
  "server": "0.0.0.0:8388",
  "password": "correct horse battery staple",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2"
}
```

**Clients** — omit both `tun_ip` and `peer_ip`. The same file can be copied,
exported as a [URI / QR](./uri-qr), and imported on every device:

```json [client.json]
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple"
}
```

Omitting only one of the two addresses is an error — they must both be set
(static) or both omitted (auto). A static `tun_ip6` with omitted IPv4 is
valid: the server assigns IPv4 and the client keeps the configured ULA.

Once two clients are up they can ping each other (`10.9.0.37` ↔ `10.9.0.4`)
and the server (`10.9.0.1`) without any extra routing on the server.

::: warning `--setup` still enables NAT
`install.sh --setup` still writes `"nat": true` until that default flips.
A no-`tun_ip` client against a NAT server exits fatal (`NatMode`). Either
drop `"nat"` from the generated `server.json`, or keep static `tun_ip` /
`peer_ip` on the client.
:::

## How it works

The client presents a persisted 16-byte `node_id`. The server allocates a
free IPv4 from the tunnel subnet (network, broadcast, server IP, and
reserved addresses excluded) and, when the server has a ULA prefix of
length ≤ 96, a matching IPv6. The assignment is pushed over the existing
`0x00` control channel; the client applies it to its TUN. Existing
learning + hub UDP→UDP relay then deliver packets whose destination is
another client's tunnel IP.

WAN data waits for one control RTT (`Assign` Ok). A cached assignment may
bring the TUN and policy routes up immediately so local sockets can bind,
but the client does not send data until the server confirms.

After Ok the periodic tick **is** `AssignRequest` (this is the keepalive in
auto mode). Mesh clients also send a `RouteAdvert` immediately on Ok, then
again on every tick.

## Identity (`node_id`)

`node_id` lives in a **state file**, never in the shared config, URI, or QR
code — cloning a URI must not clone the identity.

| How the client is started | Default state path |
|---------------------------|--------------------|
| `-c client.json`          | `client.json.state` (sibling of the config) |
| no `--config` (Linux)     | `$XDG_STATE_HOME/shadowvpn/<sha256(server)>.json` |
| no `--config` (macOS)     | `~/Library/Application Support/shadowvpn/<sha256(server)>.json` |

Override with `state_file` / `--state-file`. The file is mode `0600` and
holds the `node_id` plus the last assigned addresses so a reconnect can
pre-program the TUN. Copying the state file between machines **moves** the
node; copying it onto a second *live* machine is operator error (both
clients flap on the same IP).

A corrupt state file is discarded: the client generates a new `node_id`
and gets a new address.

## IPv6

When the client omitted `tun_ip6` and the server has `tun_ip6` with prefix
≤ 96 (recommend `/64`), the assigned IPv6 is the server prefix with octets
`[12..16]` overwritten by the assigned IPv4. For example `10.9.0.37` under
`fd07:7::/64` becomes `fd07:7::a09:25`.

A tighter prefix (`/128` on a static-only mesh hub) still starts; IPv6
assignment is skipped (`plen6 = 0`) and IPv4 assignment still succeeds.

## Operator control

Assignment is always on in learning mode — any client that sends
`AssignRequest` is served. Server-only knobs:

| JSON field        | CLI flag             | Default | Meaning |
|-------------------|----------------------|---------|---------|
| `assign_pool`     | `--assign-pool`      | TUN host range | Allocator-only IPv4 CIDR; must be a subset of the TUN network. The reply still carries the TUN netmask. |
| `reserved_ips`    | `--reserved-ips`     | `[peer_ip]` | Extra IPv4s never auto-assigned. Unioned with `peer_ip`, not a replacement. |
| `assign_ttl_secs` | `--assign-ttl-secs`  | `604800` (7d) | Idle time before an assignment is reclaimed. |
| `lease_file`      | `--lease-file`       | next to `--config`, else `/var/lib/shadowvpn/leases.json` | Persist path. `"-"` disables. |

A `/24` minus network / broadcast / server / reserved `.2` is 252
assignable addresses. The server logs `assigned/capacity` and warns at 80%.

Leases survive a server restart. Static clients that pick an address the
assigner has already leased are not learned — add that address to
`reserved_ips`.

## Mesh subnet routing

[Mesh advertise / approve / accept](./mesh-routing) still works on top of
assignment: it is Tailscale's *subnet-router* workflow, and assignment is
the missing *node IP* piece. Both require learning mode. An auto client
that also `--advertise-routes` or `--accept-routes` sends `AssignRequest`
and `RouteAdvert` on the same tick; spoke↔spoke and client↔subnet traffic
is hub-relayed exactly as with static `tun_ip`s.

## Versus `--nat`

| | Auto-assign | [`--nat`](./multi-client) |
|---|---|---|
| Shared client config | yes (omit `tun_ip` / `peer_ip`) | yes (same placeholder `tun_ip`) |
| Client↔client | yes (unique TUN addresses) | **no** |
| Handshake | one control RTT | 0-RTT |
| Mesh routes | yes | rejected at config time |
| Server rewrite | none | inner src/dst + checksums |

Pick assignment when clients should ping each other. Pick `--nat` when you
want identical configs, no control RTT, and only hub-and-spoke to the
server / the internet.

## Wire format

Two control types, exact length, no trailer. Unknown types and any other
length are dropped (old peers interoperate). A 5-byte payload whose second
byte happens to be `0x03` or `0x04` is still a keepalive.

```text
assign req  : 00 03 flags node[16] hint4[4] hint6[16]     (39 bytes)
assign      : 00 04 status ip4[4] mask[4] peer[4] ip6[16] plen6 flags ttl[4]
                                                              (37 bytes)
```

`flags` bit 0 on the request is *want IPv6*. Status `0` is Ok, `1` is
pool exhausted, `2` is `NatMode`. See the
[wire protocol reference](/reference/wire-protocol#control-channel).
