# Troubleshooting

## First checks

- **Turn on verbose logging.** Both binaries log to stderr; set
  `RUST_LOG=debug` for detailed tracing of the relay loops, DNS proxy, and
  route programming.
- **Ping across the tunnel.** From the client, `ping 10.9.0.1` (the server's
  `tun_ip`). A lossless ping proves the whole path — TUN → encrypt → UDP →
  server → decrypt → TUN — in both directions.
- **Read the startup hints.** Both binaries print the routing / forwarding
  commands they expect you to have run (IP forwarding, NAT, host route to the
  server).

## Tunnel comes up but nothing flows

- **Password / cipher mismatch.** There is no handshake, so a wrong password
  or cipher doesn't produce a connection error — packets simply fail to
  decrypt and are dropped. Check both configs use the same `password` and
  `cipher`.
- **`obfs` mismatch.** The `obfs` setting must be identical on both ends; a
  mismatched peer just sees its traffic dropped (packets fail to decode before
  decryption). It is config-file-only — check both JSON files.
- **UDP port blocked.** The tunnel is pure UDP; make sure the server's port
  (e.g. `8388/udp`) is open in every firewall/security-group on the path.

## Tunnel pings, but the internet doesn't work

The server must forward and masquerade tunneled traffic:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o <wan-if> -j MASQUERADE
```

See [Routing & IP forwarding](./routing#server-enable-ip-forwarding-nat).

On the client side (full tunnel), remember the **host route to the server via
the real gateway** — without it the encrypted UDP loops back into the tunnel
and everything stalls. See
[the client routing steps](./routing#client-route-traffic-through-the-tunnel-full-tunnel).

## Windows: error 193 / Wintun won't load

`wintun.dll` must match the **binary's CPU architecture**, not the OS
marketing name. An x64 DLL next to an ARM64 `shadowvpn-client.exe` (or vice
versa) fails to load — typically Windows error 193 (`%1 is not a valid Win32
application`). Download the matching build from
[wintun.net](https://www.wintun.net/) and place it next to the exe (the
release zip already ships the right one).

## DNS is broken after the client exited uncleanly

In policy-routing mode the client points the system resolver at its local
split-DNS proxy and restores the previous setting on exit — but only on a
*graceful* exit (Ctrl-C / `SIGTERM` / service stop). If the process is killed
hard (`kill -9`, `taskkill /F`, power loss), the resolver may be left pointing
at `127.0.0.1` with nothing listening.

Fix: start the client again and stop it gracefully, or restore DNS by hand
(`networksetup -setdnsservers <service> …` on macOS, edit `/etc/resolv.conf`
on Linux, adapter DNS settings / `netsh` on Windows). To manage DNS yourself
from the start, run with `--no-set-dns`.

## Policy routing doesn't split anything

- Routes are only installed for names resolved **through the proxy**. If
  something else overwrote your resolver (DHCP renew, VPN software, manual
  change), the policy never sees the queries. Check the system resolver points
  at `dns_listen` (default `127.0.0.1:53`).
- Automatic resolver setup only happens when `dns_listen` uses **port 53**.
  On a custom port you must point the resolver at the proxy yourself.
- Long-lived connections opened *before* a route existed keep using their old
  path until they reconnect.
- In `chinadns` mode, a domain the domestic resolver answers with an in-China
  (possibly poisoned) address goes direct; add it to a `--gfwlist` force list
  to always tunnel it.

## Assignment failed / "server did not assign an IP"

Auto-assign clients ([omit `tun_ip` / `peer_ip`](./auto-assign)) wait up to
10 seconds for an `Assign` Ok. Common causes:

- **Old server** — it drops unknown `0x03` control types. Upgrade the
  server, or set a static `tun_ip` / `peer_ip`.
- **Server `--nat`** — assignment is exclusive with NAT. A new NAT server
  replies `NatMode` (fatal); an old one times out. Drop `"nat": true` from
  `server.json` if you want client↔client, or put static IPs back on the
  client. `install.sh --setup` writes learning mode (no `"nat"`).
- **Pool exhausted** — status `Exhausted`. Widen `tun_netmask` /
  `assign_pool`, or wait for idle leases (default 7 days) to expire.
- **Only one of `tun_ip` / `peer_ip` set** — both must be present
  (static) or both omitted (auto).

The `node_id` is in `<config>.state`, not the JSON. Do not copy that file
onto a second live machine — both clients will flap on the same IP. Copying
it is the supported way to *move* a node.

A static client that uses an address the server has already leased is not
learned (`warn` on the server). Add that address to `reserved_ips`.
`.2` (`peer_ip`) is reserved by default.

## Keepalives, NAT timeouts, and idle drops

The client sends an encrypted keepalive every **15 seconds** by default so
stateful NAT/firewall mappings stay open and the server keeps an up-to-date
view of the client's UDP address. Auto-assign clients send `AssignRequest`
on that same tick instead of the 5-byte keepalive. If your NAT/router
expires UDP mappings faster than the keepalive interval, the server sees the
client's address "churn" — each keepalive arrives from a fresh mapping.
Either raise the router's UDP session timeout or lower `--keepalive-secs` so
it stays below the timeout. In server [NAT mode](./multi-client), idle
client leases are reclaimed after `lease_ttl_secs` (default 120) — an
idle-but-alive client keeps its lease via the keepalive alone. Assignment
leases last 7 days by default (`assign_ttl_secs`).

## MTU problems (some sites hang, large transfers stall)

The default TUN MTU is 1400. With `base64` obfuscation the wire payload grows
~33%, so lower `mtu` accordingly (see
[carrier obfuscation](/reference/obfuscation)). Note that in server NAT mode,
ICMP error payloads aren't rewritten, so tunneled path-MTU discovery may
degrade — if a specific host hangs on large packets, try a lower client-side
`mtu`.

## AES-GCM is slow on ARM

A plain `cargo build` for aarch64 runs AES-GCM in constant-time software.
Either use `chacha20-poly1305` (default; fast everywhere) or rebuild with
`RUSTFLAGS="-C target-feature=+aes,+neon"`. See
[ciphers](/reference/ciphers#hardware-acceleration-especially-on-arm).

## Still stuck?

Open an issue at
[github.com/madeye/shadowvpn/issues](https://github.com/madeye/shadowvpn/issues)
with `RUST_LOG=debug` output from both ends and your (password-redacted)
configs.
