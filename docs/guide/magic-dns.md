# Magic DNS (peer hostnames)

Joined peers are reachable by hostname, the way Tailscale Magic DNS is:
`ping laptop` and `ssh pi.svpn` resolve to that node's tunnel address.

[Automatic assignment](./auto-assign) is the node-IP piece. This page is the
node-name piece. Both require learning mode — [`--nat`](./multi-client)
shares a placeholder IP, so names would not map to unique addresses.

```text
  client A "laptop"                 hub                      client B "pi"
  10.9.0.5                          10.9.0.1                 10.9.0.7
       │  NameAdvert                   │  NameAdvert              │
       ├──────────────────────────────►│◄─────────────────────────┤
       │  PeerPush                     │  PeerPush                │
       │  laptop→.5  pi→.7  vpn→.1     │  (same table)            │
       │◄──────────────────────────────┤──────────────────────────►
  local stub answers                   │               local stub answers
  "pi" / "pi.svpn" → 10.9.0.7          │               "laptop.svpn" → .5
```

## Setup

Magic DNS is **on** by default. Each client announces a hostname (the sanitized
OS hostname unless you set one) on its keepalive tick. The server grants the
name — first-come keeps `laptop`; a later collision becomes `laptop-aabb` —
and pushes the whole map back. The client DNS stub answers `A`/`AAAA` from
that table. No extra control plane, no `/etc/hosts`.

```json [client.json]
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "hostname": "laptop"
}
```

```bash
sudo shadowvpn-client -s vpn.example.com:8388 -k <password> --hostname laptop
# another device
sudo shadowvpn-client -s vpn.example.com:8388 -k <password> --hostname pi
```

Omit `hostname` and the client uses the OS hostname (`My-Laptop.local` →
`my-laptop`). The server publishes its own name (default: its OS hostname)
as its tunnel IP, so `ping vpn` / `ssh <server-hostname>.svpn` works too.

## Names

| Form | Example | Notes |
|------|---------|-------|
| Bare label | `pi` | Works when the stub is the system resolver |
| Suffixed | `pi.svpn` | Always unique to the Magic DNS zone |
| Server | `vpn.svpn` | Server `hostname` → server `tun_ip` |

The suffix is `svpn` by default (`magic_dns_suffix` / `--magic-dns-suffix`).
Unknown names under that suffix are **NXDOMAIN** — they never leak to an
upstream resolver.

Sanitization: first label, lowercase, invalid characters become `-`, max 32
bytes. Empty → `node`.

Collisions: the first advertiser keeps the requested name. A later node with
the same name gets `name-aabb`, where `aabb` is the first four hex digits of
its `node_id` (auto-assign) or the last octet of its tunnel IPv4 (static).
The rename is logged.

## DNS takeover

The stub listens on `dns_listen` (default `127.0.0.1:53`).

- **gfwlist / chinadns** — Magic DNS is answered first, then the existing
  split-DNS logic. The system resolver is already pointed at the proxy.
- **full mode** — the client starts a **forwarding** stub: Magic names are
  local, everything else goes to `dns_local`. `set_dns` (default on) points
  the system resolver at that stub, the same way policy modes do.

This is a behaviour change for full mode: with default Magic DNS the client
now takes over the system resolver. Opt out with `--no-magic-dns` (restore
today's full-mode behaviour) or `--no-set-dns` (leave the stub on
`127.0.0.1:53` and configure DNS yourself).

`--nat` servers ignore name adverts. Clients still start the stub if Magic
DNS is on, but the table stays empty.

## Operator knobs

| JSON field | CLI flag | Default | Meaning |
|---|---|---|---|
| `hostname` | `--hostname` | sanitized OS hostname | Announced / published name |
| `magic_dns` | `--magic-dns` / `--no-magic-dns` | `true` | Enable the name advert + local stub |
| `magic_dns_suffix` | `--magic-dns-suffix` | `svpn` | Zone suffix |

`hostname` is **not** carried in a URI / QR code — cloning a share must not
clone identity, same as `node_id`.

## Validating

From one client, after another is up:

```bash
dig @127.0.0.1 pi.svpn A
dig @127.0.0.1 pi.svpn AAAA
ping -c3 pi
ssh user@pi.svpn
```

The server logs every grant, collision-rename, withdrawal, and expiry.
Names expire with `lease_ttl_secs` (default 120 s) when the advertiser goes
quiet; they come back on the next keepalive (15 s by default).

This flow is exercised end to end in CI (`docker/run-e2e-magicdns.sh`): a
hub named `vpn` and two auto clients named `laptop` and `pi`.

## Wire format

```text
name advert : 00 05 flags ip4[4] ip6[16] nlen name[nlen]
peer push   : 00 06 flags count { eflags ip4[4] ip6[16] nlen name[nlen] }*
```

See the [wire protocol](/reference/wire-protocol#control-channel). Old peers
drop unknown types, so the extension is wire-compatible both ways.
