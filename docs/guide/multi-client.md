# Multiple clients (NAT mode)

By default the server routes by learning each client's inner tunnel source IP,
so clients must use **distinct `tun_ip`s**. That's fine for a handful of
devices with hand-crafted configs, but awkward when you want to hand the same
config to everyone.

With `--nat` the server instead tells clients apart by their **UDP endpoint**
and maps each onto a distinct internal IP drawn from the TUN subnet, rewriting
inner addresses as packets pass through. Every client can then run the **same
static config** (same placeholder `tun_ip`) — no per-client setup, and no
IP-assignment handshake (0-RTT: a client just starts sending).

## Setup

**Server** — add `"nat": true` (or pass `--nat`):

```json [server.json]
{
  "server": "0.0.0.0:8388",
  "password": "correct horse battery staple",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2",
  "nat": true
}
```

**Clients** — all run the ordinary static config, identical on every device:

```json [client.json]
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "tun_ip": "10.9.0.2",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.1"
}
```

This pairs well with [config URIs / QR codes](./uri-qr): export one client
config once and every device can import it unchanged.

## How it works

The server keys a mapping by the client's UDP 4-tuple, allocates a free
internal IP from the subnet (network/broadcast/server excluded), and rewrites
the inner source on ingress (placeholder → internal) and destination on egress
(internal → placeholder), fixing IPv4/TCP/UDP checksums incrementally.

Mappings are refreshed by traffic (data or the client keepalive, 15 s by
default) and reclaimed after `lease_ttl_secs` / `--lease-ttl-secs` idle
(default 120).

## Trade-offs

- Clients **cannot address each other** — they share one placeholder, so the
  topology is hub-and-spoke to the server and beyond.
- ICMP error payloads that embed the original header aren't rewritten, so
  tunnelled PMTU discovery may suffer.
- The per-packet cost is a couple of checksum deltas, negligible next to the
  AEAD.

## Without NAT mode: distinct tunnel IPs

If you prefer clients to be individually addressable (or want to avoid the
trade-offs above), skip `--nat` and give each client its own `tun_ip`
(`10.9.0.2`, `10.9.0.3`, …) in the server's TUN subnet. In the default
learning mode the server maps (and re-maps, after a NAT rebind) each client's
UDP address from its keepalive announcements alone.
