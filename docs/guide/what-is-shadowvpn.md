# What is ShadowVPN?

ShadowVPN is a UDP-based, pre-shared-key (PSK), **user-mode** VPN written in
Rust on the [`tokio`](https://tokio.rs) async runtime.

It is a fixed point-to-point / multi-client tunnel. A TUN-based **client**
reads IP packets from a virtual interface, encrypts each as a single UDP
datagram, and sends it to the **server**; the server decrypts, routes, and
tunnels return traffic back. It runs on macOS (utun) and Linux, and the client
also runs on Windows (TUN via [Wintun](https://www.wintun.net/)), including
[policy routing](./policy-routing).

The on-wire crypto matches the **shadowsocks.org AEAD UDP scheme** exactly, so
the construction is spec-correct and interoperable, with one deliberate,
documented deviation (no SOCKS address header — see the
[wire protocol reference](/reference/wire-protocol)).

![ShadowVPN end-to-end data flow](../architecture.svg)

## How it works

The client encrypts every TUN packet to the server over UDP; the server
decrypts, writes to its own TUN, and (with forwarding + NAT) lets traffic
egress. Return traffic is matched back to the client by its inner tunnel IP
and re-encrypted.

Key properties:

- **One packet, one datagram** — the plaintext is the raw IP packet read from
  the TUN device. UDP datagram boundaries are the frame boundaries: there is
  no length prefix, no multiplexing, and no reassembly.
- **Entirely in user space** — ShadowVPN brings the TUN interface up and (in
  policy-routing mode) programs per-destination routes through the OS's native
  routing socket. No kernel modules, no `ipset`/`iptables`/`nft` rules.
- **0-RTT** — there is no handshake or session negotiation. A client just
  starts sending; the pre-shared key is all either side needs.
- **Pipelined data plane** — dedicated reader tasks overlap socket I/O with
  the per-packet crypto, carrying single-flow TCP at ~1 Gbit/s through the
  tunnel (see [benchmarks](/reference/benchmarks)).

## What ShadowVPN is not

- **Not a SOCKS proxy.** Standard shadowsocks UDP relays prepend a SOCKS-style
  target address to the plaintext; ShadowVPN does not. It is a fixed tunnel —
  the plaintext is exactly the raw IP packet.
- **Not a key-exchange protocol.** There are no certificates, no PKI, and no
  per-session keys: both ends share one password, and every datagram derives a
  fresh subkey from a random salt.
- **Not a kernel VPN.** Everything — crypto, routing decisions, DNS policy —
  happens in a normal user-space process (which still needs root/Administrator
  to create the TUN device).

## Platform support

| Platform | Server | Client | Policy routing |
|----------|--------|--------|----------------|
| Linux    | ✅     | ✅     | ✅ (rtnetlink) |
| macOS    | ✅     | ✅     | ✅ (`PF_ROUTE`) |
| Windows  | —      | ✅ (Wintun) | ✅ (IP Helper API) |

## Next steps

- [Quick start](./quick-start) — tunnel up in five minutes.
- [Installation](./installation) — build from source, releases, Windows setup.
- [Configuration](./configuration) — JSON config and CLI flags.
- [Wire protocol](/reference/wire-protocol) — the exact on-wire format.
