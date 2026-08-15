---
layout: home

hero:
  name: ShadowVPN
  text: UDP · PSK · user-mode VPN in Rust
  tagline: >-
    A fixed point-to-point / multi-client tunnel whose on-wire crypto matches
    the shadowsocks AEAD UDP scheme byte-for-byte. Runs on Linux, macOS, and
    Windows — with user-mode policy routing, QUIC/HTTP3 carrier obfuscation,
    and no kernel ipset or nft rules.
  actions:
    - theme: brand
      text: Quick start
      link: /guide/quick-start
    - theme: alt
      text: What is ShadowVPN?
      link: /guide/what-is-shadowvpn
    - theme: alt
      text: View on GitHub
      link: https://github.com/madeye/shadowvpn

features:
  - icon: 🔒
    title: Spec-correct crypto
    details: >-
      Per-datagram random salt, HKDF-SHA1 "ss-subkey", zero nonce, AEAD tag —
      the shadowsocks UDP scheme exactly, interoperable by construction.
    link: /reference/wire-protocol
    linkText: Wire protocol
  - icon: 📦
    title: One packet, one datagram
    details: >-
      No length prefix, no SOCKS header, no multiplexing. The plaintext is the
      raw IP packet — UDP boundaries are the frame boundaries.
  - icon: 🖧
    title: User-mode TUN
    details: >-
      Async TUN on Tokio via tun-rs — Linux tun0, macOS utun, and Windows
      Wintun. Pipelined relay loops plus a keepalive.
  - icon: 🧭
    title: Policy routing
    details: >-
      Optional split tunnel — send only selected destinations through the
      tunnel, decided entirely in user space. No ipset, no nft.
    link: /guide/policy-routing
    linkText: Policy routing
  - icon: ✨
    title: Magic DNS
    details: >-
      Resolve joined peers by hostname — ping laptop, ssh pi.svpn — the same
      way Tailscale Magic DNS works, with no extra control plane.
    link: /guide/magic-dns
    linkText: Magic DNS
  - icon: 🌏
    title: gfwlist · chinadns
    details: >-
      Tunnel a domain list, or everything that isn't a China IP. Build the
      China set from a plain CIDR file or a GeoLite2 database.
  - icon: 🎭
    title: Carrier obfuscation
    details: >-
      Optionally shape the UDP payload to look like QUIC/HTTP3, or encode it
      as printable base64 — cosmetic framing to dodge naive classification.
    link: /reference/obfuscation
    linkText: Obfuscation
  - icon: 🪟
    title: Cross-platform client
    details: >-
      The client runs on Linux, macOS, and Windows (TUN via Wintun), policy
      routing included — a self-elevating launcher ships in scripts/.
  - icon: 🦀
    title: Lean Rust
    details: >-
      Tokio + RustCrypto, a tiny dependency set, and a Docker end-to-end test
      suite covering the tunnel, HTTP/3, and policy routing.
    link: /reference/testing
    linkText: Testing
  - icon: 🚀
    title: Line-rate data plane
    details: >-
      Pipelined relay loops carry single-flow TCP at ~1 Gbit/s; at broadband
      rates the tunnel runs at or near line rate.
    link: /reference/benchmarks
    linkText: Benchmarks
---

## Install in one line

Linux & macOS — detects your OS/CPU and installs the
[latest release](https://github.com/madeye/shadowvpn/releases):

::: code-group

```sh [server]
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server
```

```sh [client]
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- client
```

:::

Uninstall with `… | sudo bash -s -- uninstall server` (or `client`). All
options — pinned versions, `--service`, `--purge`, Windows packages — are in
the [installation guide](/guide/installation#one-line-install).
