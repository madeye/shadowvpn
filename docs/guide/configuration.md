# Configuration

Configuration can come from a JSON config file, CLI flags, or both. **CLI
flags take precedence over JSON file values.** Defaults are applied for
anything not supplied.

Both binaries accept `-c, --config <PATH>` to point at a JSON file.

## Core fields

| JSON field    | CLI flag          | Meaning                                                         | Required | Default              |
|---------------|-------------------|-----------------------------------------------------------------|----------|----------------------|
| `server`      | `--listen` / `--server` | server: UDP bind address; client: remote `host:port`      | yes      | —                    |
| `password`    | `-k, --password`  | pre-shared password; master key derived from it                 | yes      | —                    |
| `cipher`      | `-m, --cipher`    | AEAD cipher name                                                | no       | `chacha20-poly1305`  |
| `tun_name`    | `--tun-name`      | explicit TUN interface name (e.g. `utun7`, `tun0`)              | no       | OS picks             |
| `tun_ip`      | `--tun-ip`        | local IPv4 address on the TUN interface                         | server: yes; client: omit with `peer_ip` for [auto-assign](./auto-assign) | — |
| `tun_netmask` | `--tun-netmask`   | IPv4 netmask for the TUN interface                              | no       | `255.255.255.0`      |
| `peer_ip`     | `--peer-ip`       | point-to-point peer IPv4 (server: reserved static client; client: server IP) | server: yes; client: omit with `tun_ip` for [auto-assign](./auto-assign) | — |
| `mtu`         | `--mtu`           | TUN interface MTU                                               | no       | `1400`               |
| `obfs`        | *(config only)*   | carrier obfuscation: `none` \| `quic` \| `base64` (both ends must match) | no | `none`         |

On the **server** the `server` field is the UDP bind/listen address; on the
**client** it is the remote server address to connect to.

There are more client-only fields for policy routing — see
[Policy routing](./policy-routing) and the full
[configuration reference](/reference/configuration).

## Example: server config

```json [server.json]
{
  "server": "0.0.0.0:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "tun_name": "utun7",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2",
  "mtu": 1400
}
```

## Example: client config

```json [client.json]
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "tun_name": "utun7",
  "tun_ip": "10.9.0.2",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.1",
  "mtu": 1400
}
```

::: tip Mirror images
`tun_ip` and `peer_ip` swap between the two ends: the server's local tunnel IP
is the client's peer, and vice versa. On the client you can [omit both](./auto-assign)
and let the server assign a unique address.
:::

## Choosing a cipher

All ciphers are AEAD, from the RustCrypto project:

| Cipher name (config) | Key / salt length |
|----------------------|-------------------|
| `aes-128-gcm`        | 16 bytes          |
| `aes-256-gcm`        | 32 bytes          |
| `chacha20-poly1305`  | 32 bytes          |

The alias `chacha20-ietf-poly1305` is accepted and treated as
`chacha20-poly1305`. The default (when none is specified) is
`chacha20-poly1305` — a good choice everywhere, and the best choice on ARM
hardware without a crypto-enabled build. See the
[ciphers reference](/reference/ciphers).

## Carrier obfuscation

The optional `obfs` field shapes the UDP payload so it doesn't read as an
opaque random blob — `quic` wraps each datagram as a QUIC 1-RTT short-header
packet, `base64` encodes it as printable ASCII. **Both ends must agree**, and
it has no CLI flag:

```json
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "obfs": "quic"
}
```

This is cosmetic framing only — it adds no security. Details, trade-offs, and
wire formats: [carrier obfuscation](/reference/obfuscation).

## Sharing configs between devices

- [Omit `tun_ip` and `peer_ip`](./auto-assign) so every device can share one
  client config and still get a unique, pingable tunnel IP.
- Export/import a client config as a single `shadowvpn://` URI or QR code —
  see [Config URIs & QR codes](./uri-qr). The `node_id` is **not** in the
  URI; it lives in `<config>.state`.
- Run many clients off one identical *placeholder* config with the server's
  [NAT mode](./multi-client) when you do not need client↔client.
