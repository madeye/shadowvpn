# ShadowVPN

A UDP-based, pre-shared-key (PSK), user-mode VPN written in Rust on the
[`tokio`](https://tokio.rs) async runtime.

ShadowVPN is a fixed point-to-point / multi-client tunnel. A TUN-based **client**
reads IP packets from a virtual interface, encrypts each as a single UDP
datagram, and sends it to the **server**; the server decrypts, routes, and
tunnels return traffic back. It runs on macOS (utun) and Linux.

The on-wire crypto matches the **shadowsocks.org AEAD UDP scheme** exactly, so
the construction is spec-correct and interoperable, with one deliberate,
documented deviation (no SOCKS address header — see below).

---

## Wire protocol

Each UDP datagram on the wire is:

```text
[ salt (salt_len bytes) ] ++ [ AEAD ciphertext ++ tag (16 bytes) ]
```

* **`salt_len == key_len`** of the cipher: 16 bytes for `aes-128-gcm`,
  32 bytes for `aes-256-gcm` and `chacha20-poly1305`. A fresh random salt is
  generated for **every** datagram.
* **Subkey:** `subkey = HKDF-SHA1(ikm = master_key, salt = salt,
  info = "ss-subkey", L = key_len)`.
* **Nonce:** the all-zero 12-byte nonce for every UDP packet. This is safe
  because each datagram has a unique random salt and therefore a unique subkey,
  so the `(subkey, nonce)` pair is never reused.
* **Master key:** derived from the password string with shadowsocks'
  `EVP_BytesToKey` (the OpenSSL legacy MD5-based KDF): repeatedly compute
  `d_0 = MD5(password)`, `d_i = MD5(d_{i-1} ++ password)`, and concatenate until
  `key_len` bytes are available. (Implemented in-tree; no external crate.)
* **Plaintext:** the raw IP packet read from the TUN device. UDP datagram
  boundaries are the frame boundaries — there is no length prefix, no
  multiplexing, and no reassembly. One IP packet maps to exactly one datagram.

### Deviation from ss-proxy

Standard shadowsocks UDP relays prepend a SOCKS-style target address to the
plaintext. **ShadowVPN does not.** This is a fixed point-to-point tunnel, not a
SOCKS proxy: the plaintext is exactly the raw IP packet, with no address header.
Everything else (salt, HKDF-SHA1 `"ss-subkey"` subkey, zero nonce, AEAD tag)
matches the shadowsocks UDP AEAD scheme byte-for-byte. This deviation is also
documented in `src/crypto.rs` and `src/protocol.rs`.

### Keepalive (ShadowVPN convention, not part of the ss spec)

The client periodically sends a tiny encrypted datagram (a 1-byte `0x00`
plaintext) so that stateful NAT/firewall mappings stay open and the server
learns the client's current source address before any real traffic flows. The
server drops any decrypted payload smaller than a 20-byte IPv4 header, so the
keepalive never reaches the TUN write path.

---

## Supported ciphers

All ciphers are AEAD, from the RustCrypto project. Nonce length is 12 bytes and
tag length is 16 bytes for all three.

| Cipher name (config)                       | Key / salt length | Crate              |
|--------------------------------------------|-------------------|--------------------|
| `aes-128-gcm`                              | 16 bytes          | `aes-gcm`          |
| `aes-256-gcm`                              | 32 bytes          | `aes-gcm`          |
| `chacha20-poly1305`                        | 32 bytes          | `chacha20poly1305` |

The alias `chacha20-ietf-poly1305` is accepted and treated as
`chacha20-poly1305`. The default cipher (when none is specified) is
`chacha20-poly1305`.

---

## Configuration

Configuration can come from a JSON config file, CLI flags, or both. **CLI flags
take precedence over JSON file values.** Defaults are applied for anything not
supplied.

### Fields

| JSON field    | CLI flag          | Meaning                                                         | Required | Default              |
|---------------|-------------------|----------------------------------------------------------------|----------|----------------------|
| `server`      | `--listen` / `--server` | server: UDP bind address; client: remote `host:port`     | yes      | —                    |
| `password`    | `-k, --password`  | pre-shared password; master key derived from it                | yes      | —                    |
| `cipher`      | `-m, --cipher`    | AEAD cipher name                                               | no       | `chacha20-poly1305`  |
| `tun_name`    | `--tun-name`      | explicit TUN interface name (e.g. `utun7`, `tun0`)            | no       | OS picks             |
| `tun_ip`      | `--tun-ip`        | local IPv4 address on the TUN interface                       | yes      | —                    |
| `tun_netmask` | `--tun-netmask`   | IPv4 netmask for the TUN interface                            | no       | `255.255.255.0`      |
| `peer_ip`     | `--peer-ip`       | point-to-point peer IPv4 (server: client IP; client: server IP)| yes     | —                    |
| `mtu`         | `--mtu`           | TUN interface MTU                                              | no       | `1400`               |

On the **server** the `server` field is the UDP bind/listen address; on the
**client** it is the remote server address to connect to. Both binaries accept
`-c, --config <PATH>` to point at a JSON file.

### Example: server config (`server.json`)

```json
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

### Example: client config (`client.json`)

```json
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

Note how `tun_ip` and `peer_ip` are mirror images: the server's local tunnel IP
is the client's peer, and vice versa.

---

## Building

Requires a recent stable Rust toolchain (edition 2021).

```sh
cargo build --release
```

This produces two binaries:

* `target/release/shadowvpn-server`
* `target/release/shadowvpn-client`

Run the test suite (crypto + config unit tests):

```sh
cargo test --lib
```

---

## Running

Creating a TUN device requires elevated privileges (root on Linux, `sudo` on
macOS). Both binaries log to stderr; set `RUST_LOG=debug` for verbose tracing.

### Server

```sh
sudo ./target/release/shadowvpn-server -c server.json
```

Or entirely via CLI flags:

```sh
sudo ./target/release/shadowvpn-server \
  --listen 0.0.0.0:8388 \
  --password "correct horse battery staple" \
  --cipher chacha20-poly1305 \
  --tun-ip 10.9.0.1 \
  --peer-ip 10.9.0.2
```

### Client

```sh
sudo ./target/release/shadowvpn-client -c client.json
```

Or via CLI flags:

```sh
sudo ./target/release/shadowvpn-client \
  --server vpn.example.com:8388 \
  --password "correct horse battery staple" \
  --cipher chacha20-poly1305 \
  --tun-ip 10.9.0.2 \
  --peer-ip 10.9.0.1
```

Once the tunnel is up you can verify connectivity with a ping across the tunnel
addresses, e.g. from the client `ping 10.9.0.1`.

---

## TUN setup, routing, and IP forwarding

ShadowVPN brings the TUN interface up (address, netmask, peer, MTU) but
**deliberately does not touch the system routing table or `sysctl`**. Doing so
silently is dangerous and platform-specific. The steps below are what you run
**outside** the process. The binaries also print these hints at startup.

### Server: enable IP forwarding + NAT

So that tunneled clients can reach the wider network through the server, the
server host must forward packets and NAT (masquerade) them out its WAN
interface. Replace `<wan-if>` with the server's real outbound interface (e.g.
`eth0`).

**Linux:**

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o <wan-if> -j MASQUERADE
```

**macOS:**

```sh
sudo sysctl -w net.inet.ip.forwarding=1
# Configure pf NAT, e.g. add to /etc/pf.conf:
#   nat on <wan-if> from 10.9.0.0/24 to any -> (<wan-if>)
# then: sudo pfctl -f /etc/pf.conf -e
```

### Client: route traffic through the tunnel

The client must keep a **host route to the server's IP via the real gateway**
(otherwise the encrypted UDP would loop back into the tunnel), then route the
desired destinations via the tunnel peer. The two `/1` routes below override the
default route without deleting it.

**Linux:**

```sh
# Keep the server reachable over your real link (replace GW/DEV):
sudo ip route add <SERVER_IP>/32 via <YOUR_DEFAULT_GW> dev <YOUR_WAN_DEV>
# Route everything through the tunnel peer:
sudo ip route add 0.0.0.0/1 via 10.9.0.1
sudo ip route add 128.0.0.0/1 via 10.9.0.1
```

**macOS:**

```sh
# Keep the server reachable over your real link (replace GW):
sudo route -n add -host <SERVER_IP> <YOUR_DEFAULT_GW>
# Route everything through the tunnel peer:
sudo route -n add -net 0.0.0.0/1 10.9.0.1
sudo route -n add -net 128.0.0.0/1 10.9.0.1
```

To stop using the tunnel, delete the routes you added. If the server is given as
a hostname rather than a literal IP, resolve it first and add the host route for
that resolved IP.

---

## Project layout

```
src/
  lib.rs          crate root + module docs
  crypto.rs       Cipher enum, EVP_BytesToKey, HKDF-SHA1 subkey, AEAD seal/open
  protocol.rs     tunnel framing constants and buffer sizing
  config.rs       JSON file + clap CLI config, merge/validate
  tun_device.rs   async TUN wrapper (tun-rs, macOS utun + Linux)
  bin/server.rs   server binary: UDP<->TUN forwarding + client routing table
  bin/client.rs   client binary: TUN<->UDP relay loops + keepalive
```

---

## License

MIT.
