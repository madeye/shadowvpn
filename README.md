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

### End-to-end test (Docker)

A full data-path test lives under `docker/`. It builds both binaries, starts a
**server** and a **client** container — each with its own TUN device — on a
private bridge network, and then pings the server's in-tunnel address from the
client. A successful, lossless ping exercises the entire path: TUN → encrypt →
UDP → server → decrypt → TUN, and the reply all the way back.

```sh
./docker/run-e2e.sh                 # default cipher (chacha20-poly1305)
./docker/run-e2e.sh aes-256-gcm     # any supported cipher
```

The containers need `NET_ADMIN` and `/dev/net/tun` (the compose file requests
both). The script exits non-zero if connectivity through the tunnel fails, so it
doubles as the CI gate (see `.github/workflows/ci.yml`, which runs it across all
three ciphers alongside `fmt` + `clippy` + unit tests).

### HTTP/3-over-tunnel test (Docker)

A second, more demanding test proves ShadowVPN carries arbitrary UDP traffic by
running **real HTTP/3 (QUIC)** through the tunnel. The server enables IP
forwarding and masquerades the tunnel subnet to the internet; the client routes
**all** egress through the tunnel (its default route is deleted, so the only way
out is via ShadowVPN) and fetches a QUIC site with an HTTP/3-only `curl`:

```sh
./docker/run-e2e-http3.sh                       # default: https://www.cloudflare-quic.com/
TARGET_URL=https://cloudflare-quic.com/ ./docker/run-e2e-http3.sh aes-256-gcm
```

The test passes when the response is delivered over **HTTP/3** (`http_version=3`);
the application status code is irrelevant (Cloudflare may bot-block with `403` —
the point is that the QUIC handshake and HTTP/3 exchange completed over the
tunnel). It runs on a private bridge network with any host proxy neutralized, so
QUIC must travel through ShadowVPN rather than around it. In CI this job runs on
pushes to `main` and on manual dispatch (it depends on external connectivity).

### Policy-routing test (Docker)

Exercises [policy routing](#policy-routing-gfwlist--chinadns--client-linux-only)
end to end. The topology puts a source-IP echo server behind the tunnel and
another on the LAN: a tunneled request shows up as the *server's* address, a
direct one as the *client's*, so the two paths are unambiguous. It verifies that
both modes tunnel the selected domain and leave the other direct:

```sh
./docker/run-e2e-policy.sh             # both gfwlist and chinadns
./docker/run-e2e-policy.sh gfwlist     # one mode
```

Fully self-contained (no external network), so CI runs it on every PR.

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

## Policy routing (gfwlist / chinadns) — client, Linux only

By default the client is a *full* tunnel: every packet that reaches the TUN is
encrypted to the server, and what you route into the TUN is your business (see
the next section). For the common case of "send only some destinations through
the tunnel", the client has a built-in **policy-routing** mode that follows the
classic `dnsmasq` + `ipset` design — no external daemon required.

A small **split-DNS proxy** runs inside the client. For each query it decides
whether the name should be tunneled, adds the answer's addresses to a kernel
**ipset**, and a dedicated policy-routing table sends anything in that set
through the tunnel. Only that table is touched; the main routing table and your
default route are left alone, and everything is removed again on exit.

Two modes:

| Mode       | Decision                                                            | Needs       |
|------------|--------------------------------------------------------------------|-------------|
| `gfwlist`  | tunnel names listed in a gfwlist file; everything else is direct    | `--gfwlist` |
| `chinadns` | query a domestic + a clean resolver; tunnel anything **not** resolving to an in-China address | `--chnroute` or `--geoip` |
| `full`     | no policy routing (the default)                                     | —           |

```sh
# gfwlist mode: tunnel only the domains in gfwlist.txt
sudo ./target/release/shadowvpn-client -c client.json \
  --mode gfwlist --gfwlist /etc/shadowvpn/gfwlist.txt

# chinadns mode: tunnel everything that isn't a China IP (CIDR file)
sudo ./target/release/shadowvpn-client -c client.json \
  --mode chinadns --chnroute /etc/shadowvpn/chnroute.txt

# chinadns mode: derive the China set from a GeoLite2 database instead
sudo ./target/release/shadowvpn-client -c client.json \
  --mode chinadns --geoip /etc/shadowvpn/GeoLite2-Country.mmdb
```

Then point the host's resolver at the proxy (it logs the exact line at startup):

```sh
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf   # proxy default: 127.0.0.1:5353
```

Relevant config / flags (all client-only; CLI overrides JSON):

| JSON field    | CLI flag        | Meaning                                                    | Default              |
|---------------|-----------------|-----------------------------------------------------------|----------------------|
| `mode`        | `--mode`        | `full` \| `gfwlist` \| `chinadns`                          | `full`               |
| `dns_listen`  | `--dns-listen`  | address the split-DNS proxy listens on                    | `127.0.0.1:5353`     |
| `dns_local`   | `--dns-local`   | domestic / direct DNS upstream                            | `114.114.114.114:53` |
| `dns_remote`  | `--dns-remote`  | clean DNS upstream (reached through the tunnel)           | `8.8.8.8:53`         |
| `gfwlist`     | `--gfwlist`     | domain-suffix file (gfwlist mode)                         | —                    |
| `chnroute`    | `--chnroute`    | China CIDR file (chinadns mode)                           | —                    |
| `geoip`       | `--geoip`       | GeoLite2/GeoIP2 `.mmdb`; builds the China set from it     | —                    |
| `geoip_country` | `--geoip-country` | ISO country code to select from the GeoIP database    | `CN`                 |
| `ipset_name`  | `--ipset`       | name of the ipset holding tunnel-routed addresses        | `shadowvpn`          |
| `route_table` | `--route-table` | routing table id for the tunnel default route            | `9011` (`0x2333`)    |
| `fwmark`      | `--fwmark`      | firewall mark linking the ipset to the routing table     | `9011` (`0x2333`)    |

* **gfwlist file** — one domain per line; `#`/`!` comments and a leading `*.`/`.`
  are accepted (the plain list produced by `gfwlist2dnsmasq`, not the base64
  blob). A name matches if it equals or is a subdomain of a listed suffix.
* **chnroute file** — one `a.b.c.d/len` per line (the classic APNIC-derived
  `chnroute.txt`).
* **geoip database** — a MaxMind `GeoLite2-Country.mmdb` (or paid GeoIP2). On
  startup every IPv4 network whose country is `--geoip-country` (default `CN`) is
  enumerated and merged into the China set, so you don't have to maintain a CIDR
  file. Takes precedence over `--chnroute` when both are given.

This needs root and the `ipset`/`iptables`/`ip` tools, and is **Linux only**; on
other platforms a non-`full` mode is rejected at startup. The
`docker/run-e2e-policy.sh` test exercises both modes end to end.

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
  policy/         client policy routing (gfwlist / chinadns + ipset)
    mod.rs        Mode, PolicyConfig, Linux orchestration
    gfwlist.rs    domain-suffix matching
    chnroute.rs   China IP range lookup
    geoip.rs      build the China set from a GeoLite2 .mmdb
    dns.rs        minimal DNS wire parsing
    proxy.rs      split-DNS proxy + routing decisions (IpSink trait)
    setup.rs      ipset/ip/iptables wiring (Linux)
  bin/server.rs   server binary: UDP<->TUN forwarding + client routing table
  bin/client.rs   client binary: TUN<->UDP relay loops + keepalive + policy
```

---

## License

MIT.
