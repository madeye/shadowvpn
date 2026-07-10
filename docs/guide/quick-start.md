# Quick start

Get a working tunnel between two hosts in a few minutes. You need a server
host with a public (or otherwise reachable) UDP port, and a client host.

## 1. Build the binaries

Requires a recent stable Rust toolchain (edition 2021):

```sh
cargo build --release
```

This produces `target/release/shadowvpn-server` and
`target/release/shadowvpn-client`. See [Installation](./installation) for
release packages, Windows, and cross-compiling.

## 2. Start the server

Creating a TUN device requires elevated privileges (root on Linux, `sudo` on
macOS, Administrator on Windows).

```sh
sudo ./target/release/shadowvpn-server \
  --listen 0.0.0.0:8388 \
  --password "correct horse battery staple" \
  --cipher chacha20-poly1305 \
  --tun-ip 10.9.0.1 \
  --peer-ip 10.9.0.2
```

## 3. Start the client

```sh
sudo ./target/release/shadowvpn-client \
  --server vpn.example.com:8388 \
  --password "correct horse battery staple" \
  --cipher chacha20-poly1305 \
  --tun-ip 10.9.0.2 \
  --peer-ip 10.9.0.1
```

Note how `tun_ip` and `peer_ip` are mirror images: the server's local tunnel
IP is the client's peer, and vice versa.

## 4. Verify

From the client, ping the server's in-tunnel address:

```sh
ping 10.9.0.1
```

A successful ping exercises the entire path: TUN → encrypt → UDP → server →
decrypt → TUN, and the reply all the way back.

## 5. Route traffic through it

The tunnel itself is up, but nothing uses it until you route traffic into the
TUN device. Pick one:

- **Full tunnel** — route everything through the tunnel (and NAT it out on
  the server). See [Routing & IP forwarding](./routing).
- **Split tunnel** — let the client decide per destination with its built-in
  policy routing (`gfwlist` / `chinadns` modes), no external tooling:

  ```sh
  # tunnel only the domains in a gfwlist file
  sudo ./target/release/shadowvpn-client -c client.json \
    --mode gfwlist --gfwlist /etc/shadowvpn/gfwlist.txt

  # or: tunnel everything that isn't a China IP, from a GeoLite2 database
  sudo ./target/release/shadowvpn-client -c client.json \
    --mode chinadns --geoip /etc/shadowvpn/GeoLite2-Country.mmdb
  ```

  See [Policy routing](./policy-routing).

Either way, for tunneled traffic to reach the internet the **server** must
enable IP forwarding and NAT — see
[Routing & IP forwarding](./routing#server-enable-ip-forwarding-nat).

## Using config files instead

Both binaries accept `-c, --config <PATH>` pointing at a JSON file; CLI flags
override JSON values. The same setup as above:

::: code-group

```json [server.json]
{
  "server": "0.0.0.0:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2",
  "mtu": 1400
}
```

```json [client.json]
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.2",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.1",
  "mtu": 1400
}
```

:::

```sh
sudo ./target/release/shadowvpn-server -c server.json
sudo ./target/release/shadowvpn-client -c client.json
```

See the [configuration guide](./configuration) for every field.
