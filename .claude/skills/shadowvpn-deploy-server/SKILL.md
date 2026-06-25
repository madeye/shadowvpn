---
name: shadowvpn-deploy-server
description: Deploy, install, and run the ShadowVPN server in a target environment (Linux/systemd). Use when the user wants to set up, install, deploy, cross-build, or run the shadowvpn-server on a host (VPS, droplet, Raspberry Pi), enable internet egress for tunneled clients (IP forwarding + NAT/MASQUERADE), wire up the systemd unit, open the UDP port, or troubleshoot a server that clients cannot reach.
---

# Deploy the ShadowVPN server

The server terminates the encrypted UDP tunnel onto a TUN device and (optionally)
NATs tunneled clients to the internet. It needs **root** (TUN creation) and runs
on **Linux** in practice (the systemd unit ships in `dist/`).

Repo references — read these for the canonical artifacts:
- `dist/README.md` + `dist/systemd/shadowvpn-server.service` — the install recipe and unit.
- `README.md` §Configuration, §Building, §"Server: enable IP forwarding + NAT".
- `docker/server.json`, `docker/run-server-nat.sh` — working config + NAT example.

## 1. Build the binary for the target

Native (build on the server itself, needs a stable Rust toolchain):
```sh
cargo build --release --bin shadowvpn-server   # -> target/release/shadowvpn-server
cargo test --lib                               # optional sanity check
```

Cross-build from a dev box (preferred for remote Linux targets — uses Zig as the
linker, no Docker, works from any path). **Pin the glibc version to the target's**:
```sh
# x86_64 Ubuntu/Debian server (glibc 2.39 = Ubuntu 24.04; use 2.31 for older)
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.39 --bin shadowvpn-server
# aarch64 (Raspberry Pi etc.)
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.31 --bin shadowvpn-server
```
`cargo install cargo-zigbuild` if the subcommand is missing. Confirm the built
binary's max GLIBC requirement is ≤ the target's before shipping.

## 2. Write `server.json`

```json
{
  "server": "0.0.0.0:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2",
  "mtu": 1400,
  "obfs": "quic",
  "nat": true
}
```

Key points:
- `server` is the **UDP bind address** (`0.0.0.0:PORT`). The client's `server` is
  this host's public `host:port`.
- `password`, `cipher`, and `obfs` **must match the client exactly** (`obfs` defaults
  to `none`; both ends must agree). Wrong cipher/obfs = silent decrypt failure.
- `tun_ip`/`peer_ip` are mirror images of the client's (`server.tun_ip` ==
  `client.peer_ip`, and vice versa).
- **`"nat": true`** lets many clients share **one identical static config** (the
  server keys each by UDP endpoint and maps it onto a distinct internal IP). Without
  NAT, every client needs a distinct `tun_ip`. With NAT, idle mappings are reclaimed
  after `lease_ttl_secs` (default 120). See README §"Multiple clients with `--nat`".

## 3. Install + enable (systemd)

```sh
sudo install -Dm755 target/release/shadowvpn-server /usr/local/bin/shadowvpn-server
sudo install -Dm600 server.json /etc/shadowvpn/server.json
sudo cp dist/systemd/shadowvpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now shadowvpn-server
```

The shipped unit's `ExecStartPre` lines **enable IP forwarding + MASQUERADE** so
tunneled clients reach the internet. They are idempotent and re-applied on boot.
**You MUST edit the unit** if your setup differs from the defaults:
- WAN egress interface — the unit assumes `eth0`. Find yours with
  `ip route get 1.1.1.1` (the `dev …`), and replace `eth0` in the three iptables lines.
- Tunnel subnet — the unit assumes `10.9.0.0/24`; match your `tun_ip`/netmask.

After editing: `sudo systemctl daemon-reload && sudo systemctl restart shadowvpn-server`.

## 4. Open the UDP port

The data plane is **UDP** on the `server` port. Allow it on the host firewall AND
the cloud security group / provider firewall:
```sh
sudo ufw allow 8388/udp          # or nftables/iptables equivalent
```
On DigitalOcean/AWS/GCP also open the port in the cloud firewall — a host that
forwards fine but drops inbound UDP looks exactly like a wrong password to a client.

## 5. Verify

```sh
journalctl -u shadowvpn-server -f          # startup log; NAT line shows "NAT : ENABLED" when "nat": true
ss -lunp | grep 8388                        # socket bound
```
From a connected client: `ping 10.9.0.1` (the server's in-tunnel IP) should answer,
and the client's public egress IP (e.g. `curl ifconfig.me`) should become this host.

## Manual forwarding + NAT (if not using the unit's ExecStartPre)

```sh
sudo sysctl -w net.ipv4.ip_forward=1                                   # persist in /etc/sysctl.d/
WAN=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')
sudo iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$WAN" -j MASQUERADE
sudo iptables -A FORWARD -s 10.9.0.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.9.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

## Troubleshooting

- **Client connects but no internet** → forwarding/NAT not applied, or wrong WAN
  interface / subnet in the iptables rules. Check `sysctl net.ipv4.ip_forward` and
  `iptables -t nat -L POSTROUTING -n -v`.
- **Client times out entirely** → UDP port not open in the cloud firewall, or wrong
  public `host:port` in the client config.
- **Garbage / decrypt errors in the log** → `password`, `cipher`, or `obfs` mismatch
  between server and client.
- **Updating the binary** → back up the old one, `systemctl stop`, swap, `systemctl
  start`. Live clients reconnect within ~1 s (UDP, stateless handshake). Keep a
  timestamped `.bak` so you can roll back.

When deploying to a known live host, record the host, port, obfs, cipher, and the
NAT subnet so the matching client config can be produced without guessing.
