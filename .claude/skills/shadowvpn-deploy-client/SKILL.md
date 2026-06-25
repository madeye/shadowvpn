---
name: shadowvpn-deploy-client
description: Deploy, install, and run the ShadowVPN client in a target environment — Linux (systemd), macOS (launchd), or Windows (Wintun, foreground launcher or scheduled-task service). Use when the user wants to set up, install, deploy, cross-build, or run shadowvpn-client on a device; configure full-tunnel vs policy routing (gfwlist/chinadns); install it as a service/daemon/scheduled task; or troubleshoot the client (no connectivity, DNS left broken, Wintun error 193, poisoned DNS cache).
---

# Deploy the ShadowVPN client

The client owns a TUN device and a single UDP socket connected to the server. It
needs elevated privileges (root on Linux, `sudo` on macOS, **Administrator** on
Windows — Wintun + route/DNS changes).

Repo references — read these for the canonical artifacts:
- `dist/README.md`, `dist/systemd/shadowvpn-client.service`, `dist/launchd/io.github.madeye.shadowvpn-client.plist` — Linux/macOS service install.
- `scripts/README.md`, `scripts/shadowvpn-client.ps1`/`.cmd` — Windows self-elevating launcher.
- `README.md` §Configuration, §Running, §"Policy routing (gfwlist / chinadns)", §"Client: route traffic through the tunnel".

## 1. Build the binary for the target

Native: `cargo build --release --bin shadowvpn-client` → `target/release/shadowvpn-client`.

Cross-build from a dev box (preferred for remote targets — Zig linker, no Docker):
```sh
# Linux x86_64 / aarch64 (pin glibc to the target, e.g. 2.31 for Pi / older distros)
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.31 --bin shadowvpn-client
# Windows x64
cargo zigbuild --release --target x86_64-pc-windows-gnu      --bin shadowvpn-client
# Windows on ARM (ARM64)
cargo zigbuild --release --target aarch64-pc-windows-gnullvm --bin shadowvpn-client
```
**Windows arch gotcha (error 193):** the exe **and** `wintun.dll` must match the
host CPU arch. An x64 exe on an ARM64 Windows box runs under emulation but cannot
load an ARM64 `wintun.dll` → `LoadLibraryExW … error 193 (%1 is not a valid Win32
application)` at TUN creation. Verify the PE machine type before shipping
(`0x8664` = x64, `0xAA64` = ARM64) and pair it with the matching `wintun.dll`.

### Getting `wintun.dll` (Windows only)

**Official release zips already bundle it.** The Windows release packages
(`shadowvpn-<ver>-<target>-pc-windows-msvc.zip`) ship the matching-arch
`wintun.dll` next to the exe **and** a `GeoLite2-Country.mmdb` for chinadns geoip
mode — so a release download is self-contained, nothing else to fetch.

You only need the steps below when you **built the client yourself** (the repo
source does not contain `wintun.dll` — separate license, arch-specific). Download
the official signed release from WireGuard and pull the DLL for the host's CPU
arch out of it:

```sh
# 1. Download the release zip (pin a known version; 0.14.1 is the latest as of writing)
curl -fLO https://www.wintun.net/builds/wintun-0.14.1.zip
# (optional, recommended) verify the download against the SHA-256 on https://www.wintun.net/

# 2. The zip lays the DLLs out by architecture:
#    wintun/bin/amd64/wintun.dll   <- x64        (PE 0x8664)
#    wintun/bin/arm64/wintun.dll   <- ARM64      (PE 0xAA64)
#    wintun/bin/x86/wintun.dll     <- 32-bit x86
#    wintun/bin/arm/wintun.dll     <- 32-bit ARM
unzip -j wintun-0.14.1.zip 'wintun/bin/amd64/wintun.dll' -d .   # pick the arch you need
```

On Windows/PowerShell: `Expand-Archive wintun-0.14.1.zip -DestinationPath wintun`
then copy `wintun\wintun\bin\<arch>\wintun.dll` next to `shadowvpn-client.exe`.

The DLL is loaded at runtime from the **same folder as the exe** (it is not
installed system-wide). Match it to the exe you built: an `x86_64-pc-windows-*`
exe needs `amd64`, an `aarch64-pc-windows-*` exe needs `arm64` — mismatch is the
error-193 above. Source + checksums: https://www.wintun.net/.

## 2. Write `client.json`

```json
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.2",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.1",
  "mtu": 1400,
  "obfs": "quic"
}
```
- `server` = the server's public `host:port`. The client resolves the hostname with
  its **own built-in DNS client** (querying `dns_remote`/`dns_local` directly), not
  the OS resolver — so a dirty/`127.0.0.1`-pinned system resolver no longer blocks
  startup (PR #27). A literal `ip:port` skips resolution entirely.
- `password`, `cipher`, `obfs` **must match the server**.
- `tun_ip`/`peer_ip` mirror the server's. If the server runs `--nat`, every client
  can share this identical config; otherwise give each client a distinct `tun_ip`.

## 3a. Install — Linux (systemd)

```sh
sudo install -Dm755 target/release/shadowvpn-client /usr/local/bin/shadowvpn-client
sudo install -Dm600 client.json /etc/shadowvpn/client.json
sudo cp dist/systemd/shadowvpn-client.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now shadowvpn-client
journalctl -u shadowvpn-client -f
sudo systemctl stop shadowvpn-client     # graceful: restores DNS + routes, saves cache
```

## 3b. Install — macOS (launchd)

```sh
sudo install -Dm755 target/release/shadowvpn-client /usr/local/bin/shadowvpn-client
sudo mkdir -p /etc/shadowvpn && sudo cp client.json /etc/shadowvpn/client.json
sudo cp dist/launchd/io.github.madeye.shadowvpn-client.plist /Library/LaunchDaemons/
sudo launchctl load -w /Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist
tail -f /var/log/shadowvpn-client.log
sudo launchctl unload -w /Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist  # graceful
```

## 3c. Install — Windows

Lay out one folder with `shadowvpn-client.exe`, the matching-arch `wintun.dll`, and
`client.json` (+ any policy data files). Two ways to run:

**Foreground (interactive):** from an elevated PowerShell, `.\shadowvpn-client.exe -c
client.json`, or use the self-elevating launcher `scripts\shadowvpn-client.cmd`
(see `scripts/README.md`). Stop with **Ctrl-C** — graceful (restores DNS, removes
routes, saves cache). **Never** `taskkill /F` (see DNS gotcha below).

**Headless service (runs with no user logged on)** — register a Scheduled Task:
- Action: `shadowvpn-client.exe -c <abs path to config>`, working dir = the folder.
- **LogonType = Password** (store the box's creds) — *Interactive* can't start at
  the login screen. **RunLevel = Highest** (Wintun needs elevation).
- Triggers: **AtStartup + AtLogon**; restart a few times on failure.
- `full` mode programs no routes itself — wrap the exe in a script that adds the
  routes + sets DNS **on the tun adapter** after the tun comes up (see the gotchas).
- Control: `Start-ScheduledTask` / `Stop-ScheduledTask -TaskName <name>`. A
  `Stop-ScheduledTask` is a hard kill (no Ctrl-C) — pair it with a teardown script
  that restores DNS/routes.

## 4. Choose a routing mode

| Mode | Behaviour | Needs |
|------|-----------|-------|
| `full` (default) | every packet routed into the tun is tunneled; you add the routes yourself | — |
| `gfwlist` | tunnel only names in a gfwlist file; everything else direct | `--gfwlist <file>` |
| `chinadns` | tunnel anything **not** resolving to an in-China IP; optional gfwlist is a force-tunnel override | `--chnroute <cidr>` or `--geoip <mmdb>` (+ optional `--gfwlist`) |

`gfwlist`/`chinadns` run a built-in split-DNS proxy and add per-destination `/32`
routes automatically — set them via `"mode"` in the JSON or `--mode` on the CLI.
For **`full`** mode you must route traffic yourself (README §"Client: route traffic
through the tunnel"): keep a host route to the **server** via the physical gateway,
then default everything via the tun `peer_ip`.

## Critical gotchas (operational)

- **Forced kill leaves DNS broken.** In gfwlist/chinadns mode the client points the
  system resolver at its proxy (`127.0.0.1:53`). A graceful stop (SIGTERM /
  launchd unload / Ctrl-C) restores it; a forced kill (`taskkill /F`,
  `Stop-ScheduledTask`, hard reboot) leaves DNS pinned at `127.0.0.1` with nothing
  listening → **all name resolution fails**. Fix on Windows:
  `Set-DnsClientServerAddress -InterfaceIndex <idx> -ServerAddresses ('223.5.5.5','119.29.29.29')`
  (target by index — the alias may be `WLAN 12` etc.; find it with
  `Get-DnsClientServerAddress | ? {$_.ServerAddresses -contains '127.0.0.1'}`).
  The client's internal resolver (PR #27) means a stale pin no longer blocks the
  client's *own* bootstrap, but it still breaks every other app until reset.
- **Poisoned `dns-cache.json` persists across restarts.** The cache is loaded at
  startup and short-circuits the gfwlist/clean-upstream logic, so a bad entry
  cached in an earlier run is served verbatim (and even gets a tun route). If a
  name resolves wrong after a mode switch, stop the client, **delete
  `dns-cache.json`** (next to the binary), restart.
- **Windows VPN bring-up can drop the LAN session.** Bringing up Wintun + route
  changes can momentarily reset the box's network; if you drive it over SSH/RDP on
  the same link, you may lose the session. Prefer the scheduled-task service or a
  teardown-safe wrapper, and have console/out-of-band access before a remote start.

## Verify

`ping 10.9.0.1` (the server's in-tunnel IP) answers; the egress IP
(`curl ifconfig.me` / a foreign-IP check) becomes the server's. In chinadns mode,
confirm a China domain resolves to a China IP and stays direct while a foreign
domain tunnels.
