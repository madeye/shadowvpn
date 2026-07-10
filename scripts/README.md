# Scripts

## One-line installer (Linux + macOS)

[`install.sh`](install.sh) installs or uninstalls the **server** or **client**
from the latest GitHub release with a single command:

```sh
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server     # or: client
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall server
```

On a Linux server, `--setup` goes from zero to a running service in one
command — it writes a real config (random password, NAT enabled), installs
the systemd unit with the detected WAN interface, enables + starts the
service, opens the UDP port in ufw/firewalld, and prints the matching client
config:

```sh
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server --setup
# optional: --port 443 --obfs quic
```

Run with `--help` (or see the
[installation guide](https://madeye.github.io/shadowvpn/guide/installation))
for `--service`, `--setup`, `--purge`, `SHADOWVPN_VERSION`, and `PREFIX`.

## Windows launcher scripts

Convenience launchers for the ShadowVPN **client** on Windows. The client needs
Administrator (to create the Wintun adapter and change routes / DNS), so the
PowerShell script self-elevates.

| File | Use |
|------|-----|
| [`shadowvpn-client.ps1`](shadowvpn-client.ps1) | Self-elevating launcher. Runs `shadowvpn-client.exe` with a config. |
| [`shadowvpn-client.cmd`](shadowvpn-client.cmd) | Thin wrapper that runs the `.ps1` with `-ExecutionPolicy Bypass` (so you don't have to relax the policy). |

## Layout

Put these next to the binary and its dependencies:

```
shadowvpn\
  shadowvpn-client.exe
  wintun.dll              <- required, from https://www.wintun.net/ (matching CPU arch)
  client.json             <- your config
  shadowvpn-client.ps1
  shadowvpn-client.cmd
```

`wintun.dll` is loaded at runtime and must sit in the same folder as the exe.

## Run

From that folder, in any console (the script elevates itself via a UAC prompt):

```bat
shadowvpn-client.cmd
```

or, if your execution policy already allows local scripts
(`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`):

```powershell
.\shadowvpn-client.ps1
```

Pick a specific config (e.g. for policy routing) with `-Config`:

```powershell
.\shadowvpn-client.ps1 -Config .\client-chinadns.json
```

## Stop

Press **Ctrl-C** in the window. The client shuts down gracefully — it restores
the system resolver, removes the per-destination routes, and saves the DNS
cache. Avoid `taskkill /F` / Task Manager: a forced kill skips that cleanup and
can leave DNS pointed at the proxy (`127.0.0.1`); if that happens, reset it with
`Set-DnsClientServerAddress -InterfaceAlias <name> -ServerAddresses <your,dns>`.
