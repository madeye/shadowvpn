# Windows launcher scripts

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
