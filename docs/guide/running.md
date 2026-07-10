# Running server & client

Creating a TUN device requires elevated privileges (root on Linux, `sudo` on
macOS, **Administrator** on Windows). Both binaries log to stderr; set
`RUST_LOG=debug` for verbose tracing.

## Server

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

For tunneled clients to reach the wider network through the server, the server
host must also enable IP forwarding and NAT — see
[Routing & IP forwarding](./routing#server-enable-ip-forwarding-nat). The
binaries print these hints at startup.

## Client

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

Once the tunnel is up, verify connectivity with a ping across the tunnel
addresses — from the client:

```sh
ping 10.9.0.1
```

## Windows (client)

Put `shadowvpn-client.exe`, `wintun.dll` (matching the CPU architecture), and
your `client.json` in one folder, then run from an **elevated** PowerShell:

```powershell
.\shadowvpn-client.exe -c client.json
```

Wintun and the routing/DNS changes need Administrator, so launch the terminal
with *Run as administrator*.

::: warning Stop with Ctrl-C, not taskkill
Stop the client with **Ctrl-C** for a graceful shutdown — it restores the
system resolver, removes the per-destination routes, and saves the DNS cache.
Avoid `taskkill /F`, which skips that cleanup.
:::

### Self-elevating launcher

The [`scripts/`](https://github.com/madeye/shadowvpn/tree/main/scripts) folder
has a launcher that elevates itself via a UAC prompt:

```bat
shadowvpn-client.cmd
```

or, if your execution policy already allows local scripts
(`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`):

```powershell
.\shadowvpn-client.ps1 -Config client.json
```

`shadowvpn-client.cmd` is a thin wrapper that runs the `.ps1` with
`-ExecutionPolicy Bypass`, so you don't have to relax the policy at all.

## Keepalive

The client periodically sends a tiny encrypted keepalive datagram (every
15 seconds by default; `keepalive_secs` / `--keepalive-secs` to tune) so that
stateful NAT/firewall mappings stay open and the server learns the client's
current source address before any real traffic flows. Keep the interval below
your path's UDP NAT timeout. Details:
[wire protocol § keepalive](/reference/wire-protocol#keepalive).

## Graceful shutdown

The client handles Ctrl-C / `SIGTERM` cleanly: it restores the system
resolver, removes the tunnel routes it added, and saves the DNS cache before
exiting. Service managers get the same behaviour — see
[Running as a service](./service).
