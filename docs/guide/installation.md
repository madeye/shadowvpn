# Installation

## One-line install (Linux & macOS) {#one-line-install}

The quickest way to install: a single `curl | bash` that detects your OS and
CPU, downloads the matching binary from the
[latest release](https://github.com/madeye/shadowvpn/releases), installs it to
`/usr/local/bin`, and drops an example config at `/etc/shadowvpn/` (the client
also gets the bundled `gfwlist.txt` for
[policy routing](./policy-routing)):

::: code-group

```sh [server]
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server
```

```sh [client]
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- client
```

:::

### Server: one-line full setup {#server-setup}

On a Linux server, add `--setup` to go from zero to a **running service** in
one command. Beyond installing the binary, it:

- writes `/etc/shadowvpn/server.json` with a **random password** in
  [learning mode](./auto-assign) (assignment always on; `peer_ip` `.2` is
  reserved; an existing config is never overwritten),
- installs the systemd unit with the **detected WAN interface** and tunnel
  subnet, then enables + starts it,
- opens the UDP port in **ufw/firewalld** (if active),
- prints the **matching client config** (no `tun_ip` / `peer_ip` — the
  server auto-assigns), ready to paste on your devices.

```sh
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server --setup
```

Pick a port or an
[obfuscation mode](./configuration#carrier-obfuscation) (both ends must
match; the printed client config includes them):

```sh
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server --setup --port 443 --obfs quic
```

::: warning Cloud firewalls
`--setup` opens the host firewall only. On DigitalOcean/AWS/GCP etc., also
allow the UDP port in the cloud firewall / security group — a blocked port
looks exactly like a wrong password from the client side.
:::

### Uninstall

Uninstall the same way (configs are kept unless you add `--purge`):

::: code-group

```sh [server]
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall server
```

```sh [client]
curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall client
```

:::

Options and overrides:

- `--service` (after the role) also installs the systemd unit / launchd plist
  from the release package — installed but **not** enabled; see
  [Running as a service](./service).
- `server --setup` (Linux) does the whole server setup in one shot — see
  [above](#server-setup); `--port N` and `--obfs none|quic|base64` tune the
  generated config.
- `uninstall all` removes both binaries; `--purge` also removes
  `/etc/shadowvpn` configs.
- `SHADOWVPN_VERSION=v0.5.0` pins a release tag (default: latest);
  `PREFIX=~/.local` installs to a user-writable prefix without sudo
  (configs/services are then skipped).

::: tip Prefer to read before you pipe?
The script is
[`scripts/install.sh`](https://github.com/madeye/shadowvpn/blob/main/scripts/install.sh)
— short, commented, and reviewable.
:::

Windows has no `curl | bash` flow — use the self-contained release `.zip`
(client + `wintun.dll` + policy data), described [below](#windows).

## Release packages

Tagged releases on the
[GitHub releases page](https://github.com/madeye/shadowvpn/releases) ship
prebuilt packages per target:

| Target | Package | Contents |
|--------|---------|----------|
| `x86_64-unknown-linux-gnu` | `.tar.gz` | server + client binaries, bundled `gfwlist.txt` |
| `aarch64-unknown-linux-gnu` | `.tar.gz` | server + client binaries, bundled `gfwlist.txt` |
| `x86_64-apple-darwin` | `.tar.gz` | server + client binaries, bundled `gfwlist.txt` |
| `aarch64-apple-darwin` | `.tar.gz` | server + client binaries, bundled `gfwlist.txt` |
| `x86_64-pc-windows-msvc` | `.zip` | client + matching-arch `wintun.dll` + policy data (self-contained) |
| `aarch64-pc-windows-msvc` | `.zip` | client + matching-arch `wintun.dll` + policy data (self-contained) |

The release also builds installable **desktop app** packages — a `.dmg` on
macOS (arm64 + x86_64), `.deb`/`.AppImage` on Linux (x86_64), and an NSIS
`-setup.exe` on Windows (x64 + ARM64) — see the [desktop app guide](./desktop).

::: tip Bundled policy data
The Unix tarballs and the Windows zip bundle `gfwlist.txt` next to the client
(the Windows zip also downloads a `GeoLite2-Country.mmdb` at package time), so
[policy routing](./policy-routing) modes work out of the box — no separate
downloads.
:::

## Building from source

Requires a recent stable Rust toolchain (edition 2021):

```sh
cargo build --release
```

This produces two binaries:

- `target/release/shadowvpn-server`
- `target/release/shadowvpn-client`

Run the test suite (crypto + config unit tests):

```sh
cargo test --lib
```

### The `shadowvpn-uri` helper (optional)

Config export/import as `shadowvpn://` URIs and QR codes lives in a separate
binary behind the `uri` feature (off by default) so the server/client builds
stay lean:

```sh
cargo build --release --features uri --bin shadowvpn-uri
```

See [Config URIs & QR codes](./uri-qr).

## Windows

ShadowVPN builds on Windows (`x86_64-pc-windows-msvc` /
`aarch64-pc-windows-msvc`) with the MSVC toolchain; CI builds and tests the
Windows target on every push.

The client's TUN layer uses [Wintun](https://www.wintun.net/), whose
`wintun.dll` is loaded at runtime and **must sit next to
`shadowvpn-client.exe`** — download the build matching the CPU architecture
and drop it alongside the binary (the release zip already includes the right
one).

A recommended folder layout, with the self-elevating launcher from
[`scripts/`](https://github.com/madeye/shadowvpn/tree/main/scripts):

```
shadowvpn\
  shadowvpn-client.exe
  wintun.dll              <- required, matching CPU arch
  client.json             <- your config
  shadowvpn-client.ps1    <- self-elevating launcher
  shadowvpn-client.cmd    <- wrapper that bypasses the execution policy
```

::: warning ARM64 needs the ARM64 DLL
An `x86_64` `wintun.dll` next to an ARM64 `shadowvpn-client.exe` (or vice
versa) fails to load — typically Windows **error 193** (`%1 is not a valid
Win32 application`). Match the DLL to the binary's architecture, not the OS
marketing name.
:::

## Cipher performance on ARM

`chacha20-poly1305` (the default) uses runtime SIMD feature detection and is
fast out of the box on every target. AES-GCM uses AES-NI automatically on
x86-64, **but on aarch64 (Raspberry Pi, Apple Silicon, Windows-on-ARM) the
ARMv8 AES backend is gated behind compile-time target features** — a plain
`cargo build` for ARM runs AES-GCM in slow constant-time software.

- On ARM hardware that lacks (or isn't built for) AES acceleration, prefer
  `chacha20-poly1305` — it is both faster and simpler there.
- To use AES-GCM at full speed on ARM, build with the crypto features enabled:

  ```sh
  RUSTFLAGS="-C target-feature=+aes,+neon" cargo build --release
  # or, when building on the target device itself:
  RUSTFLAGS="-C target-cpu=native" cargo build --release
  ```

See the [ciphers reference](/reference/ciphers) for details.

## Next steps

- [Quick start](./quick-start) — bring the tunnel up.
- [Configuration](./configuration) — JSON config and CLI flags.
- [Running as a service](./service) — systemd / launchd units.
