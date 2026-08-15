# Desktop app (experimental)

[`desktop/`](https://github.com/madeye/shadowvpn/tree/main/desktop) contains a
small [Tauri v2](https://v2.tauri.app/) GUI that wraps the existing
`shadowvpn-client` binary: it manages named JSON connection profiles, launches
the client **elevated** (root/Administrator — required for the TUN device and
DNS changes), tails its log, and shows connect/disconnect status.

It does **not** reimplement any tunnel logic — the Rust core is unchanged, and
the app just supervises the client process.

::: warning Status
This is an early, in-progress build. Profile management (list/create/edit/
delete, plus `shadowvpn://` URI import/export), status derivation, log
tailing, and the connect/disconnect elevation flow are implemented; see
[`desktop/README.md`](https://github.com/madeye/shadowvpn/blob/main/desktop/README.md)
for current status, IPC shapes, and security caveats.
:::

## Prerequisites

The GUI only needs to find and launch an already-built `shadowvpn-client`.
Build that first:

```sh
cargo build --release --bin shadowvpn-client
```

Per platform, to build/run the desktop app itself:

- **macOS** — a normal Rust + Xcode command-line-tools setup. The app launches
  the client via `osascript … with administrator privileges` (built into
  macOS).
- **Linux** — `pkexec` (from `polkit`) for the elevation prompt, and the
  WebKitGTK dev package Tauri v2 links against: `webkit2gtk-4.1-dev`
  (Debian/Ubuntu) or `webkit2gtk4.1-devel` (Fedora), plus the usual
  `build-essential`/`libssl-dev`/`libgtk-3-dev`. If `pkexec` is missing at
  runtime, `connect` fails with an error message containing the exact `sudo`
  command to run by hand instead.
- **Windows** —
  [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/)
  (preinstalled on current Windows 10/11) to render the UI, and `wintun.dll`
  next to whichever `shadowvpn-client.exe` you point the app at. The elevation
  prompt is a normal UAC dialog via PowerShell `Start-Process -Verb RunAs`.

No Node.js, no npm, no bundler, and no `tauri-cli` are required for
development — the UI is plain static HTML/CSS/JS served straight off disk, and
`cargo run` starts the whole app.

## Build & run

```sh
cd desktop/src-tauri
cargo build --bins   # also builds shadowvpn-desktop-helper (session elevation)
cargo run
```

The `--bins` build puts `shadowvpn-desktop-helper` next to the main binary in
`target/debug/`, which is where the app looks for it; without it, connecting
fails with an actionable "helper not found" error.

## Installable packages

The `desktop` job in the release workflow builds installable packages:

| Platform | Package |
|----------|---------|
| macOS (arm64 + x86_64) | `.dmg` |
| Linux (x86_64) | `.deb` / `.AppImage` |
| Windows (x64 + ARM64) | NSIS `-setup.exe` |

Each package bundles the matching-arch `shadowvpn-client` next to the app
executable, and — on macOS and Windows — the `gfwlist.txt` +
`GeoLite2-Country.mmdb` policy data (plus `wintun.dll` on Windows), so
[policy routing](./policy-routing) works out of the box.

## Profiles and Magic DNS

A saved profile **is** a `shadowvpn-client --config` file: only
[`FileConfig`](/reference/configuration) keys, same `deny_unknown_fields`
schema as the CLI. That includes [Magic DNS](./magic-dns) fields
(`hostname`, `magic_dns`, `magic_dns_suffix`) and the mesh / auto-assign
keys (`tun_ip6`, `keepalive_secs`, `advertise_routes`, `accept_routes`, …).
A CLI-written `client.json` that sets `"hostname": "tyo"` opens in the
editor instead of being rejected.

The profile form has a **Magic DNS hostname** field (blank = sanitized OS
hostname). Other optional keys without a control are preserved on save.
`hostname` is identity: it is not meant to be cloned by a share, the same
way `node_id` is kept out of a [`shadowvpn://` URI](./uri-qr).
