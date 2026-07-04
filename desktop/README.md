# ShadowVPN Desktop (experimental)

A small [Tauri v2](https://v2.tauri.app/) GUI that wraps the existing
`shadowvpn-client` binary: it manages named JSON connection profiles, launches
the client **elevated** (root/Administrator, required for the TUN device and
DNS changes), tails its log, and shows connect/disconnect status. It does not
reimplement any tunnel logic — the Rust core in `../src` is unchanged, and this
app just supervises the client process.

<p align="center">
  <img src="../docs/architecture.svg" alt="ShadowVPN Desktop screenshot placeholder" width="60%">
  <br><sub><em>(screenshot placeholder — the app has no bundled icon/build yet, see Status below)</em></sub>
</p>

> **Status:** this is an early, in-progress build. Profile management
> (list/create/edit/delete), status derivation, log tailing, and the
> `connect`/`disconnect` elevation flow described below (osascript / pkexec /
> PowerShell `Start-Process -Verb RunAs`) are all implemented. No bundled
> app/icon yet — run it with `cargo run` as described under Build & run.
> Everything in this document (paths, IPC shapes, security caveats) reflects
> the code as it stands today.

---

## Prerequisites

The GUI never touches the tunnel itself — it only needs to find and launch an
already-built `shadowvpn-client`. Build that first (see the
[root README](../README.md#building)):

```sh
cd .. && cargo build --release --bin shadowvpn-client
```

Per platform, to build/run the **desktop app**:

* **macOS** — nothing beyond a normal Rust + Xcode command-line-tools setup.
  The app launches the client via `osascript … with administrator privileges`,
  which is built into macOS.
* **Linux** — `pkexec` (from `polkit`) for the elevation prompt, and the
  WebKitGTK dev package Tauri v2 links against to build:
  `webkit2gtk-4.1-dev` (Debian/Ubuntu) or `webkit2gtk4.1-devel` (Fedora), plus
  the usual `build-essential`/`libssl-dev`/`libgtk-3-dev`. If `pkexec` is
  missing at runtime, `connect` will fail with an error message containing the
  exact `sudo` command to run by hand instead.
* **Windows** — [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/)
  (preinstalled on current Windows 10/11) to render the UI, and
  **`wintun.dll`** sitting next to whichever `shadowvpn-client.exe` you point
  the app at (same requirement as the plain CLI — see
  [`scripts/README.md`](../scripts/README.md)). The elevation prompt is a
  normal UAC dialog via PowerShell `Start-Process -Verb RunAs`.

No Node.js, no npm, no bundler, and no `tauri-cli` are required for
development — `desktop/ui` is plain static HTML/CSS/JS served straight off
disk (`frontendDist: "../ui"` in `tauri.conf.json`), and `cargo run` starts the
whole app.

## Build & run

```sh
cd desktop/src-tauri
cargo run
```

This compiles `shadowvpn-desktop` (a standalone crate — it has its own
`Cargo.toml`/`Cargo.lock` and an empty `[workspace]` table so it never attaches
to the root `shadowvpn` package) and opens the window. There is nothing to
bundle yet (`bundle.active: false` in `tauri.conf.json`), so this is the only
supported way to run the app for now; a signed, installable build (via
`cargo tauri build`, which does need `tauri-cli`) is future work.

Useful variants:

```sh
cargo check                              # fast compile check
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

All four commands are run from inside `desktop/src-tauri/` — this crate is
verified independently of the root `shadowvpn` crate's `cargo test`.

## Where things live

Everything is per-OS app-data/app-config directories resolved by
`tauri::Manager::path()` (on macOS both kinds resolve to the same folder; on
Linux/Windows they can differ):

| Path | Contents |
|---|---|
| `<app-config-dir>/profiles/<name>.json` | One file per profile. **The file is itself a valid `shadowvpn-client --config` file** — only `FileConfig` keys, `deny_unknown_fields`, present-only keys. The profile name lives only in the filename. |
| `<app-config-dir>/settings.json` | `{"client_bin": "/path/to/shadowvpn-client"}` — see [Client binary resolution](#client-binary-resolution). |
| `<app-data-dir>/runs/shadowvpn.log` | stderr+stdout of the current/last client run (this is what the Log pane tails). |
| `<app-data-dir>/runs/shadowvpn.log.out` | Windows only: `Start-Process` can't redirect stdout and stderr to the same file, so stdout lands here (normally empty — the client logs to stderr). |
| `<app-data-dir>/runs/shadowvpn.pid` | Written by the elevated wrapper once the client starts; read back by the GUI to know the PID. |
| `<app-data-dir>/runs/state.json` | Written by the GUI at connect time (`profile`, `started_unix`, `log_file`, `pid_file`). This is what makes `status()` survive a GUI restart — status is derived purely from these files plus a liveness probe of the PID, there is no in-memory daemon. |

On macOS these resolve under
`~/Library/Application Support/io.github.madeye.shadowvpn.desktop/`; on Linux,
`~/.config/io.github.madeye.shadowvpn.desktop/` (config) and
`~/.local/share/io.github.madeye.shadowvpn.desktop/` (data); on Windows, both
under `%APPDATA%\io.github.madeye.shadowvpn.desktop\`.

### Client binary resolution

`Settings` (`get_settings`/`save_settings`) holds one field, `client_bin`.
Resolution order, reported back as `resolved_from`:

1. `settings.client_bin`, if set **and the file exists** (`"settings"`).
2. `shadowvpn-client` (`shadowvpn-client.exe` on Windows) next to the running
   app executable (`"app_dir"`).
3. A hardcoded dev-machine fallback path (`"dev_default"`) — only useful on
   the maintainer's own build machine.

If none resolve, `connect` will fail (once implemented) with an error listing
which of the three it tried.

## Elevation model (by design — see Status above)

Creating a TUN device and rewriting DNS needs root/Administrator, but Tauri's
webview process does not run elevated, so `connect` shells out to a small
elevated one-liner per OS rather than elevating the whole app:

* **macOS** — `osascript -e 'do shell script "…" with administrator
  privileges'`. The inner command backgrounds the client
  (`RUST_LOG=info shadowvpn-client -c <profile> </dev/null >>log 2>&1 & echo
  $! > pidfile`) so `do shell script` returns as soon as it's launched instead
  of blocking for the tunnel's whole lifetime.
* **Linux** — `pkexec /bin/sh -c '…'` running the same backgrounded-client
  one-liner. If `pkexec` isn't on `PATH`, the app refuses to guess at another
  elevation mechanism and instead surfaces the exact `sudo sh -c '...'`
  command line to run by hand.
* **Windows** — a hidden PowerShell `Start-Process -Verb RunAs -Wait` running
  an inner `Start-Process -RedirectStandardError <log> -RedirectStandardOutput
  <log>.out -PassThru`, writing the real client PID (not a wrapper PID) to the
  pidfile.

Disconnect mirrors this per OS (`kill -TERM` via osascript/pkexec, `taskkill`
via RunAs).

### Security caveats

* **Profile passwords are stored in plaintext** in
  `<app-config-dir>/profiles/<name>.json` (0644-ish, whatever the OS default
  file permissions are for that directory) — the same tradeoff as any plain
  `client.json` used with the CLI, just persisted for you. Treat the profiles
  directory like you would an SSH key file.
* Every `connect` spawns a **new elevated child process** via
  osascript/pkexec/RunAs; the GUI itself is never elevated, but you are
  granting root/Administrator to the exact command line the app builds
  (binary path + profile path). Paths containing a `"` character are refused
  outright rather than risk shell-quoting bugs.
* **Windows disconnect is a forced kill** (`taskkill /F`) issued through
  RunAs — the client never gets the chance to run its graceful shutdown path
  (DNS resolver restore, per-destination route removal, DNS cache save), the
  same caveat [`scripts/README.md`](../scripts/README.md) documents for
  Task Manager kills. macOS/Linux disconnect sends `SIGTERM`, which the client
  **does** handle gracefully. A graceful Windows disconnect is future work.
* Status is derived from **PID liveness only** (`kill(pid, 0)`/`tasklist`),
  not from any health check of the tunnel itself — a client that's stuck but
  still running shows as "connected".

## Troubleshooting

* **"client binary not found" / connect fails immediately** — set the path
  explicitly in Settings, or build `shadowvpn-client` and place it next to the
  desktop app's executable (see [Client binary resolution](#client-binary-resolution)).
* **`pkexec` not found (Linux)** — install `polkit`
  (`sudo apt install policykit-1` / `sudo dnf install polkit`), or run the
  manual `sudo sh -c '...'` command the error message gives you.
* **Wintun error 193 (Windows, especially ARM64)** — this is a 32/64-bit or
  x86/ARM64 mismatch between `shadowvpn-client.exe` and `wintun.dll`; make sure
  both are the same architecture and that `wintun.dll` sits directly next to
  the `.exe` the app is configured to launch. See the note in
  [`scripts/README.md`](../scripts/README.md) and the root README's Windows
  section for the matching cross-build command.
* **Nothing happens after the elevation prompt** — check the log pane (or
  `<app-data-dir>/runs/shadowvpn.log` directly); a bad profile (e.g.
  `mode=gfwlist` with no `gfwlist` path) will make the client exit immediately
  after acquiring the TUN device, which briefly shows as "connected" before
  flipping back to "disconnected" with the crash reason in the log.
* **A profile won't load / "invalid profile" error** — the profile file is
  parsed with the client's own `deny_unknown_fields` rules; a hand-edited file
  with a typo'd key (or one written by a newer/older version of this app) will
  fail to parse rather than silently drop the field.
