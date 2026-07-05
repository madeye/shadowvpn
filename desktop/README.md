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
> (list/create/edit/delete, plus **`shadowvpn://` URI import/export**), status
> derivation, log tailing, and the `connect`/`disconnect` elevation flow
> described below (osascript / pkexec / PowerShell `Start-Process -Verb RunAs`)
> are all implemented. `cargo tauri build` produces a bundled app + icon (a
> `.app`/`.dmg` on macOS); `cargo run` / `cargo tauri dev` also work for
> iteration. Everything in this document (paths, IPC shapes, security caveats)
> reflects the code as it stands today.

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
cargo build --bins   # also builds shadowvpn-desktop-helper (session elevation)
cargo run
```

This compiles `shadowvpn-desktop` (a standalone crate — it has its own
`Cargo.toml`/`Cargo.lock` and an empty `[workspace]` table so it never attaches
to the root `shadowvpn` package) and opens the window. The `--bins` build puts
`shadowvpn-desktop-helper` next to the main binary in `target/debug/`, which is
where the app looks for it (see [Elevation model](#elevation-model-by-design--see-status-above));
without it, connecting fails with an actionable "helper not found" error.

Installable packages are built by the `desktop` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml): a `.dmg`
on macOS (arm64 + x86_64), `.deb`/`.AppImage` on Linux (x86_64), and an NSIS
`-setup.exe` on Windows (x64 + ARM64). Each package bundles the matching-arch
`shadowvpn-client` next to the app executable (resolved as `app_dir`), and —
on macOS and Windows — the `gfwlist.txt` + `GeoLite2-Country.mmdb` policy data
(plus `wintun.dll` on Windows) beside it. The bundle wiring (Tauri
`externalBin`/`resources`) lives in a CI-generated config overlay, not in
`tauri.conf.json`, so a plain `cargo run` needs no pre-staged files. Packages
are unsigned (macOS is ad-hoc signed): expect the usual Gatekeeper /
SmartScreen prompts.

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

### Import / export via `shadowvpn://` URI

**Import URI** (sidebar) decodes a `shadowvpn://<base64url(JSON)>` URI — the same
opaque, lossless format the standalone
[`shadowvpn-uri`](../src/uri.rs) tool and other ShadowVPN clients emit — and
opens it in the editor as a **new, unsaved** profile. Nothing is written until
you name it and click Save (which runs the same validation as any profile), so
you get a chance to re-point host-specific paths (`gfwlist` / `chnroute` /
`geoip` / `cache_file`) that a URI exported on another machine may reference.
Decoding is strict: `deny_unknown_fields` rejects a URI carrying a field this
build doesn't know, exactly like the client.

**Export URI** (in the profile editor) is the inverse — it encodes the profile
currently in the form. The payload is Base64, **not encryption**: it contains
the password in the clear, so treat an exported URI as a secret. The two
commands (`import_uri`, `export_uri`) are byte-for-byte compatible with
`shadowvpn-uri`, so a URI/QR made by that tool imports here and vice-versa.

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

### Bundled policy data (gfwlist / GeoIP)

`gfwlist` and `chinadns` modes need a data file. If a `gfwlist.txt` or a
`GeoLite2-Country.mmdb` sits **next to the resolved `shadowvpn-client` binary**,
the client auto-discovers it, so those modes work with the profile's path fields
left blank. `gfwlist` mode uses the bundled `gfwlist.txt` as its routing list;
`chinadns` mode uses the bundled `GeoLite2-Country.mmdb` for the China set and
**also auto-applies the bundled `gfwlist.txt` as its force-tunnel override**
(aligned with the iOS client's network extension). The packaged macOS app ships
both files inside `ShadowVPN.app/Contents/MacOS/` alongside the bundled
`shadowvpn-client`; the Windows zip ships both next to `shadowvpn-client.exe`.

`save_profile` mirrors this: it only rejects `mode=gfwlist` / `mode=chinadns`
with empty path fields when no matching bundled file is found next to the
resolved client binary (`bundled_data` in `profiles.rs`). A profile path, when
set, always overrides the bundled copy.

## Elevation model (by design — see Status above)

Creating a TUN device and rewriting DNS needs root/Administrator, but Tauri's
webview process never runs elevated. Instead of prompting on every
connect/disconnect, the app acquires elevation **once per session**: at UI
startup (and again at first Connect, if you declined the startup dialog) it
spawns the bundled **`shadowvpn-desktop-helper`** through the per-OS
elevation dialog:

* **macOS** — `osascript -e 'do shell script "… &" with administrator privileges'`
* **Linux** — `pkexec <helper> …`. If `pkexec` isn't on `PATH`, the app
  surfaces the exact `sudo` command line to run by hand instead.
* **Windows** — a hidden PowerShell `Start-Process -Verb RunAs` (UAC).

The helper then stays alive for the session and Connect/Disconnect become
RPCs to it — newline-delimited JSON over `127.0.0.1:<random port>`,
authenticated per request by a 32-byte random token stored 0600 in
`<app-data-dir>/runs/helper.token` (the port lands in `runs/helper.port`).
The helper's capabilities are deliberately narrow: it only ever executes the
one client binary fixed on its command line at spawn time, and only ever
signals the child it spawned itself — requests cannot name a program or a
PID. Because the helper is the client's **parent**, disconnect delivers a
real `SIGTERM` on macOS/Linux (graceful: DNS restore, route removal, cache
save) with a `SIGKILL` backstop after 10s; on Windows it terminates the
child process (forced, as before).

Lifecycle: quitting the app while disconnected shuts the helper down (and
removes the token). Quitting while **connected** leaves the helper
supervising the tunnel, so a relaunched GUI reconnects to it and can
disconnect gracefully with **zero** prompts. A client left over from a
crashed helper is still stoppable: disconnect falls back to a one-off
elevated kill (the only per-action elevation left).

### macOS: Touch ID instead of the password prompt (optional daemon)

macOS never offers Touch ID for the `osascript` admin dialog — that prompt is
password-only by OS design. The app therefore ships a second, opt-in
transport to the **same helper**: Settings > *Privileged daemon (macOS)*
registers `shadowvpn-desktop-helper` as a launchd **LaunchDaemon** via
`SMAppService` (macOS 13+). After a one-time approval in System Settings >
General > Login Items, the daemon is always available as root and there are
**no password prompts at all**; instead the GUI proves user presence once per
app session with **Touch ID / Apple Watch** (login-password fallback, via
`LocalAuthentication`) before its first use of the daemon.

Differences from the per-session helper, by design:

* **Daemon mode self-configures** (`SHADOWVPN_HELPER_DAEMON=1` in the plist):
  it only ever executes the `shadowvpn-client` sitting next to it *inside the
  app bundle* — a custom client path set in Settings silently falls back to
  the classic per-session prompt.
* The token is **generated by the daemon**, not the GUI, and published
  `root:admin 0640` (port file world-readable) under
  `/Library/Application Support/io.github.madeye.shadowvpn.desktop/`, so only
  admin-group users — who could obtain root anyway — can command it. The
  Touch ID gate is GUI-side UX/defense-in-depth, not the authority boundary;
  the Login Items approval is the durable admin consent.
* launchd owns the lifecycle (`KeepAlive`): quitting the app leaves the
  daemon running, and the helper's `shutdown` RPC only stops the client
  child. Uninstall from Settings (or `sfltool`/Login Items) to remove it.

Every daemon precondition failure (macOS < 13, dev build without a bundle,
daemon not approved yet, unreachable, version mismatch) falls back to the
osascript prompt, so nothing hard-depends on it. Note that `SMAppService`
requires a **signed** app bundle; for local testing of a `cargo tauri build`
output, ad-hoc sign it first: `codesign --force --deep -s - ShadowVPN.app`.

### Security caveats

* **Profile passwords are stored in plaintext** in
  `<app-config-dir>/profiles/<name>.json` (0644-ish, whatever the OS default
  file permissions are for that directory) — the same tradeoff as any plain
  `client.json` used with the CLI, just persisted for you. Treat the profiles
  directory like you would an SSH key file.
* Approving the session dialog grants root/Administrator to the
  **helper process** for the whole session; any process running as your user
  account that can read `runs/helper.token` can then ask it to start the
  configured client with a config of its choosing (it can never run another
  program). This is the same same-user trust boundary as the previous
  per-connect design — the GUI itself is never elevated. Paths containing a
  `"` character are refused outright rather than risk shell-quoting bugs.
* **Windows disconnect is still a forced kill** (`TerminateProcess`) — the
  client never gets the chance to run its graceful shutdown path (DNS
  resolver restore, per-destination route removal, DNS cache save), the same
  caveat [`scripts/README.md`](../scripts/README.md) documents for Task
  Manager kills. macOS/Linux disconnect is graceful (`SIGTERM` from the
  helper, `SIGKILL` backstop). A graceful Windows disconnect is future work.
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
