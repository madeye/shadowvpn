//! GUI-side manager for the elevated helper process (see
//! `bin/shadowvpn-desktop-helper.rs`).
//!
//! `ensure()` is the single entry point: it returns the port of a live,
//! token-matching helper, spawning one (→ ONE credential prompt) only when
//! none is running. Called at UI startup (`init_privileges`) so the session
//! is authorized once up front, and again by `connect` as the safety net if
//! the user declined the startup prompt.
//!
//! macOS has a second, preferred transport to the same helper protocol: the
//! helper registered as a launchd LaunchDaemon via SMAppService (see
//! `macos_native.rs` and the plist under `macos/`). Once the user approves
//! it in System Settings > Login Items there are NO password prompts at all;
//! the GUI instead proves user presence once per app session with Touch ID /
//! Apple Watch (login-password fallback) before using the always-root
//! daemon. Every daemon precondition failure falls back to the legacy
//! osascript per-session prompt, so the app never hard-depends on it.

use std::path::PathBuf;
use std::process::Command;

use crate::helper_ipc::{self, Cmd, Request, Response};
use crate::paths;
use crate::settings;

/// How long to wait for the helper's port file + first ping after the user
/// approved the elevation dialog.
const SPAWN_WAIT_MS: u64 = 15_000;

/// Which helper instance to talk to. Ordered by preference.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    /// macOS launchd daemon (fixed root-published port/token files).
    #[cfg(target_os = "macos")]
    Daemon,
    /// Per-session helper spawned via osascript/pkexec/UAC (files under the
    /// user's app-data dir).
    Session,
}

const ENDPOINTS: &[Endpoint] = &[
    #[cfg(target_os = "macos")]
    Endpoint::Daemon,
    Endpoint::Session,
];

/// (port file, token file) for an endpoint.
fn endpoint_files(app: &tauri::AppHandle, ep: Endpoint) -> Result<(PathBuf, PathBuf), String> {
    match ep {
        #[cfg(target_os = "macos")]
        Endpoint::Daemon => Ok((
            PathBuf::from(helper_ipc::DAEMON_PORT_FILE),
            PathBuf::from(helper_ipc::DAEMON_TOKEN_FILE),
        )),
        Endpoint::Session => Ok((
            paths::helper_port_file(app)?,
            paths::helper_token_file(app)?,
        )),
    }
}

fn read_port_at(path: &std::path::Path) -> Option<u16> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_token_at(path: &std::path::Path) -> Option<String> {
    let tok = std::fs::read_to_string(path).ok()?;
    let tok = tok.trim().to_string();
    (!tok.is_empty()).then_some(tok)
}

/// Send `cmd` to one specific endpoint. Errors if either the port or token
/// file is missing or the helper doesn't answer.
fn call_endpoint(app: &tauri::AppHandle, ep: Endpoint, cmd: Cmd) -> Result<Response, String> {
    let (port_path, token_path) = endpoint_files(app, ep)?;
    let port = read_port_at(&port_path).ok_or("helper port file missing")?;
    let token = read_token_at(&token_path).ok_or("helper token file missing")?;
    helper_ipc::call(port, &Request { token, cmd })
}

fn ping_endpoint(app: &tauri::AppHandle, ep: Endpoint) -> Option<Response> {
    call_endpoint(app, ep, Cmd::Ping).ok().filter(|r| r.ok)
}

/// First endpoint (daemon before session helper) that answers a ping with
/// our token.
fn live_endpoint(app: &tauri::AppHandle) -> Option<(Endpoint, Response)> {
    ENDPOINTS
        .iter()
        .find_map(|&ep| ping_endpoint(app, ep).map(|r| (ep, r)))
}

/// Send `cmd` to whichever helper is live (daemon preferred).
pub fn call(app: &tauri::AppHandle, cmd: Cmd) -> Result<Response, String> {
    let (ep, _) = live_endpoint(app).ok_or("no running helper")?;
    call_endpoint(app, ep, cmd)
}

/// Ping any live helper; `Some(response)` only for one that accepted our
/// token.
pub fn ping(app: &tauri::AppHandle) -> Option<Response> {
    live_endpoint(app).map(|(_, r)| r)
}

/// Ensure a live helper for `client_bin` and return its port.
///
/// macOS: served by the approved launchd daemon (Touch ID gate, no password)
/// whenever it can run this exact `client_bin`; otherwise — and on every
/// other OS — by the per-session helper (one credential prompt when none is
/// running).
pub fn ensure(app: &tauri::AppHandle, client_bin: &str) -> Result<u16, String> {
    #[cfg(target_os = "macos")]
    if let Some(port) = daemon_ensure(app, client_bin)? {
        return Ok(port);
    }
    ensure_session(app, client_bin)
}

fn ensure_session(app: &tauri::AppHandle, client_bin: &str) -> Result<u16, String> {
    let session_port = |app: &tauri::AppHandle| -> Result<u16, String> {
        let (port_path, _) = endpoint_files(app, Endpoint::Session)?;
        read_port_at(&port_path).ok_or("helper port file vanished".to_string())
    };
    if let Some(resp) = ping_endpoint(app, Endpoint::Session) {
        if resp.client_bin.as_deref() == Some(client_bin) {
            // Safe: a live ping always has a port file behind it.
            return session_port(app);
        }
        // The resolved client binary changed since the helper was spawned. A
        // helper only ever runs its spawn-time binary, so re-elevate — but
        // never yank a helper that is still supervising a running client.
        if resp.running == Some(true) {
            return Err(
                "the client binary changed while a connection is active; disconnect first"
                    .to_string(),
            );
        }
        let _ = call_endpoint(app, Endpoint::Session, Cmd::Shutdown);
    }

    spawn(app, client_bin)
}

// --- macOS launchd daemon path ----------------------------------------------

/// Once per GUI session: has the Touch ID / user-presence gate been passed?
#[cfg(target_os = "macos")]
static PRESENCE_PROVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The only client binary the daemon will ever run: the `shadowvpn-client`
/// bundled next to this app executable (`Contents/MacOS/` in the bundle).
#[cfg(target_os = "macos")]
fn daemon_client_bin() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("shadowvpn-client");
    candidate
        .is_file()
        .then(|| candidate.to_string_lossy().to_string())
}

/// Whether this build carries the daemon definition
/// (`Contents/Library/LaunchDaemons/<plist>` relative to the app bundle).
/// Needed because SMAppService reports a never-registered daemon as
/// `NotFound` — the same status as a dev build without a bundle — so "can we
/// offer the daemon at all" must be decided from the bundle on disk.
#[cfg(target_os = "macos")]
fn daemon_plist_bundled() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    // Contents/MacOS/<exe> → Contents/Library/LaunchDaemons/<plist>
    exe.parent()
        .and_then(|macos_dir| macos_dir.parent())
        .map(|contents| {
            contents
                .join("Library/LaunchDaemons")
                .join(helper_ipc::DAEMON_PLIST_NAME)
                .is_file()
        })
        .unwrap_or(false)
}

/// `Ok(Some(port))` when the approved daemon serves this `client_bin`;
/// `Ok(None)` to fall back to the per-session helper; `Err` only when the
/// user actively failed the Touch ID gate.
#[cfg(target_os = "macos")]
fn daemon_ensure(app: &tauri::AppHandle, client_bin: &str) -> Result<Option<u16>, String> {
    use crate::macos_native as native;

    if native::daemon_status() != native::DaemonStatus::Enabled
        || daemon_client_bin().as_deref() != Some(client_bin)
    {
        return Ok(None);
    }
    // Enabled daemons are KeepAlive-launched by launchd; a couple of retries
    // cover a just-approved daemon still starting up.
    let mut live = None;
    for _ in 0..10 {
        if let Some(resp) = ping_endpoint(app, Endpoint::Daemon) {
            live = Some(resp);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    let Some(resp) = live else {
        return Ok(None); // enabled but unreachable — legacy prompt instead
    };
    if resp.client_bin.as_deref() != Some(client_bin) {
        // A daemon from a different install/version of the bundle; don't
        // fight it, just use the per-session path.
        return Ok(None);
    }

    // The daemon is always root — restore the "deliberate user action" the
    // password prompt used to provide, once per GUI session, with Touch ID /
    // Apple Watch (login-password fallback).
    use std::sync::atomic::Ordering;
    if !PRESENCE_PROVED.load(Ordering::Relaxed) {
        native::authenticate_user("authorize ShadowVPN to manage VPN connections this session")?;
        PRESENCE_PROVED.store(true, Ordering::Relaxed);
    }

    let (port_path, _) = endpoint_files(app, Endpoint::Daemon)?;
    Ok(Some(
        read_port_at(&port_path).ok_or("daemon port file vanished")?,
    ))
}

/// Generate a fresh session token, write it 0600, and spawn the helper via
/// the per-OS elevation dialog. Blocks until the helper answers (or the user
/// declines / it times out).
fn spawn(app: &tauri::AppHandle, client_bin: &str) -> Result<u16, String> {
    let helper_bin = helper_bin_path()?;
    let token_path = paths::helper_token_file(app)?;
    let port_path = paths::helper_port_file(app)?;

    let helper_str = helper_bin.to_string_lossy().to_string();
    let token_str = token_path.to_string_lossy().to_string();
    let port_str = port_path.to_string_lossy().to_string();
    crate::runner::check_path_safe("helper binary", &helper_str)?;
    crate::runner::check_path_safe("helper token file", &token_str)?;
    crate::runner::check_path_safe("helper port file", &port_str)?;
    crate::runner::check_path_safe("client binary", client_bin)?;

    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| format!("cannot generate session token: {e}"))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    paths::write_private(&token_path, token.as_bytes())
        .map_err(|e| format!("cannot write token file: {e}"))?;
    let _ = std::fs::remove_file(&port_path);

    spawn_elevated_helper(&helper_str, &token_str, &port_str, client_bin)?;

    // The elevation call returns once the user approved (the helper itself is
    // backgrounded); give it a moment to bind and publish its port.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(SPAWN_WAIT_MS);
    while std::time::Instant::now() < deadline {
        if let Some(resp) = ping_endpoint(app, Endpoint::Session) {
            if resp.client_bin.as_deref() == Some(client_bin) {
                let (port_path, _) = endpoint_files(app, Endpoint::Session)?;
                return read_port_at(&port_path).ok_or("helper port file vanished".to_string());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err("elevated helper did not start (no response within 15s)".to_string())
}

/// On app exit: tear the per-session helper down when idle; leave it
/// supervising a live connection (a relaunched GUI reuses it — and can
/// disconnect — promptless). The macOS launchd daemon is never torn down
/// here: launchd owns it and it is the whole point of prompt-free sessions.
pub fn on_app_exit(app: &tauri::AppHandle) {
    let Some(resp) = ping_endpoint(app, Endpoint::Session) else {
        return;
    };
    if resp.running == Some(true) {
        return;
    }
    let _ = call_endpoint(app, Endpoint::Session, Cmd::Shutdown);
    if let Ok(token_path) = paths::helper_token_file(app) {
        let _ = std::fs::remove_file(token_path);
    }
    if let Ok(port_path) = paths::helper_port_file(app) {
        let _ = std::fs::remove_file(port_path);
    }
}

/// The helper ships next to the app executable (same externalBin sidecar
/// mechanism as the bundled client; in dev it's the sibling target-dir bin).
fn helper_bin_path() -> Result<std::path::PathBuf, String> {
    let name = if cfg!(windows) {
        "shadowvpn-desktop-helper.exe"
    } else {
        "shadowvpn-desktop-helper"
    };
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate app executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or("app executable has no parent directory")?;
    let candidate = dir.join(name);
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(format!(
        "{name} not found next to the app executable ({}). In development, build it with \
         `cargo build --bins` first.",
        dir.display()
    ))
}

// --- Per-OS elevated helper spawn ------------------------------------------
// Mirrors the quoting/escaping rules documented in runner.rs: every untrusted
// path is shell-escaped (macOS), passed as real argv (Linux), or escaped for
// a single-quoted PowerShell literal (Windows), after check_path_safe.

#[cfg(target_os = "macos")]
fn spawn_elevated_helper(
    helper: &str,
    token_file: &str,
    port_file: &str,
    client_bin: &str,
) -> Result<(), String> {
    use crate::runner::sh_quote;
    let inner = format!(
        "{} --token-file {} --port-file {} --client-bin {} </dev/null >/dev/null 2>&1 &",
        sh_quote(helper),
        sh_quote(token_file),
        sh_quote(port_file),
        sh_quote(client_bin)
    );
    let escaped = inner.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "do shell script \"{escaped}\" with prompt \"ShadowVPN needs administrator access once per session to manage the VPN.\" with administrator privileges"
    );
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| format!("failed to launch osascript: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "authorization cancelled or elevation failed (osascript {}): {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_elevated_helper(
    helper: &str,
    token_file: &str,
    port_file: &str,
    client_bin: &str,
) -> Result<(), String> {
    use crate::runner::{pkexec_on_path, sh_quote};
    if !pkexec_on_path() {
        return Err(format!(
            "pkexec not found on PATH; run this manually instead:\nsudo {} --token-file {} --port-file {} --client-bin {} &",
            sh_quote(helper),
            sh_quote(token_file),
            sh_quote(port_file),
            sh_quote(client_bin)
        ));
    }
    // pkexec stays in the foreground for the helper's whole lifetime, so
    // spawn it detached and reap it from a thread; the port-file poll in
    // `spawn()` is what detects success, and a declined dialog surfaces as
    // the poll timing out (pkexec exits 126/127 without ever writing it).
    let child = Command::new("pkexec")
        .args([
            helper,
            "--token-file",
            token_file,
            "--port-file",
            port_file,
            "--client-bin",
            client_bin,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to launch pkexec: {e}"))?;
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(windows)]
fn spawn_elevated_helper(
    helper: &str,
    token_file: &str,
    port_file: &str,
    client_bin: &str,
) -> Result<(), String> {
    use crate::runner::ps_quote;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Values are embedded double-quoted inside the ArgumentList items so
    // paths with spaces survive Win32 command-line splitting (same pattern
    // as the profile path in the old per-connect spawn).
    let cmd = format!(
        "$ErrorActionPreference = 'Stop'; Start-Process -Verb RunAs -WindowStyle Hidden -FilePath '{}' -ArgumentList '--token-file','\"{}\"','--port-file','\"{}\"','--client-bin','\"{}\"'",
        ps_quote(helper),
        ps_quote(token_file),
        ps_quote(port_file),
        ps_quote(client_bin)
    );
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &cmd,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to launch powershell: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "authorization cancelled or elevation failed (powershell {}): {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

/// UI-invoked at startup: acquire the session's admin authority up front.
///
/// macOS with the launchd daemon in play: no prompt of any kind at startup —
/// an enabled daemon means the session already has authority (Touch ID
/// happens at the first connect), and a pending approval means the user
/// should not ALSO get a password dialog. Everything else falls through to
/// the classic one-prompt `ensure`.
#[tauri::command]
pub fn init_privileges(app: tauri::AppHandle) -> Result<bool, String> {
    let settings_info = settings::get_settings(app.clone())?;
    let Some(bin) = settings_info.resolved_client_bin else {
        // No client binary yet (fresh install without bundle) — nothing to
        // elevate for; connect will surface the real error later.
        return Ok(false);
    };
    #[cfg(target_os = "macos")]
    {
        use crate::macos_native as native;
        if daemon_client_bin().as_deref() == Some(bin.as_str()) && daemon_plist_bundled() {
            match native::daemon_status() {
                native::DaemonStatus::Enabled => return Ok(true),
                native::DaemonStatus::RequiresApproval => return Ok(false),
                // NotFound with the plist on disk is just "never registered"
                // (SMAppService only distinguishes them after a first
                // register call).
                native::DaemonStatus::NotRegistered | native::DaemonStatus::NotFound => {
                    // First run from a real bundle: registering is silent (no
                    // password) and just flips the daemon to
                    // requires-approval; the user approves it in System
                    // Settings whenever they like. Meanwhile this session
                    // keeps the classic prompt-at-connect behavior.
                    let _ = native::daemon_register();
                    return Ok(false);
                }
                native::DaemonStatus::Unavailable => {} // macOS < 13 — classic path below
            }
        }
    }
    ensure(&app, &bin)?;
    Ok(true)
}

// --- Settings-surface commands for the macOS daemon -------------------------

#[derive(serde::Serialize)]
pub struct DaemonInfo {
    /// Whether this build/OS can use the launchd daemon at all.
    pub supported: bool,
    /// "enabled" | "requires_approval" | "not_registered" | "not_found" |
    /// "unavailable" | "unsupported"
    pub status: String,
}

#[tauri::command]
pub fn daemon_info() -> DaemonInfo {
    #[cfg(target_os = "macos")]
    {
        use crate::macos_native::DaemonStatus;
        let mut status = crate::macos_native::daemon_status();
        let bundled = daemon_plist_bundled();
        // Never-registered daemons report NotFound (see daemon_plist_bundled)
        // — with the plist actually bundled that just means "not installed".
        if status == DaemonStatus::NotFound && bundled {
            status = DaemonStatus::NotRegistered;
        }
        DaemonInfo {
            supported: status != DaemonStatus::Unavailable && bundled,
            status: status.as_str().to_string(),
        }
    }
    #[cfg(not(target_os = "macos"))]
    DaemonInfo {
        supported: false,
        status: "unsupported".to_string(),
    }
}

/// Register the launchd daemon; when macOS wants explicit consent, jump the
/// user straight to System Settings > Login Items. Returns the new status.
#[tauri::command]
pub fn daemon_install() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use crate::macos_native as native;
        let register_result = native::daemon_register();
        let status = native::daemon_status();
        if status == native::DaemonStatus::RequiresApproval {
            native::open_login_items();
        } else if status != native::DaemonStatus::Enabled {
            register_result?;
        }
        Ok(status.as_str().to_string())
    }
    #[cfg(not(target_os = "macos"))]
    Err("the privileged daemon is only supported on macOS".to_string())
}

#[tauri::command]
pub fn daemon_uninstall() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use crate::macos_native as native;
        native::daemon_unregister()?;
        Ok(native::daemon_status().as_str().to_string())
    }
    #[cfg(not(target_os = "macos"))]
    Err("the privileged daemon is only supported on macOS".to_string())
}
