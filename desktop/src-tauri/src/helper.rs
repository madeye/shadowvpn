//! GUI-side manager for the elevated helper process (see
//! `bin/shadowvpn-desktop-helper.rs`).
//!
//! `ensure()` is the single entry point: it returns the port of a live,
//! token-matching helper, spawning one (→ ONE credential prompt) only when
//! none is running. Called at UI startup (`init_privileges`) so the session
//! is authorized once up front, and again by `connect` as the safety net if
//! the user declined the startup prompt.

use std::process::Command;

use crate::helper_ipc::{self, Cmd, Request, Response};
use crate::paths;
use crate::settings;

/// How long to wait for the helper's port file + first ping after the user
/// approved the elevation dialog.
const SPAWN_WAIT_MS: u64 = 15_000;

fn read_port(app: &tauri::AppHandle) -> Option<u16> {
    let port_path = paths::helper_port_file(app).ok()?;
    std::fs::read_to_string(port_path).ok()?.trim().parse().ok()
}

fn read_token(app: &tauri::AppHandle) -> Option<String> {
    let token_path = paths::helper_token_file(app).ok()?;
    let tok = std::fs::read_to_string(token_path).ok()?;
    let tok = tok.trim().to_string();
    (!tok.is_empty()).then_some(tok)
}

/// Send `cmd` to the helper using the session token. Errors if either the
/// port or token file is missing or the helper doesn't answer.
pub fn call(app: &tauri::AppHandle, cmd: Cmd) -> Result<Response, String> {
    let port = read_port(app).ok_or("helper port file missing")?;
    let token = read_token(app).ok_or("helper token file missing")?;
    helper_ipc::call(port, &Request { token, cmd })
}

/// Ping the helper; `Some(response)` only for a live helper that accepted
/// our token.
pub fn ping(app: &tauri::AppHandle) -> Option<Response> {
    call(app, Cmd::Ping).ok().filter(|r| r.ok)
}

/// Ensure a live helper for `client_bin` and return its port.
/// Prompts for credentials (once) only when no usable helper is running.
pub fn ensure(app: &tauri::AppHandle, client_bin: &str) -> Result<u16, String> {
    if let Some(resp) = ping(app) {
        if resp.client_bin.as_deref() == Some(client_bin) {
            // Safe: ping() only returns Some for a live helper, which always
            // has a port file behind it.
            return read_port(app).ok_or("helper port file vanished".to_string());
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
        let _ = call(app, Cmd::Shutdown);
    }

    spawn(app, client_bin)
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
        if let Some(resp) = ping(app) {
            if resp.client_bin.as_deref() == Some(client_bin) {
                return read_port(app).ok_or("helper port file vanished".to_string());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err("elevated helper did not start (no response within 15s)".to_string())
}

/// On app exit: tear the helper down when idle; leave it supervising a live
/// connection (a relaunched GUI reuses it — and can disconnect — promptless).
pub fn on_app_exit(app: &tauri::AppHandle) {
    let Some(resp) = ping(app) else { return };
    if resp.running == Some(true) {
        return;
    }
    let _ = call(app, Cmd::Shutdown);
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
#[tauri::command]
pub fn init_privileges(app: tauri::AppHandle) -> Result<bool, String> {
    let settings_info = settings::get_settings(app.clone())?;
    let Some(bin) = settings_info.resolved_client_bin else {
        // No client binary yet (fresh install without bundle) — nothing to
        // elevate for; connect will surface the real error later.
        return Ok(false);
    };
    ensure(&app, &bin)?;
    Ok(true)
}
