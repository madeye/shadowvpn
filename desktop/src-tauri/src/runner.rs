//! `connect` / `disconnect` / `status` / `read_log` commands, and deriving
//! status purely from disk state (pidfile + state.json), so it survives GUI
//! restarts.
//!
//! Elevation happens ONCE per session: `helper::ensure` spawns the elevated
//! helper process (macOS `osascript`, Linux `pkexec`, Windows UAC — see
//! helper.rs), and connect/disconnect are then RPCs to it. The only elevated
//! command this module still issues itself is the `kill_elevated` fallback,
//! for stopping a client that outlived its helper (e.g. after an app
//! upgrade or a helper crash).

use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::helper;
use crate::helper_ipc::Cmd;
use crate::paths;
use crate::settings;
use crate::AppState;

#[derive(Serialize)]
pub struct StatusInfo {
    /// "connected" | "connecting" | "disconnected"
    pub state: String,
    pub pid: Option<u32>,
    pub profile: Option<String>,
    pub since: Option<u64>,
    pub log_file: Option<String>,
}

impl StatusInfo {
    fn disconnected() -> Self {
        StatusInfo {
            state: "disconnected".to_string(),
            pid: None,
            profile: None,
            since: None,
            log_file: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RunState {
    profile: String,
    started_unix: u64,
    log_file: String,
    pid_file: String,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    // Alive iff kill(pid, 0) returns 0, or errno is EPERM (process exists but
    // is owned by another user — the client runs as root, the GUI does not).
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.split_whitespace().any(|tok| tok == pid.to_string())
        }
        Err(_) => false,
    }
}

/// Pure disk + PID-probe status derivation (blueprint §5). Never errors.
pub fn current_status(app: &tauri::AppHandle) -> StatusInfo {
    let Ok(state_path) = paths::state_file(app) else {
        return StatusInfo::disconnected();
    };
    let Some(state) = std::fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str::<RunState>(&s).ok())
    else {
        return StatusInfo::disconnected();
    };

    let pid_path = std::path::PathBuf::from(&state.pid_file);

    // A run started before the current boot cannot still be alive: the
    // state/pid files survive reboots, and after a reboot the recorded PID
    // may have been reused by an unrelated process. Never probe (or later
    // kill) a PID recorded in a previous boot session; treat it as a dead
    // run instead. The 2s slack absorbs minor clock adjustments.
    if let Some(boot) = boot_time_unix() {
        if state.started_unix.saturating_add(2) < boot {
            let _ = std::fs::remove_file(&pid_path);
            let _ = std::fs::remove_file(&state_path);
            return StatusInfo {
                state: "disconnected".to_string(),
                pid: None,
                profile: Some(state.profile),
                since: None,
                log_file: Some(state.log_file),
            };
        }
    }

    let pid = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());

    match pid {
        Some(pid) if pid_alive(pid) => StatusInfo {
            state: "connected".to_string(),
            pid: Some(pid),
            profile: Some(state.profile),
            since: Some(state.started_unix),
            log_file: Some(state.log_file),
        },
        Some(_dead_pid) => {
            // Client crashed or exited; keep profile/log_file so the UI can
            // show the last log, but drop the stale pid/state files.
            let _ = std::fs::remove_file(&pid_path);
            let _ = std::fs::remove_file(&state_path);
            StatusInfo {
                state: "disconnected".to_string(),
                pid: None,
                profile: Some(state.profile),
                since: None,
                log_file: Some(state.log_file),
            }
        }
        None => {
            if now_unix().saturating_sub(state.started_unix) >= 30 {
                // Auth dialog abandoned; give up waiting for the pidfile.
                let _ = std::fs::remove_file(&state_path);
                StatusInfo::disconnected()
            } else {
                StatusInfo {
                    state: "connecting".to_string(),
                    pid: None,
                    profile: Some(state.profile),
                    since: Some(state.started_unix),
                    log_file: Some(state.log_file),
                }
            }
        }
    }
}

#[tauri::command]
pub fn status(app: tauri::AppHandle) -> Result<StatusInfo, String> {
    Ok(current_status(&app))
}

#[tauri::command]
pub fn read_log(app: tauri::AppHandle, lines: usize) -> Result<Vec<String>, String> {
    let n = lines.min(1000);
    let status = current_status(&app);
    let Some(log_file) = status.log_file else {
        return Ok(vec![]);
    };
    let Ok(data) = std::fs::read(&log_file) else {
        return Ok(vec![]);
    };

    const MAX_TAIL_BYTES: usize = 256 * 1024;
    let start = data.len().saturating_sub(MAX_TAIL_BYTES);
    let text = String::from_utf8_lossy(&data[start..]);
    let all: Vec<&str> = text.lines().collect();
    let take_from = all.len().saturating_sub(n);
    Ok(all[take_from..].iter().map(|s| s.to_string()).collect())
}

/// Reject paths that cannot be represented safely in the per-OS elevation
/// templates below. Untrusted values are never interpolated bare into shell
/// text — on macOS each value is single-quote shell-escaped, on Linux values
/// are passed as real argv positional parameters, and on Windows each value
/// is escaped for a single-quoted PowerShell literal — but two classes of
/// characters are rejected outright as defense in depth:
/// - `"`: the Windows inner template wraps the profile path in embedded
///   double quotes (Win32 command-line grouping), and the macOS wrapper is
///   embedded in an AppleScript double-quoted string;
/// - ASCII control characters (newline, CR, NUL, ...): these can terminate
///   or corrupt AppleScript/PowerShell source lines and never appear in
///   legitimate binary/profile/log paths.
pub fn check_path_safe(label: &str, s: &str) -> Result<(), String> {
    if s.contains('"') {
        return Err(format!(
            "{label} path contains a double-quote character, which is not supported: {s}"
        ));
    }
    if s.chars().any(|c| c.is_ascii_control()) {
        return Err(format!(
            "{label} path contains a control character, which is not supported: {s}"
        ));
    }
    Ok(())
}

/// POSIX shell single-quote escaping: the result is always a single literal
/// word to the shell — no `$(...)`, backtick, `$var`, glob or word-splitting
/// expansion can occur inside it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape a value for use inside a single-quoted PowerShell string literal.
#[cfg(windows)]
pub fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

// --- Boot-time staleness (guards against PID reuse across reboots) --------

#[cfg(target_os = "linux")]
fn boot_time_unix() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    Some(now_unix().saturating_sub(secs as u64))
}

#[cfg(target_os = "macos")]
fn boot_time_unix() -> Option<u64> {
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>();
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut tv as *mut libc::timeval as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret == 0 && tv.tv_sec > 0 {
        Some(tv.tv_sec as u64)
    } else {
        None
    }
}

#[cfg(windows)]
fn boot_time_unix() -> Option<u64> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount64() -> u64;
    }
    let uptime_ms = unsafe { GetTickCount64() };
    Some(now_unix().saturating_sub(uptime_ms / 1000))
}

#[cfg(target_os = "linux")]
pub fn pkexec_on_path() -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join("pkexec").is_file()))
        .unwrap_or(false)
}

// --- Per-OS elevated kill (fallback only) ----------------------------------
// Used when a running client has no live helper to stop it gracefully (helper
// crashed, or the client predates this GUI session's helper).

#[cfg(target_os = "macos")]
fn kill_elevated(pid: u32) -> Result<(), String> {
    // SIGKILL: unlike SIGTERM/SIGINT it cannot be caught, blocked, or ignored,
    // so the client always stops (see `disconnect`).
    let script = format!("do shell script \"/bin/kill -KILL {pid}\" with administrator privileges");
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| format!("failed to launch osascript: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "elevated kill failed (osascript {}): {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn kill_elevated(pid: u32) -> Result<(), String> {
    let output = Command::new("pkexec")
        .args(["/bin/kill", "-KILL", &pid.to_string()])
        .output()
        .map_err(|e| format!("failed to launch pkexec: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "elevated kill failed (pkexec {}): {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn kill_elevated(pid: u32) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // taskkill /F force-terminates the process tree — the Windows equivalent of
    // the SIGKILL used on Unix.
    let cmd = format!(
        "Start-Process -Verb RunAs -WindowStyle Hidden -Wait taskkill.exe -ArgumentList '/PID','{pid}','/T','/F'"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to launch powershell: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "elevated kill failed (powershell {}): {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

#[tauri::command]
pub fn connect(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    name: String,
) -> Result<StatusInfo, String> {
    let _guard = state
        .lock
        .lock()
        .map_err(|_| "internal state lock poisoned".to_string())?;

    let status = do_connect(&app, &name)?;
    // Record the intent: this profile should stay up. The reconnect watcher
    // uses it to restart a client that dies without a user disconnect.
    if let Ok(mut active) = state.active_profile.lock() {
        *active = Some(name);
    }
    Ok(status)
}

/// The connect body shared by the `connect` command and the auto-reconnect
/// watcher. The caller is responsible for holding `AppState.lock`.
pub fn do_connect(app: &tauri::AppHandle, name: &str) -> Result<StatusInfo, String> {
    paths::validate_profile_name(name)?;

    let current = current_status(app);
    if current.state != "disconnected" {
        return Err(format!("already {}", current.state));
    }

    let settings_info = settings::get_settings(app.clone())?;
    let Some(bin) = settings_info.resolved_client_bin else {
        return Err(
            "shadowvpn-client binary not found (checked: the path set in Settings, \
             a shadowvpn-client next to this app, and the dev default \
             /Volumes/DATA/workspace/shadowvpn/target/release/shadowvpn-client). \
             Set the client binary path in Settings."
                .to_string(),
        );
    };

    let profile_path = paths::profile_path(app, name)?;
    if !profile_path.exists() {
        return Err(format!("profile '{name}' not found"));
    }
    let profile_path_str = profile_path.to_string_lossy().to_string();

    let log_path = paths::log_file(app)?;
    let pid_path = paths::pid_file(app)?;
    let log_path_str = log_path.to_string_lossy().to_string();
    let pid_path_str = pid_path.to_string_lossy().to_string();

    check_path_safe("client binary", &bin)?;
    check_path_safe("profile", &profile_path_str)?;
    check_path_safe("log file", &log_path_str)?;
    check_path_safe("pid file", &pid_path_str)?;

    // One credential prompt per session lives here: reuses the live helper
    // when there is one, spawns (and prompts for) it otherwise.
    helper::ensure(app, &bin)?;

    // Ensure runs/ exists, rotate the previous run's log aside (its tail —
    // the reason that run ended — is the only post-mortem there is; a plain
    // truncate here used to destroy it), create the fresh log as the desktop
    // user (so it stays owned/readable even though the elevated client
    // appends to it), and clear any stale pidfile from a previous run.
    paths::runs_dir(app)?;
    rotate_log(&log_path);
    std::fs::File::create(&log_path).map_err(|e| format!("cannot create log file: {e}"))?;
    let _ = std::fs::remove_file(&pid_path);

    let run_state = RunState {
        profile: name.to_string(),
        started_unix: now_unix(),
        log_file: log_path_str.clone(),
        pid_file: pid_path_str.clone(),
    };
    let state_path = paths::state_file(app)?;
    let state_json = serde_json::to_string_pretty(&run_state).map_err(|e| e.to_string())?;
    std::fs::write(&state_path, state_json).map_err(|e| format!("cannot write state file: {e}"))?;

    // The helper writes the pidfile before responding, so a success here is
    // already "connected" for `current_status` — no pidfile polling needed.
    let resp = helper::call(
        app,
        Cmd::Connect {
            profile: profile_path_str,
            log: log_path_str,
            pid_file: pid_path_str,
        },
    );
    match resp {
        Ok(r) if r.ok => Ok(current_status(app)),
        Ok(r) => {
            let _ = std::fs::remove_file(&state_path);
            Err(r
                .error
                .unwrap_or_else(|| "helper refused connect".to_string()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&state_path);
            Err(e)
        }
    }
}

#[tauri::command]
pub fn disconnect(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
) -> Result<StatusInfo, String> {
    let _guard = state
        .lock
        .lock()
        .map_err(|_| "internal state lock poisoned".to_string())?;

    // Clear the intent up front (even if the stop below fails): the user asked
    // for the tunnel to be down, so the watcher must not bring it back.
    if let Ok(mut active) = state.active_profile.lock() {
        *active = None;
    }

    let current = current_status(&app);

    let Some(pid) = current.pid else {
        if current.state == "connecting" {
            // The auth dialog is still pending (or was abandoned): there is
            // no pid to kill yet, so just drop the pending run so the UI is
            // free to try again.
            if let Ok(state_path) = paths::state_file(&app) {
                let _ = std::fs::remove_file(&state_path);
            }
            return Ok(current_status(&app));
        }
        return Err("nothing running".to_string());
    };

    // Preferred path: the helper parents the client, so it can deliver a
    // real SIGTERM (graceful: DNS restore, route removal, cache save) with a
    // SIGKILL backstop — no credential prompt. (The old per-disconnect
    // elevation couldn't: `osascript "… &"` launched the client somewhere
    // SIGTERM never reached, which is why pre-helper builds used SIGKILL.)
    let stopped_by_helper = match helper::ping(&app) {
        Some(r) if r.running == Some(true) && r.pid == Some(pid) => {
            match helper::call(&app, Cmd::Disconnect) {
                Ok(r) if r.ok => true,
                // Helper answered but couldn't stop it — fall through to the
                // elevated kill rather than leaving the tunnel up.
                _ => false,
            }
        }
        // No helper, or it isn't supervising this pid (e.g. the client
        // predates this session): elevated kill fallback below.
        _ => false,
    };

    if !stopped_by_helper {
        kill_elevated(pid)?;
    }
    if !wait_for_exit(pid, 25) {
        return Err(format!(
            "process {pid} still alive 5s after being stopped; it may need to be stopped manually"
        ));
    }

    if let Ok(pid_path) = paths::pid_file(&app) {
        let _ = std::fs::remove_file(&pid_path);
    }
    if let Ok(state_path) = paths::state_file(&app) {
        let _ = std::fs::remove_file(&state_path);
    }

    Ok(current_status(&app))
}

/// Keep the previous run's log around as `<log>.1` (best-effort; one
/// generation is enough for a post-mortem).
fn rotate_log(path: &std::path::Path) {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        let rotated = std::path::PathBuf::from(rotated);
        // Windows `rename` refuses to replace an existing file.
        let _ = std::fs::remove_file(&rotated);
        let _ = std::fs::rename(path, &rotated);
    }
}

/// Poll `pid_alive` every 200ms up to `ticks` times; return true as soon as the
/// process is gone, false if it is still alive after the whole window.
fn wait_for_exit(pid: u32, ticks: u32) -> bool {
    for _ in 0..ticks {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    !pid_alive(pid)
}
