//! The elevated helper: spawned ONCE per GUI session (root via osascript /
//! pkexec, Administrator via UAC), so the user authorizes a single time and
//! every subsequent connect/disconnect is a token-authenticated RPC instead
//! of a fresh credential prompt.
//!
//! Security posture:
//! - It only ever executes the one client binary passed as `--client-bin` at
//!   spawn time (shown to the user by the elevation prompt's provenance) —
//!   requests cannot name a program to run.
//! - It only ever signals/kills the child it spawned itself — requests cannot
//!   name a PID.
//! - Every request must carry the token from the `--token-file`, which the
//!   GUI creates with 0600 permissions before requesting elevation. The file
//!   is re-read per request so a new GUI session can re-key a running helper.
//! - It listens on 127.0.0.1 only.
//!
//! Lifecycle: exits on a `shutdown` request, or when the token file has been
//! missing for ~30s while no client child is running (a crashed/closed GUI
//! that cleaned up). While a client it started is still running it stays
//! alive, so a later GUI session can disconnect gracefully with no prompt.
//!
//! macOS daemon mode (`SHADOWVPN_HELPER_DAEMON=1`, set by the launchd plist
//! registered via SMAppService): instead of GUI-supplied arguments it
//! self-configures — the client binary is the `shadowvpn-client` sitting
//! next to it inside the app bundle (never anything else), the port/token
//! files live under /Library/Application Support/<app id>/, and the token is
//! GENERATED HERE and published root:admin 0640, so only admin-group users
//! (who could obtain root anyway) can command the always-running daemon.
//! launchd owns the lifecycle: `shutdown` only stops the client child, and
//! the token-file janitor is disabled.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../helper_ipc.rs"]
mod helper_ipc;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use helper_ipc::{Cmd, Request, Response};

struct Args {
    token_file: PathBuf,
    port_file: PathBuf,
    client_bin: String,
    /// launchd daemon mode (macOS): launchd owns the lifecycle — never exit
    /// on `shutdown`, never remove the port file, no token-file janitor.
    daemon: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut token_file = None;
    let mut port_file = None;
    let mut client_bin = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--token-file" => token_file = Some(PathBuf::from(val()?)),
            "--port-file" => port_file = Some(PathBuf::from(val()?)),
            "--client-bin" => client_bin = Some(val()?),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        token_file: token_file.ok_or("--token-file is required")?,
        port_file: port_file.ok_or("--port-file is required")?,
        client_bin: client_bin.ok_or("--client-bin is required")?,
        daemon: false,
    })
}

/// Self-configuration for macOS launchd daemon mode: fixed publish paths, a
/// freshly generated root:admin 0640 token, and the bundle-sibling client
/// binary as the ONLY program this daemon will ever execute.
#[cfg(target_os = "macos")]
fn daemon_args() -> Result<Args, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own executable: {e}"))?;
    let client = exe
        .parent()
        .ok_or("helper executable has no parent directory")?
        .join("shadowvpn-client");
    if !client.is_file() {
        return Err(format!(
            "bundled shadowvpn-client not found at {}",
            client.display()
        ));
    }

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o755);
    builder
        .create(helper_ipc::DAEMON_DIR)
        .map_err(|e| format!("cannot create {}: {e}", helper_ipc::DAEMON_DIR))?;

    // Fresh token per daemon start. Written 0600 first, then handed to
    // root:admin 0640 so there is no window where a broader group can read
    // an unowned file.
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| format!("cannot generate session token: {e}"))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let token_file = PathBuf::from(helper_ipc::DAEMON_TOKEN_FILE);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&token_file)
            .map_err(|e| format!("cannot write token file: {e}"))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot tighten token file: {e}"))?;
        f.write_all(token.as_bytes())
            .map_err(|e| format!("cannot write token file: {e}"))?;
    }
    let path_c = std::ffi::CString::new(helper_ipc::DAEMON_TOKEN_FILE)
        .map_err(|_| "token path contains NUL")?;
    if unsafe { libc::chown(path_c.as_ptr(), 0, admin_gid()) } != 0 {
        return Err(format!(
            "cannot chown token file: {}",
            std::io::Error::last_os_error()
        ));
    }
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o640))
        .map_err(|e| format!("cannot set token file mode: {e}"))?;

    Ok(Args {
        token_file,
        port_file: PathBuf::from(helper_ipc::DAEMON_PORT_FILE),
        client_bin: client.to_string_lossy().to_string(),
        daemon: true,
    })
}

/// gid of the `admin` group (80 on every macOS release; looked up anyway).
#[cfg(target_os = "macos")]
fn admin_gid() -> libc::gid_t {
    // Safe: "admin" contains no NUL bytes.
    let name = std::ffi::CString::new("admin").unwrap();
    let grp = unsafe { libc::getgrnam(name.as_ptr()) };
    if grp.is_null() {
        80
    } else {
        unsafe { (*grp).gr_gid }
    }
}

fn read_token(path: &Path) -> Option<String> {
    let tok = std::fs::read_to_string(path).ok()?;
    let tok = tok.trim().to_string();
    (!tok.is_empty()).then_some(tok)
}

/// Constant-time-ish comparison; token strings are short and fixed-format,
/// this just avoids the obvious early-exit compare.
fn token_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

type ChildSlot = Arc<Mutex<Option<Child>>>;

/// Drop the child handle if the process has already exited (reaps zombies).
fn reap(slot: &mut Option<Child>) {
    if let Some(child) = slot.as_mut() {
        if matches!(child.try_wait(), Ok(Some(_))) {
            *slot = None;
        }
    }
}

fn spawn_client(
    client_bin: &str,
    profile: &str,
    log: &str,
    pid_file: &str,
) -> Result<Child, String> {
    // O_NOFOLLOW (Unix): the log/pid paths come from the GUI request and this
    // process runs as root — refuse to be tricked into writing through a
    // symlink planted at a user-controlled path.
    let mut log_opts = std::fs::OpenOptions::new();
    log_opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        log_opts.custom_flags(libc::O_NOFOLLOW);
    }
    let log_out = log_opts
        .open(log)
        .map_err(|e| format!("cannot open log file {log}: {e}"))?;
    let log_err = log_out
        .try_clone()
        .map_err(|e| format!("cannot clone log handle: {e}"))?;

    let mut cmd = Command::new(client_bin);
    cmd.arg("-c")
        .arg(profile)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to start {client_bin}: {e}"))?;
    if let Err(e) = write_nofollow(pid_file, format!("{}\n", child.id()).as_bytes()) {
        // Without the pidfile the GUI can neither show nor stop this run;
        // don't leave an orphaned root client behind.
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot write pid file {pid_file}: {e}"));
    }
    Ok(child)
}

/// `fs::write` that refuses to follow a symlink at `path` (see the note in
/// `spawn_client`; no-op difference on Windows, where the per-user ACLs
/// already protect these paths).
fn write_nofollow(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)?.write_all(data)
}

/// Stop the child: graceful where possible, forced as the backstop.
/// Unix: SIGTERM (the client restores DNS/routes and saves its cache), wait
/// up to 10s, then SIGKILL. Windows: TerminateProcess (the client has no
/// Ctrl-C equivalent we can deliver to a hidden detached process; same
/// tradeoff as the pre-helper design).
fn stop_child(child: &mut Child) -> Result<(), String> {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
        if ret == 0 {
            for _ in 0..50 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        // Never delivered, ignored, or hung mid-cleanup: force it.
        let _ = child.kill();
    }
    #[cfg(windows)]
    {
        let _ = child.kill();
    }
    child
        .wait()
        .map(|_| ())
        .map_err(|e| format!("wait for client exit failed: {e}"))
}

fn handle_conn(stream: TcpStream, args: &Args, slot: &ChildSlot) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return false,
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }

    let (resp, shutdown) = respond(&line, args, slot);
    let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    out.push('\n');
    let _ = writer.write_all(out.as_bytes());
    let _ = writer.flush();
    shutdown
}

fn respond(line: &str, args: &Args, slot: &ChildSlot) -> (Response, bool) {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return (Response::err(format!("bad request: {e}")), false),
    };
    // Re-read the token file on every request: rejects everything once the
    // GUI removed the file, and follows a re-key by a new GUI session.
    let Some(expected) = read_token(&args.token_file) else {
        return (Response::err("token file missing"), false);
    };
    if !token_eq(&expected, &req.token) {
        return (Response::err("bad token"), false);
    }

    let mut guard = match slot.lock() {
        Ok(g) => g,
        Err(_) => return (Response::err("helper state poisoned"), false),
    };
    reap(&mut guard);

    match req.cmd {
        Cmd::Ping => (
            Response {
                ok: true,
                running: Some(guard.is_some()),
                pid: guard.as_ref().map(|c| c.id()),
                client_bin: Some(args.client_bin.clone()),
                ..Default::default()
            },
            false,
        ),
        Cmd::Connect {
            profile,
            log,
            pid_file,
        } => {
            if guard.is_some() {
                return (Response::err("client already running"), false);
            }
            match spawn_client(&args.client_bin, &profile, &log, &pid_file) {
                Ok(child) => {
                    let pid = child.id();
                    *guard = Some(child);
                    (
                        Response {
                            ok: true,
                            pid: Some(pid),
                            running: Some(true),
                            ..Default::default()
                        },
                        false,
                    )
                }
                Err(e) => (Response::err(e), false),
            }
        }
        Cmd::Disconnect => match guard.take() {
            Some(mut child) => match stop_child(&mut child) {
                Ok(()) => (
                    Response {
                        ok: true,
                        running: Some(false),
                        ..Default::default()
                    },
                    false,
                ),
                Err(e) => (Response::err(e), false),
            },
            None => (
                // Idempotent, but flagged so the GUI can fall back to a
                // pid-based kill for a client this helper didn't start.
                Response {
                    ok: true,
                    running: Some(false),
                    ..Default::default()
                },
                false,
            ),
        },
        Cmd::Shutdown => {
            if let Some(mut child) = guard.take() {
                let _ = stop_child(&mut child);
            }
            // Daemon mode: launchd owns the lifecycle (and would immediately
            // restart us) — treat shutdown as "stop the client" only, and
            // keep the port file published.
            if !args.daemon {
                let _ = std::fs::remove_file(&args.port_file);
            }
            (
                Response {
                    ok: true,
                    ..Default::default()
                },
                !args.daemon,
            )
        }
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    let daemon_mode = std::env::var_os("SHADOWVPN_HELPER_DAEMON").is_some_and(|v| v == "1");
    #[cfg(not(target_os = "macos"))]
    let daemon_mode = false;

    let args = if daemon_mode {
        #[cfg(target_os = "macos")]
        match daemon_args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("shadowvpn-desktop-helper (daemon): {e}");
                std::process::exit(2);
            }
        }
        #[cfg(not(target_os = "macos"))]
        unreachable!()
    } else {
        match parse_args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("shadowvpn-desktop-helper: {e}");
                std::process::exit(2);
            }
        }
    };
    // The GUI writes the token file before requesting elevation; refuse to
    // serve without it rather than running open.
    if read_token(&args.token_file).is_none() {
        eprintln!(
            "shadowvpn-desktop-helper: token file {} missing or empty",
            args.token_file.display()
        );
        std::process::exit(2);
    }

    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("shadowvpn-desktop-helper: cannot bind 127.0.0.1: {e}");
            std::process::exit(2);
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            eprintln!("shadowvpn-desktop-helper: cannot read bound port: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = std::fs::write(&args.port_file, format!("{port}\n")) {
        eprintln!(
            "shadowvpn-desktop-helper: cannot write port file {}: {e}",
            args.port_file.display()
        );
        std::process::exit(2);
    }

    let slot: ChildSlot = Arc::new(Mutex::new(None));

    // Janitor: exit once the token file has been gone for ~30s with no client
    // running (the GUI closed and cleaned up, or the user revoked us). With a
    // client still up we stay, so a later session can stop it promptly.
    // Daemon mode: the token file is our own (root-owned, never GUI-removed)
    // and launchd owns the lifecycle — no janitor.
    if !args.daemon {
        let slot = Arc::clone(&slot);
        let token_file = args.token_file.clone();
        let port_file = args.port_file.clone();
        std::thread::spawn(move || {
            let mut missing_ticks = 0u32;
            loop {
                std::thread::sleep(Duration::from_secs(5));
                if token_file.exists() {
                    missing_ticks = 0;
                    continue;
                }
                missing_ticks += 1;
                let idle = slot
                    .lock()
                    .map(|mut g| {
                        reap(&mut g);
                        g.is_none()
                    })
                    .unwrap_or(false);
                if missing_ticks >= 6 && idle {
                    let _ = std::fs::remove_file(&port_file);
                    std::process::exit(0);
                }
            }
        });
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if handle_conn(stream, &args, &slot) {
            break; // shutdown requested (response already sent)
        }
    }
}
