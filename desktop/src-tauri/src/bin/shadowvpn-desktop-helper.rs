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
//!   is re-read per request so a new GUI session can re-key a running helper;
//!   a world-readable or non-regular replacement is rejected.
//! - Connect `log` / `pid_file` writes are allowlisted (fixed basenames under
//!   a `runs/` directory — the session token dir, or a user-home app-data
//!   path in daemon mode) and opened `O_NOFOLLOW`, so a request cannot point
//!   root at an arbitrary file.
//! - It listens on 127.0.0.1 only. Requests are capped before the token check.
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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use helper_ipc::{Cmd, Request, Response};

/// Last path component of the app's data/config directory. Connect writes
/// must live under a directory of this name so a request cannot aim the root
/// helper at `/tmp/.../runs/shadowvpn.log`.
const APP_ID: &str = "io.github.madeye.shadowvpn.desktop";

/// Hard cap on one RPC line. Paths + a 64-hex token do not need more, and
/// the listen socket is reachable by every local uid.
const MAX_REQUEST_BYTES: u64 = 8 * 1024;

struct Args {
    token_file: PathBuf,
    port_file: PathBuf,
    client_bin: String,
    /// launchd daemon mode (macOS): launchd owns the lifecycle — never exit
    /// on `shutdown`, never remove the port file, no token-file janitor.
    daemon: bool,
    /// Session helper: Connect log/pid writes must stay inside this directory
    /// (the token file's parent, i.e. the GUI `runs/` dir). `None` in daemon
    /// mode, which uses a user-home + app-id + `runs/` rule instead.
    write_dir: Option<PathBuf>,
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
    let token_file = token_file.ok_or("--token-file is required")?;
    let write_dir = token_file.parent().map(|p| p.to_path_buf());
    Ok(Args {
        token_file,
        port_file: port_file.ok_or("--port-file is required")?,
        client_bin: client_bin.ok_or("--client-bin is required")?,
        daemon: false,
        write_dir,
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
        write_dir: None,
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
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW: a symlink swap after elevation must not redirect us at
        // a FIFO (which would block the accept thread) or another uid's file.
        // O_NONBLOCK: a FIFO that slipped through still cannot hang us.
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut f = opts.open(path).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // World-readable/writable or group-writable: leaked or hijackable.
        // Group-readable is intentional for the macOS daemon (root:admin 0640).
        if meta.permissions().mode() & 0o047 != 0 {
            return None;
        }
    }
    let mut tok = String::new();
    f.read_to_string(&mut tok).ok()?;
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
    write_dir: Option<&Path>,
) -> Result<Child, String> {
    let log = resolve_write_path(log, WriteKind::Log, write_dir)?;
    let pid_file = resolve_write_path(pid_file, WriteKind::Pid, write_dir)?;
    // O_NOFOLLOW (Unix): even an allowlisted path can be swapped for a
    // symlink between the check and the open.
    let mut log_opts = std::fs::OpenOptions::new();
    log_opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        log_opts.custom_flags(libc::O_NOFOLLOW);
    }
    let log_out = log_opts
        .open(&log)
        .map_err(|e| format!("cannot open log file {}: {e}", log.display()))?;
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
    if let Err(e) = write_nofollow(&pid_file, format!("{}\n", child.id()).as_bytes()) {
        // Without the pidfile the GUI can neither show nor stop this run;
        // don't leave an orphaned root client behind.
        let _ = child.kill();
        let _ = wait_with_timeout(&mut child, Duration::from_secs(2));
        return Err(format!("cannot write pid file {}: {e}", pid_file.display()));
    }
    Ok(child)
}

/// `fs::write` that refuses to follow a symlink at `path` (see the note in
/// `spawn_client`; no-op difference on Windows, where the per-user ACLs
/// already protect these paths). Every path this elevated process writes
/// that lives in a GUI-user-controlled directory MUST go through here.
fn write_nofollow(path: &Path, data: &[u8]) -> std::io::Result<()> {
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

#[derive(Clone, Copy)]
enum WriteKind {
    Log,
    Pid,
}

impl WriteKind {
    fn allows(self, name: &str) -> bool {
        match self {
            WriteKind::Log => name == "shadowvpn.log" || name == "shadowvpn.log.out",
            WriteKind::Pid => name == "shadowvpn.pid",
        }
    }
}

/// Refuse Connect paths that would let this root process create/truncate an
/// arbitrary file. Session helpers pin writes to the token file's directory;
/// the daemon (no GUI-supplied dir) requires a user-home prefix, the app-id
/// component, a `runs/` parent, and a fixed basename.
fn resolve_write_path(
    requested: &str,
    kind: WriteKind,
    allow_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let path = Path::new(requested);
    if !path.is_absolute() {
        return Err(format!("{requested}: write path must be absolute"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("{requested}: write path must not contain '..'"));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{requested}: write path has no file name"))?;
    if !kind.allows(name) {
        return Err(format!(
            "{requested}: writes are restricted to shadowvpn.log / shadowvpn.pid"
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{requested}: write path has no parent"))?;
    if parent.file_name().and_then(|n| n.to_str()) != Some("runs") {
        return Err(format!(
            "{requested}: writes are restricted to a runs/ directory"
        ));
    }
    let parent_canon = parent.canonicalize().map_err(|e| {
        format!(
            "{}: runs directory is missing or unreachable ({e})",
            parent.display()
        )
    })?;
    if let Some(dir) = allow_dir {
        let dir_canon = dir.canonicalize().map_err(|e| {
            format!(
                "{}: session runs directory is missing or unreachable ({e})",
                dir.display()
            )
        })?;
        if parent_canon != dir_canon {
            return Err(format!(
                "{requested}: write path is outside the session runs directory"
            ));
        }
    } else {
        if !parent_canon.components().any(|c| c.as_os_str() == APP_ID) {
            return Err(format!(
                "{requested}: write path is not under the ShadowVPN app directory"
            ));
        }
        if !has_user_home_prefix(&parent_canon) {
            return Err(format!(
                "{requested}: write path is not under a user home directory"
            ));
        }
    }
    Ok(parent_canon.join(name))
}

fn has_user_home_prefix(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        path.starts_with("/Users/")
    }
    #[cfg(target_os = "linux")]
    {
        path.starts_with("/home/") || path.starts_with("/root/")
    }
    #[cfg(windows)]
    {
        path.components()
            .any(|c| c.as_os_str().eq_ignore_ascii_case("Users"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        false
    }
}

/// Poll `try_wait` until the child exits or `timeout` elapses.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<bool, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(true),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("wait for client exit failed: {e}")),
        }
    }
}

/// `Command::output()` with a deadline: this helper serves all requests on a
/// single thread, so a child that never exits (a wedged `networksetup`, DNS
/// I/O stuck in the kernel) must be killed rather than allowed to block every
/// later request — including Disconnect and Shutdown — forever. Pipes are
/// drained only after exit; a child producing more output than the pipe
/// buffer stalls until the deadline kills it, which is fine for the tiny
/// output these subcommands emit.
fn output_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start: {e}"))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("failed to collect output: {e}"));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "did not exit within {}s and was killed",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wait failed: {e}"));
            }
        }
    }
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
        if ret == 0 && wait_with_timeout(child, Duration::from_secs(10))? {
            return Ok(());
        }
        // Never delivered, ignored, or hung mid-cleanup: force it.
        let _ = child.kill();
    }
    #[cfg(windows)]
    {
        let _ = child.kill();
    }
    if wait_with_timeout(child, Duration::from_secs(10))? {
        Ok(())
    } else {
        // D-state I/O (the case `wait_for_exit` already worries about on the
        // GUI side) would block `Child::wait` forever and wedge this
        // single-threaded helper with the IPC mutex held.
        Err("client did not exit after SIGKILL".to_string())
    }
}

fn handle_conn(stream: TcpStream, args: &Args, slot: &ChildSlot) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return false,
    };
    let mut reader = BufReader::new(stream.take(MAX_REQUEST_BYTES + 1));
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return false,
        Ok(_) if line.len() as u64 > MAX_REQUEST_BYTES || !line.ends_with('\n') => return false,
        Ok(_) => {}
        Err(_) => return false,
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
            match spawn_client(
                &args.client_bin,
                &profile,
                &log,
                &pid_file,
                args.write_dir.as_deref(),
            ) {
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
                Err(e) => {
                    // Rust does not kill on drop. Put the child back so the
                    // next Connect cannot start a second root client while
                    // this one is still alive.
                    *guard = Some(child);
                    (Response::err(e), false)
                }
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
        Cmd::RestoreDns => {
            if guard.is_some() {
                return (
                    Response::err("client is running; it owns the resolver configuration"),
                    false,
                );
            }
            // Same posture as Connect: only ever the one fixed client binary,
            // with a fixed argument — requests cannot influence what runs.
            let mut cmd = Command::new(&args.client_bin);
            cmd.arg("--restore-dns");
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            // Deadline-bound: a hung restore must not wedge this
            // single-threaded helper for every later request.
            match output_with_timeout(&mut cmd, Duration::from_secs(10)) {
                Ok(out) if out.status.success() => (
                    Response {
                        ok: true,
                        ..Default::default()
                    },
                    false,
                ),
                Ok(out) => (
                    Response::err(format!(
                        "restore-dns failed ({}): {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    )),
                    false,
                ),
                Err(e) => (
                    Response::err(format!("restore-dns via {}: {e}", args.client_bin)),
                    false,
                ),
            }
        }
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
    // O_NOFOLLOW like every other GUI-controlled path this root process
    // writes: a symlink planted at the port-file path must not let an
    // unprivileged user truncate an arbitrary root-owned file.
    if let Err(e) = write_nofollow(&args.port_file, format!("{port}\n").as_bytes()) {
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

#[cfg(test)]
mod write_path_tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn uniq_dir() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "svpn-helper-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejects_relative_and_dotdot() {
        let err = resolve_write_path("runs/shadowvpn.log", WriteKind::Log, None).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        let err = resolve_write_path("/tmp/runs/../runs/shadowvpn.log", WriteKind::Log, None)
            .unwrap_err();
        assert!(err.contains(".."), "{err}");
    }

    #[test]
    fn rejects_wrong_basename_or_parent() {
        let root = uniq_dir();
        let runs = root.join("runs");
        fs::create_dir_all(&runs).unwrap();
        let err = resolve_write_path(
            &runs.join("evil.log").to_string_lossy(),
            WriteKind::Log,
            Some(&runs),
        )
        .unwrap_err();
        assert!(err.contains("restricted"), "{err}");
        let other = root.join("other");
        fs::create_dir_all(&other).unwrap();
        let err = resolve_write_path(
            &other.join("shadowvpn.log").to_string_lossy(),
            WriteKind::Log,
            Some(&runs),
        )
        .unwrap_err();
        assert!(err.contains("runs/"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn session_allows_only_token_dir() {
        let root = uniq_dir();
        let runs = root.join("runs");
        let other = root.join("other").join("runs");
        fs::create_dir_all(&runs).unwrap();
        fs::create_dir_all(&other).unwrap();
        let ok = resolve_write_path(
            &runs.join("shadowvpn.pid").to_string_lossy(),
            WriteKind::Pid,
            Some(&runs),
        )
        .unwrap();
        assert_eq!(ok.file_name().unwrap(), "shadowvpn.pid");
        let err = resolve_write_path(
            &other.join("shadowvpn.pid").to_string_lossy(),
            WriteKind::Pid,
            Some(&runs),
        )
        .unwrap_err();
        assert!(err.contains("outside"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn daemon_rejects_tmp_even_with_app_id() {
        let root = uniq_dir();
        let runs = root.join(APP_ID).join("runs");
        fs::create_dir_all(&runs).unwrap();
        let err = resolve_write_path(
            &runs.join("shadowvpn.log").to_string_lossy(),
            WriteKind::Log,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("home") || err.contains("ShadowVPN app"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
