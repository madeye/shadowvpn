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
    })
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
    let log_out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
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
    if let Err(e) = std::fs::write(pid_file, format!("{}\n", child.id())) {
        // Without the pidfile the GUI can neither show nor stop this run;
        // don't leave an orphaned root client behind.
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot write pid file {pid_file}: {e}"));
    }
    Ok(child)
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
            let _ = std::fs::remove_file(&args.port_file);
            (
                Response {
                    ok: true,
                    ..Default::default()
                },
                true,
            )
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("shadowvpn-desktop-helper: {e}");
            std::process::exit(2);
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
    {
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
