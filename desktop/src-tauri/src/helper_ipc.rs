//! Wire protocol between the GUI and the elevated helper process.
//!
//! Transport: newline-delimited JSON, one request per TCP connection to
//! `127.0.0.1:<port>`. The port is published by the helper in a port file;
//! every request carries the shared-secret token from the 0600 token file
//! (the helper re-reads that file on each request, so a new GUI session can
//! re-key a still-running helper just by rewriting the file).
//!
//! This module is compiled into both the GUI (`mod helper_ipc`) and the
//! helper binary (`#[path] mod`), so the two sides can never drift. Each
//! side only calls part of it (the GUI sends, the helper builds responses),
//! hence the file-level dead_code allow.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Cmd {
    /// Liveness + identity probe.
    Ping,
    /// Start the client with `-c <profile>`, appending output to `log` and
    /// writing the child PID to `pid_file` before responding.
    Connect {
        profile: String,
        log: String,
        pid_file: String,
    },
    /// Stop the helper's client child (graceful where the OS allows it).
    Disconnect,
    /// Stop the client child if any, remove the port file, and exit.
    Shutdown,
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub token: String,
    #[serde(flatten)]
    pub cmd: Cmd,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    /// Echoed by `ping`: the client binary this helper was spawned for (a
    /// helper never executes any other program).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_bin: Option<String>,
}

impl Response {
    pub fn err(msg: impl Into<String>) -> Self {
        Response {
            ok: false,
            error: Some(msg.into()),
            ..Default::default()
        }
    }
}

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Generous enough to cover a graceful-stop wait inside the helper (10s).
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// One request/response round-trip on a fresh connection.
pub fn call(port: u16, req: &Request) -> Result<Response, String> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("cannot reach helper on 127.0.0.1:{port}: {e}"))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("helper write failed: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| format!("helper read failed: {e}"))?;
    serde_json::from_str(&resp_line).map_err(|e| format!("bad helper response: {e}"))
}
