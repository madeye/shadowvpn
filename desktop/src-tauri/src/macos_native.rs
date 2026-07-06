//! Safe Rust wrappers over `macos/native_auth.m` (linked by build.rs):
//! SMAppService LaunchDaemon registration and the LAContext user-presence
//! gate (Touch ID / Apple Watch, login-password fallback).

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn svpn_daemon_status(plist_name: *const c_char) -> c_int;
    fn svpn_daemon_register(plist_name: *const c_char, err: *mut c_char, errlen: usize) -> c_int;
    fn svpn_daemon_unregister(plist_name: *const c_char, err: *mut c_char, errlen: usize) -> c_int;
    fn svpn_open_login_items();
    fn svpn_authenticate_user(reason: *const c_char, err: *mut c_char, errlen: usize) -> c_int;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStatus {
    /// SMAppService not available (macOS < 13).
    Unavailable,
    NotRegistered,
    Enabled,
    /// Registered, pending user approval in System Settings > Login Items.
    RequiresApproval,
    /// The plist is not in the app bundle (dev build / not bundled).
    NotFound,
}

impl DaemonStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DaemonStatus::Unavailable => "unavailable",
            DaemonStatus::NotRegistered => "not_registered",
            DaemonStatus::Enabled => "enabled",
            DaemonStatus::RequiresApproval => "requires_approval",
            DaemonStatus::NotFound => "not_found",
        }
    }
}

fn plist_cstr() -> CString {
    // Safe: the constant contains no NUL bytes.
    CString::new(crate::helper_ipc::DAEMON_PLIST_NAME).unwrap()
}

fn err_string(buf: &[u8], fallback: &str) -> String {
    // No NUL found means the C side filled the whole buffer without
    // terminating — take it all rather than discarding the message.
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let msg = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if msg.is_empty() {
        fallback.to_string()
    } else {
        msg
    }
}

pub fn daemon_status() -> DaemonStatus {
    let plist = plist_cstr();
    match unsafe { svpn_daemon_status(plist.as_ptr()) } {
        0 => DaemonStatus::NotRegistered,
        1 => DaemonStatus::Enabled,
        2 => DaemonStatus::RequiresApproval,
        3 => DaemonStatus::NotFound,
        _ => DaemonStatus::Unavailable,
    }
}

pub fn daemon_register() -> Result<(), String> {
    let plist = plist_cstr();
    let mut err = [0u8; 512];
    let ret =
        unsafe { svpn_daemon_register(plist.as_ptr(), err.as_mut_ptr() as *mut c_char, err.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(err_string(&err, "daemon registration failed"))
    }
}

pub fn daemon_unregister() -> Result<(), String> {
    let plist = plist_cstr();
    let mut err = [0u8; 512];
    let ret = unsafe {
        svpn_daemon_unregister(plist.as_ptr(), err.as_mut_ptr() as *mut c_char, err.len())
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(err_string(&err, "daemon unregistration failed"))
    }
}

pub fn open_login_items() {
    unsafe { svpn_open_login_items() }
}

/// Prove user presence before using the always-root daemon: Touch ID / Apple
/// Watch, falling back to the login password. Policy-unavailable (no
/// password set, headless) is treated as pass — the daemon approval itself
/// was the admin consent; this gate is defense in depth, not the authority.
pub fn authenticate_user(reason: &str) -> Result<(), String> {
    let reason = CString::new(reason).map_err(|_| "invalid authentication reason")?;
    let mut err = [0u8; 512];
    let ret = unsafe {
        svpn_authenticate_user(reason.as_ptr(), err.as_mut_ptr() as *mut c_char, err.len())
    };
    match ret {
        1 | -1 => Ok(()),
        _ => Err(format!(
            "authentication cancelled: {}",
            err_string(&err, "user denied")
        )),
    }
}
