//! Private state-file helpers for the client identity file and server leases.
//!
//! Writes use mode `0600` (and parent directories `0700`) so a copied or
//! world-readable state file cannot leak a `node_id`. Atomic replace is used
//! for the lease table so a crash cannot leave a half-written JSON file.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Write `data` to `path` with mode `0600` on Unix (tighten pre-existing files).
/// Create parent directories with mode `0700`.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    create_parent_private(path)?;
    write_private_to(path, data, false)
}

/// Atomic replace: write `path` + `.tmp`, fsync, then rename over `path`.
///
/// On Windows, `remove_file(path)` first if it exists (`rename` cannot replace).
pub fn write_private_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    create_parent_private(path)?;
    let tmp = tmp_sidecar(path, ".tmp");
    write_private_to(&tmp, data, true)?;
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Default client state path.
///
/// * If `config_path` is `Some`, `<config_path>.state` (e.g. `client.json.state`).
/// * Else on macOS: `~/Library/Application Support/shadowvpn/<sha256(server)>.json`.
/// * Else `$XDG_STATE_HOME/shadowvpn/<sha256(server)>.json`, falling back to
///   `$HOME/.local/state/shadowvpn/…`.
///
/// `server` is the exact `ClientConfig.server` text. The hash is SHA-256 (not
/// `DefaultHasher`) so the path is stable across processes.
pub fn default_client_state_path(config_path: Option<&Path>, server: &str) -> PathBuf {
    if let Some(cfg) = config_path {
        let mut s = cfg.as_os_str().to_os_string();
        s.push(".state");
        return PathBuf::from(s);
    }
    let filename = format!("{}.json", hex_sha256(server.as_bytes()));
    state_dir().join(filename)
}

fn state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Application Support/shadowvpn")
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(xdg).join("shadowvpn");
        }
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/state/shadowvpn")
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn hex_sha256(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn tmp_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn create_parent_private(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => create_dir_private(dir),
        _ => Ok(()),
    }
}

fn create_dir_private(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_dir_private(parent)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

fn write_private_to(path: &Path, data: &[u8], sync: bool) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode(0o600)` only applies on create; tighten a pre-existing 0644 file.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    if sync {
        file.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn temp_path(tag: &str) -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "shadowvpn-state-{}-{}-{n}",
            tag,
            std::process::id()
        ))
    }

    struct TempPath(PathBuf);
    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(tmp_sidecar(&self.0, ".tmp"));
            if let Some(dir) = self.0.parent() {
                if dir.ends_with("shadowvpn-state-nest") {
                    let _ = std::fs::remove_dir_all(dir);
                }
            }
        }
    }

    #[test]
    fn config_path_appends_state_suffix() {
        let p = default_client_state_path(Some(Path::new("/etc/client.json")), "ignored:1");
        assert_eq!(p, PathBuf::from("/etc/client.json.state"));
    }

    #[test]
    fn no_config_path_uses_sha256_not_default_hasher() {
        let server = "vpn.example.com:8388";
        let p = default_client_state_path(None, server);
        let expected = format!("{}.json", hex_sha256(server.as_bytes()));
        assert_eq!(p.file_name().unwrap(), expected.as_str());
        assert!(p.to_string_lossy().contains("shadowvpn"));
        // Distinct server strings must not collide even if they name one host.
        let q = default_client_state_path(None, "203.0.113.8:8388");
        assert_ne!(p, q);
    }

    #[test]
    fn write_private_round_trip() {
        let path = TempPath(temp_path("wp.json"));
        write_private(&path.0, b"hello").unwrap();
        assert_eq!(std::fs::read(&path.0).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path.0).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn write_private_atomic_replaces() {
        let path = TempPath(temp_path("atom.json"));
        write_private_atomic(&path.0, b"one").unwrap();
        write_private_atomic(&path.0, b"two").unwrap();
        assert_eq!(std::fs::read(&path.0).unwrap(), b"two");
        assert!(!tmp_sidecar(&path.0, ".tmp").exists());
    }

    #[test]
    fn write_private_creates_parent_dirs() {
        let dir = std::env::temp_dir().join(format!(
            "shadowvpn-state-nest/{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let path = TempPath(dir.join("file.json"));
        write_private(&path.0, b"x").unwrap();
        assert_eq!(std::fs::read(&path.0).unwrap(), b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path.0.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }
}
