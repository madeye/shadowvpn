//! Point the system resolver at the split-DNS proxy — and put it back on exit.
//!
//! For policy routing to take effect, name lookups must go through the proxy
//! (that is what installs the per-destination routes). [`apply`] configures the
//! OS resolver to do that and returns a [`DnsGuard`] that restores the previous
//! configuration when dropped:
//!
//! * **macOS** — `networksetup -setdnsservers <primary-service> <proxy-ip>`,
//!   remembering and restoring the service's previous servers.
//! * **Linux** — rewrite `/etc/resolv.conf` to `nameserver <proxy-ip>`,
//!   remembering the previous file (or symlink) and restoring it.
//!
//! The OS resolver can only point at an address, not a port, so this is only
//! applied when the proxy listens on port 53; otherwise it is skipped with a
//! warning and the operator must configure DNS themselves.

use std::net::IpAddr;

use anyhow::Result;
use log::{info, warn};

/// Restores the previous system DNS configuration when dropped.
pub struct DnsGuard {
    restore: imp::Restore,
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        imp::restore(&self.restore);
        info!("system resolver restored");
    }
}

/// Point the system resolver at `proxy` (the proxy's listen address).
///
/// Returns `Ok(None)` (with a warning) if the port is not 53, since the OS
/// resolver cannot target a custom port. On success the returned guard restores
/// the prior configuration on drop.
pub fn apply(proxy: IpAddr, port: u16) -> Result<Option<DnsGuard>> {
    if port != 53 {
        warn!(
            "not setting the system resolver automatically: proxy port is {port}, but the OS \
             resolver only supports port 53 — point DNS at {proxy} (port 53) yourself, or set \
             dns_listen to a :53 address"
        );
        return Ok(None);
    }
    let restore = imp::apply(proxy)?;
    info!("system resolver pointed at {proxy} (restored automatically on exit)");
    Ok(Some(DnsGuard { restore }))
}

// ---------------------------------------------------------------------------
// macOS / BSD: networksetup on the primary network service.
// ---------------------------------------------------------------------------
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::process::Command;

    /// What to put back: the service and its previous DNS servers (empty = none).
    pub struct Restore {
        service: String,
        prev: Vec<String>,
    }

    pub fn apply(proxy: IpAddr) -> Result<Restore> {
        let service = primary_service()
            .context("could not determine the primary network service to configure DNS on")?;
        let prev = get_dns(&service);
        set_dns(&service, &[proxy.to_string()])?;
        flush();
        Ok(Restore { service, prev })
    }

    pub fn restore(r: &Restore) {
        // `empty` clears all DNS servers for the service.
        let servers: Vec<String> = if r.prev.is_empty() {
            vec!["empty".to_string()]
        } else {
            r.prev.clone()
        };
        let _ = set_dns(&r.service, &servers);
        flush();
    }

    fn set_dns(service: &str, servers: &[String]) -> Result<()> {
        let mut cmd = Command::new("networksetup");
        cmd.arg("-setdnsservers").arg(service).args(servers);
        let out = cmd
            .output()
            .context("running networksetup -setdnsservers")?;
        if !out.status.success() {
            bail!(
                "networksetup -setdnsservers {service} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Current DNS servers for a service, or empty if none are set.
    fn get_dns(service: &str) -> Vec<String> {
        let out = match Command::new("networksetup")
            .arg("-getdnsservers")
            .arg(service)
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        // "There aren't any DNS Servers set on <service>." means none.
        if text.contains("aren't any") {
            return Vec::new();
        }
        text.lines()
            .map(str::trim)
            .filter(|l| l.parse::<IpAddr>().is_ok())
            .map(String::from)
            .collect()
    }

    /// Map the default-route interface to its network service name.
    fn primary_service() -> Option<String> {
        let iface = default_iface()?;
        let out = Command::new("networksetup")
            .arg("-listnetworkserviceorder")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Blocks look like:
        //   (1) Ethernet
        //   (Hardware Port: Ethernet, Device: en0)
        let mut current: Option<String> = None;
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix('(') {
                if let Some((num, name)) = rest.split_once(')') {
                    if num.chars().all(|c| c.is_ascii_digit()) {
                        current = Some(name.trim().to_string());
                        continue;
                    }
                }
            }
            if t.contains(&format!("Device: {iface})")) {
                return current.take();
            }
        }
        None
    }

    /// Interface carrying the default route, e.g. `en0`.
    fn default_iface() -> Option<String> {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
            l.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_string())
        })
    }

    fn flush() {
        let _ = Command::new("dscacheutil").arg("-flushcache").status();
        let _ = Command::new("killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
    }
}

// ---------------------------------------------------------------------------
// Linux: rewrite /etc/resolv.conf, remembering the previous file/symlink.
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use anyhow::Context;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    const PATH: &str = "/etc/resolv.conf";

    /// What `/etc/resolv.conf` was before we changed it.
    pub enum Restore {
        /// It was a symlink to this target.
        Symlink(PathBuf),
        /// It was a regular file with these bytes.
        File(Vec<u8>),
        /// It did not exist.
        Absent,
    }

    pub fn apply(proxy: IpAddr) -> Result<Restore> {
        let restore = match fs::symlink_metadata(PATH) {
            Ok(m) if m.file_type().is_symlink() => {
                let target = fs::read_link(PATH).context("reading resolv.conf symlink")?;
                // Replace the symlink with a regular file so a resolver daemon
                // (systemd-resolved) doesn't keep overwriting the target.
                fs::remove_file(PATH).context("removing resolv.conf symlink")?;
                Restore::Symlink(target)
            }
            Ok(_) => Restore::File(fs::read(PATH).unwrap_or_default()),
            Err(_) => Restore::Absent,
        };
        fs::write(PATH, format!("# shadowvpn split-DNS\nnameserver {proxy}\n"))
            .context("writing /etc/resolv.conf")?;
        Ok(restore)
    }

    pub fn restore(r: &Restore) {
        match r {
            Restore::Symlink(target) => {
                let _ = fs::remove_file(PATH);
                let _ = symlink(target, PATH);
            }
            Restore::File(content) => {
                let _ = fs::write(PATH, content);
            }
            Restore::Absent => {
                let _ = fs::remove_file(PATH);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Other platforms: unsupported.
// ---------------------------------------------------------------------------
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
mod imp {
    use super::*;

    pub struct Restore;

    pub fn apply(_proxy: IpAddr) -> Result<Restore> {
        anyhow::bail!("automatic DNS configuration is not supported on this platform")
    }

    pub fn restore(_r: &Restore) {}
}
