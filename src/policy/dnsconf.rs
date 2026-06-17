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
//! * **Windows** — `netsh interface ipv4 set dnsservers <primary-iface> static
//!   <proxy-ip>`, remembering whether the interface used DHCP or a static list
//!   and restoring it.
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
/// `direct_src` is the host's physical source address (the local IP of the
/// socket connected to the server); on Windows it identifies the interface whose
/// DNS to reconfigure. Ignored on other platforms.
///
/// Returns `Ok(None)` (with a warning) if the port is not 53, since the OS
/// resolver cannot target a custom port. On success the returned guard restores
/// the prior configuration on drop.
pub fn apply(proxy: IpAddr, port: u16, direct_src: IpAddr) -> Result<Option<DnsGuard>> {
    if port != 53 {
        warn!(
            "not setting the system resolver automatically: proxy port is {port}, but the OS \
             resolver only supports port 53 — point DNS at {proxy} (port 53) yourself, or set \
             dns_listen to a :53 address"
        );
        return Ok(None);
    }
    let restore = imp::apply(proxy, direct_src)?;
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

    pub fn apply(proxy: IpAddr, direct_src: IpAddr) -> Result<Restore> {
        let _ = direct_src; // macOS finds the primary service via the route table
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

    pub fn apply(proxy: IpAddr, direct_src: IpAddr) -> Result<Restore> {
        let _ = direct_src; // Linux rewrites the global /etc/resolv.conf
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
// Windows: point the primary interface's resolver at the proxy via `netsh`.
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::io;
    use std::process::Command;

    /// What to put back when we exit: either the interface used DHCP-assigned
    /// DNS, or it had this explicit list of static servers.
    pub enum Restore {
        Dhcp { alias: String },
        Static { alias: String, servers: Vec<String> },
    }

    pub fn apply(proxy: IpAddr, direct_src: IpAddr) -> Result<Restore> {
        let alias = primary_alias(direct_src)
            .context("could not determine the primary network interface to configure DNS on")?;
        let restore = read_current(&alias);
        set_static(&alias, &[proxy.to_string()])?;
        flush();
        Ok(restore)
    }

    pub fn restore(r: &Restore) {
        match r {
            Restore::Dhcp { alias } => {
                let _ = netsh(&[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    &name_arg(alias),
                    "dhcp",
                ]);
            }
            Restore::Static { alias, servers } => {
                let _ = set_static(alias, servers);
            }
        }
        flush();
    }

    /// The alias of the interface to reconfigure DNS on.
    ///
    /// Preferred: the interface that owns `direct_src` (the physical source
    /// address used to reach the server) — deterministic and unaffected by the
    /// route-table churn that accompanies the tun coming up. Falls back to the
    /// interface carrying the default route if `direct_src` can't be matched.
    fn primary_alias(direct_src: IpAddr) -> Option<String> {
        if !direct_src.is_unspecified() {
            if let Some(alias) = interface_for_ip(direct_src) {
                return Some(alias);
            }
        }
        default_route_alias()
    }

    /// Find the interface whose configured address is `ip` by scanning
    /// `netsh interface ipv4 show addresses` (no PowerShell dependency). Output:
    ///   Configuration for interface "Ethernet"
    ///       IP Address:                           192.168.0.109
    fn interface_for_ip(ip: IpAddr) -> Option<String> {
        let out = netsh(&["interface", "ipv4", "show", "addresses"]).ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let want = ip.to_string();
        let mut current: Option<String> = None;
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("Configuration for interface ") {
                current = Some(rest.trim().trim_matches('"').to_string());
            } else if t.split_whitespace().any(|tok| tok == want) {
                if let Some(name) = current.as_ref() {
                    return Some(name.clone());
                }
            }
        }
        None
    }

    /// The alias of the interface carrying the (lowest-metric) default route.
    fn default_route_alias() -> Option<String> {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
                 Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias",
            ])
            .output()
            .ok()?;
        let alias = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if alias.is_empty() {
            None
        } else {
            Some(alias)
        }
    }

    /// Inspect an interface's current IPv4 DNS configuration so it can be
    /// restored later: DHCP, or a static list of servers.
    fn read_current(alias: &str) -> Restore {
        let out = netsh(&["interface", "ipv4", "show", "dnsservers", &name_arg(alias)]);
        let text = out
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();

        // netsh prints "DNS servers configured through DHCP" for DHCP, or
        // "Statically Configured DNS Servers". The first server shares the label
        // line and the rest are indented one per line, so scan every whitespace
        // token for IPs rather than parsing whole lines.
        if text.contains("through DHCP") {
            return Restore::Dhcp {
                alias: alias.to_string(),
            };
        }
        let servers: Vec<String> = text
            .split_whitespace()
            .filter_map(|tok| tok.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
            .collect();
        if servers.is_empty() {
            // No static servers and not flagged DHCP: safest is to clear to DHCP.
            Restore::Dhcp {
                alias: alias.to_string(),
            }
        } else {
            Restore::Static {
                alias: alias.to_string(),
                servers,
            }
        }
    }

    /// Replace an interface's IPv4 DNS servers with `servers` (first = primary).
    fn set_static(alias: &str, servers: &[String]) -> Result<()> {
        let (first, rest) = servers
            .split_first()
            .context("refusing to set an empty DNS server list")?;
        run_checked(&[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &name_arg(alias),
            "static",
            first,
            "primary",
            "validate=no",
        ])?;
        for (i, srv) in rest.iter().enumerate() {
            run_checked(&[
                "interface",
                "ipv4",
                "add",
                "dnsservers",
                &name_arg(alias),
                srv,
                &format!("index={}", i + 2),
                "validate=no",
            ])?;
        }
        Ok(())
    }

    /// `name="<alias>"` argument for netsh (quoting handled by the OS, not a shell).
    fn name_arg(alias: &str) -> String {
        format!("name={alias}")
    }

    fn netsh(args: &[&str]) -> io::Result<std::process::Output> {
        Command::new("netsh").args(args).output()
    }

    fn run_checked(args: &[&str]) -> Result<()> {
        let out = netsh(args).context("running netsh")?;
        if !out.status.success() {
            bail!(
                "netsh {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn flush() {
        let _ = Command::new("ipconfig").arg("/flushdns").status();
    }
}

// ---------------------------------------------------------------------------
// Other platforms: unsupported.
// ---------------------------------------------------------------------------
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios", windows)))]
mod imp {
    use super::*;

    pub struct Restore;

    pub fn apply(_proxy: IpAddr, _direct_src: IpAddr) -> Result<Restore> {
        anyhow::bail!("automatic DNS configuration is not supported on this platform")
    }

    pub fn restore(_r: &Restore) {}
}
