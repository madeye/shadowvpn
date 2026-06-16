//! Lightweight policy routing for the ShadowVPN **client**.
//!
//! Instead of pushing *all* traffic through the tunnel, policy routing sends
//! only selected destinations through it and leaves the rest on the direct path.
//! A small split-DNS [`proxy`] decides, per query, whether a name should be
//! tunneled and hands the resolved addresses to a user-mode [`route`]r, which
//! programs a host route for each one into the tun device using the OS's native
//! routing socket (rtnetlink on Linux, `PF_ROUTE` on macOS). There is no
//! dependency on `ipset`, `iptables`/nft, or `fwmark`, so it runs on **Linux and
//! macOS** alike; direct traffic stays on the normal kernel path.
//!
//! Two modes are offered (see [`Mode`]):
//!
//! * **gfwlist** — tunnel names listed in a [`gfwlist`] file; everything else
//!   resolves and routes directly.
//! * **chinadns** — query a domestic and a clean resolver in parallel and tunnel
//!   anything that does not resolve to an in-China address ([`chnroute`], which
//!   can also be built from a GeoIP database via [`geoip`]).
//!
//! [`Mode::Full`] disables all of this (the historical behavior: the whole TUN
//! is the tunnel and routing is the operator's job).

pub mod chnroute;
pub mod dns;
pub mod geoip;
pub mod gfwlist;
pub mod proxy;
pub mod route;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub use proxy::{chinadns_decision, Decision, IpSink, Resolver};

/// Which policy-routing strategy the client should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No policy routing: the entire TUN is the tunnel (routing is manual).
    Full,
    /// Tunnel only the domains listed in the gfwlist file.
    GfwList,
    /// Tunnel anything that does not resolve to an in-China address.
    ChinaDns,
}

impl Mode {
    /// Parse a mode name. Accepts `full`/`off`/`none`, `gfwlist`, and
    /// `chinadns`/`china` (case-insensitive).
    pub fn from_name(name: &str) -> Result<Self, PolicyError> {
        match name.to_ascii_lowercase().as_str() {
            "full" | "off" | "none" => Ok(Mode::Full),
            "gfwlist" => Ok(Mode::GfwList),
            "chinadns" | "china" => Ok(Mode::ChinaDns),
            other => Err(PolicyError::UnknownMode(other.to_string())),
        }
    }

    /// The canonical name of this mode.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Full => "full",
            Mode::GfwList => "gfwlist",
            Mode::ChinaDns => "chinadns",
        }
    }

    /// Whether this mode runs the DNS proxy + policy routing (i.e. not `full`).
    pub fn is_enabled(self) -> bool {
        !matches!(self, Mode::Full)
    }
}

/// Errors specific to policy-routing configuration.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The mode name was not recognized.
    #[error("unknown policy mode: {0} (expected full|gfwlist|chinadns)")]
    UnknownMode(String),
}

/// Fully resolved policy-routing configuration for the client.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Active mode.
    pub mode: Mode,
    /// Address the split-DNS proxy listens on (point the resolver here).
    pub dns_listen: SocketAddr,
    /// Domestic / direct DNS upstream.
    pub dns_local: SocketAddr,
    /// Clean DNS upstream, reached through the tunnel.
    pub dns_remote: SocketAddr,
    /// gfwlist domain file (required in gfwlist mode).
    pub gfwlist: Option<PathBuf>,
    /// China route (CIDR) file (one source for chinadns mode).
    pub chnroute: Option<PathBuf>,
    /// GeoLite2/GeoIP2 country database; when set, chinadns mode builds the
    /// China set from it (takes precedence over `chnroute`).
    pub geoip: Option<PathBuf>,
    /// ISO 3166-1 alpha-2 country code selected from the GeoIP database.
    pub geoip_country: String,
    /// Per-query upstream timeout.
    pub dns_timeout: Duration,
}

/// A running policy-routing setup: the DNS proxy task plus a guard that removes
/// the installed routes when dropped.
pub struct PolicyHandle {
    /// The DNS proxy serve loop; resolves only on a fatal socket error.
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
    _guard: route::RouteGuard,
}

/// Start policy routing and the split-DNS proxy.
///
/// Loads the mode's data file, builds the [`route::TunRouter`] (seeding a route
/// for the clean DNS upstream so it is reached through the tunnel), and spawns
/// the proxy on `dns_listen`. The returned [`PolicyHandle`] owns the teardown
/// guard, so keep it alive for as long as policy routing should remain in
/// effect. Works on Linux and macOS.
pub async fn spawn(
    cfg: &PolicyConfig,
    tun_name: &str,
    tun_ip: std::net::Ipv4Addr,
) -> anyhow::Result<PolicyHandle> {
    use anyhow::Context;
    use std::net::IpAddr;
    use std::sync::Arc;

    let gfwlist = if matches!(cfg.mode, Mode::GfwList) {
        let p = cfg
            .gfwlist
            .as_ref()
            .context("gfwlist mode requires a gfwlist file")?;
        let list = gfwlist::GfwList::load(p)
            .with_context(|| format!("loading gfwlist from {}", p.display()))?;
        log::info!("loaded {} gfwlist domains from {}", list.len(), p.display());
        list
    } else {
        gfwlist::GfwList::default()
    };

    let chnroute = if matches!(cfg.mode, Mode::ChinaDns) {
        // GeoIP, when provided, takes precedence over a plain CIDR file.
        if let Some(db) = cfg.geoip.as_ref() {
            let routes = geoip::load_country_routes(db, &cfg.geoip_country).with_context(|| {
                format!(
                    "building {} routes from {}",
                    cfg.geoip_country,
                    db.display()
                )
            })?;
            log::info!(
                "loaded {} {} routes from GeoIP database {}",
                routes.len(),
                cfg.geoip_country,
                db.display()
            );
            routes
        } else {
            let p = cfg
                .chnroute
                .as_ref()
                .context("chinadns mode requires a chnroute file or a geoip database")?;
            let routes = chnroute::ChnRoute::load(p)
                .with_context(|| format!("loading chnroute from {}", p.display()))?;
            log::info!("loaded {} china routes from {}", routes.len(), p.display());
            routes
        }
    } else {
        chnroute::ChnRoute::default()
    };

    // Build the router that programs per-destination routes into the tun.
    let router = Arc::new(
        route::TunRouter::new(tun_name, tun_ip)
            .with_context(|| format!("setting up routing for tun device {tun_name}"))?,
    );

    // The clean upstream must itself be reached through the tunnel, so route it
    // there up front (before any query is forwarded to it).
    if let IpAddr::V4(v4) = cfg.dns_remote.ip() {
        router
            .add_route(v4)
            .with_context(|| format!("routing clean DNS upstream {v4} through the tunnel"))?;
    }

    let sink: Arc<dyn IpSink> = router.clone();
    let resolver = Arc::new(Resolver::new(
        cfg.mode,
        gfwlist,
        chnroute,
        cfg.dns_local,
        cfg.dns_remote,
        cfg.dns_timeout,
        sink,
    ));

    let listener = tokio::net::UdpSocket::bind(cfg.dns_listen)
        .await
        .with_context(|| format!("binding DNS proxy on {}", cfg.dns_listen))?;
    log::info!(
        "policy routing active (mode={}); DNS proxy on {}",
        cfg.mode.name(),
        cfg.dns_listen
    );
    log::info!(
        "point this host's resolver at {} (e.g. nameserver {}) to use policy routing",
        cfg.dns_listen,
        cfg.dns_listen.ip()
    );

    let task = tokio::spawn(proxy::serve(listener, resolver));
    Ok(PolicyHandle {
        task,
        _guard: route::RouteGuard::new(router),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes() {
        assert_eq!(Mode::from_name("full").unwrap(), Mode::Full);
        assert_eq!(Mode::from_name("OFF").unwrap(), Mode::Full);
        assert_eq!(Mode::from_name("gfwlist").unwrap(), Mode::GfwList);
        assert_eq!(Mode::from_name("ChinaDNS").unwrap(), Mode::ChinaDns);
        assert_eq!(Mode::from_name("china").unwrap(), Mode::ChinaDns);
        assert!(Mode::from_name("bogus").is_err());
    }

    #[test]
    fn enabled_flag() {
        assert!(!Mode::Full.is_enabled());
        assert!(Mode::GfwList.is_enabled());
        assert!(Mode::ChinaDns.is_enabled());
    }
}
