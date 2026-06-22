//! Lightweight policy routing for the ShadowVPN **client**.
//!
//! Instead of pushing *all* traffic through the tunnel, policy routing sends
//! only selected destinations through it and leaves the rest on the direct path.
//! A small split-DNS [`proxy`] decides, per query, whether a name should be
//! tunneled and hands the resolved addresses to a user-mode [`route`]r, which
//! programs a host route for each one into the tun device using the OS's native
//! routing interface (rtnetlink on Linux, `PF_ROUTE` on macOS, the IP Helper API
//! on Windows). There is no dependency on `ipset`, `iptables`/nft, or `fwmark`,
//! so it runs on **Linux, macOS, and Windows** alike; direct traffic stays on
//! the normal kernel path.
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

pub mod cache;
pub mod chnroute;
pub mod dns;
pub mod dnsconf;
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

/// Common (mostly outside-China) domains pre-resolved on startup so their first
/// real lookup is served from cache and their routes are pre-installed.
pub const DEFAULT_PREWARM: &[&str] = &[
    "google.com",
    "www.google.com",
    "www.gstatic.com",
    "fonts.gstatic.com",
    "ssl.gstatic.com",
    "www.googleapis.com",
    "ajax.googleapis.com",
    "accounts.google.com",
    "www.youtube.com",
    "youtube.com",
    "i.ytimg.com",
    "googlevideo.com",
    "twitter.com",
    "x.com",
    "abs.twimg.com",
    "pbs.twimg.com",
    "www.facebook.com",
    "static.xx.fbcdn.net",
    "www.instagram.com",
    "www.wikipedia.org",
    "en.wikipedia.org",
    "upload.wikimedia.org",
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "telegram.org",
    "web.telegram.org",
    "www.reddit.com",
    "duckduckgo.com",
];

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
    /// gfwlist domain file: required in gfwlist mode; an optional force-tunnel
    /// override in chinadns mode.
    pub gfwlist: Option<PathBuf>,
    /// China route (CIDR) file (one source for chinadns mode).
    pub chnroute: Option<PathBuf>,
    /// GeoLite2/GeoIP2 country database; when set, chinadns mode builds the
    /// China set from it (takes precedence over `chnroute`).
    pub geoip: Option<PathBuf>,
    /// ISO 3166-1 alpha-2 country code selected from the GeoIP database.
    pub geoip_country: String,
    /// Whether to point the system resolver at the proxy automatically (and
    /// restore it on exit). Only effective when `dns_listen` uses port 53.
    pub set_dns: bool,
    /// Domains to pre-resolve into the cache on startup (empty = disabled).
    pub prewarm: Vec<String>,
    /// Where to persist the DNS cache across restarts (`None` = don't persist).
    pub cache_file: Option<PathBuf>,
    /// Per-query upstream timeout.
    pub dns_timeout: Duration,
}

/// A running policy-routing setup: the DNS proxy task plus a guard that removes
/// the installed routes when dropped.
pub struct PolicyHandle {
    /// The DNS proxy serve loop; resolves only on a fatal socket error.
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
    _guard: route::RouteGuard,
    /// Restores the system resolver on drop (when auto-DNS was applied).
    _dns_guard: Option<dnsconf::DnsGuard>,
    /// Persists the DNS cache to disk on drop (when a cache file is configured).
    _cache_guard: Option<CacheGuard>,
}

/// Saves the shared DNS cache to disk when dropped.
struct CacheGuard {
    cache: std::sync::Arc<cache::DnsCache>,
    path: PathBuf,
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        self.cache.save(&self.path);
    }
}

/// Start policy routing and the split-DNS proxy.
///
/// Loads the mode's data file, builds the [`route::TunRouter`] (seeding a route
/// for the clean DNS upstream so it is reached through the tunnel), and spawns
/// the proxy on `dns_listen`. The returned [`PolicyHandle`] owns the teardown
/// guard, so keep it alive for as long as policy routing should remain in
/// effect. Works on Linux, macOS, and Windows.
pub async fn spawn(
    cfg: &PolicyConfig,
    tun_name: &str,
    tun_ip: std::net::Ipv4Addr,
    direct_src: std::net::IpAddr,
) -> anyhow::Result<PolicyHandle> {
    use anyhow::Context;
    use std::net::IpAddr;
    use std::sync::Arc;

    let gfwlist = match cfg.mode {
        // Required in gfwlist mode: it is the sole routing decision.
        Mode::GfwList => {
            let p = cfg
                .gfwlist
                .as_ref()
                .context("gfwlist mode requires a gfwlist file")?;
            let list = gfwlist::GfwList::load(p)
                .with_context(|| format!("loading gfwlist from {}", p.display()))?;
            log::info!("loaded {} gfwlist domains from {}", list.len(), p.display());
            list
        }
        // Optional in chinadns mode: a force-tunnel override for names the
        // local-vs-clean race would otherwise misclassify as domestic.
        Mode::ChinaDns if cfg.gfwlist.is_some() => {
            let p = cfg.gfwlist.as_ref().unwrap();
            let list = gfwlist::GfwList::load(p)
                .with_context(|| format!("loading gfwlist from {}", p.display()))?;
            log::info!(
                "loaded {} gfwlist force-tunnel domains from {}",
                list.len(),
                p.display()
            );
            list
        }
        _ => gfwlist::GfwList::default(),
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

    // Shared DNS cache, pre-loaded from disk if persistence is enabled.
    let dns_cache = Arc::new(cache::DnsCache::new());
    if let Some(path) = cfg.cache_file.as_ref() {
        dns_cache.load(path);
    }

    // Source addresses to bind upstream DNS queries to. On Windows, with the tun
    // up, the OS otherwise mis-selects the tun as the source for the direct
    // (domestic) query — sending it through the tunnel so the domestic resolver
    // sees the server's foreign IP and returns foreign answers. Pinning the
    // direct query to the physical source and the tunneled query to the tun
    // address makes each path deterministic. Other platforms select correctly on
    // their own, so they keep the unspecified defaults.
    let sink: Arc<dyn IpSink> = router.clone();
    let resolver = Resolver::new(
        cfg.mode,
        gfwlist,
        chnroute,
        cfg.dns_local,
        cfg.dns_remote,
        cfg.dns_timeout,
        sink,
        Arc::clone(&dns_cache),
    );
    #[cfg(windows)]
    let resolver = resolver.with_bind_sources(direct_src, IpAddr::V4(tun_ip));
    let resolver = Arc::new(resolver);

    let listener = tokio::net::UdpSocket::bind(cfg.dns_listen)
        .await
        .with_context(|| format!("binding DNS proxy on {}", cfg.dns_listen))?;
    log::info!(
        "policy routing active (mode={}); DNS proxy on {}",
        cfg.mode.name(),
        cfg.dns_listen
    );

    // Point the system resolver at the proxy (and restore it on exit) unless the
    // operator opted out; otherwise just tell them how to do it themselves.
    let dns_guard = if cfg.set_dns {
        dnsconf::apply(cfg.dns_listen.ip(), cfg.dns_listen.port(), direct_src)
            .context("configuring the system resolver")?
    } else {
        log::info!(
            "point this host's resolver at {} (e.g. nameserver {}) to use policy routing",
            cfg.dns_listen,
            cfg.dns_listen.ip()
        );
        None
    };

    // Pre-warm common domains in the background so their first real lookup is hot.
    if !cfg.prewarm.is_empty() {
        log::info!("pre-warming {} common domains", cfg.prewarm.len());
        tokio::spawn(proxy::prewarm(Arc::clone(&resolver), cfg.prewarm.clone()));
    }

    let cache_guard = cfg.cache_file.as_ref().map(|path| CacheGuard {
        cache: Arc::clone(&dns_cache),
        path: path.clone(),
    });

    let task = tokio::spawn(proxy::serve(listener, resolver));
    Ok(PolicyHandle {
        task,
        _guard: route::RouteGuard::new(router),
        _dns_guard: dns_guard,
        _cache_guard: cache_guard,
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
