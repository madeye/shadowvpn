//! Configuration for the ShadowVPN server and client.
//!
//! Configuration can come from a JSON file ([`FileConfig`], loaded with
//! [`FileConfig::load`]) and/or from command-line flags ([`ServerArgs`] /
//! [`ClientArgs`], parsed with `clap`). The binaries call
//! [`ServerArgs::resolve`] / [`ClientArgs::resolve`] to merge the two into a
//! fully validated [`ServerConfig`] / [`ClientConfig`], where CLI flags take
//! precedence over file values.
//!
//! # Example JSON
//!
//! ```json
//! {
//!   "server": "0.0.0.0:8388",
//!   "password": "correct horse battery staple",
//!   "cipher": "chacha20-poly1305",
//!   "tun_name": "utun7",
//!   "tun_ip": "10.9.0.1",
//!   "tun_netmask": "255.255.255.0",
//!   "peer_ip": "10.9.0.2",
//!   "mtu": 1400
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};

use crate::assign::DEFAULT_ASSIGN_TTL_SECS;
use crate::crypto::Cipher;
use crate::mesh::{canonical, AssignReq, RouteAdvert, RouteApproval, FLAG_WANT_IP6, MAX_ROUTES};
use crate::policy::{Mode, PolicyConfig};
use crate::pool::host_range;
use crate::protocol::DEFAULT_TUN_MTU;
use crate::state::default_client_state_path;

/// Default cipher used when none is specified.
pub const DEFAULT_CIPHER: &str = "chacha20-poly1305";

/// Default TUN netmask (a /24).
pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Default address the split-DNS proxy listens on. Port 53 so the client can
/// point the system resolver at it automatically (the client needs root for the
/// TUN anyway, and nothing else binds `127.0.0.1:53` by default).
pub const DEFAULT_DNS_LISTEN: &str = "127.0.0.1:53";

/// Default domestic / direct DNS upstream (114DNS).
pub const DEFAULT_DNS_LOCAL: &str = "114.114.114.114:53";

/// Default clean DNS upstream, reached through the tunnel (Google DNS).
pub const DEFAULT_DNS_REMOTE: &str = "8.8.8.8:53";

/// Default GeoIP country code selected for the China set.
pub const DEFAULT_GEOIP_COUNTRY: &str = "CN";

/// Default file name for the persisted DNS cache (placed next to the binary).
pub const DEFAULT_CACHE_FILE_NAME: &str = "dns-cache.json";

/// File name of a GeoLite2 country database shipped alongside the client
/// binary. In chinadns mode, when the config supplies neither a `chnroute` nor
/// a `geoip` path, the client auto-discovers this file next to its own
/// executable (how the desktop `.app` and Windows packages bundle it), so the
/// China IP set works out of the box with no explicit path.
pub const DEFAULT_GEOIP_DB_NAME: &str = "GeoLite2-Country.mmdb";

/// File name of a gfwlist domain-suffix list shipped alongside the client
/// binary. When the config supplies no `gfwlist` path, the client auto-discovers
/// this file next to its own executable — as the routing list in gfwlist mode,
/// and as the force-tunnel override in chinadns mode (matching the iOS client).
pub const DEFAULT_GFWLIST_NAME: &str = "gfwlist.txt";

/// Default per-query DNS upstream timeout, in milliseconds.
pub const DEFAULT_DNS_TIMEOUT_MS: u64 = 3000;

/// Default idle time-to-live for a client's NAT mapping, in seconds. A mapping
/// is refreshed by any traffic (data or keepalive) from the client and reclaimed
/// once idle for longer than this — comfortably above the client's default
/// keepalive interval ([`DEFAULT_KEEPALIVE_SECS`]).
pub const DEFAULT_LEASE_TTL_SECS: u64 = 120;

/// Default client keepalive interval, in seconds. Consumer routers commonly
/// expire idle UDP NAT mappings in as little as ~20 seconds; a keepalive
/// slower than that rebinds the flow to a new source port on every idle gap
/// (churning the server's per-client NAT and dropping in-flight replies), so
/// the default sits safely below it.
pub const DEFAULT_KEEPALIVE_SECS: u64 = 15;

/// Errors raised while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The JSON config file could not be read.
    #[error("failed to read config file {path}: {source}")]
    Read {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// The JSON config file could not be parsed.
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// A required field was missing from both the file and the CLI flags.
    #[error("missing required configuration field: {0}")]
    Missing(&'static str),

    /// The cipher name was not recognized.
    #[error(transparent)]
    Cipher(#[from] crate::crypto::CryptoError),

    /// A policy-routing value was invalid (e.g. an unknown mode).
    #[error(transparent)]
    Policy(#[from] crate::policy::PolicyError),

    /// A field had an invalid value (e.g. an unparsable socket address).
    #[error("invalid value for {field}: {message}")]
    Invalid {
        /// Field name.
        field: &'static str,
        /// Human-readable explanation.
        message: String,
    },
}

/// The JSON config file schema, shared by server and client.
///
/// All fields are optional so that any subset can live in the file and the rest
/// can be supplied on the command line. Field semantics differ slightly between
/// server and client (see [`ServerConfig`] / [`ClientConfig`]).
///
/// `None` fields are omitted on serialization (`skip_serializing_if`) so an
/// exported config — and the `shadowvpn://` URI built from it — stays compact and
/// matches the hand-written configs, which simply leave unused keys out. Missing
/// keys deserialize back to `None`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Server `host:port`. On the server this is the bind/listen address; on
    /// the client this is the remote address to connect to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Pre-shared password; the AEAD master key is derived from it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// AEAD cipher name (e.g. `"aes-256-gcm"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,

    /// Optional explicit TUN interface name (e.g. `utun7` / `tun0`). If unset,
    /// the OS picks a name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_name: Option<String>,

    /// Local IPv4 address assigned to the TUN interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_ip: Option<Ipv4Addr>,

    /// IPv4 netmask for the TUN interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_netmask: Option<Ipv4Addr>,

    /// Peer / point-to-point destination IPv4 address inside the tunnel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<Ipv4Addr>,

    /// Optional IPv6 address + prefix for the TUN interface (CIDR form, e.g.
    /// `"fd07:7::2/64"`). Give every node an address in one shared ULA prefix
    /// so IPv6 subnet routes have an in-tunnel source/return address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_ip6: Option<Ipv6Network>,

    /// TUN interface MTU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Carrier obfuscation: `"none"` (default), `"quic"` (wrap datagrams to
    /// look like QUIC/HTTP3 short-header packets), or `"base64"` (printable
    /// ASCII payload). Must match the other end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,

    /// Server-only: NAT multiple clients (each identified by its UDP endpoint)
    /// onto distinct internal IPs from the TUN subnet, so every client can share
    /// one static config. Ignored by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat: Option<bool>,

    /// Server-only: idle time-to-live for a client's NAT mapping, in seconds
    /// (default [`DEFAULT_LEASE_TTL_SECS`]). Ignored by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ttl_secs: Option<u64>,

    /// Server-only: IPv4 CIDR the assigner may hand out (must be a subset of
    /// the TUN network). Allocator-only; the Assign reply still carries the
    /// TUN netmask. Ignored by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assign_pool: Option<IpNetwork>,

    /// Server-only: extra IPv4s never auto-assigned (unioned with `peer_ip`).
    /// Ignored by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved_ips: Option<Vec<Ipv4Addr>>,

    /// Server-only: idle time-to-live for an assignment lease, in seconds
    /// (default [`DEFAULT_ASSIGN_TTL_SECS`]). Ignored by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assign_ttl_secs: Option<u64>,

    /// Server-only: assignment lease persist path. `"-"` disables. Default is
    /// next to `--config`, else `/var/lib/shadowvpn/leases.json` (Windows:
    /// `%PROGRAMDATA%\shadowvpn\leases.json`). Ignored by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_file: Option<String>,

    /// Client-only: keepalive interval in seconds (default
    /// [`DEFAULT_KEEPALIVE_SECS`]). Must stay below the shortest UDP NAT
    /// timeout on the path or the flow rebinds to a new source port whenever
    /// it goes idle. Ignored by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u64>,

    /// Client-only: persisted `node_id` + last assignment. Default is
    /// [`default_client_state_path`]. Ignored by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_file: Option<String>,

    // --- Mesh subnet routing (Tailscale-like) -------------------------------
    /// Client-only: subnets behind this client to advertise to the server
    /// (IPv4/IPv6 CIDRs). The server relays matching traffic here once the
    /// route is approved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_routes: Option<Vec<IpNetwork>>,

    /// Client-only: accept subnet routes pushed by the server and install them
    /// onto the TUN interface (removed again on exit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_routes: Option<bool>,

    /// Server-only: allowlist of CIDRs whose sub-networks are approved when a
    /// client advertises them. Advertised routes outside it are held as
    /// "awaiting approval" and never routed or pushed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approve_routes: Option<Vec<IpNetwork>>,

    /// Server-only: approve every advertised route (no allowlist needed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_approve_routes: Option<bool>,

    // --- Client-only policy routing (ignored by the server) ----------------
    /// Policy-routing mode: `full` (default), `gfwlist`, or `chinadns`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Address the split-DNS proxy listens on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_listen: Option<String>,

    /// Domestic / direct DNS upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_local: Option<String>,

    /// Clean DNS upstream (reached through the tunnel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_remote: Option<String>,

    /// Path to the gfwlist domain file (gfwlist mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gfwlist: Option<PathBuf>,

    /// Path to the China route (CIDR) file (chinadns mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chnroute: Option<PathBuf>,

    /// Path to a GeoLite2/GeoIP2 country database (chinadns mode); when set, the
    /// China set is built from it instead of `chnroute`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<PathBuf>,

    /// ISO 3166-1 alpha-2 country code to select from the GeoIP database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_country: Option<String>,

    /// Whether to point the system resolver at the proxy automatically
    /// (default `true` in gfwlist/chinadns mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_dns: Option<bool>,

    /// Domains to pre-resolve into the cache on startup. Absent uses a built-in
    /// list of common domains; an empty list disables pre-warming.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prewarm: Option<Vec<String>>,

    /// Where to persist the DNS cache across restarts. Absent uses the default
    /// path; set to disable via `--no-cache-persist`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<String>,

    /// Per-query DNS upstream timeout, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_timeout_ms: Option<u64>,
}

impl FileConfig {
    /// Load and parse a JSON config file from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Settings for the TUN interface, resolved and validated.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Explicit interface name, or `None` to let the OS choose.
    pub name: Option<String>,
    /// Local IPv4 address on the interface.
    pub ip: Ipv4Addr,
    /// IPv4 netmask.
    pub netmask: Ipv4Addr,
    /// Peer / point-to-point destination address inside the tunnel.
    pub peer_ip: Ipv4Addr,
    /// Optional IPv6 address + prefix on the interface (mesh IPv6 routing).
    pub ip6: Option<Ipv6Network>,
    /// Interface MTU.
    pub mtu: u16,
}

/// Fully resolved, validated server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind the UDP socket to (`host:port`).
    pub listen: String,
    /// Negotiated AEAD cipher.
    pub cipher: Cipher,
    /// `EVP_BytesToKey`-derived master key (length == `cipher.key_len()`).
    pub master_key: Vec<u8>,
    /// TUN interface settings.
    pub tun: TunConfig,
    /// Carrier obfuscation name (`"quic"` | `"base64"`), or `None` for plain.
    pub obfs: Option<String>,
    /// NAT multiple clients onto distinct internal IPs (keyed by UDP endpoint).
    pub nat: bool,
    /// Idle time-to-live for a client's NAT mapping (reclamation threshold).
    /// Also the expiry for advertised subnet routes whose owner went quiet,
    /// and for learned inner-IP → UDP mappings.
    pub lease_ttl: Duration,
    /// Approval policy for client-advertised subnet routes.
    pub route_approval: RouteApproval,
    /// Allocator-only IPv4 CIDR (canonical). `None` means the full TUN host range.
    pub assign_pool: Option<Ipv4Network>,
    /// IPv4s never auto-assigned. Always includes [`TunConfig::peer_ip`].
    pub reserved_ips: Vec<Ipv4Addr>,
    /// Idle time before an assignment lease is reclaimed.
    pub assign_ttl: Duration,
    /// Assignment lease persist path. `None` disables persistence (`lease_file: "-"`).
    pub lease_file: Option<PathBuf>,
}

/// Fully resolved, validated client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Remote server address to send to (`host:port`).
    pub server: String,
    /// Negotiated AEAD cipher.
    pub cipher: Cipher,
    /// `EVP_BytesToKey`-derived master key (length == `cipher.key_len()`).
    pub master_key: Vec<u8>,
    /// TUN interface settings.
    pub tun: TunConfig,
    /// Both `tun_ip` and `peer_ip` were omitted; the server assigns them.
    pub auto_tun: bool,
    /// `auto_tun` and no file/CLI `tun_ip6` (computed before any cache overlay).
    pub want_ip6: bool,
    /// Persisted `node_id` + last assignment. Always set after [`ClientArgs::resolve`].
    pub state_file: Option<PathBuf>,
    /// Policy-routing settings (mode `full` means no policy routing).
    pub policy: PolicyConfig,
    /// Carrier obfuscation name (`"quic"` | `"base64"`), or `None` for plain.
    /// Must match the server.
    pub obfs: Option<String>,
    /// Interval between keepalive datagrams.
    pub keepalive: Duration,
    /// Subnets behind this client to advertise to the server.
    pub advertise_routes: Vec<IpNetwork>,
    /// Whether to accept and install subnet routes pushed by the server.
    pub accept_routes: bool,
}

/// Command-line arguments for `shadowvpn-server`.
///
/// Every option overrides the corresponding JSON field when present.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "shadowvpn-server",
    about = "ShadowVPN server: terminates the encrypted UDP tunnel onto a TUN device."
)]
pub struct ServerArgs {
    /// Path to a JSON config file. CLI flags override its values.
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// UDP address to listen on, e.g. `0.0.0.0:8388`.
    #[arg(short = 'l', long = "listen")]
    pub listen: Option<String>,

    /// Pre-shared password.
    #[arg(short = 'k', long = "password")]
    pub password: Option<String>,

    /// AEAD cipher: aes-128-gcm | aes-256-gcm | chacha20-poly1305.
    #[arg(short = 'm', long = "cipher")]
    pub cipher: Option<String>,

    /// Explicit TUN interface name.
    #[arg(long = "tun-name")]
    pub tun_name: Option<String>,

    /// Local IPv4 address for the TUN interface.
    #[arg(long = "tun-ip")]
    pub tun_ip: Option<Ipv4Addr>,

    /// IPv4 netmask for the TUN interface.
    #[arg(long = "tun-netmask")]
    pub tun_netmask: Option<Ipv4Addr>,

    /// Peer (client) IPv4 address inside the tunnel.
    #[arg(long = "peer-ip")]
    pub peer_ip: Option<Ipv4Addr>,

    /// IPv6 address + prefix for the TUN interface (e.g. fd07:7::1/64).
    #[arg(long = "tun-ip6")]
    pub tun_ip6: Option<Ipv6Network>,

    /// TUN interface MTU.
    #[arg(long = "mtu")]
    pub mtu: Option<u16>,

    /// NAT multiple clients (by UDP endpoint) onto distinct internal IPs so they
    /// can share one static config.
    #[arg(long = "nat")]
    pub nat: bool,

    /// Idle time-to-live for a client's NAT mapping, in seconds.
    #[arg(long = "lease-ttl-secs")]
    pub lease_ttl_secs: Option<u64>,

    /// Approve advertised routes covered by these CIDRs (comma-separated).
    #[arg(long = "approve-routes", value_delimiter = ',')]
    pub approve_routes: Option<Vec<IpNetwork>>,

    /// Approve every route clients advertise (Tailscale "approve all").
    #[arg(long = "auto-approve-routes")]
    pub auto_approve_routes: bool,

    /// IPv4 CIDR the assigner may hand out (subset of the TUN network).
    #[arg(long = "assign-pool")]
    pub assign_pool: Option<IpNetwork>,

    /// Extra IPv4s never auto-assigned (unioned with `--peer-ip`).
    #[arg(long = "reserved-ips", value_delimiter = ',')]
    pub reserved_ips: Option<Vec<Ipv4Addr>>,

    /// Idle time-to-live for an assignment lease, in seconds (default 604800).
    #[arg(long = "assign-ttl-secs")]
    pub assign_ttl_secs: Option<u64>,

    /// Assignment lease persist path. "-" disables persistence.
    #[arg(long = "lease-file")]
    pub lease_file: Option<String>,
}

/// Command-line arguments for `shadowvpn-client`.
///
/// Every option overrides the corresponding JSON field when present.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "shadowvpn-client",
    about = "ShadowVPN client: tunnels TUN traffic to the server over encrypted UDP."
)]
pub struct ClientArgs {
    /// Path to a JSON config file. CLI flags override its values.
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// Remote server address to connect to, e.g. `vpn.example.com:8388`.
    #[arg(short = 's', long = "server")]
    pub server: Option<String>,

    /// Pre-shared password.
    #[arg(short = 'k', long = "password")]
    pub password: Option<String>,

    /// AEAD cipher: aes-128-gcm | aes-256-gcm | chacha20-poly1305.
    #[arg(short = 'm', long = "cipher")]
    pub cipher: Option<String>,

    /// Explicit TUN interface name.
    #[arg(long = "tun-name")]
    pub tun_name: Option<String>,

    /// Local IPv4 address for the TUN interface.
    #[arg(long = "tun-ip")]
    pub tun_ip: Option<Ipv4Addr>,

    /// IPv4 netmask for the TUN interface.
    #[arg(long = "tun-netmask")]
    pub tun_netmask: Option<Ipv4Addr>,

    /// Peer (server) IPv4 address inside the tunnel.
    #[arg(long = "peer-ip")]
    pub peer_ip: Option<Ipv4Addr>,

    /// IPv6 address + prefix for the TUN interface (e.g. fd07:7::2/64).
    #[arg(long = "tun-ip6")]
    pub tun_ip6: Option<Ipv6Network>,

    /// TUN interface MTU.
    #[arg(long = "mtu")]
    pub mtu: Option<u16>,

    /// Subnets behind this client to advertise to the server (comma-separated
    /// IPv4/IPv6 CIDRs), e.g. 192.168.200.0/24,fd42:cafe::/64.
    #[arg(long = "advertise-routes", value_delimiter = ',')]
    pub advertise_routes: Option<Vec<IpNetwork>>,

    /// Accept subnet routes pushed by the server and install them on the TUN.
    #[arg(long = "accept-routes")]
    pub accept_routes: bool,

    /// Policy-routing mode: full | gfwlist | chinadns.
    #[arg(long = "mode")]
    pub mode: Option<String>,

    /// Address for the split-DNS proxy to listen on.
    #[arg(long = "dns-listen")]
    pub dns_listen: Option<String>,

    /// Domestic / direct DNS upstream.
    #[arg(long = "dns-local")]
    pub dns_local: Option<String>,

    /// Clean DNS upstream (reached through the tunnel).
    #[arg(long = "dns-remote")]
    pub dns_remote: Option<String>,

    /// Path to the gfwlist domain file (gfwlist mode).
    #[arg(long = "gfwlist")]
    pub gfwlist: Option<PathBuf>,

    /// Path to the China route (CIDR) file (chinadns mode).
    #[arg(long = "chnroute")]
    pub chnroute: Option<PathBuf>,

    /// Path to a GeoLite2/GeoIP2 country database (chinadns mode).
    #[arg(long = "geoip")]
    pub geoip: Option<PathBuf>,

    /// ISO country code to select from the GeoIP database (default CN).
    #[arg(long = "geoip-country")]
    pub geoip_country: Option<String>,

    /// Point the system resolver at the split-DNS proxy (the default in
    /// gfwlist/chinadns mode).
    #[arg(long = "set-dns")]
    pub set_dns: bool,

    /// Do NOT modify the system resolver; configure DNS yourself.
    #[arg(long = "no-set-dns")]
    pub no_set_dns: bool,

    /// Restore the system resolver from the journal left by a run that did
    /// not exit cleanly, then exit (no tunnel is brought up). Used by the
    /// desktop app to heal DNS after a crashed client.
    #[arg(long = "restore-dns")]
    pub restore_dns: bool,

    /// Do NOT pre-resolve common domains into the cache on startup.
    #[arg(long = "no-prewarm")]
    pub no_prewarm: bool,

    /// Path to persist the DNS cache across restarts.
    #[arg(long = "cache-file")]
    pub cache_file: Option<String>,

    /// Do NOT persist the DNS cache to disk.
    #[arg(long = "no-cache-persist")]
    pub no_cache_persist: bool,

    /// Keepalive interval in seconds (keep below the path's UDP NAT timeout).
    #[arg(long = "keepalive-secs")]
    pub keepalive_secs: Option<u64>,

    /// Persisted node identity + last assignment (default: next to `--config`,
    /// or a hashed path under the OS state directory).
    #[arg(long = "state-file")]
    pub state_file: Option<PathBuf>,
}

/// Load the optional file config referenced by a `--config` path.
fn load_file(config: &Option<PathBuf>) -> Result<FileConfig, ConfigError> {
    match config {
        Some(path) => FileConfig::load(path),
        None => Ok(FileConfig::default()),
    }
}

/// Derive cipher + master key from a (possibly file-supplied) cipher name and
/// password, applying defaults and validating presence.
fn resolve_crypto(
    cipher_name: Option<String>,
    password: Option<String>,
) -> Result<(Cipher, Vec<u8>), ConfigError> {
    let cipher_name = cipher_name.unwrap_or_else(|| DEFAULT_CIPHER.to_string());
    let cipher = Cipher::from_name(&cipher_name)?;
    let password = password.ok_or(ConfigError::Missing("password"))?;
    let master_key = crate::crypto::evp_bytes_to_key(password.as_bytes(), cipher.key_len());
    Ok((cipher, master_key))
}

/// Default DNS-cache path: `dns-cache.json` in the same directory as the running
/// binary (falling back to the current directory if the exe path is unknown).
fn default_cache_file() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_CACHE_FILE_NAME)
}

/// The directory holding the running client binary, if it can be determined.
/// Bundled policy data files (a GeoLite2 database, a gfwlist) are looked up here
/// so a copy shipped alongside the executable (desktop `.app`, Windows zip) is
/// auto-discovered.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

/// The file `name` inside `dir`, if it exists as a regular file.
fn data_file_in_dir(dir: &Path, name: &str) -> Option<PathBuf> {
    let path = dir.join(name);
    path.is_file().then_some(path)
}

/// The gfwlist to use when the config sets no explicit `gfwlist` path: a bundled
/// [`DEFAULT_GFWLIST_NAME`] in `dir`. Applied in gfwlist mode (the routing list)
/// and in chinadns mode (the force-tunnel override, matching the iOS client,
/// whose network extension always injects its bundled gfwlist in chinadns mode);
/// never in full mode.
fn bundled_gfwlist(mode: Mode, dir: &Path) -> Option<PathBuf> {
    if matches!(mode, Mode::GfwList | Mode::ChinaDns) {
        data_file_in_dir(dir, DEFAULT_GFWLIST_NAME)
    } else {
        None
    }
}

/// The GeoIP database to use when the config sets no `chnroute`/`geoip` path: a
/// bundled [`DEFAULT_GEOIP_DB_NAME`] in `dir`, in chinadns mode only (and only
/// when no `chnroute` is configured, since that supplies the China set instead).
fn bundled_geoip(mode: Mode, chnroute_set: bool, dir: &Path) -> Option<PathBuf> {
    if matches!(mode, Mode::ChinaDns) && !chnroute_set {
        data_file_in_dir(dir, DEFAULT_GEOIP_DB_NAME)
    } else {
        None
    }
}

/// Parse a DNS endpoint that may be `ip:port` or a bare `ip` (defaulting the
/// port to `default_port`).
fn parse_dns_addr(
    field: &'static str,
    value: &str,
    default_port: u16,
) -> Result<SocketAddr, ConfigError> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    Err(ConfigError::Invalid {
        field,
        message: format!("`{value}` is not an `ip` or `ip:port` address"),
    })
}

/// Build the validated [`PolicyConfig`] from merged file + CLI values, applying
/// defaults and validating that the active mode has the data file it needs.
fn resolve_policy(args: &ClientArgs, file: &FileConfig) -> Result<PolicyConfig, ConfigError> {
    let mode = match args.mode.clone().or_else(|| file.mode.clone()) {
        Some(name) => Mode::from_name(&name)?,
        None => Mode::Full,
    };

    let pick = |a: &Option<String>, f: &Option<String>, default: &str| -> String {
        a.clone()
            .or_else(|| f.clone())
            .unwrap_or_else(|| default.to_string())
    };

    let dns_listen = parse_dns_addr(
        "dns_listen",
        &pick(&args.dns_listen, &file.dns_listen, DEFAULT_DNS_LISTEN),
        53,
    )?;
    let dns_local = parse_dns_addr(
        "dns_local",
        &pick(&args.dns_local, &file.dns_local, DEFAULT_DNS_LOCAL),
        53,
    )?;
    let dns_remote = parse_dns_addr(
        "dns_remote",
        &pick(&args.dns_remote, &file.dns_remote, DEFAULT_DNS_REMOTE),
        53,
    )?;

    // Data files bundled next to the client binary are the fallback when the
    // config sets no explicit path (desktop `.app`, Windows zip). Resolve the
    // exe dir once and reuse it for both lookups.
    let bundle_dir = exe_dir();

    // Explicit `gfwlist` (CLI or file) wins; otherwise fall back to a bundled
    // gfwlist.txt (routing list in gfwlist mode, force-tunnel override in
    // chinadns mode).
    let gfwlist = args
        .gfwlist
        .clone()
        .or_else(|| file.gfwlist.clone())
        .or_else(|| bundle_dir.as_deref().and_then(|d| bundled_gfwlist(mode, d)));
    let chnroute = args.chnroute.clone().or_else(|| file.chnroute.clone());
    // Explicit `geoip` (CLI or file) wins; otherwise, in chinadns mode with no
    // `chnroute` either, fall back to a bundled GeoLite2-Country.mmdb so the
    // China set works with no configured path.
    let geoip = args
        .geoip
        .clone()
        .or_else(|| file.geoip.clone())
        .or_else(|| {
            bundle_dir
                .as_deref()
                .and_then(|d| bundled_geoip(mode, chnroute.is_some(), d))
        });

    // `--no-set-dns` wins over `--set-dns`; otherwise file value; default on.
    let set_dns = if args.no_set_dns {
        false
    } else if args.set_dns {
        true
    } else {
        file.set_dns.unwrap_or(true)
    };

    // Pre-warm: `--no-prewarm` disables; else the file list, else the built-in.
    let prewarm = if args.no_prewarm {
        Vec::new()
    } else {
        file.prewarm.clone().unwrap_or_else(|| {
            crate::policy::DEFAULT_PREWARM
                .iter()
                .map(|s| s.to_string())
                .collect()
        })
    };

    // Cache persistence: `--no-cache-persist` disables; else CLI/file path, else
    // a file next to the binary.
    let cache_file = if args.no_cache_persist {
        None
    } else {
        Some(
            args.cache_file
                .clone()
                .or_else(|| file.cache_file.clone())
                .map(PathBuf::from)
                .unwrap_or_else(default_cache_file),
        )
    };

    // Fail fast if the chosen mode is missing its data file.
    if matches!(mode, Mode::GfwList) && gfwlist.is_none() {
        return Err(ConfigError::Missing("gfwlist (required by gfwlist mode)"));
    }
    if matches!(mode, Mode::ChinaDns) && chnroute.is_none() && geoip.is_none() {
        return Err(ConfigError::Missing(
            "chnroute or geoip (required by chinadns mode)",
        ));
    }

    Ok(PolicyConfig {
        mode,
        dns_listen,
        dns_local,
        dns_remote,
        gfwlist,
        chnroute,
        geoip,
        geoip_country: args
            .geoip_country
            .clone()
            .or_else(|| file.geoip_country.clone())
            .unwrap_or_else(|| DEFAULT_GEOIP_COUNTRY.to_string()),
        set_dns,
        prewarm,
        cache_file,
        dns_timeout: Duration::from_millis(file.dns_timeout_ms.unwrap_or(DEFAULT_DNS_TIMEOUT_MS)),
    })
}

/// Build the validated [`TunConfig`] from merged file + CLI values.
#[allow(clippy::too_many_arguments)]
fn resolve_tun(
    name: Option<String>,
    ip: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    ip6: Option<Ipv6Network>,
    mtu: Option<u16>,
) -> Result<TunConfig, ConfigError> {
    Ok(TunConfig {
        name,
        ip: ip.ok_or(ConfigError::Missing("tun_ip"))?,
        netmask: netmask.unwrap_or(DEFAULT_NETMASK),
        peer_ip: peer_ip.ok_or(ConfigError::Missing("peer_ip"))?,
        ip6,
        mtu: mtu.unwrap_or(DEFAULT_TUN_MTU),
    })
}

/// Client TUN: both addresses set (static) or both omitted (auto-assign).
#[allow(clippy::too_many_arguments)]
fn resolve_client_tun(
    name: Option<String>,
    ip: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    ip6: Option<Ipv6Network>,
    mtu: Option<u16>,
) -> Result<(TunConfig, bool, bool), ConfigError> {
    let auto_tun = match (ip, peer_ip) {
        (None, None) => true,
        (Some(_), Some(_)) => false,
        _ => {
            return Err(ConfigError::Invalid {
                field: "tun_ip",
                message: "tun_ip and peer_ip must both be set, or both omitted for auto-assign"
                    .to_string(),
            });
        }
    };
    // Pre-overlay: a cached tun_ip6 must not flip this off later.
    let want_ip6 = auto_tun && ip6.is_none();
    Ok((
        TunConfig {
            name,
            ip: ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            netmask: netmask.unwrap_or(DEFAULT_NETMASK),
            peer_ip: peer_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            ip6,
            mtu: mtu.unwrap_or(DEFAULT_TUN_MTU),
        },
        auto_tun,
        want_ip6,
    ))
}

/// Validate a set of advertised routes: bounded and free of degenerate
/// (default-route) entries, which must go through the normal full-tunnel
/// routing setup rather than a subnet advertisement.
fn validate_advertised(routes: &[IpNetwork]) -> Result<(), ConfigError> {
    if routes.len() > MAX_ROUTES {
        return Err(ConfigError::Invalid {
            field: "advertise_routes",
            message: format!("at most {MAX_ROUTES} routes may be advertised"),
        });
    }
    if let Some(net) = routes.iter().find(|net| net.prefix() == 0) {
        return Err(ConfigError::Invalid {
            field: "advertise_routes",
            message: format!("`{net}` is a default route; advertise specific subnets instead"),
        });
    }
    Ok(())
}

/// Default server lease-file path: `<config>.leases.json` next to `--config`,
/// else `/var/lib/shadowvpn/leases.json` (Windows: `%PROGRAMDATA%\shadowvpn\leases.json`).
fn default_lease_file(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        let mut s = cfg.as_os_str().to_os_string();
        s.push(".leases.json");
        return PathBuf::from(s);
    }
    #[cfg(windows)]
    {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("shadowvpn")
            .join("leases.json")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/shadowvpn/leases.json")
    }
}

/// TUN IPv4 network from address + netmask, or an error if the mask is not
/// a contiguous prefix (needed for `assign_pool` subset checks).
fn tun_v4_network(ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<Ipv4Network, ConfigError> {
    let mask = u32::from(netmask);
    if mask.leading_ones() + mask.trailing_zeros() != 32 {
        return Err(ConfigError::Invalid {
            field: "tun_netmask",
            message: format!("{netmask} is not a contiguous IPv4 netmask"),
        });
    }
    let prefix = mask.leading_ones() as u8;
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Ipv4Network::new(network, prefix).map_err(|e| ConfigError::Invalid {
        field: "tun_ip",
        message: e.to_string(),
    })
}

/// Validate `assign_pool`: IPv4 only, canonical subset of `tun`, at least one
/// host left after network/broadcast/server/reserved exclusions.
fn validate_assign_pool(
    pool: IpNetwork,
    tun: Ipv4Network,
    server_ip: Ipv4Addr,
    reserved: &[Ipv4Addr],
) -> Result<Ipv4Network, ConfigError> {
    let IpNetwork::V4(pool) = canonical(pool) else {
        return Err(ConfigError::Invalid {
            field: "assign_pool",
            message: "must be an IPv4 CIDR".to_string(),
        });
    };
    if pool.prefix() < tun.prefix() || !tun.contains(pool.ip()) {
        return Err(ConfigError::Invalid {
            field: "assign_pool",
            message: format!("{pool} is not a subset of the TUN network {tun}"),
        });
    }
    let (start, end) = host_range(pool.network(), pool.mask());
    let mut usable = 0usize;
    if start <= end {
        for host in start..=end {
            let addr = Ipv4Addr::from(host);
            if addr != server_ip && !reserved.contains(&addr) {
                usable += 1;
            }
        }
    }
    if usable == 0 {
        return Err(ConfigError::Invalid {
            field: "assign_pool",
            message: format!(
                "{pool} has no assignable hosts after excluding the network, \
                 broadcast, server IP, and reserved addresses"
            ),
        });
    }
    Ok(pool)
}

impl ServerArgs {
    /// Merge these CLI args over the (optional) JSON file and produce a
    /// validated [`ServerConfig`]. CLI flags take precedence over file values.
    pub fn resolve(self) -> Result<ServerConfig, ConfigError> {
        let file = load_file(&self.config)?;

        let listen = self
            .listen
            .or(file.server)
            .ok_or(ConfigError::Missing("listen"))?;

        let (cipher, master_key) =
            resolve_crypto(self.cipher.or(file.cipher), self.password.or(file.password))?;

        let tun = resolve_tun(
            self.tun_name.or(file.tun_name),
            self.tun_ip.or(file.tun_ip),
            self.tun_netmask.or(file.tun_netmask),
            self.peer_ip.or(file.peer_ip),
            self.tun_ip6.or(file.tun_ip6),
            self.mtu.or(file.mtu),
        )?;

        let obfs = file.obfs.filter(|s| !s.is_empty() && s != "none");

        let nat = self.nat || file.nat.unwrap_or(false);
        let lease_ttl = Duration::from_secs(
            self.lease_ttl_secs
                .or(file.lease_ttl_secs)
                .unwrap_or(DEFAULT_LEASE_TTL_SECS),
        );

        let route_approval = RouteApproval {
            auto: self.auto_approve_routes || file.auto_approve_routes.unwrap_or(false),
            allowlist: self
                .approve_routes
                .or(file.approve_routes)
                .unwrap_or_default(),
        };

        // Mesh routing identifies clients by their distinct tunnel IPs; NAT
        // mode deliberately erases that distinction (one shared config), so
        // the two cannot be combined.
        if nat && (route_approval.auto || !route_approval.allowlist.is_empty() || tun.ip6.is_some())
        {
            return Err(ConfigError::Invalid {
                field: "nat",
                message: "mesh subnet routing (approve_routes / auto_approve_routes / tun_ip6) \
                          requires learning mode; remove --nat"
                    .to_string(),
            });
        }

        // `peer_ip` is always reserved so mixed static/auto fleets keep .2.
        let extra_reserved = self.reserved_ips.or(file.reserved_ips).unwrap_or_default();
        let mut reserved_ips = Vec::with_capacity(extra_reserved.len() + 1);
        reserved_ips.push(tun.peer_ip);
        for ip in extra_reserved {
            if !reserved_ips.contains(&ip) {
                reserved_ips.push(ip);
            }
        }

        let assign_pool = match self.assign_pool.or(file.assign_pool) {
            Some(pool) => {
                let tun_net = tun_v4_network(tun.ip, tun.netmask)?;
                Some(validate_assign_pool(pool, tun_net, tun.ip, &reserved_ips)?)
            }
            None => None,
        };
        let assign_ttl = Duration::from_secs(
            self.assign_ttl_secs
                .or(file.assign_ttl_secs)
                .unwrap_or(DEFAULT_ASSIGN_TTL_SECS),
        );
        let lease_file = match self.lease_file.as_deref().or(file.lease_file.as_deref()) {
            Some("-") => None,
            Some(path) => Some(PathBuf::from(path)),
            None => Some(default_lease_file(self.config.as_deref())),
        };

        Ok(ServerConfig {
            listen,
            cipher,
            master_key,
            tun,
            obfs,
            nat,
            lease_ttl,
            route_approval,
            assign_pool,
            reserved_ips,
            assign_ttl,
            lease_file,
        })
    }
}

impl ClientArgs {
    /// Merge these CLI args over the (optional) JSON file and produce a
    /// validated [`ClientConfig`]. CLI flags take precedence over file values.
    pub fn resolve(self) -> Result<ClientConfig, ConfigError> {
        let file = load_file(&self.config)?;

        // Resolve policy first: it borrows `self`/`file`, which the moves below
        // would otherwise partially consume.
        let policy = resolve_policy(&self, &file)?;

        let server = self
            .server
            .or(file.server)
            .ok_or(ConfigError::Missing("server"))?;

        let (cipher, master_key) =
            resolve_crypto(self.cipher.or(file.cipher), self.password.or(file.password))?;

        let (tun, auto_tun, want_ip6) = resolve_client_tun(
            self.tun_name.or(file.tun_name),
            self.tun_ip.or(file.tun_ip),
            self.tun_netmask.or(file.tun_netmask),
            self.peer_ip.or(file.peer_ip),
            self.tun_ip6.or(file.tun_ip6),
            self.mtu.or(file.mtu),
        )?;

        let obfs = file.obfs.filter(|s| !s.is_empty() && s != "none");

        let keepalive_secs = self
            .keepalive_secs
            .or(file.keepalive_secs)
            .unwrap_or(DEFAULT_KEEPALIVE_SECS);
        if keepalive_secs == 0 {
            return Err(ConfigError::Invalid {
                field: "keepalive_secs",
                message: "must be at least 1 second".to_string(),
            });
        }

        let advertise_routes = self
            .advertise_routes
            .or(file.advertise_routes)
            .unwrap_or_default();
        validate_advertised(&advertise_routes)?;
        let accept_routes = self.accept_routes || file.accept_routes.unwrap_or(false);

        // Path only; the file is not read here.
        let state_file = Some(
            self.state_file
                .or_else(|| file.state_file.map(PathBuf::from))
                .unwrap_or_else(|| default_client_state_path(self.config.as_deref(), &server)),
        );

        Ok(ClientConfig {
            server,
            cipher,
            master_key,
            tun,
            auto_tun,
            want_ip6,
            state_file,
            policy,
            obfs,
            keepalive: Duration::from_secs(keepalive_secs),
            advertise_routes,
            accept_routes,
        })
    }
}

impl ClientConfig {
    /// Overlay a cached assignment onto `tun`. Does not change [`Self::want_ip6`].
    pub fn overlay_cached_assignment(
        &mut self,
        tun_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        peer_ip: Ipv4Addr,
        tun_ip6: Option<Ipv6Network>,
    ) {
        self.tun.ip = tun_ip;
        self.tun.netmask = netmask;
        self.tun.peer_ip = peer_ip;
        if self.want_ip6 {
            self.tun.ip6 = tun_ip6;
        }
    }

    /// `AssignRequest` bytes. `FLAG_WANT_IP6` follows [`Self::want_ip6`], not `tun.ip6`.
    pub fn assign_request(&self, node_id: [u8; 16]) -> Vec<u8> {
        AssignReq {
            flags: if self.want_ip6 { FLAG_WANT_IP6 } else { 0 },
            node_id,
            hint_ip4: self.tun.ip,
            hint_ip6: self.tun.ip6.map(|n| n.ip()),
        }
        .encode()
    }

    /// True when this client advertises or accepts mesh subnet routes.
    pub fn mesh_active(&self) -> bool {
        self.accept_routes || !self.advertise_routes.is_empty()
    }

    /// Mesh advert carrying the addresses currently on `tun`.
    pub fn route_advert(&self) -> RouteAdvert {
        RouteAdvert {
            tunnel_ip: self.tun.ip,
            tunnel_ip6: self.tun.ip6.map(|n| n.ip()),
            accept_routes: self.accept_routes,
            routes: self.advertise_routes.clone(),
        }
    }

    /// Periodic auto-mode payloads after Assign Ok. Never a 5-byte keepalive.
    pub fn auto_tick_payloads(&self, node_id: [u8; 16]) -> Vec<Vec<u8>> {
        let mut out = vec![self.assign_request(node_id)];
        if self.mesh_active() {
            out.push(self.route_advert().encode());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ServerArgs {
        /// All-`None` server args, for building test cases with struct update
        /// syntax (`..ServerArgs::empty()`).
        fn empty() -> Self {
            ServerArgs {
                config: None,
                listen: None,
                password: None,
                cipher: None,
                tun_name: None,
                tun_ip: None,
                tun_netmask: None,
                peer_ip: None,
                tun_ip6: None,
                mtu: None,
                nat: false,
                lease_ttl_secs: None,
                approve_routes: None,
                auto_approve_routes: false,
                assign_pool: None,
                reserved_ips: None,
                assign_ttl_secs: None,
                lease_file: None,
            }
        }

        fn test_base() -> Self {
            ServerArgs {
                listen: Some("0.0.0.0:1".to_string()),
                password: Some("pw".to_string()),
                tun_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
                peer_ip: Some(Ipv4Addr::new(10, 9, 0, 2)),
                ..Self::empty()
            }
        }
    }

    impl ClientArgs {
        /// All-`None` client args, for building test cases with struct update
        /// syntax (`..ClientArgs::empty()`).
        fn empty() -> Self {
            ClientArgs {
                config: None,
                server: None,
                password: None,
                cipher: None,
                tun_name: None,
                tun_ip: None,
                tun_netmask: None,
                peer_ip: None,
                tun_ip6: None,
                mtu: None,
                advertise_routes: None,
                accept_routes: false,
                mode: None,
                dns_listen: None,
                dns_local: None,
                dns_remote: None,
                gfwlist: None,
                chnroute: None,
                geoip: None,
                geoip_country: None,
                set_dns: false,
                no_set_dns: false,
                restore_dns: false,
                no_prewarm: false,
                cache_file: None,
                no_cache_persist: false,
                keepalive_secs: None,
                state_file: None,
            }
        }
    }

    #[test]
    fn cli_overrides_file_and_resolves() {
        let args = ServerArgs {
            config: None,
            listen: Some("0.0.0.0:9000".to_string()),
            password: Some("test".to_string()),
            cipher: Some("aes-128-gcm".to_string()),
            tun_name: Some("utun9".to_string()),
            tun_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            tun_netmask: None,
            peer_ip: Some(Ipv4Addr::new(10, 9, 0, 2)),
            tun_ip6: None,
            mtu: None,
            nat: false,
            lease_ttl_secs: None,
            approve_routes: None,
            auto_approve_routes: false,
            assign_pool: None,
            reserved_ips: None,
            assign_ttl_secs: None,
            lease_file: None,
        };
        let cfg = args.resolve().expect("resolve");
        assert_eq!(cfg.listen, "0.0.0.0:9000");
        assert_eq!(cfg.cipher, Cipher::Aes128Gcm);
        // password "test" + aes-128-gcm => MD5("test").
        assert_eq!(cfg.master_key.len(), 16);
        assert_eq!(cfg.tun.netmask, DEFAULT_NETMASK);
        assert_eq!(cfg.tun.mtu, DEFAULT_TUN_MTU);
        assert_eq!(cfg.tun.name.as_deref(), Some("utun9"));
    }

    #[test]
    fn missing_password_is_an_error() {
        let args = ClientArgs {
            config: None,
            server: Some("host:1".to_string()),
            password: None,
            cipher: None,
            tun_name: None,
            tun_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            tun_netmask: None,
            peer_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            mtu: None,
            ..ClientArgs::empty()
        };
        assert!(matches!(
            args.resolve(),
            Err(ConfigError::Missing("password"))
        ));
    }

    #[test]
    fn policy_defaults_to_full_and_validates() {
        // Default mode is full; no DNS/gfwlist needed.
        let base = ClientArgs {
            config: None,
            server: Some("host:1".to_string()),
            password: Some("pw".to_string()),
            tun_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            peer_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..ClientArgs::empty()
        };
        let cfg = base.clone().resolve().expect("resolve full");
        assert_eq!(cfg.policy.mode, Mode::Full);
        assert_eq!(cfg.policy.dns_listen.to_string(), "127.0.0.1:53");
        assert!(cfg.policy.set_dns, "set_dns defaults to on");

        // --no-set-dns wins; --set-dns forces on.
        let mut nd = base.clone();
        nd.no_set_dns = true;
        assert!(!nd.resolve().unwrap().policy.set_dns);
        let mut sd = base.clone();
        sd.set_dns = true;
        assert!(sd.resolve().unwrap().policy.set_dns);

        // prewarm defaults to the built-in list; --no-prewarm empties it.
        assert!(!cfg.policy.prewarm.is_empty());
        let mut np = base.clone();
        np.no_prewarm = true;
        assert!(np.resolve().unwrap().policy.prewarm.is_empty());

        // cache persistence on by default; --no-cache-persist disables it.
        assert!(cfg.policy.cache_file.is_some());
        let mut nc = base.clone();
        nc.no_cache_persist = true;
        assert!(nc.resolve().unwrap().policy.cache_file.is_none());

        // gfwlist mode without a gfwlist file is rejected.
        let mut g = base.clone();
        g.mode = Some("gfwlist".to_string());
        assert!(matches!(g.resolve(), Err(ConfigError::Missing(_))));

        // chinadns mode without a chnroute file or geoip database is rejected.
        let mut c = base.clone();
        c.mode = Some("chinadns".to_string());
        assert!(matches!(c.resolve(), Err(ConfigError::Missing(_))));

        // chinadns mode is satisfied by a geoip database alone (default CN).
        let mut cg = base.clone();
        cg.mode = Some("chinadns".to_string());
        cg.geoip = Some(PathBuf::from("/tmp/GeoLite2-Country.mmdb"));
        let cfg = cg.resolve().expect("resolve chinadns+geoip");
        assert_eq!(cfg.policy.mode, Mode::ChinaDns);
        assert_eq!(cfg.policy.geoip_country, "CN");

        // A bare DNS IP gets the default port; bad mode is an error.
        let mut d = base.clone();
        d.dns_local = Some("1.2.3.4".to_string());
        assert_eq!(
            d.resolve().unwrap().policy.dns_local.to_string(),
            "1.2.3.4:53"
        );
        let mut m = base;
        m.mode = Some("bogus".to_string());
        assert!(matches!(m.resolve(), Err(ConfigError::Policy(_))));
    }

    #[test]
    fn keepalive_defaults_overrides_and_validates() {
        let base = ClientArgs {
            config: None,
            server: Some("host:1".to_string()),
            password: Some("pw".to_string()),
            tun_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            peer_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..ClientArgs::empty()
        };
        let cfg = base.clone().resolve().expect("resolve default");
        assert_eq!(cfg.keepalive, Duration::from_secs(DEFAULT_KEEPALIVE_SECS));

        let mut k = base.clone();
        k.keepalive_secs = Some(10);
        assert_eq!(
            k.resolve().unwrap().keepalive,
            Duration::from_secs(10),
            "CLI override wins"
        );

        let mut z = base;
        z.keepalive_secs = Some(0);
        assert!(matches!(
            z.resolve(),
            Err(ConfigError::Invalid {
                field: "keepalive_secs",
                ..
            })
        ));
    }

    #[test]
    fn bundled_data_fallbacks_match_mode() {
        // A unique scratch dir with both bundled data files present.
        let dir = std::env::temp_dir().join(format!(
            "svpn-bundle-test-{}-{:p}",
            std::process::id(),
            &0u8 as *const u8
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let gfw = dir.join(DEFAULT_GFWLIST_NAME);
        let db = dir.join(DEFAULT_GEOIP_DB_NAME);
        std::fs::write(&gfw, b"example.com\n").expect("write dummy gfwlist");
        std::fs::write(&db, b"not a real mmdb").expect("write dummy db");

        // gfwlist fallback: applied in gfwlist and chinadns modes, not full.
        assert_eq!(
            bundled_gfwlist(Mode::GfwList, &dir).as_deref(),
            Some(gfw.as_path())
        );
        assert_eq!(
            bundled_gfwlist(Mode::ChinaDns, &dir).as_deref(),
            Some(gfw.as_path()),
            "chinadns must auto-apply a bundled gfwlist (iOS-aligned force-tunnel override)"
        );
        assert!(bundled_gfwlist(Mode::Full, &dir).is_none());

        // geoip fallback: chinadns only, and only when no chnroute is set.
        assert_eq!(
            bundled_geoip(Mode::ChinaDns, false, &dir).as_deref(),
            Some(db.as_path())
        );
        assert!(bundled_geoip(Mode::ChinaDns, true, &dir).is_none());
        assert!(bundled_geoip(Mode::GfwList, false, &dir).is_none());
        assert!(bundled_geoip(Mode::Full, false, &dir).is_none());

        // An empty dir yields nothing for any mode.
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).expect("create empty subdir");
        assert!(bundled_gfwlist(Mode::ChinaDns, &empty).is_none());
        assert!(bundled_geoip(Mode::ChinaDns, false, &empty).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_config_parses() {
        let json = r#"{
            "server": "1.2.3.4:8388",
            "password": "pw",
            "cipher": "aes-256-gcm",
            "tun_ip": "10.1.0.2",
            "peer_ip": "10.1.0.1"
        }"#;
        let fc: FileConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(fc.server.as_deref(), Some("1.2.3.4:8388"));
        assert_eq!(fc.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(fc.tun_ip, Some(Ipv4Addr::new(10, 1, 0, 2)));
    }

    #[test]
    fn server_nat_flag_and_default_ttl() {
        let args = ServerArgs {
            config: None,
            listen: Some("0.0.0.0:1".to_string()),
            password: Some("pw".to_string()),
            cipher: None,
            tun_name: None,
            tun_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            tun_netmask: None,
            peer_ip: Some(Ipv4Addr::new(10, 9, 0, 2)),
            tun_ip6: None,
            mtu: None,
            nat: true,
            lease_ttl_secs: None,
            approve_routes: None,
            auto_approve_routes: false,
            assign_pool: None,
            reserved_ips: None,
            assign_ttl_secs: None,
            lease_file: None,
        };
        let cfg = args.resolve().expect("resolve");
        assert!(cfg.nat);
        assert_eq!(cfg.lease_ttl, Duration::from_secs(DEFAULT_LEASE_TTL_SECS));
    }

    #[test]
    fn mesh_config_resolves_and_validates() {
        let base = ClientArgs {
            config: None,
            server: Some("host:1".to_string()),
            password: Some("pw".to_string()),
            tun_ip: Some(Ipv4Addr::new(10, 77, 0, 2)),
            peer_ip: Some(Ipv4Addr::new(10, 77, 0, 1)),
            ..ClientArgs::empty()
        };

        // Defaults: no mesh.
        let cfg = base.clone().resolve().expect("resolve");
        assert!(cfg.advertise_routes.is_empty());
        assert!(!cfg.accept_routes);
        assert!(cfg.tun.ip6.is_none());

        // Advertise + accept + tun_ip6 resolve through.
        let mut m = base.clone();
        m.advertise_routes = Some(vec![
            "192.168.200.0/24".parse().unwrap(),
            "fd42:cafe::/64".parse().unwrap(),
        ]);
        m.accept_routes = true;
        m.tun_ip6 = Some("fd07:7::2/64".parse().unwrap());
        let cfg = m.resolve().expect("resolve mesh");
        assert_eq!(cfg.advertise_routes.len(), 2);
        assert!(cfg.accept_routes);
        assert_eq!(cfg.tun.ip6.unwrap().to_string(), "fd07:7::2/64");

        // A default route may not be advertised.
        let mut d = base.clone();
        d.advertise_routes = Some(vec!["0.0.0.0/0".parse().unwrap()]);
        assert!(matches!(
            d.resolve(),
            Err(ConfigError::Invalid {
                field: "advertise_routes",
                ..
            })
        ));

        // More than MAX_ROUTES is rejected.
        let mut o = base;
        o.advertise_routes = Some(
            (0..=MAX_ROUTES)
                .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap())
                .collect(),
        );
        assert!(matches!(
            o.resolve(),
            Err(ConfigError::Invalid {
                field: "advertise_routes",
                ..
            })
        ));
    }

    #[test]
    fn server_mesh_approval_resolves_and_rejects_nat_combo() {
        let base = ServerArgs {
            config: None,
            listen: Some("0.0.0.0:1".to_string()),
            password: Some("pw".to_string()),
            cipher: None,
            tun_name: None,
            tun_ip: Some(Ipv4Addr::new(10, 77, 0, 1)),
            tun_netmask: None,
            peer_ip: Some(Ipv4Addr::new(10, 77, 0, 2)),
            tun_ip6: None,
            mtu: None,
            nat: false,
            lease_ttl_secs: None,
            approve_routes: None,
            auto_approve_routes: false,
            assign_pool: None,
            reserved_ips: None,
            assign_ttl_secs: None,
            lease_file: None,
        };

        let cfg = base.clone().resolve().expect("resolve");
        assert!(!cfg.route_approval.auto);
        assert!(cfg.route_approval.allowlist.is_empty());

        let mut a = base.clone();
        a.approve_routes = Some(vec!["192.168.0.0/16".parse().unwrap()]);
        a.tun_ip6 = Some("fd07:7::1/64".parse().unwrap());
        let cfg = a.resolve().expect("resolve approval");
        assert_eq!(cfg.route_approval.allowlist.len(), 1);
        assert_eq!(cfg.tun.ip6.unwrap().prefix(), 64);

        // Mesh settings + NAT mode are mutually exclusive.
        let mut n = base;
        n.nat = true;
        n.auto_approve_routes = true;
        assert!(matches!(
            n.resolve(),
            Err(ConfigError::Invalid { field: "nat", .. })
        ));
    }

    #[test]
    fn assign_pool_ipv4_subset_and_defaults() {
        let cfg = ServerArgs::test_base().resolve().expect("resolve");
        assert!(cfg.assign_pool.is_none());
        assert_eq!(cfg.reserved_ips, vec![Ipv4Addr::new(10, 9, 0, 2)]);
        assert_eq!(cfg.assign_ttl, Duration::from_secs(DEFAULT_ASSIGN_TTL_SECS));
        #[cfg(not(windows))]
        assert_eq!(
            cfg.lease_file.as_deref(),
            Some(Path::new("/var/lib/shadowvpn/leases.json"))
        );
        #[cfg(windows)]
        {
            let p = cfg.lease_file.expect("default lease file");
            assert_eq!(p.file_name().unwrap(), "leases.json");
            assert!(p.to_string_lossy().contains("shadowvpn"));
        }

        let mut a = ServerArgs::test_base();
        a.assign_pool = Some("10.9.0.128/25".parse().unwrap());
        a.reserved_ips = Some(vec![Ipv4Addr::new(10, 9, 0, 10)]);
        a.assign_ttl_secs = Some(3600);
        a.lease_file = Some("/tmp/leases.json".into());
        let cfg = a.resolve().expect("valid subset");
        assert_eq!(cfg.assign_pool.unwrap().to_string(), "10.9.0.128/25");
        assert_eq!(
            cfg.reserved_ips,
            vec![Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(10, 9, 0, 10)]
        );
        assert_eq!(cfg.assign_ttl, Duration::from_secs(3600));
        assert_eq!(
            cfg.lease_file.as_deref(),
            Some(Path::new("/tmp/leases.json"))
        );

        let mut d = ServerArgs::test_base();
        d.lease_file = Some("-".into());
        assert!(d.resolve().unwrap().lease_file.is_none());

        assert_eq!(
            default_lease_file(Some(Path::new("/etc/shadowvpn/server.json"))),
            PathBuf::from("/etc/shadowvpn/server.json.leases.json")
        );
    }

    #[test]
    fn assign_pool_rejects_ipv6_non_subset_and_degenerate() {
        let mut v6 = ServerArgs::test_base();
        v6.assign_pool = Some("fd07:7::/64".parse().unwrap());
        assert!(matches!(
            v6.resolve(),
            Err(ConfigError::Invalid {
                field: "assign_pool",
                ..
            })
        ));

        let mut outside = ServerArgs::test_base();
        outside.assign_pool = Some("10.8.0.0/24".parse().unwrap());
        assert!(matches!(
            outside.resolve(),
            Err(ConfigError::Invalid {
                field: "assign_pool",
                ..
            })
        ));

        let mut supernet = ServerArgs::test_base();
        supernet.assign_pool = Some("10.9.0.0/16".parse().unwrap());
        assert!(matches!(
            supernet.resolve(),
            Err(ConfigError::Invalid {
                field: "assign_pool",
                ..
            })
        ));

        // /30 = network, server, reserved peer, broadcast → no hosts.
        let mut empty = ServerArgs::test_base();
        empty.assign_pool = Some("10.9.0.0/30".parse().unwrap());
        assert!(matches!(
            empty.resolve(),
            Err(ConfigError::Invalid {
                field: "assign_pool",
                ..
            })
        ));
    }

    #[test]
    fn tun_ip6_prefix_over_96_still_resolves() {
        let mut args = ServerArgs::test_base();
        args.tun_ip6 = Some("fd07:7::1/128".parse().unwrap());
        let cfg = args
            .resolve()
            .expect("static-only /128 hub must still start");
        assert_eq!(cfg.tun.ip6.unwrap().prefix(), 128);
    }

    #[test]
    fn file_config_parses_assign_keys() {
        let json = r#"{
            "server": "0.0.0.0:8388",
            "assign_pool": "10.9.0.128/25",
            "reserved_ips": ["10.9.0.10"],
            "assign_ttl_secs": 3600,
            "lease_file": "-"
        }"#;
        let fc: FileConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(fc.assign_pool.unwrap().to_string(), "10.9.0.128/25");
        assert_eq!(fc.reserved_ips.unwrap(), vec![Ipv4Addr::new(10, 9, 0, 10)]);
        assert_eq!(fc.assign_ttl_secs, Some(3600));
        assert_eq!(fc.lease_file.as_deref(), Some("-"));
    }

    fn auto_client_base() -> ClientArgs {
        ClientArgs {
            server: Some("vpn.example.com:8388".to_string()),
            password: Some("pw".to_string()),
            ..ClientArgs::empty()
        }
    }

    #[test]
    fn tun_ip_and_peer_ip_both_omitted_is_auto_tun() {
        let cfg = auto_client_base().resolve().expect("resolve auto");
        assert!(cfg.auto_tun);
        assert!(cfg.want_ip6);
        assert_eq!(cfg.tun.ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(cfg.tun.peer_ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(cfg.tun.netmask, DEFAULT_NETMASK);
        assert!(cfg.tun.ip6.is_none());
        assert!(cfg.state_file.is_some());
    }

    #[test]
    fn tun_ip_or_peer_ip_alone_is_an_error() {
        let mut ip_only = auto_client_base();
        ip_only.tun_ip = Some(Ipv4Addr::new(10, 9, 0, 2));
        assert!(matches!(
            ip_only.resolve(),
            Err(ConfigError::Invalid {
                field: "tun_ip",
                ..
            })
        ));

        let mut peer_only = auto_client_base();
        peer_only.peer_ip = Some(Ipv4Addr::new(10, 9, 0, 1));
        assert!(matches!(
            peer_only.resolve(),
            Err(ConfigError::Invalid {
                field: "tun_ip",
                ..
            })
        ));
    }

    #[test]
    fn auto_with_static_tun_ip6_clears_want_ip6() {
        let mut args = auto_client_base();
        args.tun_ip6 = Some("fd07:7::2/64".parse().unwrap());
        let cfg = args.resolve().expect("auto + static v6");
        assert!(cfg.auto_tun);
        assert!(!cfg.want_ip6);
        assert_eq!(cfg.tun.ip6.unwrap().to_string(), "fd07:7::2/64");
    }

    #[test]
    fn both_tun_addresses_stay_static() {
        let mut args = auto_client_base();
        args.tun_ip = Some(Ipv4Addr::new(10, 9, 0, 2));
        args.peer_ip = Some(Ipv4Addr::new(10, 9, 0, 1));
        let cfg = args.resolve().expect("static");
        assert!(!cfg.auto_tun);
        assert!(!cfg.want_ip6);
        assert_eq!(cfg.tun.ip, Ipv4Addr::new(10, 9, 0, 2));
        assert_eq!(cfg.tun.peer_ip, Ipv4Addr::new(10, 9, 0, 1));
    }

    #[test]
    fn cache_overlay_still_sends_flag_want_ip6() {
        let mut cfg = auto_client_base().resolve().expect("resolve auto");
        assert!(cfg.want_ip6);
        cfg.overlay_cached_assignment(
            Ipv4Addr::new(10, 9, 0, 37),
            DEFAULT_NETMASK,
            Ipv4Addr::new(10, 9, 0, 1),
            Some("fd07:7::a09:25/64".parse().unwrap()),
        );
        // Overlay wrote tun_ip6; the request flag must still follow want_ip6.
        assert!(cfg.want_ip6);
        assert!(cfg.tun.ip6.is_some());
        let node_id = [
            0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let bytes = cfg.assign_request(node_id);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x03);
        assert_eq!(bytes[2] & FLAG_WANT_IP6, FLAG_WANT_IP6);
        assert_eq!(&bytes[3..19], &node_id);
    }

    #[test]
    fn auto_tick_is_assign_request_not_five_byte_keepalive() {
        let mut cfg = auto_client_base().resolve().expect("resolve auto");
        cfg.overlay_cached_assignment(
            Ipv4Addr::new(10, 9, 0, 37),
            DEFAULT_NETMASK,
            Ipv4Addr::new(10, 9, 0, 1),
            None,
        );
        let node_id = [0x11u8; 16];
        let ticks = cfg.auto_tick_payloads(node_id);
        assert_eq!(ticks.len(), 1, "no mesh → AssignRequest only");
        assert!(ticks[0].starts_with(&[0x00, 0x03]));
        assert_eq!(&ticks[0][3..19], &node_id);
        assert!(
            ticks.iter().all(|p| p.len() != 5),
            "auto mode must not send a 5-byte keepalive"
        );

        cfg.accept_routes = true;
        let mesh_ticks = cfg.auto_tick_payloads(node_id);
        assert_eq!(mesh_ticks.len(), 2);
        assert!(mesh_ticks[0].starts_with(&[0x00, 0x03]));
        assert_eq!(&mesh_ticks[0][3..19], &node_id);
        assert!(mesh_ticks.iter().all(|p| p.len() != 5));
    }

    #[test]
    fn state_file_override_and_default() {
        let mut args = auto_client_base();
        args.state_file = Some(PathBuf::from("/tmp/node.state"));
        let cfg = args.resolve().expect("override");
        assert_eq!(
            cfg.state_file.as_deref(),
            Some(Path::new("/tmp/node.state"))
        );

        let dir = std::env::temp_dir().join(format!(
            "svpn-state-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let cfg_path = dir.join("client.json");
        std::fs::write(&cfg_path, b"{}").expect("write empty config");
        let mut with_cfg = auto_client_base();
        with_cfg.config = Some(cfg_path.clone());
        let cfg = with_cfg.resolve().expect("default next to config");
        let mut expect = cfg_path.into_os_string();
        expect.push(".state");
        assert_eq!(cfg.state_file.as_deref(), Some(Path::new(&expect)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
