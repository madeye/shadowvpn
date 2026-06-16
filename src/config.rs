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
use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::policy::{Mode, PolicyConfig};
use crate::protocol::DEFAULT_TUN_MTU;

/// Default cipher used when none is specified.
pub const DEFAULT_CIPHER: &str = "chacha20-poly1305";

/// Default TUN netmask (a /24).
pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Default address the split-DNS proxy listens on.
pub const DEFAULT_DNS_LISTEN: &str = "127.0.0.1:5353";

/// Default domestic / direct DNS upstream (114DNS).
pub const DEFAULT_DNS_LOCAL: &str = "114.114.114.114:53";

/// Default clean DNS upstream, reached through the tunnel (Google DNS).
pub const DEFAULT_DNS_REMOTE: &str = "8.8.8.8:53";

/// Default ipset name holding tunnel-routed addresses.
pub const DEFAULT_IPSET_NAME: &str = "shadowvpn";

/// Default routing table id / firewall mark for policy routing (0x2333).
pub const DEFAULT_ROUTE_TABLE: u32 = 0x2333;

/// Default per-query DNS upstream timeout, in milliseconds.
pub const DEFAULT_DNS_TIMEOUT_MS: u64 = 3000;

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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Server `host:port`. On the server this is the bind/listen address; on
    /// the client this is the remote address to connect to.
    pub server: Option<String>,

    /// Pre-shared password; the AEAD master key is derived from it.
    pub password: Option<String>,

    /// AEAD cipher name (e.g. `"aes-256-gcm"`).
    pub cipher: Option<String>,

    /// Optional explicit TUN interface name (e.g. `utun7` / `tun0`). If unset,
    /// the OS picks a name.
    pub tun_name: Option<String>,

    /// Local IPv4 address assigned to the TUN interface.
    pub tun_ip: Option<Ipv4Addr>,

    /// IPv4 netmask for the TUN interface.
    pub tun_netmask: Option<Ipv4Addr>,

    /// Peer / point-to-point destination IPv4 address inside the tunnel.
    pub peer_ip: Option<Ipv4Addr>,

    /// TUN interface MTU.
    pub mtu: Option<u16>,

    // --- Client-only policy routing (ignored by the server) ----------------
    /// Policy-routing mode: `full` (default), `gfwlist`, or `chinadns`.
    pub mode: Option<String>,

    /// Address the split-DNS proxy listens on.
    pub dns_listen: Option<String>,

    /// Domestic / direct DNS upstream.
    pub dns_local: Option<String>,

    /// Clean DNS upstream (reached through the tunnel).
    pub dns_remote: Option<String>,

    /// Path to the gfwlist domain file (gfwlist mode).
    pub gfwlist: Option<PathBuf>,

    /// Path to the China route (CIDR) file (chinadns mode).
    pub chnroute: Option<PathBuf>,

    /// Name of the ipset holding tunnel-routed addresses.
    pub ipset_name: Option<String>,

    /// Routing table id used for the tunnel default route.
    pub route_table: Option<u32>,

    /// Firewall mark linking the ipset to the routing table.
    pub fwmark: Option<u32>,

    /// Per-query DNS upstream timeout, in milliseconds.
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
    /// Policy-routing settings (mode `full` means no policy routing).
    pub policy: PolicyConfig,
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

    /// TUN interface MTU.
    #[arg(long = "mtu")]
    pub mtu: Option<u16>,
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

    /// TUN interface MTU.
    #[arg(long = "mtu")]
    pub mtu: Option<u16>,

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

    /// Name of the ipset holding tunnel-routed addresses.
    #[arg(long = "ipset")]
    pub ipset_name: Option<String>,

    /// Routing table id used for the tunnel default route.
    #[arg(long = "route-table")]
    pub route_table: Option<u32>,

    /// Firewall mark linking the ipset to the routing table.
    #[arg(long = "fwmark")]
    pub fwmark: Option<u32>,
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

    let gfwlist = args.gfwlist.clone().or_else(|| file.gfwlist.clone());
    let chnroute = args.chnroute.clone().or_else(|| file.chnroute.clone());

    // Fail fast if the chosen mode is missing its data file.
    if matches!(mode, Mode::GfwList) && gfwlist.is_none() {
        return Err(ConfigError::Missing("gfwlist (required by gfwlist mode)"));
    }
    if matches!(mode, Mode::ChinaDns) && chnroute.is_none() {
        return Err(ConfigError::Missing("chnroute (required by chinadns mode)"));
    }

    Ok(PolicyConfig {
        mode,
        dns_listen,
        dns_local,
        dns_remote,
        gfwlist,
        chnroute,
        ipset_name: args
            .ipset_name
            .clone()
            .or_else(|| file.ipset_name.clone())
            .unwrap_or_else(|| DEFAULT_IPSET_NAME.to_string()),
        route_table: args
            .route_table
            .or(file.route_table)
            .unwrap_or(DEFAULT_ROUTE_TABLE),
        fwmark: args.fwmark.or(file.fwmark).unwrap_or(DEFAULT_ROUTE_TABLE),
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
    mtu: Option<u16>,
) -> Result<TunConfig, ConfigError> {
    Ok(TunConfig {
        name,
        ip: ip.ok_or(ConfigError::Missing("tun_ip"))?,
        netmask: netmask.unwrap_or(DEFAULT_NETMASK),
        peer_ip: peer_ip.ok_or(ConfigError::Missing("peer_ip"))?,
        mtu: mtu.unwrap_or(DEFAULT_TUN_MTU),
    })
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
            self.mtu.or(file.mtu),
        )?;

        Ok(ServerConfig {
            listen,
            cipher,
            master_key,
            tun,
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

        let tun = resolve_tun(
            self.tun_name.or(file.tun_name),
            self.tun_ip.or(file.tun_ip),
            self.tun_netmask.or(file.tun_netmask),
            self.peer_ip.or(file.peer_ip),
            self.mtu.or(file.mtu),
        )?;

        Ok(ClientConfig {
            server,
            cipher,
            master_key,
            tun,
            policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                mtu: None,
                mode: None,
                dns_listen: None,
                dns_local: None,
                dns_remote: None,
                gfwlist: None,
                chnroute: None,
                ipset_name: None,
                route_table: None,
                fwmark: None,
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
            mtu: None,
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
        assert_eq!(cfg.policy.dns_listen.to_string(), "127.0.0.1:5353");
        assert_eq!(cfg.policy.ipset_name, "shadowvpn");

        // gfwlist mode without a gfwlist file is rejected.
        let mut g = base.clone();
        g.mode = Some("gfwlist".to_string());
        assert!(matches!(g.resolve(), Err(ConfigError::Missing(_))));

        // chinadns mode without a chnroute file is rejected.
        let mut c = base.clone();
        c.mode = Some("chinadns".to_string());
        assert!(matches!(c.resolve(), Err(ConfigError::Missing(_))));

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
}
