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

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::protocol::DEFAULT_TUN_MTU;

/// Default cipher used when none is specified.
pub const DEFAULT_CIPHER: &str = "chacha20-poly1305";

/// Default TUN netmask (a /24).
pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        assert!(matches!(
            args.resolve(),
            Err(ConfigError::Missing("password"))
        ));
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
