//! # ShadowVPN
//!
//! A UDP-based, pre-shared-key (PSK), user-mode VPN written in Rust.
//!
//! ShadowVPN is a fixed point-to-point / multi-client tunnel. A TUN-based
//! client reads IP packets from a virtual interface, encrypts each as a single
//! UDP datagram, and sends it to the server; the server decrypts, routes, and
//! tunnels return traffic back. The async runtime is [`tokio`].
//!
//! ## Wire protocol
//!
//! The on-wire crypto matches the **shadowsocks.org AEAD UDP scheme** exactly,
//! so the construction is spec-correct and interoperable. Each UDP datagram is:
//!
//! ```text
//! [ salt (salt_len bytes) ] ++ [ AEAD ciphertext ++ tag ]
//! ```
//!
//! with `salt_len == key_len`, a random per-datagram salt, a subkey of
//! `HKDF-SHA1(master_key, salt, "ss-subkey")`, and an all-zero 12-byte nonce.
//! The master key is derived from the password with OpenSSL's legacy
//! `EVP_BytesToKey` (MD5) KDF. See [`crypto`] for the full description.
//!
//! **Deviation from ss-proxy:** the plaintext is the raw IP packet from TUN,
//! with no SOCKS address header — this is a tunnel, not a SOCKS proxy. See
//! [`protocol`].
//!
//! ## Multiple clients
//!
//! One server serves many clients. By default it routes by *learning* each
//! client's inner tunnel source IP, so clients need distinct addresses. With the
//! server's NAT mode every client may share one identical config (same
//! placeholder IP): the server tells them apart by UDP endpoint and maps each
//! onto a distinct internal IP, rewriting inner addresses in flight. See [`nat`]
//! and [`pool`].
//!
//! ## Binaries
//!
//! This crate ships three binaries: `shadowvpn-server` and `shadowvpn-client`
//! (always built), and `shadowvpn-uri` — a config import/export tool gated behind
//! the optional `uri` feature so the server/client builds stay lean (see the
//! `uri` module, compiled only with that feature).
//!
//! ## Modules
//!
//! * [`crypto`] — cipher abstraction, key derivation, packet encrypt/decrypt.
//! * [`config`] — JSON + CLI configuration for the server and client.
//! * [`protocol`] — tunnel framing constants and buffer sizing.
//! * [`obfs`] — optional carrier obfuscation (QUIC/HTTP3-shaped or base64).
//! * [`tun_device`] — async TUN interface wrapper (macOS utun + Linux + Windows).
//! * [`policy`] — client-side policy routing (gfwlist / chinadns split tunnel).
//! * [`nat`] — server-side per-client NAT (multiple clients, one shared config).
//! * [`pool`] — internal-IP allocation pool used by [`nat`].
//! * `uri` — `shadowvpn://` config import/export + QR codes (feature `uri`).

#![warn(missing_docs)]

pub mod config;
pub mod crypto;
pub mod nat;
pub mod obfs;
pub mod policy;
pub mod pool;
pub mod protocol;
pub mod tun_device;
#[cfg(feature = "uri")]
pub mod uri;
