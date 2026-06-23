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
//! ## Modules
//!
//! * [`crypto`] — cipher abstraction, key derivation, packet encrypt/decrypt.
//! * [`config`] — JSON + CLI configuration for the server and client.
//! * [`protocol`] — tunnel framing constants and buffer sizing.
//! * [`tun_device`] — async TUN interface wrapper (macOS utun + Linux).
//! * [`policy`] — client-side policy routing (gfwlist / chinadns + ipset).

#![warn(missing_docs)]

pub mod config;
pub mod crypto;
pub mod nat;
pub mod obfs;
pub mod policy;
pub mod pool;
pub mod protocol;
pub mod tun_device;
pub mod uri;
