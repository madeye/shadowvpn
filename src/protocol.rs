//! Tunnel framing constants for ShadowVPN.
//!
//! ShadowVPN's tunnel framing is intentionally trivial: **the plaintext of each
//! UDP datagram is exactly one raw IP packet** as read from / written to the
//! TUN interface. There is no per-packet length prefix, no SOCKS address
//! header, and no multiplexing — UDP datagram boundaries are the frame
//! boundaries. The only on-wire structure is the cryptographic envelope
//! described in [`crate::crypto`]: `salt ++ AEAD(ciphertext ++ tag)`.
//!
//! This module exposes the size constants needed to size receive buffers
//! correctly on both the encrypted (UDP socket) and plaintext (TUN) sides.

use crate::crypto::{Cipher, TAG_LEN};

/// Default tunnel MTU for the TUN interface, in bytes.
///
/// 1400 leaves comfortable headroom under a typical 1500-byte path MTU for the
/// outer IP + UDP headers and the ShadowVPN crypto overhead (salt + tag), so
/// that an encrypted datagram is unlikely to fragment on a normal Ethernet
/// path.
pub const DEFAULT_TUN_MTU: u16 = 1400;

/// A generous upper bound on the plaintext IP packet size we will read from the
/// TUN device in a single read, in bytes.
///
/// This is the largest IPv4/IPv6 datagram (65535) and bounds the plaintext
/// buffer size regardless of the configured MTU.
pub const MAX_IP_PACKET: usize = 65535;

/// Per-datagram crypto overhead for a given cipher, in bytes: the leading salt
/// plus the trailing AEAD tag.
///
/// `overhead = salt_len + TAG_LEN`. The plaintext (an IP packet) contributes
/// the rest of the datagram. There is no nonce on the wire
/// ([`crate::crypto::NONCE_LEN`] bytes of all-zero nonce are implicit), so it
/// does not appear here.
pub fn crypto_overhead(cipher: Cipher) -> usize {
    cipher.salt_len() + TAG_LEN
}

/// The size, in bytes, that a UDP receive buffer must have to hold the
/// encrypted form of the largest plaintext IP packet for `cipher`.
///
/// Equals [`MAX_IP_PACKET`] plus [`crypto_overhead`].
pub fn max_datagram_size(cipher: Cipher) -> usize {
    MAX_IP_PACKET + crypto_overhead(cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead_matches_salt_plus_tag() {
        // AES-128-GCM: 16-byte salt + 16-byte tag.
        assert_eq!(crypto_overhead(Cipher::Aes128Gcm), 16 + 16);
        // ChaCha20-Poly1305: 32-byte salt + 16-byte tag.
        assert_eq!(crypto_overhead(Cipher::ChaCha20Poly1305), 32 + 16);
    }

    #[test]
    fn nonce_len_is_not_on_wire() {
        // Documented invariant: the 12-byte nonce is implicit, not transmitted.
        assert_eq!(crate::crypto::NONCE_LEN, 12);
    }
}
