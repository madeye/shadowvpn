//! In-band control frames for dynamic tunnel-IP assignment.
//!
//! Normally a ShadowVPN datagram's plaintext is exactly one raw IP packet (see
//! [`crate::protocol`]). Auto-IP assignment adds a tiny **control channel** that
//! rides the very same AEAD envelope, so control frames are indistinguishable
//! from data on the wire (and work identically under carrier obfuscation).
//!
//! A control frame is recognised by a 4-byte magic prefix:
//!
//! ```text
//! "SVPN" (4) | version (1) | type (1) | payload…
//! ```
//!
//! The magic's first byte (`0x53`) is never a valid IP version nibble (4 or 6),
//! and a real IP packet is at least 20 bytes, so control frames never collide
//! with the data path. Receivers classify a plaintext as: control if it
//! [`parse`]s, else keepalive if shorter than an IP header, else an IP packet.
//!
//! The protocol is deliberately minimal — there is no client identifier. The
//! server keys a lease by the client's *assigned inner IP* and keeps it alive
//! from ongoing traffic (data or keepalive), so reconnects simply draw a fresh
//! lease and idle ones are reclaimed by TTL.

use std::net::Ipv4Addr;

/// Magic prefix marking a control frame (vs. a raw IP packet).
pub const MAGIC: [u8; 4] = *b"SVPN";

/// Control-protocol version. Bumped only on an incompatible frame change.
pub const VERSION: u8 = 1;

// Frame type tags.
const TYPE_REQUEST: u8 = 0x01;
const TYPE_ASSIGN: u8 = 0x02;
const TYPE_NAK: u8 = 0x03;

/// Reason codes carried by [`Control::Nak`].
pub mod nak {
    /// No free address remained in the server's pool.
    pub const POOL_EXHAUSTED: u8 = 1;
    /// The server is not configured to assign addresses.
    pub const NOT_ENABLED: u8 = 2;
}

/// A parsed control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Client → server: please assign me a tunnel address. No payload — the
    /// server identifies the client by the datagram's UDP source address.
    Request,
    /// Server → client: here is your tunnel configuration.
    Assign {
        /// Assigned tunnel IPv4 address for the client's TUN interface.
        ip: Ipv4Addr,
        /// Netmask for the tunnel interface.
        netmask: Ipv4Addr,
        /// The server's tunnel IP, used as the client's point-to-point peer.
        peer_ip: Ipv4Addr,
        /// Tunnel MTU.
        mtu: u16,
    },
    /// Server → client: request refused (see [`nak`] for the reason code).
    Nak(u8),
}

impl Control {
    /// Serialize this control message to its on-wire plaintext (to be encrypted
    /// like any other datagram).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        match *self {
            Control::Request => out.push(TYPE_REQUEST),
            Control::Assign {
                ip,
                netmask,
                peer_ip,
                mtu,
            } => {
                out.push(TYPE_ASSIGN);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&netmask.octets());
                out.extend_from_slice(&peer_ip.octets());
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            Control::Nak(reason) => {
                out.push(TYPE_NAK);
                out.push(reason);
            }
        }
        out
    }
}

/// Whether `plaintext` is a control frame (begins with the magic prefix).
///
/// Cheaper than a full [`parse`] for the hot data path: a `false` here means the
/// plaintext is a keepalive or an IP packet and should be handled normally.
pub fn is_control(plaintext: &[u8]) -> bool {
    plaintext.len() >= MAGIC.len() && plaintext[..MAGIC.len()] == MAGIC
}

/// Parse a control frame, or `None` if `plaintext` is not a (well-formed,
/// known-version) control frame — in which case the caller treats it as data.
pub fn parse(plaintext: &[u8]) -> Option<Control> {
    if !is_control(plaintext) {
        return None;
    }
    // magic(4) + version(1) + type(1) header.
    if plaintext.len() < 6 || plaintext[4] != VERSION {
        return None;
    }
    let body = &plaintext[6..];
    match plaintext[5] {
        TYPE_REQUEST => Some(Control::Request),
        TYPE_ASSIGN => {
            // ip(4) + netmask(4) + peer(4) + mtu(2) = 14 bytes.
            if body.len() < 14 {
                return None;
            }
            Some(Control::Assign {
                ip: ipv4(&body[0..4]),
                netmask: ipv4(&body[4..8]),
                peer_ip: ipv4(&body[8..12]),
                mtu: u16::from_be_bytes([body[12], body[13]]),
            })
        }
        TYPE_NAK => body.first().copied().map(Control::Nak),
        _ => None,
    }
}

/// Build an `Ipv4Addr` from a 4-byte slice (caller guarantees the length).
fn ipv4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(c: Control) {
        let bytes = c.encode();
        assert!(is_control(&bytes));
        assert_eq!(parse(&bytes), Some(c));
    }

    #[test]
    fn round_trips_all_frames() {
        roundtrip(Control::Request);
        roundtrip(Control::Assign {
            ip: Ipv4Addr::new(10, 9, 0, 42),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            peer_ip: Ipv4Addr::new(10, 9, 0, 1),
            mtu: 1400,
        });
        roundtrip(Control::Nak(nak::POOL_EXHAUSTED));
    }

    #[test]
    fn ip_packets_are_not_control() {
        // A typical IPv4 header (version 4, IHL 5) and a keepalive byte.
        let ipv4_pkt = [0x45u8; 20];
        assert!(!is_control(&ipv4_pkt));
        assert_eq!(parse(&ipv4_pkt), None);
        assert!(!is_control(&[0x00]));
    }

    #[test]
    fn rejects_unknown_version_and_type() {
        let mut wrong_ver = Control::Request.encode();
        wrong_ver[4] = 0xFF;
        assert_eq!(parse(&wrong_ver), None);

        let unknown_type = [b'S', b'V', b'P', b'N', VERSION, 0x7F];
        assert_eq!(parse(&unknown_type), None);
    }

    #[test]
    fn rejects_truncated_assign() {
        let mut bytes = Control::Assign {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            peer_ip: Ipv4Addr::new(1, 2, 3, 1),
            mtu: 1400,
        }
        .encode();
        bytes.truncate(10); // header + a few bytes only
        assert_eq!(parse(&bytes), None);
    }
}
