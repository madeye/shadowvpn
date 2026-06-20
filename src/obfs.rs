//! HTTP/3 (QUIC) traffic-shaping obfuscation for the ShadowVPN UDP carrier.
//!
//! Wraps each finished crypto datagram so it resembles a QUIC 1-RTT
//! (short-header) packet on the wire, and unwraps received packets. This is the
//! server-side counterpart of the iOS client's `obfs` module and **must stay
//! byte-compatible** with it: same first-byte form bits, same fixed 8-byte
//! Destination Connection ID length, same `pn_len = (first & 0x03) + 1` decode.
//!
//! It is cosmetic framing, not a real QUIC stack — it adds no security, only
//! evades naive UDP/protocol classification.
//!
//! # Wire prefix prepended to every datagram
//!
//! ```text
//! [ first byte (1) ] [ DCID (dcid_len) ] [ packet number (PN_LEN) ] [ payload … ]
//!   0b01RR_SPKK         random, per-session   big-endian counter        salt ++ AEAD
//! ```
//!
//! Decoding is self-describing given the shared `dcid_len`: read the first byte,
//! take `pn_len = (first & 0x03) + 1`, then the payload starts at
//! `1 + dcid_len + pn_len`.

use std::sync::atomic::{AtomicU32, Ordering};

use rand::RngExt;

/// Destination Connection ID length, in bytes. Fixed and shared by both ends.
pub const DEFAULT_DCID_LEN: usize = 8;

/// Packet-number length, in bytes, that we emit (QUIC allows 1..=4).
const PN_LEN: usize = 2;

/// Upper bound on the obfs header size (`1 + max DCID + max PN`), used to size
/// receive buffers with headroom regardless of the negotiated `dcid_len`.
pub const MAX_HEADER: usize = 1 + 20 + 4;

/// A QUIC short-header obfuscator for one server. Cheap to share via `Arc`.
pub struct QuicObfs {
    /// Per-process Destination Connection ID used for packets we send.
    dcid: Vec<u8>,
    /// Length of `dcid`, cached so `unwrap` need not read `dcid`.
    dcid_len: usize,
    /// Monotonic packet-number counter (cosmetic).
    pn: AtomicU32,
}

impl QuicObfs {
    /// Build an obfuscator with a fresh random `dcid_len`-byte connection id and
    /// a random initial packet number.
    pub fn new(dcid_len: usize) -> Self {
        let mut dcid = vec![0u8; dcid_len];
        rand::rng().fill(dcid.as_mut_slice());
        let mut seed = [0u8; 4];
        rand::rng().fill(seed.as_mut_slice());
        QuicObfs {
            dcid,
            dcid_len,
            pn: AtomicU32::new(u32::from_be_bytes(seed)),
        }
    }

    /// Prepend the QUIC short-header prefix to a finished crypto `datagram`.
    pub fn wrap(&self, datagram: &[u8]) -> Vec<u8> {
        let pn = self.pn.fetch_add(1, Ordering::Relaxed);

        let mut rnd = [0u8; 1];
        rand::rng().fill(rnd.as_mut_slice());
        let first = 0x40 | (rnd[0] & 0x3C) | ((PN_LEN as u8 - 1) & 0x03);

        let mut out = Vec::with_capacity(self.header_len() + datagram.len());
        out.push(first);
        out.extend_from_slice(&self.dcid);
        out.extend_from_slice(&pn.to_be_bytes()[4 - PN_LEN..]);
        out.extend_from_slice(datagram);
        out
    }

    /// Strip the obfs prefix from a received packet, returning the inner crypto
    /// datagram slice, or `None` if it isn't a QUIC short header / is too short.
    pub fn unwrap<'a>(&self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        let first = *pkt.first()?;
        if first & 0x80 != 0 || first & 0x40 == 0 {
            return None;
        }
        let pn_len = (first & 0x03) as usize + 1;
        let hdr = 1 + self.dcid_len + pn_len;
        if pkt.len() < hdr {
            return None;
        }
        Some(&pkt[hdr..])
    }

    fn header_len(&self) -> usize {
        1 + self.dcid_len + PN_LEN
    }
}

/// Carrier obfuscation applied to every datagram. Both ends must select the same
/// variant; wire formats are documented in DESIGN.md.
pub enum Obfuscator {
    /// QUIC 1-RTT short-header shaping — binary, looks like HTTP/3.
    Quic(QuicObfs),
    /// Base64 of the datagram — the UDP payload is printable ASCII (standard
    /// alphabet, `=` padding). Adds ~33% size, so pair it with a lower MTU.
    Base64,
}

impl Obfuscator {
    /// Build an obfuscator from its config name; `None` for "none"/unknown.
    pub fn from_name(name: &str) -> Option<Obfuscator> {
        match name {
            "quic" => Some(Obfuscator::Quic(QuicObfs::new(DEFAULT_DCID_LEN))),
            "base64" => Some(Obfuscator::Base64),
            _ => None,
        }
    }

    /// Encode a finished crypto datagram for the wire.
    pub fn wrap(&self, datagram: &[u8]) -> Vec<u8> {
        match self {
            Obfuscator::Quic(q) => q.wrap(datagram),
            Obfuscator::Base64 => base64_encode(datagram).into_bytes(),
        }
    }

    /// Decode a received wire packet back to the crypto datagram, or `None` if it
    /// doesn't match this obfuscation (caller drops it).
    pub fn unwrap(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        match self {
            Obfuscator::Quic(q) => q.unwrap(pkt).map(<[u8]>::to_vec),
            Obfuscator::Base64 => base64_decode(pkt),
        }
    }
}

/// Standard base64 alphabet.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Reverse lookup (byte -> 6-bit value, `0xFF` = invalid), built at compile time
/// so decode needs no per-call setup.
const B64_REV: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0;
    while i < 64 {
        t[B64[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// Encode `data` as standard base64 with `=` padding.
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = ((chunk[0] as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 (stopping at `=` padding). Returns `None` on any byte
/// outside the alphabet, so a non-base64 datagram is rejected, not mis-decoded.
fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        if c == b'=' {
            break;
        }
        let v = B64_REV[c as usize];
        if v == 0xFF {
            return None;
        }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_is_printable() {
        for data in [
            &b""[..],
            b"x",
            b"hi!",
            b"\x00\x01\x02\xff\xfe",
            &[0u8; 49][..],
        ] {
            let enc = base64_encode(data);
            assert!(enc.bytes().all(|c| c.is_ascii_graphic()), "printable");
            assert_eq!(base64_decode(enc.as_bytes()).as_deref(), Some(data));
        }
        assert!(base64_decode(b"not base64 !!").is_none());
    }

    #[test]
    fn obfuscator_base64_wrap_unwrap() {
        let o = Obfuscator::Base64;
        let datagram = b"salt ++ AEAD(ciphertext ++ tag)";
        let wire = o.wrap(datagram);
        assert!(wire.iter().all(|b| b.is_ascii_graphic()));
        assert_eq!(o.unwrap(&wire).as_deref(), Some(&datagram[..]));
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let obfs = QuicObfs::new(DEFAULT_DCID_LEN);
        let payload = b"salt ++ AEAD(ciphertext ++ tag)";
        let wire = obfs.wrap(payload);
        assert_eq!(wire.len(), payload.len() + 1 + DEFAULT_DCID_LEN + 2);
        assert_eq!(wire[0] & 0x80, 0);
        assert_eq!(wire[0] & 0x40, 0x40);
        assert_eq!(obfs.unwrap(&wire), Some(&payload[..]));
    }

    #[test]
    fn unwrap_decodes_any_pn_length() {
        let obfs = QuicObfs::new(DEFAULT_DCID_LEN);
        let payload = b"abc";
        for pn_len in 1usize..=4 {
            let mut pkt = vec![0x40 | ((pn_len as u8 - 1) & 0x03)];
            pkt.extend_from_slice(&[0u8; DEFAULT_DCID_LEN]);
            pkt.extend_from_slice(&vec![0u8; pn_len]);
            pkt.extend_from_slice(payload);
            assert_eq!(obfs.unwrap(&pkt), Some(&payload[..]));
        }
    }

    #[test]
    fn unwrap_rejects_non_short_header_and_truncated() {
        let obfs = QuicObfs::new(DEFAULT_DCID_LEN);
        assert!(obfs.unwrap(&[0xC0, 0, 0, 0]).is_none());
        assert!(obfs.unwrap(&[0x00, 0, 0, 0]).is_none());
        assert!(obfs.unwrap(&[0x40, 1, 2]).is_none());
        assert!(obfs.unwrap(&[]).is_none());
    }
}
