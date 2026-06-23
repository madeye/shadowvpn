//! Server-side per-client NAT for zero-handshake multi-client support.
//!
//! Every client can run the *same* static config with a fixed placeholder tunnel
//! IP (e.g. `10.9.0.2`). The server tells clients apart by their UDP source
//! address — the one thing already unique per client — and maps each peer to a
//! distinct *internal* IP drawn from the tunnel subnet ([`crate::pool`]). On the
//! way in it rewrites the inner source address (placeholder → internal); on the
//! way out it rewrites the destination back (internal → that peer's placeholder).
//! The host kernel and the wider network only ever see the unique internal IPs,
//! so ordinary masquerade NAT and reply routing work unchanged.
//!
//! This removes the need for any IP-assignment handshake: a client picks its
//! (placeholder) address locally and starts sending immediately — 0-RTT, no
//! control protocol. The trade-off is that clients cannot address *each other*
//! (they all share one placeholder); it is a hub-and-spoke to the server and the
//! networks beyond it.
//!
//! Address rewriting fixes the IPv4 header checksum and, for TCP/UDP, the
//! transport checksum (which covers the pseudo-header) incrementally per
//! RFC 1624. ICMP checksums do not cover the IP addresses, so they need no
//! transport fixup. ICMP *error* payloads embed the original header; rewriting
//! those is a known limitation (PMTU discovery through the tunnel may suffer).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use log::info;

use crate::pool::LeasePool;

/// Per-peer NAT state mapping client UDP endpoints to unique internal IPs.
pub struct Nat {
    /// Allocator + idle-TTL tracker for the internal address space.
    pool: LeasePool,
    /// UDP peer → its session (internal IP + the placeholder it uses).
    by_peer: HashMap<SocketAddr, Session>,
    /// Internal IP → owning UDP peer (for the egress lookup).
    by_internal: HashMap<Ipv4Addr, SocketAddr>,
}

#[derive(Clone, Copy)]
struct Session {
    /// Unique internal IP the host side sees for this client.
    internal: Ipv4Addr,
    /// The placeholder source IP the client actually uses (learned on ingress).
    client_ip: Ipv4Addr,
}

/// Outcome of an ingress rewrite.
pub enum Ingress {
    /// Rewritten in place; forward the packet. Carries the internal IP.
    Rewritten(Ipv4Addr),
    /// No free internal address remained — drop the packet.
    Exhausted,
    /// Not a parseable IPv4 packet — drop it.
    Invalid,
}

impl Nat {
    /// Build a NAT over the host range of `server_ip`'s subnet, with `ttl` as the
    /// idle time after which a client's mapping is reclaimed.
    pub fn new(server_ip: Ipv4Addr, netmask: Ipv4Addr, ttl: Duration) -> Self {
        Self {
            pool: LeasePool::new(server_ip, netmask, ttl),
            by_peer: HashMap::new(),
            by_internal: HashMap::new(),
        }
    }

    /// Number of clients that can be mapped concurrently.
    pub fn capacity(&self) -> usize {
        self.pool.capacity()
    }

    /// Rewrite a client→net packet's source from its placeholder to this peer's
    /// internal IP, allocating a mapping on first sight. Mutates `pkt` in place.
    pub fn ingress(&mut self, peer: SocketAddr, pkt: &mut [u8], now: Instant) -> Ingress {
        let src = match parse_src(pkt) {
            Some(ip) => ip,
            None => return Ingress::Invalid,
        };

        let internal = match self.by_peer.get(&peer) {
            Some(session) => {
                self.pool.refresh(session.internal, now);
                session.internal
            }
            None => {
                let internal = match self.pool.allocate(now) {
                    Some(ip) => ip,
                    None => return Ingress::Exhausted,
                };
                self.by_peer.insert(
                    peer,
                    Session {
                        internal,
                        client_ip: src,
                    },
                );
                self.by_internal.insert(internal, peer);
                info!("nat: {peer} (as {src}) -> internal {internal}");
                internal
            }
        };

        rewrite_addr(pkt, SRC_OFFSET, internal);
        Ingress::Rewritten(internal)
    }

    /// Refresh a peer's mapping without rewriting (e.g. on a keepalive, which
    /// carries no inner IP). No-op if the peer has no mapping yet.
    pub fn touch(&mut self, peer: SocketAddr, now: Instant) {
        if let Some(session) = self.by_peer.get(&peer) {
            self.pool.refresh(session.internal, now);
        }
    }

    /// Rewrite a net→client packet's destination from the internal IP back to the
    /// owning client's placeholder, returning the UDP peer to send it to (or
    /// `None` if the internal IP is unmapped). Mutates `pkt` in place.
    pub fn egress(&mut self, pkt: &mut [u8], now: Instant) -> Option<SocketAddr> {
        let dst = parse_dst(pkt)?;
        let peer = *self.by_internal.get(&dst)?;
        let session = *self.by_peer.get(&peer)?;
        self.pool.refresh(dst, now);
        rewrite_addr(pkt, DST_OFFSET, session.client_ip);
        Some(peer)
    }

    /// Reclaim idle client mappings; returns how many were dropped.
    pub fn reap(&mut self, now: Instant) -> usize {
        let freed = self.pool.reap(now);
        for ip in &freed {
            if let Some(peer) = self.by_internal.remove(ip) {
                self.by_peer.remove(&peer);
                info!("nat: reclaimed idle mapping {ip} ({peer})");
            }
        }
        freed.len()
    }
}

// --- IPv4 header rewriting -------------------------------------------------

/// Byte offset of the source address in an IPv4 header.
const SRC_OFFSET: usize = 12;
/// Byte offset of the destination address in an IPv4 header.
const DST_OFFSET: usize = 16;

/// Source IPv4 address, if `pkt` is a well-formed IPv4 header.
fn parse_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    addr_at(pkt, SRC_OFFSET)
}

/// Destination IPv4 address, if `pkt` is a well-formed IPv4 header.
fn parse_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    addr_at(pkt, DST_OFFSET)
}

fn addr_at(pkt: &[u8], off: usize) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        pkt[off],
        pkt[off + 1],
        pkt[off + 2],
        pkt[off + 3],
    ))
}

/// Overwrite the address at `off` (src or dst) with `new`, fixing the IPv4 header
/// checksum and the TCP/UDP transport checksum (which include the address)
/// incrementally. Assumes `pkt` is a validated IPv4 packet of length ≥ 20.
fn rewrite_addr(pkt: &mut [u8], off: usize, new: Ipv4Addr) {
    let old: [u8; 4] = [pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]];
    let new = new.octets();

    // IPv4 header checksum (bytes 10..12).
    let ip_ck = u16::from_be_bytes([pkt[10], pkt[11]]);
    let ip_ck = adjust_checksum(ip_ck, &old, &new);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    // Transport checksum, only for the first fragment (later fragments carry no
    // L4 header) and when the buffer actually contains it.
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let frag_off = (u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff) != 0;
    if !frag_off {
        match pkt[9] {
            // TCP checksum at L4 + 16.
            6 if pkt.len() >= ihl + 18 => {
                let pos = ihl + 16;
                let ck = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                let ck = adjust_checksum(ck, &old, &new);
                pkt[pos..pos + 2].copy_from_slice(&ck.to_be_bytes());
            }
            // UDP checksum at L4 + 6; 0 means "no checksum", leave it.
            17 if pkt.len() >= ihl + 8 => {
                let pos = ihl + 6;
                let ck = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                if ck != 0 {
                    let ck = adjust_checksum(ck, &old, &new);
                    pkt[pos..pos + 2].copy_from_slice(&ck.to_be_bytes());
                }
            }
            // ICMP etc. (and truncated TCP/UDP): no transport-checksum fixup.
            _ => {}
        }
    }

    pkt[off..off + 4].copy_from_slice(&new);
}

/// Incrementally update a one's-complement checksum for a changed field, per
/// RFC 1624: `HC' = ~(~HC + ~m + m')`, summed over each 16-bit word.
fn adjust_checksum(check: u16, old: &[u8; 4], new: &[u8; 4]) -> u16 {
    let mut sum: u32 = (!check) as u32;
    for i in (0..4).step_by(2) {
        let m = u16::from_be_bytes([old[i], old[i + 1]]);
        let mp = u16::from_be_bytes([new[i], new[i + 1]]);
        sum += (!m) as u32 & 0xffff;
        sum += mp as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One's-complement sum over a byte slice, for full-checksum verification.
    fn ones_complement(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build a UDP/IPv4 packet (header + 4-byte payload) with valid checksums.
    fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let payload = *b"ping";
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        // IP checksum.
        let ck = ones_complement(&p[0..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        // UDP header.
        p[20..22].copy_from_slice(&1111u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&53u16.to_be_bytes()); // dst port
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..32].copy_from_slice(&payload);
        // UDP checksum over pseudo-header + UDP header + payload.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        let ck = ones_complement(&pseudo);
        p[26..28].copy_from_slice(&ck.to_be_bytes());
        p
    }

    /// After verification a correct packet's checksum field folds the whole
    /// region to 0.
    fn ip_checksum_ok(p: &[u8]) -> bool {
        ones_complement(&p[0..20]) == 0
    }
    fn udp_checksum_ok(p: &[u8]) -> bool {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&p[12..16]); // src
        pseudo.extend_from_slice(&p[16..20]); // dst
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&((p.len() - 20) as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        ones_complement(&pseudo) == 0
    }

    #[test]
    fn rewrite_keeps_checksums_valid() {
        let mut p = udp_packet(Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        assert!(ip_checksum_ok(&p) && udp_checksum_ok(&p));

        rewrite_addr(&mut p, SRC_OFFSET, Ipv4Addr::new(10, 9, 0, 37));
        assert_eq!(parse_src(&p), Some(Ipv4Addr::new(10, 9, 0, 37)));
        assert!(ip_checksum_ok(&p), "IP checksum after src rewrite");
        assert!(udp_checksum_ok(&p), "UDP checksum after src rewrite");

        rewrite_addr(&mut p, DST_OFFSET, Ipv4Addr::new(10, 9, 0, 2));
        assert_eq!(parse_dst(&p), Some(Ipv4Addr::new(10, 9, 0, 2)));
        assert!(ip_checksum_ok(&p) && udp_checksum_ok(&p));
    }

    #[test]
    fn ingress_allocates_distinct_internals_per_peer() {
        let mut nat = Nat::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Duration::from_secs(120),
        );
        let now = Instant::now();
        let p1: SocketAddr = "203.0.113.1:5000".parse().unwrap();
        let p2: SocketAddr = "203.0.113.2:5000".parse().unwrap();

        // Both clients use the SAME placeholder; they must map to distinct internals.
        let mut a = udp_packet(Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        let mut b = udp_packet(Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        let ia = match nat.ingress(p1, &mut a, now) {
            Ingress::Rewritten(ip) => ip,
            _ => panic!("ingress p1"),
        };
        let ib = match nat.ingress(p2, &mut b, now) {
            Ingress::Rewritten(ip) => ip,
            _ => panic!("ingress p2"),
        };
        assert_ne!(ia, ib);
        // Idempotent: same peer keeps its internal.
        let mut a2 = udp_packet(Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        assert!(matches!(nat.ingress(p1, &mut a2, now), Ingress::Rewritten(ip) if ip == ia));
    }

    #[test]
    fn egress_maps_back_to_the_right_peer_and_placeholder() {
        let mut nat = Nat::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Duration::from_secs(120),
        );
        let now = Instant::now();
        let peer: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let mut up = udp_packet(Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        let internal = match nat.ingress(peer, &mut up, now) {
            Ingress::Rewritten(ip) => ip,
            _ => panic!("ingress"),
        };

        // A reply addressed to the internal IP routes back to `peer`, dst rewritten
        // to the client's placeholder.
        let mut down = udp_packet(Ipv4Addr::new(8, 8, 8, 8), internal);
        let to = nat.egress(&mut down, now);
        assert_eq!(to, Some(peer));
        assert_eq!(parse_dst(&down), Some(Ipv4Addr::new(10, 9, 0, 2)));
        assert!(ip_checksum_ok(&down) && udp_checksum_ok(&down));

        // An unmapped internal IP has nowhere to go.
        let mut stray = udp_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 9, 0, 200));
        assert_eq!(nat.egress(&mut stray, now), None);
    }

    #[test]
    fn reap_frees_idle_mappings() {
        let mut nat = Nat::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Duration::from_secs(10),
        );
        let t0 = Instant::now();
        let peer: SocketAddr = "203.0.113.5:5000".parse().unwrap();
        let mut up = udp_packet(Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(8, 8, 8, 8));
        let internal = match nat.ingress(peer, &mut up, t0) {
            Ingress::Rewritten(ip) => ip,
            _ => panic!("ingress"),
        };
        assert_eq!(nat.reap(t0 + Duration::from_secs(11)), 1);
        // Mapping gone: a reply to the old internal IP no longer routes.
        let mut down = udp_packet(Ipv4Addr::new(8, 8, 8, 8), internal);
        assert_eq!(nat.egress(&mut down, t0 + Duration::from_secs(11)), None);
    }
}
