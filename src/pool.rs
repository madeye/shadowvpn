//! Tunnel-IP allocation pool with TTL leases.
//!
//! Allocates host addresses from the server's TUN subnet (network and broadcast
//! addresses and the server's own IP excluded) and tracks a per-IP lease. A
//! lease is refreshed by any traffic from its client (data packet or keepalive)
//! and reclaimed once it has been idle longer than the TTL — so an abandoned
//! address is freed for reuse.
//!
//! Used by [`crate::nat`] to hand each client (keyed by its UDP endpoint) a
//! distinct internal IP.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A pool of assignable tunnel IPv4 addresses with TTL-based leases.
pub struct LeasePool {
    /// First assignable host address (inclusive), as a host-order `u32`.
    start: u32,
    /// Last assignable host address (inclusive), as a host-order `u32`.
    end: u32,
    /// The server's own tunnel IP, never handed out.
    server_ip: u32,
    /// Idle time after which a lease is reclaimed.
    ttl: Duration,
    /// `ip -> last-seen`. Presence means leased.
    leases: HashMap<u32, Instant>,
    /// Round-robin cursor so a just-freed IP is not immediately reused.
    cursor: u32,
}

impl LeasePool {
    /// Build a pool spanning the host addresses of `server_ip`'s subnet (per
    /// `netmask`), excluding the network, broadcast, and server addresses.
    pub fn new(server_ip: Ipv4Addr, netmask: Ipv4Addr, ttl: Duration) -> Self {
        let ip = u32::from(server_ip);
        let mask = u32::from(netmask);
        let network = ip & mask;
        let broadcast = network | !mask;
        // First/last host; for a degenerate mask (/31, /32) this yields an empty
        // range (start > end), which `allocate` reports as exhausted.
        let start = network.saturating_add(1);
        let end = broadcast.saturating_sub(1);
        Self {
            start,
            end,
            server_ip: ip,
            ttl,
            leases: HashMap::new(),
            cursor: start,
        }
    }

    /// Number of addresses that could ever be assigned (excludes the server IP
    /// when it falls inside the host range).
    pub fn capacity(&self) -> usize {
        if self.end < self.start {
            return 0;
        }
        let span = (self.end - self.start + 1) as usize;
        if (self.start..=self.end).contains(&self.server_ip) {
            span - 1
        } else {
            span
        }
    }

    /// Allocate the next free address, recording a lease stamped `now`, or `None`
    /// if every address is leased (pool exhausted).
    pub fn allocate(&mut self, now: Instant) -> Option<Ipv4Addr> {
        if self.end < self.start {
            return None;
        }
        let span = self.end - self.start + 1;
        for _ in 0..span {
            let cand = self.cursor;
            self.cursor = if cand >= self.end {
                self.start
            } else {
                cand + 1
            };
            if cand == self.server_ip || self.leases.contains_key(&cand) {
                continue;
            }
            self.leases.insert(cand, now);
            return Some(Ipv4Addr::from(cand));
        }
        None
    }

    /// Refresh the lease for `ip` to `now`. Returns `false` if `ip` is not a
    /// currently leased address.
    pub fn refresh(&mut self, ip: Ipv4Addr, now: Instant) -> bool {
        if let Some(slot) = self.leases.get_mut(&u32::from(ip)) {
            *slot = now;
            true
        } else {
            false
        }
    }

    /// Whether `ip` currently holds a lease.
    pub fn is_leased(&self, ip: Ipv4Addr) -> bool {
        self.leases.contains_key(&u32::from(ip))
    }

    /// Reclaim every lease idle longer than the TTL, returning the freed
    /// addresses so the caller can drop its own per-IP routing state.
    pub fn reap(&mut self, now: Instant) -> Vec<Ipv4Addr> {
        let ttl = self.ttl;
        let expired: Vec<u32> = self
            .leases
            .iter()
            .filter(|(_, &seen)| now.duration_since(seen) > ttl)
            .map(|(&ip, _)| ip)
            .collect();
        for ip in &expired {
            self.leases.remove(ip);
        }
        expired.into_iter().map(Ipv4Addr::from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> LeasePool {
        // 10.9.0.1/24 server -> hosts .1..=.254, minus .1 (server).
        LeasePool::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Duration::from_secs(120),
        )
    }

    #[test]
    fn allocates_distinct_addresses_skipping_the_server() {
        let mut p = pool();
        let now = Instant::now();
        let a = p.allocate(now).unwrap();
        let b = p.allocate(now).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, Ipv4Addr::new(10, 9, 0, 1));
        assert_ne!(b, Ipv4Addr::new(10, 9, 0, 1));
        // Both inside the subnet host range.
        for ip in [a, b] {
            assert!(ip > Ipv4Addr::new(10, 9, 0, 1) || ip < Ipv4Addr::new(10, 9, 0, 1));
            assert!(p.is_leased(ip));
        }
    }

    #[test]
    fn capacity_excludes_network_broadcast_and_server() {
        // /24 has 254 hosts; minus the server IP => 253 assignable.
        assert_eq!(pool().capacity(), 253);
    }

    #[test]
    fn exhaustion_returns_none() {
        // Tiny subnet: 10.0.0.0/30 with server .1 -> hosts .1,.2, minus .1 => 1.
        let mut p = LeasePool::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 252),
            Duration::from_secs(60),
        );
        let now = Instant::now();
        assert_eq!(p.capacity(), 1);
        assert!(p.allocate(now).is_some());
        assert!(p.allocate(now).is_none());
    }

    #[test]
    fn refresh_only_known_leases() {
        let mut p = pool();
        let now = Instant::now();
        let ip = p.allocate(now).unwrap();
        assert!(p.refresh(ip, now));
        assert!(!p.refresh(Ipv4Addr::new(10, 9, 0, 200), now));
    }

    #[test]
    fn reap_reclaims_idle_leases_and_frees_them() {
        let mut p = LeasePool::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Duration::from_secs(120),
        );
        let t0 = Instant::now();
        let ip = p.allocate(t0).unwrap();
        // Not yet expired.
        assert!(p.reap(t0 + Duration::from_secs(60)).is_empty());
        assert!(p.is_leased(ip));
        // Past the TTL: reclaimed and reported.
        let freed = p.reap(t0 + Duration::from_secs(121));
        assert_eq!(freed, vec![ip]);
        assert!(!p.is_leased(ip));
    }
}
