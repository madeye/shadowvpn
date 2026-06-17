//! A small TTL-respecting DNS answer cache for the split-DNS proxy.
//!
//! In chinadns/gfwlist mode every uncached lookup pays an upstream round-trip —
//! for tunneled names that round-trip goes through the tunnel, so it is slow.
//! Browsers re-resolve the same handful of names constantly, so caching the
//! decided response (and which addresses it routed through the tunnel) makes
//! repeat lookups effectively free, much like `dnsmasq`'s cache.
//!
//! Entries are keyed by the question `(name, qtype, qclass)` and expire after the
//! answer's minimum TTL (clamped to a sane range). A cache hit returns a copy of
//! the stored response with its transaction id rewritten to match the new query,
//! plus the addresses to (re-)route through the tunnel.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::dns;

/// Maximum number of cached entries before we prune/clear.
const MAX_ENTRIES: usize = 4096;
/// Never cache for less than this (avoids thrashing on tiny TTLs).
const MIN_TTL: u64 = 10;
/// Never cache for longer than this, regardless of the record TTL.
const MAX_TTL: u64 = 3600;
/// TTL to use when a response carries no answer TTL (e.g. NXDOMAIN).
const DEFAULT_TTL: u64 = 30;

struct Entry {
    response: Vec<u8>,
    tunnel_ips: Vec<Ipv4Addr>,
    expires: Instant,
}

/// A thread-safe DNS answer cache.
#[derive(Default)]
pub struct DnsCache {
    map: Mutex<HashMap<(String, u16, u16), Entry>>,
}

impl DnsCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a fresh cached response for `query`. On a hit, returns the
    /// response (with its transaction id set to match `query`) and the addresses
    /// that should be (re-)routed through the tunnel.
    pub fn get(&self, query: &[u8]) -> Option<(Vec<u8>, Vec<Ipv4Addr>)> {
        let key = dns::question(query)?;
        let mut map = self.map.lock().unwrap();
        let entry = map.get(&key)?;
        if Instant::now() >= entry.expires {
            map.remove(&key);
            return None;
        }
        let mut response = entry.response.clone();
        // The stored response carries the original query's id; rewrite it so the
        // stub resolver matches it to *this* query.
        if response.len() >= 2 && query.len() >= 2 {
            response[0] = query[0];
            response[1] = query[1];
        }
        Some((response, entry.tunnel_ips.clone()))
    }

    /// Cache `response` for `query`, remembering which addresses were tunneled.
    pub fn put(&self, query: &[u8], response: &[u8], tunnel_ips: &[Ipv4Addr]) {
        let key = match dns::question(query) {
            Some(k) => k,
            None => return,
        };
        let ttl = dns::min_ttl(response)
            .map(u64::from)
            .unwrap_or(DEFAULT_TTL)
            .clamp(MIN_TTL, MAX_TTL);

        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
            let now = Instant::now();
            map.retain(|_, e| e.expires > now);
            if map.len() >= MAX_ENTRIES {
                map.clear();
            }
        }
        map.insert(
            key,
            Entry {
                response: response.to_vec(),
                tunnel_ips: tunnel_ips.to_vec(),
                expires: Instant::now() + Duration::from_secs(ttl),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str) -> Vec<u8> {
        let [a, b] = id.to_be_bytes();
        let mut m = vec![a, b, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // A / IN
        m
    }

    fn response(q: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[6] = 0;
        m[7] = 1;
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&ip);
        m
    }

    #[test]
    fn miss_then_hit_with_rewritten_id() {
        let c = DnsCache::new();
        let q1 = query(0x1111, "example.com");
        assert!(c.get(&q1).is_none());

        let resp = response(&q1, [93, 184, 216, 34], 300);
        c.put(&q1, &resp, &[Ipv4Addr::new(93, 184, 216, 34)]);

        // A new query for the same name with a *different* id hits the cache and
        // gets the response stamped with the new id.
        let q2 = query(0x2222, "example.com");
        let (hit, ips) = c.get(&q2).expect("cache hit");
        assert_eq!(&hit[0..2], &[0x22, 0x22]);
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        assert_eq!(dns::a_records(&hit), vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn distinct_names_are_separate() {
        let c = DnsCache::new();
        let qa = query(1, "a.com");
        c.put(&qa, &response(&qa, [1, 1, 1, 1], 300), &[]);
        assert!(c.get(&query(2, "a.com")).is_some());
        assert!(c.get(&query(3, "b.com")).is_none());
    }

    #[test]
    fn expired_entry_is_evicted() {
        let c = DnsCache::new();
        let q = query(1, "ttl.com");
        // TTL 0 clamps up to MIN_TTL, so force expiry by inserting a past entry.
        c.put(&q, &response(&q, [1, 2, 3, 4], 300), &[]);
        {
            let mut map = c.map.lock().unwrap();
            let e = map.get_mut(&dns::question(&q).unwrap()).unwrap();
            e.expires = Instant::now() - Duration::from_secs(1);
        }
        assert!(c.get(&q).is_none());
    }
}
