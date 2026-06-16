//! China IPv4 route table for **chinadns mode**.
//!
//! A [`ChnRoute`] is the set of IPv4 ranges allocated to China (the classic
//! `chnroute.txt` derived from APNIC delegations). chinadns mode uses it to
//! decide whether a DNS answer points at a domestic address: if the local
//! resolver returns an in-China IP the domain is treated as domestic and left on
//! the direct path; otherwise the clean upstream's answer is trusted and routed
//! through the tunnel.
//!
//! # File format
//!
//! One CIDR per line, e.g. `1.0.1.0/24`. Blank lines and `#` comments are
//! ignored. Ranges are merged on load, so lookups are a binary search over a
//! compact, sorted, non-overlapping set.

use std::net::Ipv4Addr;
use std::path::Path;

/// A merged, sorted set of China IPv4 ranges (inclusive `[start, end]` as
/// `u32`).
#[derive(Debug, Default, Clone)]
pub struct ChnRoute {
    ranges: Vec<(u32, u32)>,
}

impl ChnRoute {
    /// Build a route table from an iterator of raw `a.b.c.d/len` lines.
    ///
    /// Unparsable lines, blanks, and `#` comments are skipped. Overlapping or
    /// adjacent ranges are merged.
    pub fn from_lines<I, S>(lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for line in lines {
            if let Some(r) = parse_cidr(line.as_ref()) {
                ranges.push(r);
            }
        }
        Self {
            ranges: merge(ranges),
        }
    }

    /// Load a route table from a newline-delimited CIDR file.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_lines(text.lines()))
    }

    /// Build a route table directly from inclusive `[start, end]` `u32` ranges
    /// (used by the GeoIP loader). Ranges are sorted and merged.
    pub fn from_ranges(ranges: Vec<(u32, u32)>) -> Self {
        Self {
            ranges: merge(ranges),
        }
    }

    /// Number of merged ranges.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the table has no ranges.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether `ip` falls inside any China range.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        // Find the last range whose start <= v, then check its end.
        match self.ranges.binary_search_by(|&(start, _)| start.cmp(&v)) {
            Ok(_) => true, // v is exactly a range start
            Err(0) => false,
            Err(idx) => {
                let (_, end) = self.ranges[idx - 1];
                v <= end
            }
        }
    }
}

/// Parse one `a.b.c.d/len` line into an inclusive `[start, end]` u32 range.
fn parse_cidr(line: &str) -> Option<(u32, u32)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (addr, len) = line.split_once('/')?;
    let base = u32::from(addr.trim().parse::<Ipv4Addr>().ok()?);
    let len: u32 = len.trim().parse().ok()?;
    if len > 32 {
        return None;
    }
    // mask with `len` leading ones; len==0 means the whole space.
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    let start = base & mask;
    let end = start | !mask;
    Some((start, end))
}

/// Sort and merge overlapping/adjacent ranges into a minimal set.
fn merge(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            // Merge when overlapping or directly adjacent (last.1 + 1 == start).
            if start <= last.1 || (last.1 != u32::MAX && start == last.1 + 1) {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_merges() {
        let r = ChnRoute::from_lines([
            "# comment",
            "1.0.1.0/24",
            "1.0.2.0/23", // adjacent to 1.0.1.0/24 -> merges
            "8.8.8.0/24",
            "garbage",
            "",
        ]);
        // 1.0.1.0/24 + 1.0.2.0/23 are contiguous (1.0.1.0 - 1.0.3.255) -> 1 range,
        // plus 8.8.8.0/24 -> 2 total.
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn contains_china_and_excludes_others() {
        let r = ChnRoute::from_lines(["1.0.1.0/24", "114.114.114.0/24"]);
        assert!(r.contains(ip("1.0.1.0")));
        assert!(r.contains(ip("1.0.1.255")));
        assert!(r.contains(ip("114.114.114.114")));
        assert!(!r.contains(ip("1.0.2.0")));
        assert!(!r.contains(ip("8.8.8.8"))); // Google DNS: not in China
        assert!(!r.contains(ip("0.0.0.0")));
        assert!(!r.contains(ip("255.255.255.255")));
    }

    #[test]
    fn from_ranges_merges_and_looks_up() {
        // Two adjacent ranges merge; lookups still work.
        let r = ChnRoute::from_ranges(vec![
            (u32::from(ip("1.0.0.0")), u32::from(ip("1.0.0.255"))),
            (u32::from(ip("1.0.1.0")), u32::from(ip("1.0.1.255"))),
            (u32::from(ip("8.8.8.0")), u32::from(ip("8.8.8.255"))),
        ]);
        assert_eq!(r.len(), 2);
        assert!(r.contains(ip("1.0.0.7")));
        assert!(r.contains(ip("1.0.1.7")));
        assert!(r.contains(ip("8.8.8.8")));
        assert!(!r.contains(ip("1.0.2.0")));
    }

    #[test]
    fn full_space_contains_everything() {
        let r = ChnRoute::from_lines(["0.0.0.0/0"]);
        assert!(r.contains(ip("0.0.0.0")));
        assert!(r.contains(ip("255.255.255.255")));
        assert!(r.contains(ip("123.45.67.89")));
    }
}
