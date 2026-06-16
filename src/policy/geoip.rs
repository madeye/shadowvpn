//! Build the China IP set from a MaxMind GeoLite2 database.
//!
//! As an alternative to a hand-maintained `chnroute.txt`, chinadns mode can read
//! a `GeoLite2-Country.mmdb` (or the paid GeoIP2 equivalent) and enumerate every
//! IPv4 network whose country matches a chosen ISO code (default `CN`). The
//! result is folded into the same [`ChnRoute`] structure used everywhere else,
//! so the per-query decision path is unchanged and stays a fast binary search.
//!
//! Only IPv4 is collected — ShadowVPN's policy routing is IPv4-only.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use ipnetwork::{IpNetwork, Ipv4Network};
use maxminddb::{geoip2, Reader, WithinOptions};

use super::chnroute::ChnRoute;

/// Load all IPv4 networks for `country` (an ISO 3166-1 alpha-2 code such as
/// `CN`) from the GeoLite2/GeoIP2 country database at `path`, returning them as a
/// merged [`ChnRoute`].
pub fn load_country_routes(path: impl AsRef<Path>, country: &str) -> Result<ChnRoute> {
    let path = path.as_ref();
    let reader = Reader::open_readfile(path)
        .with_context(|| format!("opening GeoIP database {}", path.display()))?;

    // Walk the whole IPv4 space; the iterator yields the most specific networks.
    let all_v4 = IpNetwork::V4(
        Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is a valid network"),
    );

    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for item in reader
        .within(all_v4, WithinOptions::default())
        .context("iterating GeoIP networks")?
    {
        let item = item.context("decoding a GeoIP network")?;
        // Restrict to real IPv4 networks (skip IPv4-in-IPv6 representations).
        let net = match item.network().context("reading GeoIP network")? {
            IpNetwork::V4(v4) => v4,
            IpNetwork::V6(_) => continue,
        };
        let record: Option<geoip2::Country> = item.decode().context("decoding GeoIP country")?;
        if country_matches(record.as_ref(), country) {
            ranges.push((u32::from(net.network()), u32::from(net.broadcast())));
        }
    }

    Ok(ChnRoute::from_ranges(ranges))
}

/// Whether a decoded country record's ISO code equals `want` (case-insensitive).
fn country_matches(record: Option<&geoip2::Country>, want: &str) -> bool {
    record
        .and_then(|r| r.country.iso_code)
        .is_some_and(|iso| iso.eq_ignore_ascii_case(want))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(iso: Option<&'static str>) -> geoip2::Country<'static> {
        let mut c = geoip2::Country::default();
        c.country.iso_code = iso;
        c
    }

    #[test]
    fn matches_iso_code_case_insensitively() {
        let cn = record(Some("CN"));
        assert!(country_matches(Some(&cn), "CN"));
        assert!(country_matches(Some(&cn), "cn")); // case-insensitive
        assert!(!country_matches(Some(&cn), "US"));
        assert!(!country_matches(Some(&record(None)), "CN")); // no iso_code
        assert!(!country_matches(None, "CN")); // network without data
    }

    #[test]
    fn missing_database_is_an_error() {
        assert!(load_country_routes("/nonexistent/GeoLite2-Country.mmdb", "CN").is_err());
    }
}
