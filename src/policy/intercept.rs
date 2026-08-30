//! User-mode DNS intercept on the TUN path.
//!
//! IPv4 UDP packets destined to port 53 are classified here and answered
//! locally instead of being encrypted to the server. The split-DNS
//! [`Resolver`](super::proxy::Resolver) produces the DNS payload; this
//! module only parses TUN frames and builds checksum-valid IPv4/UDP replies
//! with swapped endpoints.
//!
//! Host DNS reaches the TUN without rewriting the OS nameserver to
//! `127.0.0.1`: [`attract_destinations`] collects well-known public resolvers
//! plus the host's current non-loopback nameservers so `/32` tun routes can
//! steal those queries. Loopback stubs (systemd-resolved `127.0.0.53`, Docker
//! `127.0.0.11`, …) never appear on TUN — the hijack is of the stub's
//! *upstream* destinations.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

/// UDP destination port that identifies a DNS query on the TUN.
const DNS_PORT: u16 = 53;
/// IPv4 header: version 4, IHL 5 (20 bytes), no options.
const IPV4_VIHL: u8 = 0x45;
/// IPv4 protocol number for UDP.
const PROTO_UDP: u8 = 17;
/// Default TTL for synthesized replies.
const REPLY_TTL: u8 = 64;

/// Well-known public resolvers. A `/32` tun route for each attracts host DNS
/// onto the intercept path without pointing the OS resolver at loopback.
pub const WELL_KNOWN_DNS: &[Ipv4Addr] = &[
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(8, 8, 4, 4),
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(1, 0, 0, 1),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(149, 112, 112, 112),
    Ipv4Addr::new(208, 67, 222, 222),
    Ipv4Addr::new(208, 67, 220, 220),
    Ipv4Addr::new(114, 114, 114, 114),
    Ipv4Addr::new(114, 114, 115, 115),
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(223, 6, 6, 6),
    Ipv4Addr::new(180, 76, 76, 76),
    Ipv4Addr::new(119, 29, 29, 29),
];

/// Files that may list the host's real DNS upstreams. `/etc/resolv.conf` is
/// often a loopback stub; systemd-resolved's non-stub file has the actual
/// destinations we can hijack onto the TUN.
const RESOLV_PATHS: &[&str] = &["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"];

/// A DNS query extracted from a TUN IPv4/UDP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// IPv4 source of the query (reply destination).
    pub src: Ipv4Addr,
    /// IPv4 destination of the query (reply source) — any address, not only
    /// loopback; public resolvers such as `8.8.8.8` are the common case.
    pub dst: Ipv4Addr,
    /// UDP source port (reply destination port).
    pub src_port: u16,
    /// UDP destination port (always 53 for a classified query).
    pub dst_port: u16,
    /// Raw DNS message (UDP payload).
    pub payload: Vec<u8>,
}

/// Classify a TUN frame as a DNS query to intercept, or pass-through.
///
/// Returns [`Some`] only for a well-formed, non-fragmented IPv4 UDP packet
/// whose destination port is 53. Truncated, non-IPv4, non-UDP, or non-53
/// packets return [`None`] and never panic.
pub fn classify(pkt: &[u8]) -> Option<DnsQuery> {
    if pkt.len() < 20 {
        return None;
    }
    // Version 4, IHL in 5..=15 words and in-bounds.
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > pkt.len() {
        return None;
    }
    if pkt[9] != PROTO_UDP {
        return None;
    }
    // First fragment only, and no more-fragments: we need the whole UDP
    // datagram to answer it. Later fragments have no UDP header.
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x1fff != 0 {
        return None;
    }
    if frag & 0x2000 != 0 {
        return None;
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total < ihl + 8 || total > pkt.len() {
        return None;
    }
    let udp = &pkt[ihl..total];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != DNS_PORT {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    Some(DnsQuery {
        src,
        dst,
        src_port,
        dst_port,
        payload: udp[8..udp_len].to_vec(),
    })
}

/// Build an IPv4/UDP reply for `query` carrying `dns_response` as the payload.
///
/// Endpoints are swapped (original dest becomes source, original src becomes
/// dest; UDP ports likewise). The IPv4 header checksum and UDP checksum are
/// valid. `dns_response` is copied verbatim — typically the bytes returned by
/// [`Resolver::resolve`](super::proxy::Resolver::resolve).
pub fn build_reply(query: &DnsQuery, dns_response: &[u8]) -> Vec<u8> {
    let udp_len = 8 + dns_response.len();
    let total = 20 + udp_len;
    let mut p = vec![0u8; total];
    p[0] = IPV4_VIHL;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = REPLY_TTL;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&query.dst.octets());
    p[16..20].copy_from_slice(&query.src.octets());
    let ip_ck = checksum(&p[0..20]);
    p[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    p[20..22].copy_from_slice(&query.dst_port.to_be_bytes());
    p[22..24].copy_from_slice(&query.src_port.to_be_bytes());
    p[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    p[28..].copy_from_slice(dns_response);
    let udp_ck = udp_checksum(&p);
    // IPv4 UDP: a computed 0 is transmitted as 0xFFFF (0 means "no checksum").
    let udp_ck = if udp_ck == 0 { 0xffff } else { udp_ck };
    p[26..28].copy_from_slice(&udp_ck.to_be_bytes());
    p
}

/// IPv4 addresses that should get a `/32` tun route so host DNS queries land
/// on the intercept path.
///
/// Combines [`WELL_KNOWN_DNS`], `extra` (typically `dns_local` / `dns_remote`),
/// and non-loopback nameservers from the host's resolv.conf files. Loopback,
/// unspecified, multicast, and broadcast addresses are dropped — those never
/// appear on TUN.
pub fn attract_destinations(extra: impl IntoIterator<Item = Ipv4Addr>) -> Vec<Ipv4Addr> {
    collect_attract(
        WELL_KNOWN_DNS.iter().copied(),
        extra,
        read_resolv_nameservers(),
    )
}

/// Name of the interface that owns `ip`, if any (Unix `getifaddrs`).
///
/// Used to pin direct (domestic) DNS sockets to the physical NIC so they do
/// not follow a tun `/32` that was installed to attract host DNS.
#[cfg(unix)]
pub fn interface_name_for_ip(ip: IpAddr) -> Option<String> {
    interface_name_for_ip_unix(ip)
}

#[cfg(not(unix))]
pub fn interface_name_for_ip(_ip: IpAddr) -> Option<String> {
    None
}

fn collect_attract(
    well_known: impl IntoIterator<Item = Ipv4Addr>,
    extra: impl IntoIterator<Item = Ipv4Addr>,
    from_files: impl IntoIterator<Item = Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for ip in well_known.into_iter().chain(extra).chain(from_files) {
        if !is_attractable(ip) {
            continue;
        }
        if seen.insert(ip) {
            out.push(ip);
        }
    }
    out
}

fn is_attractable(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
}

fn read_resolv_nameservers() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    for path in RESOLV_PATHS {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        parse_resolv_nameservers(&text, &mut ips);
    }
    ips
}

fn parse_resolv_nameservers(text: &str, ips: &mut Vec<Ipv4Addr>) {
    for line in text.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("nameserver") {
            Some(r) => r,
            None => continue,
        };
        let addr = rest.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = addr.parse::<Ipv4Addr>() {
            ips.push(ip);
        }
    }
}

/// Internet checksum (one's complement of the one's-complement sum).
fn checksum(bytes: &[u8]) -> u16 {
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

/// UDP checksum over the IPv4 pseudo-header + UDP header + payload.
fn udp_checksum(pkt: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src, dst, zero, proto, UDP length.
    for i in (12..20).step_by(2) {
        sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
    }
    sum += PROTO_UDP as u32;
    let udp_len = (pkt.len() - 20) as u32;
    sum += udp_len;
    let mut i = 20;
    while i + 1 < pkt.len() {
        sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        i += 2;
    }
    if i < pkt.len() {
        sum += (pkt[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(unix)]
fn interface_name_for_ip_unix(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;

    // SAFETY: `getifaddrs` writes a linked list we walk and then free with
    // `freeifaddrs`. Pointers are valid for the duration of the walk.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut found = None;
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if let Some(addr) = sockaddr_ip(ifa.ifa_addr) {
                if addr == ip && !ifa.ifa_name.is_null() {
                    found = CStr::from_ptr(ifa.ifa_name)
                        .to_str()
                        .ok()
                        .map(str::to_owned);
                    break;
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found
    }
}

/// SAFETY: `sa` must be a valid `sockaddr` (or null).
#[cfg(unix)]
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let sin = &*(sa as *const libc::sockaddr_in);
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let sin6 = &*(sa as *const libc::sockaddr_in6);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magic::PeerTable;
    use crate::policy::cache::DnsCache;
    use crate::policy::chnroute::ChnRoute;
    use crate::policy::dns;
    use crate::policy::gfwlist::GfwList;
    use crate::policy::proxy::{IpSink, Resolver};
    use crate::policy::Mode;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::UdpSocket;

    const MAX_DNS_MSG: usize = 4096;

    fn ones_complement(bytes: &[u8]) -> u16 {
        checksum(bytes)
    }

    fn ip_checksum_ok(p: &[u8]) -> bool {
        ones_complement(&p[0..20]) == 0
    }

    fn udp_checksum_ok_or_omitted(p: &[u8]) -> bool {
        let ck = u16::from_be_bytes([p[26], p[27]]);
        if ck == 0 {
            return true;
        }
        let mut sum: u32 = 0;
        for i in (12..20).step_by(2) {
            sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
        }
        sum += PROTO_UDP as u32;
        sum += (p.len() - 20) as u32;
        let mut i = 20;
        while i + 1 < p.len() {
            sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
            i += 2;
        }
        if i < p.len() {
            sum += (p[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    /// Build a UDP/IPv4 packet with valid checksums, independently of
    /// [`build_reply`] (the unit under test).
    fn udp_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut p = vec![0u8; total];
        p[0] = IPV4_VIHL;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = REPLY_TTL;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ck = checksum(&p[0..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        let udp_ck = udp_checksum(&p);
        let udp_ck = if udp_ck == 0 { 0xffff } else { udp_ck };
        p[26..28].copy_from_slice(&udp_ck.to_be_bytes());
        p
    }

    #[test]
    fn udp_53_to_public_resolver_is_intercept() {
        let payload = dns::build_query(0x1234, "example.com");
        let src = Ipv4Addr::new(10, 9, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let pkt = udp_packet(src, dst, 54321, 53, &payload);
        let q = classify(&pkt).expect("UDP/53 to 8.8.8.8 is intercept");
        assert_eq!(q.src, src);
        assert_eq!(q.dst, dst);
        assert_eq!(q.src_port, 54321);
        assert_eq!(q.dst_port, 53);
        assert_eq!(q.payload, payload);
    }

    #[test]
    fn udp_non_53_is_not_intercept() {
        let pkt = udp_packet(
            Ipv4Addr::new(10, 9, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            1234,
            443,
            b"not dns",
        );
        assert!(classify(&pkt).is_none());
    }

    #[test]
    fn tcp_is_not_intercept() {
        let mut pkt = udp_packet(
            Ipv4Addr::new(10, 9, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            1234,
            53,
            b"xxxx",
        );
        pkt[9] = 6; // TCP
                    // Header checksum no longer matters; classify must not panic.
        assert!(classify(&pkt).is_none());
    }

    #[test]
    fn truncated_and_non_ipv4_do_not_panic_or_reply() {
        assert!(classify(&[]).is_none());
        assert!(classify(&[0u8; 8]).is_none());
        // IPv6 version nibble.
        let mut v6 = udp_packet(
            Ipv4Addr::new(10, 9, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            1,
            53,
            b"q",
        );
        v6[0] = 0x60;
        assert!(classify(&v6).is_none());
        // IHL claims 60 bytes on a 28-byte packet.
        let mut short = udp_packet(
            Ipv4Addr::new(10, 9, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            1,
            53,
            b"q",
        );
        short.truncate(28);
        short[0] = 0x4f;
        assert!(classify(&short).is_none());
        // UDP header truncated (IP total length too small).
        let mut tiny = udp_packet(
            Ipv4Addr::new(10, 9, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            1,
            53,
            b"",
        );
        tiny.truncate(24);
        tiny[2..4].copy_from_slice(&24u16.to_be_bytes());
        assert!(classify(&tiny).is_none());
    }

    #[test]
    fn reply_swaps_endpoints_and_has_valid_checksums() {
        let payload = b"\x12\x34dns-query-bytes";
        let src = Ipv4Addr::new(10, 9, 0, 2);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let pkt = udp_packet(src, dst, 40000, 53, payload);
        let q = classify(&pkt).unwrap();
        let resp = b"\x12\x34dns-response-bytes";
        let reply = build_reply(&q, resp);
        assert_eq!(&reply[12..16], &dst.octets(), "reply src is original dst");
        assert_eq!(&reply[16..20], &src.octets(), "reply dst is original src");
        assert_eq!(
            u16::from_be_bytes([reply[20], reply[21]]),
            53,
            "reply src port is 53"
        );
        assert_eq!(
            u16::from_be_bytes([reply[22], reply[23]]),
            40000,
            "reply dst port is original src port"
        );
        assert_eq!(&reply[28..], resp, "DNS payload is the resolver output");
        assert!(ip_checksum_ok(&reply), "IPv4 header checksum");
        assert!(
            udp_checksum_ok_or_omitted(&reply),
            "UDP checksum valid or omitted"
        );
    }

    #[test]
    fn attract_skips_loopback_and_keeps_public() {
        let got = collect_attract(
            WELL_KNOWN_DNS.iter().copied(),
            [
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 53),
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(172, 30, 0, 4),
            ],
            [Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
        );
        assert!(got.contains(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(got.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(got.contains(&Ipv4Addr::new(172, 30, 0, 4)));
        assert!(got.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!got.contains(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!got.contains(&Ipv4Addr::new(127, 0, 0, 53)));
        assert!(!got.contains(&Ipv4Addr::UNSPECIFIED));
        // Dedup: 8.8.8.8 appears in well-known and from_files once.
        assert_eq!(
            got.iter()
                .filter(|ip| **ip == Ipv4Addr::new(8, 8, 8, 8))
                .count(),
            1
        );
    }

    #[test]
    fn parse_resolv_conf_nameserver_lines() {
        let text = "\
# comment
nameserver 8.8.8.8
nameserver  1.1.1.1
nameserver 127.0.0.53
search lan
nameserver not-an-ip
nameserver 2001:db8::1
";
        let mut ips = Vec::new();
        parse_resolv_nameservers(text, &mut ips);
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(8, 8, 8, 8),
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(127, 0, 0, 53),
            ]
        );
    }

    #[derive(Default)]
    struct VecSink(Mutex<Vec<Ipv4Addr>>);
    impl IpSink for VecSink {
        fn add(&self, ip: Ipv4Addr) {
            self.0.lock().unwrap().push(ip);
        }
    }
    impl VecSink {
        fn ips(&self) -> Vec<Ipv4Addr> {
            self.0.lock().unwrap().clone()
        }
    }

    fn dns_response(query: &[u8], ips: &[Ipv4Addr]) -> Vec<u8> {
        let mut m = query.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[6] = (ips.len() >> 8) as u8;
        m[7] = ips.len() as u8;
        for ip in ips {
            m.extend_from_slice(&[0xC0, 0x0C]);
            m.extend_from_slice(&[0, 1, 0, 1]);
            m.extend_from_slice(&300u32.to_be_bytes());
            m.extend_from_slice(&4u16.to_be_bytes());
            m.extend_from_slice(&ip.octets());
        }
        m
    }

    async fn mock_upstream(ips: Vec<Ipv4Addr>) -> SocketAddr {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_MSG];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                let resp = dns_response(&buf[..n], &ips);
                sock.send_to(&resp, from).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn intercept_gfwlist_query_installs_tunnel_route() {
        let local = mock_upstream(vec![Ipv4Addr::new(10, 0, 0, 1)]).await;
        let remote = mock_upstream(vec![Ipv4Addr::new(93, 184, 216, 34)]).await;
        let sink = Arc::new(VecSink::default());
        let resolver = Resolver::new(
            Mode::GfwList,
            GfwList::from_lines(["blocked.com"]),
            ChnRoute::default(),
            local,
            remote,
            Duration::from_secs(2),
            sink.clone(),
            Arc::new(DnsCache::new()),
        );

        let dns_q = dns::build_query(0x1111, "www.blocked.com");
        let src = Ipv4Addr::new(10, 9, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let pkt = udp_packet(src, dst, 33333, 53, &dns_q);
        let q = classify(&pkt).expect("classified");
        let resolved = resolver
            .resolve(&q.payload)
            .await
            .expect("resolver answered");
        let reply = build_reply(&q, &resolved);

        assert_eq!(&reply[12..16], &dst.octets());
        assert_eq!(&reply[16..20], &src.octets());
        assert_eq!(&reply[28..], resolved.as_slice());
        assert_eq!(
            dns::a_records(&reply[28..]),
            vec![Ipv4Addr::new(93, 184, 216, 34)]
        );
        assert_eq!(sink.ips(), vec![Ipv4Addr::new(93, 184, 216, 34)]);
        assert!(ip_checksum_ok(&reply));
        assert!(udp_checksum_ok_or_omitted(&reply));
    }

    #[tokio::test]
    async fn intercept_magic_dns_returns_peer_a() {
        let local = mock_upstream(vec![Ipv4Addr::new(1, 2, 3, 4)]).await;
        let remote = mock_upstream(vec![Ipv4Addr::new(8, 8, 8, 8)]).await;
        let table = Arc::new(PeerTable::new());
        table.replace(
            &[crate::mesh::PeerEntry {
                name: "pi".into(),
                ip4: Ipv4Addr::new(10, 9, 0, 7),
                ip6: None,
            }],
            "svpn",
        );
        let sink = Arc::new(VecSink::default());
        let resolver = Resolver::new(
            Mode::GfwList,
            GfwList::from_lines(["blocked.com"]),
            ChnRoute::default(),
            local,
            remote,
            Duration::from_secs(2),
            sink.clone(),
            Arc::new(DnsCache::new()),
        )
        .with_magic(table, "svpn".into());

        let dns_q = dns::build_query(0x2222, "pi.svpn");
        let pkt = udp_packet(
            Ipv4Addr::new(10, 9, 0, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            1200,
            53,
            &dns_q,
        );
        let q = classify(&pkt).unwrap();
        let resolved = resolver.resolve(&q.payload).await.unwrap();
        let reply = build_reply(&q, &resolved);
        assert_eq!(
            dns::a_records(&reply[28..]),
            vec![Ipv4Addr::new(10, 9, 0, 7)]
        );
        assert!(sink.ips().is_empty(), "peer IPs are on-link, not sunk");
        assert!(ip_checksum_ok(&reply));
        assert!(udp_checksum_ok_or_omitted(&reply));
    }
}
