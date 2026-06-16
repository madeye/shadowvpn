//! The split-DNS proxy at the heart of policy routing.
//!
//! This is a tiny stand-in for the classic `dnsmasq` + ipset recipe. It listens
//! for DNS queries from the local stub resolver and, depending on the
//! [`Mode`](super::Mode), forwards each to the right upstream and decides whether
//! the answer's addresses should be routed through the tunnel:
//!
//! * **gfwlist mode** — names matching the [`GfwList`] go to the *clean* upstream
//!   (reached through the tunnel); their `A` records are added to the ipset.
//!   Everything else goes to the *local* upstream and is left on the direct path.
//! * **chinadns mode** — every query is sent to both upstreams concurrently. If
//!   the local resolver returns an in-China address ([`ChnRoute`]) the domain is
//!   treated as domestic and the local answer is returned directly; otherwise the
//!   clean upstream's answer is trusted, returned, and its addresses are added to
//!   the ipset.
//!
//! Queries and answers are relayed verbatim, so the stub resolver sees ordinary
//! DNS responses (same transaction id, flags, and records).
//!
//! Adding addresses to the ipset is abstracted behind [`IpSink`] so the routing
//! logic can be unit-tested without root or a real ipset.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, warn};
use tokio::net::UdpSocket;

use super::chnroute::ChnRoute;
use super::dns;
use super::gfwlist::GfwList;
use super::Mode;

/// Maximum DNS-over-UDP message we will buffer (generous EDNS0 headroom).
const MAX_DNS_MSG: usize = 4096;

/// A destination for addresses that should be routed through the tunnel.
///
/// The production implementation adds them to a kernel ipset; tests use an
/// in-memory collector.
pub trait IpSink: Send + Sync {
    /// Add one IPv4 address to the tunnel-routed set. Implementations should be
    /// idempotent and must not panic on error (a failure to add one address
    /// must not take down the resolver).
    fn add(&self, ip: Ipv4Addr);
}

/// What to do with a resolved name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Leave it on the direct path.
    Direct,
    /// Route its addresses through the tunnel (and add them to the ipset).
    Tunnel,
}

/// chinadns decision: domestic (direct) if the local resolver returned any
/// in-China address, otherwise trust the clean upstream (tunnel).
pub fn chinadns_decision(local_ips: &[Ipv4Addr], chnroute: &ChnRoute) -> Decision {
    if local_ips.iter().any(|ip| chnroute.contains(*ip)) {
        Decision::Direct
    } else {
        Decision::Tunnel
    }
}

/// The resolver state shared across all in-flight queries.
pub struct Resolver {
    mode: Mode,
    gfwlist: GfwList,
    chnroute: ChnRoute,
    local: SocketAddr,
    remote: SocketAddr,
    timeout: Duration,
    sink: Arc<dyn IpSink>,
}

impl Resolver {
    /// Build a resolver. `gfwlist` is only consulted in gfwlist mode and
    /// `chnroute` only in chinadns mode; pass empty defaults for the unused one.
    pub fn new(
        mode: Mode,
        gfwlist: GfwList,
        chnroute: ChnRoute,
        local: SocketAddr,
        remote: SocketAddr,
        timeout: Duration,
        sink: Arc<dyn IpSink>,
    ) -> Self {
        Self {
            mode,
            gfwlist,
            chnroute,
            local,
            remote,
            timeout,
            sink,
        }
    }

    /// Resolve one raw DNS query, returning the raw response to relay back, or
    /// `None` if no usable answer could be obtained.
    pub async fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        let name = dns::question_name(query);
        match self.mode {
            Mode::Full => None, // proxy is not run in full mode
            Mode::GfwList => self.resolve_gfwlist(query, name.as_deref()).await,
            Mode::ChinaDns => self.resolve_chinadns(query).await,
        }
    }

    /// gfwlist mode: pick the upstream by name, tunnel the answer if matched.
    async fn resolve_gfwlist(&self, query: &[u8], name: Option<&str>) -> Option<Vec<u8>> {
        let tunnel = name.map(|n| self.gfwlist.matches(n)).unwrap_or(false);
        let upstream = if tunnel { self.remote } else { self.local };
        let resp = match query_upstream(upstream, query, self.timeout).await {
            Ok(r) => r,
            Err(e) => {
                debug!("gfwlist: upstream {upstream} failed for {name:?}: {e}");
                return None;
            }
        };
        if tunnel {
            self.tunnel_addresses(name, &resp);
        }
        Some(resp)
    }

    /// chinadns mode: query both upstreams, choose by China-IP membership.
    async fn resolve_chinadns(&self, query: &[u8]) -> Option<Vec<u8>> {
        let (local_res, remote_res) = tokio::join!(
            query_upstream(self.local, query, self.timeout),
            query_upstream(self.remote, query, self.timeout),
        );
        let local_res = local_res.ok();
        let remote_res = remote_res.ok();

        let local_ips = local_res.as_deref().map(dns::a_records).unwrap_or_default();
        // No local answer at all -> trust the clean upstream.
        let decision = if local_res.is_none() {
            Decision::Tunnel
        } else {
            chinadns_decision(&local_ips, &self.chnroute)
        };

        match decision {
            Decision::Direct => local_res,
            Decision::Tunnel => {
                // Prefer the clean answer; fall back to local if remote failed.
                let resp = remote_res.or(local_res)?;
                self.tunnel_addresses(dns::question_name(query).as_deref(), &resp);
                Some(resp)
            }
        }
    }

    /// Add every `A` record in `resp` to the ipset.
    fn tunnel_addresses(&self, name: Option<&str>, resp: &[u8]) {
        for ip in dns::a_records(resp) {
            debug!("tunnel route: {} -> {ip}", name.unwrap_or("?"));
            self.sink.add(ip);
        }
    }
}

/// Send a query to one upstream over a fresh ephemeral UDP socket and return the
/// raw response, bounded by `timeout`.
async fn query_upstream(server: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let bind: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
    let sock = UdpSocket::bind(bind)
        .await
        .context("bind upstream DNS socket")?;
    sock.connect(server)
        .await
        .with_context(|| format!("connect to DNS upstream {server}"))?;
    sock.send(query).await.context("send DNS query")?;

    let mut buf = vec![0u8; MAX_DNS_MSG];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .with_context(|| format!("DNS upstream {server} timed out"))?
        .context("recv DNS response")?;
    buf.truncate(n);
    Ok(buf)
}

/// Run the proxy: receive queries on `listener` and answer each with `resolver`.
///
/// Each query is handled in its own task so a slow upstream never blocks others.
/// Returns only on a fatal error reading the listening socket.
pub async fn serve(listener: UdpSocket, resolver: Arc<Resolver>) -> Result<()> {
    let listener = Arc::new(listener);
    let mut buf = vec![0u8; MAX_DNS_MSG];
    loop {
        let (n, client) = listener
            .recv_from(&mut buf)
            .await
            .context("DNS proxy recv_from failed")?;
        let query = buf[..n].to_vec();
        let resolver = Arc::clone(&resolver);
        let listener = Arc::clone(&listener);
        tokio::spawn(async move {
            match resolver.resolve(&query).await {
                Some(resp) => {
                    if let Err(e) = listener.send_to(&resp, client).await {
                        warn!("DNS proxy failed to reply to {client}: {e}");
                    }
                }
                None => debug!("DNS proxy: no answer for query from {client}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory [`IpSink`] for assertions.
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

    fn query(name: &str) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        m
    }

    /// Build a response to `query` with the given A records.
    fn response(query: &[u8], ips: &[Ipv4Addr]) -> Vec<u8> {
        let mut m = query.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[6] = (ips.len() >> 8) as u8;
        m[7] = ips.len() as u8;
        for ip in ips {
            m.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
            m.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A CLASS=IN
            m.extend_from_slice(&300u32.to_be_bytes());
            m.extend_from_slice(&4u16.to_be_bytes());
            m.extend_from_slice(&ip.octets());
        }
        m
    }

    /// Spawn a mock upstream that always answers with `ips`. Returns its addr.
    async fn mock_upstream(ips: Vec<Ipv4Addr>) -> SocketAddr {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_MSG];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                let resp = response(&buf[..n], &ips);
                sock.send_to(&resp, from).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn gfwlist_tunnels_only_matched_domains() {
        let local = mock_upstream(vec![Ipv4Addr::new(10, 0, 0, 1)]).await;
        let remote = mock_upstream(vec![Ipv4Addr::new(93, 184, 216, 34)]).await;
        let sink = Arc::new(VecSink::default());
        let r = Resolver::new(
            Mode::GfwList,
            GfwList::from_lines(["blocked.com"]),
            ChnRoute::default(),
            local,
            remote,
            Duration::from_secs(2),
            sink.clone(),
        );

        // Matched: goes to remote, address tunneled.
        let resp = r.resolve(&query("www.blocked.com")).await.unwrap();
        assert_eq!(dns::a_records(&resp), vec![Ipv4Addr::new(93, 184, 216, 34)]);
        // Not matched: goes to local, nothing tunneled.
        let resp = r.resolve(&query("safe.cn")).await.unwrap();
        assert_eq!(dns::a_records(&resp), vec![Ipv4Addr::new(10, 0, 0, 1)]);

        assert_eq!(sink.ips(), vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[tokio::test]
    async fn chinadns_routes_by_china_membership() {
        // Local returns a China IP for the domestic name and a (poisoned)
        // foreign IP for the blocked name; remote returns the real foreign IP.
        let china_ip = Ipv4Addr::new(114, 114, 114, 114);
        let poison_ip = Ipv4Addr::new(8, 7, 6, 5);
        let real_ip = Ipv4Addr::new(93, 184, 216, 34);
        let chnroute = ChnRoute::from_lines(["114.114.114.0/24"]);

        let sink = Arc::new(VecSink::default());

        // Domestic: local says China -> use local, no tunnel.
        let r_dom = Resolver::new(
            Mode::ChinaDns,
            GfwList::default(),
            chnroute.clone(),
            mock_upstream(vec![china_ip]).await,
            mock_upstream(vec![real_ip]).await,
            Duration::from_secs(2),
            sink.clone(),
        );
        let resp = r_dom.resolve(&query("baidu.cn")).await.unwrap();
        assert_eq!(dns::a_records(&resp), vec![china_ip]);
        assert!(sink.ips().is_empty());

        // Blocked: local says foreign(poison) -> trust remote, tunnel it.
        let r_blk = Resolver::new(
            Mode::ChinaDns,
            GfwList::default(),
            chnroute,
            mock_upstream(vec![poison_ip]).await,
            mock_upstream(vec![real_ip]).await,
            Duration::from_secs(2),
            sink.clone(),
        );
        let resp = r_blk.resolve(&query("blocked.com")).await.unwrap();
        assert_eq!(dns::a_records(&resp), vec![real_ip]);
        assert_eq!(sink.ips(), vec![real_ip]);
    }

    #[test]
    fn decision_is_china_aware() {
        let chn = ChnRoute::from_lines(["1.2.3.0/24"]);
        assert_eq!(
            chinadns_decision(&[Ipv4Addr::new(1, 2, 3, 4)], &chn),
            Decision::Direct
        );
        assert_eq!(
            chinadns_decision(&[Ipv4Addr::new(8, 8, 8, 8)], &chn),
            Decision::Tunnel
        );
        assert_eq!(chinadns_decision(&[], &chn), Decision::Tunnel);
    }
}
