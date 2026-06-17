//! The split-DNS proxy at the heart of policy routing.
//!
//! This is a tiny stand-in for the classic `dnsmasq` + ipset recipe. It listens
//! for DNS queries from the local stub resolver and, depending on the
//! [`Mode`](super::Mode), forwards each to the right upstream and decides whether
//! the answer's addresses should be routed through the tunnel:
//!
//! * **gfwlist mode** — names matching the [`GfwList`] go to the *clean* upstream
//!   (reached through the tunnel); their addresses are added to the route set.
//!   Everything else goes to the *local* upstream and is left on the direct path.
//! * **chinadns mode** — the clean (tunneled) query and the local query run
//!   concurrently, but the resolver returns as soon as the *local* answer settles
//!   a domestic (in-China, [`ChnRoute`]) result — so China names resolve at
//!   local-DNS speed instead of waiting for the slow clean upstream. Only
//!   foreign/poisoned names wait for the clean answer, whose addresses are then
//!   routed through the tunnel.
//!
//! Answers are [cached](super::cache) by question (TTL-respecting), so repeat
//! lookups skip the upstream round-trip entirely. Responses are otherwise relayed
//! verbatim (the cache only rewrites the transaction id to match the new query).
//!
//! Adding addresses to the route set is abstracted behind [`IpSink`] so the
//! routing logic can be unit-tested without root.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, warn};
use tokio::net::UdpSocket;

use super::cache;
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

/// A decided answer: the raw response to relay, and the addresses (if any) that
/// must be routed through the tunnel.
struct Decided {
    response: Vec<u8>,
    tunnel_ips: Vec<Ipv4Addr>,
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
    cache: Arc<cache::DnsCache>,
}

impl Resolver {
    /// Build a resolver. `gfwlist` is only consulted in gfwlist mode and
    /// `chnroute` only in chinadns mode; pass empty defaults for the unused one.
    /// `cache` is shared so it can be pre-loaded and persisted by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: Mode,
        gfwlist: GfwList,
        chnroute: ChnRoute,
        local: SocketAddr,
        remote: SocketAddr,
        timeout: Duration,
        sink: Arc<dyn IpSink>,
        cache: Arc<cache::DnsCache>,
    ) -> Self {
        Self {
            mode,
            gfwlist,
            chnroute,
            local,
            remote,
            timeout,
            sink,
            cache,
        }
    }

    /// Resolve one raw DNS query, returning the raw response to relay back, or
    /// `None` if no usable answer could be obtained.
    ///
    /// Fresh answers are served from the cache; otherwise the per-mode logic runs
    /// and its result is cached. Either way, any tunnel-bound addresses are
    /// (re-)installed into the route set (the sink is idempotent).
    pub async fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        if matches!(self.mode, Mode::Full) {
            return None; // proxy is not run in full mode
        }

        if let Some((response, tunnel_ips)) = self.cache.get(query) {
            self.tunnel(&tunnel_ips);
            return Some(response);
        }

        let decided = match self.mode {
            Mode::Full => return None,
            Mode::GfwList => {
                let name = dns::question_name(query);
                self.decide_gfwlist(query, name.as_deref()).await?
            }
            Mode::ChinaDns => self.decide_chinadns(query).await?,
        };

        self.tunnel(&decided.tunnel_ips);
        self.cache
            .put(query, &decided.response, &decided.tunnel_ips);
        Some(decided.response)
    }

    /// gfwlist mode: pick the upstream by name, tunnel the answer if matched.
    async fn decide_gfwlist(&self, query: &[u8], name: Option<&str>) -> Option<Decided> {
        let tunnel = name.map(|n| self.gfwlist.matches(n)).unwrap_or(false);
        let upstream = if tunnel { self.remote } else { self.local };
        let response = match query_upstream(upstream, query, self.timeout).await {
            Ok(r) => r,
            Err(e) => {
                debug!("gfwlist: upstream {upstream} failed for {name:?}: {e}");
                return None;
            }
        };
        let tunnel_ips = if tunnel {
            dns::a_records(&response)
        } else {
            Vec::new()
        };
        Some(Decided {
            response,
            tunnel_ips,
        })
    }

    /// chinadns mode: query both upstreams concurrently, but return as soon as the
    /// *local* resolver settles a domestic (in-China) answer — so China names
    /// resolve at local-DNS speed instead of waiting for the slow clean upstream.
    /// Only foreign/poisoned names wait for the clean (tunneled) answer.
    async fn decide_chinadns(&self, query: &[u8]) -> Option<Decided> {
        // Start the clean (tunneled) query in the background so it overlaps the
        // local query, but don't block on it unless we actually need it.
        let remote_query = query.to_vec();
        let remote = self.remote;
        let timeout = self.timeout;
        let remote_task =
            tokio::spawn(async move { query_upstream(remote, &remote_query, timeout).await.ok() });

        let local_res = query_upstream(self.local, query, self.timeout).await.ok();
        let local_ips = local_res.as_deref().map(dns::a_records).unwrap_or_default();

        // Domestic: trust the local answer and drop the in-flight clean query.
        if local_res.is_some() && chinadns_decision(&local_ips, &self.chnroute) == Decision::Direct
        {
            remote_task.abort();
            return local_res.map(|response| Decided {
                response,
                tunnel_ips: Vec::new(),
            });
        }

        // Foreign / poisoned / no local answer: use the clean upstream's answer
        // (falling back to local if it failed) and route it through the tunnel.
        let remote_res = remote_task.await.ok().flatten();
        let response = remote_res.or(local_res)?;
        let tunnel_ips = dns::a_records(&response);
        Some(Decided {
            response,
            tunnel_ips,
        })
    }

    /// (Re-)install every tunnel-bound address into the route set.
    fn tunnel(&self, ips: &[Ipv4Addr]) {
        for ip in ips {
            self.sink.add(*ip);
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

/// Resolve `domains` through `resolver` to pre-fill the cache (and pre-install
/// routes for tunneled ones) so the first real lookup of a common domain is hot.
///
/// Runs in small concurrent batches and ignores individual failures; intended to
/// be spawned in the background at startup.
pub async fn prewarm(resolver: Arc<Resolver>, domains: Vec<String>) {
    let total = domains.len();
    for batch in domains.chunks(8) {
        let mut handles = Vec::with_capacity(batch.len());
        for (i, domain) in batch.iter().enumerate() {
            let resolver = Arc::clone(&resolver);
            let query = dns::build_query(i as u16 + 1, domain);
            handles.push(tokio::spawn(async move { resolver.resolve(&query).await }));
        }
        for h in handles {
            let _ = h.await;
        }
    }
    debug!("pre-warmed {total} domains into the DNS cache");
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
            Arc::new(cache::DnsCache::new()),
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
            Arc::new(cache::DnsCache::new()),
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
            Arc::new(cache::DnsCache::new()),
        );
        let resp = r_blk.resolve(&query("blocked.com")).await.unwrap();
        assert_eq!(dns::a_records(&resp), vec![real_ip]);
        assert_eq!(sink.ips(), vec![real_ip]);
    }

    /// A mock upstream that answers with a different IP (10.0.0.N) on each query,
    /// so a second *cached* lookup is distinguishable from a fresh upstream call.
    async fn mock_counting() -> SocketAddr {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_MSG];
            let mut n: u8 = 0;
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                n += 1;
                let resp = response(&buf[..len], &[Ipv4Addr::new(10, 0, 0, n)]);
                sock.send_to(&resp, from).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn second_lookup_is_served_from_cache() {
        let remote = mock_counting().await;
        let sink = Arc::new(VecSink::default());
        let r = Resolver::new(
            Mode::GfwList,
            GfwList::from_lines(["blocked.com"]),
            ChnRoute::default(),
            mock_upstream(vec![Ipv4Addr::new(10, 0, 0, 1)]).await,
            remote,
            Duration::from_secs(2),
            sink.clone(),
            Arc::new(cache::DnsCache::new()),
        );
        // First lookup hits the (counting) upstream -> 10.0.0.1.
        let first = r.resolve(&query("www.blocked.com")).await.unwrap();
        assert_eq!(dns::a_records(&first), vec![Ipv4Addr::new(10, 0, 0, 1)]);
        // Second lookup must come from cache: still 10.0.0.1, not 10.0.0.2.
        let second = r.resolve(&query("www.blocked.com")).await.unwrap();
        assert_eq!(dns::a_records(&second), vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[tokio::test]
    async fn chinadns_does_not_wait_for_remote_on_china_domain() {
        let china = Ipv4Addr::new(114, 114, 114, 114);
        let local = mock_upstream(vec![china]).await;
        // Unreachable (RFC 5737 TEST-NET-1): querying it would hang until timeout.
        let dead: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let sink = Arc::new(VecSink::default());
        let r = Resolver::new(
            Mode::ChinaDns,
            GfwList::default(),
            ChnRoute::from_lines(["114.114.114.0/24"]),
            local,
            dead,
            Duration::from_secs(30), // long: proves we don't block on `dead`
            sink.clone(),
            Arc::new(cache::DnsCache::new()),
        );
        // If the resolver wrongly waited for the dead remote it would take ~30s;
        // a 2s bound proves the early return on a domestic answer.
        let resp = tokio::time::timeout(Duration::from_secs(2), r.resolve(&query("baidu.cn")))
            .await
            .expect("resolved without waiting for the remote")
            .expect("got an answer");
        assert_eq!(dns::a_records(&resp), vec![china]);
        assert!(sink.ips().is_empty());
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
