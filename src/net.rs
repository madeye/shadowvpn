//! UDP socket construction with enlarged kernel buffers.
//!
//! The default per-socket send/receive buffers (often ~200 KB) are far smaller
//! than the bandwidth-delay product of a fast tunnel: at multi-hundred-Mbit
//! rates the single receive task can fall behind for a few hundred microseconds
//! and the kernel silently drops the overflow. Enlarging `SO_RCVBUF`/`SO_SNDBUF`
//! gives the data plane headroom to absorb those bursts (and lets TCP *inside*
//! the tunnel open a larger window), which together with the pipelined relay
//! loops is what keeps the carrier from dropping packets under load.
//!
//! Sizing is best-effort: the OS may clamp the request (on Linux to
//! `net.core.{r,w}mem_max`), and that is fine — a clamped-but-larger buffer is
//! still better than the default, and the relay loops do not depend on an exact
//! size.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::policy::dns;

/// Requested size, in bytes, for each UDP socket's send and receive buffers.
/// 4 MiB comfortably covers a ~300 Mbit/s tunnel at tens of milliseconds RTT.
pub const UDP_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Transaction id for the bootstrap server-resolution query. The socket is
/// connected to a single upstream and only one query is in flight, so the exact
/// value does not matter; a fixed non-zero id keeps things deterministic.
const SERVER_QUERY_ID: u16 = 0x5650; // "VP"

/// Receive buffer for a server-resolution DNS response. An `A` answer is tiny;
/// this is generous headroom.
const RESOLVE_BUF_BYTES: usize = 4096;

/// Bind a non-blocking [`UdpSocket`] to `addr` with enlarged send/receive
/// buffers ([`UDP_BUFFER_BYTES`], best-effort).
///
/// Returns a tokio socket ready to use with the current runtime; on the client
/// it is subsequently `connect()`ed to the server.
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Best-effort: a clamp (e.g. to net.core.rmem_max) is not an error.
    let _ = sock.set_recv_buffer_size(UDP_BUFFER_BYTES);
    let _ = sock.set_send_buffer_size(UDP_BUFFER_BYTES);

    // tokio requires the underlying socket to be non-blocking.
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Resolve a `host:port` server address to a concrete [`SocketAddr`] using a
/// built-in DNS client that queries `upstreams` directly over UDP, bypassing
/// the OS stub resolver.
///
/// The client connects to the server *before* the tunnel is up, so the only
/// reachable resolvers are the ones on the physical network. Going through the
/// OS resolver here is fragile: a previous run (or another tool) may have
/// pinned the system DNS at a split-DNS proxy on `127.0.0.1` that is not yet
/// listening — or at any other stale/dirty entry — leaving `getaddrinfo` to
/// fail or hang and the tunnel unable to bootstrap. Querying a known-clean
/// upstream ourselves sidesteps that dirty local state entirely.
///
/// `upstreams` are tried in order; the first one to return an `A` record wins.
/// A literal `ip:port` (or bare-IP host) short-circuits with no query at all.
pub async fn resolve_server(
    server: &str,
    upstreams: &[SocketAddr],
    timeout: Duration,
) -> std::io::Result<SocketAddr> {
    // Already a literal `ip:port`? Nothing to resolve.
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Split off the `:port`; the remainder is the host to resolve.
    let (host, port) = server
        .rsplit_once(':')
        .ok_or_else(|| resolve_err(format!("server `{server}` is missing a `:port`")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| resolve_err(format!("server `{server}` has an invalid port")))?;

    // A bare IP host needs no DNS either.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    if upstreams.is_empty() {
        return Err(resolve_err(
            "no DNS upstreams configured to resolve the server".into(),
        ));
    }

    let query = dns::build_query(SERVER_QUERY_ID, host);
    for &upstream in upstreams {
        match query_a(upstream, &query, timeout).await {
            Ok(Some(ip)) => return Ok(SocketAddr::new(IpAddr::V4(ip), port)),
            Ok(None) => {
                log::debug!("internal resolver: {upstream} returned no A record for {host}")
            }
            Err(e) => log::debug!("internal resolver: {upstream} failed for {host}: {e}"),
        }
    }

    Err(resolve_err(format!(
        "internal resolver could not resolve `{host}` via any upstream ({upstreams:?})"
    )))
}

/// Send a single `A` query to `upstream` over a fresh UDP socket and return the
/// first IPv4 address in the response, or `None` if the answer has no `A` record.
async fn query_a(
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> std::io::Result<Option<Ipv4Addr>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;

    let mut buf = vec![0u8; RESOLVE_BUF_BYTES];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| resolve_err(format!("DNS upstream {upstream} timed out")))??;
    buf.truncate(n);
    Ok(dns::a_records(&buf).into_iter().next())
}

/// Build an `io::Error` for a resolution failure.
fn resolve_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_addr_short_circuits() {
        // `ip:port` returns verbatim with no DNS query (unreachable upstream).
        let bogus = "192.0.2.1:9".parse().unwrap();
        let got = resolve_server("157.245.227.200:443", &[bogus], Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(got, "157.245.227.200:443".parse().unwrap());
    }

    #[tokio::test]
    async fn bare_ip_host_short_circuits() {
        let bogus = "192.0.2.1:9".parse().unwrap();
        let got = resolve_server("10.9.0.1:1234", &[bogus], Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(
            got,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)), 1234)
        );
    }

    #[tokio::test]
    async fn missing_port_is_an_error() {
        assert!(resolve_server("example.com", &[], Duration::from_millis(1))
            .await
            .is_err());
    }
}
