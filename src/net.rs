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

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Requested size, in bytes, for each UDP socket's send and receive buffers.
/// 4 MiB comfortably covers a ~300 Mbit/s tunnel at tens of milliseconds RTT.
pub const UDP_BUFFER_BYTES: usize = 4 * 1024 * 1024;

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
