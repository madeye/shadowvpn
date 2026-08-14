//! ShadowVPN server entrypoint.
//!
//! The server terminates the encrypted UDP tunnel onto a local TUN device and
//! routes traffic between connected clients. It runs two concurrent loops over a
//! single shared [`UdpSocket`] and a single shared [`TunDevice`]:
//!
//! * **UDP → TUN** ([`udp_to_tun`]): receive an encrypted UDP datagram, decrypt
//!   it into a raw IP packet, route/rewrite it, and write it to TUN.
//! * **TUN → UDP** ([`tun_to_udp`]): read a raw IP packet from TUN, find the UDP
//!   address of the client it belongs to, encrypt, and send it back.
//!
//! Two routing modes:
//!
//! * **Default (learning):** map each client's inner tunnel source IP to the UDP
//!   `SocketAddr` it was last seen from, and route replies by inner destination
//!   IP. Clients must use distinct tunnel IPs.
//! * **NAT (`--nat`):** every client may share one static config with the same
//!   placeholder tunnel IP. The server tells clients apart by UDP endpoint and
//!   maps each to a distinct internal IP (see [`shadowvpn::nat`]), rewriting inner
//!   addresses on the way through. No IP-assignment handshake is needed.
//!
//! Decrypt failures, malformed packets, and unknown-destination packets are
//! logged and dropped; they never crash the server.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use shadowvpn::config::{ServerArgs, ServerConfig};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet};
use shadowvpn::mesh::{self, Control, RouteApproval, RoutePush, SubnetTable};
use shadowvpn::nat::{Ingress, Nat};
use shadowvpn::obfs::{self, Obfuscator};
use shadowvpn::protocol::{max_datagram_size, MAX_IP_PACKET};
use shadowvpn::tun_device::TunDevice;

/// Learning-mode routing state: the classic per-address client map plus the
/// mesh subnet-route table (Tailscale-like advertised routes).
#[derive(Default)]
struct Learned {
    /// Inner tunnel IP (v4 or v6) → the UDP endpoint it was last seen from.
    clients: HashMap<IpAddr, SocketAddr>,
    /// Advertised subnet routes, matched by longest prefix after `clients`.
    subnets: SubnetTable,
}

impl Learned {
    /// Record that `src` is reachable via `peer`, logging on change.
    fn learn(&mut self, src: IpAddr, peer: SocketAddr, via: &str) {
        if self.clients.insert(src, peer) != Some(peer) {
            info!("client {src} reachable via {peer}{via}");
        }
    }

    /// Resolve an inner destination: exact client first, then the
    /// longest-prefix subnet route.
    fn lookup(&self, dst: IpAddr) -> Option<SocketAddr> {
        self.clients
            .get(&dst)
            .copied()
            .or_else(|| self.subnets.lookup(dst))
    }
}

/// How the server maps inner IP packets to clients. Held behind a [`Mutex`] and
/// only touched synchronously (never across an `.await`).
enum Routing {
    /// Learn inner source IP → UDP peer; route by inner destination IP. Clients
    /// must use distinct tunnel IPs.
    Learn(Learned),
    /// NAT clients onto distinct internal IPs keyed by their UDP endpoint, so
    /// they can all share one static config.
    Nat(Nat),
}

/// Shared routing state.
type Shared = Arc<Mutex<Routing>>;

/// Depth of the hand-off channel between each relay loop's I/O reader and its
/// processor. Bounded so a slow processor applies backpressure rather than
/// buffering without limit; deep enough to absorb short bursts at line rate.
const CHANNEL_DEPTH: usize = 1024;

#[tokio::main]
async fn main() -> Result<()> {
    // Default to `info` so the startup banner and routing events are visible
    // without extra configuration; `RUST_LOG` can override.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = ServerArgs::parse()
        .resolve()
        .context("failed to resolve server configuration")?;

    if let Err(err) = run(cfg).await {
        error!("server exited with error: {err:#}");
        return Err(err);
    }
    Ok(())
}

/// Bind the socket, bring up TUN, print the banner, and run both forwarding
/// loops (plus the NAT sweeper) until one of them fails.
async fn run(cfg: ServerConfig) -> Result<()> {
    let listen_addr = cfg
        .listen
        .to_socket_addrs()
        .with_context(|| format!("resolving listen address {}", cfg.listen))?
        .next()
        .with_context(|| format!("no address resolved for {}", cfg.listen))?;
    let socket = shadowvpn::net::bind_udp(listen_addr)
        .with_context(|| format!("failed to bind UDP socket on {}", cfg.listen))?;
    let socket = Arc::new(socket);

    let tun = TunDevice::create(&cfg.tun)
        .context("failed to create TUN device (TUN setup needs root / elevated privileges)")?;
    let tun = Arc::new(tun);

    let tun_name = tun.name().unwrap_or_else(|_| {
        cfg.tun
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string())
    });

    print_banner(&cfg, &tun_name);

    let routing: Shared = Arc::new(Mutex::new(if cfg.nat {
        let nat = Nat::new(cfg.tun.ip, cfg.tun.netmask, cfg.lease_ttl);
        info!(
            "  NAT            : ENABLED ({} clients max, idle TTL {}s)",
            nat.capacity(),
            cfg.lease_ttl.as_secs()
        );
        Routing::Nat(nat)
    } else {
        Routing::Learn(Learned::default())
    }));

    // Carrier obfuscation, matching the client. When enabled, datagrams on the
    // wire look like QUIC/HTTP3 short-header packets; `None` is the plain
    // `salt ++ AEAD` envelope.
    let obfuscator: Option<Arc<Obfuscator>> = cfg
        .obfs
        .as_deref()
        .and_then(Obfuscator::from_name)
        .map(Arc::new);
    if let Some(name) = cfg.obfs.as_deref() {
        info!("  obfuscation    : {name} datagram shaping ENABLED");
    }

    let nat_enabled = cfg.nat;
    let lease_ttl = cfg.lease_ttl;
    let cfg = Arc::new(cfg);

    // Loop A: UDP → TUN.
    let a = {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let routing = Arc::clone(&routing);
        let cfg = Arc::clone(&cfg);
        let obfs = obfuscator.clone();
        tokio::spawn(async move { udp_to_tun(socket, tun, routing, cfg, obfs).await })
    };

    // Loop B: TUN → UDP.
    let b = {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let routing = Arc::clone(&routing);
        let cfg = Arc::clone(&cfg);
        let obfs = obfuscator.clone();
        tokio::spawn(async move { tun_to_udp(socket, tun, routing, cfg, obfs).await })
    };

    // Sweeper: periodically reclaim idle NAT mappings, or (in learning mode)
    // expire advertised subnet routes whose owner went quiet. Aborted when
    // `run` returns (the handle is dropped).
    let _sweeper = {
        let routing = Arc::clone(&routing);
        let interval = (lease_ttl / 2).max(Duration::from_secs(5));
        let _ = nat_enabled;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match &mut *routing.lock().unwrap() {
                    Routing::Nat(nat) => {
                        nat.reap(Instant::now());
                    }
                    Routing::Learn(learned) => {
                        for net in learned.subnets.expire(lease_ttl, Instant::now()) {
                            info!("subnet route {net} expired (advertiser went quiet)");
                        }
                    }
                }
            }
        })
    };

    // If either loop returns (only on a fatal IO error), tear the server down.
    tokio::select! {
        res = a => res.context("UDP→TUN task panicked")?,
        res = b => res.context("TUN→UDP task panicked")?,
    }
}

/// Loop A: receive encrypted datagrams, decrypt, route/rewrite, write to TUN.
///
/// Split into a pipeline so socket I/O overlaps the per-packet crypto: a
/// **reader** drains the UDP socket into a bounded channel as fast as the kernel
/// delivers (so bursts are not dropped while a packet is being decrypted), and a
/// single **processor** de-obfuscates, decrypts, routes/rewrites, and writes to
/// TUN. One processor keeps packets in order.
async fn udp_to_tun(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    routing: Shared,
    cfg: Arc<ServerConfig>,
    obfuscator: Option<Arc<Obfuscator>>,
) -> Result<()> {
    let cipher = cfg.cipher;
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(CHANNEL_DEPTH);

    // The processor sends too (mesh relays + route pushes), so it keeps its
    // own handle on the socket while the reader owns the other.
    let socket_out = Arc::clone(&socket);

    // Reader: pull datagrams off the wire and hand each to the processor.
    let reader = tokio::spawn(async move {
        // Extra headroom for the obfs prefix on top of the largest crypto datagram.
        let mut buf = vec![0u8; max_datagram_size(cipher) + obfs::MAX_HEADER];
        loop {
            let (n, peer) = socket
                .recv_from(&mut buf)
                .await
                .context("UDP recv_from failed")?;
            if tx.send((peer, buf[..n].to_vec())).await.is_err() {
                return Ok(()); // processor gone; nothing left to feed
            }
        }
    });

    // Processor: de-obfuscate, decrypt, route/rewrite, write to TUN.
    let processor = tokio::spawn(async move {
        while let Some((peer, pkt)) = rx.recv().await {
            let n = pkt.len();

            // De-obfuscate when enabled; a packet that doesn't match the configured
            // obfuscation is noise/probe traffic — drop it. `decoded` (a `Cow`)
            // borrows from `pkt` for QUIC and owns for base64.
            let decoded;
            let datagram: &[u8] = match obfuscator {
                Some(ref o) => match o.unwrap(&pkt) {
                    Some(inner) => {
                        decoded = inner;
                        &decoded
                    }
                    None => {
                        debug!("dropping {n}-byte non-obfs datagram from {peer}");
                        continue;
                    }
                },
                None => &pkt,
            };

            let mut plaintext = match decrypt_packet(cipher, &cfg.master_key, datagram) {
                Ok(pt) => pt,
                Err(err) => {
                    // Bad PSK, corruption, or stray traffic — drop and continue.
                    debug!("dropping {n}-byte datagram from {peer}: decrypt failed: {err}");
                    continue;
                }
            };

            let now = Instant::now();

            // Control messages (keepalives + mesh route messages) never reach
            // the TUN, but keep the sender's routing state fresh and may earn
            // a route push in reply.
            if mesh::is_control(&plaintext) {
                let reply = handle_control(&routing, &cfg.route_approval, peer, &plaintext, now);
                if let Some(push) = reply {
                    send_ciphered(
                        &socket_out,
                        cipher,
                        &cfg.master_key,
                        &obfuscator,
                        &push.encode(),
                        peer,
                    )
                    .await;
                }
                continue;
            }

            // Too small to carry even an IPv4 header: stray traffic, drop.
            if plaintext.len() < 20 {
                debug!(
                    "dropping {}-byte sub-IP-header payload from {peer}",
                    plaintext.len()
                );
                continue;
            }

            /// Where a decrypted inner packet goes next.
            enum Action {
                /// Deliver to this host / the wider network via TUN.
                Tun,
                /// Hub-relay straight back out to another client.
                Relay(SocketAddr),
                /// Drop (would bounce back to its sender).
                Bounce,
            }

            // Route/rewrite under the lock; release it before any await.
            let action = {
                let mut guard = routing.lock().unwrap();
                match &mut *guard {
                    Routing::Learn(learned) => {
                        if let Some(src) = ip_src(&plaintext) {
                            learned.learn(src, peer, "");
                        } else {
                            debug!("datagram from {peer} is not a parseable IP packet; forwarding");
                        }
                        match ip_dst(&plaintext).and_then(|dst| learned.lookup(dst)) {
                            // Spoke↔spoke: relay UDP→UDP without touching TUN.
                            Some(next) if next != peer => Action::Relay(next),
                            // The destination maps back to the sender itself;
                            // relaying would loop the packet.
                            Some(_) => Action::Bounce,
                            None => Action::Tun,
                        }
                    }
                    Routing::Nat(nat) => match nat.ingress(peer, &mut plaintext, now) {
                        Ingress::Rewritten(_) => Action::Tun,
                        Ingress::Exhausted => {
                            warn!("NAT address pool exhausted; dropping packet from {peer}");
                            continue;
                        }
                        Ingress::Invalid => {
                            debug!("unparseable IPv4 packet from {peer}; dropping");
                            continue;
                        }
                    },
                }
            };

            match action {
                Action::Tun => {
                    tun.send(&plaintext)
                        .await
                        .context("failed to write packet to TUN")?;
                }
                Action::Relay(next) => {
                    send_ciphered(
                        &socket_out,
                        cipher,
                        &cfg.master_key,
                        &obfuscator,
                        &plaintext,
                        next,
                    )
                    .await;
                }
                Action::Bounce => {
                    debug!("dropping {n}-byte packet from {peer}: destination routes back to its sender");
                }
            }
        }
        Ok(())
    });

    // First task to finish (only on a fatal error) ends the loop; abort the other.
    let mut reader = reader;
    let mut processor = processor;
    tokio::select! {
        r = &mut reader => { processor.abort(); r.context("UDP→TUN reader task panicked")? }
        r = &mut processor => { reader.abort(); r.context("UDP→TUN processor task panicked")? }
    }
}

/// Loop B: read IP packets from TUN, find the destination client, encrypt, send.
///
/// Same reader/processor split as [`udp_to_tun`]: a **reader** drains the TUN
/// device into a bounded channel, and a single **processor** resolves the
/// destination (rewriting under NAT), encrypts, obfuscates, and sends.
async fn tun_to_udp(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    routing: Shared,
    cfg: Arc<ServerConfig>,
    obfuscator: Option<Arc<Obfuscator>>,
) -> Result<()> {
    let cipher = cfg.cipher;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);

    // Reader: pull IP packets off the TUN device and hand each to the processor.
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_IP_PACKET];
        loop {
            let n = tun
                .recv(&mut buf)
                .await
                .context("failed to read from TUN")?;
            if tx.send(buf[..n].to_vec()).await.is_err() {
                return Ok(());
            }
        }
    });

    // Processor: resolve/rewrite the destination, encrypt, obfuscate, send.
    let processor = tokio::spawn(async move {
        while let Some(mut pkt) = rx.recv().await {
            let n = pkt.len();
            let now = Instant::now();

            // Resolve (and, in NAT mode, rewrite) the destination under the lock.
            let peer = {
                let mut guard = routing.lock().unwrap();
                match &mut *guard {
                    Routing::Learn(learned) => ip_dst(&pkt).and_then(|dst| learned.lookup(dst)),
                    Routing::Nat(nat) => nat.egress(&mut pkt, now),
                }
            };

            let peer = match peer {
                Some(peer) => peer,
                None => {
                    debug!("dropping {n}-byte TUN packet: no known client for its destination");
                    continue;
                }
            };

            let datagram = match encrypt_packet(cipher, &cfg.master_key, &pkt) {
                Ok(d) => d,
                Err(err) => {
                    warn!("failed to encrypt packet for {peer}: {err}");
                    continue;
                }
            };

            // Shape the reply to look like a QUIC packet when obfuscation is on.
            let datagram = match obfuscator {
                Some(ref o) => o.wrap(&datagram),
                None => datagram,
            };

            if let Err(err) = socket.send_to(&datagram, peer).await {
                // A transient send error to one client must not kill the server.
                warn!("failed to send datagram to {peer}: {err}");
            }
        }
        Ok(())
    });

    let mut reader = reader;
    let mut processor = processor;
    tokio::select! {
        r = &mut reader => { processor.abort(); r.context("TUN→UDP reader task panicked")? }
        r = &mut processor => { reader.abort(); r.context("TUN→UDP processor task panicked")? }
    }
}

/// Handle an authenticated control message (keepalive or mesh route message)
/// from `peer`, updating routing state. Returns a route push to send back when
/// the message was an advert from an accept-routes client. The payload has
/// already been AEAD-authenticated, so its contents are exactly as trustworthy
/// as the header fields of a data packet.
fn handle_control(
    routing: &Shared,
    approval: &RouteApproval,
    peer: SocketAddr,
    payload: &[u8],
    now: Instant,
) -> Option<RoutePush> {
    let control = match mesh::parse_control(payload) {
        Some(control) => control,
        None => {
            debug!(
                "dropping malformed {}-byte control payload from {peer}",
                payload.len()
            );
            return None;
        }
    };
    let mut guard = routing.lock().unwrap();
    match (&mut *guard, control) {
        // NAT mode identifies clients by endpoint alone: any control message
        // refreshes the lease, and mesh routing is unsupported (rejected at
        // config time on this server; other clients may still ask).
        (Routing::Nat(nat), control) => {
            nat.touch(peer, now);
            if !matches!(control, Control::Keepalive(_)) {
                debug!("ignoring mesh control from {peer}: NAT mode has no subnet routing");
            }
            None
        }
        (Routing::Learn(learned), Control::Keepalive(src)) => {
            if let Some(src) = src {
                learned.learn(IpAddr::V4(src), peer, " (keepalive)");
            }
            None
        }
        (Routing::Learn(learned), Control::RouteAdvert(advert)) => {
            // An advert doubles as a keepalive: learn/refresh the client's
            // tunnel addresses.
            learned.learn(IpAddr::V4(advert.tunnel_ip), peer, " (advert)");
            if let Some(ip6) = advert.tunnel_ip6 {
                learned.learn(IpAddr::V6(ip6), peer, " (advert)");
            }
            let outcome = learned
                .subnets
                .advertise(peer, &advert.routes, approval, now);
            let who = advert.tunnel_ip;
            for net in &outcome.approved {
                info!("subnet route {net} via client {who} approved");
            }
            for net in &outcome.awaiting {
                warn!(
                    "subnet route {net} from client {who} is awaiting approval \
                     (add it to approve_routes, or set auto_approve_routes)"
                );
            }
            for net in &outcome.moved {
                info!("subnet route {net} moved to client {who} ({peer})");
            }
            for net in &outcome.withdrawn {
                info!("subnet route {net} withdrawn by client {who}");
            }
            // Reply with the (split-horizon) approved set — even when empty,
            // so a client whose routes were all withdrawn removes them.
            advert.accept_routes.then(|| RoutePush {
                routes: learned.subnets.routes_for(peer),
            })
        }
        (Routing::Learn(_), Control::RoutePush(_)) => {
            debug!("ignoring route push from {peer}: pushes only flow server→client");
            None
        }
        (Routing::Learn(_), Control::AssignReq(_) | Control::Assign(_)) => {
            debug!("ignoring assign control from {peer}");
            None
        }
    }
}

/// Encrypt `plaintext`, apply carrier obfuscation, and send it to `peer`.
/// Failures are logged, never fatal: one bad relay/push must not kill the
/// server.
async fn send_ciphered(
    socket: &UdpSocket,
    cipher: shadowvpn::crypto::Cipher,
    master_key: &[u8],
    obfuscator: &Option<Arc<Obfuscator>>,
    plaintext: &[u8],
    peer: SocketAddr,
) {
    let datagram = match encrypt_packet(cipher, master_key, plaintext) {
        Ok(d) => d,
        Err(err) => {
            warn!(
                "failed to encrypt {}-byte payload for {peer}: {err}",
                plaintext.len()
            );
            return;
        }
    };
    let datagram = match obfuscator {
        Some(o) => o.wrap(&datagram),
        None => datagram,
    };
    if let Err(err) = socket.send_to(&datagram, peer).await {
        warn!("failed to send datagram to {peer}: {err}");
    }
}

/// Extract the source address from a raw IP packet (v4 or v6), or `None` if
/// the buffer is not a well-formed IP header.
fn ip_src(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        // IPv4: header ≥ 20 bytes, source at 12..16.
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        // IPv6: fixed 40-byte header, source at 8..24.
        6 if packet.len() >= 40 => Some(IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).expect("16 bytes"),
        ))),
        _ => None,
    }
}

/// Extract the destination address from a raw IP packet (v4 or v6), or `None`
/// if the buffer is not a well-formed IP header.
fn ip_dst(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        // IPv4: destination at 16..20.
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        // IPv6: destination at 24..40.
        6 if packet.len() >= 40 => Some(IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).expect("16 bytes"),
        ))),
        _ => None,
    }
}

/// Print a human-readable startup banner, including hints for enabling IP
/// forwarding / NAT so that tunneled clients can reach the wider network.
fn print_banner(cfg: &ServerConfig, tun_name: &str) {
    info!("ShadowVPN server starting");
    info!("  listen (UDP)   : {}", cfg.listen);
    info!("  cipher         : {}", cfg.cipher.name());
    info!(
        "  TUN interface  : {tun_name} ip={} netmask={} peer={} mtu={}",
        cfg.tun.ip, cfg.tun.netmask, cfg.tun.peer_ip, cfg.tun.mtu
    );
    if let Some(ip6) = cfg.tun.ip6 {
        info!("  TUN IPv6       : {ip6}");
    }
    info!("  routing        : learn inner src IP -> UDP addr; route by inner dst IP");
    if cfg.route_approval.auto {
        info!("  mesh routes    : auto-approving every advertised subnet route");
    } else if !cfg.route_approval.allowlist.is_empty() {
        info!(
            "  mesh routes    : approving advertised routes within {:?}",
            cfg.route_approval
                .allowlist
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }

    // Forwarding hints — these are environment changes the operator must make
    // outside this process to let clients route past the server.
    info!("To route client traffic beyond this host, enable forwarding + NAT:");
    #[cfg(target_os = "linux")]
    {
        info!("  Linux: sysctl -w net.ipv4.ip_forward=1");
        info!(
            "  Linux: iptables -t nat -A POSTROUTING -s {}/{} -o <wan-if> -j MASQUERADE",
            cfg.tun.ip, cfg.tun.netmask
        );
    }
    #[cfg(target_os = "macos")]
    {
        info!("  macOS: sysctl -w net.inet.ip.forwarding=1");
        info!(
            "  macOS: configure pf NAT (nat on <wan-if> from {} -> (<wan-if>))",
            cfg.tun.ip
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but valid 20-byte IPv4 header with the given src/dst.
    fn ipv4_header(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5 (20 bytes)
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    /// A minimal 40-byte IPv6 header with the given src/dst.
    fn ipv6_header(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60; // version 6
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn parses_v4_src_and_dst() {
        let p = ipv4_header([10, 7, 0, 2], [10, 7, 0, 1]);
        assert_eq!(ip_src(&p), Some("10.7.0.2".parse().unwrap()));
        assert_eq!(ip_dst(&p), Some("10.7.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_v6_src_and_dst() {
        let src: std::net::Ipv6Addr = "fd07:7::2".parse().unwrap();
        let dst: std::net::Ipv6Addr = "fd42:cafe::1".parse().unwrap();
        let p = ipv6_header(src, dst);
        assert_eq!(ip_src(&p), Some(IpAddr::V6(src)));
        assert_eq!(ip_dst(&p), Some(IpAddr::V6(dst)));
    }

    #[test]
    fn rejects_too_short() {
        let p = vec![0x45u8; 10];
        assert_eq!(ip_src(&p), None);
        assert_eq!(ip_dst(&p), None);
        // A v6 version nibble with a truncated (v4-sized) header is invalid.
        let p = vec![0x60u8; 20];
        assert_eq!(ip_src(&p), None);
        assert_eq!(ip_dst(&p), None);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut p = ipv4_header([1, 2, 3, 4], [5, 6, 7, 8]);
        p[0] = 0x50; // version 5
        assert_eq!(ip_src(&p), None);
        assert_eq!(ip_dst(&p), None);
    }

    #[test]
    fn learned_lookup_prefers_exact_client_over_subnet() {
        use shadowvpn::mesh::RouteApproval;

        let mut learned = Learned::default();
        let peer_a: SocketAddr = "198.51.100.1:1000".parse().unwrap();
        let peer_b: SocketAddr = "198.51.100.2:2000".parse().unwrap();
        learned.learn("10.77.0.2".parse().unwrap(), peer_a, "");
        learned.subnets.advertise(
            peer_b,
            &["10.77.0.0/16".parse().unwrap()],
            &RouteApproval {
                auto: true,
                allowlist: vec![],
            },
            Instant::now(),
        );

        // Exact client match beats the covering subnet route…
        assert_eq!(learned.lookup("10.77.0.2".parse().unwrap()), Some(peer_a));
        // …and everything else in the subnet goes to its advertiser.
        assert_eq!(learned.lookup("10.77.9.9".parse().unwrap()), Some(peer_b));
        assert_eq!(learned.lookup("192.0.2.1".parse().unwrap()), None);
    }

    #[test]
    fn control_handling_learns_and_replies_to_accepting_clients() {
        use shadowvpn::mesh::{RouteAdvert, RouteApproval};

        let routing: Shared = Arc::new(Mutex::new(Routing::Learn(Learned::default())));
        let approval = RouteApproval {
            auto: false,
            allowlist: vec!["192.168.200.0/24".parse().unwrap()],
        };
        let now = Instant::now();
        let router_peer: SocketAddr = "198.51.100.1:1000".parse().unwrap();
        let client_peer: SocketAddr = "198.51.100.2:2000".parse().unwrap();

        // The subnet router advertises one approved and one unapproved route
        // (and does not accept routes itself → no push back).
        let advert = RouteAdvert {
            tunnel_ip: "10.77.0.2".parse().unwrap(),
            tunnel_ip6: Some("fd07:7::2".parse().unwrap()),
            accept_routes: false,
            routes: vec![
                "192.168.200.0/24".parse().unwrap(),
                "10.99.0.0/16".parse().unwrap(),
            ],
        };
        assert_eq!(
            handle_control(&routing, &approval, router_peer, &advert.encode(), now),
            None
        );

        // An accepting client gets only the approved route, split-horizon.
        let advert = RouteAdvert {
            tunnel_ip: "10.77.0.3".parse().unwrap(),
            tunnel_ip6: None,
            accept_routes: true,
            routes: vec![],
        };
        let push = handle_control(&routing, &approval, client_peer, &advert.encode(), now)
            .expect("accepting client gets a push");
        assert_eq!(push.routes, vec!["192.168.200.0/24".parse().unwrap()]);

        // Learning happened for v4 and v6 tunnel addresses, and the approved
        // subnet routes through the advertiser.
        let guard = routing.lock().unwrap();
        let Routing::Learn(learned) = &*guard else {
            panic!("learning mode")
        };
        assert_eq!(
            learned.lookup("10.77.0.2".parse().unwrap()),
            Some(router_peer)
        );
        assert_eq!(
            learned.lookup("fd07:7::2".parse().unwrap()),
            Some(router_peer)
        );
        assert_eq!(
            learned.lookup("192.168.200.7".parse().unwrap()),
            Some(router_peer)
        );
        // The unapproved route is not routable.
        assert_eq!(learned.lookup("10.99.1.1".parse().unwrap()), None);
    }
}
