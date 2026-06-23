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
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use tokio::net::UdpSocket;

use shadowvpn::config::{ServerArgs, ServerConfig};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet};
use shadowvpn::nat::{Ingress, Nat};
use shadowvpn::obfs::{self, Obfuscator};
use shadowvpn::protocol::{max_datagram_size, MAX_IP_PACKET};
use shadowvpn::tun_device::TunDevice;

/// How the server maps inner IP packets to clients. Held behind a [`Mutex`] and
/// only touched synchronously (never across an `.await`).
enum Routing {
    /// Learn inner source IP → UDP peer; route by inner destination IP. Clients
    /// must use distinct tunnel IPs.
    Learn(HashMap<Ipv4Addr, SocketAddr>),
    /// NAT clients onto distinct internal IPs keyed by their UDP endpoint, so
    /// they can all share one static config.
    Nat(Nat),
}

/// Shared routing state.
type Shared = Arc<Mutex<Routing>>;

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
    let socket = UdpSocket::bind(&cfg.listen)
        .await
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
        Routing::Learn(HashMap::new())
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

    // NAT sweeper: periodically reclaim idle client mappings. Aborted when `run`
    // returns (the handle is dropped).
    let _sweeper = nat_enabled.then(|| {
        let routing = Arc::clone(&routing);
        let interval = (lease_ttl / 2).max(Duration::from_secs(5));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Routing::Nat(nat) = &mut *routing.lock().unwrap() {
                    nat.reap(Instant::now());
                }
            }
        })
    });

    // If either loop returns (only on a fatal IO error), tear the server down.
    tokio::select! {
        res = a => res.context("UDP→TUN task panicked")?,
        res = b => res.context("TUN→UDP task panicked")?,
    }
}

/// Loop A: receive encrypted datagrams, decrypt, route/rewrite, write to TUN.
async fn udp_to_tun(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    routing: Shared,
    cfg: Arc<ServerConfig>,
    obfuscator: Option<Arc<Obfuscator>>,
) -> Result<()> {
    let cipher = cfg.cipher;
    // Extra headroom for the obfs prefix on top of the largest crypto datagram.
    let mut buf = vec![0u8; max_datagram_size(cipher) + obfs::MAX_HEADER];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("UDP recv_from failed")?;

        // De-obfuscate when enabled; a packet that doesn't match the configured
        // obfuscation is noise/probe traffic — drop it. `decoded` owns the bytes
        // for variants (base64) that can't borrow from `buf`.
        let decoded;
        let datagram: &[u8] = match obfuscator {
            Some(ref o) => match o.unwrap(&buf[..n]) {
                Some(inner) => {
                    decoded = inner;
                    &decoded
                }
                None => {
                    debug!("dropping {n}-byte non-obfs datagram from {peer}");
                    continue;
                }
            },
            None => &buf[..n],
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

        // Sub-IP-header payloads (the client keepalive) must not reach TUN, but
        // still refresh the sender's NAT mapping so a quiet client isn't reaped.
        if plaintext.len() < 20 {
            if let Routing::Nat(nat) = &mut *routing.lock().unwrap() {
                nat.touch(peer, now);
            }
            debug!(
                "dropping {}-byte sub-IP-header payload from {peer} (keepalive?)",
                plaintext.len()
            );
            continue;
        }

        // Route/rewrite under the lock; release it before the awaited TUN write.
        let forward = {
            let mut guard = routing.lock().unwrap();
            match &mut *guard {
                Routing::Learn(clients) => {
                    if let Some(src) = ipv4_src(&plaintext) {
                        if clients.insert(src, peer) != Some(peer) {
                            info!("client {src} reachable via {peer}");
                        }
                    } else {
                        debug!("datagram from {peer} is not a parseable IPv4 packet; forwarding");
                    }
                    true
                }
                Routing::Nat(nat) => match nat.ingress(peer, &mut plaintext, now) {
                    Ingress::Rewritten(_) => true,
                    Ingress::Exhausted => {
                        warn!("NAT address pool exhausted; dropping packet from {peer}");
                        false
                    }
                    Ingress::Invalid => {
                        debug!("unparseable IPv4 packet from {peer}; dropping");
                        false
                    }
                },
            }
        };

        if forward {
            if let Err(err) = tun.send(&plaintext).await {
                // A TUN write error is fatal: the interface is gone or broken.
                return Err(err).context("failed to write packet to TUN");
            }
        }
    }
}

/// Loop B: read IP packets from TUN, find the destination client, encrypt, send.
async fn tun_to_udp(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    routing: Shared,
    cfg: Arc<ServerConfig>,
    obfuscator: Option<Arc<Obfuscator>>,
) -> Result<()> {
    let cipher = cfg.cipher;
    let mut buf = vec![0u8; MAX_IP_PACKET];
    loop {
        let n = tun
            .recv(&mut buf)
            .await
            .context("failed to read from TUN")?;
        let now = Instant::now();

        // Resolve (and, in NAT mode, rewrite) the destination under the lock.
        let peer = {
            let mut guard = routing.lock().unwrap();
            match &mut *guard {
                Routing::Learn(clients) => {
                    ipv4_dst(&buf[..n]).and_then(|dst| clients.get(&dst).copied())
                }
                Routing::Nat(nat) => nat.egress(&mut buf[..n], now),
            }
        };

        let peer = match peer {
            Some(peer) => peer,
            None => {
                debug!("dropping {n}-byte TUN packet: no known client for its destination");
                continue;
            }
        };

        let datagram = match encrypt_packet(cipher, &cfg.master_key, &buf[..n]) {
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
}

/// Extract the source IPv4 address from a raw IPv4 packet, or `None` if the
/// buffer is not a well-formed IPv4 header.
fn ipv4_src(packet: &[u8]) -> Option<Ipv4Addr> {
    // IPv4 header is at least 20 bytes; the version nibble must be 4. Source
    // address occupies bytes 12..16.
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

/// Extract the destination IPv4 address from a raw IPv4 packet, or `None` if the
/// buffer is not a well-formed IPv4 header.
fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    // Destination address occupies bytes 16..20 of the IPv4 header.
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
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
    info!("  routing        : learn inner src IP -> UDP addr; route by inner dst IP");

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

    #[test]
    fn parses_src_and_dst() {
        let p = ipv4_header([10, 7, 0, 2], [10, 7, 0, 1]);
        assert_eq!(ipv4_src(&p), Some(Ipv4Addr::new(10, 7, 0, 2)));
        assert_eq!(ipv4_dst(&p), Some(Ipv4Addr::new(10, 7, 0, 1)));
    }

    #[test]
    fn rejects_too_short() {
        let p = vec![0x45u8; 10];
        assert_eq!(ipv4_src(&p), None);
        assert_eq!(ipv4_dst(&p), None);
    }

    #[test]
    fn rejects_non_ipv4_version() {
        // Version 6 nibble.
        let mut p = ipv4_header([1, 2, 3, 4], [5, 6, 7, 8]);
        p[0] = 0x60;
        assert_eq!(ipv4_src(&p), None);
        assert_eq!(ipv4_dst(&p), None);
    }
}
