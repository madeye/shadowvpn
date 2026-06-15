//! ShadowVPN server entrypoint.
//!
//! The server terminates the encrypted UDP tunnel onto a local TUN device and
//! routes traffic between connected clients. It runs two concurrent loops over a
//! single shared [`UdpSocket`] and a single shared [`TunDevice`]:
//!
//! * **UDP → TUN** ([`udp_to_tun`]): receive an encrypted UDP datagram, decrypt
//!   it into a raw IP packet, learn the client's tunnel source IP (so we know
//!   where to route its return traffic), and write the packet to TUN.
//! * **TUN → UDP** ([`tun_to_udp`]): read a raw IP packet from TUN, look up the
//!   UDP address of the client that owns the packet's destination tunnel IP,
//!   encrypt the packet, and send it back over UDP.
//!
//! Routing uses a *client table* mapping an inner tunnel IPv4 address (the
//! source address inside a decrypted IP packet) to the UDP `SocketAddr` it was
//! last seen from. This supports a point-to-point link as well as multiple
//! clients sharing one tunnel subnet.
//!
//! Decrypt failures, malformed packets, and unknown-destination packets are
//! logged and dropped; they never crash the server.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use shadowvpn::config::{ServerArgs, ServerConfig};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet, Cipher};
use shadowvpn::protocol::{max_datagram_size, MAX_IP_PACKET};
use shadowvpn::tun_device::TunDevice;

/// Maps an inner tunnel IPv4 address to the UDP address of the client that owns
/// it (most recently seen). Shared between both forwarding loops.
type ClientTable = Arc<RwLock<HashMap<Ipv4Addr, SocketAddr>>>;

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
/// loops until one of them fails.
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

    let clients: ClientTable = Arc::new(RwLock::new(HashMap::new()));

    // Loop A: UDP → TUN.
    let a = {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let clients = Arc::clone(&clients);
        let cipher = cfg.cipher;
        let key = cfg.master_key.clone();
        tokio::spawn(async move { udp_to_tun(socket, tun, clients, cipher, key).await })
    };

    // Loop B: TUN → UDP.
    let b = {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let clients = Arc::clone(&clients);
        let cipher = cfg.cipher;
        let key = cfg.master_key.clone();
        tokio::spawn(async move { tun_to_udp(socket, tun, clients, cipher, key).await })
    };

    // If either loop returns (only on a fatal IO error), tear the server down.
    tokio::select! {
        res = a => res.context("UDP→TUN task panicked")?,
        res = b => res.context("TUN→UDP task panicked")?,
    }
}

/// Loop A: receive encrypted datagrams, decrypt, learn the source client, and
/// write the inner IP packet to TUN.
async fn udp_to_tun(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    clients: ClientTable,
    cipher: Cipher,
    master_key: Vec<u8>,
) -> Result<()> {
    let mut buf = vec![0u8; max_datagram_size(cipher)];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("UDP recv_from failed")?;

        let plaintext = match decrypt_packet(cipher, &master_key, &buf[..n]) {
            Ok(pt) => pt,
            Err(err) => {
                // Bad PSK, corruption, or stray traffic — drop and continue.
                debug!("dropping {n}-byte datagram from {peer}: decrypt failed: {err}");
                continue;
            }
        };

        // Drop sub-IP-header payloads (e.g. the client keepalive): too small to
        // be a real IP packet, must not be written to TUN. Mirrors the client.
        if plaintext.len() < 20 {
            debug!(
                "dropping {}-byte sub-IP-header payload from {peer} (keepalive?)",
                plaintext.len()
            );
            continue;
        }

        // Learn which client owns this inner source IP so return traffic
        // (TUN → UDP) can be routed back to it.
        if let Some(src) = ipv4_src(&plaintext) {
            let mut table = clients.write().await;
            if table.insert(src, peer) != Some(peer) {
                info!("client {src} reachable via {peer}");
            }
        } else {
            debug!("datagram from {peer} is not a parseable IPv4 packet; forwarding anyway");
        }

        if let Err(err) = tun.send(&plaintext).await {
            // A TUN write error is fatal: the interface is gone or broken.
            return Err(err).context("failed to write packet to TUN");
        }
    }
}

/// Loop B: read IP packets from TUN, look up the destination client's UDP
/// address, encrypt, and send. Packets to unknown destinations are dropped.
async fn tun_to_udp(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    clients: ClientTable,
    cipher: Cipher,
    master_key: Vec<u8>,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_IP_PACKET];
    loop {
        let n = tun
            .recv(&mut buf)
            .await
            .context("failed to read from TUN")?;
        let packet = &buf[..n];

        let dst = match ipv4_dst(packet) {
            Some(dst) => dst,
            None => {
                // Non-IPv4 (e.g. IPv6) — we have no route table for it. Drop.
                debug!("dropping {n}-byte TUN packet: not a parseable IPv4 packet");
                continue;
            }
        };

        let peer = {
            let table = clients.read().await;
            table.get(&dst).copied()
        };

        let peer = match peer {
            Some(peer) => peer,
            None => {
                debug!("dropping packet for {dst}: no known client");
                continue;
            }
        };

        let datagram = match encrypt_packet(cipher, &master_key, packet) {
            Ok(d) => d,
            Err(err) => {
                // Encryption of a well-formed packet should not fail; log loudly
                // but keep serving other traffic.
                warn!("failed to encrypt packet for {dst} ({peer}): {err}");
                continue;
            }
        };

        if let Err(err) = socket.send_to(&datagram, peer).await {
            // A transient send error to one client must not kill the server.
            warn!("failed to send datagram to {dst} ({peer}): {err}");
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
