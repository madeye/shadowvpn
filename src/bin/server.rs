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
//! With `--auto-assign`, the server also runs an in-band control channel (see
//! [`shadowvpn::control`]): a client may REQUEST a tunnel IP, which the server
//! draws from a [`LeasePool`] over the TUN subnet and returns in an ASSIGN.
//! Leases are refreshed by ongoing traffic and reclaimed when idle.
//!
//! Decrypt failures, malformed packets, and unknown-destination packets are
//! logged and dropped; they never crash the server.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use shadowvpn::config::{ServerArgs, ServerConfig};
use shadowvpn::control::{self, Control};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet, Cipher};
use shadowvpn::obfs::{self, Obfuscator};
use shadowvpn::pool::LeasePool;
use shadowvpn::protocol::{max_datagram_size, MAX_IP_PACKET};
use shadowvpn::tun_device::TunDevice;

/// Routing + lease state shared by both forwarding loops and the lease sweeper.
struct Router {
    /// Inner tunnel IP → UDP address of the owning client (the return path).
    clients: HashMap<Ipv4Addr, SocketAddr>,
    /// UDP address → the IP currently leased to it. Drives request idempotency
    /// and keepalive-based lease refresh; only populated for auto-assigned peers.
    assigned: HashMap<SocketAddr, Ipv4Addr>,
    /// Address pool, present only when `--auto-assign` is enabled.
    pool: Option<LeasePool>,
}

/// Shared, lockable [`Router`].
type Shared = Arc<RwLock<Router>>;

impl Router {
    fn new(pool: Option<LeasePool>) -> Self {
        Self {
            clients: HashMap::new(),
            assigned: HashMap::new(),
            pool,
        }
    }

    /// Learn (or refresh) that inner source IP `src` is reachable via `peer`,
    /// logging when reachability changes. Refreshes the lease if `src` is an
    /// auto-assigned address.
    fn learn(&mut self, src: Ipv4Addr, peer: SocketAddr, now: Instant) {
        if self.clients.insert(src, peer) != Some(peer) {
            info!("client {src} reachable via {peer}");
        }
        if let Some(pool) = self.pool.as_mut() {
            if pool.refresh(src, now) {
                self.assigned.insert(peer, src);
            }
        }
    }

    /// Refresh the lease tied to `peer`. Used for keepalives/control frames,
    /// which carry no inner IP. No-op for statically configured clients.
    fn touch(&mut self, peer: SocketAddr, now: Instant) {
        if let (Some(pool), Some(&ip)) = (self.pool.as_mut(), self.assigned.get(&peer)) {
            pool.refresh(ip, now);
        }
    }

    /// Handle an auto-IP REQUEST from `peer`: reuse its current lease (so a
    /// retransmitted request is idempotent) or allocate a fresh address. Returns
    /// the control reply to send back.
    fn request(&mut self, peer: SocketAddr, now: Instant, cfg: &ServerConfig) -> Control {
        let pool = match self.pool.as_mut() {
            Some(p) => p,
            None => return Control::Nak(control::nak::NOT_ENABLED),
        };
        let ip = if let Some(&ip) = self.assigned.get(&peer) {
            pool.refresh(ip, now);
            ip
        } else {
            match pool.allocate(now) {
                Some(ip) => ip,
                None => {
                    warn!("address pool exhausted; refusing {peer}");
                    return Control::Nak(control::nak::POOL_EXHAUSTED);
                }
            }
        };
        self.assigned.insert(peer, ip);
        self.clients.insert(ip, peer);
        info!("assigned {ip} to {peer}");
        Control::Assign {
            ip,
            netmask: cfg.tun.netmask,
            peer_ip: cfg.tun.ip,
            mtu: cfg.tun.mtu,
        }
    }

    /// Reclaim idle leases and drop their routing state.
    fn reap(&mut self, now: Instant) {
        let freed = match self.pool.as_mut() {
            Some(p) => p.reap(now),
            None => return,
        };
        for ip in freed {
            if let Some(peer) = self.clients.remove(&ip) {
                self.assigned.remove(&peer);
            }
            info!("reclaimed idle lease {ip}");
        }
    }
}

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
/// loops (plus the lease sweeper) until one of them fails.
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

    // Build the lease pool up front (so its capacity can be logged) when
    // auto-assignment is enabled.
    let pool = if cfg.auto_assign {
        let p = LeasePool::new(cfg.tun.ip, cfg.tun.netmask, cfg.lease_ttl);
        info!(
            "  auto-assign    : ENABLED ({} addresses, lease TTL {}s)",
            p.capacity(),
            cfg.lease_ttl.as_secs()
        );
        Some(p)
    } else {
        None
    };
    let router: Shared = Arc::new(RwLock::new(Router::new(pool)));

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

    let auto_assign = cfg.auto_assign;
    let lease_ttl = cfg.lease_ttl;
    let cfg = Arc::new(cfg);

    // Loop A: UDP → TUN.
    let a = {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let router = Arc::clone(&router);
        let cfg = Arc::clone(&cfg);
        let obfs = obfuscator.clone();
        tokio::spawn(async move { udp_to_tun(socket, tun, router, cfg, obfs).await })
    };

    // Loop B: TUN → UDP.
    let b = {
        let socket = Arc::clone(&socket);
        let tun = Arc::clone(&tun);
        let router = Arc::clone(&router);
        let cfg = Arc::clone(&cfg);
        let obfs = obfuscator.clone();
        tokio::spawn(async move { tun_to_udp(socket, tun, router, cfg, obfs).await })
    };

    // Lease sweeper: periodically reclaim idle leases. Runs only when
    // auto-assignment is on; aborted when `run` returns (handles dropped).
    let _sweeper = auto_assign.then(|| {
        let router = Arc::clone(&router);
        let interval = (lease_ttl / 2).max(Duration::from_secs(5));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                router.write().await.reap(Instant::now());
            }
        })
    });

    // If either loop returns (only on a fatal IO error), tear the server down.
    tokio::select! {
        res = a => res.context("UDP→TUN task panicked")?,
        res = b => res.context("TUN→UDP task panicked")?,
    }
}

/// Loop A: receive encrypted datagrams, decrypt, dispatch control frames, learn
/// the source client, and write inner IP packets to TUN.
async fn udp_to_tun(
    socket: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    router: Shared,
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

        let plaintext = match decrypt_packet(cipher, &cfg.master_key, datagram) {
            Ok(pt) => pt,
            Err(err) => {
                // Bad PSK, corruption, or stray traffic — drop and continue.
                debug!("dropping {n}-byte datagram from {peer}: decrypt failed: {err}");
                continue;
            }
        };

        let now = Instant::now();

        // In-band control channel (auto-IP). Control frames are never written to
        // TUN.
        if let Some(ctrl) = control::parse(&plaintext) {
            match ctrl {
                Control::Request => {
                    let reply = router.write().await.request(peer, now, &cfg);
                    send_control(&socket, cipher, &cfg.master_key, &obfuscator, peer, &reply).await;
                }
                other => debug!("ignoring unexpected control frame from {peer}: {other:?}"),
            }
            continue;
        }

        // Drop sub-IP-header payloads (e.g. the client keepalive): too small to
        // be a real IP packet. Still refresh the sender's lease, since a quiet
        // client relies on keepalives to keep its address.
        if plaintext.len() < 20 {
            router.write().await.touch(peer, now);
            debug!(
                "dropping {}-byte sub-IP-header payload from {peer} (keepalive?)",
                plaintext.len()
            );
            continue;
        }

        // Learn which client owns this inner source IP so return traffic
        // (TUN → UDP) can be routed back to it.
        if let Some(src) = ipv4_src(&plaintext) {
            router.write().await.learn(src, peer, now);
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
    router: Shared,
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
            let router = router.read().await;
            router.clients.get(&dst).copied()
        };

        let peer = match peer {
            Some(peer) => peer,
            None => {
                debug!("dropping packet for {dst}: no known client");
                continue;
            }
        };

        let datagram = match encrypt_packet(cipher, &cfg.master_key, packet) {
            Ok(d) => d,
            Err(err) => {
                // Encryption of a well-formed packet should not fail; log loudly
                // but keep serving other traffic.
                warn!("failed to encrypt packet for {dst} ({peer}): {err}");
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
            warn!("failed to send datagram to {dst} ({peer}): {err}");
        }
    }
}

/// Encrypt and send a control frame to `peer` (with obfuscation if enabled).
/// Best-effort: a failure is logged, not fatal.
async fn send_control(
    socket: &UdpSocket,
    cipher: Cipher,
    master_key: &[u8],
    obfuscator: &Option<Arc<Obfuscator>>,
    peer: SocketAddr,
    ctrl: &Control,
) {
    let datagram = match encrypt_packet(cipher, master_key, &ctrl.encode()) {
        Ok(d) => d,
        Err(err) => {
            warn!("failed to encrypt control frame for {peer}: {err}");
            return;
        }
    };
    let wire = match obfuscator {
        Some(o) => o.wrap(&datagram),
        None => datagram,
    };
    if let Err(err) = socket.send_to(&wire, peer).await {
        warn!("failed to send control frame to {peer}: {err}");
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

    /// A REQUEST allocates a lease and routes it; a retransmit is idempotent.
    #[test]
    fn request_allocates_then_is_idempotent() {
        let cfg = test_cfg();
        let mut r = Router::new(Some(LeasePool::new(
            cfg.tun.ip,
            cfg.tun.netmask,
            cfg.lease_ttl,
        )));
        let peer: SocketAddr = "203.0.113.5:5000".parse().unwrap();
        let now = Instant::now();

        let first = r.request(peer, now, &cfg);
        let ip = match first {
            Control::Assign { ip, peer_ip, .. } => {
                assert_eq!(peer_ip, cfg.tun.ip);
                ip
            }
            other => panic!("expected Assign, got {other:?}"),
        };
        assert_eq!(r.clients.get(&ip), Some(&peer));

        // Same peer asks again → same IP, no second allocation.
        match r.request(peer, now, &cfg) {
            Control::Assign { ip: again, .. } => assert_eq!(again, ip),
            other => panic!("expected Assign, got {other:?}"),
        }
    }

    /// Without a pool (auto-assign off), a request is refused.
    #[test]
    fn request_without_pool_is_naked() {
        let cfg = test_cfg();
        let mut r = Router::new(None);
        let peer: SocketAddr = "203.0.113.6:5000".parse().unwrap();
        assert!(matches!(
            r.request(peer, Instant::now(), &cfg),
            Control::Nak(_)
        ));
    }

    /// A reaped lease drops its routing entries.
    #[test]
    fn reap_clears_routing_state() {
        let mut cfg = test_cfg();
        cfg.lease_ttl = Duration::from_secs(10);
        let mut r = Router::new(Some(LeasePool::new(
            cfg.tun.ip,
            cfg.tun.netmask,
            cfg.lease_ttl,
        )));
        let peer: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        let t0 = Instant::now();
        let ip = match r.request(peer, t0, &cfg) {
            Control::Assign { ip, .. } => ip,
            other => panic!("expected Assign, got {other:?}"),
        };
        r.reap(t0 + Duration::from_secs(11));
        assert!(!r.clients.contains_key(&ip));
        assert!(!r.assigned.contains_key(&peer));
    }

    fn test_cfg() -> ServerConfig {
        use shadowvpn::config::TunConfig;
        use shadowvpn::crypto::Cipher;
        ServerConfig {
            listen: "0.0.0.0:8388".to_string(),
            cipher: Cipher::ChaCha20Poly1305,
            master_key: vec![0u8; 32],
            tun: TunConfig {
                name: None,
                ip: Ipv4Addr::new(10, 9, 0, 1),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                peer_ip: Ipv4Addr::new(10, 9, 0, 2),
                mtu: 1400,
            },
            obfs: None,
            auto_assign: true,
            lease_ttl: Duration::from_secs(120),
        }
    }
}
