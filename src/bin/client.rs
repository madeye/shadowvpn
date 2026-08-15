//! ShadowVPN client.
//!
//! The client owns a TUN device (assigned the client tunnel IP, e.g.
//! `10.7.0.2/24`) and a single UDP socket *connected* to the server. It runs two
//! concurrent loops:
//!
//! * **Loop A (TUN -> net):** read one raw IP packet from the TUN device,
//!   encrypt it into a single shadowsocks-AEAD UDP datagram
//!   (`salt ++ AEAD(ciphertext ++ tag)`), and send it to the server.
//! * **Loop B (net -> TUN):** receive one UDP datagram from the server, decrypt
//!   it back into a raw IP packet, and write that packet to the TUN device.
//!
//! Because UDP datagram boundaries are the frame boundaries (see
//! [`shadowvpn::protocol`]), one IP packet maps to exactly one datagram; there is
//! no length prefix or reassembly.
//!
//! # Keepalive
//!
//! Static clients send a 5-byte plaintext (`0x00` + tunnel IPv4) or a mesh
//! `RouteAdvert`. Auto-assign clients send `AssignRequest` instead (it carries
//! `node_id`); mesh adds a `RouteAdvert` as a second datagram on the same tick.
//!
//! # Routing (NOT done automatically)
//!
//! The client deliberately does **not** touch the system routing table or the
//! default route — doing so silently is dangerous and platform-specific. After
//! the interface comes up, the client logs the suggested commands to route
//! traffic through the tunnel. See [`print_routing_hint`].

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Parser;
use ipnetwork::Ipv6Network;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use shadowvpn::config::{ClientArgs, ClientConfig, TunConfig};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet, Cipher};
use shadowvpn::magic::{apply_push, PeerTable};
use shadowvpn::mesh::{self, Assign, AssignStatus, RouteInstaller};
use shadowvpn::obfs::{self, Obfuscator};
use shadowvpn::protocol::{max_datagram_size, MAX_IP_PACKET};
use shadowvpn::state::{default_client_state_path, write_private};
use shadowvpn::tun_device::{SubnetRouteGuard, TunDevice};

/// Depth of the hand-off channel between each relay loop's I/O reader and its
/// processor (see the server for the rationale). Bounded for backpressure.
const CHANNEL_DEPTH: usize = 1024;

/// Pause after a transient receive error before retrying: queued ICMP errors
/// surface back-to-back, and without a breather a condition that persists for
/// a few seconds would spin the receive loop.
const TRANSIENT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// How often to resend `AssignRequest` until the first Ok.
const ASSIGN_RETRY: Duration = Duration::from_secs(1);

/// Fatal if the server never answers (old server or lost replies).
const ASSIGN_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared slot so `run` can drop/recreate the installer when the assigned IPv4 changes.
type InstallerSlot = Arc<Mutex<Option<Arc<RouteInstaller>>>>;

/// Plaintext payload of a keepalive datagram: a `0x00` marker byte followed by
/// the client's 4-byte tunnel IP. At 5 bytes it is smaller than any real IP
/// packet header, so the server can distinguish/drop it cheaply; the announced
/// tunnel IP lets the server learn/refresh this client's UDP source address
/// from the keepalive alone, before any real traffic flows. (Servers predating
/// the address suffix simply drop the datagram, same as the old bare `0x00`.)
fn keepalive_payload(tun_ip: Ipv4Addr) -> [u8; 5] {
    let [a, b, c, d] = tun_ip.octets();
    [0u8, a, b, c, d]
}

#[tokio::main]
async fn main() -> Result<()> {
    // Default to `info` logging; override with `RUST_LOG`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = ClientArgs::parse();

    // Journal-only recovery mode: put the resolver back after a run that died
    // without cleaning up (typically invoked by the desktop app's elevated
    // helper), then exit without bringing up a tunnel.
    if args.restore_dns {
        if !shadowvpn::policy::dnsconf::restore_from_journal()? {
            info!("no DNS restore journal found; nothing to do");
        }
        return Ok(());
    }

    let cfg = args
        .resolve()
        .context("failed to resolve client configuration")?;

    run(cfg).await
}

/// Bring up the TUN device + UDP socket and drive the two relay loops until one
/// of them fails (or the process is signalled).
async fn run(mut cfg: ClientConfig) -> Result<()> {
    // The master key length is guaranteed to match the cipher by `resolve()`.
    let cipher = cfg.cipher;
    let master_key: Arc<[u8]> = Arc::from(cfg.master_key.as_slice());

    // Carrier obfuscation, matching the server. When enabled, every datagram is
    // wrapped on send and unwrapped on recv; `None` is the plain envelope. Both
    // ends must agree (see `obfs`).
    let obfuscator: Option<Arc<Obfuscator>> = cfg
        .obfs
        .as_deref()
        .and_then(Obfuscator::from_name)
        .map(Arc::new);
    if let Some(name) = cfg.obfs.as_deref() {
        info!("carrier obfuscation: {name}");
    }

    // --- UDP socket ---------------------------------------------------------
    // Bind to an ephemeral local port on the unspecified address, then
    // `connect()` to the server so we can use send/recv (no per-call addr) and
    // benefit from kernel-side source-address selection + ICMP error reporting.
    //
    // This MUST happen *before* the TUN device is brought up. On Windows the
    // freshly-created Wintun adapter perturbs source-address selection, and a
    // `connect()` issued while it is up fails with `WSAEHOSTUNREACH` even though
    // the physical default route is unchanged. Connecting first resolves the
    // route against the pristine table and pins the socket to the physical
    // 5-tuple, so the tunnel coming up afterwards no longer affects it.
    let socket = shadowvpn::net::bind_udp("0.0.0.0:0".parse().expect("valid bind address"))
        .context("failed to bind local UDP socket")?;
    // Resolve the server's address with the built-in DNS client (querying the
    // clean/local upstreams directly) rather than the OS resolver, which may be
    // pinned at a not-yet-listening split-DNS proxy on 127.0.0.1 left over from a
    // previous run. The tunnel is not up yet, so these queries egress the
    // physical interface like the tunnel datagrams themselves.
    let server_addr = shadowvpn::net::resolve_server(
        &cfg.server,
        &[cfg.policy.dns_remote, cfg.policy.dns_local],
        cfg.policy.dns_timeout,
    )
    .await
    .with_context(|| format!("failed to resolve server address {}", cfg.server))?;
    if server_addr.to_string() != cfg.server {
        info!("resolved server {} -> {server_addr}", cfg.server);
    }
    socket.connect(server_addr).await.with_context(|| {
        format!(
            "failed to connect UDP socket to server {} ({server_addr})",
            cfg.server
        )
    })?;
    // The physical source address the OS chose to reach the server. Policy
    // routing binds direct (domestic) DNS queries to it on Windows so they don't
    // get mis-routed into the tunnel once it is up.
    let direct_src = socket
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let local_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!("UDP socket {local_addr} connected to server {}", cfg.server);
    let socket = Arc::new(socket);

    // --- Identity / cache (auto only; want_ip6 is already frozen) -----------
    let state_path = cfg
        .state_file
        .clone()
        .unwrap_or_else(|| default_client_state_path(None, &cfg.server));
    let node_id = if cfg.auto_tun {
        let (id, last) = load_or_create_state(&state_path, &cfg.server);
        if let Some(last) = last {
            cfg.overlay_cached_assignment(
                last.tun_ip,
                last.tun_netmask,
                last.peer_ip,
                last.tun_ip6,
            );
        }
        id
    } else {
        [0u8; 16]
    };

    // --- TUN device ---------------------------------------------------------
    // Auto always uses unaddressed+apply so Windows never gets a default route.
    let tun = if cfg.auto_tun {
        let tun = TunDevice::create_unaddressed(cfg.tun.name.as_deref(), cfg.tun.mtu).context(
            "failed to create TUN device (need root/elevated privileges); \
                 auto-assign (no IPv4 yet)",
        )?;
        if !cfg.tun.ip.is_unspecified() {
            tun.apply_assignment(cfg.tun.ip, cfg.tun.netmask, cfg.tun.peer_ip, cfg.tun.ip6)
                .context("failed to apply cached tunnel assignment")?;
        }
        tun
    } else {
        TunDevice::create(&cfg.tun).with_context(|| {
            format!(
                "failed to create TUN device (need root/elevated privileges); \
                 requested ip={} peer={} mtu={}",
                cfg.tun.ip, cfg.tun.peer_ip, cfg.tun.mtu
            )
        })?
    };
    let tun = Arc::new(tun);

    let iface_name = tun.name().unwrap_or_else(|_| {
        cfg.tun
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string())
    });
    if cfg.auto_tun && cfg.tun.ip.is_unspecified() {
        info!(
            "TUN up: iface={iface_name} mtu={} (waiting for assignment)",
            cfg.tun.mtu
        );
    } else {
        info!(
            "TUN up: iface={iface_name} ip={} peer={} netmask={} mtu={}",
            cfg.tun.ip, cfg.tun.peer_ip, cfg.tun.netmask, cfg.tun.mtu
        );
    }

    if !cfg.advertise_routes.is_empty() {
        info!(
            "advertising subnet routes to the server: {}",
            cfg.advertise_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if cfg.accept_routes {
        info!("accepting subnet routes pushed by the server");
    }
    if cfg.magic_dns {
        info!(
            "magic DNS: hostname={} suffix={}",
            cfg.hostname, cfg.magic_dns_suffix
        );
    }

    let peers = Arc::new(PeerTable::new());
    let magic_suffix = cfg.magic_dns_suffix.clone();

    // Policy / RouteInstaller store an immutable tun_ip: only build once IPv4
    // is known (a cache counts). Recreated below if the server hands out a new IP.
    let mut policy_handle = None;
    let installer_slot: InstallerSlot = Arc::new(Mutex::new(None));
    let mut _route_guard = None;
    let mut subnet_guard = None;
    let mut hinted_routing = false;

    if !cfg.tun.ip.is_unspecified() {
        start_policy_and_installer(
            &cfg,
            &iface_name,
            server_addr.ip(),
            direct_src,
            &mut policy_handle,
            &installer_slot,
            &mut _route_guard,
            Arc::clone(&peers),
        )
        .await?;
        if cfg.auto_tun {
            let mut guard =
                SubnetRouteGuard::new(&iface_name).context("setting up the TUN subnet route")?;
            guard
                .apply(cfg.tun.ip, cfg.tun.netmask, cfg.tun.ip6)
                .context("installing cached TUN subnet route")?;
            subnet_guard = Some(guard);
        }
        if !cfg.policy.mode.is_enabled() {
            print_routing_hint(&cfg.tun, &cfg.server);
            hinted_routing = true;
        }
    }

    // Auto: drop every TUN read (including IPv6 NS) until Assign Ok.
    let assigned_ok = Arc::new(AtomicBool::new(!cfg.auto_tun));
    let (assign_tx, mut assign_rx) = mpsc::channel::<Assign>(8);

    // --- Relay + keepalive tasks -------------------------------------------
    let mut up = tokio::spawn(tun_to_net(
        Arc::clone(&tun),
        Arc::clone(&socket),
        cipher,
        Arc::clone(&master_key),
        obfuscator.clone(),
        Arc::clone(&assigned_ok),
    ));

    let mut down = tokio::spawn(net_to_tun(
        Arc::clone(&tun),
        Arc::clone(&socket),
        cipher,
        Arc::clone(&master_key),
        obfuscator.clone(),
        Arc::clone(&installer_slot),
        cfg.auto_tun.then_some(assign_tx),
        Arc::clone(&peers),
        magic_suffix,
    ));

    // Static clients keep the 5-byte keepalive / RouteAdvert / NameAdvert tick.
    let mut keepalive = if cfg.auto_tun {
        None
    } else {
        let mut periodic = cfg.static_tick_payloads();
        if periodic.is_empty() {
            periodic.push(keepalive_payload(cfg.tun.ip).to_vec());
        }
        Some(tokio::spawn(keepalive_loop(
            Arc::clone(&socket),
            cipher,
            Arc::clone(&master_key),
            obfuscator.clone(),
            cfg.keepalive,
            periodic,
        )))
    };

    let mut assign_retry = if cfg.auto_tun {
        let mut ticker = tokio::time::interval(ASSIGN_RETRY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Some(ticker)
    } else {
        None
    };
    let assign_deadline = Instant::now() + ASSIGN_TIMEOUT;
    let mut keep_tick: Option<tokio::time::Interval> = None;
    let mut got_ok = !cfg.auto_tun;

    loop {
        // Process Assign outside `select` so we can drop/respawn `policy_handle`.
        let mut pending_assign: Option<Assign> = None;
        tokio::select! {
            r = &mut up => return propagate("tun->net", r),
            r = &mut down => return propagate("net->tun", r),
            r = join_opt(&mut keepalive) => return propagate("keepalive", r),
            r = policy_task_result(&mut policy_handle) => return r,
            _ = shutdown_signal() => {
                info!("received shutdown signal; shutting down");
                return Ok(());
            }
            reply = assign_rx.recv(), if cfg.auto_tun => {
                pending_assign = Some(reply.context("assignment channel closed")?);
            }
            _ = tick_opt(&mut assign_retry), if !got_ok => {
                if Instant::now() >= assign_deadline {
                    bail!(
                        "server did not assign an IP; set a static tun_ip or upgrade the server"
                    );
                }
                send_control(
                    socket.as_ref(),
                    cipher,
                    master_key.as_ref(),
                    obfuscator.as_deref(),
                    &cfg.assign_request(node_id),
                )
                .await?;
            }
            _ = tick_opt(&mut keep_tick) => {
                // After Ok, AssignRequest *is* the keepalive (carries node_id).
                for payload in cfg.auto_tick_payloads(node_id) {
                    send_control(
                        socket.as_ref(),
                        cipher,
                        master_key.as_ref(),
                        obfuscator.as_deref(),
                        &payload,
                    )
                    .await?;
                }
            }
        }
        if let Some(reply) = pending_assign {
            handle_assign_reply(
                reply,
                &mut cfg,
                &tun,
                &iface_name,
                server_addr.ip(),
                direct_src,
                &state_path,
                node_id,
                &assigned_ok,
                &mut got_ok,
                &mut assign_retry,
                &mut keep_tick,
                &mut policy_handle,
                &installer_slot,
                &mut _route_guard,
                &mut subnet_guard,
                &mut hinted_routing,
                socket.as_ref(),
                cipher,
                master_key.as_ref(),
                obfuscator.as_deref(),
                Arc::clone(&peers),
            )
            .await?;
        }
    }
}

/// Resolve when the OS asks the process to terminate (Ctrl-C / SIGTERM on Unix,
/// Ctrl-C / close / shutdown on Windows), so the run loop can exit gracefully.
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// See the Unix variant; on Windows there is no SIGTERM, so we watch the console
/// control events instead.
#[cfg(windows)]
async fn shutdown_signal() {
    use tokio::signal::windows;
    let mut close = windows::ctrl_close().expect("install ctrl-close handler");
    let mut shutdown = windows::ctrl_shutdown().expect("install ctrl-shutdown handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = close.recv() => {}
        _ = shutdown.recv() => {}
    }
}

/// Flatten a `JoinHandle` result + inner loop result into a single `Result`,
/// tagging which loop produced it.
fn propagate(which: &str, joined: Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match joined {
        Ok(inner) => inner.with_context(|| format!("{which} loop failed")),
        Err(join_err) => {
            Err(anyhow::Error::new(join_err).context(format!("{which} task panicked/aborted")))
        }
    }
}

/// I/O errors on the connected UDP socket that reflect a transient *network*
/// condition rather than a broken socket: an ICMP unreachable bounced back
/// while a NAT on the path rebinds (`ECONNREFUSED`/`ECONNRESET`/
/// `EHOSTUNREACH`/`ENETUNREACH`), the physical interface flapping
/// (`ENETDOWN`/`EADDRNOTAVAIL`), or a momentarily full output queue
/// (`ENOBUFS`, common on macOS under load). Exiting on one of these turns a
/// seconds-long blip into a dead tunnel (a ~1 AM home-router NAT reset used
/// to take the client down for the rest of the night), so the relay and
/// keepalive loops log, drop the affected datagram, and keep going — the
/// path heals on its own.
fn is_transient_udp_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    // ENOBUFS has no dedicated `ErrorKind`; match the raw OS error.
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ENOBUFS) {
        return true;
    }
    #[cfg(windows)]
    if e.raw_os_error() == Some(10055) {
        // WSAENOBUFS
        return true;
    }
    matches!(
        e.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::AddrNotAvailable
            | ErrorKind::Interrupted
    )
}

/// Loop A: read raw IP packets from TUN, encrypt, and send to the server.
///
/// Pipelined so TUN reads overlap the per-packet encryption + UDP send: a
/// **reader** drains the TUN device into a bounded channel, and a single
/// **processor** encrypts, obfuscates, and sends (order preserved).
async fn tun_to_net(
    tun: Arc<TunDevice>,
    socket: Arc<UdpSocket>,
    cipher: Cipher,
    master_key: Arc<[u8]>,
    obfuscator: Option<Arc<Obfuscator>>,
    assigned_ok: Arc<AtomicBool>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);

    // Reader: pull IP packets off the TUN device and hand each to the processor.
    let reader = tokio::spawn(async move {
        // Plaintext buffer sized for the largest IP packet we might read.
        let mut buf = vec![0u8; MAX_IP_PACKET];
        loop {
            let n = tun
                .recv(&mut buf)
                .await
                .context("failed to read from TUN device")?;
            if n == 0 {
                continue;
            }
            // Unaddressed / cached-but-unconfirmed TUN still emits IPv6 NS.
            if !assigned_ok.load(Ordering::Acquire) {
                debug!("dropping {n}-byte TUN packet until Assign Ok");
                continue;
            }
            if tx.send(buf[..n].to_vec()).await.is_err() {
                return Ok(());
            }
        }
    });

    // Processor: encrypt, obfuscate, and send to the server.
    let processor = tokio::spawn(async move {
        // Consecutive transient send failures (see `is_transient_udp_error`):
        // warn once when a burst starts, then stay quiet until it clears.
        let mut send_failures: u64 = 0;
        while let Some(pkt) = rx.recv().await {
            let n = pkt.len();

            // Encrypt this IP packet into one on-wire datagram. A crypto failure
            // here is non-fatal (skip the packet) — it should not normally happen
            // since we control the key and input.
            let datagram = match encrypt_packet(cipher, &master_key, &pkt) {
                Ok(d) => d,
                Err(e) => {
                    warn!("failed to encrypt a {n}-byte packet, dropping: {e}");
                    continue;
                }
            };

            // Apply carrier obfuscation (if enabled) just before the wire.
            let wire = match obfuscator {
                Some(ref o) => o.wrap(&datagram),
                None => datagram,
            };

            // A transient path error drops this packet (the peers' transport
            // protocols retransmit); anything else is fatal.
            if let Err(e) = socket.send(&wire).await {
                if is_transient_udp_error(&e) {
                    send_failures += 1;
                    if send_failures == 1 {
                        warn!("transient send error, dropping packets until the path clears: {e}");
                    } else {
                        debug!("transient send error #{send_failures}: {e}");
                    }
                    continue;
                }
                return Err(e).context("failed to send datagram to server");
            }
            if send_failures > 0 {
                info!("send path recovered after {send_failures} dropped packet(s)");
                send_failures = 0;
            }
            debug!(
                "tun->net: {n} bytes plaintext -> {} bytes on wire",
                wire.len()
            );
        }
        Ok(())
    });

    let mut reader = reader;
    let mut processor = processor;
    tokio::select! {
        r = &mut reader => { processor.abort(); r.context("tun->net reader task panicked")? }
        r = &mut processor => { reader.abort(); r.context("tun->net processor task panicked")? }
    }
}

/// Loop B: receive datagrams from the server, decrypt, and write the resulting
/// IP packet to the TUN device.
///
/// Pipelined so UDP receives overlap decryption + the TUN write: a **reader**
/// drains the socket into a bounded channel (so reply bursts are not dropped
/// while a packet is being decrypted), and a single **processor** de-obfuscates,
/// decrypts, and writes to TUN (order preserved).
#[allow(clippy::too_many_arguments)]
async fn net_to_tun(
    tun: Arc<TunDevice>,
    socket: Arc<UdpSocket>,
    cipher: Cipher,
    master_key: Arc<[u8]>,
    obfuscator: Option<Arc<Obfuscator>>,
    installer_slot: InstallerSlot,
    assign_tx: Option<mpsc::Sender<Assign>>,
    peers: Arc<PeerTable>,
    magic_suffix: String,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);

    // Reader: pull datagrams off the socket and hand each to the processor.
    let reader = tokio::spawn(async move {
        // UDP buffer sized for the encrypted form of the largest IP packet, plus
        // headroom for the obfs prefix when obfuscation is enabled.
        let mut buf = vec![0u8; max_datagram_size(cipher) + obfs::MAX_HEADER];
        // Consecutive transient receive failures (see `is_transient_udp_error`):
        // warn once when a burst starts, then stay quiet until it clears.
        let mut recv_failures: u64 = 0;
        loop {
            let n = match socket.recv(&mut buf).await {
                Ok(n) => n,
                // A transient path error (typically an ICMP unreachable queued
                // on the connected socket) is retried, with a breather so a
                // persistent condition doesn't spin this loop.
                Err(e) if is_transient_udp_error(&e) => {
                    recv_failures += 1;
                    if recv_failures == 1 {
                        warn!("transient receive error, retrying until the path clears: {e}");
                    } else {
                        debug!("transient receive error #{recv_failures}: {e}");
                    }
                    tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                    continue;
                }
                Err(e) => return Err(e).context("failed to receive datagram from server"),
            };
            if recv_failures > 0 {
                info!("receive path recovered after {recv_failures} transient error(s)");
                recv_failures = 0;
            }
            if tx.send(buf[..n].to_vec()).await.is_err() {
                return Ok(());
            }
        }
    });

    // Processor: de-obfuscate, decrypt, and write to TUN.
    let processor = tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            let n = pkt.len();

            // De-obfuscate (if enabled); a packet that doesn't match the configured
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
                        debug!("dropping {n}-byte non-obfs datagram");
                        continue;
                    }
                },
                None => &pkt,
            };

            // Bad/forged/corrupt datagrams (too short or failing AEAD auth) are
            // dropped, not fatal — this is normal on an open UDP port.
            let plaintext = match decrypt_packet(cipher, &master_key, datagram) {
                Ok(p) => p,
                Err(e) => {
                    debug!("dropping undecryptable {n}-byte datagram: {e}");
                    continue;
                }
            };

            // Control payloads never reach the TUN. Assign is forwarded to
            // `run` so this processor does not reconfigure the device.
            if mesh::is_control(&plaintext) {
                match mesh::parse_control(&plaintext) {
                    Some(mesh::Control::RoutePush(push)) => {
                        match installer_slot.lock().unwrap().clone() {
                            Some(installer) => installer.apply(&push.routes),
                            None => debug!("ignoring route push: no installer yet"),
                        }
                    }
                    Some(mesh::Control::Assign(reply)) => match &assign_tx {
                        Some(tx) => {
                            if tx.try_send(reply).is_err() {
                                debug!("dropping Assign: run is not accepting");
                            }
                        }
                        None => debug!("dropping Assign: not in auto mode"),
                    },
                    Some(mesh::Control::PeerPush(push)) => {
                        apply_push(&peers, &push, &magic_suffix);
                        debug!("magic-dns: applied {} peer name(s)", push.peers.len());
                    }
                    other => debug!(
                        "dropping {}-byte control payload ({other:?})",
                        plaintext.len()
                    ),
                }
                continue;
            }

            // Drop keepalive-sized payloads: anything too small to be an IP packet
            // (an IPv4 header alone is 20 bytes) must not be written to the TUN.
            if plaintext.len() < 20 {
                debug!("dropping {}-byte sub-IP-header payload", plaintext.len());
                continue;
            }

            // A write failure to our own TUN device is fatal.
            tun.send(&plaintext)
                .await
                .context("failed to write packet to TUN device")?;
            debug!(
                "net->tun: {n} bytes datagram -> {} bytes plaintext",
                plaintext.len()
            );
        }
        Ok(())
    });

    let mut reader = reader;
    let mut processor = processor;
    tokio::select! {
        r = &mut reader => { processor.abort(); r.context("net->tun reader task panicked")? }
        r = &mut processor => { reader.abort(); r.context("net->tun processor task panicked")? }
    }
}

/// Periodically send a tiny encrypted keepalive (or mesh route advert) to the
/// server.
///
/// This refreshes NAT mappings and lets the server learn our source address
/// before we send real traffic; when mesh routing is active, the payload is a
/// route advert, which the server treats as a keepalive too (and answers with
/// a route push for accept-routes clients). Encryption failures and transient
/// send errors are logged and skipped (the next tick retries); any other send
/// failure is fatal (the socket itself is broken).
async fn keepalive_loop(
    socket: Arc<UdpSocket>,
    cipher: Cipher,
    master_key: Arc<[u8]>,
    obfuscator: Option<Arc<Obfuscator>>,
    interval: Duration,
    payloads: Vec<Vec<u8>>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    // Don't fire a burst if we ever fall behind schedule.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        for payload in &payloads {
            let datagram = match encrypt_packet(cipher, &master_key, payload) {
                Ok(d) => d,
                Err(e) => {
                    warn!("failed to encrypt keepalive, skipping: {e}");
                    continue;
                }
            };
            // Keepalives ride the same obfs framing so the whole flow is uniform.
            let wire = match obfuscator {
                Some(ref o) => o.wrap(&datagram),
                None => datagram,
            };
            if let Err(e) = socket.send(&wire).await {
                if is_transient_udp_error(&e) {
                    warn!("transient keepalive send error, retrying next tick: {e}");
                    continue;
                }
                return Err(e).context("failed to send keepalive to server");
            }
            debug!("sent {}-byte keepalive", wire.len());
        }
    }
}

async fn send_control(
    socket: &UdpSocket,
    cipher: Cipher,
    master_key: &[u8],
    obfuscator: Option<&Obfuscator>,
    payload: &[u8],
) -> Result<()> {
    let datagram = match encrypt_packet(cipher, master_key, payload) {
        Ok(d) => d,
        Err(e) => {
            warn!("failed to encrypt control payload, skipping: {e}");
            return Ok(());
        }
    };
    let wire = match obfuscator {
        Some(o) => o.wrap(&datagram),
        None => datagram,
    };
    if let Err(e) = socket.send(&wire).await {
        if is_transient_udp_error(&e) {
            warn!("transient control send error: {e}");
            return Ok(());
        }
        return Err(e).context("failed to send control payload to server");
    }
    debug!("sent {}-byte control payload", payload.len());
    Ok(())
}

async fn tick_opt(interval: &mut Option<tokio::time::Interval>) {
    match interval.as_mut() {
        Some(i) => {
            i.tick().await;
        }
        None => std::future::pending().await,
    }
}

async fn join_opt(
    handle: &mut Option<tokio::task::JoinHandle<Result<()>>>,
) -> Result<Result<()>, tokio::task::JoinError> {
    match handle.as_mut() {
        Some(h) => h.await,
        None => std::future::pending().await,
    }
}

async fn policy_task_result(handle: &mut Option<shadowvpn::policy::PolicyHandle>) -> Result<()> {
    match handle.as_mut() {
        Some(h) => match (&mut h.task).await {
            Ok(inner) => inner.context("DNS proxy loop failed"),
            Err(join) => Err(anyhow::Error::new(join).context("DNS proxy task panicked")),
        },
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_policy_and_installer(
    cfg: &ClientConfig,
    iface_name: &str,
    server_ip: std::net::IpAddr,
    direct_src: std::net::IpAddr,
    policy_handle: &mut Option<shadowvpn::policy::PolicyHandle>,
    installer_slot: &InstallerSlot,
    route_guard: &mut Option<mesh::InstallerGuard>,
    peers: Arc<PeerTable>,
) -> Result<()> {
    let want_dns = cfg.policy.mode.is_enabled() || cfg.magic_dns;
    if want_dns && policy_handle.is_none() {
        if cfg.policy.mode.is_enabled() {
            info!(
                "policy routing mode = {}; only matched destinations are tunneled",
                cfg.policy.mode.name()
            );
        }
        *policy_handle = Some(
            shadowvpn::policy::spawn(
                &cfg.policy,
                iface_name,
                cfg.tun.ip,
                server_ip,
                direct_src,
                peers,
            )
            .await
            .context("failed to start DNS proxy")?,
        );
    }
    if cfg.accept_routes && installer_slot.lock().unwrap().is_none() {
        let installer = Arc::new(
            RouteInstaller::new(iface_name, cfg.tun.ip, server_ip)
                .context("setting up the mesh route installer")?,
        );
        *installer_slot.lock().unwrap() = Some(Arc::clone(&installer));
        *route_guard = Some(mesh::InstallerGuard::new(installer));
    }
    Ok(())
}

/// Abort the DNS-proxy task and wait for it to exit so `dns_listen` is released
/// before a replacement `spawn` (dropping the JoinHandle would detach it).
async fn shutdown_policy(handle: &mut Option<shadowvpn::policy::PolicyHandle>) {
    if let Some(mut old) = handle.take() {
        old.task.abort();
        let _ = (&mut old.task).await;
        drop(old);
    }
}

fn reply_ip6(
    want_ip6: bool,
    reply: &Assign,
    static_ip6: Option<Ipv6Network>,
) -> Option<Ipv6Network> {
    if want_ip6 {
        let ip = reply.tun_ip6?;
        (reply.plen6 != 0)
            .then(|| Ipv6Network::new(ip, reply.plen6).ok())
            .flatten()
    } else {
        static_ip6
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_assign_reply(
    reply: Assign,
    cfg: &mut ClientConfig,
    tun: &TunDevice,
    iface_name: &str,
    server_ip: std::net::IpAddr,
    direct_src: std::net::IpAddr,
    state_path: &Path,
    node_id: [u8; 16],
    assigned_ok: &AtomicBool,
    got_ok: &mut bool,
    assign_retry: &mut Option<tokio::time::Interval>,
    keep_tick: &mut Option<tokio::time::Interval>,
    policy_handle: &mut Option<shadowvpn::policy::PolicyHandle>,
    installer_slot: &InstallerSlot,
    route_guard: &mut Option<mesh::InstallerGuard>,
    subnet_guard: &mut Option<SubnetRouteGuard>,
    hinted_routing: &mut bool,
    socket: &UdpSocket,
    cipher: Cipher,
    master_key: &[u8],
    obfuscator: Option<&Obfuscator>,
    peers: Arc<PeerTable>,
) -> Result<()> {
    match reply.status {
        AssignStatus::Ok => {}
        AssignStatus::Exhausted if *got_ok => {
            warn!("server address pool exhausted; keeping current assignment");
            return Ok(());
        }
        AssignStatus::NatMode if *got_ok => {
            warn!("server entered NAT mode; keeping current assignment");
            return Ok(());
        }
        AssignStatus::Exhausted => bail!("server address pool exhausted"),
        AssignStatus::NatMode => {
            bail!("server is in NAT mode; assignment is disabled")
        }
    }

    let first_ok = !*got_ok;
    let static_ip6 = if cfg.want_ip6 { None } else { cfg.tun.ip6 };
    let ip6 = reply_ip6(cfg.want_ip6, &reply, static_ip6);
    let old_ip = cfg.tun.ip;
    let old_ip6 = cfg.tun.ip6;
    let ipv4_changed = !old_ip.is_unspecified() && old_ip != reply.tun_ip;
    // Periodic refresh: do not re-program the TUN / persist / log every 15s.
    if !first_ok
        && reply.tun_ip == cfg.tun.ip
        && reply.netmask == cfg.tun.netmask
        && reply.peer_ip == cfg.tun.peer_ip
        && ip6 == cfg.tun.ip6
    {
        return Ok(());
    }

    tun.apply_assignment(reply.tun_ip, reply.netmask, reply.peer_ip, ip6)
        .context("failed to apply tunnel assignment")?;

    cfg.tun.ip = reply.tun_ip;
    cfg.tun.netmask = reply.netmask;
    cfg.tun.peer_ip = reply.peer_ip;
    if cfg.want_ip6 {
        cfg.tun.ip6 = ip6;
    }

    match subnet_guard {
        Some(g) => g
            .apply(reply.tun_ip, reply.netmask, ip6)
            .context("refreshing TUN subnet route")?,
        None => {
            let mut g =
                SubnetRouteGuard::new(iface_name).context("setting up the TUN subnet route")?;
            g.apply(reply.tun_ip, reply.netmask, ip6)
                .context("installing TUN subnet route")?;
            *subnet_guard = Some(g);
        }
    }

    if ipv4_changed {
        warn!(
            "TUN IPv4 changed from {old_ip} to {}; in-flight sockets bound to the old address will break",
            reply.tun_ip
        );
        // JoinHandle drop would detach the proxy and leave 127.0.0.1:53 bound.
        shutdown_policy(policy_handle).await;
        if cfg.accept_routes {
            *installer_slot.lock().unwrap() = None;
            *route_guard = None;
        }
    }

    start_policy_and_installer(
        cfg,
        iface_name,
        server_ip,
        direct_src,
        policy_handle,
        installer_slot,
        route_guard,
        peers,
    )
    .await?;

    persist_assignment(state_path, &cfg.server, node_id, &reply, ip6);

    if first_ok {
        assigned_ok.store(true, Ordering::Release);
        *got_ok = true;
        *assign_retry = None;
        let mut ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + cfg.keepalive, cfg.keepalive);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        *keep_tick = Some(ticker);
    }

    if !*hinted_routing && !cfg.policy.mode.is_enabled() {
        print_routing_hint(&cfg.tun, &cfg.server);
        *hinted_routing = true;
    }

    let v6 = ip6
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".to_string());
    if first_ok && !old_ip.is_unspecified() && !ipv4_changed && ip6 == old_ip6 {
        info!("assignment confirmed (cached): {} / {v6}", reply.tun_ip);
    } else {
        info!(
            "TUN assigned: {} / {v6} (peer {} ttl {}s)",
            reply.tun_ip, reply.peer_ip, reply.ttl_secs
        );
    }

    // Immediate advert on first Ok (and if the IPv4 moved); later ticks send it.
    if cfg.mesh_active() && (first_ok || ipv4_changed) {
        send_control(
            socket,
            cipher,
            master_key,
            obfuscator,
            &cfg.route_advert().encode(),
        )
        .await?;
    }
    if cfg.magic_dns && (first_ok || ipv4_changed) {
        send_control(
            socket,
            cipher,
            master_key,
            obfuscator,
            &cfg.name_advert().encode(),
        )
        .await?;
    }
    Ok(())
}

/// Persisted client identity. `last_assign` is absent until the first Ok.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientStateFile {
    node_id: String,
    server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_assign: Option<LastAssign>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LastAssign {
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    peer_ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tun_ip6: Option<Ipv6Network>,
    assigned_at_unix: u64,
}

fn generate_node_id() -> [u8; 16] {
    use rand::rngs::SysRng;
    use rand::TryRng;
    let mut id = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut id)
        .expect("OS entropy for node_id");
    // UUID v4 (RFC 4122): version 4, variant 10.
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

fn fmt_node(id: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
        id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]
    )
}

fn parse_node_id(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_or_create_state(path: &Path, server: &str) -> ([u8; 16], Option<LastAssign>) {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<ClientStateFile>(&bytes) {
            Ok(st) => {
                if let Some(id) = parse_node_id(&st.node_id) {
                    return (id, st.last_assign);
                }
                warn!(
                    "corrupt node_id in {}; generating a new identity",
                    path.display()
                );
            }
            Err(e) => warn!(
                "corrupt client state {}: {e}; generating a new identity",
                path.display()
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            "failed to read client state {}: {e}; generating a new identity",
            path.display()
        ),
    }
    let id = generate_node_id();
    persist_state(
        path,
        &ClientStateFile {
            node_id: fmt_node(&id),
            server: server.to_string(),
            last_assign: None,
        },
    );
    (id, None)
}

fn persist_assignment(
    path: &Path,
    server: &str,
    node_id: [u8; 16],
    reply: &Assign,
    ip6: Option<Ipv6Network>,
) {
    persist_state(
        path,
        &ClientStateFile {
            node_id: fmt_node(&node_id),
            server: server.to_string(),
            last_assign: Some(LastAssign {
                tun_ip: reply.tun_ip,
                tun_netmask: reply.netmask,
                peer_ip: reply.peer_ip,
                tun_ip6: ip6,
                assigned_at_unix: unix_now(),
            }),
        },
    );
}

fn persist_state(path: &Path, state: &ClientStateFile) {
    match serde_json::to_vec_pretty(state) {
        Ok(bytes) => {
            if let Err(e) = write_private(path, &bytes) {
                warn!("failed to persist client state {}: {e}", path.display());
            }
        }
        Err(e) => warn!("failed to serialize client state: {e}"),
    }
}

/// Print the routing commands the user should run to send traffic through the
/// tunnel. We never modify the routing table automatically.
///
/// `server` is the remote `host:port`; only its host part matters for the
/// "host route to the server" hint, and only when it is a literal IP.
fn print_routing_hint(tun: &TunConfig, server: &str) {
    let peer = tun.peer_ip;
    let local = tun.ip;

    info!("-----------------------------------------------------------------");
    info!("Tunnel is up (local {local}, peer {peer}). It does NOT change your");
    info!("routing table. To send traffic through the tunnel, add routes by hand.");
    info!("");

    // A host route for the server itself must go via the *physical* gateway, or
    // the encrypted UDP would loop back into the tunnel. We can only fully spell
    // this out when the server host is a literal IP.
    let server_host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);
    let server_ip = server_host.parse::<Ipv4Addr>().ok();

    #[cfg(target_os = "linux")]
    {
        info!("Linux:");
        if let Some(ip) = server_ip {
            info!("  # keep the server reachable over your real link (replace GW/DEV):");
            info!("  sudo ip route add {ip}/32 via <YOUR_DEFAULT_GW> dev <YOUR_WAN_DEV>");
        } else {
            info!("  # first add a host route for the server's resolved IP via your real");
            info!("  # gateway, so encrypted UDP does not re-enter the tunnel.");
        }
        info!("  # then route everything (or a subnet) through the tunnel peer:");
        info!("  sudo ip route add 0.0.0.0/1 via {peer}");
        info!("  sudo ip route add 128.0.0.0/1 via {peer}");
        info!("  # (the two /1 routes override the default without deleting it)");
    }

    #[cfg(target_os = "macos")]
    {
        info!("macOS:");
        if let Some(ip) = server_ip {
            info!("  # keep the server reachable over your real link (replace GW):");
            info!("  sudo route -n add -host {ip} <YOUR_DEFAULT_GW>");
        } else {
            info!("  # first add a host route for the server's resolved IP via your real");
            info!("  # gateway, so encrypted UDP does not re-enter the tunnel.");
        }
        info!("  # then route everything through the tunnel peer:");
        info!("  sudo route -n add -net 0.0.0.0/1 {peer}");
        info!("  sudo route -n add -net 128.0.0.0/1 {peer}");
    }

    #[cfg(windows)]
    {
        info!("Windows (run in an elevated prompt):");
        if let Some(ip) = server_ip {
            info!("  :: keep the server reachable over your real link (replace GW):");
            info!("  route add {ip} mask 255.255.255.255 <YOUR_DEFAULT_GW>");
        } else {
            info!("  :: first add a host route for the server's resolved IP via your real");
            info!("  :: gateway, so encrypted UDP does not re-enter the tunnel.");
        }
        info!("  :: then route everything through the tunnel peer:");
        info!("  route add 0.0.0.0 mask 128.0.0.0 {peer}");
        info!("  route add 128.0.0.0 mask 128.0.0.0 {peer}");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = server_ip;
        info!("Add a host route to the server via your real gateway, then route the");
        info!("desired destinations via the tunnel peer {peer}.");
    }

    info!("");
    info!("To stop using the tunnel, delete the routes you added above.");
    info!("-----------------------------------------------------------------");

    if server_ip.is_none() {
        warn!(
            "server '{server}' is a hostname, not a literal IP: resolve it and add a \
             host route for that IP via your real gateway before routing all traffic."
        );
    }
}
