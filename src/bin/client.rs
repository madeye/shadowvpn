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
//! The client also runs a lightweight keepalive: it periodically encrypts and
//! sends a tiny dummy packet so that (a) a stateful NAT/firewall on the path
//! keeps the UDP mapping open, and (b) the server learns the client's current
//! source address even before the client sends any real traffic. We send a
//! 1-byte plaintext (`0x00`); a real IP packet is always larger than this, and
//! the server is expected to drop sub-IP-header datagrams, so the keepalive is
//! harmless if it ever reaches the TUN-write path. (This is a ShadowVPN
//! convention, not part of the shadowsocks wire spec.)
//!
//! # Routing (NOT done automatically)
//!
//! The client deliberately does **not** touch the system routing table or the
//! default route — doing so silently is dangerous and platform-specific. After
//! the interface comes up, the client logs the suggested commands to route
//! traffic through the tunnel. See [`print_routing_hint`].

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use shadowvpn::config::{ClientArgs, ClientConfig, TunConfig};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet, Cipher};
use shadowvpn::obfs::{self, Obfuscator};
use shadowvpn::protocol::{max_datagram_size, MAX_IP_PACKET};
use shadowvpn::tun_device::TunDevice;

/// How often to send a keepalive datagram to the server.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Depth of the hand-off channel between each relay loop's I/O reader and its
/// processor (see the server for the rationale). Bounded for backpressure.
const CHANNEL_DEPTH: usize = 1024;

/// Plaintext payload of a keepalive datagram: a single zero byte. Smaller than
/// any real IP packet header, so the server can distinguish/drop it cheaply.
const KEEPALIVE_PAYLOAD: &[u8] = &[0u8];

#[tokio::main]
async fn main() -> Result<()> {
    // Default to `info` logging; override with `RUST_LOG`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = ClientArgs::parse()
        .resolve()
        .context("failed to resolve client configuration")?;

    run(cfg).await
}

/// Bring up the TUN device + UDP socket and drive the two relay loops until one
/// of them fails (or the process is signalled).
async fn run(cfg: ClientConfig) -> Result<()> {
    // The master key length is guaranteed to match the cipher by `resolve()`.
    let cipher = cfg.cipher;
    let master_key: Arc<[u8]> = Arc::from(cfg.master_key.into_boxed_slice());

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
    socket
        .connect(&cfg.server)
        .await
        .with_context(|| format!("failed to connect UDP socket to server {}", cfg.server))?;
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

    // --- TUN device ---------------------------------------------------------
    let tun = TunDevice::create(&cfg.tun).with_context(|| {
        format!(
            "failed to create TUN device (need root/elevated privileges); \
             requested ip={} peer={} mtu={}",
            cfg.tun.ip, cfg.tun.peer_ip, cfg.tun.mtu
        )
    })?;
    let tun = Arc::new(tun);

    let iface_name = tun.name().unwrap_or_else(|_| {
        cfg.tun
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string())
    });
    info!(
        "TUN up: iface={iface_name} ip={} peer={} netmask={} mtu={}",
        cfg.tun.ip, cfg.tun.peer_ip, cfg.tun.netmask, cfg.tun.mtu
    );

    // --- Policy routing (optional) -----------------------------------------
    // In `gfwlist`/`chinadns` mode the client runs a split-DNS proxy and
    // programs per-destination routes into the tun (user-mode, via the OS
    // routing socket) so that only selected destinations go through the tunnel.
    // In `full` mode (the default) we touch nothing and just print the manual
    // routing hint, preserving the historical behavior.
    let mut policy_handle = if cfg.policy.mode.is_enabled() {
        info!(
            "policy routing mode = {}; only matched destinations are tunneled",
            cfg.policy.mode.name()
        );
        Some(
            shadowvpn::policy::spawn(&cfg.policy, &iface_name, cfg.tun.ip, direct_src)
                .await
                .context("failed to start policy routing")?,
        )
    } else {
        // Tell the user how to actually route traffic through the tunnel; in
        // full mode we never mutate the routing table ourselves.
        print_routing_hint(&cfg.tun, &cfg.server);
        None
    };

    // --- Relay + keepalive tasks -------------------------------------------
    // Loop A: TUN -> net (read IP packet, encrypt, send UDP).
    let up = tokio::spawn(tun_to_net(
        Arc::clone(&tun),
        Arc::clone(&socket),
        cipher,
        Arc::clone(&master_key),
        obfuscator.clone(),
    ));

    // Loop B: net -> TUN (recv UDP, decrypt, write IP packet).
    let down = tokio::spawn(net_to_tun(
        Arc::clone(&tun),
        Arc::clone(&socket),
        cipher,
        Arc::clone(&master_key),
        obfuscator.clone(),
    ));

    // Keepalive: periodic tiny encrypted datagram so the server learns/refreshes
    // our address and NAT mappings stay open.
    let keepalive = tokio::spawn(keepalive_loop(
        Arc::clone(&socket),
        cipher,
        Arc::clone(&master_key),
        obfuscator.clone(),
    ));

    // The DNS-proxy task, when policy routing is active. When it is not (or on
    // non-Linux), this future stays pending forever so it never wins the select.
    // Keeping `policy_handle` owned here also keeps the teardown guard alive for
    // the lifetime of the client.
    let policy_fut = async {
        if let Some(handle) = policy_handle.as_mut() {
            return match (&mut handle.task).await {
                Ok(inner) => inner.context("DNS proxy loop failed"),
                Err(join) => Err(anyhow::Error::new(join).context("DNS proxy task panicked")),
            };
        }
        std::future::pending::<Result<()>>().await
    };
    tokio::pin!(policy_fut);

    // Whichever arm fires first ends the client (a returning relay loop means a
    // fatal IO error; the keepalive loop only returns on a fatal send error; the
    // policy loop only returns on a fatal DNS-proxy error; a signal is a clean
    // shutdown request). Exiting gracefully drops the policy handle, whose guards
    // restore the system DNS, remove the tunnel routes, and save the cache.
    tokio::select! {
        r = up => propagate("tun->net", r),
        r = down => propagate("net->tun", r),
        r = keepalive => propagate("keepalive", r),
        r = &mut policy_fut => r,
        _ = shutdown_signal() => { info!("received shutdown signal; shutting down"); Ok(()) }
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
            if tx.send(buf[..n].to_vec()).await.is_err() {
                return Ok(());
            }
        }
    });

    // Processor: encrypt, obfuscate, and send to the server.
    let processor = tokio::spawn(async move {
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

            // A failed send to a connected socket is treated as fatal.
            socket
                .send(&wire)
                .await
                .context("failed to send datagram to server")?;
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
async fn net_to_tun(
    tun: Arc<TunDevice>,
    socket: Arc<UdpSocket>,
    cipher: Cipher,
    master_key: Arc<[u8]>,
    obfuscator: Option<Arc<Obfuscator>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);

    // Reader: pull datagrams off the socket and hand each to the processor.
    let reader = tokio::spawn(async move {
        // UDP buffer sized for the encrypted form of the largest IP packet, plus
        // headroom for the obfs prefix when obfuscation is enabled.
        let mut buf = vec![0u8; max_datagram_size(cipher) + obfs::MAX_HEADER];
        loop {
            let n = socket
                .recv(&mut buf)
                .await
                .context("failed to receive datagram from server")?;
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

/// Periodically send a tiny encrypted keepalive datagram to the server.
///
/// This refreshes NAT mappings and lets the server learn our source address
/// before we send real traffic. Encryption failures are logged and skipped; a
/// send failure is fatal (the path to the server is gone).
async fn keepalive_loop(
    socket: Arc<UdpSocket>,
    cipher: Cipher,
    master_key: Arc<[u8]>,
    obfuscator: Option<Arc<Obfuscator>>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(KEEPALIVE_INTERVAL);
    // Don't fire a burst if we ever fall behind schedule.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        let datagram = match encrypt_packet(cipher, &master_key, KEEPALIVE_PAYLOAD) {
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
            return Err(e).context("failed to send keepalive to server");
        }
        debug!("sent {}-byte keepalive", wire.len());
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
