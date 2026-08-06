//! Mesh subnet routing: ShadowVPN's Tailscale-like route sharing.
//!
//! This module gives the fixed hub-and-spoke tunnel the three moving parts of
//! Tailscale's subnet-router workflow, without any external control plane:
//!
//! * **Advertise** — a client configured with `advertise_routes` announces the
//!   subnets it can reach (IPv4 and/or IPv6 CIDRs) to the server, piggybacked
//!   on its keepalive tick ([`RouteAdvert`]).
//! * **Approve** — the server accepts an advertised route only if it is covered
//!   by its `approve_routes` allowlist (or `auto_approve_routes` is on). This
//!   is the stand-in for Tailscale's admin-console route approval: unapproved
//!   routes are held and logged as *awaiting approval*, and never routed or
//!   pushed to peers ([`SubnetTable`]).
//! * **Accept** — a client configured with `accept_routes` receives the
//!   approved route set from the server ([`RoutePush`]) and installs matching
//!   kernel routes onto its TUN interface, removing them when they are
//!   withdrawn and on exit. Split horizon applies: a client is never sent the
//!   routes it advertised itself.
//!
//! The server relays packets between clients (and to advertised subnets)
//! directly UDP→UDP by longest-prefix match, so spoke↔spoke traffic never
//! touches the server's TUN device or kernel forwarding path.
//!
//! # Wire format (inside the AEAD envelope)
//!
//! Control messages share the plaintext channel with raw IP packets. Every
//! control message starts with a `0x00` byte: an IP packet's first high nibble
//! is its version (4 or 6), so a leading zero byte can never be a valid IP
//! packet and old peers simply drop such payloads — the extension is
//! wire-compatible in both directions.
//!
//! ```text
//! keepalive   : 00                      (legacy, 1 byte)
//! keepalive   : 00 ip4[4]               (legacy, 5 bytes)
//! route advert: 00 01 flags ip4[4] ip6[16] count { family plen addr[4|16] }*
//! route push  : 00 02 00    count { family plen addr[4|16] }*
//! ```
//!
//! `flags` bit 0 is *accept routes* (the client asks for pushes). `family` is
//! the literal byte `4` or `6`; `addr` is the network address (host bits are
//! masked off on both ends). The 1- and 5-byte keepalives are distinguished
//! from typed messages by length alone, preserving the historical format.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use log::{debug, info, warn};

/// First byte of every control message. An IP packet's version nibble is 4 or
/// 6, so a payload starting with `0x00` is unambiguously not an IP packet.
pub const CONTROL_MARKER: u8 = 0x00;

/// Type byte of a client→server [`RouteAdvert`].
const TYPE_ROUTE_ADVERT: u8 = 0x01;

/// Type byte of a server→client [`RoutePush`].
const TYPE_ROUTE_PUSH: u8 = 0x02;

/// `flags` bit: the advertising client also wants approved routes pushed back.
const FLAG_ACCEPT_ROUTES: u8 = 0x01;

/// Maximum number of routes carried in one advert or push. Bounds the message
/// well under the tunnel MTU (64 IPv6 entries ≈ 1.2 KB) so control messages
/// never fragment.
pub const MAX_ROUTES: usize = 64;

/// Fixed advert header: marker + type + flags + ip4 + ip6 + count.
const ADVERT_HEADER_LEN: usize = 3 + 4 + 16 + 1;

/// Fixed push header: marker + type + reserved + count.
const PUSH_HEADER_LEN: usize = 4;

/// True if a decrypted payload is a control message rather than an IP packet.
pub fn is_control(payload: &[u8]) -> bool {
    payload.first() == Some(&CONTROL_MARKER)
}

/// A decoded control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// A legacy keepalive, optionally announcing the client's tunnel IPv4.
    Keepalive(Option<Ipv4Addr>),
    /// A client→server route advertisement (also acts as a keepalive).
    RouteAdvert(RouteAdvert),
    /// A server→client push of the approved route set.
    RoutePush(RoutePush),
}

/// Client→server: "these subnets are reachable through me".
///
/// Also carries the client's tunnel addresses so the server can learn/refresh
/// its UDP mapping (exactly like the keepalive) and register the IPv6 tunnel
/// address for return routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvert {
    /// The client's tunnel IPv4 address.
    pub tunnel_ip: Ipv4Addr,
    /// The client's tunnel IPv6 address, when it has one.
    pub tunnel_ip6: Option<Ipv6Addr>,
    /// Whether the client wants the server to push approved routes back.
    pub accept_routes: bool,
    /// Subnets reachable through this client (may be empty for a pure
    /// accept-routes client).
    pub routes: Vec<IpNetwork>,
}

/// Server→client: the approved routes of *other* peers (split horizon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePush {
    /// Approved subnets reachable through the tunnel.
    pub routes: Vec<IpNetwork>,
}

/// Canonicalize a network: mask the host bits off so `10.0.0.7/24` and
/// `10.0.0.0/24` compare (and encode) identically.
pub fn canonical(net: IpNetwork) -> IpNetwork {
    IpNetwork::new(net.network(), net.prefix()).expect("network address + same prefix is valid")
}

/// Append one `{family, prefix_len, addr}` route entry.
fn push_route(buf: &mut Vec<u8>, net: &IpNetwork) {
    match canonical(*net) {
        IpNetwork::V4(n) => {
            buf.push(4);
            buf.push(n.prefix());
            buf.extend_from_slice(&n.ip().octets());
        }
        IpNetwork::V6(n) => {
            buf.push(6);
            buf.push(n.prefix());
            buf.extend_from_slice(&n.ip().octets());
        }
    }
}

/// Decode `count` route entries from `buf`, or `None` on any malformation
/// (unknown family, bad prefix, short buffer, trailing bytes).
fn parse_routes(mut buf: &[u8], count: usize) -> Option<Vec<IpNetwork>> {
    let mut routes = Vec::with_capacity(count);
    for _ in 0..count {
        let (&family, rest) = buf.split_first()?;
        let (&plen, rest) = rest.split_first()?;
        let (addr, rest): (IpAddr, &[u8]) = match family {
            4 => {
                let (bytes, rest) = rest.split_first_chunk::<4>()?;
                (Ipv4Addr::from(*bytes).into(), rest)
            }
            6 => {
                let (bytes, rest) = rest.split_first_chunk::<16>()?;
                (Ipv6Addr::from(*bytes).into(), rest)
            }
            _ => return None,
        };
        routes.push(canonical(IpNetwork::new(addr, plen).ok()?));
        buf = rest;
    }
    buf.is_empty().then_some(routes)
}

impl RouteAdvert {
    /// Serialize into a control payload. `routes` beyond [`MAX_ROUTES`] are
    /// truncated (config validation rejects such sets before we get here).
    pub fn encode(&self) -> Vec<u8> {
        let routes = &self.routes[..self.routes.len().min(MAX_ROUTES)];
        let mut buf = Vec::with_capacity(ADVERT_HEADER_LEN + routes.len() * 18);
        buf.push(CONTROL_MARKER);
        buf.push(TYPE_ROUTE_ADVERT);
        buf.push(if self.accept_routes {
            FLAG_ACCEPT_ROUTES
        } else {
            0
        });
        buf.extend_from_slice(&self.tunnel_ip.octets());
        buf.extend_from_slice(&self.tunnel_ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
        buf.push(routes.len() as u8);
        for net in routes {
            push_route(&mut buf, net);
        }
        buf
    }
}

impl RoutePush {
    /// Serialize into a control payload (same truncation rule as the advert).
    pub fn encode(&self) -> Vec<u8> {
        let routes = &self.routes[..self.routes.len().min(MAX_ROUTES)];
        let mut buf = Vec::with_capacity(PUSH_HEADER_LEN + routes.len() * 18);
        buf.push(CONTROL_MARKER);
        buf.push(TYPE_ROUTE_PUSH);
        buf.push(0); // reserved
        buf.push(routes.len() as u8);
        for net in routes {
            push_route(&mut buf, net);
        }
        buf
    }
}

/// Decode a control payload (a payload for which [`is_control`] is true).
///
/// Returns `None` for malformed or unknown messages, which callers drop —
/// exactly how peers predating this module treat every control payload.
pub fn parse_control(payload: &[u8]) -> Option<Control> {
    if !is_control(payload) {
        return None;
    }
    // The two historical keepalive shapes are length-dispatched: they predate
    // the type byte, and a 5-byte keepalive's second byte is an IP octet.
    match payload {
        [_] => return Some(Control::Keepalive(None)),
        [_, a, b, c, d] => return Some(Control::Keepalive(Some(Ipv4Addr::new(*a, *b, *c, *d)))),
        _ => {}
    }
    match *payload.get(1)? {
        TYPE_ROUTE_ADVERT => {
            let body = payload.get(2..)?;
            if body.len() < ADVERT_HEADER_LEN - 2 {
                return None;
            }
            let flags = body[0];
            let tunnel_ip = Ipv4Addr::new(body[1], body[2], body[3], body[4]);
            let ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&body[5..21]).expect("16 bytes"));
            let count = body[21] as usize;
            if count > MAX_ROUTES {
                return None;
            }
            let routes = parse_routes(&body[22..], count)?;
            Some(Control::RouteAdvert(RouteAdvert {
                tunnel_ip,
                tunnel_ip6: (!ip6.is_unspecified()).then_some(ip6),
                accept_routes: flags & FLAG_ACCEPT_ROUTES != 0,
                routes,
            }))
        }
        TYPE_ROUTE_PUSH => {
            let count = *payload.get(3)? as usize;
            if count > MAX_ROUTES {
                return None;
            }
            let routes = parse_routes(payload.get(4..)?, count)?;
            Some(Control::RoutePush(RoutePush { routes }))
        }
        _ => None,
    }
}

/// How the server decides whether an advertised route is approved.
///
/// The Tailscale-console equivalent: `auto` approves everything (like clicking
/// every checkbox), otherwise a route must be a subnet of (or equal to) an
/// allowlist entry.
#[derive(Debug, Clone, Default)]
pub struct RouteApproval {
    /// Approve every advertised route.
    pub auto: bool,
    /// CIDRs whose sub-networks (and exact matches) are approved.
    pub allowlist: Vec<IpNetwork>,
}

impl RouteApproval {
    /// Whether `net` is approved under this policy.
    pub fn approves(&self, net: &IpNetwork) -> bool {
        if self.auto {
            return true;
        }
        self.allowlist.iter().any(|allow| match (allow, net) {
            (IpNetwork::V4(a), IpNetwork::V4(n)) => a.is_supernet_of(*n),
            (IpNetwork::V6(a), IpNetwork::V6(n)) => a.is_supernet_of(*n),
            _ => false,
        })
    }
}

/// One advertised route held by the server.
#[derive(Debug, Clone)]
struct SubnetRoute {
    /// The advertised network (canonical form).
    net: IpNetwork,
    /// UDP endpoint of the advertising client.
    peer: SocketAddr,
    /// Whether the approval policy accepted it (unapproved routes are kept so
    /// operators can see what is "awaiting approval", but never routed/pushed).
    approved: bool,
    /// Last time the owning client re-advertised it.
    last_seen: Instant,
}

/// What changed when an advert was applied — for the server's log lines.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AdvertOutcome {
    /// Routes newly added and approved.
    pub approved: Vec<IpNetwork>,
    /// Routes newly added but not approved ("awaiting approval").
    pub awaiting: Vec<IpNetwork>,
    /// Routes that moved from another peer to this one.
    pub moved: Vec<IpNetwork>,
    /// Routes this peer previously advertised but no longer does.
    pub withdrawn: Vec<IpNetwork>,
}

impl AdvertOutcome {
    /// True when nothing changed (the steady state for periodic re-adverts).
    pub fn is_quiet(&self) -> bool {
        self.approved.is_empty()
            && self.awaiting.is_empty()
            && self.moved.is_empty()
            && self.withdrawn.is_empty()
    }
}

/// The server's table of advertised subnet routes.
///
/// Small-N by construction (≤ [`MAX_ROUTES`] per client), so lookups are a
/// linear longest-prefix scan.
#[derive(Debug, Default)]
pub struct SubnetTable {
    routes: Vec<SubnetRoute>,
}

impl SubnetTable {
    /// Apply one client's advert: refresh its routes, add new ones (running
    /// them through `approval`), drop the ones it stopped advertising, and
    /// report what changed.
    pub fn advertise(
        &mut self,
        peer: SocketAddr,
        advertised: &[IpNetwork],
        approval: &RouteApproval,
        now: Instant,
    ) -> AdvertOutcome {
        let mut outcome = AdvertOutcome::default();
        let advertised: Vec<IpNetwork> = advertised.iter().copied().map(canonical).collect();

        // Withdraw routes this peer no longer advertises.
        self.routes.retain(|r| {
            let keep = r.peer != peer || advertised.contains(&r.net);
            if !keep {
                outcome.withdrawn.push(r.net);
            }
            keep
        });

        for net in advertised {
            if let Some(existing) = self.routes.iter_mut().find(|r| r.net == net) {
                if existing.peer != peer {
                    // Last advertiser wins, like the address learning table.
                    existing.peer = peer;
                    outcome.moved.push(net);
                }
                // Re-run approval so an allowlist change on restart applies.
                existing.approved = approval.approves(&net);
                existing.last_seen = now;
            } else {
                let approved = approval.approves(&net);
                self.routes.push(SubnetRoute {
                    net,
                    peer,
                    approved,
                    last_seen: now,
                });
                if approved {
                    outcome.approved.push(net);
                } else {
                    outcome.awaiting.push(net);
                }
            }
        }
        outcome
    }

    /// Longest-prefix match `dst` against the approved routes, returning the
    /// advertising client's UDP endpoint.
    pub fn lookup(&self, dst: IpAddr) -> Option<SocketAddr> {
        self.routes
            .iter()
            .filter(|r| r.approved && r.net.contains(dst))
            .max_by_key(|r| r.net.prefix())
            .map(|r| r.peer)
    }

    /// The approved routes advertised by peers *other than* `peer` — the split
    /// horizon set pushed to an accept-routes client at that endpoint.
    pub fn routes_for(&self, peer: SocketAddr) -> Vec<IpNetwork> {
        self.routes
            .iter()
            .filter(|r| r.approved && r.peer != peer)
            .map(|r| r.net)
            .collect()
    }

    /// Drop routes whose owner has not re-advertised within `ttl`, returning
    /// the expired networks for logging. Accept-routes clients withdraw them
    /// on their next push.
    pub fn expire(&mut self, ttl: Duration, now: Instant) -> Vec<IpNetwork> {
        let mut expired = Vec::new();
        self.routes.retain(|r| {
            let live = now.duration_since(r.last_seen) <= ttl;
            if !live {
                expired.push(r.net);
            }
            live
        });
        expired
    }

    /// Number of held routes (approved + awaiting).
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// True when the table holds no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Installs server-pushed subnet routes onto the client's TUN interface and
/// removes them when they are withdrawn (and on drop).
///
/// The accept-routes half of the workflow: each pushed set is diffed against
/// what is already installed, so a steady-state push is a no-op. A route that
/// would capture the VPN server's own address is never installed — that would
/// feed the client's encrypted datagrams back into the tunnel.
pub struct RouteInstaller {
    /// Kernel interface index of the TUN device.
    ifindex: u32,
    /// The TUN's IPv4 address (preferred source for installed v4 routes).
    tun_ip: Ipv4Addr,
    /// The VPN server's address; routes covering it are rejected.
    server_ip: IpAddr,
    /// Currently installed networks.
    installed: Mutex<HashSet<IpNetwork>>,
}

impl RouteInstaller {
    /// Resolve the TUN interface and build an installer for it.
    pub fn new(tun_name: &str, tun_ip: Ipv4Addr, server_ip: IpAddr) -> std::io::Result<Self> {
        Ok(Self {
            ifindex: crate::policy::route::interface_index(tun_name)?,
            tun_ip,
            server_ip,
            installed: Mutex::new(HashSet::new()),
        })
    }

    /// Reconcile the installed routes with a pushed set: install the new ones,
    /// remove the withdrawn ones. Failures are logged and skipped (a failed
    /// install is retried on the next push because it never enters the
    /// installed set).
    pub fn apply(&self, pushed: &[IpNetwork]) {
        let mut installed = self.installed.lock().unwrap();
        let (add, remove) = diff_routes(&installed, pushed);
        for net in add {
            if net.contains(self.server_ip) {
                warn!(
                    "refusing pushed route {net}: it covers the VPN server {} \
                     (would loop the tunnel into itself)",
                    self.server_ip
                );
                continue;
            }
            match crate::policy::route::modify_route(
                self.ifindex,
                self.tun_ip,
                net.network(),
                net.prefix(),
                true,
            ) {
                Ok(()) => {
                    info!("installed subnet route {net} via the tunnel");
                    installed.insert(net);
                }
                Err(e) => warn!("failed to install subnet route {net}: {e}"),
            }
        }
        for net in remove {
            match crate::policy::route::modify_route(
                self.ifindex,
                self.tun_ip,
                net.network(),
                net.prefix(),
                false,
            ) {
                Ok(()) => info!("removed withdrawn subnet route {net}"),
                // warn, not debug: a failed removal leaves a stale kernel
                // route silently steering traffic into the tunnel.
                Err(e) => warn!("failed to remove subnet route {net}: {e}"),
            }
            installed.remove(&net);
        }
    }

    /// Remove every installed route. Best-effort, like [`apply`]'s removals.
    pub fn remove_all(&self) {
        let nets: Vec<IpNetwork> = {
            let mut installed = self.installed.lock().unwrap();
            installed.drain().collect()
        };
        for net in nets {
            if let Err(e) = crate::policy::route::modify_route(
                self.ifindex,
                self.tun_ip,
                net.network(),
                net.prefix(),
                false,
            ) {
                debug!("failed to remove subnet route {net} on shutdown: {e}");
            }
        }
    }
}

impl Drop for RouteInstaller {
    fn drop(&mut self) {
        self.remove_all();
    }
}

/// Drop guard that removes every installed mesh route when the client's run
/// loop exits, even while a (possibly detached) relay task still holds its own
/// reference to the same installer. Removal is idempotent, so the installer's
/// own `Drop` running later is harmless.
pub struct InstallerGuard(std::sync::Arc<RouteInstaller>);

impl InstallerGuard {
    /// Wrap an installer so its routes are cleaned up when this guard drops.
    pub fn new(installer: std::sync::Arc<RouteInstaller>) -> Self {
        Self(installer)
    }
}

impl Drop for InstallerGuard {
    fn drop(&mut self) {
        self.0.remove_all();
    }
}

/// Diff a pushed route set against the currently installed one: returns
/// `(to_add, to_remove)`. Both inputs are canonicalized before comparison.
pub fn diff_routes(
    installed: &HashSet<IpNetwork>,
    pushed: &[IpNetwork],
) -> (Vec<IpNetwork>, Vec<IpNetwork>) {
    let pushed: HashSet<IpNetwork> = pushed.iter().copied().map(canonical).collect();
    let add = pushed.difference(installed).copied().collect();
    let remove = installed.difference(&pushed).copied().collect();
    (add, remove)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNetwork {
        s.parse().expect("valid test network")
    }

    fn peer(port: u16) -> SocketAddr {
        format!("192.0.2.1:{port}").parse().unwrap()
    }

    #[test]
    fn control_marker_never_collides_with_ip() {
        // IPv4 and IPv6 packets have a non-zero version nibble in byte 0.
        assert!(!is_control(&[0x45, 0, 0, 20]));
        assert!(!is_control(&[0x60, 0, 0, 0]));
        assert!(is_control(&[0x00]));
        assert!(!is_control(&[]));
    }

    #[test]
    fn legacy_keepalives_still_parse() {
        assert_eq!(parse_control(&[0]), Some(Control::Keepalive(None)));
        assert_eq!(
            parse_control(&[0, 10, 7, 0, 2]),
            Some(Control::Keepalive(Some(Ipv4Addr::new(10, 7, 0, 2))))
        );
    }

    #[test]
    fn advert_roundtrips() {
        let advert = RouteAdvert {
            tunnel_ip: Ipv4Addr::new(10, 77, 0, 2),
            tunnel_ip6: Some("fd07:7::2".parse().unwrap()),
            accept_routes: true,
            routes: vec![net("192.168.200.0/24"), net("fd42:cafe::/64")],
        };
        let bytes = advert.encode();
        assert!(is_control(&bytes));
        assert_eq!(parse_control(&bytes), Some(Control::RouteAdvert(advert)));
    }

    #[test]
    fn advert_without_ip6_or_routes_roundtrips() {
        let advert = RouteAdvert {
            tunnel_ip: Ipv4Addr::new(10, 77, 0, 3),
            tunnel_ip6: None,
            accept_routes: true,
            routes: vec![],
        };
        assert_eq!(
            parse_control(&advert.encode()),
            Some(Control::RouteAdvert(advert))
        );
    }

    #[test]
    fn push_roundtrips_and_canonicalizes() {
        let push = RoutePush {
            // A host-bit-carrying network must encode as its network address.
            routes: vec![net("10.1.2.3/16"), net("fd42:cafe::1/64")],
        };
        let parsed = parse_control(&push.encode());
        assert_eq!(
            parsed,
            Some(Control::RoutePush(RoutePush {
                routes: vec![net("10.1.0.0/16"), net("fd42:cafe::/64")],
            }))
        );
    }

    #[test]
    fn malformed_messages_are_rejected() {
        // Unknown type.
        assert_eq!(parse_control(&[0, 0x7f, 0, 0]), None);
        // Truncated advert header.
        assert_eq!(parse_control(&[0, 1, 0]), None);
        // Advert claiming more routes than present.
        let mut advert = RouteAdvert {
            tunnel_ip: Ipv4Addr::UNSPECIFIED,
            tunnel_ip6: None,
            accept_routes: false,
            routes: vec![],
        }
        .encode();
        let count_at = advert.len() - 1;
        advert[count_at] = 3;
        assert_eq!(parse_control(&advert), None);
        // Push with trailing garbage. (An empty push plus one byte would be 5
        // bytes — the legacy keepalive shape, which length-dispatch claims —
        // so use a one-route push to exercise the trailing-bytes check.)
        let mut push = RoutePush {
            routes: vec![net("10.0.0.0/8")],
        }
        .encode();
        push.push(0xaa);
        assert_eq!(parse_control(&push), None);
        // Bad family / bad prefix.
        assert_eq!(parse_control(&[0, 2, 0, 1, 5, 24, 1, 2, 3, 4]), None);
        assert_eq!(parse_control(&[0, 2, 0, 1, 4, 33, 1, 2, 3, 4]), None);
    }

    #[test]
    fn approval_allowlist_is_supernet_scoped() {
        let policy = RouteApproval {
            auto: false,
            allowlist: vec![net("192.168.0.0/16"), net("fd42::/16")],
        };
        assert!(policy.approves(&net("192.168.200.0/24")));
        assert!(policy.approves(&net("192.168.0.0/16")));
        assert!(!policy.approves(&net("10.0.0.0/8")));
        assert!(policy.approves(&net("fd42:cafe::/64")));
        assert!(!policy.approves(&net("fd07::/64")));
        // Family mismatch never approves.
        assert!(!policy.approves(&net("172.16.0.0/12")));

        let auto = RouteApproval {
            auto: true,
            allowlist: vec![],
        };
        assert!(auto.approves(&net("10.0.0.0/8")));
    }

    #[test]
    fn table_advertise_lookup_and_split_horizon() {
        let mut table = SubnetTable::default();
        let approval = RouteApproval {
            auto: false,
            allowlist: vec![net("192.168.200.0/24"), net("fd42:cafe::/64")],
        };
        let now = Instant::now();

        let outcome = table.advertise(
            peer(1),
            &[
                net("192.168.200.0/24"),
                net("fd42:cafe::/64"),
                net("10.99.0.0/16"),
            ],
            &approval,
            now,
        );
        assert_eq!(outcome.approved.len(), 2);
        assert_eq!(outcome.awaiting, vec![net("10.99.0.0/16")]);

        // LPM only matches approved routes.
        assert_eq!(
            table.lookup("192.168.200.7".parse().unwrap()),
            Some(peer(1))
        );
        assert_eq!(table.lookup("fd42:cafe::1".parse().unwrap()), Some(peer(1)));
        assert_eq!(table.lookup("10.99.1.1".parse().unwrap()), None);

        // Split horizon: the advertiser gets nothing back; another peer gets
        // only the approved set.
        assert!(table.routes_for(peer(1)).is_empty());
        let for_other = table.routes_for(peer(2));
        assert_eq!(for_other.len(), 2);
        assert!(!for_other.contains(&net("10.99.0.0/16")));

        // A quiet re-advert reports no changes.
        assert!(table
            .advertise(
                peer(1),
                &[
                    net("192.168.200.0/24"),
                    net("fd42:cafe::/64"),
                    net("10.99.0.0/16")
                ],
                &approval,
                now,
            )
            .is_quiet());
    }

    #[test]
    fn table_longest_prefix_wins() {
        let mut table = SubnetTable::default();
        let auto = RouteApproval {
            auto: true,
            allowlist: vec![],
        };
        let now = Instant::now();
        table.advertise(peer(1), &[net("10.0.0.0/8")], &auto, now);
        table.advertise(peer(2), &[net("10.5.0.0/16")], &auto, now);
        assert_eq!(table.lookup("10.5.1.1".parse().unwrap()), Some(peer(2)));
        assert_eq!(table.lookup("10.9.1.1".parse().unwrap()), Some(peer(1)));
    }

    #[test]
    fn table_moves_withdraws_and_expires() {
        let mut table = SubnetTable::default();
        let auto = RouteApproval {
            auto: true,
            allowlist: vec![],
        };
        let now = Instant::now();

        table.advertise(peer(1), &[net("192.168.200.0/24")], &auto, now);
        // The same route from a new endpoint moves (client roamed / restarted).
        let outcome = table.advertise(peer(2), &[net("192.168.200.0/24")], &auto, now);
        assert_eq!(outcome.moved, vec![net("192.168.200.0/24")]);
        assert_eq!(
            table.lookup("192.168.200.1".parse().unwrap()),
            Some(peer(2))
        );

        // Advertising an empty set withdraws.
        let outcome = table.advertise(peer(2), &[], &auto, now);
        assert_eq!(outcome.withdrawn, vec![net("192.168.200.0/24")]);
        assert!(table.is_empty());

        // Expiry drops stale routes.
        table.advertise(peer(1), &[net("10.1.0.0/16")], &auto, now);
        let expired = table.expire(Duration::from_secs(60), now + Duration::from_secs(120));
        assert_eq!(expired, vec![net("10.1.0.0/16")]);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn diff_routes_computes_add_and_remove() {
        let installed: HashSet<IpNetwork> = [net("192.168.200.0/24"), net("10.1.0.0/16")]
            .into_iter()
            .collect();
        let (add, remove) = diff_routes(
            &installed,
            &[net("192.168.200.0/24"), net("fd42:cafe::/64")],
        );
        assert_eq!(add, vec![net("fd42:cafe::/64")]);
        assert_eq!(remove, vec![net("10.1.0.0/16")]);
    }
}
