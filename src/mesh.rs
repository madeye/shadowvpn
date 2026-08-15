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
//! assign req  : 00 03 flags node[16] hint4[4] hint6[16]
//! assign      : 00 04 status ip4[4] mask[4] peer[4] ip6[16] plen6 flags ttl[4]
//! name advert : 00 05 flags ip4[4] ip6[16] nlen name[nlen]
//! peer push   : 00 06 flags count { eflags ip4[4] ip6[16] nlen name[nlen] }*
//! ```
//!
//! `flags` bit 0 on a route advert is *accept routes* (the client asks for
//! pushes). On an assign request it is *want IPv6*. `family` is the literal
//! byte `4` or `6`; `addr` is the network address (host bits are masked off
//! on both ends). The 1- and 5-byte keepalives are distinguished from typed
//! messages by length alone, so typed messages must not be 1 or 5 bytes.
//! Assign request and reply are exact-length (39 and 37); any other length
//! or unknown type is dropped.

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

/// Type byte of a client→server [`AssignReq`].
const TYPE_ASSIGN_REQ: u8 = 0x03;

/// Type byte of a server→client [`Assign`].
const TYPE_ASSIGN: u8 = 0x04;

/// Type byte of a client→server [`NameAdvert`].
const TYPE_NAME_ADVERT: u8 = 0x05;

/// Type byte of a server→client [`PeerPush`].
const TYPE_PEER_PUSH: u8 = 0x06;

/// Exact length of an [`AssignReq`] payload. Not 1 or 5: those stay keepalives.
pub const ASSIGN_REQ_LEN: usize = 39;

/// Exact length of an [`Assign`] payload. Not 1 or 5: those stay keepalives.
pub const ASSIGN_LEN: usize = 37;

/// `flags` bit: the advertising client also wants approved routes pushed back.
const FLAG_ACCEPT_ROUTES: u8 = 0x01;

/// `AssignReq.flags` bit: the client wants an IPv6 assignment when the server
/// has a prefix.
pub const FLAG_WANT_IP6: u8 = 0x01;

/// Maximum number of routes carried in one advert or push. Bounds the message
/// well under the tunnel MTU (64 IPv6 entries ≈ 1.2 KB) so control messages
/// never fragment.
pub const MAX_ROUTES: usize = 64;

/// Maximum Magic DNS peers in one [`PeerPush`]. With a 32-byte name, 24
/// entries stay under the 1400-byte tunnel MTU.
pub const MAX_PEERS: usize = 24;

/// Maximum length of a Magic DNS hostname label (bytes).
pub const MAX_NAME_LEN: usize = 32;

/// `NameAdvert.flags` bit: the client wants the current peer map pushed back.
const FLAG_WANT_PEERS: u8 = 0x01;

/// `PeerPush` entry `eflags` bit: `ip6` is present (otherwise the 16 bytes
/// are `::` and ignored).
const EFLAG_HAS_IP6: u8 = 0x01;

/// Fixed name-advert header: marker + type + flags + ip4 + ip6 + nlen.
const NAME_ADVERT_HEADER_LEN: usize = 3 + 4 + 16 + 1;

/// Fixed peer-push header: marker + type + flags + count.
const PEER_PUSH_HEADER_LEN: usize = 4;

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
    /// A client→server request for a tunnel address.
    AssignReq(AssignReq),
    /// A server→client tunnel-address assignment (or a non-Ok status).
    Assign(Assign),
    /// A client→server hostname announcement (also acts as a keepalive).
    NameAdvert(NameAdvert),
    /// A server→client push of the current peer name → address map.
    PeerPush(PeerPush),
}

/// Client→server: "my hostname is `name`; here are my tunnel addresses".
///
/// Also carries the client's tunnel addresses so the server can learn/refresh
/// its UDP mapping (exactly like the keepalive). An empty `name` withdraws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAdvert {
    /// Whether the client wants the server to push the peer map back.
    pub want_peers: bool,
    /// The client's tunnel IPv4 address.
    pub tunnel_ip: Ipv4Addr,
    /// The client's tunnel IPv6 address, when it has one.
    pub tunnel_ip6: Option<Ipv6Addr>,
    /// Requested DNS label (already sanitized by the sender). Empty = withdraw.
    pub name: String,
}

/// One peer in a [`PeerPush`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// Granted DNS label (no suffix).
    pub name: String,
    /// Tunnel IPv4.
    pub ip4: Ipv4Addr,
    /// Tunnel IPv6, when the peer has one.
    pub ip6: Option<Ipv6Addr>,
}

/// Server→client: the current hostname → tunnel-IP map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPush {
    /// Peers (server included), truncated to [`MAX_PEERS`].
    pub peers: Vec<PeerEntry>,
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

/// Client→server: request a unique tunnel address keyed by `node_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignReq {
    /// Bit 0 is [`FLAG_WANT_IP6`]; other bits are 0 in v1.
    pub flags: u8,
    /// Persistent 16-byte node identity.
    pub node_id: [u8; 16],
    /// Preferred IPv4; `0.0.0.0` = no hint.
    pub hint_ip4: Ipv4Addr,
    /// Preferred IPv6; wire `::` decodes to `None`.
    pub hint_ip6: Option<Ipv6Addr>,
}

/// Outcome of an [`Assign`] reply. There is no `Conflict` discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssignStatus {
    /// Assignment succeeded.
    Ok = 0,
    /// Pool exhausted.
    Exhausted = 1,
    /// Server is in `--nat` mode; assignment is disabled.
    NatMode = 2,
}

impl AssignStatus {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::Exhausted),
            2 => Some(Self::NatMode),
            _ => None,
        }
    }
}

/// Server→client: assigned tunnel addresses, or a non-Ok status with zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assign {
    /// Whether the request was granted.
    pub status: AssignStatus,
    /// Assigned tunnel IPv4.
    pub tun_ip: Ipv4Addr,
    /// Server TUN IPv4 netmask.
    pub netmask: Ipv4Addr,
    /// Server TUN IPv4 (the client's point-to-point destination).
    pub peer_ip: Ipv4Addr,
    /// `None` when `plen6 == 0` (wire IPv6 bytes are `::`).
    pub tun_ip6: Option<Ipv6Addr>,
    /// IPv6 prefix length; `0` means no IPv6.
    pub plen6: u8,
    /// Reserved; v1 senders write 0.
    pub flags: u8,
    /// Lease lifetime in seconds.
    pub ttl_secs: u32,
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

impl AssignReq {
    /// Serialize into a 39-byte control payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ASSIGN_REQ_LEN);
        buf.push(CONTROL_MARKER);
        buf.push(TYPE_ASSIGN_REQ);
        buf.push(self.flags);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.hint_ip4.octets());
        buf.extend_from_slice(&self.hint_ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
        buf
    }
}

impl Assign {
    /// Serialize into a 37-byte control payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ASSIGN_LEN);
        buf.push(CONTROL_MARKER);
        buf.push(TYPE_ASSIGN);
        buf.push(self.status as u8);
        buf.extend_from_slice(&self.tun_ip.octets());
        buf.extend_from_slice(&self.netmask.octets());
        buf.extend_from_slice(&self.peer_ip.octets());
        buf.extend_from_slice(&self.tun_ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
        buf.push(self.plen6);
        buf.push(self.flags);
        buf.extend_from_slice(&self.ttl_secs.to_be_bytes());
        buf
    }
}

impl NameAdvert {
    /// Serialize into a control payload. `name` is truncated to [`MAX_NAME_LEN`].
    pub fn encode(&self) -> Vec<u8> {
        let name = name_bytes(&self.name);
        let mut buf = Vec::with_capacity(NAME_ADVERT_HEADER_LEN + name.len());
        buf.push(CONTROL_MARKER);
        buf.push(TYPE_NAME_ADVERT);
        buf.push(if self.want_peers { FLAG_WANT_PEERS } else { 0 });
        buf.extend_from_slice(&self.tunnel_ip.octets());
        buf.extend_from_slice(&self.tunnel_ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
        buf.push(name.len() as u8);
        buf.extend_from_slice(name);
        buf
    }
}

impl PeerPush {
    /// Serialize into a control payload. Entries beyond [`MAX_PEERS`] and
    /// names longer than [`MAX_NAME_LEN`] are truncated.
    pub fn encode(&self) -> Vec<u8> {
        let peers = &self.peers[..self.peers.len().min(MAX_PEERS)];
        let mut buf = Vec::with_capacity(PEER_PUSH_HEADER_LEN + peers.len() * 54);
        buf.push(CONTROL_MARKER);
        buf.push(TYPE_PEER_PUSH);
        buf.push(0); // reserved
        buf.push(peers.len() as u8);
        for p in peers {
            let name = name_bytes(&p.name);
            buf.push(if p.ip6.is_some() { EFLAG_HAS_IP6 } else { 0 });
            buf.extend_from_slice(&p.ip4.octets());
            buf.extend_from_slice(&p.ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
            buf.push(name.len() as u8);
            buf.extend_from_slice(name);
        }
        buf
    }
}

/// Truncate `name` to [`MAX_NAME_LEN`] ASCII/UTF-8 bytes without splitting a
/// codepoint (labels are ASCII in practice).
fn name_bytes(name: &str) -> &[u8] {
    let raw = name.as_bytes();
    let n = raw.len().min(MAX_NAME_LEN);
    // Walk back if we landed mid-character (should not happen for DNS labels).
    let mut end = n;
    while end > 0 && raw[end - 1] & 0b1100_0000 == 0b1000_0000 {
        end -= 1;
    }
    &raw[..end]
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
        TYPE_ASSIGN_REQ => {
            if payload.len() != ASSIGN_REQ_LEN {
                return None;
            }
            let flags = payload[2];
            let node_id = <[u8; 16]>::try_from(&payload[3..19]).expect("16 bytes");
            let hint_ip4 = Ipv4Addr::new(payload[19], payload[20], payload[21], payload[22]);
            let hint6 = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[23..39]).expect("16 bytes"));
            Some(Control::AssignReq(AssignReq {
                flags,
                node_id,
                hint_ip4,
                hint_ip6: (!hint6.is_unspecified()).then_some(hint6),
            }))
        }
        TYPE_NAME_ADVERT => {
            let body = payload.get(2..)?;
            if body.len() < NAME_ADVERT_HEADER_LEN - 2 {
                return None;
            }
            let flags = body[0];
            let tunnel_ip = Ipv4Addr::new(body[1], body[2], body[3], body[4]);
            let ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&body[5..21]).expect("16 bytes"));
            let nlen = body[21] as usize;
            if nlen > MAX_NAME_LEN {
                return None;
            }
            let name_bytes = body.get(22..)?;
            if name_bytes.len() != nlen {
                return None;
            }
            let name = std::str::from_utf8(name_bytes).ok()?.to_string();
            Some(Control::NameAdvert(NameAdvert {
                want_peers: flags & FLAG_WANT_PEERS != 0,
                tunnel_ip,
                tunnel_ip6: (!ip6.is_unspecified()).then_some(ip6),
                name,
            }))
        }
        TYPE_PEER_PUSH => {
            let count = *payload.get(3)? as usize;
            if count > MAX_PEERS {
                return None;
            }
            let mut rest = payload.get(4..)?;
            let mut peers = Vec::with_capacity(count);
            for _ in 0..count {
                let (&eflags, after_flags) = rest.split_first()?;
                let (ip4b, after_ip4) = after_flags.split_first_chunk::<4>()?;
                let (ip6b, after_ip6) = after_ip4.split_first_chunk::<16>()?;
                let (&nlen, after_nlen) = after_ip6.split_first()?;
                let nlen = nlen as usize;
                if nlen > MAX_NAME_LEN {
                    return None;
                }
                if after_nlen.len() < nlen {
                    return None;
                }
                let (nameb, after_name) = after_nlen.split_at(nlen);
                let name = std::str::from_utf8(nameb).ok()?.to_string();
                let ip6 = Ipv6Addr::from(*ip6b);
                peers.push(PeerEntry {
                    name,
                    ip4: Ipv4Addr::from(*ip4b),
                    ip6: (eflags & EFLAG_HAS_IP6 != 0 && !ip6.is_unspecified()).then_some(ip6),
                });
                rest = after_name;
            }
            rest.is_empty()
                .then_some(Control::PeerPush(PeerPush { peers }))
        }
        TYPE_ASSIGN => {
            if payload.len() != ASSIGN_LEN {
                return None;
            }
            let status = AssignStatus::from_u8(payload[2])?;
            let tun_ip = Ipv4Addr::new(payload[3], payload[4], payload[5], payload[6]);
            let netmask = Ipv4Addr::new(payload[7], payload[8], payload[9], payload[10]);
            let peer_ip = Ipv4Addr::new(payload[11], payload[12], payload[13], payload[14]);
            let ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[15..31]).expect("16 bytes"));
            let plen6 = payload[31];
            let flags = payload[32];
            let ttl_secs =
                u32::from_be_bytes(<[u8; 4]>::try_from(&payload[33..37]).expect("4 bytes"));
            Some(Control::Assign(Assign {
                status,
                tun_ip,
                netmask,
                peer_ip,
                tun_ip6: (plen6 != 0).then_some(ip6),
                plen6,
                flags,
                ttl_secs,
            }))
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

    /// Remove every installed route. Best-effort, like [`Self::apply`]'s removals.
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
    fn assign_ok_hex_example_roundtrips() {
        let hex = [
            0x00, 0x04, 0x00, // marker, type, Ok
            0x0a, 0x09, 0x00, 0x25, // 10.9.0.37
            0xff, 0xff, 0xff, 0x00, // /24
            0x0a, 0x09, 0x00, 0x01, // peer 10.9.0.1
            0xfd, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x09,
            0x00, 0x25, // fd07:7::a09:25
            0x40, // plen6 = 64
            0x00, // flags
            0x00, 0x09, 0x3a, 0x80, // ttl 604800
        ];
        assert_eq!(hex.len(), ASSIGN_LEN);
        let expected = Assign {
            status: AssignStatus::Ok,
            tun_ip: Ipv4Addr::new(10, 9, 0, 37),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            peer_ip: Ipv4Addr::new(10, 9, 0, 1),
            tun_ip6: Some("fd07:7::a09:25".parse().unwrap()),
            plen6: 64,
            flags: 0,
            ttl_secs: 604_800,
        };
        assert_eq!(parse_control(&hex), Some(Control::Assign(expected.clone())));
        assert_eq!(expected.encode(), hex);
    }

    #[test]
    fn assign_req_roundtrips() {
        let req = AssignReq {
            flags: FLAG_WANT_IP6,
            node_id: [
                0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            hint_ip4: Ipv4Addr::new(10, 9, 0, 37),
            hint_ip6: Some("fd07:7::a09:25".parse().unwrap()),
        };
        let bytes = req.encode();
        assert_eq!(bytes.len(), ASSIGN_REQ_LEN);
        assert_eq!(parse_control(&bytes), Some(Control::AssignReq(req)));

        let no_hints = AssignReq {
            flags: 0,
            node_id: [0; 16],
            hint_ip4: Ipv4Addr::UNSPECIFIED,
            hint_ip6: None,
        };
        match parse_control(&no_hints.encode()) {
            Some(Control::AssignReq(r)) => {
                assert_eq!(r.hint_ip4, Ipv4Addr::UNSPECIFIED);
                assert_eq!(r.hint_ip6, None);
            }
            other => panic!("expected AssignReq, got {other:?}"),
        }
    }

    #[test]
    fn five_byte_00_03_is_still_keepalive() {
        // Length-dispatch claims 5-byte payloads before the type byte; 0x03 is
        // an IP octet here, not TYPE_ASSIGN_REQ.
        assert_eq!(
            parse_control(&[0x00, 0x03, 0xaa, 0xbb, 0xcc]),
            Some(Control::Keepalive(Some(Ipv4Addr::new(
                0x03, 0xaa, 0xbb, 0xcc
            ))))
        );
    }

    #[test]
    fn assign_wrong_length_and_unknown_type_are_none() {
        let mut short = vec![0x00, 0x04];
        short.resize(36, 0);
        assert_eq!(parse_control(&short), None);

        let mut long = vec![0x00, 0x04];
        long.resize(38, 0);
        assert_eq!(parse_control(&long), None);

        // Unknown type 0x07 (0x05/0x06 are name advert / peer push).
        assert_eq!(parse_control(&[0x00, 0x07, 0x00, 0x00]), None);
        // Type 0x05 with a truncated header is still None.
        assert_eq!(parse_control(&[0x00, 0x05, 0x00, 0x00]), None);
    }

    #[test]
    fn assign_plen6_zero_clears_tun_ip6() {
        // plen6 is authoritative: a non-:: address with plen6=0 is still None.
        let mut bytes = Assign {
            status: AssignStatus::Ok,
            tun_ip: Ipv4Addr::new(10, 9, 0, 37),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            peer_ip: Ipv4Addr::new(10, 9, 0, 1),
            tun_ip6: Some("fd07:7::a09:25".parse().unwrap()),
            plen6: 64,
            flags: 0,
            ttl_secs: 604_800,
        }
        .encode();
        bytes[31] = 0;
        match parse_control(&bytes) {
            Some(Control::Assign(a)) => {
                assert_eq!(a.tun_ip6, None);
                assert_eq!(a.plen6, 0);
            }
            other => panic!("expected Assign, got {other:?}"),
        }
    }

    #[test]
    fn name_advert_roundtrips() {
        let advert = NameAdvert {
            want_peers: true,
            tunnel_ip: Ipv4Addr::new(10, 9, 0, 5),
            tunnel_ip6: Some("fd07:7::a09:5".parse().unwrap()),
            name: "laptop".into(),
        };
        let bytes = advert.encode();
        assert_ne!(bytes.len(), 1);
        assert_ne!(bytes.len(), 5);
        assert_eq!(parse_control(&bytes), Some(Control::NameAdvert(advert)));

        let empty = NameAdvert {
            want_peers: false,
            tunnel_ip: Ipv4Addr::new(10, 9, 0, 2),
            tunnel_ip6: None,
            name: String::new(),
        };
        assert_eq!(
            parse_control(&empty.encode()),
            Some(Control::NameAdvert(empty))
        );
    }

    #[test]
    fn peer_push_roundtrips_and_caps_name() {
        let push = PeerPush {
            peers: vec![
                PeerEntry {
                    name: "vpn".into(),
                    ip4: Ipv4Addr::new(10, 9, 0, 1),
                    ip6: Some("fd07:7::1".parse().unwrap()),
                },
                PeerEntry {
                    name: "pi".into(),
                    ip4: Ipv4Addr::new(10, 9, 0, 7),
                    ip6: None,
                },
            ],
        };
        assert_eq!(parse_control(&push.encode()), Some(Control::PeerPush(push)));

        // Empty push is 4 bytes (not 1 or 5).
        let empty = PeerPush { peers: vec![] };
        let bytes = empty.encode();
        assert_eq!(bytes.len(), 4);
        assert_eq!(parse_control(&bytes), Some(Control::PeerPush(empty)));
    }

    #[test]
    fn five_byte_00_05_is_still_keepalive() {
        assert_eq!(
            parse_control(&[0x00, 0x05, 0xaa, 0xbb, 0xcc]),
            Some(Control::Keepalive(Some(Ipv4Addr::new(
                0x05, 0xaa, 0xbb, 0xcc
            ))))
        );
    }

    #[test]
    fn assign_status_has_no_conflict() {
        // Exhaustiveness: a Conflict discriminant would fail this match.
        match AssignStatus::Ok {
            AssignStatus::Ok | AssignStatus::Exhausted | AssignStatus::NatMode => {}
        }
        assert_eq!(AssignStatus::from_u8(3), None);
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
