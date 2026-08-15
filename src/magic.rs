//! Magic DNS: resolve joined peers by hostname.
//!
//! The server collects a hostname from each learning-mode client ([`NameAdvert`])
//! and pushes the granted name → tunnel-IP map ([`PeerPush`]) back. Each client
//! answers `A`/`AAAA` for those names from a local [`PeerTable`] — Tailscale's
//! *Magic DNS* without a control plane.
//!
//! Names are a single DNS label (default: the sanitized OS hostname). The
//! default suffix is [`DEFAULT_SUFFIX`] (`svpn`), so `laptop` and `laptop.svpn`
//! both resolve. First-come keeps a colliding name; later nodes get
//! `name-aabb`. NAT mode has no unique peer IPs, so the server ignores adverts.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::assign::NodeId;
use crate::mesh::{NameAdvert, PeerEntry, PeerPush, MAX_NAME_LEN, MAX_PEERS};

/// Default Magic DNS suffix: `laptop` and `laptop.svpn` both resolve.
pub const DEFAULT_SUFFIX: &str = "svpn";

/// TTL advertised on synthesized Magic DNS answers (seconds).
pub const MAGIC_TTL_SECS: u32 = 30;

/// One peer's tunnel addresses, as stored on the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddrs {
    /// Tunnel IPv4.
    pub ip4: Ipv4Addr,
    /// Tunnel IPv6, when the peer has one.
    pub ip6: Option<Ipv6Addr>,
}

/// Client-side hostname → address map, updated from each [`PeerPush`].
///
/// Keys are stored lower-cased, once as the bare label and once as
/// `label.suffix`, so a lookup of either form hits.
#[derive(Debug, Default)]
pub struct PeerTable {
    inner: RwLock<HashMap<String, PeerAddrs>>,
}

impl PeerTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the table with `peers`, indexing each name and `name.suffix`.
    pub fn replace(&self, peers: &[PeerEntry], suffix: &str) {
        let mut map = HashMap::with_capacity(peers.len().saturating_mul(2));
        for p in peers {
            let addrs = PeerAddrs {
                ip4: p.ip4,
                ip6: p.ip6,
            };
            let label = p.name.to_ascii_lowercase();
            if label.is_empty() {
                continue;
            }
            if !suffix.is_empty() {
                map.insert(format!("{label}.{suffix}"), addrs);
            }
            map.insert(label, addrs);
        }
        *self.inner.write().expect("peer table lock") = map;
    }

    /// Look up a (already lower-cased) question name.
    pub fn lookup(&self, name: &str) -> Option<PeerAddrs> {
        self.inner
            .read()
            .expect("peer table lock")
            .get(name)
            .copied()
    }

    /// Number of stored keys (bare + suffixed).
    pub fn len(&self) -> usize {
        self.inner.read().expect("peer table lock").len()
    }

    /// True when no names are stored.
    pub fn is_empty(&self) -> bool {
        self.inner.read().expect("peer table lock").is_empty()
    }
}

/// Apply a server push onto `table`.
pub fn apply_push(table: &PeerTable, push: &PeerPush, suffix: &str) {
    table.replace(&push.peers, suffix);
}

/// True when `name` is in the Magic DNS zone (`suffix` or `*.suffix`).
///
/// Unknown names in this zone must NXDOMAIN rather than leak to upstream.
pub fn is_magic_suffix_name(name: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

/// Sanitize a user- or OS-supplied hostname into one DNS label.
///
/// Takes the first label, lowercases, replaces invalid characters with `-`,
/// collapses hyphens, trims, and caps at [`MAX_NAME_LEN`]. Empty → `"node"`.
pub fn sanitize_hostname(raw: &str) -> String {
    let first = raw.split('.').find(|s| !s.is_empty()).unwrap_or("");
    let mut out = String::with_capacity(first.len().min(MAX_NAME_LEN));
    let mut prev_hyphen = false;
    for c in first.chars() {
        if out.len() >= MAX_NAME_LEN {
            break;
        }
        let c = c.to_ascii_lowercase();
        let ok = c.is_ascii_alphanumeric() || c == '-';
        if ok {
            if c == '-' {
                if prev_hyphen || out.is_empty() {
                    continue;
                }
                prev_hyphen = true;
            } else {
                prev_hyphen = false;
            }
            out.push(c);
        } else if c == '_' || c.is_whitespace() {
            if prev_hyphen || out.is_empty() {
                continue;
            }
            out.push('-');
            prev_hyphen = true;
        }
    }
    let trimmed = out.trim_end_matches('-');
    if trimmed.is_empty() {
        "node".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Sanitize a Magic DNS suffix (same label rules as a hostname).
pub fn sanitize_suffix(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    let s = sanitize_hostname(raw);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Best-effort OS hostname (unsanitized). Falls back to `"node"`.
pub fn os_hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: `buf` is a valid writable 256-byte region; gethostname writes
        // a NUL-terminated name or returns -1.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if rc == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(s) = std::env::var("COMPUTERNAME") {
            if !s.is_empty() {
                return s;
            }
        }
    }
    if let Ok(s) = std::env::var("HOSTNAME") {
        if !s.is_empty() {
            return s;
        }
    }
    "node".to_string()
}

/// Collision disambiguator: first two bytes of `node_id` as hex, else the IPv4
/// last octet as two hex digits.
pub fn collision_suffix(node_id: Option<NodeId>, ip4: Ipv4Addr) -> String {
    match node_id {
        Some(id) => format!("{:02x}{:02x}", id[0], id[1]),
        None => format!("{:02x}", ip4.octets()[3]),
    }
}

/// What changed when a name advert was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameOutcome {
    /// `name` is newly granted (or the peer changed to it). `renamed` is set
    /// when the granted label is not the one requested (collision suffix).
    Granted {
        /// Label the peer now owns.
        name: String,
        /// True when `name` is not the requested label.
        renamed: bool,
    },
    /// Same peer, same name: addresses / last-seen refreshed.
    Refreshed {
        /// Label the peer still owns.
        name: String,
    },
    /// The peer withdrew its name (`nlen = 0`) or advertised an empty label.
    Withdrawn {
        /// Label that was removed, if the peer had one.
        name: Option<String>,
    },
}

struct NameRow {
    requested: String,
    granted: String,
    ip4: Ipv4Addr,
    ip6: Option<Ipv6Addr>,
    last_seen: Instant,
}

/// Server-side hostname table.
///
/// Keyed by the client's current UDP endpoint. The server's own name is a
/// permanent row that never expires and always wins collisions.
pub struct NameTable {
    server: Option<PeerEntry>,
    by_peer: HashMap<SocketAddr, NameRow>,
    by_name: HashMap<String, SocketAddr>,
}

impl Default for NameTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NameTable {
    /// Empty table (no server name).
    pub fn new() -> Self {
        Self {
            server: None,
            by_peer: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Table with a permanent server row.
    pub fn with_server(name: String, ip4: Ipv4Addr, ip6: Option<Ipv6Addr>) -> Self {
        let name = sanitize_hostname(&name);
        Self {
            server: Some(PeerEntry { name, ip4, ip6 }),
            by_peer: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Apply one client's advert. An empty `raw` withdraws the name.
    /// `node_id` is used only for the collision suffix.
    pub fn advertise(
        &mut self,
        peer: SocketAddr,
        raw: &str,
        ip4: Ipv4Addr,
        ip6: Option<Ipv6Addr>,
        node_id: Option<NodeId>,
        now: Instant,
    ) -> NameOutcome {
        if raw.is_empty() {
            return self.withdraw(peer);
        }
        let requested = sanitize_hostname(raw);
        if let Some(row) = self.by_peer.get_mut(&peer) {
            if row.requested == requested {
                row.ip4 = ip4;
                row.ip6 = ip6;
                row.last_seen = now;
                return NameOutcome::Refreshed {
                    name: row.granted.clone(),
                };
            }
        }
        // Name change (or first advert): drop the previous grant first so the
        // old label is free for someone else, including this peer.
        let _ = self.withdraw(peer);

        let granted = self.unique_name(&requested, node_id, ip4);
        let renamed = granted != requested;
        self.by_name.insert(granted.clone(), peer);
        self.by_peer.insert(
            peer,
            NameRow {
                requested,
                granted: granted.clone(),
                ip4,
                ip6,
                last_seen: now,
            },
        );
        NameOutcome::Granted {
            name: granted,
            renamed,
        }
    }

    /// Forget `peer`'s name, if any.
    pub fn withdraw(&mut self, peer: SocketAddr) -> NameOutcome {
        let Some(row) = self.by_peer.remove(&peer) else {
            return NameOutcome::Withdrawn { name: None };
        };
        if self.by_name.get(&row.granted) == Some(&peer) {
            self.by_name.remove(&row.granted);
        }
        NameOutcome::Withdrawn {
            name: Some(row.granted),
        }
    }

    /// Drop names whose owner has not re-advertised within `ttl`.
    pub fn expire(&mut self, ttl: Duration, now: Instant) -> Vec<String> {
        let mut expired = Vec::new();
        self.by_peer.retain(|peer, row| {
            let live = now.saturating_duration_since(row.last_seen) <= ttl;
            if !live {
                if self.by_name.get(&row.granted) == Some(peer) {
                    self.by_name.remove(&row.granted);
                }
                expired.push(row.granted.clone());
            }
            live
        });
        expired
    }

    /// Snapshot for a [`PeerPush`]: server first, then live clients, capped
    /// at [`MAX_PEERS`].
    pub fn snapshot(&self) -> Vec<PeerEntry> {
        let mut out = Vec::with_capacity(self.by_peer.len() + 1);
        if let Some(server) = &self.server {
            out.push(server.clone());
        }
        for row in self.by_peer.values() {
            if out.len() >= MAX_PEERS {
                break;
            }
            out.push(PeerEntry {
                name: row.granted.clone(),
                ip4: row.ip4,
                ip6: row.ip6,
            });
        }
        out
    }

    /// Granted name for `peer`, if any.
    pub fn name_for(&self, peer: SocketAddr) -> Option<&str> {
        self.by_peer.get(&peer).map(|r| r.granted.as_str())
    }

    /// Number of client rows (server not counted).
    pub fn len(&self) -> usize {
        self.by_peer.len()
    }

    /// True when no client has advertised a name.
    pub fn is_empty(&self) -> bool {
        self.by_peer.is_empty()
    }

    fn name_taken(&self, name: &str) -> bool {
        self.server.as_ref().is_some_and(|s| s.name == name) || self.by_name.contains_key(name)
    }

    fn unique_name(&self, wanted: &str, node_id: Option<NodeId>, ip4: Ipv4Addr) -> String {
        if !self.name_taken(wanted) {
            return wanted.to_string();
        }
        let tag = collision_suffix(node_id, ip4);
        let extra = format!("-{tag}");
        let candidate = fit_label(wanted, &extra);
        if !self.name_taken(&candidate) {
            return candidate;
        }
        for n in 2u16..256 {
            let extra = format!("-{tag}-{n}");
            let candidate = fit_label(wanted, &extra);
            if !self.name_taken(&candidate) {
                return candidate;
            }
        }
        candidate
    }
}

/// Build a [`NameAdvert`] for a client tick.
pub fn name_advert(
    hostname: &str,
    tun_ip: Ipv4Addr,
    tun_ip6: Option<Ipv6Addr>,
    want_peers: bool,
) -> NameAdvert {
    NameAdvert {
        want_peers,
        tunnel_ip: tun_ip,
        tunnel_ip6: tun_ip6,
        name: hostname.to_string(),
    }
}

fn fit_label(base: &str, extra: &str) -> String {
    let max_base = MAX_NAME_LEN.saturating_sub(extra.len());
    let mut head: String = base.chars().take(max_base).collect();
    while head.ends_with('-') {
        head.pop();
    }
    if head.is_empty() {
        extra.trim_start_matches('-').to_string()
    } else {
        format!("{head}{extra}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        format!("192.0.2.1:{port}").parse().unwrap()
    }

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn sanitize_takes_first_label_and_lowercases() {
        assert_eq!(sanitize_hostname("My-Laptop.local"), "my-laptop");
        assert_eq!(sanitize_hostname("PI_4"), "pi-4");
        assert_eq!(sanitize_hostname("  "), "node");
        assert_eq!(sanitize_hostname(""), "node");
        assert_eq!(sanitize_hostname("---"), "node");
        assert_eq!(sanitize_hostname("Foo--Bar"), "foo-bar");
        let long = "a".repeat(40);
        assert_eq!(sanitize_hostname(&long).len(), MAX_NAME_LEN);
    }

    #[test]
    fn suffix_rejects_empty() {
        assert_eq!(sanitize_suffix(""), None);
        assert_eq!(sanitize_suffix("   "), None);
        assert_eq!(sanitize_suffix(".svpn"), Some("svpn".into()));
        assert_eq!(sanitize_suffix("SVPN"), Some("svpn".into()));
    }

    #[test]
    fn collision_suffix_uses_node_id_then_ip() {
        let id = [0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            collision_suffix(Some(id), Ipv4Addr::new(10, 9, 0, 7)),
            "abcd"
        );
        assert_eq!(collision_suffix(None, Ipv4Addr::new(10, 9, 0, 7)), "07");
    }

    #[test]
    fn first_come_keeps_name_second_gets_suffix() {
        let mut t = NameTable::with_server("vpn".into(), Ipv4Addr::new(10, 9, 0, 1), None);
        let a = peer(1000);
        let b = peer(2000);
        let tick = now();
        match t.advertise(a, "laptop", Ipv4Addr::new(10, 9, 0, 5), None, None, tick) {
            NameOutcome::Granted { name, renamed } => {
                assert_eq!(name, "laptop");
                assert!(!renamed);
            }
            other => panic!("{other:?}"),
        }
        match t.advertise(b, "laptop", Ipv4Addr::new(10, 9, 0, 7), None, None, tick) {
            NameOutcome::Granted { name, renamed } => {
                assert_eq!(name, "laptop-07");
                assert!(renamed);
            }
            other => panic!("{other:?}"),
        }
        // Server name is reserved.
        match t.advertise(
            peer(3000),
            "vpn",
            Ipv4Addr::new(10, 9, 0, 8),
            None,
            None,
            tick,
        ) {
            NameOutcome::Granted { name, renamed } => {
                assert_eq!(name, "vpn-08");
                assert!(renamed);
            }
            other => panic!("{other:?}"),
        }
        let snap = t.snapshot();
        assert_eq!(snap[0].name, "vpn");
        assert_eq!(snap[0].ip4, Ipv4Addr::new(10, 9, 0, 1));
        assert_eq!(snap.len(), 4); // server + 3 clients
    }

    #[test]
    fn refresh_is_quiet_and_withdraw_frees_name() {
        let mut t = NameTable::new();
        let a = peer(1);
        let tick = now();
        t.advertise(a, "pi", Ipv4Addr::new(10, 9, 0, 4), None, None, tick);
        match t.advertise(a, "pi", Ipv4Addr::new(10, 9, 0, 4), None, None, tick) {
            NameOutcome::Refreshed { name } => assert_eq!(name, "pi"),
            other => panic!("{other:?}"),
        }
        match t.advertise(a, "", Ipv4Addr::new(10, 9, 0, 4), None, None, tick) {
            NameOutcome::Withdrawn { name } => assert_eq!(name.as_deref(), Some("pi")),
            other => panic!("{other:?}"),
        }
        assert!(t.is_empty());
        // Name is free again.
        match t.advertise(peer(2), "pi", Ipv4Addr::new(10, 9, 0, 9), None, None, tick) {
            NameOutcome::Granted { name, renamed } => {
                assert_eq!(name, "pi");
                assert!(!renamed);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn expire_drops_quiet_peers() {
        let mut t = NameTable::new();
        let tick = now();
        t.advertise(
            peer(1),
            "old",
            Ipv4Addr::new(10, 9, 0, 4),
            None,
            None,
            tick - Duration::from_secs(200),
        );
        t.advertise(
            peer(2),
            "fresh",
            Ipv4Addr::new(10, 9, 0, 5),
            None,
            None,
            tick,
        );
        let gone = t.expire(Duration::from_secs(120), tick);
        assert_eq!(gone, vec!["old".to_string()]);
        assert_eq!(t.len(), 1);
        assert_eq!(t.name_for(peer(2)), Some("fresh"));
    }

    #[test]
    fn peer_table_indexes_bare_and_suffix() {
        let table = PeerTable::new();
        table.replace(
            &[PeerEntry {
                name: "Pi".into(),
                ip4: Ipv4Addr::new(10, 9, 0, 7),
                ip6: Some("fd07:7::a09:7".parse().unwrap()),
            }],
            "svpn",
        );
        let got = table.lookup("pi").unwrap();
        assert_eq!(got.ip4, Ipv4Addr::new(10, 9, 0, 7));
        assert_eq!(table.lookup("pi.svpn").unwrap().ip4, got.ip4);
        assert!(table.lookup("pi.svpn.svpn").is_none());
        assert!(is_magic_suffix_name("nope.svpn", "svpn"));
        assert!(is_magic_suffix_name("svpn", "svpn"));
        assert!(!is_magic_suffix_name("pi", "svpn"));
        assert!(!is_magic_suffix_name("example.com", "svpn"));
    }
}
