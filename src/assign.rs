//! Node-id keyed tunnel-IP assignment (learning mode).
//!
//! Distinct from [`crate::nat`] / [`crate::pool`]: NAT keys sessions by UDP
//! endpoint and rewrites packets; this table keys by a persisted 16-byte
//! `node_id` and returns the address to the client. Probe offset is
//! SHA-256 of the node id so a lost lease file restores the same starting
//! address across processes (`DefaultHasher` would not).

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnetwork::Ipv6Network;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mesh::{Assign, AssignReq, AssignStatus, FLAG_WANT_IP6};
use crate::pool::host_range;
use crate::state::write_private_atomic;

/// Idle time before an assignment is reclaimed (7 days).
pub const DEFAULT_ASSIGN_TTL_SECS: u64 = 604_800;

/// Persisted 16-byte node identity.
pub type NodeId = [u8; 16];

/// One node's assigned addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Owning node.
    pub node_id: NodeId,
    /// Assigned tunnel IPv4.
    pub ip4: Ipv4Addr,
    /// Assigned tunnel IPv6, when `FLAG_WANT_IP6` and the server prefix is ≤ 96.
    pub ip6: Option<Ipv6Addr>,
    /// Last `AssignRequest` that refreshed this lease.
    pub last_seen: SystemTime,
    /// Last UDP endpoint that requested this lease (not restored into `by_peer`).
    pub last_peer: Option<SocketAddr>,
}

/// Node-id keyed lease table.
pub struct Assigner {
    server_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    server_ip6: Option<Ipv6Network>,
    start: u32,
    end: u32,
    reserved: HashSet<Ipv4Addr>,
    by_node: HashMap<NodeId, Lease>,
    by_ip4: HashMap<Ipv4Addr, NodeId>,
    by_ip6: HashMap<Ipv6Addr, NodeId>,
    by_peer: HashMap<SocketAddr, NodeId>,
    ttl: Duration,
    persist_path: Option<PathBuf>,
    last_persist: SystemTime,
}

impl Assigner {
    /// Build an assigner over `server_ip`'s TUN subnet.
    ///
    /// `peer_ip` is always reserved (unioned with `extra_reserved`). Pass
    /// `persist_path = None` to disable persistence (`lease_file: "-"`).
    pub fn new(
        server_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        server_ip6: Option<Ipv6Network>,
        peer_ip: Ipv4Addr,
        extra_reserved: impl IntoIterator<Item = Ipv4Addr>,
        ttl: Duration,
        persist_path: Option<PathBuf>,
    ) -> Self {
        let (start, end) = host_range(server_ip, netmask);
        let mut reserved = HashSet::new();
        reserved.insert(peer_ip);
        reserved.extend(extra_reserved);
        let mut this = Self {
            server_ip,
            netmask,
            server_ip6,
            start,
            end,
            reserved,
            by_node: HashMap::new(),
            by_ip4: HashMap::new(),
            by_ip6: HashMap::new(),
            by_peer: HashMap::new(),
            ttl,
            persist_path,
            last_persist: SystemTime::now(),
        };
        if this.persist_path.is_some() {
            this.load(SystemTime::now());
        }
        // Caller (server banner) logs after optional set_host_range so
        // assigned/capacity reflects assign_pool, not the unscoped TUN range.
        this
    }

    /// Restrict the allocator to an inclusive host-order range (`assign_pool`).
    pub fn set_host_range(&mut self, start: u32, end: u32) {
        self.start = start;
        self.end = end;
    }

    /// Inclusive host-order allocator range.
    pub fn host_range(&self) -> (u32, u32) {
        (self.start, self.end)
    }

    /// Addresses that could be assigned (server IP and reserved excluded).
    pub fn capacity(&self) -> usize {
        if self.end < self.start {
            return 0;
        }
        let span = (self.end - self.start + 1) as usize;
        let mut cap = span;
        if in_range(self.server_ip, self.start, self.end) {
            cap -= 1;
        }
        for ip in &self.reserved {
            if *ip != self.server_ip && in_range(*ip, self.start, self.end) {
                cap -= 1;
            }
        }
        cap
    }

    /// Number of currently held leases.
    pub fn leased(&self) -> usize {
        self.by_node.len()
    }

    /// Lease for `node_id`, if any.
    pub fn lease(&self, node_id: NodeId) -> Option<&Lease> {
        self.by_node.get(&node_id)
    }

    /// Owner of an assigned IPv4.
    pub fn node_for_ip4(&self, ip: Ipv4Addr) -> Option<NodeId> {
        self.by_ip4.get(&ip).copied()
    }

    /// Owner of an assigned IPv6.
    pub fn node_for_ip6(&self, ip: Ipv6Addr) -> Option<NodeId> {
        self.by_ip6.get(&ip).copied()
    }

    /// Owner bound to a live UDP endpoint (`by_peer` is in-memory only).
    pub fn node_for_peer(&self, peer: SocketAddr) -> Option<NodeId> {
        self.by_peer.get(&peer).copied()
    }

    /// Allocate or refresh a lease for `req.node_id`.
    ///
    /// The `Vec` is every lease dropped during this call (TTL expiry or
    /// pressure reclaim) so the caller can unlearn those addresses.
    pub fn allocate(
        &mut self,
        req: &AssignReq,
        peer: SocketAddr,
        now: SystemTime,
    ) -> (Assign, Vec<Lease>) {
        let mut dropped = self.reap_inner(now);
        let mut dirty = !dropped.is_empty();

        if let Some(reply) = self.refresh_existing(req, peer, now, &mut dirty) {
            if dirty || self.should_persist(now) {
                self.persist(now);
            }
            return (reply, dropped);
        }

        if let Some(other) = self.by_peer.get(&peer).copied() {
            if other != req.node_id {
                self.by_peer.remove(&peer);
                warn!(
                    "duplicate endpoint {peer}, previous node_id {} unbound",
                    fmt_node(&other)
                );
            }
        }

        let want_ip6 = req.flags & FLAG_WANT_IP6 != 0;
        let Some((ip4, ip6)) = self.pick_addrs(req.node_id, req.hint_ip4, want_ip6) else {
            if let Some(reclaimed) = self.reclaim_oldest() {
                dirty = true;
                dropped.push(reclaimed);
                if let Some((ip4, ip6)) = self.pick_addrs(req.node_id, req.hint_ip4, want_ip6) {
                    return (self.bind_new(req.node_id, peer, ip4, ip6, now), dropped);
                }
            }
            if dirty {
                self.persist(now);
            }
            return (exhausted(), dropped);
        };
        (self.bind_new(req.node_id, peer, ip4, ip6, now), dropped)
    }

    /// Reclaim expired leases. Returns the dropped rows so the caller can unlearn.
    pub fn reap(&mut self, now: SystemTime) -> Vec<Lease> {
        let dropped = self.reap_inner(now);
        if !dropped.is_empty() {
            self.persist(now);
        }
        dropped
    }

    fn refresh_existing(
        &mut self,
        req: &AssignReq,
        peer: SocketAddr,
        now: SystemTime,
        dirty: &mut bool,
    ) -> Option<Assign> {
        let (ip4, ip6, old_peer) = {
            let lease = self.by_node.get_mut(&req.node_id)?;
            if is_expired(lease.last_seen, now, self.ttl) {
                return None;
            }
            lease.last_seen = now;
            (lease.ip4, lease.ip6, lease.last_peer)
        };
        if old_peer != Some(peer) {
            // Only unbind if we still own that socket. Restored last_peer (or
            // a step-2 unbind) may now belong to a different node.
            if let Some(old) = old_peer {
                if self.by_peer.get(&old) == Some(&req.node_id) {
                    self.by_peer.remove(&old);
                    warn!("duplicate node_id {}", fmt_node(&req.node_id));
                }
                info!(
                    "assigned {ip4} / {} to node {} via {peer} (moved endpoint {old})",
                    ip6_disp(ip6),
                    fmt_node(&req.node_id)
                );
            }
            if let Some(lease) = self.by_node.get_mut(&req.node_id) {
                lease.last_peer = Some(peer);
            }
            *dirty = true;
        }
        self.by_peer.insert(peer, req.node_id);
        Some(self.ok_reply(ip4, ip6))
    }

    fn bind_new(
        &mut self,
        node_id: NodeId,
        peer: SocketAddr,
        ip4: Ipv4Addr,
        ip6: Option<Ipv6Addr>,
        now: SystemTime,
    ) -> Assign {
        let _ = self.drop_lease(node_id);
        let lease = Lease {
            node_id,
            ip4,
            ip6,
            last_seen: now,
            last_peer: Some(peer),
        };
        self.by_node.insert(node_id, lease);
        self.by_ip4.insert(ip4, node_id);
        if let Some(v6) = ip6 {
            self.by_ip6.insert(v6, node_id);
        }
        self.by_peer.insert(peer, node_id);
        info!(
            "assigned {ip4} / {} to node {} via {peer} ({}/{})",
            ip6_disp(ip6),
            fmt_node(&node_id),
            self.by_node.len(),
            self.capacity()
        );
        self.maybe_warn_full();
        self.persist(now);
        self.ok_reply(ip4, ip6)
    }

    fn pick_addrs(
        &self,
        node_id: NodeId,
        hint: Ipv4Addr,
        want_ip6: bool,
    ) -> Option<(Ipv4Addr, Option<Ipv6Addr>)> {
        if let Some(pair) = self.try_ip4(node_id, hint, want_ip6) {
            return Some(pair);
        }
        if self.end < self.start {
            return None;
        }
        let span = self.end - self.start + 1;
        let offset = sha256_offset(node_id, span);
        let mut cand = self.start + offset;
        for _ in 0..span {
            let ip = Ipv4Addr::from(cand);
            if let Some(pair) = self.try_ip4(node_id, ip, want_ip6) {
                return Some(pair);
            }
            cand = if cand >= self.end {
                self.start
            } else {
                cand + 1
            };
        }
        None
    }

    fn try_ip4(
        &self,
        node_id: NodeId,
        ip4: Ipv4Addr,
        want_ip6: bool,
    ) -> Option<(Ipv4Addr, Option<Ipv6Addr>)> {
        if !self.usable_ip4(ip4, node_id) {
            return None;
        }
        match self.ip6_for(ip4, node_id, want_ip6) {
            Ip6Pick::SkipV4 => None,
            Ip6Pick::None => Some((ip4, None)),
            Ip6Pick::Some(ip6) => Some((ip4, Some(ip6))),
        }
    }

    fn usable_ip4(&self, ip: Ipv4Addr, node_id: NodeId) -> bool {
        if !in_range(ip, self.start, self.end) {
            return false;
        }
        if ip == self.server_ip || self.reserved.contains(&ip) {
            return false;
        }
        match self.by_ip4.get(&ip) {
            None => true,
            Some(owner) => *owner == node_id,
        }
    }

    fn ip6_for(&self, ip4: Ipv4Addr, node_id: NodeId, want_ip6: bool) -> Ip6Pick {
        if !want_ip6 {
            return Ip6Pick::None;
        }
        let Some(net) = self.server_ip6 else {
            return Ip6Pick::None;
        };
        if net.prefix() > 96 {
            warn_ip6_prefix_too_long();
            return Ip6Pick::None;
        }
        let ip6 = embed_ip4(net, ip4);
        if ip6 == net.ip() {
            return Ip6Pick::SkipV4;
        }
        match self.by_ip6.get(&ip6) {
            Some(owner) if *owner != node_id => Ip6Pick::SkipV4,
            _ => Ip6Pick::Some(ip6),
        }
    }

    fn reclaim_oldest(&mut self) -> Option<Lease> {
        let oldest = self
            .by_node
            .iter()
            .min_by_key(|(_, l)| l.last_seen)
            .map(|(id, _)| *id)?;
        warn!(
            "reclaiming oldest idle lease for node {} under pool pressure",
            fmt_node(&oldest)
        );
        self.drop_lease(oldest)
    }

    fn reap_inner(&mut self, now: SystemTime) -> Vec<Lease> {
        let expired: Vec<NodeId> = self
            .by_node
            .iter()
            .filter(|(_, l)| is_expired(l.last_seen, now, self.ttl))
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for id in expired {
            if let Some(lease) = self.drop_lease(id) {
                out.push(lease);
            }
        }
        out
    }

    fn drop_lease(&mut self, id: NodeId) -> Option<Lease> {
        let lease = self.by_node.remove(&id)?;
        self.by_ip4.remove(&lease.ip4);
        if let Some(ip6) = lease.ip6 {
            self.by_ip6.remove(&ip6);
        }
        if let Some(peer) = lease.last_peer {
            if self.by_peer.get(&peer) == Some(&id) {
                self.by_peer.remove(&peer);
            }
        }
        Some(lease)
    }

    fn ok_reply(&self, ip4: Ipv4Addr, ip6: Option<Ipv6Addr>) -> Assign {
        let (tun_ip6, plen6) = match (ip6, self.server_ip6) {
            (Some(ip), Some(net)) => (Some(ip), net.prefix()),
            _ => (None, 0),
        };
        Assign {
            status: AssignStatus::Ok,
            tun_ip: ip4,
            netmask: self.netmask,
            peer_ip: self.server_ip,
            tun_ip6,
            plen6,
            flags: 0,
            ttl_secs: u32::try_from(self.ttl.as_secs()).unwrap_or(u32::MAX),
        }
    }

    fn maybe_warn_full(&self) {
        let cap = self.capacity();
        if cap > 0 && self.by_node.len() * 5 >= cap * 4 {
            warn!("assignment pool at {}/{} (80%)", self.by_node.len(), cap);
        }
    }

    fn should_persist(&self, now: SystemTime) -> bool {
        now.duration_since(self.last_persist)
            .map(|d| d >= self.ttl / 4)
            .unwrap_or(true)
    }

    fn persist(&mut self, now: SystemTime) {
        let Some(path) = self.persist_path.clone() else {
            return;
        };
        match self.write_leases(&path) {
            Ok(()) => self.last_persist = now,
            Err(e) => warn!("failed to persist leases to {}: {e}", path.display()),
        }
    }

    fn write_leases(&self, path: &Path) -> std::io::Result<()> {
        let file = PersistFile {
            version: 1,
            leases: self
                .by_node
                .values()
                .map(PersistLease::from_lease)
                .collect(),
        };
        let data = serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_private_atomic(path, &data)
    }

    fn load(&mut self, now: SystemTime) {
        let Some(path) = self.persist_path.clone() else {
            return;
        };
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("cannot read lease file {}: {e}", path.display());
                return;
            }
        };
        let parsed: Result<PersistFile, _> = serde_json::from_slice(&data);
        let file = match parsed {
            Ok(f) if f.version == 1 => f,
            Ok(f) => {
                warn!(
                    "lease file {} has unsupported version {}",
                    path.display(),
                    f.version
                );
                quarantine(&path);
                return;
            }
            Err(e) => {
                warn!("corrupt lease file {}: {e}", path.display());
                quarantine(&path);
                return;
            }
        };
        let mut dropped = false;
        for row in file.leases {
            let Some(node_id) = parse_node_id(&row.node_id) else {
                warn!("skipping lease with bad node_id {}", row.node_id);
                dropped = true;
                continue;
            };
            let Some(last_seen) = from_unix(row.last_seen_unix) else {
                warn!(
                    "skipping lease with unrepresentable last_seen_unix {}",
                    row.last_seen_unix
                );
                dropped = true;
                continue;
            };
            if is_expired(last_seen, now, self.ttl) {
                dropped = true;
                continue;
            }
            if self.by_node.contains_key(&node_id) || self.by_ip4.contains_key(&row.ip4) {
                warn!("skipping duplicate lease for {}", row.node_id);
                dropped = true;
                continue;
            }
            if let Some(ip6) = row.ip6 {
                if self.by_ip6.contains_key(&ip6) {
                    warn!("skipping lease with duplicate ip6 {ip6}");
                    dropped = true;
                    continue;
                }
                self.by_ip6.insert(ip6, node_id);
            }
            self.by_ip4.insert(row.ip4, node_id);
            self.by_node.insert(
                node_id,
                Lease {
                    node_id,
                    ip4: row.ip4,
                    ip6: row.ip6,
                    last_seen,
                    last_peer: row.last_peer,
                },
            );
        }
        // by_peer stays empty on purpose: a restored binding plus a recycled
        // CGNAT port would unbind the wrong node.
        if dropped {
            self.persist(now);
        }
    }
}

enum Ip6Pick {
    None,
    Some(Ipv6Addr),
    SkipV4,
}

/// Embed `ip4` into the last 32 bits of `prefix`'s network address.
pub fn embed_ip4(prefix: Ipv6Network, ip4: Ipv4Addr) -> Ipv6Addr {
    let mut o = prefix.network().octets();
    o[12..16].copy_from_slice(&ip4.octets());
    Ipv6Addr::from(o)
}

fn sha256_offset(node_id: NodeId, span: u32) -> u32 {
    let digest = Sha256::digest(node_id);
    let mut head = [0u8; 4];
    head.copy_from_slice(&digest[..4]);
    u32::from_be_bytes(head) % span
}

fn in_range(ip: Ipv4Addr, start: u32, end: u32) -> bool {
    (start..=end).contains(&u32::from(ip))
}

fn is_expired(last_seen: SystemTime, now: SystemTime, ttl: Duration) -> bool {
    now.duration_since(last_seen)
        .map(|d| d > ttl)
        .unwrap_or(false)
}

fn to_unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn from_unix(secs: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

fn exhausted() -> Assign {
    Assign {
        status: AssignStatus::Exhausted,
        tun_ip: Ipv4Addr::UNSPECIFIED,
        netmask: Ipv4Addr::UNSPECIFIED,
        peer_ip: Ipv4Addr::UNSPECIFIED,
        tun_ip6: None,
        plen6: 0,
        flags: 0,
        ttl_secs: 0,
    }
}

fn fmt_node(id: &NodeId) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
        id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]
    )
}

fn parse_node_id(s: &str) -> Option<NodeId> {
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

fn ip6_disp(ip6: Option<Ipv6Addr>) -> String {
    ip6.map(|a| a.to_string()).unwrap_or_else(|| "-".into())
}

fn warn_ip6_prefix_too_long() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        warn!("tun_ip6 prefix > 96; IPv6 assignment skipped");
    });
}

fn quarantine(path: &Path) {
    let bad = {
        let mut s = path.as_os_str().to_os_string();
        s.push(".bad");
        PathBuf::from(s)
    };
    #[cfg(windows)]
    let _ = std::fs::remove_file(&bad);
    match std::fs::rename(path, &bad) {
        Ok(()) => warn!("renamed corrupt lease file to {}", bad.display()),
        Err(e) => warn!(
            "could not rename corrupt lease file {} -> {}: {e}",
            path.display(),
            bad.display()
        ),
    }
}

#[derive(Serialize, Deserialize)]
struct PersistFile {
    version: u32,
    leases: Vec<PersistLease>,
}

#[derive(Serialize, Deserialize)]
struct PersistLease {
    node_id: String,
    ip4: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip6: Option<Ipv6Addr>,
    last_seen_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_peer: Option<SocketAddr>,
}

impl PersistLease {
    fn from_lease(l: &Lease) -> Self {
        Self {
            node_id: fmt_node(&l.node_id),
            ip4: l.ip4,
            ip6: l.ip6,
            last_seen_unix: to_unix(l.last_seen),
            last_peer: l.last_peer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    const NODE_A: NodeId = [
        0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    const NODE_B: NodeId = [
        0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    const NODE_C: NodeId = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), port))
    }

    fn req(node: NodeId, hint: Ipv4Addr, want_ip6: bool) -> AssignReq {
        AssignReq {
            flags: if want_ip6 { FLAG_WANT_IP6 } else { 0 },
            node_id: node,
            hint_ip4: hint,
            hint_ip6: None,
        }
    }

    fn alloc(
        a: &mut Assigner,
        node: NodeId,
        hint: Ipv4Addr,
        p: SocketAddr,
        now: SystemTime,
    ) -> Assign {
        a.allocate(&req(node, hint, false), p, now).0
    }

    fn assigner(persist: Option<PathBuf>) -> Assigner {
        assigner_full(
            None,
            [],
            Duration::from_secs(DEFAULT_ASSIGN_TTL_SECS),
            persist,
        )
    }

    fn assigner_full(
        ip6: Option<Ipv6Network>,
        extra: impl IntoIterator<Item = Ipv4Addr>,
        ttl: Duration,
        persist: Option<PathBuf>,
    ) -> Assigner {
        Assigner::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            ip6,
            Ipv4Addr::new(10, 9, 0, 2),
            extra,
            ttl,
            persist,
        )
    }

    struct TempFile(PathBuf);
    impl TempFile {
        fn new() -> Self {
            let n = N.fetch_add(1, Ordering::Relaxed);
            Self(
                std::env::temp_dir()
                    .join(format!("shadowvpn-leases-{}-{n}.json", std::process::id())),
            )
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let mut bad = self.0.as_os_str().to_os_string();
            bad.push(".bad");
            let _ = std::fs::remove_file(bad);
            let mut tmp = self.0.as_os_str().to_os_string();
            tmp.push(".tmp");
            let _ = std::fs::remove_file(tmp);
        }
    }

    fn expected_probe(node: NodeId) -> Ipv4Addr {
        let start = u32::from(Ipv4Addr::new(10, 9, 0, 1));
        let end = u32::from(Ipv4Addr::new(10, 9, 0, 254));
        let span = end - start + 1;
        let mut cand = start + sha256_offset(node, span);
        let skip = [Ipv4Addr::new(10, 9, 0, 1), Ipv4Addr::new(10, 9, 0, 2)];
        for _ in 0..span {
            let ip = Ipv4Addr::from(cand);
            if !skip.contains(&ip) {
                return ip;
            }
            cand = if cand >= end { start } else { cand + 1 };
        }
        panic!("no probe candidate");
    }

    #[test]
    fn sha256_offset_stable_across_assigners() {
        let mut a = assigner(None);
        let mut b = assigner(None);
        let now = t0();
        let ra = alloc(&mut a, NODE_A, Ipv4Addr::UNSPECIFIED, peer(1), now);
        let rb = alloc(&mut b, NODE_A, Ipv4Addr::UNSPECIFIED, peer(1), now);
        assert_eq!(ra.status, AssignStatus::Ok);
        assert_eq!(ra.tun_ip, rb.tun_ip);
        assert_eq!(ra.tun_ip, expected_probe(NODE_A));
        assert_ne!(ra.tun_ip, Ipv4Addr::new(10, 9, 0, 1));
        assert_ne!(ra.tun_ip, Ipv4Addr::new(10, 9, 0, 2));
    }

    #[test]
    fn hint_reuse() {
        let mut a = assigner(None);
        let now = t0();
        let hint = Ipv4Addr::new(10, 9, 0, 37);
        let first = alloc(&mut a, NODE_A, hint, peer(1), now);
        assert_eq!(first.tun_ip, hint);
        let again = alloc(&mut a, NODE_A, hint, peer(1), now);
        assert_eq!(again.tun_ip, hint);
        let other = alloc(&mut a, NODE_B, hint, peer(2), now);
        assert_ne!(other.tun_ip, hint);
        assert_eq!(other.status, AssignStatus::Ok);
    }

    #[test]
    fn skip_reserved_and_server() {
        let reserved = Ipv4Addr::new(10, 9, 0, 10);
        let mut a = assigner_full(None, [reserved], Duration::from_secs(60), None);
        let now = t0();
        for (node, hint, port) in [
            (NODE_A, Ipv4Addr::new(10, 9, 0, 1), 1),
            (NODE_B, Ipv4Addr::new(10, 9, 0, 2), 2),
            (NODE_C, reserved, 3),
        ] {
            let r = alloc(&mut a, node, hint, peer(port), now);
            assert_eq!(r.status, AssignStatus::Ok);
            assert_ne!(r.tun_ip, Ipv4Addr::new(10, 9, 0, 1));
            assert_ne!(r.tun_ip, Ipv4Addr::new(10, 9, 0, 2));
            assert_ne!(r.tun_ip, reserved);
        }
        assert_eq!(a.capacity(), 252 - 1); // /24 minus server, .2, .10
    }

    #[test]
    fn one_in_memory_lease_per_endpoint() {
        let mut a = assigner(None);
        let now = t0();
        let p = peer(9);
        let ra = alloc(&mut a, NODE_A, Ipv4Addr::UNSPECIFIED, p, now);
        let rb = alloc(&mut a, NODE_B, Ipv4Addr::UNSPECIFIED, p, now);
        assert_eq!(a.node_for_peer(p), Some(NODE_B));
        assert!(a.lease(NODE_A).is_some());
        assert_ne!(ra.tun_ip, rb.tun_ip);
        assert_eq!(a.by_peer.len(), 1);
    }

    #[test]
    fn ipv6_embed_of_10_9_0_37() {
        let prefix: Ipv6Network = "fd07:7::/64".parse().unwrap();
        let embedded: Ipv6Addr = "fd07:7::a09:25".parse().unwrap();
        assert_eq!(embed_ip4(prefix, Ipv4Addr::new(10, 9, 0, 37)), embedded);
        let mut a = assigner_full(Some(prefix), [], Duration::from_secs(60), None);
        let r = a
            .allocate(
                &req(NODE_A, Ipv4Addr::new(10, 9, 0, 37), true),
                peer(1),
                t0(),
            )
            .0;
        assert_eq!(r.status, AssignStatus::Ok);
        assert_eq!(r.tun_ip, Ipv4Addr::new(10, 9, 0, 37));
        assert_eq!(r.tun_ip6, Some(embedded));
        assert_eq!(r.plen6, 64);
        assert_eq!(a.node_for_ip6(r.tun_ip6.unwrap()), Some(NODE_A));
    }

    #[test]
    fn prefix_128_skips_v6() {
        let prefix: Ipv6Network = "fd07:7::1/128".parse().unwrap();
        let mut a = assigner_full(Some(prefix), [], Duration::from_secs(60), None);
        let r = a
            .allocate(&req(NODE_A, Ipv4Addr::UNSPECIFIED, true), peer(1), t0())
            .0;
        assert_eq!(r.status, AssignStatus::Ok);
        assert!(r.tun_ip6.is_none());
        assert_eq!(r.plen6, 0);
        assert!(!r.tun_ip.is_unspecified());
    }

    #[test]
    fn persist_round_trip_restores_ips_not_by_peer() {
        let file = TempFile::new();
        let prefix: Ipv6Network = "fd07:7::/64".parse().unwrap();
        let mut a = assigner_full(
            Some(prefix),
            [],
            Duration::from_secs(DEFAULT_ASSIGN_TTL_SECS),
            Some(file.0.clone()),
        );
        let r = a
            .allocate(
                &req(NODE_A, Ipv4Addr::new(10, 9, 0, 37), true),
                peer(54321),
                SystemTime::now(),
            )
            .0;
        assert_eq!(a.node_for_peer(peer(54321)), Some(NODE_A));
        drop(a);

        let b = assigner_full(
            Some(prefix),
            [],
            Duration::from_secs(DEFAULT_ASSIGN_TTL_SECS),
            Some(file.0.clone()),
        );
        assert_eq!(b.node_for_ip4(r.tun_ip), Some(NODE_A));
        assert_eq!(b.node_for_ip6(r.tun_ip6.unwrap()), Some(NODE_A));
        assert_eq!(b.node_for_peer(peer(54321)), None);
        assert_eq!(b.lease(NODE_A).unwrap().last_peer, Some(peer(54321)));
        assert!(b.by_peer.is_empty());
    }

    #[test]
    fn stale_last_seen_unix_dropped_on_load() {
        let file = TempFile::new();
        let body = serde_json::json!({
            "version": 1,
            "leases": [{
                "node_id": "c0ffee00-0000-4000-8000-000000000001",
                "ip4": "10.9.0.37",
                "ip6": "fd07:7::a09:25",
                "last_seen_unix": 1,
                "last_peer": "203.0.113.9:54321"
            }]
        });
        std::fs::write(&file.0, body.to_string()).unwrap();
        let a = assigner(Some(file.0.clone()));
        assert!(a.lease(NODE_A).is_none());
        assert!(a.node_for_ip4(Ipv4Addr::new(10, 9, 0, 37)).is_none());
    }

    #[test]
    fn ttl_quarter_write_updates_last_seen() {
        let file = TempFile::new();
        let ttl = Duration::from_secs(8);
        let mut a = assigner_full(None, [], ttl, Some(file.0.clone()));
        // Truncate to whole seconds: persist stores last_seen_unix.
        let start = from_unix(to_unix(SystemTime::now())).expect("now fits in SystemTime");
        alloc(&mut a, NODE_A, Ipv4Addr::UNSPECIFIED, peer(1), start);
        let loaded = |path: &Path| {
            assigner_full(None, [], ttl, Some(path.to_path_buf()))
                .lease(NODE_A)
                .unwrap()
                .last_seen
        };
        assert_eq!(loaded(&file.0), start);

        alloc(
            &mut a,
            NODE_A,
            Ipv4Addr::UNSPECIFIED,
            peer(1),
            start + Duration::from_secs(1),
        );
        assert_eq!(loaded(&file.0), start);

        alloc(
            &mut a,
            NODE_A,
            Ipv4Addr::UNSPECIFIED,
            peer(1),
            start + Duration::from_secs(2),
        );
        assert_eq!(loaded(&file.0), start + Duration::from_secs(2));
    }

    #[test]
    fn corrupt_lease_file_quarantined() {
        let file = TempFile::new();
        std::fs::write(&file.0, b"not-json").unwrap();
        let a = assigner(Some(file.0.clone()));
        assert_eq!(a.leased(), 0);
        let mut bad = file.0.as_os_str().to_os_string();
        bad.push(".bad");
        assert!(PathBuf::from(&bad).exists());
        assert!(!file.0.exists());
    }

    #[test]
    fn reply_uses_server_netmask_and_server_ip_as_peer() {
        let mut a = assigner(None);
        let r = alloc(&mut a, NODE_A, Ipv4Addr::UNSPECIFIED, peer(1), t0());
        assert_eq!(r.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(r.peer_ip, Ipv4Addr::new(10, 9, 0, 1));
        assert_eq!(r.flags, 0);
        assert_eq!(r.ttl_secs, DEFAULT_ASSIGN_TTL_SECS as u32);
    }

    #[test]
    fn refresh_does_not_unbind_foreign_peer() {
        let file = TempFile::new();
        let now_unix = to_unix(SystemTime::now());
        let body = serde_json::json!({
            "version": 1,
            "leases": [{
                "node_id": "c0ffee00-0000-4000-8000-000000000001",
                "ip4": "10.9.0.37",
                "last_seen_unix": now_unix,
                "last_peer": "203.0.113.9:1234"
            }]
        });
        std::fs::write(&file.0, body.to_string()).unwrap();
        let mut a = assigner(Some(file.0.clone()));
        assert_eq!(a.node_for_peer(peer(1234)), None);

        let now = SystemTime::now();
        alloc(&mut a, NODE_B, Ipv4Addr::UNSPECIFIED, peer(1234), now);
        assert_eq!(a.node_for_peer(peer(1234)), Some(NODE_B));

        alloc(&mut a, NODE_A, Ipv4Addr::UNSPECIFIED, peer(5678), now);
        assert_eq!(a.node_for_peer(peer(1234)), Some(NODE_B));
        assert_eq!(a.node_for_peer(peer(5678)), Some(NODE_A));
    }

    #[test]
    fn allocate_surfaces_reaped_and_reclaimed() {
        let ttl = Duration::from_secs(10);
        let mut a = assigner_full(None, [], ttl, None);
        alloc(&mut a, NODE_A, Ipv4Addr::UNSPECIFIED, peer(1), t0());
        let (_reply, expired) = a.allocate(
            &req(NODE_B, Ipv4Addr::UNSPECIFIED, false),
            peer(2),
            t0() + Duration::from_secs(11),
        );
        assert!(expired.iter().any(|l| l.node_id == NODE_A));

        let mut b = assigner(None);
        let only = Ipv4Addr::new(10, 9, 0, 10);
        b.set_host_range(u32::from(only), u32::from(only));
        alloc(&mut b, NODE_A, only, peer(1), t0());
        let (reply, reclaimed) = b.allocate(&req(NODE_B, only, false), peer(2), t0());
        assert_eq!(reply.status, AssignStatus::Ok);
        assert_eq!(reply.tun_ip, only);
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].node_id, NODE_A);
    }

    #[test]
    fn huge_last_seen_unix_does_not_panic() {
        let file = TempFile::new();
        let body = serde_json::json!({
            "version": 1,
            "leases": [{
                "node_id": "c0ffee00-0000-4000-8000-000000000001",
                "ip4": "10.9.0.37",
                "last_seen_unix": u64::MAX,
                "last_peer": "203.0.113.9:54321"
            }]
        });
        std::fs::write(&file.0, body.to_string()).unwrap();
        let a = assigner(Some(file.0.clone()));
        if from_unix(u64::MAX).is_none() {
            assert!(a.lease(NODE_A).is_none());
        }
    }
}
