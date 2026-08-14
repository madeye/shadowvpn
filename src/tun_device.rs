//! A thin async wrapper around the [`tun-rs`](https://crates.io/crates/tun-rs)
//! TUN device, exposing whole-IP-packet async read/write.
//!
//! ShadowVPN treats the TUN device as a stream of IP packets: each
//! [`TunDevice::recv`] returns exactly one IP packet read from the kernel, and
//! each [`TunDevice::send`] writes exactly one IP packet. This matches the
//! tunnel framing in [`crate::protocol`], where one IP packet maps to one UDP
//! datagram.
//!
//! The wrapper is cross-platform: it builds and runs on macOS (utun) and Linux
//! via `tun-rs`'s `async_tokio` backend.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{debug, warn};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::config::TunConfig;

/// An async TUN interface that reads and writes whole IP packets.
///
/// Create one with [`TunDevice::create`] (static address) or
/// [`TunDevice::create_unaddressed`] (auto-assign). The device is closed when
/// dropped.
pub struct TunDevice {
    inner: AsyncDevice,
    /// Last IPv6 this wrapper programmed, so apply can remove it.
    programmed_ip6: Mutex<Option<IpAddr>>,
}

impl TunDevice {
    /// Create and bring up a TUN interface from the given [`TunConfig`].
    ///
    /// Applies the configured name (if any), IPv4 address + netmask, MTU, and
    /// point-to-point peer (destination) address. Returns an error if the
    /// interface cannot be created (commonly: insufficient privileges — TUN
    /// creation requires root on Linux and elevated rights on macOS).
    ///
    /// Static clients only. Records `cfg.ip6` so a later
    /// [`Self::apply_assignment`] can remove it before adding a new one.
    pub fn create(cfg: &TunConfig) -> std::io::Result<Self> {
        let mut builder = DeviceBuilder::new()
            .mtu(cfg.mtu)
            // Point-to-point: address + netmask, with the peer as destination.
            .ipv4(cfg.ip, cfg.netmask, Some(cfg.peer_ip));

        // Optional IPv6 (mesh routing): one shared ULA prefix across the
        // tunnel gives IPv6 subnet routes an in-tunnel source/return address.
        if let Some(ip6) = cfg.ip6 {
            builder = builder.ipv6(ip6.ip(), ip6.prefix());
        }

        if let Some(name) = &cfg.name {
            builder = builder.name(name.clone());
        }

        let inner = builder.build_async()?;
        Ok(Self {
            inner,
            programmed_ip6: Mutex::new(cfg.ip6.map(|n| n.ip().into())),
        })
    }

    /// Create a TUN with only a name and MTU, leaving addresses unset.
    ///
    /// Auto-assign clients apply the server's assignment afterwards via
    /// [`Self::apply_assignment`].
    pub fn create_unaddressed(name: Option<&str>, mtu: u16) -> std::io::Result<Self> {
        let mut builder = DeviceBuilder::new().mtu(mtu);
        if let Some(name) = name {
            builder = builder.name(name);
        }
        let inner = builder.build_async()?;
        Ok(Self {
            inner,
            programmed_ip6: Mutex::new(None),
        })
    }

    /// Program IPv4 (and optional IPv6) onto an existing TUN.
    ///
    /// On Windows the point-to-point destination is omitted: tun-rs treats it
    /// as a default-route gateway, which would install `0.0.0.0/0` via Wintun.
    pub fn apply_assignment(
        &self,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        peer: Ipv4Addr,
        ip6: Option<Ipv6Network>,
    ) -> std::io::Result<()> {
        self.inner
            .set_network_address(ip, netmask, assignment_destination(peer))?;

        if let Some(old) = peek_programmed_ip6(&self.programmed_ip6) {
            forget_if_removed(&self.programmed_ip6, self.inner.remove_address(old))?;
        }
        if let Some(n) = ip6 {
            self.inner.add_address_v6(n.ip(), n.prefix())?;
            record_programmed_ip6(&self.programmed_ip6, n.ip());
        }
        Ok(())
    }

    /// Read a single IP packet from the interface into `buf`.
    ///
    /// Returns the number of bytes read; `buf` must be large enough to hold the
    /// largest expected packet (see [`crate::protocol::MAX_IP_PACKET`]). Excess
    /// bytes of an over-long packet may be discarded by the OS.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }

    /// Write a single IP packet (`packet`) to the interface.
    ///
    /// Returns the number of bytes written.
    pub async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.inner.send(packet).await
    }

    /// The OS-assigned name of the interface (e.g. `utun7`, `tun0`).
    pub fn name(&self) -> std::io::Result<String> {
        // `AsyncDevice` derefs to the platform `DeviceImpl`, which exposes
        // `name()` on all supported platforms.
        self.inner.name()
    }

    /// The interface MTU as reported by the OS.
    pub fn mtu(&self) -> std::io::Result<u16> {
        self.inner.mtu()
    }

    /// The configured local IPv4 address. Convenience accessor that simply
    /// echoes back the value the device was created with.
    pub fn local_ip(cfg: &TunConfig) -> Ipv4Addr {
        cfg.ip
    }
}

/// Windows treats `destination` as a default-route gateway (`netsh … gateway=`).
fn assignment_destination(peer: Ipv4Addr) -> Option<Ipv4Addr> {
    #[cfg(windows)]
    {
        let _ = peer;
        None
    }
    #[cfg(not(windows))]
    Some(peer)
}

fn peek_programmed_ip6(slot: &Mutex<Option<IpAddr>>) -> Option<IpAddr> {
    *slot.lock().unwrap()
}

fn take_programmed_ip6(slot: &Mutex<Option<IpAddr>>) -> Option<IpAddr> {
    slot.lock().unwrap().take()
}

fn record_programmed_ip6(slot: &Mutex<Option<IpAddr>>, ip: Ipv6Addr) {
    *slot.lock().unwrap() = Some(IpAddr::V6(ip));
}

fn address_already_gone(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::AddrNotAvailable
    ) {
        return true;
    }
    #[cfg(windows)]
    {
        // ERROR_NOT_FOUND — netsh/IP Helper when the address is already gone
        if err.raw_os_error() == Some(1168) {
            return true;
        }
    }
    false
}

/// Forget the slot only after the address is gone from the TUN, so a failed
/// remove can be retried on the next apply.
fn forget_if_removed(slot: &Mutex<Option<IpAddr>>, remove: io::Result<()>) -> io::Result<()> {
    match remove {
        Ok(()) => {
            take_programmed_ip6(slot);
            Ok(())
        }
        Err(e) if address_already_gone(&e) => {
            take_programmed_ip6(slot);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// A prefix actually installed on the TUN (network address, not a host `/32`/`/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstalledPrefix {
    dst: IpAddr,
    prefix: u8,
}

/// How to update an already-tracked connected route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrefixAction {
    /// Same prefix: leave the route; IPv4 re-add replaces Linux `PREFSRC`.
    Refresh,
    /// Missing or different prefix: delete `old` if any, then add.
    Replace { old: Option<InstalledPrefix> },
}

fn prefix_action(current: Option<InstalledPrefix>, next: InstalledPrefix) -> PrefixAction {
    match current {
        Some(old) if old == next => PrefixAction::Refresh,
        other => PrefixAction::Replace { old: other },
    }
}

fn v4_connected(assigned: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<InstalledPrefix> {
    let net = Ipv4Network::with_netmask(assigned, netmask)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(InstalledPrefix {
        dst: IpAddr::V4(net.network()),
        prefix: net.prefix(),
    })
}

fn ip6_connected(n: Ipv6Network) -> InstalledPrefix {
    InstalledPrefix {
        dst: IpAddr::V6(n.network()),
        prefix: n.prefix(),
    }
}

/// Drop-guard for the TUN's connected IPv4/IPv6 prefix routes.
///
/// macOS `associate_route` may only add a host route to the peer, so the extra
/// prefix route is still required. Linux `PREFSRC` is the assigned IPv4 and
/// must be programmed after that address exists on the TUN.
pub struct SubnetRouteGuard {
    ifindex: u32,
    tun_ip: Ipv4Addr,
    v4: Option<InstalledPrefix>,
    v6: Option<InstalledPrefix>,
}

impl SubnetRouteGuard {
    /// Resolve `tun_name` to an interface index. No routes are installed until
    /// [`Self::apply`].
    pub fn new(tun_name: &str) -> io::Result<Self> {
        Ok(Self {
            ifindex: crate::policy::route::interface_index(tun_name)?,
            tun_ip: Ipv4Addr::UNSPECIFIED,
            v4: None,
            v6: None,
        })
    }

    /// Install or refresh the connected routes for the prefixes on the TUN.
    ///
    /// Same IPv4 prefix: leave the route and replace Linux `PREFSRC`. Changed
    /// prefix: delete the old route, then add the new one. IPv6 uses the prefix
    /// actually on the TUN, not a `/128`.
    pub fn apply(
        &mut self,
        assigned_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        ip6: Option<Ipv6Network>,
    ) -> io::Result<()> {
        // PREFSRC must match the address already on the TUN.
        self.tun_ip = assigned_ip;
        self.sync_prefix(true, v4_connected(assigned_ip, netmask)?)?;
        match ip6 {
            Some(n) => self.sync_prefix(false, ip6_connected(n))?,
            None => {
                if let Some(old) = self.v6.take() {
                    self.delete_prefix(old, false);
                }
            }
        }
        Ok(())
    }

    fn sync_prefix(&mut self, is_v4: bool, next: InstalledPrefix) -> io::Result<()> {
        let current = if is_v4 { self.v4 } else { self.v6 };
        match prefix_action(current, next) {
            PrefixAction::Refresh => {
                // IPv6 has no PREFSRC; leave the existing route alone.
                if is_v4 {
                    crate::policy::route::modify_route(
                        self.ifindex,
                        self.tun_ip,
                        next.dst,
                        next.prefix,
                        true,
                    )?;
                }
            }
            PrefixAction::Replace { old } => {
                if is_v4 {
                    self.v4 = None;
                } else {
                    self.v6 = None;
                }
                if let Some(old) = old {
                    self.delete_prefix(old, false);
                }
                crate::policy::route::modify_route(
                    self.ifindex,
                    self.tun_ip,
                    next.dst,
                    next.prefix,
                    true,
                )?;
            }
        }
        if is_v4 {
            self.v4 = Some(next);
        } else {
            self.v6 = Some(next);
        }
        Ok(())
    }

    fn delete_prefix(&self, p: InstalledPrefix, on_shutdown: bool) {
        if let Err(e) =
            crate::policy::route::modify_route(self.ifindex, self.tun_ip, p.dst, p.prefix, false)
        {
            if on_shutdown {
                debug!(
                    "failed to remove subnet route {}/{} on shutdown: {e}",
                    p.dst, p.prefix
                );
            } else {
                warn!("failed to remove subnet route {}/{}: {e}", p.dst, p.prefix);
            }
        }
    }
}

impl Drop for SubnetRouteGuard {
    fn drop(&mut self) {
        if let Some(p) = self.v4.take() {
            self.delete_prefix(p, true);
        }
        if let Some(p) = self.v6.take() {
            self.delete_prefix(p, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_destination_is_not_a_windows_gateway() {
        let peer = Ipv4Addr::new(10, 9, 0, 1);
        let dest = assignment_destination(peer);
        #[cfg(windows)]
        assert_eq!(dest, None);
        #[cfg(not(windows))]
        assert_eq!(dest, Some(peer));
    }

    #[test]
    fn reapply_leaves_a_single_programmed_v6() {
        // create() records DeviceBuilder::ipv6; we cannot open a real TUN here.
        let create_v6: Ipv6Addr = "fd07:7::1".parse().unwrap();
        let first: Ipv6Network = "fd07:7::a09:25/64".parse().unwrap();
        let second: Ipv6Network = "fd07:7::a09:26/64".parse().unwrap();
        let slot = Mutex::new(Some(IpAddr::V6(create_v6)));

        let old = take_programmed_ip6(&slot);
        record_programmed_ip6(&slot, first.ip());
        assert_eq!(old, Some(IpAddr::V6(create_v6)));
        assert_eq!(*slot.lock().unwrap(), Some(IpAddr::V6(first.ip())));

        let old = take_programmed_ip6(&slot);
        record_programmed_ip6(&slot, first.ip());
        assert_eq!(old, Some(IpAddr::V6(first.ip())));
        assert_eq!(*slot.lock().unwrap(), Some(IpAddr::V6(first.ip())));

        let old = take_programmed_ip6(&slot);
        record_programmed_ip6(&slot, second.ip());
        assert_eq!(old, Some(IpAddr::V6(first.ip())));
        assert_eq!(*slot.lock().unwrap(), Some(IpAddr::V6(second.ip())));
    }

    #[test]
    fn failed_remove_keeps_programmed_ip6() {
        let ip: Ipv6Addr = "fd07:7::1".parse().unwrap();
        let slot = Mutex::new(Some(IpAddr::V6(ip)));
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "busy");
        assert!(forget_if_removed(&slot, Err(err)).is_err());
        assert_eq!(*slot.lock().unwrap(), Some(IpAddr::V6(ip)));
    }

    #[test]
    fn gone_remove_forgets_programmed_ip6() {
        let ip: Ipv6Addr = "fd07:7::1".parse().unwrap();
        let slot = Mutex::new(Some(IpAddr::V6(ip)));
        let err = io::Error::new(io::ErrorKind::NotFound, "gone");
        assert!(forget_if_removed(&slot, Err(err)).is_ok());
        assert!(slot.lock().unwrap().is_none());
    }

    #[test]
    fn unaddressed_apply_then_reapply_leaves_a_single_v6() {
        let slot = Mutex::new(None);
        let n: Ipv6Network = "fd07:7::a09:25/64".parse().unwrap();

        assert!(take_programmed_ip6(&slot).is_none());
        record_programmed_ip6(&slot, n.ip());
        assert_eq!(*slot.lock().unwrap(), Some(IpAddr::V6(n.ip())));

        let old = take_programmed_ip6(&slot);
        record_programmed_ip6(&slot, n.ip());
        assert_eq!(old, Some(IpAddr::V6(n.ip())));
        assert_eq!(*slot.lock().unwrap(), Some(IpAddr::V6(n.ip())));
    }

    #[test]
    fn v4_connected_is_the_network_not_the_host() {
        let p = v4_connected(Ipv4Addr::new(10, 9, 0, 37), Ipv4Addr::new(255, 255, 255, 0)).unwrap();
        assert_eq!(p.dst, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0)));
        assert_eq!(p.prefix, 24);
    }

    #[test]
    fn ip6_connected_is_the_prefix_not_a_host_route() {
        let n: Ipv6Network = "fd07:7::a09:25/64".parse().unwrap();
        let p = ip6_connected(n);
        assert_eq!(p.dst, IpAddr::V6("fd07:7::".parse().unwrap()));
        assert_eq!(p.prefix, 64);
    }

    #[test]
    fn same_prefix_refreshes_different_prefix_replaces() {
        let a = v4_connected(Ipv4Addr::new(10, 9, 0, 37), Ipv4Addr::new(255, 255, 255, 0)).unwrap();
        let same =
            v4_connected(Ipv4Addr::new(10, 9, 0, 38), Ipv4Addr::new(255, 255, 255, 0)).unwrap();
        let other =
            v4_connected(Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(255, 255, 255, 0)).unwrap();

        assert_eq!(prefix_action(None, a), PrefixAction::Replace { old: None });
        assert_eq!(prefix_action(Some(a), same), PrefixAction::Refresh);
        assert_eq!(
            prefix_action(Some(a), other),
            PrefixAction::Replace { old: Some(a) }
        );

        let v6a = ip6_connected("fd07:7::a09:25/64".parse().unwrap());
        let v6b = ip6_connected("fd07:7::a09:26/64".parse().unwrap());
        let v6c = ip6_connected("fd08:8::1/64".parse().unwrap());
        assert_eq!(prefix_action(Some(v6a), v6b), PrefixAction::Refresh);
        assert_eq!(
            prefix_action(Some(v6a), v6c),
            PrefixAction::Replace { old: Some(v6a) }
        );
    }
}
