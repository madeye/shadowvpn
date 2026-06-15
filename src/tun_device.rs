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

use std::net::Ipv4Addr;

use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::config::TunConfig;

/// An async TUN interface that reads and writes whole IP packets.
///
/// Create one with [`TunDevice::create`]. The device is closed when dropped.
pub struct TunDevice {
    inner: AsyncDevice,
}

impl TunDevice {
    /// Create and bring up a TUN interface from the given [`TunConfig`].
    ///
    /// Applies the configured name (if any), IPv4 address + netmask, MTU, and
    /// point-to-point peer (destination) address. Returns an error if the
    /// interface cannot be created (commonly: insufficient privileges — TUN
    /// creation requires root on Linux and elevated rights on macOS).
    pub fn create(cfg: &TunConfig) -> std::io::Result<Self> {
        let mut builder = DeviceBuilder::new()
            .mtu(cfg.mtu)
            // Point-to-point: address + netmask, with the peer as destination.
            .ipv4(cfg.ip, cfg.netmask, Some(cfg.peer_ip));

        if let Some(name) = &cfg.name {
            builder = builder.name(name.clone());
        }

        let inner = builder.build_async()?;
        Ok(Self { inner })
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
