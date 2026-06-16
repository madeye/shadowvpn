//! User-mode policy routing: program per-destination routes into the tun device.
//!
//! This replaces the Linux-only ipset + nft + fwmark machinery with a small,
//! cross-platform router. As the split-DNS [`proxy`](super::proxy) decides a name
//! should be tunneled, it hands each resolved address to [`TunRouter`], which
//! installs a host route (`<ip>/32`) whose output device is the tun interface.
//! The kernel then sends matching traffic into the tunnel — and, because the
//! route's output device is the tun, picks the tun's address as the source, so
//! the server's masquerade matches with no client-side NAT.
//!
//! Direct (non-tunneled) traffic is never touched: it stays on the normal kernel
//! path, so no user-mode NAT or packet capture is needed. Only the routing table
//! is modified, and only for addresses we explicitly tunnel.
//!
//! Routes are programmed with the OS's native routing socket — `rtnetlink` on
//! Linux, `PF_ROUTE` on macOS/BSD — so there is no dependency on `ip`, `ipset`,
//! `iptables`, or `route`. Every address added is tracked and removed again when
//! the [`RouteGuard`] is dropped.

use std::collections::HashSet;
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use log::{debug, warn};

use super::proxy::IpSink;

/// Adds and removes `<ip>/32` routes pointing at the tun device.
pub struct TunRouter {
    /// Interface index of the tun device.
    ifindex: u32,
    /// The tun's local address, used as the route's preferred source.
    tun_ip: Ipv4Addr,
    /// Every address we have installed a route for (for cleanup + dedup).
    added: Mutex<HashSet<Ipv4Addr>>,
}

impl TunRouter {
    /// Resolve the tun interface index and build a router for it.
    pub fn new(tun_name: &str, tun_ip: Ipv4Addr) -> io::Result<Self> {
        let cname = CString::new(tun_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tun name has a NUL byte"))?;
        // SAFETY: `cname` is a valid NUL-terminated C string for the call.
        let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ifindex,
            tun_ip,
            added: Mutex::new(HashSet::new()),
        })
    }

    /// Install a route for `ip` if we have not already, recording it for cleanup.
    pub fn add_route(&self, ip: Ipv4Addr) -> io::Result<()> {
        {
            let mut set = self.added.lock().unwrap();
            if !set.insert(ip) {
                return Ok(()); // already routed
            }
        }
        imp::modify_route(self.ifindex, self.tun_ip, ip, true)
    }

    /// Remove every route we installed. Best-effort: logs failures, continues.
    pub fn delete_all(&self) {
        let ips: Vec<Ipv4Addr> = {
            let mut set = self.added.lock().unwrap();
            set.drain().collect()
        };
        for ip in ips {
            if let Err(e) = imp::modify_route(self.ifindex, self.tun_ip, ip, false) {
                debug!("failed to delete route {ip}/32: {e}");
            }
        }
    }
}

impl IpSink for TunRouter {
    fn add(&self, ip: Ipv4Addr) {
        if let Err(e) = self.add_route(ip) {
            warn!("failed to add tunnel route {ip}/32: {e}");
        }
    }
}

/// Drop guard that removes all installed routes when the client exits.
///
/// Held separately from the [`IpSink`] handed to the proxy so that teardown runs
/// as soon as the client's run loop returns, even though the (possibly detached)
/// proxy task may still hold a reference to the same [`TunRouter`].
pub struct RouteGuard {
    router: std::sync::Arc<TunRouter>,
}

impl RouteGuard {
    /// Wrap a router so its routes are cleaned up on drop.
    pub fn new(router: std::sync::Arc<TunRouter>) -> Self {
        Self { router }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.router.delete_all();
    }
}

// ---------------------------------------------------------------------------
// Linux: rtnetlink over a raw AF_NETLINK socket.
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // rtnetlink message-type and flag constants (from <linux/netlink.h> and
    // <linux/rtnetlink.h>); taken via libc where available.
    const NLMSG_ERROR: u16 = 2;

    /// Add (or delete) a `dst/32` route via the tun interface.
    pub fn modify_route(
        ifindex: u32,
        tun_ip: Ipv4Addr,
        dst: Ipv4Addr,
        add: bool,
    ) -> io::Result<()> {
        let msg = build_request(1, add, ifindex, tun_ip, dst);

        // SAFETY: a straightforward socket()/send()/recv() sequence; all buffers
        // and the destination sockaddr are valid for the duration of each call.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);

            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            let sent = libc::sendto(
                fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut buf = [0u8; 4096];
            let n = libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            parse_ack(&buf[..n as usize])
        }
    }

    /// Parse a netlink ACK: an `NLMSG_ERROR` with `error == 0` means success.
    fn parse_ack(buf: &[u8]) -> io::Result<()> {
        // nlmsghdr is 16 bytes; nlmsgerr starts with an i32 error code.
        if buf.len() < 20 {
            return Ok(()); // no error payload -> treat as success
        }
        let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if nlmsg_type != NLMSG_ERROR {
            return Ok(());
        }
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if err == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(-err))
        }
    }

    /// Serialize an `RTM_NEWROUTE`/`RTM_DELROUTE` request for a `dst/32` route.
    fn build_request(
        seq: u32,
        add: bool,
        ifindex: u32,
        tun_ip: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Vec<u8> {
        const NLM_F_REQUEST: u16 = 0x01;
        const NLM_F_ACK: u16 = 0x04;
        const NLM_F_CREATE: u16 = 0x400;
        const NLM_F_REPLACE: u16 = 0x100;
        const RTM_NEWROUTE: u16 = 24;
        const RTM_DELROUTE: u16 = 25;
        const RT_TABLE_MAIN: u8 = 254;
        const RTPROT_STATIC: u8 = 4;
        const RT_SCOPE_LINK: u8 = 253;
        const RTN_UNICAST: u8 = 1;
        const RTA_DST: u16 = 1;
        const RTA_OIF: u16 = 4;
        const RTA_PREFSRC: u16 = 7;

        let mut attrs = Vec::new();
        push_attr(&mut attrs, RTA_DST, &dst.octets());
        push_attr(&mut attrs, RTA_OIF, &ifindex.to_ne_bytes());
        if add {
            push_attr(&mut attrs, RTA_PREFSRC, &tun_ip.octets());
        }

        // nlmsghdr(16) + rtmsg(12) + attrs.
        let total = 16 + 12 + attrs.len();
        let mut buf = Vec::with_capacity(total);

        // nlmsghdr.
        buf.extend_from_slice(&(total as u32).to_ne_bytes());
        buf.extend_from_slice(&(if add { RTM_NEWROUTE } else { RTM_DELROUTE }).to_ne_bytes());
        let mut flags = NLM_F_REQUEST | NLM_F_ACK;
        if add {
            flags |= NLM_F_CREATE | NLM_F_REPLACE;
        }
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel picks)

        // rtmsg.
        buf.push(libc::AF_INET as u8); // rtm_family
        buf.push(32); // rtm_dst_len (/32)
        buf.push(0); // rtm_src_len
        buf.push(0); // rtm_tos
        buf.push(RT_TABLE_MAIN); // rtm_table
        buf.push(if add { RTPROT_STATIC } else { 0 }); // rtm_protocol
        buf.push(if add { RT_SCOPE_LINK } else { 0 }); // rtm_scope
        buf.push(if add { RTN_UNICAST } else { 0 }); // rtm_type
        buf.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags

        buf.extend_from_slice(&attrs);
        buf
    }

    /// Append one rtattr (header + data) padded to a 4-byte boundary.
    fn push_attr(buf: &mut Vec<u8>, atype: u16, data: &[u8]) {
        let len = 4 + data.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(data);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn add_request_has_expected_header_and_attrs() {
            let dst = Ipv4Addr::new(1, 2, 3, 4);
            let src = Ipv4Addr::new(10, 9, 0, 2);
            let m = build_request(7, true, 12, src, dst);

            // nlmsg_len == buffer length; type == RTM_NEWROUTE(24).
            assert_eq!(
                u32::from_ne_bytes([m[0], m[1], m[2], m[3]]) as usize,
                m.len()
            );
            assert_eq!(u16::from_ne_bytes([m[4], m[5]]), 24);
            // rtm_family == AF_INET, rtm_dst_len == 32 (right after the 16-byte header).
            assert_eq!(m[16], libc::AF_INET as u8);
            assert_eq!(m[17], 32);
            // Three attributes present (DST + OIF + PREFSRC), so the dst octets appear.
            assert!(m.windows(4).any(|w| w == dst.octets()));
            assert!(m.windows(4).any(|w| w == src.octets()));
        }

        #[test]
        fn del_request_is_delroute_without_prefsrc() {
            let m = build_request(
                1,
                false,
                5,
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(8, 8, 8, 8),
            );
            assert_eq!(u16::from_ne_bytes([m[4], m[5]]), 25); // RTM_DELROUTE
                                                              // DST + OIF only: header(16) + rtmsg(12) + 2*(4+4) = 44.
            assert_eq!(m.len(), 44);
        }

        #[test]
        fn parse_ack_maps_error_code() {
            // Build a minimal NLMSG_ERROR with error == 0 (ack) then -1 (EPERM-ish).
            let mut ok = vec![0u8; 20];
            ok[4] = 2; // NLMSG_ERROR
            assert!(parse_ack(&ok).is_ok());

            let mut err = vec![0u8; 20];
            err[4] = 2;
            err[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
            assert!(parse_ack(&err).is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// macOS / BSD: routing messages over a raw PF_ROUTE socket.
// ---------------------------------------------------------------------------
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// Add (or delete) a host route to `dst` via the tun interface.
    pub fn modify_route(
        ifindex: u32,
        tun_ip: Ipv4Addr,
        dst: Ipv4Addr,
        add: bool,
    ) -> io::Result<()> {
        let _ = tun_ip; // the interface route picks the tun's source itself
        let msg = build_message(add, ifindex, dst);

        // SAFETY: socket()/write() with a correctly sized routing message; the
        // buffer outlives the call.
        unsafe {
            let fd = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let written = libc::write(
                fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
            );
            if written < 0 {
                let err = io::Error::last_os_error();
                // Deleting a route that is already gone is not a real failure.
                if !add && err.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(());
                }
                // Re-adding an existing route returns EEXIST; treat as success.
                if add && err.raw_os_error() == Some(libc::EEXIST) {
                    return Ok(());
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Build an `RTM_ADD`/`RTM_DELETE` message: dst (sockaddr_in), gateway
    /// (sockaddr_dl carrying the interface index), netmask (sockaddr_in /32).
    fn build_message(add: bool, ifindex: u32, dst: Ipv4Addr) -> Vec<u8> {
        const RTM_ADD: u8 = 0x1;
        const RTM_DELETE: u8 = 0x2;
        const RTM_VERSION: u8 = 5;
        const RTF_UP: i32 = 0x1;
        const RTF_HOST: i32 = 0x4;
        const RTF_STATIC: i32 = 0x800;
        const RTA_DST: i32 = 0x1;
        const RTA_GATEWAY: i32 = 0x2;
        const RTA_NETMASK: i32 = 0x4;

        let hdr_len = std::mem::size_of::<libc::rt_msghdr>();

        let sa_dst = sockaddr_in_bytes(dst);
        let sa_gw = sockaddr_dl_bytes(ifindex);
        let sa_mask = sockaddr_in_bytes(Ipv4Addr::new(255, 255, 255, 255));

        let total = hdr_len + sa_dst.len() + sa_gw.len() + sa_mask.len();

        // SAFETY: zeroed rt_msghdr is a valid all-fields-zero struct; we then set
        // the fields we need before serializing it to bytes.
        let mut hdr: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        hdr.rtm_msglen = total as u16;
        hdr.rtm_version = RTM_VERSION;
        hdr.rtm_type = if add { RTM_ADD } else { RTM_DELETE };
        hdr.rtm_index = ifindex as u16;
        hdr.rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC;
        hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        hdr.rtm_seq = 1;
        hdr.rtm_pid = 0;

        let mut buf = Vec::with_capacity(total);
        // SAFETY: read the header's bytes; rt_msghdr is plain old data.
        let hdr_bytes =
            unsafe { std::slice::from_raw_parts(&hdr as *const _ as *const u8, hdr_len) };
        buf.extend_from_slice(hdr_bytes);
        buf.extend_from_slice(&sa_dst);
        buf.extend_from_slice(&sa_gw);
        buf.extend_from_slice(&sa_mask);
        buf
    }

    /// A `sockaddr_in` for `ip`, padded to the routing-socket alignment.
    fn sockaddr_in_bytes(ip: Ipv4Addr) -> Vec<u8> {
        // SAFETY: zeroed sockaddr_in is valid; we fill the fields we need.
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        sa.sin_family = libc::AF_INET as u8;
        sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &sa as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        };
        round_up(bytes)
    }

    /// A link-level `sockaddr_dl` carrying only the interface index.
    fn sockaddr_dl_bytes(ifindex: u32) -> Vec<u8> {
        // SAFETY: zeroed sockaddr_dl is valid; we fill family/len/index.
        let mut sa: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
        sa.sdl_len = std::mem::size_of::<libc::sockaddr_dl>() as u8;
        sa.sdl_family = libc::AF_LINK as u8;
        sa.sdl_index = ifindex as u16;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &sa as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_dl>(),
            )
        };
        round_up(bytes)
    }

    /// Pad a sockaddr to the routing socket's 4-byte rounding (min 4 bytes).
    fn round_up(bytes: &[u8]) -> Vec<u8> {
        let len = bytes.len().max(1);
        let padded = len.div_ceil(4) * 4;
        let mut v = bytes.to_vec();
        v.resize(padded, 0);
        v
    }
}

// ---------------------------------------------------------------------------
// Other platforms: policy routing is unsupported.
// ---------------------------------------------------------------------------
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
mod imp {
    use super::*;

    pub fn modify_route(
        _ifindex: u32,
        _tun_ip: Ipv4Addr,
        _dst: Ipv4Addr,
        _add: bool,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "policy routing is not supported on this platform",
        ))
    }
}
