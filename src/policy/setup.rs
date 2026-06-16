//! Linux ipset + policy-routing wiring (the side-effectful half).
//!
//! This mirrors the classic dnsmasq/ipset routing recipe, driven from Rust by
//! shelling out to `ipset`, `ip`, and `iptables` (so there is no heavyweight
//! netlink dependency). [`PolicyRouting::install`] sets everything up and the
//! returned guard tears it all down again on drop:
//!
//! ```text
//! ipset create  <set> hash:net family inet         # the tunnel-routed set
//! ip rule add   fwmark <mark> table <table>         # marked traffic -> our table
//! ip route add  default via <peer> dev <tun> table <table>
//! iptables -t mangle -A OUTPUT/PREROUTING -m set --match-set <set> dst \
//!          -j MARK --set-mark <mark>                # mark dst-in-set packets
//! ```
//!
//! The DNS proxy then adds addresses to `<set>` (via [`CommandIpSet`]), and the
//! kernel routes anything destined for them through the tunnel. Only this
//! dedicated table is touched — the main routing table and default route are
//! left alone — so the change is contained and fully reversible.
//!
//! All of this needs root and is Linux-only; the module is compiled only on
//! Linux.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{bail, Result};
use log::{debug, info, warn};

use super::proxy::IpSink;

/// An [`IpSink`] that adds addresses to a kernel ipset via `ipset add`.
pub struct CommandIpSet {
    set: String,
}

impl CommandIpSet {
    /// Create a sink targeting the named ipset (which must already exist).
    pub fn new(set: impl Into<String>) -> Self {
        Self { set: set.into() }
    }
}

impl IpSink for CommandIpSet {
    fn add(&self, ip: Ipv4Addr) {
        // `-exist` makes re-adding an address a no-op instead of an error.
        let status = Command::new("ipset")
            .args(["add", "-exist", &self.set, &ip.to_string()])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => warn!("ipset add {} {ip} exited with {s}", self.set),
            Err(e) => warn!("failed to run ipset add {} {ip}: {e}", self.set),
        }
    }
}

/// Installed policy routing; drops back to a clean state when this guard is
/// dropped.
pub struct PolicyRouting {
    set: String,
    table: u32,
    fwmark: u32,
    tun: String,
}

impl PolicyRouting {
    /// Install the ipset, routing rule, dedicated default route, and the mangle
    /// marking rules. `extra_ips` are seeded into the set immediately (used to
    /// route the clean DNS upstream through the tunnel from the start).
    pub fn install(
        set: &str,
        table: u32,
        fwmark: u32,
        tun_name: &str,
        peer_ip: Ipv4Addr,
        extra_ips: &[Ipv4Addr],
    ) -> Result<Self> {
        let mark = format!("0x{fwmark:x}");
        let table_s = table.to_string();

        // ipset: create fresh and empty.
        run(
            "ipset",
            &["create", "-exist", set, "hash:net", "family", "inet"],
        )?;
        run("ipset", &["flush", set])?;
        for ip in extra_ips {
            run("ipset", &["add", "-exist", set, &ip.to_string()])?;
        }

        // ip rule: marked packets consult our dedicated table.
        // Delete any stale copy first so install is idempotent.
        run_ok("ip", &["rule", "del", "fwmark", &mark, "table", &table_s]);
        run("ip", &["rule", "add", "fwmark", &mark, "table", &table_s])?;

        // That table's default route points into the tunnel.
        run(
            "ip",
            &[
                "route",
                "replace",
                "default",
                "via",
                &peer_ip.to_string(),
                "dev",
                tun_name,
                "table",
                &table_s,
            ],
        )?;

        // mangle: mark every packet whose destination is in the set. OUTPUT
        // covers this host's own traffic; PREROUTING covers anything it forwards.
        for chain in ["OUTPUT", "PREROUTING"] {
            run(
                "iptables",
                &[
                    "-t",
                    "mangle",
                    "-A",
                    chain,
                    "-m",
                    "set",
                    "--match-set",
                    set,
                    "dst",
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            )?;
        }

        // nat: masquerade everything leaving the tunnel so it is sourced from
        // the tun address. For *locally generated* marked traffic the source is
        // chosen from the main table (the LAN address) before the mark reroutes
        // it onto tun0; without this the server's `-s <tun-subnet>` masquerade
        // would not match and the packet would carry the wrong source.
        run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                tun_name,
                "-j",
                "MASQUERADE",
            ],
        )?;

        info!(
            "policy routing installed: ipset={set} table={table} fwmark={mark} -> via {peer_ip} dev {tun_name}"
        );
        Ok(Self {
            set: set.to_string(),
            table,
            fwmark,
            tun: tun_name.to_string(),
        })
    }

    /// Reverse every change made by [`install`](Self::install). Best-effort:
    /// each step logs but does not abort the others.
    fn teardown(&self) {
        let mark = format!("0x{:x}", self.fwmark);
        let table_s = self.table.to_string();

        for chain in ["OUTPUT", "PREROUTING"] {
            run_ok(
                "iptables",
                &[
                    "-t",
                    "mangle",
                    "-D",
                    chain,
                    "-m",
                    "set",
                    "--match-set",
                    &self.set,
                    "dst",
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            );
        }
        run_ok(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                &self.tun,
                "-j",
                "MASQUERADE",
            ],
        );
        run_ok("ip", &["route", "flush", "table", &table_s]);
        run_ok("ip", &["rule", "del", "fwmark", &mark, "table", &table_s]);
        run_ok("ipset", &["flush", &self.set]);
        run_ok("ipset", &["destroy", &self.set]);
        info!(
            "policy routing torn down (ipset={}, table={})",
            self.set, self.table
        );
    }
}

impl Drop for PolicyRouting {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Run a command, returning an error if it cannot start or exits non-zero.
fn run(cmd: &str, args: &[&str]) -> Result<()> {
    debug!("exec: {cmd} {}", args.join(" "));
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `{cmd}` (is it installed?): {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("`{cmd} {}` failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// Run a command for its side effect, ignoring failure (used for idempotent
/// deletes and best-effort teardown).
fn run_ok(cmd: &str, args: &[&str]) {
    debug!("exec (ignore-fail): {cmd} {}", args.join(" "));
    if let Err(e) = Command::new(cmd).args(args).output() {
        debug!("`{cmd}` not run: {e}");
    }
}
