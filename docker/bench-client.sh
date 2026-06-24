#!/bin/sh
# Client side of the ShadowVPN netem benchmark.
#
# Emulates the same internet path on its WAN, brings up the ShadowVPN client,
# waits for the tunnel, then measures latency and TCP/UDP throughput both
# *through the tunnel* (-> 10.9.0.1 over tun0) and *directly* over the WAN (->
# the server container) as a baseline. Because both paths cross the same netem
# qdisc, the gap between them is ShadowVPN's own overhead (crypto + obfs + MTU).
#
# Prints a summary table and exits 0 on success so compose's
# `--exit-code-from client` turns the run into a pass/fail.
set -eu

. /usr/local/bin/bench-lib.sh

TUNNEL_PEER=10.9.0.1            # server's in-tunnel address
BASELINE_HOST="${SERVER_HOST:-server}"  # server's WAN address (docker DNS)
DURATION="${DURATION:-10}"     # seconds per iperf3 stream
UDP_RATE="${UDP_RATE:-50M}"    # offered load for the UDP test
PING_COUNT="${PING_COUNT:-20}"

WAN="$(wan_iface)"
apply_netem "$WAN"

write_config /run/client.json client

echo "[client] starting shadowvpn-client"
shadowvpn-client -c /run/client.json &
CLIENT_PID=$!
trap 'kill "$CLIENT_PID" 2>/dev/null || true' EXIT

# Wait for the tunnel to carry a round-trip, bailing out if the client dies.
connected=0
i=1
while [ "$i" -le 40 ]; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "[client] FAIL: shadowvpn-client exited during startup" >&2
        exit 1
    fi
    if ping -c 1 -W 1 "$TUNNEL_PEER" >/dev/null 2>&1; then
        connected=1
        break
    fi
    i=$((i + 1))
    sleep 0.5
done
if [ "$connected" -ne 1 ]; then
    echo "[client] FAIL: tunnel never came up (no reply from $TUNNEL_PEER)" >&2
    exit 1
fi
echo "[client] tunnel is up; starting measurements"

# --- measurement helpers ----------------------------------------------------

# Mean RTT in ms from a ping burst (rtt min/avg/max/mdev line), or "n/a".
ping_avg() {
    out="$(ping -c "$PING_COUNT" -i 0.2 -W 2 "$1" 2>/dev/null | tail -1)"
    echo "$out" | awk -F'/' 'NF>=5 {printf "%.1f", $5; found=1} END{if(!found) printf "n/a"}'
}

# TCP throughput in Mbit/s, receiver side. $2="-R" requests the download
# direction (server -> client). Empty/failed runs yield "n/a".
tcp_mbps() {
    json="$(iperf3 -c "$1" -t "$DURATION" -J ${2:-} 2>/dev/null || true)"
    bps="$(printf '%s' "$json" | jq -r '.end.sum_received.bits_per_second // empty' 2>/dev/null || true)"
    [ -n "$bps" ] && awk -v b="$bps" 'BEGIN{printf "%.1f", b/1e6}' || echo "n/a"
}

# UDP throughput (Mbit/s) and loss (%) at the offered UDP_RATE, as "MBPS LOSS".
udp_stats() {
    json="$(iperf3 -c "$1" -u -b "$UDP_RATE" -t "$DURATION" -J 2>/dev/null || true)"
    bps="$(printf '%s' "$json" | jq -r '.end.sum.bits_per_second // empty' 2>/dev/null || true)"
    loss="$(printf '%s' "$json" | jq -r '.end.sum.lost_percent // empty' 2>/dev/null || true)"
    if [ -n "$bps" ] && [ -n "$loss" ]; then
        awk -v b="$bps" -v l="$loss" 'BEGIN{printf "%.1f %.2f", b/1e6, l}'
    else
        echo "n/a n/a"
    fi
}

# --- run the matrix ---------------------------------------------------------

echo "[client] latency..."
RTT_TUN="$(ping_avg "$TUNNEL_PEER")"
RTT_BASE="$(ping_avg "$BASELINE_HOST")"

echo "[client] TCP upload (tunnel / baseline)..."
TCP_UP_TUN="$(tcp_mbps "$TUNNEL_PEER")"
TCP_UP_BASE="$(tcp_mbps "$BASELINE_HOST")"

echo "[client] TCP download (tunnel / baseline)..."
TCP_DN_TUN="$(tcp_mbps "$TUNNEL_PEER" -R)"
TCP_DN_BASE="$(tcp_mbps "$BASELINE_HOST" -R)"

echo "[client] UDP (tunnel / baseline) at offered ${UDP_RATE}..."
UDP_TUN="$(udp_stats "$TUNNEL_PEER")"
UDP_BASE="$(udp_stats "$BASELINE_HOST")"
UDP_TUN_MBPS="${UDP_TUN% *}"; UDP_TUN_LOSS="${UDP_TUN#* }"
UDP_BASE_MBPS="${UDP_BASE% *}"; UDP_BASE_LOSS="${UDP_BASE#* }"

# --- summary ----------------------------------------------------------------
cat <<EOF

============================================================================
 ShadowVPN benchmark — cipher=${CIPHER:-chacha20-poly1305} obfs=${OBFS:-none} mtu=${MTU:-1400}
 emulated WAN: delay=${DELAY:-20ms} jitter=${JITTER:-0} loss=${LOSS:-0} rate=${RATE:-unlimited}
 (each side applies netem, so RTT ~ 2x delay; ${DURATION}s per stream)
============================================================================
 Metric                       Tunnel        Direct(WAN)
 ---------------------------------------------------------------------------
 RTT (ms)                     ${RTT_TUN}            ${RTT_BASE}
 TCP upload   (Mbit/s)        ${TCP_UP_TUN}            ${TCP_UP_BASE}
 TCP download (Mbit/s)        ${TCP_DN_TUN}            ${TCP_DN_BASE}
 UDP @ ${UDP_RATE} (Mbit/s)         ${UDP_TUN_MBPS}            ${UDP_BASE_MBPS}
 UDP loss (%)                 ${UDP_TUN_LOSS}            ${UDP_BASE_LOSS}
============================================================================

EOF

# Treat the run as a pass if the tunnel moved real TCP traffic in both
# directions; the absolute numbers are informational.
if [ "$TCP_UP_TUN" = "n/a" ] || [ "$TCP_DN_TUN" = "n/a" ]; then
    echo "[client] FAIL: tunnel throughput measurement did not complete" >&2
    exit 1
fi
echo "[client] PASS"
exit 0
