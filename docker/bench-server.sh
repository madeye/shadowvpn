#!/bin/sh
# Server side of the ShadowVPN netem benchmark.
#
# Emulates a real internet path on the WAN (the encrypted carrier), brings up the
# ShadowVPN server, and runs an iperf3 server. iperf3 listens on 0.0.0.0, so the
# same instance serves both the through-tunnel test (client -> 10.9.0.1 over
# tun0) and the direct baseline (client -> this container's WAN IP).
set -eu

. /usr/local/bin/bench-lib.sh

WAN="$(wan_iface)"
apply_netem "$WAN"

write_config /run/server.json server

echo "[server] starting shadowvpn-server"
shadowvpn-server -c /run/server.json &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

# Give the server a moment to create tun0 before iperf3 starts accepting.
i=1
while [ "$i" -le 10 ]; do
    if ip link show tun0 >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 0.5
done

echo "[server] tun0 up; starting iperf3 server (foreground)"
# iperf3 in the foreground keeps the container alive for the client's test run.
exec iperf3 --server --interval 0
