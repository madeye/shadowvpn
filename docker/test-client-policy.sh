#!/bin/sh
# Client entry point for the policy-routing E2E test.
#
# Starts the ShadowVPN client with policy routing (mode from $MODE), points the
# system resolver at the built-in split-DNS proxy, then connects to two domains:
#
#   blocked.com -> should be TUNNELED  -> echo server sees the SERVER's address
#   safe.com    -> should go DIRECT    -> echo server sees the CLIENT's address
#
# The echo servers report the source address they observe, which is how we prove
# each domain took the intended path.
set -eu

MODE="${MODE:-gfwlist}"
SERVER_IP=172.30.0.2 # tunneled traffic is masqueraded as this
CLIENT_IP=172.30.0.3 # direct traffic keeps this source
DNS=172.30.0.4

echo "[client] starting shadowvpn-client (mode=$MODE)"
shadowvpn-client -c /etc/shadowvpn/policy-client.json \
    --mode "$MODE" \
    --dns-listen 127.0.0.1:53 \
    --dns-local "$DNS:53" \
    --dns-remote "$DNS:53" \
    --gfwlist /etc/shadowvpn/gfwlist.txt \
    --chnroute /etc/shadowvpn/chnroute.txt \
    --no-prewarm --no-cache-persist &
CLIENT_PID=$!
trap 'kill "$CLIENT_PID" 2>/dev/null || true' EXIT

# Wait for the tunnel.
i=1
while [ "$i" -le 30 ]; do
    kill -0 "$CLIENT_PID" 2>/dev/null || {
        echo "[client] FAIL: client exited during startup" >&2
        exit 1
    }
    if ping -c 1 -W 1 10.9.0.1 >/dev/null 2>&1; then break; fi
    echo "[client] waiting for tunnel... ($i/30)"
    i=$((i + 1))
    sleep 1
done
ping -c 1 -W 1 10.9.0.1 >/dev/null 2>&1 || {
    echo "[client] FAIL: tunnel never came up" >&2
    exit 1
}

# The client points the system resolver at its split-DNS proxy automatically
# (set_dns defaults on). Verify it actually rewrote /etc/resolv.conf rather than
# doing it ourselves — this exercises the auto-DNS feature end to end.
sleep 1
echo "[client] /etc/resolv.conf after client startup:"
sed 's/^/[client]   /' /etc/resolv.conf
grep -q '^nameserver[[:space:]]\+127\.0\.0\.1' /etc/resolv.conf || {
    echo "[client] FAIL: client did not point the resolver at its proxy" >&2
    exit 1
}

probe() {
    # $1 = hostname; print the source address the echo server observed.
    echo | nc -w 4 "$1" 7 | tr -d '[:space:]'
}

echo "[client] probing blocked.com (expect tunneled -> $SERVER_IP)"
blocked="$(probe blocked.com)"
echo "[client] probing safe.com    (expect direct   -> $CLIENT_IP)"
safe="$(probe safe.com)"

echo "[client] tunnel routes programmed into tun0:"
ip route show 2>/dev/null | grep -w tun0 | sed 's/^/[client]   /' || true

echo "[client] result: blocked.com seen-as=${blocked:-<none>}  safe.com seen-as=${safe:-<none>}"

if [ "$blocked" = "$SERVER_IP" ] && [ "$safe" = "$CLIENT_IP" ]; then
    echo "[client] PASS: policy routing (mode=$MODE) tunneled blocked.com and kept safe.com direct"
    exit 0
fi

echo "[client] FAIL: expected blocked=$SERVER_IP safe=$CLIENT_IP" >&2
exit 1
