#!/bin/sh
# Client entry point for the policy-routing E2E test.
#
# Starts the ShadowVPN client with policy routing (mode from $MODE). DNS is
# intercepted on the TUN (the client does not rewrite resolv.conf to 127.0.0.1);
# the test points the stub resolver at 8.8.8.8 so queries hit that intercept,
# then connects to two domains:
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

# DNS is intercepted on the TUN. Do not require (or treat as success) a
# nameserver 127.0.0.1 rewrite — Docker's stub is 127.0.0.11 and the client
# no longer takes over the OS resolver. Point at 8.8.8.8 so queries hit the
# /32 the client attracts onto the tun.
sleep 1
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "[client] /etc/resolv.conf for TUN intercept:"
sed 's/^/[client]   /' /etc/resolv.conf

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
