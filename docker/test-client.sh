#!/bin/sh
# Entry point for the client container in the E2E test.
#
# Brings up the ShadowVPN client and then verifies real connectivity *through*
# the encrypted tunnel by pinging the server's in-tunnel address (10.9.0.1).
# A successful ping proves the full data path end to end:
#
#   client kernel -> TUN -> encrypt -> UDP -> server -> decrypt -> server TUN
#   -> server kernel replies -> server TUN -> encrypt -> UDP -> client -> TUN
#   -> client kernel delivers the echo reply.
#
# The script exits 0 on success and non-zero on failure, so the compose run can
# use `--exit-code-from client` to turn this into the test's pass/fail result.
set -eu

SERVER_TUN_IP=10.9.0.1
PING_COUNT=5
STARTUP_TIMEOUT=30

echo "[client] starting shadowvpn-client (cipher=${CIPHER:-from-config})"
shadowvpn-client -c /etc/shadowvpn/client.json ${CIPHER:+--cipher "$CIPHER"} &
CLIENT_PID=$!

# Always tear the client down when this script exits.
trap 'kill "$CLIENT_PID" 2>/dev/null || true' EXIT

# Wait for the tunnel to carry a single round-trip, retrying to absorb the
# server/client startup race. Bail out early if the client process has died.
connected=0
i=1
while [ "$i" -le "$STARTUP_TIMEOUT" ]; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "[client] FAIL: shadowvpn-client exited during startup" >&2
        wait "$CLIENT_PID" || true
        exit 1
    fi
    if ping -c 1 -W 1 "$SERVER_TUN_IP" >/dev/null 2>&1; then
        connected=1
        break
    fi
    echo "[client] waiting for tunnel to come up... ($i/${STARTUP_TIMEOUT})"
    i=$((i + 1))
    sleep 1
done

if [ "$connected" -ne 1 ]; then
    echo "[client] FAIL: no reply from $SERVER_TUN_IP after ${STARTUP_TIMEOUT}s" >&2
    echo "[client] --- tunnel interface ---" >&2
    ip addr show tun0 >&2 || true
    exit 1
fi

# Stronger assertion: a short burst must all get through with 0% loss.
echo "[client] tunnel is up; running ping burst to $SERVER_TUN_IP"
if ping -c "$PING_COUNT" -i 0.3 -W 2 "$SERVER_TUN_IP"; then
    echo "[client] PASS: end-to-end connectivity through the ShadowVPN tunnel"
    exit 0
fi

echo "[client] FAIL: ping burst to $SERVER_TUN_IP lost packets" >&2
exit 1
