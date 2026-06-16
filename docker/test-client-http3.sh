#!/bin/sh
# Client entry point for the HTTP/3-over-tunnel test.
#
# Brings up the ShadowVPN client, then routes *all* internet egress through the
# tunnel (the default route is deleted, so the only paths left are the connected
# docker subnet — used to reach the server's UDP port — and the tunnel). With no
# direct escape, a successful HTTP/3 (QUIC, i.e. UDP) fetch of a real site proves
# the request travelled through ShadowVPN.
#
# Success criterion: the response is delivered over HTTP/3. The application-layer
# status code is irrelevant (Cloudflare may bot-block with 403); what matters is
# that the QUIC handshake + HTTP/3 request/response completed over the tunnel.
set -eu

TARGET_URL="${TARGET_URL:-https://www.cloudflare-quic.com/}"
PEER=10.9.0.1
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

echo "[client] starting shadowvpn-client (cipher=${CIPHER:-from-config})"
shadowvpn-client -c /etc/shadowvpn/client.json ${CIPHER:+--cipher "$CIPHER"} &
CLIENT_PID=$!
trap 'kill "$CLIENT_PID" 2>/dev/null || true' EXIT

# Wait for the tunnel to come up and carry a round-trip to the server's tunnel
# IP, bailing out early if the client process dies.
i=1
while [ "$i" -le 30 ]; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "[client] FAIL: shadowvpn-client exited during startup" >&2
        exit 1
    fi
    if ip link show tun0 >/dev/null 2>&1 && ping -c 1 -W 1 "$PEER" >/dev/null 2>&1; then
        break
    fi
    echo "[client] waiting for tunnel to come up... ($i/30)"
    i=$((i + 1))
    sleep 1
done

if ! ping -c 1 -W 1 "$PEER" >/dev/null 2>&1; then
    echo "[client] FAIL: tunnel never came up (no reply from $PEER)" >&2
    exit 1
fi

# Send every public destination through the tunnel. The two /1 routes blanket
# the whole address space and outrank the default route; deleting the default
# route as well guarantees there is no direct path to the internet, so this test
# truly exercises the tunnel rather than leaking around it.
ip route add 0.0.0.0/1 via "$PEER"
ip route add 128.0.0.0/1 via "$PEER"
ip route del default 2>/dev/null || true
echo "[client] routing table:"
ip route

echo "[client] HTTP/3 request through the tunnel: $TARGET_URL"
result="$(curl --http3-only -A "$UA" -sS --max-time 30 -o /dev/null \
    -w 'http_version=%{http_version} code=%{http_code} server_ip=%{remote_ip}' \
    "$TARGET_URL")" || {
    echo "[client] FAIL: curl returned an error (no HTTP/3 response through the tunnel)" >&2
    exit 1
}
echo "[client] $result"

version="$(printf '%s\n' "$result" | sed -n 's/.*http_version=\([0-9][0-9]*\).*/\1/p')"
if [ "$version" = "3" ]; then
    echo "[client] PASS: HTTP/3 (QUIC) reached $TARGET_URL end-to-end through the ShadowVPN tunnel"
    exit 0
fi

echo "[client] FAIL: expected HTTP/3, got HTTP version '$version'" >&2
exit 1
