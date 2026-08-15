#!/usr/bin/env bash
# Magic DNS end-to-end test for ShadowVPN.
#
# Starts one learning-mode server (hostname=vpn) and two auto clients
# (hostname=laptop / hostname=pi), then verifies:
#   1. each client reaches the server's tunnel IP,
#   2. laptop's stub resolves pi.svpn / pi to pi's assigned IPv4,
#   3. pi's stub resolves laptop.svpn AAAA to laptop's embedded IPv6,
#   4. unknown *.svpn is NXDOMAIN,
#   5. the server name vpn.svpn is 10.9.0.1,
#   6. ping of the resolved IPv4 reaches the other spoke through the hub.
#
# Exits 0 only if all checks pass. Optional cipher as $1.
set -euo pipefail

cd "$(dirname "$0")"

CIPHER="${1:-${CIPHER:-chacha20-poly1305}}"
export CIPHER
SERVER_TUN_IP=10.9.0.1

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.magicdns.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.magicdns.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail=0
check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  OK: $desc"
    else
        echo "FAIL: $desc" >&2
        fail=1
    fi
}

wait_ping() {
    local c="$1" dest="$2" i
    for i in $(seq 1 30); do
        if $COMPOSE exec -T "$c" ping -c 1 -W 1 "$dest" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

client_ip4() {
    $COMPOSE exec -T "$1" ip -4 -o addr show tun0 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n1
}

client_ip6() {
    $COMPOSE exec -T "$1" ip -6 -o addr show tun0 scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n1
}

# Wait until $1's stub answers $2 with a non-empty A/AAAA record.
wait_dig() {
    local c="$1" name="$2" type="${3:-A}" i
    for i in $(seq 1 30); do
        if [ -n "$($COMPOSE exec -T "$c" dig +short +time=1 +tries=1 @"127.0.0.1" "$name" "$type" 2>/dev/null | tr -d '[:space:]')" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

dig_short() {
    $COMPOSE exec -T "$1" dig +short +time=2 +tries=1 @"127.0.0.1" "$2" "$3" 2>/dev/null \
        | tr -d '\r' | head -n1
}

echo "==> ShadowVPN Magic DNS test (cipher=${CIPHER})"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

if ! wait_ping laptop "$SERVER_TUN_IP" || ! wait_ping pi "$SERVER_TUN_IP"; then
    echo "FAIL: clients could not reach the server" >&2
    $COMPOSE logs --no-color >&2 || true
    exit 1
fi
echo "  OK: laptop and pi reach the server"

if ! wait_dig laptop pi.svpn A || ! wait_dig pi laptop.svpn A; then
    echo "FAIL: Magic DNS stub did not answer peer names" >&2
    $COMPOSE logs --no-color laptop pi >&2 || true
    exit 1
fi

pi_v4=$(client_ip4 pi)
laptop_v4=$(client_ip4 laptop)
laptop_v6=$(client_ip6 laptop)
echo "  laptop tun=${laptop_v4} ${laptop_v6:-<no-v6>}  pi tun=${pi_v4}"

got=$(dig_short laptop pi.svpn A)
check "laptop stub: pi.svpn A → ${pi_v4}" [ "$got" = "$pi_v4" ]

got=$(dig_short laptop pi A)
check "laptop stub: bare 'pi' A → ${pi_v4}" [ "$got" = "$pi_v4" ]

got=$(dig_short pi laptop.svpn A)
check "pi stub: laptop.svpn A → ${laptop_v4}" [ "$got" = "$laptop_v4" ]

if [ -n "$laptop_v6" ]; then
    got=$(dig_short pi laptop.svpn AAAA)
    check "pi stub: laptop.svpn AAAA → ${laptop_v6}" [ "$got" = "$laptop_v6" ]
else
    echo "FAIL: laptop has no tun IPv6 for AAAA check" >&2
    fail=1
fi

got=$(dig_short laptop vpn.svpn A)
check "laptop stub: vpn.svpn A → ${SERVER_TUN_IP}" [ "$got" = "$SERVER_TUN_IP" ]

# NXDOMAIN: status line, no answer.
if $COMPOSE exec -T laptop dig +time=2 +tries=1 @"127.0.0.1" no-such-peer.svpn A \
        2>/dev/null | grep -q 'status: NXDOMAIN'; then
    echo "  OK: unknown no-such-peer.svpn is NXDOMAIN"
else
    echo "FAIL: unknown *.svpn was not NXDOMAIN" >&2
    fail=1
fi

# Name resolution plus spoke↔spoke: ping the address Magic DNS returned.
if [ -n "$pi_v4" ]; then
    check "laptop pings Magic-DNS-resolved pi (${pi_v4})" \
        $COMPOSE exec -T laptop ping -c 3 -i 0.3 -W 2 "$pi_v4"
fi

# Single-label ping via the stub (point resolv.conf at it for this one shot).
check "laptop: ping -c1 pi via 127.0.0.1 stub" \
    $COMPOSE exec -T laptop sh -c \
        'printf "nameserver 127.0.0.1\n" > /etc/resolv.conf && ping -c 1 -W 2 pi'

if [ "$fail" -ne 0 ]; then
    echo "==> Magic DNS test FAILED" >&2
    exit 1
fi
echo "==> Magic DNS test passed"
