#!/usr/bin/env bash
# Multi-client end-to-end test for ShadowVPN auto-IP assignment.
#
# Starts one --auto-assign server and three auto_ip clients, then verifies:
#   1. each client is assigned a tunnel IP by the server,
#   2. the three assigned IPs are distinct (no collisions),
#   3. every client reaches the server's tunnel IP through the tunnel,
#   4. clients reach each other (server-side inner-IP routing).
#
# Exits 0 only if all checks pass. Optional cipher as $1 (default from env).
# Uses only POSIX-ish bash (indexed arrays) so it runs under macOS bash 3.2.
set -euo pipefail

cd "$(dirname "$0")"

CIPHER="${1:-${CIPHER:-chacha20-poly1305}}"
export CIPHER
SERVER_TUN_IP=10.9.0.1
CLIENTS=(client1 client2 client3)

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.multi.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.multi.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> ShadowVPN multi-client auto-IP test (cipher=${CIPHER}, clients=${#CLIENTS[@]})"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

fail=0
ASSIGNED=() # indexed parallel to CLIENTS

# 1 + 2: each client gets an address; collect them (in client order).
for idx in "${!CLIENTS[@]}"; do
    c=${CLIENTS[$idx]}
    ip=""
    for _ in $(seq 1 40); do
        ip=$($COMPOSE logs --no-color "$c" 2>/dev/null \
            | sed -n 's/.*auto-IP: server assigned ip=\([0-9.]*\).*/\1/p' | tail -1)
        [ -n "$ip" ] && break
        sleep 1
    done
    if [ -z "$ip" ]; then
        echo "FAIL: $c received no address assignment" >&2
        $COMPOSE logs --no-color "$c" 2>/dev/null | tail -8 >&2
        fail=1
    else
        echo "  [$c] assigned $ip"
    fi
    ASSIGNED[$idx]=$ip
done

# Distinctness of the addresses we did collect.
got=$(printf '%s\n' "${ASSIGNED[@]}" | grep -c .)
distinct=$(printf '%s\n' "${ASSIGNED[@]}" | grep . | sort -u | wc -l | tr -d ' ')
if [ "$got" -ge 2 ] && [ "$distinct" -eq "$got" ]; then
    echo "  OK: $got distinct addresses (no collisions)"
elif [ "$got" -ge 2 ]; then
    echo "FAIL: assigned addresses are not distinct ($distinct unique of $got)" >&2
    fail=1
fi

# 3: every client reaches the server through the tunnel.
for c in "${CLIENTS[@]}"; do
    if $COMPOSE exec -T "$c" ping -c 3 -i 0.3 -W 2 "$SERVER_TUN_IP" >/dev/null 2>&1; then
        echo "  OK: $c -> server ($SERVER_TUN_IP) through the tunnel"
    else
        echo "FAIL: $c could not reach the server ($SERVER_TUN_IP)" >&2
        fail=1
    fi
done

# 4: client1 -> client2 (proves the server routes between clients by inner IP).
target=${ASSIGNED[1]:-}
if [ -n "$target" ]; then
    if $COMPOSE exec -T client1 ping -c 3 -i 0.3 -W 2 "$target" >/dev/null 2>&1; then
        echo "  OK: client1 -> client2 ($target) via the server (inter-client routing)"
    else
        echo "FAIL: client1 could not reach client2 ($target)" >&2
        fail=1
    fi
fi

echo "==> server log (tail):"
$COMPOSE logs --no-color server 2>/dev/null | tail -10

if [ "$fail" -eq 0 ]; then
    echo "PASS: multi-client auto-IP works end to end"
else
    echo "FAIL: one or more checks failed" >&2
fi
exit "$fail"
