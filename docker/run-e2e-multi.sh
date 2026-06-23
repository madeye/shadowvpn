#!/usr/bin/env bash
# Multi-client end-to-end test for ShadowVPN server-side NAT.
#
# Starts one --nat server and three clients that all run the SAME static config
# (same placeholder tunnel IP), then verifies:
#   1. every client reaches the server's tunnel IP through the tunnel,
#   2. the server mapped each client onto a distinct internal IP (no collisions).
#
# (Clients cannot address each other in NAT mode — they share one placeholder —
# so this is hub-and-spoke to the server, by design.)
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

echo "==> ShadowVPN multi-client NAT test (cipher=${CIPHER}, clients=${#CLIENTS[@]})"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

fail=0

# 1: every client reaches the server (which also creates its NAT mapping, since
# the first data packet is what allocates an internal IP).
for c in "${CLIENTS[@]}"; do
    ok=0
    for _ in $(seq 1 30); do
        if $COMPOSE exec -T "$c" ping -c 1 -W 1 "$SERVER_TUN_IP" >/dev/null 2>&1; then
            ok=1
            break
        fi
        sleep 1
    done
    if [ "$ok" -eq 1 ] && $COMPOSE exec -T "$c" ping -c 3 -i 0.3 -W 2 "$SERVER_TUN_IP" >/dev/null 2>&1; then
        echo "  OK: $c -> server ($SERVER_TUN_IP) through the tunnel"
    else
        echo "FAIL: $c could not reach the server ($SERVER_TUN_IP)" >&2
        fail=1
    fi
done

# 2: the server allocated a distinct internal IP for each client.
internals=$($COMPOSE logs --no-color server 2>/dev/null \
    | sed -n 's/.*-> internal \([0-9.]*\).*/\1/p' | sort -u)
count=$(printf '%s\n' "$internals" | grep -c . || true)
echo "  server-allocated internal IPs:"
printf '    %s\n' $internals
if [ "$count" -ge "${#CLIENTS[@]}" ]; then
    echo "  OK: $count distinct internal IPs (>= ${#CLIENTS[@]} clients, no collisions)"
else
    echo "FAIL: expected >= ${#CLIENTS[@]} distinct internal IPs, got $count" >&2
    fail=1
fi

echo "==> server log (tail):"
$COMPOSE logs --no-color server 2>/dev/null | tail -12

if [ "$fail" -eq 0 ]; then
    echo "PASS: multi-client server-side NAT works end to end"
else
    echo "FAIL: one or more checks failed" >&2
fi
exit "$fail"
