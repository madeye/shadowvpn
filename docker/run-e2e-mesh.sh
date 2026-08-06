#!/usr/bin/env bash
# Mesh subnet-routing end-to-end test for ShadowVPN (Tailscale-like
# advertise / approve / accept).
#
# Topology: hub server + a subnet-router client advertising
# 192.168.200.0/24 + fd42:cafe::/64 (hosted on its lo) + 192.168.201.0/24
# (deliberately outside the allowlist) + an accept-routes client. Verifies:
#   1. the approved IPv4 + IPv6 routes are pushed and installed on the
#      accepting client's TUN,
#   2. approval gating: in allowlist mode the unlisted route is held as
#      awaiting approval and never pushed; in auto mode it is approved,
#   3. spoke<->spoke connectivity through the hub relay (IPv4 + IPv6),
#   4. the advertised subnets are reachable end to end (IPv4 + IPv6),
#   5. routes are withdrawn from the accepting client after the advertiser
#      goes away (lease expiry -> withdrawal push -> kernel route removal).
#
# Exits 0 only if all checks pass. Approval mode as $1: auto (default) or
# allowlist. Uses only POSIX-ish bash so it runs under macOS bash 3.2.
set -euo pipefail

cd "$(dirname "$0")"

APPROVAL="${1:-${MESH_APPROVAL:-auto}}"
case "$APPROVAL" in
auto | allowlist) ;;
*)
    echo "usage: $0 [auto|allowlist]" >&2
    exit 2
    ;;
esac
export MESH_APPROVAL="$APPROVAL"

ROUTER_TUN_IP=10.77.0.2
ROUTER_TUN_IP6=fd07:7::2
SUBNET_V4=192.168.200.0/24
SUBNET_V4_HOST=192.168.200.1
SUBNET_V6=fd42:cafe::/64
SUBNET_V6_HOST=fd42:cafe::1
UNLISTED_V4=192.168.201.0/24

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.mesh.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.mesh.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

# has_route <4|6> <cidr>: the accepting client has this route on its TUN.
has_route() { $COMPOSE exec -T accept ip "-$1" route show "$2" 2>/dev/null | grep -q tun0; }

fail=0
check() { # check <description> <command...>
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  OK: $desc"
    else
        echo "FAIL: $desc" >&2
        fail=1
    fi
}

echo "==> ShadowVPN mesh subnet-routing test (approval=${APPROVAL}, cipher=${CIPHER:-chacha20-poly1305})"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

# 1: wait for the advert -> approve -> accept round trip; the approved routes
# must land on the accepting client's TUN.
got_routes=0
for _ in $(seq 1 60); do
    if has_route 4 "$SUBNET_V4" && has_route 6 "$SUBNET_V6"; then
        got_routes=1
        break
    fi
    sleep 1
done
if [ "$got_routes" -eq 1 ]; then
    echo "  OK: approved routes ($SUBNET_V4, $SUBNET_V6) installed on the accepting client's tun0"
else
    echo "FAIL: approved routes never appeared on the accepting client" >&2
    echo "==> accept client routes:" >&2
    $COMPOSE exec -T accept ip route >&2 || true
    $COMPOSE exec -T accept ip -6 route >&2 || true
    fail=1
fi

# 2: approval gating for the route outside the allowlist.
if [ "$APPROVAL" = allowlist ]; then
    if has_route 4 "$UNLISTED_V4"; then
        echo "FAIL: unlisted route $UNLISTED_V4 was pushed despite the allowlist" >&2
        fail=1
    else
        echo "  OK: unlisted route $UNLISTED_V4 was not pushed"
    fi
    check "server holds $UNLISTED_V4 as awaiting approval" \
        bash -c "$COMPOSE logs --no-color server | grep 'awaiting approval' | grep -q '192.168.201.0/24'"
else
    # Auto mode approves everything, including the extra route.
    check "auto-approved route $UNLISTED_V4 installed on the accepting client" \
        has_route 4 "$UNLISTED_V4"
fi

# 3: spoke<->spoke through the hub relay (never on the server's TUN).
check "spoke<->spoke IPv4: accept -> router ($ROUTER_TUN_IP)" \
    $COMPOSE exec -T accept ping -c 3 -i 0.3 -W 2 "$ROUTER_TUN_IP"
check "spoke<->spoke IPv6: accept -> router ($ROUTER_TUN_IP6)" \
    $COMPOSE exec -T accept ping -6 -c 3 -i 0.3 -W 2 "$ROUTER_TUN_IP6"

# 4: the advertised subnets, end to end over the pushed routes.
check "advertised IPv4 subnet: accept -> $SUBNET_V4_HOST" \
    $COMPOSE exec -T accept ping -c 3 -i 0.3 -W 2 "$SUBNET_V4_HOST"
check "advertised IPv6 subnet: accept -> $SUBNET_V6_HOST" \
    $COMPOSE exec -T accept ping -6 -c 3 -i 0.3 -W 2 "$SUBNET_V6_HOST"

# 5: withdrawal — stop the router; its routes must expire on the server
# (lease-ttl-secs 8) and be withdrawn from the accepting client's kernel.
echo "  stopping the router to trigger lease expiry + withdrawal..."
$COMPOSE stop -t 2 router >/dev/null 2>&1
withdrawn=0
for _ in $(seq 1 45); do
    if ! has_route 4 "$SUBNET_V4" && ! has_route 6 "$SUBNET_V6"; then
        withdrawn=1
        break
    fi
    sleep 1
done
if [ "$withdrawn" -eq 1 ]; then
    # Guard: has_route also fails if the accept client died — make sure its
    # TUN is still up (it vanishes with the process), so a crashed client
    # can't fake a withdrawal.
    if $COMPOSE exec -T accept ip link show tun0 >/dev/null 2>&1; then
        echo "  OK: routes withdrawn from the accepting client after the advertiser went away"
    else
        echo "FAIL: accepting client lost its tunnel during the withdrawal check" >&2
        fail=1
    fi
else
    echo "FAIL: routes still installed on the accepting client after router shutdown" >&2
    $COMPOSE exec -T accept ip route >&2 || true
    fail=1
fi

echo "==> server log (tail):"
$COMPOSE logs --no-color server 2>/dev/null | tail -15

if [ "$fail" -eq 0 ]; then
    echo "PASS: mesh subnet routing (advertise/approve/accept, $APPROVAL) works end to end"
else
    echo "FAIL: one or more checks failed" >&2
fi
exit "$fail"
