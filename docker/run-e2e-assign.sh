#!/usr/bin/env bash
# Auto-assign spoke-to-spoke end-to-end test for ShadowVPN.
#
# Starts one learning-mode server (no --nat) and three identical auto
# clients (omit tun_ip / peer_ip / tun_ip6), then verifies:
#   1. every client reaches the server's tunnel IP through the tunnel,
#   2. the server assigned three distinct IPv4s (never .1 or reserved .2),
#   3. client A can ping client B's assigned IPv4 and embedded IPv6,
#   4. restarting a client keeps the same IPv4 (state volume),
#   5. restarting the server keeps the same IPv4s (lease volume),
#   6. an injected lease with last_seen_unix older than the assign TTL
#      is dropped on load (that IPv4 is not held for a dead node).
#
# Exits 0 only if all checks pass. Optional cipher as $1 (default from env).
# Uses only POSIX-ish bash (indexed arrays) so it runs under macOS bash 3.2.
set -euo pipefail

cd "$(dirname "$0")"

CIPHER="${1:-${CIPHER:-chacha20-poly1305}}"
export CIPHER
SERVER_TUN_IP=10.9.0.1
RESERVED_IP=10.9.0.2
CLIENTS=(client1 client2 client3)

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.assign.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.assign.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

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

# Wait until $1 can ping $2 (IPv4).
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

# IPv4 currently programmed on $1's tun0 (empty if the iface is not up).
client_ip4() {
    $COMPOSE exec -T "$1" ip -4 -o addr show tun0 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n1
}

# Global IPv6 currently programmed on $1's tun0.
client_ip6() {
    $COMPOSE exec -T "$1" ip -6 -o addr show tun0 scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n1
}

# Embed IPv4 into fd07:7::/64 the same way assign::embed_ip4 does.
ip4_to_ip6() {
    local a b c d
    IFS=. read -r a b c d <<EOF
$1
EOF
    printf 'fd07:7::%x:%x\n' $(((a << 8) | b)) $(((c << 8) | d))
}

# Unique IPv4s from `assigned <ip4> / ...` server log lines.
parse_assigned_v4() {
    $COMPOSE logs --no-color server 2>/dev/null \
        | sed -n 's/.*assigned \([0-9][0-9.]*\) \/ .*/\1/p' | sort -u
}

echo "==> ShadowVPN auto-assign spoke-to-spoke test (cipher=${CIPHER}, clients=${#CLIENTS[@]})"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

# 1: every client reaches the server (which also forces AssignRequest + Ok).
for c in "${CLIENTS[@]}"; do
    if wait_ping "$c" "$SERVER_TUN_IP" \
        && $COMPOSE exec -T "$c" ping -c 3 -i 0.3 -W 2 "$SERVER_TUN_IP" >/dev/null 2>&1; then
        echo "  OK: $c -> server ($SERVER_TUN_IP) through the tunnel"
    else
        echo "FAIL: $c could not reach the server ($SERVER_TUN_IP)" >&2
        fail=1
    fi
done

# 2: three distinct assigned IPv4s, none is the server or reserved .2.
assigned_v4=$(parse_assigned_v4)
count=$(printf '%s\n' "$assigned_v4" | grep -c . || true)
echo "  server-assigned IPv4s (from 'assigned <ip4> /' log lines):"
printf '    %s\n' $assigned_v4
if [ "$count" -eq "${#CLIENTS[@]}" ]; then
    echo "  OK: $count distinct assigned IPv4s"
else
    echo "FAIL: expected ${#CLIENTS[@]} distinct assigned IPv4s, got $count" >&2
    fail=1
fi
if printf '%s\n' "$assigned_v4" | grep -qx "$SERVER_TUN_IP"; then
    echo "FAIL: assigned set includes the server IP $SERVER_TUN_IP" >&2
    fail=1
elif printf '%s\n' "$assigned_v4" | grep -qx "$RESERVED_IP"; then
    echo "FAIL: assigned set includes reserved $RESERVED_IP" >&2
    fail=1
else
    echo "  OK: no assigned IPv4 is $SERVER_TUN_IP or reserved $RESERVED_IP"
fi

# 3: spoke<->spoke through the hub relay (IPv4 + embedded IPv6).
a_v4=$(client_ip4 client1)
b_v4=$(client_ip4 client2)
b_v6=$(client_ip6 client2)
echo "  client1 tun=$a_v4  client2 tun=$b_v4 ${b_v6:-<no-v6>}"
if [ -n "$a_v4" ] && [ -n "$b_v4" ] && [ "$a_v4" != "$b_v4" ]; then
    check "spoke<->spoke IPv4: client1 -> client2 ($b_v4)" \
        $COMPOSE exec -T client1 ping -c 3 -i 0.3 -W 2 "$b_v4"
else
    echo "FAIL: could not read distinct tun IPv4s on client1/client2" >&2
    fail=1
fi
if [ -n "$b_v6" ]; then
    expect_v6=$(ip4_to_ip6 "$b_v4")
    if [ "$b_v6" = "$expect_v6" ]; then
        echo "  OK: client2 IPv6 $b_v6 is fd07:7:: embed of $b_v4"
    else
        echo "FAIL: client2 IPv6 $b_v6 != expected $expect_v6" >&2
        fail=1
    fi
    check "spoke<->spoke IPv6: client1 -> client2 ($b_v6)" \
        $COMPOSE exec -T client1 ping -6 -c 3 -i 0.3 -W 2 "$b_v6"
else
    echo "FAIL: client2 has no global IPv6 on tun0" >&2
    fail=1
fi

# 4: restart one client; the state volume must restore the same IPv4.
before=$(client_ip4 client1)
echo "  restarting client1 (expect IPv4 $before from state volume)..."
$COMPOSE restart -t 2 client1 >/dev/null 2>&1
if wait_ping client1 "$SERVER_TUN_IP"; then
    after=$(client_ip4 client1)
    if [ -n "$before" ] && [ "$after" = "$before" ]; then
        echo "  OK: client1 kept $after across restart"
    else
        echo "FAIL: client1 IPv4 changed across restart ($before -> $after)" >&2
        fail=1
    fi
else
    echo "FAIL: client1 did not come back after restart" >&2
    fail=1
fi

# 5: restart the server; the lease volume must restore the same IPv4s.
before1=$(client_ip4 client1)
before2=$(client_ip4 client2)
before3=$(client_ip4 client3)
echo "  restarting server (expect $before1 $before2 $before3 from lease volume)..."
$COMPOSE restart -t 2 server >/dev/null 2>&1
ok_after=1
for c in "${CLIENTS[@]}"; do
    if ! wait_ping "$c" "$SERVER_TUN_IP"; then
        echo "FAIL: $c could not reach the server after server restart" >&2
        fail=1
        ok_after=0
    fi
done
if [ "$ok_after" -eq 1 ]; then
    after1=$(client_ip4 client1)
    after2=$(client_ip4 client2)
    after3=$(client_ip4 client3)
    if [ "$after1" = "$before1" ] && [ "$after2" = "$before2" ] && [ "$after3" = "$before3" ]; then
        echo "  OK: all clients kept their IPv4s across server restart"
    else
        echo "FAIL: IPv4s changed across server restart ($before1 $before2 $before3 -> $after1 $after2 $after3)" >&2
        fail=1
    fi
fi

# 6: inject a lease whose last_seen_unix is older than the 7-day TTL.
# On load the assigner drops it, so that IPv4 is not held for a dead node.
# (Skipped when python3 or compose cp is unavailable.)
STALE_IP=10.9.0.200
case " $before1 $before2 $before3 " in
*" $STALE_IP "*) STALE_IP=10.9.0.201 ;;
esac
if ! command -v python3 >/dev/null 2>&1; then
    echo "  skip: stale-lease inject (python3 not available to edit leases.json)"
else
    work=$(mktemp -d "${TMPDIR:-/tmp}/svpn-assign.XXXXXX")
    echo "  injecting expired lease for $STALE_IP and restarting the server..."
    $COMPOSE stop -t 2 server >/dev/null 2>&1
    if $COMPOSE cp server:/var/lib/shadowvpn/leases.json "$work/leases.json" 2>/dev/null \
        || docker cp svpn-assign-server:/var/lib/shadowvpn/leases.json "$work/leases.json" 2>/dev/null; then
        python3 - "$work/leases.json" "$STALE_IP" <<'PY'
import json, sys
path, ip = sys.argv[1], sys.argv[2]
with open(path) as f:
    data = json.load(f)
octets = [int(x) for x in ip.split(".")]
embed = "fd07:7::{:x}:{:x}".format((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3])
data.setdefault("leases", []).append({
    "node_id": "deadbeef-0000-4000-8000-000000000099",
    "ip4": ip,
    "ip6": embed,
    "last_seen_unix": 1,
})
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
        if $COMPOSE cp "$work/leases.json" server:/var/lib/shadowvpn/leases.json 2>/dev/null \
            || docker cp "$work/leases.json" svpn-assign-server:/var/lib/shadowvpn/leases.json 2>/dev/null; then
            $COMPOSE start server >/dev/null 2>&1
            # Load+persist of the dropped row happens in Assigner::new.
            # Poll the rewritten file (old "assignment: ON" banners stay in logs).
            dropped=0
            for _ in $(seq 1 20); do
                if $COMPOSE exec -T server cat /var/lib/shadowvpn/leases.json \
                    >"$work/after.json" 2>/dev/null \
                    && [ -s "$work/after.json" ] \
                    && ! grep -q "$STALE_IP" "$work/after.json"; then
                    dropped=1
                    break
                fi
                sleep 1
            done
            banner=$($COMPOSE logs --no-color server 2>/dev/null | grep 'assignment: ON' | tail -1 || true)
            echo "  latest banner: $banner"
            if [ "$dropped" -eq 1 ]; then
                echo "  OK: expired lease $STALE_IP was dropped on load (not held for a new node)"
            else
                echo "FAIL: expired lease $STALE_IP was restored after server start" >&2
                fail=1
            fi
            # Live clients must still reach the server on their original IPs.
            for c in "${CLIENTS[@]}"; do
                if ! wait_ping "$c" "$SERVER_TUN_IP"; then
                    echo "FAIL: $c lost the tunnel after stale-lease inject" >&2
                    fail=1
                fi
            done
        else
            echo "  skip: stale-lease inject (could not copy leases.json back into the server)"
            $COMPOSE start server >/dev/null 2>&1 || true
        fi
    else
        echo "  skip: stale-lease inject (could not copy leases.json out of the server)"
        $COMPOSE start server >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
fi

echo "==> server log (tail):"
$COMPOSE logs --no-color server 2>/dev/null | tail -20

if [ "$fail" -eq 0 ]; then
    echo "PASS: auto-assign spoke-to-spoke works end to end"
else
    echo "FAIL: one or more checks failed" >&2
fi
exit "$fail"
