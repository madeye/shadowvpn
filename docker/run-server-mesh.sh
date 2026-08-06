#!/bin/sh
# Hub server for the mesh subnet-routing test.
#
# Runs in the default learning mode (mesh routing rejects --nat), gives the
# tunnel an IPv6 ULA alongside IPv4, and shortens the route lease so the driver
# can observe expiry + withdrawal without waiting out the 120 s default.
#
# MESH_APPROVAL selects the approval policy:
#   auto      -> --auto-approve-routes: everything advertised is approved.
#   allowlist -> --approve-routes with the two expected prefixes; anything else
#                a client advertises is held as "awaiting approval".
set -eu

case "${MESH_APPROVAL:-auto}" in
auto) APPROVAL="--auto-approve-routes" ;;
allowlist) APPROVAL="--approve-routes 192.168.200.0/24,fd42:cafe::/64" ;;
*)
    echo "[server] unknown MESH_APPROVAL '${MESH_APPROVAL}' (want auto|allowlist)" >&2
    exit 2
    ;;
esac

echo "[server] mesh hub starting (approval=${MESH_APPROVAL:-auto})"
# $APPROVAL is intentionally unquoted: it expands to a flag plus its value.
exec shadowvpn-server -c /etc/shadowvpn/server.json ${CIPHER:+--cipher "$CIPHER"} \
    --tun-ip 10.77.0.1 --peer-ip 10.77.0.2 --tun-ip6 fd07:7::1/64 \
    --lease-ttl-secs 8 \
    $APPROVAL
