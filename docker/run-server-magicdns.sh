#!/bin/sh
# Learning-mode server for the Magic DNS e2e test.
#
# Hostname "vpn" is published as 10.9.0.1. Assignment + IPv6 embed match the
# assign e2e so clients can resolve each other over both families.
set -eu

mkdir -p /var/lib/shadowvpn

echo "[server] magic-dns assigner starting (hostname=vpn)"
exec shadowvpn-server -c /etc/shadowvpn/server.json ${CIPHER:+--cipher "$CIPHER"} \
    --tun-ip 10.9.0.1 --peer-ip 10.9.0.2 --tun-ip6 fd07:7::1/64 \
    --hostname vpn \
    --lease-file /var/lib/shadowvpn/leases.json
