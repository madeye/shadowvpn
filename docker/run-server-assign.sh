#!/bin/sh
# Learning-mode server for the auto-assign spoke-to-spoke test.
#
# No --nat: assignment is always on in learning mode. peer_ip 10.9.0.2 is
# reserved so a mixed fleet's static client at .2 is never handed out.
# tun_ip6 /64 lets clients that omitted tun_ip6 get fd07:7::<embedded v4>.
# The lease file lives on a named volume so compose restart keeps leases.
set -eu

mkdir -p /var/lib/shadowvpn

echo "[server] learning-mode assigner starting (no --nat)"
exec shadowvpn-server -c /etc/shadowvpn/server.json ${CIPHER:+--cipher "$CIPHER"} \
    --tun-ip 10.9.0.1 --peer-ip 10.9.0.2 --tun-ip6 fd07:7::1/64 \
    --lease-file /var/lib/shadowvpn/leases.json
