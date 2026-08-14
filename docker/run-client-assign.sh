#!/bin/sh
# Auto-assign client for the spoke-to-spoke assignment test.
#
# Every replica runs the same config: tun_ip / peer_ip stripped so this is
# auto_tun, and tun_ip6 left unset so FLAG_WANT_IP6 is set. node_id + last
# assignment persist on a per-client volume so compose restart keeps the
# same lease. A short keepalive makes AssignRequest land quickly.
set -eu

# Shared client.json carries a static placeholder pair for the NAT/plain
# tests; assignment requires both addresses omitted.
sed -e '/"tun_ip"/d' -e '/"peer_ip"/d' /etc/shadowvpn/client.json \
    > /tmp/client-assign.json

echo "[client] starting auto-assign client (no tun_ip/peer_ip, cipher=${CIPHER:-from-config})"
exec shadowvpn-client -c /tmp/client-assign.json ${CIPHER:+--cipher "$CIPHER"} \
    --state-file /var/lib/shadowvpn/client.state \
    --keepalive-secs 2
