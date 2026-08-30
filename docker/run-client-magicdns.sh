#!/bin/sh
# Auto-assign client for the Magic DNS e2e test.
#
# HOSTNAME (env) is the announced Magic DNS label. The test queries the stub
# at 127.0.0.1:53 directly (the client does not rewrite the OS resolver).
set -eu

sed -e '/"tun_ip"/d' -e '/"peer_ip"/d' /etc/shadowvpn/client.json \
    > /tmp/client-magicdns.json

PEER_NAME="${PEER_NAME:-node}"

echo "[client] magic-dns auto client hostname=${PEER_NAME} cipher=${CIPHER:-from-config}"
exec shadowvpn-client -c /tmp/client-magicdns.json ${CIPHER:+--cipher "$CIPHER"} \
    --state-file /var/lib/shadowvpn/client.state \
    --keepalive-secs 2 \
    --hostname "$PEER_NAME"
