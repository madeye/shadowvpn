#!/bin/sh
# Long-lived client for the multi-client NAT test.
#
# Every client runs the *same* static config (docker/client.json) — same
# placeholder tunnel IP and all — and stays in the foreground so the driver
# (run-e2e-multi.sh) can run ping probes from inside the container. The server's
# --nat keeps them apart.
set -eu

echo "[client] starting shadowvpn-client (shared static config, cipher=${CIPHER:-from-config})"
exec shadowvpn-client -c /etc/shadowvpn/client.json ${CIPHER:+--cipher "$CIPHER"}
