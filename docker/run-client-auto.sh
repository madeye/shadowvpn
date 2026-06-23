#!/bin/sh
# Long-lived client for the multi-client auto-IP test.
#
# Brings up the tunnel with a *server-assigned* IP (auto_ip) and stays in the
# foreground so the driver (run-e2e-multi.sh) can read its assigned address from
# the logs and run ping probes from inside the container.
set -eu

echo "[client] starting shadowvpn-client (auto-IP, cipher=${CIPHER:-from-config})"
exec shadowvpn-client -c /etc/shadowvpn/client-auto.json ${CIPHER:+--cipher "$CIPHER"}
