#!/bin/sh
# Server for the multi-client NAT test.
#
# Runs with --nat so it maps each client (identified by its UDP endpoint) onto a
# distinct internal IP from the TUN subnet — letting every client share one
# identical static config with the same placeholder tunnel IP.
set -eu

exec shadowvpn-server -c /etc/shadowvpn/server.json --nat ${CIPHER:+--cipher "$CIPHER"}
