#!/bin/sh
# Server entry point for the multi-client auto-IP E2E test.
#
# Enables IPv4 forwarding (and relaxes reverse-path filtering) so the server can
# relay traffic between two clients that share the same tun0 /24 — a packet from
# one client destined to another arrives on tun0 and must be forwarded back out
# tun0 to reach the second client. Then runs the server with --auto-assign so it
# hands out tunnel IPs from the subnet on request.
set -eu

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo "[server] warn: could not enable ip_forward" >&2
# `default` applies to tun0 when the server creates it after this point.
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

exec shadowvpn-server -c /etc/shadowvpn/server.json --auto-assign ${CIPHER:+--cipher "$CIPHER"}
