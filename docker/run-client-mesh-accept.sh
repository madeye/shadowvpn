#!/bin/sh
# Accept-routes client for the mesh test.
#
# Opts into server route pushes and stays in the foreground so the driver
# (run-e2e-mesh.sh) can exec ip/ping probes inside this netns while routes are
# pushed and later withdrawn. A short keepalive makes pushes arrive quickly.
set -eu

echo "[accept] starting accept-routes client"
exec shadowvpn-client -c /etc/shadowvpn/client.json ${CIPHER:+--cipher "$CIPHER"} \
    --tun-ip 10.77.0.3 --peer-ip 10.77.0.1 --tun-ip6 fd07:7::3/64 \
    --keepalive-secs 2 \
    --accept-routes
