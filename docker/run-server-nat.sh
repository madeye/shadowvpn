#!/bin/sh
# Server entry point for the HTTP/3-over-tunnel test.
#
# Unlike the plain E2E server, this one must let tunneled client traffic reach
# the wider internet. It enables IP forwarding and masquerades the tunnel subnet
# out the container's WAN interface, then hands off to the normal server.
set -eu

# Belt-and-suspenders: the compose file also sets this sysctl.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# The WAN interface is whichever one carries the default route (eth0 on a
# default docker bridge, but don't hard-code it).
WAN="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
WAN="${WAN:-eth0}"

echo "[server] enabling NAT: masquerade 10.9.0.0/24 -> $WAN"
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$WAN" -j MASQUERADE
# Explicitly allow forwarding to/from the tunnel (FORWARD policy is normally
# ACCEPT inside a container netns, but be explicit).
iptables -A FORWARD -s 10.9.0.0/24 -j ACCEPT
iptables -A FORWARD -d 10.9.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

exec run-server.sh
