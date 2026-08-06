#!/bin/sh
# Subnet-router client for the mesh test.
#
# Hosts the "LAN" it advertises directly on lo — a /32 and a /128 are enough to
# answer pings arriving over the tunnel, with no dummy module, forwarding, or
# masquerade needed. Advertises the two prefixes the allowlist expects plus one
# (192.168.201.0/24) the allowlist deliberately omits, so the driver can assert
# approval gating in both modes.
#
# Adverts ride the keepalive tick, so a short keepalive keeps the test fast.
set -eu

ip addr add 192.168.200.1/32 dev lo
ip -6 addr add fd42:cafe::1/128 dev lo

echo "[router] advertising 192.168.200.0/24, fd42:cafe::/64, 192.168.201.0/24"
exec shadowvpn-client -c /etc/shadowvpn/client.json ${CIPHER:+--cipher "$CIPHER"} \
    --tun-ip 10.77.0.2 --peer-ip 10.77.0.1 --tun-ip6 fd07:7::2/64 \
    --keepalive-secs 2 \
    --advertise-routes 192.168.200.0/24,fd42:cafe::/64,192.168.201.0/24
