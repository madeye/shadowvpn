#!/bin/sh
# Shared helpers for the ShadowVPN netem benchmark, sourced by bench-server.sh
# and bench-client.sh. POSIX sh (the image's /bin/sh is dash).

# Print the WAN interface — the one carrying the default route (the encrypted
# UDP carrier rides it), falling back to eth0 on a plain docker bridge.
wan_iface() {
    iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    [ -n "$iface" ] && printf '%s\n' "$iface" || printf 'eth0\n'
}

# Apply a netem qdisc to $1 (the WAN iface) emulating a real internet path from
# the DELAY/JITTER/LOSS/RATE environment. netem shapes egress only, so when both
# containers apply it the link is shaped symmetrically and the round-trip delay
# is ~2×DELAY. Empty/zero knobs are omitted so netem doesn't choke on them.
apply_netem() {
    iface="$1"
    netem="delay ${DELAY:-20ms}"
    if [ -n "${JITTER:-}" ] && [ "${JITTER}" != "0" ]; then
        netem="${netem} ${JITTER} distribution normal"
    fi
    if [ -n "${LOSS:-}" ] && [ "${LOSS}" != "0" ]; then
        netem="${netem} loss ${LOSS}"
    fi
    if [ -n "${RATE:-}" ]; then
        netem="${netem} rate ${RATE}"
    fi
    # Replace any existing root qdisc so re-runs are idempotent.
    tc qdisc replace dev "$iface" root netem ${netem}
    echo "[netem] ${iface}: ${netem}"
}

# Write a ShadowVPN JSON config to $1 for the given role ($2 = server|client).
# Pulls cipher/obfs/mtu/addresses from the environment so one image covers the
# whole scenario matrix without baking configs into the image.
write_config() {
    out="$1"
    role="$2"
    cipher="${CIPHER:-chacha20-poly1305}"
    mtu="${MTU:-1400}"
    # `obfs` is config-only (no CLI flag); omit the line entirely when OBFS=none
    # so the plain salt++AEAD envelope is used.
    obfs_line=""
    if [ -n "${OBFS:-}" ] && [ "${OBFS}" != "none" ]; then
        obfs_line="  \"obfs\": \"${OBFS}\","
    fi
    if [ "$role" = "server" ]; then
        server_addr="0.0.0.0:8388"
        tun_ip="10.9.0.1"
        peer_ip="10.9.0.2"
    else
        server_addr="${SERVER_HOST:-server}:8388"
        tun_ip="10.9.0.2"
        peer_ip="10.9.0.1"
    fi
    cat >"$out" <<EOF
{
  "server": "${server_addr}",
  "password": "shadowvpn-bench-password",
  "cipher": "${cipher}",
${obfs_line}
  "tun_name": "tun0",
  "tun_ip": "${tun_ip}",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "${peer_ip}",
  "mtu": ${mtu}
}
EOF
    # Drop the blank line left when obfs is omitted, keeping the JSON tidy.
    sed -i '/^$/d' "$out"
    echo "[config] ${role}: cipher=${cipher} obfs=${OBFS:-none} mtu=${mtu}"
}
