#!/usr/bin/env bash
# Run the ShadowVPN netem benchmark.
#
# Builds the bench image, starts the server + client on a shaped private link,
# and prints the client's summary table. The client's pass/fail becomes this
# script's exit code.
#
# Scenario knobs come from the environment (defaults emulate a ~100 Mbit
# broadband path with light loss):
#
#   CIPHER   AEAD cipher           (default chacha20-poly1305)
#   OBFS     carrier framing       (default none; e.g. quic, base64)
#   MTU      tunnel MTU            (default 1400)
#   DELAY    one-way latency       (default 20ms; RTT ~ 2x this)
#   JITTER   latency variation     (default 5ms)
#   LOSS     packet loss           (default 0.05%)
#   RATE     bandwidth cap         (default 100mbit)
#   DURATION seconds per stream    (default 10)
#   UDP_RATE offered UDP load      (default 50M)
#
# Examples:
#   docker/run-bench.sh
#   OBFS=quic CIPHER=aes-256-gcm docker/run-bench.sh
#   DELAY=80ms LOSS=1% RATE=20mbit docker/run-bench.sh   # lossy mobile-ish link
set -euo pipefail

cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.bench.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.bench.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> ShadowVPN benchmark"
echo "    cipher=${CIPHER:-chacha20-poly1305} obfs=${OBFS:-none} mtu=${MTU:-1400}"
echo "    netem: delay=${DELAY:-20ms} jitter=${JITTER:-5ms} loss=${LOSS:-0.05%} rate=${RATE:-100mbit}"

$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up --build --abort-on-container-exit --exit-code-from client
