#!/usr/bin/env bash
# Run the ShadowVPN HTTP/3-over-tunnel end-to-end test.
#
# Builds the image, brings up a NAT-ing server and a client, and verifies that an
# HTTP/3 (QUIC) request to a real site succeeds *through* the tunnel. The client
# container's exit code is the test result.
#
# Optional args/env:
#   $1 / CIPHER     - cipher to use (default: chacha20-poly1305)
#   TARGET_URL      - QUIC URL to fetch (default: https://www.cloudflare-quic.com/)
#
#   ./docker/run-e2e-http3.sh aes-256-gcm
#
set -euo pipefail

cd "$(dirname "$0")"

CIPHER="${1:-${CIPHER:-chacha20-poly1305}}"
export CIPHER
export TARGET_URL="${TARGET_URL:-https://www.cloudflare-quic.com/}"

# Prefer the Compose v2 plugin; fall back to the standalone binary.
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.http3.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.http3.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> ShadowVPN HTTP/3 E2E test (cipher=${CIPHER}, url=${TARGET_URL})"

$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up --build --abort-on-container-exit --exit-code-from client
