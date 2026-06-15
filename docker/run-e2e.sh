#!/usr/bin/env bash
# Run the ShadowVPN Docker end-to-end test.
#
# Builds the image, starts the server + client containers, and reports the
# client's pass/fail as this script's exit code. Optionally takes a cipher name
# as the first argument (default: chacha20-poly1305) so it can be driven over a
# matrix:
#
#   ./docker/run-e2e.sh aes-256-gcm
#
set -euo pipefail

cd "$(dirname "$0")"

CIPHER="${1:-${CIPHER:-chacha20-poly1305}}"
export CIPHER

# Prefer the Compose v2 plugin (`docker compose`); fall back to the standalone
# `docker-compose` binary when the plugin isn't wired into the active CLI.
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

cleanup() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> ShadowVPN Docker E2E test (cipher=${CIPHER})"

# Start from a clean slate in case a previous run was interrupted.
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true

# `--exit-code-from client` makes the compose run return the client (test)
# container's exit code, and implies `--abort-on-container-exit` so the server
# is torn down as soon as the test finishes.
$COMPOSE up --build --abort-on-container-exit --exit-code-from client
