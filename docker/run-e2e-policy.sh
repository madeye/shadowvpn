#!/usr/bin/env bash
# Run the ShadowVPN policy-routing E2E test for one or more modes.
#
#   ./docker/run-e2e-policy.sh                # both gfwlist and chinadns
#   ./docker/run-e2e-policy.sh gfwlist        # just one mode
#
# For each mode it verifies that a gfwlisted/foreign domain is routed through the
# tunnel while a direct/domestic domain is not. The client container's exit code
# is the test result.
set -euo pipefail

cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose -f docker-compose.policy.yml"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose -f docker-compose.policy.yml"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

MODES=("$@")
if [ "${#MODES[@]}" -eq 0 ]; then
    MODES=(gfwlist chinadns)
fi

cleanup() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

for mode in "${MODES[@]}"; do
    echo "==> ShadowVPN policy-routing E2E test (mode=${mode})"
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    MODE="$mode" $COMPOSE up --build --abort-on-container-exit --exit-code-from client
    echo "==> mode=${mode} PASSED"
done

echo "==> all policy-routing modes passed"
