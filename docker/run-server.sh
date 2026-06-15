#!/bin/sh
# Entry point for the server container in the E2E test.
#
# Runs the ShadowVPN server from its JSON config. When the CIPHER environment
# variable is set it overrides the cipher in the config, so the same image can
# be exercised against every supported cipher from a CI matrix.
set -eu

exec shadowvpn-server -c /etc/shadowvpn/server.json ${CIPHER:+--cipher "$CIPHER"}
