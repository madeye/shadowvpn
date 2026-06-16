#!/bin/sh
# Source-IP echo server for the policy-routing E2E test.
#
# Accepts a TCP connection on port 7 and writes back the peer address it saw.
# Because the VPN server masquerades tunneled traffic, a client reaching this
# host *through the tunnel* shows up as the server's address, while a client
# reaching it *directly* shows up as its own address — which is exactly what the
# test uses to tell the two paths apart.
set -eu
exec socat -T2 TCP-LISTEN:7,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR'
