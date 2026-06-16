#!/bin/sh
# Authoritative-ish DNS for the policy-routing E2E test.
#
# Maps the two test domains onto the two echo servers. The client's split-DNS
# proxy uses this as both its local and remote upstream, so the routing decision
# (tunnel vs direct) is made purely by the policy logic, not by the answers.
set -eu
exec dnsmasq -k -p 53 --no-resolv --no-hosts \
    --address=/blocked.com/172.30.0.5 \
    --address=/safe.com/172.30.0.6
