#!/usr/bin/env bash
# Regenerate assets/gfwlist.txt from the canonical AutoProxy gfwlist.
#
# The bundled gfwlist is the domain-suffix list for gfwlist mode (and the
# optional chinadns force-tunnel override): names matching a suffix here take
# the clean tunneled path. See src/policy/gfwlist.rs for the file format. We
# fetch the upstream AutoProxy list (base64), decode it, and reduce it to a
# plain domain-per-line file — the shape `GfwList::from_lines` expects. `||`,
# `|`, scheme, path, wildcard, and `@@` exception rules are stripped/dropped;
# regex rules are skipped.
#
# Usage: scripts/gen-gfwlist.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT="$ROOT/assets/gfwlist.txt"
SRC_URL="https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> fetching $SRC_URL"
curl -fsSL "$SRC_URL" -o "$TMP/gfwlist.b64"

echo "==> decoding base64"
base64 -D -i "$TMP/gfwlist.b64" -o "$TMP/gfwlist.raw" 2>/dev/null \
    || base64 -d "$TMP/gfwlist.b64" > "$TMP/gfwlist.raw"

echo "==> reducing to plain domains"
python3 - "$TMP/gfwlist.raw" "$TMP/gfwlist.clean" <<'PY'
import re, sys

src, dst = sys.argv[1], sys.argv[2]
domains = set()
host_re = re.compile(r'^[a-z0-9.-]+$')

def add(host):
    host = host.strip().strip('.').lower().split(':', 1)[0]
    if not host or '.' not in host or not host_re.match(host):
        return
    if host.replace('.', '').isdigit():  # bare IP
        return
    tld = host.rsplit('.', 1)[-1]
    if not tld.isalpha() or len(tld) < 2:
        return
    domains.add(host)

for raw in open(src, encoding='utf-8', errors='replace'):
    line = raw.strip()
    if not line or line[0] in '![':
        continue
    if line.startswith('@@'):           # whitelist/exception rule
        continue
    if line.startswith('/') and line.endswith('/'):  # regex rule
        continue
    s = line
    if s.startswith('||'):
        s = s[2:]
    elif s.startswith('|'):
        s = s[1:]
    if s.endswith('|'):
        s = s[:-1]
    s = re.sub(r'^[a-zA-Z]+://', '', s)  # scheme
    s = s.lstrip('*').lstrip('.')
    s = re.split(r'[/*?#]', s, maxsplit=1)[0]
    add(s)

with open(dst, 'w') as f:
    f.write('\n'.join(sorted(domains)) + '\n')
print(f"extracted {len(domains)} domains")
PY

echo "==> writing $OUT"
{
    cat <<'HDR'
# gfwlist domain-suffix list — bundled next to the shadowvpn-client binary.
#
# One domain per line; '#' and '!' lines and blanks are ignored. In gfwlist
# mode, names matching a suffix here (or any subdomain of it) are tunneled and
# everything else goes direct; in chinadns mode this is an optional
# force-tunnel override. See src/policy/gfwlist.rs for the format. The client
# auto-discovers this file when it sits next to the executable and no --gfwlist
# path is configured.
#
# Source: github.com/gfwlist/gfwlist (AutoProxy gfwlist, LGPL-2.1), decoded from
# base64 and reduced to plain domains (gfwlist2dnsmasq-style: '||', '|', scheme,
# path, wildcard, and '@@' exception rules stripped/dropped). Regenerate with
# scripts/gen-gfwlist.sh.
HDR
    cat "$TMP/gfwlist.clean"
} > "$OUT"

echo "==> wrote $(grep -c -v '^#' "$OUT") domains to $OUT"
