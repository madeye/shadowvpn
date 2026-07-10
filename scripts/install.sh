#!/usr/bin/env bash
# ShadowVPN one-line installer / uninstaller (Linux + macOS).
#
#   install server:   curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- server
#   install client:   curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- client
#   uninstall server: curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall server
#   uninstall client: curl -fsSL https://raw.githubusercontent.com/madeye/shadowvpn/main/scripts/install.sh | sudo bash -s -- uninstall client
#
# Options (after the role):
#   --service   also install the service definition (systemd unit / launchd
#               plist) from the release package — installed, not enabled
#   --purge     uninstall only: also remove /etc/shadowvpn configs
#
# Environment overrides:
#   SHADOWVPN_VERSION  release tag to install (e.g. v0.4.0; default: latest)
#   PREFIX             install prefix (default /usr/local). With a non-root
#                      PREFIX no sudo is needed; configs/services are skipped.
#
# Windows has no curl|bash flow — use the release .zip (client + wintun.dll
# bundled): https://github.com/madeye/shadowvpn/releases
set -euo pipefail

REPO="madeye/shadowvpn"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
ETC_DIR="/etc/shadowvpn"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
usage: install.sh <server|client> [--service]
       install.sh uninstall <server|client|all> [--purge]

  --service   also install the service definition (systemd unit / launchd
              plist) from the release package — installed, not enabled
  --purge     uninstall only: also remove /etc/shadowvpn configs

environment:
  SHADOWVPN_VERSION  release tag to install (e.g. v0.4.0; default: latest)
  PREFIX             install prefix (default /usr/local); a user-writable
                     PREFIX needs no sudo (configs/services are skipped)
EOF
  exit 1
}

# ---------- argument parsing ----------------------------------------------

ACTION=install ROLE="" SERVICE=0 PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    server|client) ROLE="$1" ;;
    uninstall)     ACTION=uninstall ;;
    all)           ROLE=all ;;
    --service)     SERVICE=1 ;;
    --purge)       PURGE=1 ;;
    -h|--help)     usage ;;
    *)             die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
[ -n "$ROLE" ] || usage
[ "$ROLE" = all ] && [ "$ACTION" = install ] && die "'all' is only valid with uninstall"

# ---------- platform detection --------------------------------------------

OS=$(uname -s)
case "$OS" in
  Linux)  SYS=linux;  TARGET_OS=unknown-linux-gnu ;;
  Darwin) SYS=darwin; TARGET_OS=apple-darwin ;;
  *) die "unsupported OS: $OS (Windows: use the release .zip — https://github.com/$REPO/releases)" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "unsupported CPU architecture: $ARCH" ;;
esac
TARGET="$ARCH-$TARGET_OS"

# Root is needed for the default prefix and for configs/services; a custom
# user-writable PREFIX works without sudo (configs/services are skipped).
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
if [ "$IS_ROOT" = 0 ] && [ ! -w "$BIN_DIR" ] && ! mkdir -p "$BIN_DIR" 2>/dev/null; then
  die "cannot write $BIN_DIR — re-run with sudo, or set PREFIX to a writable directory"
fi

# ---------- uninstall -------------------------------------------------------

remove_service() { # role
  local role="$1"
  if [ "$SYS" = linux ] && command -v systemctl >/dev/null 2>&1; then
    local unit="shadowvpn-$role.service"
    if [ -f "/etc/systemd/system/$unit" ]; then
      say "removing systemd unit $unit"
      systemctl disable --now "$unit" 2>/dev/null || true
      rm -f "/etc/systemd/system/$unit"
      systemctl daemon-reload 2>/dev/null || true
    fi
  elif [ "$SYS" = darwin ] && [ "$role" = client ]; then
    local plist="/Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist"
    if [ -f "$plist" ]; then
      say "removing launchd daemon"
      launchctl unload -w "$plist" 2>/dev/null || true
      rm -f "$plist"
    fi
  fi
}

uninstall_role() { # role
  local role="$1"
  [ "$IS_ROOT" = 1 ] && remove_service "$role"
  say "removing $BIN_DIR/shadowvpn-$role"
  rm -f "$BIN_DIR/shadowvpn-$role"
  if [ "$role" = client ]; then
    # bundled policy data + DNS cache live next to the binary
    rm -f "$BIN_DIR/gfwlist.txt" "$BIN_DIR/GeoLite2-Country.mmdb" "$BIN_DIR/dns-cache.json"
  fi
  if [ "$PURGE" = 1 ] && [ -f "$ETC_DIR/$role.json" ]; then
    say "purging $ETC_DIR/$role.json"
    rm -f "$ETC_DIR/$role.json"
    rmdir "$ETC_DIR" 2>/dev/null || true
  fi
}

if [ "$ACTION" = uninstall ]; then
  if [ "$ROLE" = all ]; then uninstall_role server; uninstall_role client
  else uninstall_role "$ROLE"; fi
  if [ "$PURGE" = 1 ]; then say "done."
  else say "done (configs in $ETC_DIR were kept; add --purge to remove them)."
  fi
  exit 0
fi

# ---------- resolve version & download -------------------------------------

VERSION="${SHADOWVPN_VERSION:-}"
if [ -z "$VERSION" ]; then
  say "resolving latest release"
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || die "could not determine the latest release tag"
fi
VER="${VERSION#v}"

NAME="shadowvpn-$VER-$TARGET"
URL="https://github.com/$REPO/releases/download/$VERSION/$NAME.tar.gz"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "downloading $NAME.tar.gz"
curl -fsSL "$URL" -o "$TMP/pkg.tar.gz" ||
  die "download failed: $URL (does release $VERSION have a $TARGET build?)"
tar -xzf "$TMP/pkg.tar.gz" -C "$TMP"
PKG="$TMP/$NAME"
[ -x "$PKG/shadowvpn-$ROLE" ] || die "shadowvpn-$ROLE not found in the release package"

# ---------- install ---------------------------------------------------------

say "installing shadowvpn-$ROLE $VERSION to $BIN_DIR"
install -m 755 "$PKG/shadowvpn-$ROLE" "$BIN_DIR/shadowvpn-$ROLE"

if [ "$ROLE" = client ] && [ -f "$PKG/gfwlist.txt" ]; then
  # next to the binary, where policy routing auto-discovers it
  install -m 644 "$PKG/gfwlist.txt" "$BIN_DIR/gfwlist.txt"
fi

# Example config (root only; never overwrites an existing one).
if [ "$IS_ROOT" = 1 ] && [ ! -f "$ETC_DIR/$ROLE.json" ]; then
  say "writing example config $ETC_DIR/$ROLE.json (edit it before starting!)"
  mkdir -p "$ETC_DIR"
  if [ "$ROLE" = server ]; then
    cat > "$ETC_DIR/server.json" <<'EOF'
{
  "server": "0.0.0.0:8388",
  "password": "CHANGE-ME",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.1",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.2",
  "mtu": 1400
}
EOF
  else
    cat > "$ETC_DIR/client.json" <<'EOF'
{
  "server": "vpn.example.com:8388",
  "password": "CHANGE-ME",
  "cipher": "chacha20-poly1305",
  "tun_ip": "10.9.0.2",
  "tun_netmask": "255.255.255.0",
  "peer_ip": "10.9.0.1",
  "mtu": 1400
}
EOF
  fi
  chmod 600 "$ETC_DIR/$ROLE.json"
fi

# Optional service definition — installed, not enabled.
if [ "$SERVICE" = 1 ]; then
  if [ "$IS_ROOT" != 1 ]; then
    warn "--service needs root; skipped"
  elif [ "$SYS" = linux ] && [ -f "$PKG/systemd/shadowvpn-$ROLE.service" ]; then
    say "installing systemd unit (not enabled)"
    install -m 644 "$PKG/systemd/shadowvpn-$ROLE.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    SERVICE_HINT="sudo systemctl enable --now shadowvpn-$ROLE"
  elif [ "$SYS" = darwin ] && [ "$ROLE" = client ] && [ -f "$PKG/launchd/io.github.madeye.shadowvpn-client.plist" ]; then
    say "installing launchd daemon (not loaded)"
    install -m 644 "$PKG/launchd/io.github.madeye.shadowvpn-client.plist" /Library/LaunchDaemons/
    SERVICE_HINT="sudo launchctl load -w /Library/LaunchDaemons/io.github.madeye.shadowvpn-client.plist"
  else
    warn "no service definition for $ROLE on $SYS; skipped"
  fi
fi

say "installed: $BIN_DIR/shadowvpn-$ROLE ($VERSION, $TARGET)"
echo
echo "next steps:"
if [ "$IS_ROOT" = 1 ]; then
  echo "  1. edit $ETC_DIR/$ROLE.json (set the password on BOTH ends)"
  echo "  2. run:  sudo $BIN_DIR/shadowvpn-$ROLE -c $ETC_DIR/$ROLE.json"
else
  echo "  1. create a $ROLE.json config (set the password on BOTH ends)"
  echo "  2. run:  sudo $BIN_DIR/shadowvpn-$ROLE -c $ROLE.json"
fi
[ -n "${SERVICE_HINT:-}" ] && echo "  3. or as a service:  $SERVICE_HINT"
echo
echo "docs: https://madeye.github.io/shadowvpn/"
