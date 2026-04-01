#!/bin/sh
# Hermetic Installer
# https://hermeticsys.com
#
# Usage: curl -fsSL https://hermeticsys.com/install.sh | sh
#    or: curl -fsSL https://raw.githubusercontent.com/hermetic-sys/hermetic/main/scripts/install.sh | sh
#
# Respects: HERMETIC_INSTALL_DIR (default: /usr/local/bin or ~/.local/bin)

set -e

REPO="hermetic-sys/hermetic"
BINARY="hermetic"

# ── Parse flags ──
VERIFY=false
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=true ;;
  esac
done

# ── Colors (if terminal supports them) ──
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  GREEN='' RED='' YELLOW='' CYAN='' BOLD='' NC=''
fi

info()  { printf "${CYAN}${BOLD}=>${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}${BOLD} ✓${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}${BOLD} !${NC} %s\n" "$1"; }
fail()  { printf "${RED}${BOLD} ✗${NC} %s\n" "$1"; exit 1; }

# ── Platform check ──
OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" != "Linux" ]; then
  fail "Hermetic V1 requires Linux. You have: $OS"
fi

if [ "$ARCH" != "x86_64" ]; then
  fail "Hermetic V1 requires x86_64. You have: $ARCH"
fi

ok "Platform: Linux $ARCH"

# ── Check dependencies ──
for cmd in curl tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fail "Required: $cmd (install with your package manager)"
  fi
done

# ── Determine install directory ──
if [ -n "$HERMETIC_INSTALL_DIR" ]; then
  INSTALL_DIR="$HERMETIC_INSTALL_DIR"
elif [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

# ── Check for existing installation ──
if command -v hermetic >/dev/null 2>&1; then
  CURRENT=$(hermetic version 2>/dev/null | head -1 || echo "unknown")
  warn "Existing installation: $CURRENT"
  info "Upgrading..."
fi

# ── Get latest release ──
info "Finding latest release..."

RELEASE_URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | \
  grep -o '"browser_download_url": *"[^"]*linux-x86_64\.tar\.gz"' | \
  grep -o 'https://[^"]*' | head -1)

if [ -z "$RELEASE_URL" ]; then
  # Fallback: try to construct URL from latest tag
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | \
    grep -o '"tag_name": *"[^"]*"' | grep -o 'v[^"]*' | head -1)

  if [ -z "$TAG" ]; then
    fail "Could not find latest release. Check: https://github.com/$REPO/releases"
  fi

  VERSION=${TAG#v}
  RELEASE_URL="https://github.com/$REPO/releases/download/$TAG/hermetic-${VERSION}-linux-x86_64.tar.gz"
fi

info "Downloading: $RELEASE_URL"

# ── Download and extract ──
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if ! curl -fsSL "$RELEASE_URL" -o "$TMPDIR/hermetic.tar.gz"; then
  fail "Download failed. Check your network and try again."
fi

cd "$TMPDIR"
tar xzf hermetic.tar.gz

if [ ! -f "$TMPDIR/hermetic" ]; then
  fail "Archive does not contain 'hermetic' binary"
fi

chmod +x "$TMPDIR/hermetic"

# ── Verify binary runs ──
if ! "$TMPDIR/hermetic" version >/dev/null 2>&1; then
  fail "Binary verification failed — may be incompatible with your system"
fi

# ── Install ──
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMPDIR/hermetic" "$INSTALL_DIR/"
else
  info "Need sudo to install to $INSTALL_DIR"
  sudo mv "$TMPDIR/hermetic" "$INSTALL_DIR/"
fi

ok "Installed to $INSTALL_DIR/hermetic"

# ── GPG signature verification (--verify) ──
if [ "$VERIFY" = true ]; then
  info "Verifying GPG signature..."

  if ! command -v gpg >/dev/null 2>&1; then
    warn "gpg not found — cannot verify signature"
    warn "Install gnupg to enable verification"
  else
    curl -sSL -o "${TMPDIR}/hermetic.tar.gz.asc" \
      "${RELEASE_URL}.asc" 2>/dev/null || true
    curl -sSL -o "${TMPDIR}/SIGNING_KEY.pub" \
      "https://raw.githubusercontent.com/hermetic-sys/hermetic/main/SIGNING_KEY.pub" 2>/dev/null || true

    if [ -f "${TMPDIR}/hermetic.tar.gz.asc" ] && [ -f "${TMPDIR}/SIGNING_KEY.pub" ]; then
      gpg --batch --import "${TMPDIR}/SIGNING_KEY.pub" 2>/dev/null
      if gpg --batch --verify "${TMPDIR}/hermetic.tar.gz.asc" "${TMPDIR}/hermetic.tar.gz" 2>/dev/null; then
        ok "GPG signature verified"
      else
        fail "GPG signature verification FAILED — binary may have been tampered with"
      fi
    else
      warn "Signature not available (release may not be signed yet)"
      warn "Continuing without verification..."
    fi
  fi
fi

# ── Verify PATH ──
if ! command -v hermetic >/dev/null 2>&1; then
  warn "$INSTALL_DIR is not in your PATH"
  warn "Add this to your shell profile:"
  warn "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

# ── Show version ──
echo ""
"$INSTALL_DIR/hermetic" version 2>/dev/null || true
echo ""

# ── Run doctor ──
info "Running diagnostics..."
"$INSTALL_DIR/hermetic" doctor 2>/dev/null || true
echo ""

# ── Success ──
printf "${GREEN}${BOLD}"
cat << 'BANNER'
╔══════════════════════════════════════════════╗
║  Hermetic installed successfully!              ║
╚══════════════════════════════════════════════╝
BANNER
printf "${NC}"
echo ""
echo "  Quick start:"
echo "    hermetic init --quickstart     # One-command setup"
echo "    hermetic scan .                # Find exposed API keys"
echo "    hermetic add --wizard --batch  # Add multiple keys at once"
echo ""
echo "  100 service templates · 31 subcommands · agent-isolated"
echo ""
echo "  Documentation: https://hermeticsys.com/docs"
echo "  Source:         https://github.com/$REPO"
echo ""
