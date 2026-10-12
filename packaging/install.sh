#!/usr/bin/env bash
# Build and install Blocker (daemon + GUI) on a Linux system with systemd.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="/usr/local/bin"
UNIT_DIR="/etc/systemd/system"
DESKTOP_DIR="/usr/share/applications"

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root:  sudo $0"
    exit 1
fi

# The non-root user who should be allowed to control the daemon.
TARGET_USER="${SUDO_USER:-}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    warn "Could not detect your normal login user from \$SUDO_USER."
    warn "After install, add your user to the 'blocker' group manually:"
    warn "    sudo usermod -aG blocker <your-user>"
fi

msg "Building release binaries (this can take a few minutes)…"
if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo (Rust) is required. Install from https://rustup.rs and retry."
    exit 1
fi
# Build as the invoking user when possible to reuse their cargo cache.
if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    sudo -u "$TARGET_USER" bash -lc "cd '$REPO_ROOT' && cargo build --release"
else
    (cd "$REPO_ROOT" && cargo build --release)
fi

msg "Creating 'blocker' control group…"
groupadd -f blocker
if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    usermod -aG blocker "$TARGET_USER"
    msg "Added '$TARGET_USER' to the 'blocker' group."
fi

msg "Installing binaries to $BIN_DIR…"
install -m 0755 "$REPO_ROOT/target/release/blockerd"   "$BIN_DIR/blockerd"
install -m 0755 "$REPO_ROOT/target/release/blocker-gui" "$BIN_DIR/blocker-gui"

msg "Installing systemd unit…"
install -m 0644 "$REPO_ROOT/packaging/blockerd.service" "$UNIT_DIR/blockerd.service"

msg "Installing desktop launcher…"
install -d "$DESKTOP_DIR"
install -m 0644 "$REPO_ROOT/packaging/blocker-gui.desktop" "$DESKTOP_DIR/blocker-gui.desktop"

msg "Enabling and starting the daemon…"
systemctl daemon-reload
systemctl enable --now blockerd.service

echo
msg "Done."
echo "  • Daemon status:   systemctl status blockerd"
echo "  • CLI check:       blockerd status"
echo "  • Launch the GUI:  blocker-gui   (or from your app menu)"
echo
if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    warn "Log out and back in (or run 'newgrp blocker') so your new group"
    warn "membership takes effect before launching the GUI."
fi
