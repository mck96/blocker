#!/usr/bin/env bash
# Remove Blocker and revert all system changes.
set -euo pipefail

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root:  sudo $0"
    exit 1
fi

msg "Stopping and disabling services…"
systemctl disable --now blocker-proxy.service 2>/dev/null || true
systemctl disable --now blockerd.service 2>/dev/null || true
# Stopping the daemon triggers its own cleanup (resolv.conf + hosts restore).
sleep 1

# Remove the CA from the system trust store if the proxy was ever enabled.
if command -v update-ca-certificates >/dev/null 2>&1; then
    rm -f /usr/local/share/ca-certificates/blocker.crt
    update-ca-certificates --fresh >/dev/null 2>&1 || true
elif command -v update-ca-trust >/dev/null 2>&1; then
    rm -f /etc/pki/ca-trust/source/anchors/blocker.crt
    update-ca-trust >/dev/null 2>&1 || true
fi

msg "Removing files…"
rm -f /usr/local/bin/blockerd /usr/local/bin/blocker-gui /usr/local/bin/blocker-proxy
rm -f /etc/systemd/system/blockerd.service /etc/systemd/system/blocker-proxy.service
rm -f /usr/share/applications/blocker-gui.desktop
systemctl daemon-reload || true

msg "Belt-and-braces: ensuring resolv.conf / hosts are clean…"
# In case the daemon could not restore (e.g. it was killed with -9), fix up.
if [[ -f /etc/blocker/resolv.conf.backup ]]; then
    rm -f /etc/resolv.conf
    cp /etc/blocker/resolv.conf.backup /etc/resolv.conf
fi
# Strip any leftover managed block from /etc/hosts.
if grep -q 'blocker managed block' /etc/hosts 2>/dev/null; then
    sed -i '/>>> blocker managed block >>>/,/<<< blocker managed block <<</d' /etc/hosts
fi

echo
read -rp "Also delete configuration in /etc/blocker? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
    rm -rf /etc/blocker
    msg "Removed /etc/blocker."
fi

msg "Uninstalled. You may remove the 'blocker' group with: sudo groupdel blocker"
