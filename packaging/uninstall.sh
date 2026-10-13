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
# Stopping the daemon triggers its own cleanup (resolv.conf + hosts + nftables).
sleep 1

# Belt-and-braces: remove the network-filter nftables rules in case the daemon
# was killed hard and could not clean up after itself.
nft delete table inet blocker_nf 2>/dev/null || true

# Remove the CA from the system trust store if the proxy was ever enabled.
if command -v update-ca-certificates >/dev/null 2>&1; then
    rm -f /usr/local/share/ca-certificates/blocker.crt
    update-ca-certificates --fresh >/dev/null 2>&1 || true
elif command -v update-ca-trust >/dev/null 2>&1; then
    rm -f /etc/pki/ca-trust/source/anchors/blocker.crt
    update-ca-trust >/dev/null 2>&1 || true
fi

msg "Removing files…"
rm -f /usr/local/bin/blockerd /usr/local/bin/blocker-gui /usr/local/bin/blocker-proxy /usr/local/bin/blocker-tray
rm -f /etc/systemd/system/blockerd.service /etc/systemd/system/blocker-proxy.service
rm -f /usr/share/applications/blocker-gui.desktop
rm -f /etc/xdg/autostart/blocker-tray.desktop
systemctl daemon-reload || true

msg "Belt-and-braces: ensuring resolv.conf / hosts are clean…"
# Only touch resolv.conf if it is still OUR managed file (daemon didn't restore).
if grep -q 'Managed by blocker' /etc/resolv.conf 2>/dev/null; then
    rm -f /etc/resolv.conf
    if [[ -f /etc/blocker/resolv.conf.backup ]]; then
        cp /etc/blocker/resolv.conf.backup /etc/resolv.conf
    elif [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    else
        printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
    fi
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
