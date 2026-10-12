#!/usr/bin/env bash
# Disable path-level blocking: stop the proxy and remove the CA from the system
# trust store. Remember to also turn off the manual proxy in your desktop /
# browser settings (and remove the CA from the browser's own store if you added
# it there with certutil).
set -euo pipefail

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root:  sudo $0"
    exit 1
fi

msg "Stopping the proxy service…"
systemctl disable --now blocker-proxy 2>/dev/null || true

msg "Removing the Blocker CA from the system trust store…"
if command -v update-ca-certificates >/dev/null 2>&1; then
    rm -f /usr/local/share/ca-certificates/blocker.crt
    update-ca-certificates --fresh || update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
    rm -f /etc/pki/ca-trust/source/anchors/blocker.crt
    update-ca-trust
fi

cat <<'EOF'

==> Proxy disabled. Don't forget to undo the manual proxy setting:

   GNOME:  gsettings set org.gnome.system.proxy mode 'none'
   Shell:  unset http_proxy https_proxy  (and remove from your profile)

   Chrome/Chromium NSS (as your user):
     certutil -d sql:$HOME/.pki/nssdb -D -n "Blocker CA"
EOF
