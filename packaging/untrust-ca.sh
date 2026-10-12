#!/usr/bin/env bash
# Remove the Blocker local CA from the system trust store.
set -euo pipefail

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root:  sudo $0"
    exit 1
fi

msg "Removing the Blocker CA from the system trust store…"
if command -v update-ca-certificates >/dev/null 2>&1; then
    rm -f /usr/local/share/ca-certificates/blocker.crt
    update-ca-certificates --fresh || update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
    rm -f /etc/pki/ca-trust/source/anchors/blocker.crt
    update-ca-trust
fi

cat <<'EOF'

==> Done. If you added the CA to a browser's own store, remove it there too:

   Chrome/Chromium NSS (as your user):
     certutil -d sql:$HOME/.pki/nssdb -D -n "Blocker CA"
   Firefox: set security.enterprise_roots.enabled back to false if you wish.
EOF
