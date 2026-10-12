#!/usr/bin/env bash
# Enable OPTIONAL path-level (URL) blocking: install the local CA into the
# system trust store and start the filtering proxy. You still need to point
# your browser/system HTTP+HTTPS proxy at 127.0.0.1:8080 (instructions printed
# at the end).
#
# This is only needed for rules that contain a path, e.g. x.com/elonmusk/*.
# Plain domain/subdomain blocking does NOT need the proxy or the CA.
set -euo pipefail

CA_SRC="/etc/blocker/ca.crt"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root:  sudo $0"
    exit 1
fi

# The proxy generates the CA on first start; make sure it exists.
if [[ ! -f "$CA_SRC" ]]; then
    msg "Generating the local CA (starting the proxy once)…"
    systemctl start blocker-proxy 2>/dev/null || true
    sleep 1
fi
if [[ ! -f "$CA_SRC" ]]; then
    echo "Could not find $CA_SRC. Start the proxy once with: blocker-proxy"
    exit 1
fi

msg "Trusting the local CA…"
"$HERE/trust-ca.sh"

msg "Enabling and starting the proxy service…"
systemctl enable --now blocker-proxy

cat <<'EOF'

==> Path-level blocking is armed and the CA is trusted (see above for the
    per-browser step).

One thing remains: point your system / browser proxy at the filter.

   GNOME (most desktops):
     gsettings set org.gnome.system.proxy mode 'manual'
     gsettings set org.gnome.system.proxy.http  host '127.0.0.1'
     gsettings set org.gnome.system.proxy.http  port 8080
     gsettings set org.gnome.system.proxy.https host '127.0.0.1'
     gsettings set org.gnome.system.proxy.https port 8080

   Or, for terminal apps, add to your shell profile:
     export http_proxy=http://127.0.0.1:8080
     export https_proxy=http://127.0.0.1:8080

Domain and subdomain blocking work WITHOUT any of the above — this is only for
path rules on HTTPS sites.
EOF
