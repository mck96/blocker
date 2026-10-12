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

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root:  sudo $0"
    exit 1
fi

# The proxy generates the CA on first start; make sure it exists.
if [[ ! -f "$CA_SRC" ]]; then
    msg "Generating the local CA (starting the proxy once)…"
    systemctl start blocker-proxy || /usr/local/bin/blocker-proxy --ca-path >/dev/null 2>&1 || true
    sleep 1
fi
if [[ ! -f "$CA_SRC" ]]; then
    echo "Could not find $CA_SRC. Start the proxy once with: blocker-proxy"
    exit 1
fi

msg "Installing the Blocker CA into the system trust store…"
if command -v update-ca-certificates >/dev/null 2>&1; then
    # Debian / Ubuntu
    install -D -m 0644 "$CA_SRC" /usr/local/share/ca-certificates/blocker.crt
    update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
    # Fedora / RHEL / Arch
    install -D -m 0644 "$CA_SRC" /etc/pki/ca-trust/source/anchors/blocker.crt
    update-ca-trust
else
    warn "Unknown trust-store tooling; install $CA_SRC into your system CA store manually."
fi

msg "Enabling and starting the proxy service…"
systemctl enable --now blocker-proxy

cat <<'EOF'

==> Path-level blocking is now armed. Two things remain (one-time):

1) Point your system / browser proxy at the filter:

   GNOME (most desktops):
     gsettings set org.gnome.system.proxy mode 'manual'
     gsettings set org.gnome.system.proxy.http  host '127.0.0.1'
     gsettings set org.gnome.system.proxy.http  port 8080
     gsettings set org.gnome.system.proxy.https host '127.0.0.1'
     gsettings set org.gnome.system.proxy.https port 8080

   Or, for terminal apps, add to your shell profile:
     export http_proxy=http://127.0.0.1:8080
     export https_proxy=http://127.0.0.1:8080

2) Make your browser trust the CA (browsers often use their own store):

   Firefox:  Settings -> Privacy & Security -> Certificates ->
             enable "Query OCSP…"? no — set about:config
             security.enterprise_roots.enabled = true   (trusts the system CA)

   Chrome/Chromium (NSS), run AS YOUR USER (not root):
     certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Blocker CA" -i /etc/blocker/ca.crt

Domain and subdomain blocking work WITHOUT any of the above — this is only for
path rules on HTTPS sites.
EOF
