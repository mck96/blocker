# Blocker

A native **Linux website blocker with a GUI**, in the spirit of
[AppBlock](https://appblock.app/) — but enforced at the operating-system level,
not as a browser extension.

Because blocking happens in a privileged background daemon (not in the
browser), **every browser sees the same result**: Firefox, Chrome, Chromium,
Brave, Epiphany, a `curl` on the command line — all of them. There is nothing
to install per-browser and nothing a browser can disable.

Written in Rust. Three binaries:

| Binary          | Runs as | Job                                                           |
|-----------------|---------|---------------------------------------------------------------|
| `blockerd`      | root    | The engine: a local DNS sinkhole + `/etc/hosts` manager       |
| `blocker-gui`   | you     | A desktop GUI that talks to the daemon over a Unix socket     |
| `blocker-proxy` | root    | *Optional.* Filtering proxy for path rules (HTTPS via a CA)   |

---

## What it can block

* **A whole domain and all its subdomains.**
  Add `youtube.com` and you also block `www.youtube.com`, `m.youtube.com`,
  **and `music.youtube.com`** (so the "YouTube Music" app dies too). This is the
  natural behaviour of the DNS sinkhole.

* **Subdomain wildcards.** `*.reddit.com` is accepted as sugar for the same
  thing (domain + every subdomain).

* **A single exact host.** Prefix with `=`, e.g. `=mail.google.com`, to block
  *only* that host and leave `calendar.google.com` alone.

* **A URL path / profile.** e.g. `x.com/elonmusk/*` or `x.com/elonmusk`.
  Path rules do **not** take down the whole domain — the rest of `x.com` keeps
  working. (Path enforcement needs the optional proxy component; see
  [Path-level blocking](#path-level-blocking-the-honest-part) below for exactly
  what is and isn't possible.)

### Pattern syntax, by example

```
youtube.com            domain + ALL subdomains (incl. music.youtube.com)
*.youtube.com          same as above (the *. is optional sugar)
=mail.google.com       this exact host only, no subdomains
reddit.com/r/all       a path on a host (and all deeper paths)
x.com/elonmusk/*       a path prefix; trailing /* is optional
https://x.com/foo      a scheme is accepted and ignored
```

Lines can be toggled on/off individually in the GUI without deleting them.

---

## How it actually blocks (and why it's cross-browser)

Every normal program on Linux — including every browser in its default
configuration — resolves hostnames through the system resolver. `blockerd`
inserts itself there:

1. It runs a tiny **DNS server on `127.0.0.1:53`**.
2. It points `/etc/resolv.conf` at itself (backing up the original first).
3. For a hostname that matches your blocklist it answers `0.0.0.0` (IPv4) and
   `::` (IPv6) — the connection fails instantly. Everything else is forwarded
   to your real upstream resolvers (auto-detected at startup) and relayed back
   untouched.
4. As a belt-and-braces second layer it also writes the blocked hosts into a
   clearly-marked managed block in **`/etc/hosts`**.

Because this is the OS resolver, the block is identical in every browser and
every app. No extension, no per-browser setup.

### Enforcement modes

* **Always on** — the blocklist is enforced continuously.
* **On a schedule** — enforced only during the weekly time windows you define
  (e.g. Mon–Fri 09:00–17:00, or 22:00–06:00 which correctly wraps past
  midnight).
* **Off** — not enforced (the daemon still runs and resolves normally).

### Focus sessions

Force blocking **on** for a fixed duration regardless of the mode above — a
Pomodoro / deep-work button. Optionally **lock** a session so it cannot be
cancelled early (a commitment device): once locked it only ends when the timer
runs out.

### Strict mode (secure DNS)

Modern browsers can be configured to use their own encrypted DNS (DNS-over-HTTPS
/ DNS-over-TLS), which would bypass the system resolver. **Strict mode** (on by
default) additionally sinkholes the well-known DoH/DoT *bootstrap* hostnames, so
those browsers fall back to the system resolver — which is us. For a 100%
guarantee you should also turn off "Secure DNS" in the browser's settings; the
GUI reminds you of this.

---

## Build

Requires a recent stable Rust toolchain (`rustup` recommended) and, for the GUI,
the usual desktop libraries (X11 or Wayland, present on any normal desktop).

```bash
cargo build --release
# binaries land in target/release/blockerd and target/release/blocker-gui
```

Run the tests:

```bash
cargo test
```

---

## Install (systemd)

```bash
sudo ./packaging/install.sh
```

This builds the release binaries, installs them to `/usr/local/bin`, creates a
`blocker` group (and adds you to it so the GUI can talk to the daemon), installs
and starts a systemd service, and adds an application-menu launcher.

Log out and back in (or run `newgrp blocker`) once, so your new group membership
is active, then launch **Blocker** from your menu or run `blocker-gui`.

Check the engine from the terminal any time:

```bash
blockerd status
```

### Uninstall

```bash
sudo ./packaging/uninstall.sh
```

Stopping the daemon (or uninstalling) **restores your original
`/etc/resolv.conf` and removes the managed `/etc/hosts` block** automatically —
every system change is reversible.

---

## Path-level blocking (the honest part)

Blocking a whole domain or subdomain is reliable and needs nothing but the DNS
daemon. Blocking a *specific path* like `x.com/elonmusk/*` is fundamentally
harder, and it's worth being precise about why:

* DNS only knows **hostnames**, never paths. So the DNS layer cannot, even in
  principle, block one path on `x.com` while allowing the rest.
* On **HTTPS** (which is ~everything today) the path is *encrypted*. A network
  observer can see the hostname (via the TLS SNI) but not the path — unless it
  terminates TLS itself.

So path rules are enforced by an **optional local filtering proxy**
(`blocker-proxy`) which, for the hosts that have path rules, terminates TLS
using a **locally-generated CA that you choose to trust**. This is the same
technique focus tools and debugging proxies use. It is opt-in because trusting a
local CA is a meaningful decision, and it is scoped to only the hosts you
actually wrote path rules for — every other host is passed through untouched,
still end-to-end encrypted.

**Enable it (one time):**

```bash
sudo ./packaging/enable-proxy.sh
```

That starts the `blocker-proxy` service, generates the CA at
`/etc/blocker/ca.crt`, and installs it into the system trust store. The script
then prints the two remaining one-time steps: pointing your system/browser
HTTP+HTTPS proxy at `127.0.0.1:8080`, and (because browsers often keep their own
trust store) trusting the CA in Firefox
(`security.enterprise_roots.enabled = true`) or Chrome/Chromium (`certutil`).
Turn it all back off with `sudo ./packaging/disable-proxy.sh`.

How the proxy decides, per connection:

* host has a **domain** block → refused (defence in depth; usually already dead
  at DNS);
* host has a **path** rule → TLS is terminated, the request path is checked, and
  the request is either answered with a 403 block page or re-originated to the
  real server;
* otherwise → a transparent pass-through tunnel (no interception).

If you don't enable the proxy, a path rule simply does nothing at the DNS layer
(by design — it will not accidentally block the whole domain). If you want to
hard-block all of `x.com`, just add `x.com` as a domain rule instead and skip
the proxy entirely.

---

## Project layout

```
crates/
  blocker-core/    shared rule-matching, config, schedule, IPC types (unit-tested)
  blocker-daemon/  the privileged DNS sinkhole + system integration  -> blockerd
  blocker-gui/     the egui/eframe desktop front-end                 -> blocker-gui
  blocker-proxy/   optional filtering proxy for path rules (TLS MITM) -> blocker-proxy
packaging/
  blockerd.service       systemd unit (DNS daemon)
  blocker-proxy.service  systemd unit (optional path-rule proxy)
  install.sh             build + install + enable the daemon
  uninstall.sh           stop + remove + revert everything
  enable-proxy.sh        opt in to path-level blocking (CA + proxy)
  disable-proxy.sh       opt back out
  blocker-gui.desktop    app-menu launcher
```

## Security & privilege model

* The daemon runs as root because it must bind port 53 and edit `/etc/hosts`
  and `/etc/resolv.conf`. All of its changes are backed up and reverted on stop.
* The GUI runs as your normal user and only speaks to the daemon over a Unix
  socket at `/run/blocker/blocker.sock`, restricted to the `blocker` group.
* Configuration lives in `/etc/blocker/config.json` (owned by root; written only
  by the daemon).

## License

MIT — see [LICENSE](LICENSE).
