//! Privileged system integration: detecting the real upstream resolvers,
//! pointing /etc/resolv.conf at our local sinkhole, and maintaining a managed
//! block inside /etc/hosts. All changes are reversible and backed up.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use blocker_core::{HOSTS_BEGIN, HOSTS_END, STATE_DIR};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const HOSTS: &str = "/etc/hosts";
const RESOLV_BACKUP: &str = "/etc/blocker/resolv.conf.backup";
const RESOLV_SYMLINK_MARK: &str = "/etc/blocker/resolv.conf.was-symlink";
const SYSTEMD_RESOLV: &str = "/run/systemd/resolve/resolv.conf";

pub fn ensure_state_dir() -> std::io::Result<()> {
    fs::create_dir_all(STATE_DIR)?;
    let mut perm = fs::metadata(STATE_DIR)?.permissions();
    perm.set_mode(0o755);
    fs::set_permissions(STATE_DIR, perm)?;
    Ok(())
}

/// Detect the system's real upstream nameservers before we take over
/// resolv.conf. Loopback addresses (our own sinkhole, or a systemd stub) are
/// skipped in favour of the real servers behind them.
pub fn detect_upstreams() -> Vec<String> {
    // Prefer systemd-resolved's own view of the real upstreams.
    if let Ok(contents) = fs::read_to_string(SYSTEMD_RESOLV) {
        let v = parse_nameservers(&contents);
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(contents) = fs::read_to_string(RESOLV_CONF) {
        let v = parse_nameservers(&contents);
        if !v.is_empty() {
            return v;
        }
    }
    // Last resort: well-known public resolvers.
    vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()]
}

fn parse_nameservers(contents: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ip = rest.trim();
            if ip.is_empty() {
                continue;
            }
            // Skip loopback (our sinkhole / systemd stub).
            if ip.starts_with("127.") || ip == "::1" {
                continue;
            }
            let entry = if ip.contains(':') && !ip.contains('.') && !ip.ends_with(":53") {
                // bare IPv6 without port
                format!("[{ip}]:53")
            } else if ip.contains(':') {
                ip.to_string()
            } else {
                format!("{ip}:53")
            };
            out.push(entry);
        }
    }
    out
}

/// Point /etc/resolv.conf at our local resolver, backing up the original
/// exactly once. Idempotent: if the backup already exists we assume we are
/// already installed.
pub fn install_resolver() -> std::io::Result<()> {
    if Path::new(RESOLV_BACKUP).exists() {
        // Already installed in a previous run; just (re)write our pointer.
        write_our_resolv()?;
        return Ok(());
    }

    let meta = fs::symlink_metadata(RESOLV_CONF);
    match meta {
        Ok(m) if m.file_type().is_symlink() => {
            // Record the symlink target so we can restore it.
            if let Ok(target) = fs::read_link(RESOLV_CONF) {
                fs::write(RESOLV_SYMLINK_MARK, target.to_string_lossy().as_bytes())?;
            }
            // Back up the *contents* it pointed to, if readable.
            if let Ok(contents) = fs::read(RESOLV_CONF) {
                fs::write(RESOLV_BACKUP, contents)?;
            } else {
                fs::write(RESOLV_BACKUP, b"")?;
            }
            fs::remove_file(RESOLV_CONF)?;
        }
        Ok(_) => {
            let contents = fs::read(RESOLV_CONF).unwrap_or_default();
            fs::write(RESOLV_BACKUP, contents)?;
        }
        Err(_) => {
            // No resolv.conf at all; record an empty backup.
            fs::write(RESOLV_BACKUP, b"")?;
        }
    }
    write_our_resolv()
}

fn write_our_resolv() -> std::io::Result<()> {
    // Remove any existing file/symlink first so we always write a real file.
    let _ = fs::remove_file(RESOLV_CONF);
    let body = "# Managed by blocker (blockerd). Original backed up at\n\
                # /etc/blocker/resolv.conf.backup and restored when the\n\
                # service stops.\n\
                nameserver 127.0.0.1\n\
                options edns0 trust-ad\n";
    fs::write(RESOLV_CONF, body)?;
    Ok(())
}

/// If something external (a VPN client, NetworkManager, resolvconf) replaced
/// our managed `/etc/resolv.conf`, re-assert our sinkhole pointer. Returns true
/// if we had to rewrite it. Only acts when we previously installed (a backup
/// exists), so we never hijack resolution we didn't set up.
pub fn reassert_resolver_if_hijacked() -> bool {
    if !Path::new(RESOLV_BACKUP).exists() {
        return false;
    }
    let current = fs::read_to_string(RESOLV_CONF).unwrap_or_default();
    if current.contains("Managed by blocker") {
        return false; // still ours
    }
    // Someone replaced it; take it back over. (Upstreams were harvested by the
    // caller before this point.)
    write_our_resolv().is_ok()
}

/// Restore the original resolv.conf captured by `install_resolver`.
pub fn uninstall_resolver() -> std::io::Result<()> {
    if !Path::new(RESOLV_BACKUP).exists() {
        return Ok(());
    }
    let _ = fs::remove_file(RESOLV_CONF);

    if Path::new(RESOLV_SYMLINK_MARK).exists() {
        let target = fs::read_to_string(RESOLV_SYMLINK_MARK).unwrap_or_default();
        let target = target.trim();
        if !target.is_empty() {
            // Recreate the original symlink.
            let _ = std::os::unix::fs::symlink(target, RESOLV_CONF);
            let _ = fs::remove_file(RESOLV_SYMLINK_MARK);
            let _ = fs::remove_file(RESOLV_BACKUP);
            return Ok(());
        }
        let _ = fs::remove_file(RESOLV_SYMLINK_MARK);
    }

    let contents = fs::read(RESOLV_BACKUP).unwrap_or_default();
    fs::write(RESOLV_CONF, contents)?;
    let _ = fs::remove_file(RESOLV_BACKUP);
    Ok(())
}

/// Write (or clear) the managed block in /etc/hosts. When `entries` is empty
/// the block is removed. The rest of the file is preserved untouched.
pub fn apply_hosts(entries: &[String]) -> std::io::Result<()> {
    let current = fs::read_to_string(HOSTS).unwrap_or_default();
    let stripped = strip_managed_block(&current);

    let mut out = stripped;
    if !entries.is_empty() {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(HOSTS_BEGIN);
        out.push('\n');
        out.push_str("# Do not edit between these markers; managed by blockerd.\n");
        for e in entries {
            out.push_str(&format!("0.0.0.0 {e}\n"));
            out.push_str(&format!(":: {e}\n"));
        }
        out.push_str(HOSTS_END);
        out.push('\n');
    }

    // Atomic-ish replace via a temp file in the same directory.
    let tmp = format!("{HOSTS}.blocker.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(out.as_bytes())?;
        f.flush()?;
    }
    fs::rename(&tmp, HOSTS)?;
    Ok(())
}

fn strip_managed_block(contents: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in contents.lines() {
        if line.trim() == HOSTS_BEGIN {
            inside = true;
            continue;
        }
        if line.trim() == HOSTS_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_loopback() {
        let c = "nameserver 127.0.0.53\nnameserver 192.168.1.1\n";
        assert_eq!(parse_nameservers(c), vec!["192.168.1.1:53".to_string()]);
    }

    #[test]
    fn strip_round_trip() {
        let original = "127.0.0.1 localhost\n";
        let with_block = format!(
            "{original}{HOSTS_BEGIN}\n0.0.0.0 youtube.com\n{HOSTS_END}\n"
        );
        assert_eq!(strip_managed_block(&with_block), original);
    }
}
