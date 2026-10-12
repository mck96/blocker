//! Shared types and logic for the Blocker application.
//!
//! This crate is deliberately free of any OS-specific or privileged code so
//! that both the privileged daemon and the unprivileged GUI can depend on it
//! and agree on the exact same rule-matching semantics and IPC protocol.

pub mod rule;
pub mod config;
pub mod schedule;
pub mod ipc;
pub mod blockpage;

pub use config::{Config, Enforcement};
pub use rule::{HostMatch, ParsedRule, SiteRule};
pub use schedule::{Schedule, Window};

/// Default location of the on-disk configuration owned by the daemon.
pub const CONFIG_PATH: &str = "/etc/blocker/config.json";
/// Directory holding the daemon's runtime state (socket, backups).
pub const STATE_DIR: &str = "/etc/blocker";
/// Unix domain socket the GUI uses to talk to the daemon.
pub const SOCKET_PATH: &str = "/run/blocker/blocker.sock";
/// Marker used to delimit the block managed by this app inside /etc/hosts.
pub const HOSTS_BEGIN: &str = "# >>> blocker managed block >>>";
pub const HOSTS_END: &str = "# <<< blocker managed block <<<";
