//! Persisted configuration shared by daemon and GUI.

use serde::{Deserialize, Serialize};

use crate::rule::SiteRule;
use crate::schedule::Schedule;

/// When blocking is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Always on.
    Always,
    /// On only during the configured schedule windows.
    Scheduled,
    /// Off (unless a focus session is running).
    Off,
}

impl Default for Enforcement {
    fn default() -> Self {
        Enforcement::Off
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub rules: Vec<SiteRule>,

    /// Upstream resolvers for non-blocked queries, e.g. "1.1.1.1:53". If empty
    /// the daemon auto-detects the system's real upstreams at start.
    #[serde(default)]
    pub upstream_dns: Vec<String>,

    #[serde(default)]
    pub enforcement: Enforcement,

    #[serde(default)]
    pub schedule: Schedule,

    /// Also sinkhole well-known DNS-over-HTTPS/TLS endpoints so browsers with
    /// "secure DNS" turned on still obey the blocklist.
    #[serde(default = "default_true")]
    pub strict_block_doh: bool,

    /// Unix timestamp (seconds) until which a focus session forces blocking on,
    /// regardless of `enforcement`. `None` when no session is running.
    #[serde(default)]
    pub session_until: Option<i64>,

    /// When true, a running focus session cannot be cancelled early (a
    /// commitment device). The GUI greys out "Stop session".
    #[serde(default)]
    pub lock_session: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rules: Vec::new(),
            upstream_dns: Vec::new(),
            enforcement: Enforcement::Off,
            schedule: Schedule::default(),
            strict_block_doh: true,
            session_until: None,
            lock_session: false,
        }
    }
}

impl Config {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn from_json(s: &str) -> Result<Config, serde_json::Error> {
        serde_json::from_str(s)
    }
}
