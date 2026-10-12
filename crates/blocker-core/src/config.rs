//! Persisted configuration shared by daemon and GUI.

use serde::{Deserialize, Serialize};

use crate::rule::SiteRule;
use crate::schedule::Schedule;

/// When blocking is enforced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Always on.
    Always,
    /// On only during the configured schedule windows.
    Scheduled,
    /// Off (unless a focus session is running).
    #[default]
    Off,
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

    /// How long a single "break" pauses blocking, in minutes.
    #[serde(default = "default_break_minutes")]
    pub break_minutes: u32,

    /// How many breaks are allowed per day (0 disables breaks entirely).
    #[serde(default = "default_breaks_per_day")]
    pub breaks_per_day: u32,

    /// Unix timestamp until which blocking is paused by a break. `None` when no
    /// break is running.
    #[serde(default)]
    pub break_until: Option<i64>,

    /// Breaks taken so far today, and the local day they belong to (so the
    /// count resets at local midnight).
    #[serde(default)]
    pub breaks_used_today: u32,
    #[serde(default)]
    pub break_day: i32,

    /// Show a motivational block page instead of a silent connection failure.
    /// When on, blocked hosts resolve to 127.0.0.1 and the daemon serves the
    /// page on :80 and (via the local CA) :443.
    #[serde(default)]
    pub block_page: bool,

    /// Heading shown on the block page.
    #[serde(default = "default_block_title")]
    pub block_title: String,

    /// Body text / motivational message shown on the block page.
    #[serde(default = "default_block_message")]
    pub block_message: String,
}

fn default_true() -> bool {
    true
}

fn default_break_minutes() -> u32 {
    5
}

fn default_breaks_per_day() -> u32 {
    3
}

fn default_block_title() -> String {
    "Stay focused.".to_string()
}

fn default_block_message() -> String {
    "You blocked this site for a reason. Take a breath and get back to what matters."
        .to_string()
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
            break_minutes: default_break_minutes(),
            breaks_per_day: default_breaks_per_day(),
            break_until: None,
            breaks_used_today: 0,
            break_day: 0,
            block_page: false,
            block_title: default_block_title(),
            block_message: default_block_message(),
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

    /// Is a focus session currently running?
    pub fn session_running(&self, now_unix: i64) -> bool {
        matches!(self.session_until, Some(until) if now_unix < until)
    }

    /// Is a locked focus session running (cannot be paused or stopped)?
    pub fn locked_now(&self, now_unix: i64) -> bool {
        self.lock_session && self.session_running(now_unix)
    }

    /// Is a break currently pausing blocking?
    pub fn break_active(&self, now_unix: i64) -> bool {
        matches!(self.break_until, Some(until) if now_unix < until)
    }

    /// The single source of truth for "should blocking be enforced right now",
    /// shared by the daemon and the proxy so they never disagree. `now_unix`,
    /// `weekday_mon0` (0 = Monday) and `minute_of_day` come from the caller's
    /// system clock.
    pub fn is_blocking_active(&self, now_unix: i64, weekday_mon0: u8, minute_of_day: u16) -> bool {
        // A break pauses everything — except a locked session, which cannot be
        // escaped with a break.
        if self.break_active(now_unix) && !self.locked_now(now_unix) {
            return false;
        }
        if self.session_running(now_unix) {
            return true;
        }
        match self.enforcement {
            Enforcement::Always => true,
            Enforcement::Off => false,
            Enforcement::Scheduled => self.schedule.is_active(weekday_mon0, minute_of_day),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_pauses_blocking() {
        let mut c = Config {
            enforcement: Enforcement::Always,
            ..Config::default()
        };
        assert!(c.is_blocking_active(1000, 0, 600));
        c.break_until = Some(2000);
        assert!(!c.is_blocking_active(1000, 0, 600)); // paused
        assert!(c.is_blocking_active(2000, 0, 600)); // break expired
    }

    #[test]
    fn locked_session_ignores_break() {
        let c = Config {
            enforcement: Enforcement::Off,
            session_until: Some(5000),
            lock_session: true,
            break_until: Some(5000),
            ..Config::default()
        };
        // A locked session cannot be broken out of.
        assert!(c.is_blocking_active(1000, 0, 600));
    }
}
