//! Line-delimited JSON protocol spoken over the Unix socket between the GUI
//! (client) and the daemon (server). One JSON object per line in each
//! direction.

use serde::{Deserialize, Serialize};

use crate::config::{Config, Enforcement};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Return the current status and effective config.
    Status,
    /// Replace the whole configuration (rules, schedule, upstreams, flags).
    SetConfig { config: Config },
    /// Start a focus session for `minutes`, optionally locked (uncancellable).
    StartSession { minutes: u32, lock: bool },
    /// End a focus session early (fails if the session is locked).
    StopSession,
    /// Pause blocking for `break_minutes` (fails if no breaks remain today or a
    /// locked session is running).
    TakeBreak,
    /// Change the enforcement mode.
    SetEnforcement { enforcement: Enforcement },
    /// Re-read config from disk and re-apply (useful after manual edits).
    Reload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
// The `Ok` variant is intentionally much larger than `Error`; this is a small,
// short-lived IPC message, so the size difference does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Response {
    Ok { status: Status },
    Error { message: String },
}

/// A snapshot of daemon state for display in the GUI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    /// Is blocking enforced *right now*?
    pub blocking_active: bool,
    /// Why it is (or isn't) active, in human terms.
    pub reason: String,
    pub enforcement: Enforcement,
    /// Seconds remaining in a focus session, if one is running.
    pub session_remaining_secs: Option<i64>,
    pub session_locked: bool,
    // Fields below were added in later versions; `#[serde(default)]` keeps a
    // newer client from erroring when it talks to an older daemon still running
    // across an upgrade (restart the daemon to refresh it).
    /// Seconds remaining in a break, if one is running.
    #[serde(default)]
    pub break_remaining_secs: Option<i64>,
    /// Breaks still available today, and how long each one lasts.
    #[serde(default)]
    pub breaks_left: u32,
    #[serde(default)]
    pub break_minutes: u32,
    pub host_rule_count: usize,
    pub path_rule_count: usize,
    #[serde(default)]
    pub keyword_count: usize,
    /// Whether the DNS sinkhole socket is bound and serving.
    pub dns_listening: bool,
    /// Whether the motivational block page is enabled *and* its local servers
    /// are bound (so blocked hosts resolve to 127.0.0.1 and show the page).
    #[serde(default)]
    pub block_page_active: bool,
    /// Whether network-level enforcement (nftables + SNI/Host filter) is on.
    #[serde(default)]
    pub network_filter_active: bool,
    /// The upstream resolvers currently in use.
    pub upstreams: Vec<String>,
    pub config: Config,
}

impl Response {
    pub fn err(msg: impl Into<String>) -> Response {
        Response::Error {
            message: msg.into(),
        }
    }
}
