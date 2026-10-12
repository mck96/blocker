//! Shared, thread-safe runtime state. The DNS threads read from it on every
//! query; the IPC and ticker threads write to it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use blocker_core::config::{Config, Enforcement};
use blocker_core::ipc::Status;
use blocker_core::rule::{doh_bootstrap_hosts, ParsedRule, RuleSet};

pub struct Engine {
    inner: RwLock<Inner>,
    dns_listening: AtomicBool,
    block_page_serving: AtomicBool,
    last_block: Mutex<Option<String>>,
    verbose: bool,
}

struct Inner {
    config: Config,
    ruleset: RuleSet,
    doh_rules: Vec<ParsedRule>,
    upstreams: Vec<String>,
    /// Cached "blocking is active right now" flag, refreshed by the ticker.
    active: bool,
}

impl Engine {
    pub fn new(config: Config, upstreams: Vec<String>, verbose: bool) -> Engine {
        let ruleset = RuleSet::compile(&config.rules);
        let doh_rules = compile_doh();
        let mut inner = Inner {
            config,
            ruleset,
            doh_rules,
            upstreams,
            active: false,
        };
        inner.active = compute_active(&inner.config);
        Engine {
            inner: RwLock::new(inner),
            dns_listening: AtomicBool::new(false),
            block_page_serving: AtomicBool::new(false),
            last_block: Mutex::new(None),
            verbose,
        }
    }

    pub fn set_dns_listening(&self, v: bool) {
        self.dns_listening.store(v, Ordering::Relaxed);
    }

    pub fn dns_listening(&self) -> bool {
        self.dns_listening.load(Ordering::Relaxed)
    }

    pub fn set_block_page_serving(&self, v: bool) {
        self.block_page_serving.store(v, Ordering::Relaxed);
    }

    pub fn block_page_serving(&self) -> bool {
        self.block_page_serving.load(Ordering::Relaxed)
    }

    /// Is the config asking for a block page?
    pub fn block_page_enabled(&self) -> bool {
        self.inner.read().unwrap().config.block_page
    }

    /// Should blocked queries resolve to 127.0.0.1 (page) rather than 0.0.0.0
    /// (silent)? Only when enabled *and* the local page servers are up.
    pub fn use_block_page(&self) -> bool {
        self.block_page_enabled() && self.block_page_serving()
    }

    pub fn block_title(&self) -> String {
        self.inner.read().unwrap().config.block_title.clone()
    }

    pub fn block_message(&self) -> String {
        self.inner.read().unwrap().config.block_message.clone()
    }

    pub fn upstreams(&self) -> Vec<String> {
        self.inner.read().unwrap().upstreams.clone()
    }

    /// Replace the active upstream resolvers (used when the network/VPN
    /// changes). Returns true if they actually changed.
    pub fn set_upstreams(&self, upstreams: Vec<String>) -> bool {
        let mut g = self.inner.write().unwrap();
        if g.upstreams == upstreams {
            false
        } else {
            g.upstreams = upstreams;
            true
        }
    }

    /// Per-query decision used by the DNS server.
    pub fn should_block_host(&self, host: &str) -> bool {
        let g = self.inner.read().unwrap();
        if !g.active {
            return false;
        }
        if g.ruleset.is_host_blocked(host) {
            return true;
        }
        if g.config.strict_block_doh && g.doh_rules.iter().any(|r| r.host_matches(host)) {
            return true;
        }
        false
    }

    pub fn log_block(&self, host: &str) {
        if self.verbose {
            eprintln!("[blocker] sinkholed {host}");
        }
        *self.last_block.lock().unwrap() = Some(host.to_string());
    }

    /// Replace the configuration (from IPC SetConfig) and recompile.
    pub fn replace_config(&self, mut config: Config) {
        let mut g = self.inner.write().unwrap();
        // Preserve detected upstreams if the new config leaves them empty.
        if !config.upstream_dns.is_empty() {
            g.upstreams = config.upstream_dns.clone();
        } else {
            config.upstream_dns = g.upstreams.clone();
        }
        g.ruleset = RuleSet::compile(&config.rules);
        g.config = config;
        g.active = compute_active(&g.config);
    }

    pub fn set_enforcement(&self, e: Enforcement) {
        let mut g = self.inner.write().unwrap();
        g.config.enforcement = e;
        g.active = compute_active(&g.config);
    }

    /// Start a focus session; returns the updated config to persist.
    pub fn start_session(&self, minutes: u32, lock: bool) -> Config {
        let mut g = self.inner.write().unwrap();
        let until = now_unix() + (minutes as i64) * 60;
        g.config.session_until = Some(until);
        g.config.lock_session = lock;
        g.active = compute_active(&g.config);
        g.config.clone()
    }

    /// Take a break: pause blocking for `break_minutes`. Fails if a locked
    /// session is running or no breaks remain today.
    pub fn take_break(&self) -> Result<Config, String> {
        let mut g = self.inner.write().unwrap();
        reset_breaks_if_new_day(&mut g.config);
        if g.config.locked_now(now_unix()) {
            return Err("A locked focus session is running; breaks are disabled".into());
        }
        if g.config.breaks_per_day == 0 {
            return Err("Breaks are disabled".into());
        }
        if g.config.breaks_used_today >= g.config.breaks_per_day {
            return Err(format!(
                "No breaks left today ({}/{})",
                g.config.breaks_used_today, g.config.breaks_per_day
            ));
        }
        let mins = g.config.break_minutes.max(1) as i64;
        g.config.break_until = Some(now_unix() + mins * 60);
        g.config.breaks_used_today += 1;
        g.active = compute_active(&g.config);
        Ok(g.config.clone())
    }

    /// Stop a focus session early. Returns Err if the session is locked.
    pub fn stop_session(&self) -> Result<Config, String> {
        let mut g = self.inner.write().unwrap();
        if g.config.lock_session && session_running(&g.config) {
            return Err("Focus session is locked and cannot be stopped early".into());
        }
        g.config.session_until = None;
        g.config.lock_session = false;
        g.active = compute_active(&g.config);
        Ok(g.config.clone())
    }

    /// Called by the ticker. Returns `Some(active)` when the active flag
    /// changed, so the caller can update /etc/hosts.
    pub fn refresh_active(&self) -> Option<bool> {
        let mut g = self.inner.write().unwrap();
        // Expire a finished session.
        if let Some(until) = g.config.session_until {
            if now_unix() >= until {
                g.config.session_until = None;
                g.config.lock_session = false;
            }
        }
        // Expire a finished break; reset the daily break count at local midnight.
        if let Some(until) = g.config.break_until {
            if now_unix() >= until {
                g.config.break_until = None;
            }
        }
        reset_breaks_if_new_day(&mut g.config);
        let new_active = compute_active(&g.config);
        if new_active != g.active {
            g.active = new_active;
            Some(new_active)
        } else {
            None
        }
    }

    pub fn is_active(&self) -> bool {
        self.inner.read().unwrap().active
    }

    pub fn config_snapshot(&self) -> Config {
        self.inner.read().unwrap().config.clone()
    }

    pub fn hosts_entries(&self) -> Vec<String> {
        let g = self.inner.read().unwrap();
        let mut e = g.ruleset.hosts_entries();
        if g.config.strict_block_doh {
            for h in doh_bootstrap_hosts() {
                e.push((*h).to_string());
            }
        }
        e.sort();
        e.dedup();
        e
    }

    pub fn status(&self) -> Status {
        let g = self.inner.read().unwrap();
        let now = now_unix();
        let session_remaining = g.config.session_until.map(|u| (u - now).max(0));
        let break_remaining = g.config.break_until.filter(|u| *u > now).map(|u| u - now);
        let breaks_left = if local_day() != g.config.break_day {
            g.config.breaks_per_day
        } else {
            g.config.breaks_per_day.saturating_sub(g.config.breaks_used_today)
        };
        let reason = describe_reason(&g.config, g.active);
        Status {
            blocking_active: g.active,
            reason,
            enforcement: g.config.enforcement,
            session_remaining_secs: session_remaining,
            session_locked: g.config.lock_session && session_running(&g.config),
            break_remaining_secs: break_remaining,
            breaks_left,
            break_minutes: g.config.break_minutes,
            host_rule_count: g.ruleset.host_rule_count(),
            path_rule_count: g.ruleset.path_rule_count(),
            keyword_count: g.ruleset.keyword_count(),
            dns_listening: self.dns_listening.load(Ordering::Relaxed),
            block_page_active: g.config.block_page && self.block_page_serving.load(Ordering::Relaxed),
            upstreams: g.upstreams.clone(),
            config: g.config.clone(),
        }
    }
}

fn compile_doh() -> Vec<ParsedRule> {
    doh_bootstrap_hosts()
        .iter()
        .filter_map(|h| ParsedRule::parse(h))
        .collect()
}

fn session_running(c: &Config) -> bool {
    c.session_running(now_unix())
}

/// Reset the per-day break counter when the local calendar day changes.
fn reset_breaks_if_new_day(c: &mut Config) {
    let today = local_day();
    if c.break_day != today {
        c.break_day = today;
        c.breaks_used_today = 0;
    }
}

/// A monotonic id for the current local calendar day (for break-count resets).
fn local_day() -> i32 {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_year * 366 + tm.tm_yday
    }
}

/// Decide whether blocking should be on right now, delegating to the shared
/// core logic so the daemon and proxy always agree.
fn compute_active(c: &Config) -> bool {
    let (weekday, minute) = local_weekday_minute();
    c.is_blocking_active(now_unix(), weekday, minute)
}

fn describe_reason(c: &Config, active: bool) -> String {
    if c.break_active(now_unix()) && !c.locked_now(now_unix()) {
        return "On a break — blocking paused".into();
    }
    if session_running(c) {
        let lock = if c.lock_session { " (locked)" } else { "" };
        return format!("Focus session in progress{lock}");
    }
    match (c.enforcement, active) {
        (Enforcement::Always, _) => "Enforcement: always on".into(),
        (Enforcement::Off, _) => "Enforcement: off".into(),
        (Enforcement::Scheduled, true) => "Within a scheduled block window".into(),
        (Enforcement::Scheduled, false) => "Outside scheduled block windows".into(),
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current local weekday (0 = Monday) and minute-of-day, via libc localtime_r
/// so the system timezone is respected without pulling in a date library.
fn local_weekday_minute() -> (u8, u16) {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return (0, 0);
        }
        // tm_wday: 0 = Sunday .. 6 = Saturday. Convert to Monday=0.
        let weekday_mon0 = ((tm.tm_wday + 6) % 7) as u8;
        let minute = (tm.tm_hour * 60 + tm.tm_min) as u16;
        (weekday_mon0, minute)
    }
}
