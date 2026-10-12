//! Loads the blocker config (shared with the daemon) and answers the two
//! questions the proxy cares about: is blocking active right now, and does a
//! given URL match a rule. The file is re-read when its mtime changes.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use blocker_core::config::Config;
use blocker_core::rule::RuleSet;
use blocker_core::CONFIG_PATH;

pub struct Filter {
    inner: Mutex<Inner>,
}

struct Inner {
    mtime: Option<SystemTime>,
    config: Config,
    ruleset: RuleSet,
}

impl Filter {
    pub fn new() -> Filter {
        let mut f = Filter {
            inner: Mutex::new(Inner {
                mtime: None,
                config: Config::default(),
                ruleset: RuleSet::compile(&[]),
            }),
        };
        f.reload_if_changed();
        f
    }

    /// Re-read the config file if it changed on disk.
    pub fn reload_if_changed(&mut self) {
        self.reload_locked();
    }

    fn reload_locked(&self) {
        let disk_mtime = std::fs::metadata(CONFIG_PATH).and_then(|m| m.modified()).ok();
        let mut g = self.inner.lock().unwrap();
        if disk_mtime == g.mtime && g.mtime.is_some() {
            return;
        }
        if let Ok(s) = std::fs::read_to_string(CONFIG_PATH) {
            if let Ok(cfg) = Config::from_json(&s) {
                g.ruleset = RuleSet::compile(&cfg.rules);
                g.config = cfg;
                g.mtime = disk_mtime;
            }
        }
    }

    /// Whether blocking is active right now (mode + schedule + session).
    pub fn active(&self) -> bool {
        self.reload_locked();
        let g = self.inner.lock().unwrap();
        let (weekday, minute) = local_weekday_minute();
        g.config.is_blocking_active(now_unix(), weekday, minute)
    }

    /// A host is "fully blocked" when a domain/exact rule matches it. (Normally
    /// such hosts never reach the proxy because DNS already sinkholes them, but
    /// we enforce it anyway as defence in depth.)
    pub fn host_fully_blocked(&self, host: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.ruleset.is_host_blocked(host)
    }

    /// Does this host have any path rule, i.e. is it worth TLS-intercepting?
    pub fn host_has_path_rule(&self, host: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.ruleset.host_has_path_rule(host)
    }

    /// Final decision for a concrete request.
    pub fn url_blocked(&self, host: &str, path: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.ruleset.is_url_blocked(host, path)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn local_weekday_minute() -> (u8, u16) {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return (0, 0);
        }
        let weekday_mon0 = ((tm.tm_wday + 6) % 7) as u8;
        let minute = (tm.tm_hour * 60 + tm.tm_min) as u16;
        (weekday_mon0, minute)
    }
}
