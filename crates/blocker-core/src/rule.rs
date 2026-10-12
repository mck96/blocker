//! Parsing and matching of user-entered block rules.
//!
//! A user types patterns in a small, forgiving mini-language. Examples the UI
//! documents and this module understands:
//!
//! * `youtube.com`          -> the domain *and every subdomain* (www., music., …)
//! * `*.youtube.com`        -> same as above (the leading `*.` is sugar)
//! * `=mail.google.com`     -> an *exact* host only; subdomains are not matched
//! * `x.com/elonmusk`       -> a path prefix on a host (handled by the proxy)
//! * `x.com/elonmusk/*`     -> trailing `/*` is sugar for a path prefix
//! * `https://x.com/foo`    -> a scheme is accepted and ignored
//!
//! The important semantic rule: a pattern that carries a **path** only ever
//! affects URL-level (proxy) matching. It must NOT sinkhole the whole host at
//! the DNS layer, otherwise blocking `x.com/elonmusk/*` would take down all of
//! `x.com`. Host-only patterns are enforced by DNS (and /etc/hosts); path
//! patterns are enforced by the optional filtering proxy.

use serde::{Deserialize, Serialize};

/// A single rule as stored in the configuration. `pattern` is exactly what the
/// user typed; parsing happens on demand so the raw text is never lost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteRule {
    pub pattern: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub note: String,
}

fn default_true() -> bool {
    true
}

impl SiteRule {
    pub fn new(pattern: impl Into<String>) -> Self {
        SiteRule {
            pattern: pattern.into(),
            enabled: true,
            note: String::new(),
        }
    }

    /// Parse the raw pattern, returning `None` if it is empty/garbage.
    pub fn parse(&self) -> Option<ParsedRule> {
        ParsedRule::parse(&self.pattern)
    }
}

/// How the host portion of a rule is matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostMatch {
    /// Match this domain and all of its subdomains.
    DomainAndSubdomains(String),
    /// Match only this exact host.
    Exact(String),
}

/// A normalised, ready-to-match rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRule {
    pub host: HostMatch,
    /// When present, the rule matches only URLs whose path starts with this
    /// (leading-slash-normalised) prefix. Such rules are proxy-only.
    pub path_prefix: Option<String>,
}

impl ParsedRule {
    pub fn parse(raw: &str) -> Option<ParsedRule> {
        let mut s = raw.trim();
        if s.is_empty() || s.starts_with('#') {
            return None;
        }

        // Drop an optional scheme.
        if let Some(idx) = s.find("://") {
            s = &s[idx + 3..];
        }

        // Exact-host marker.
        let mut exact = false;
        if let Some(rest) = s.strip_prefix('=') {
            exact = true;
            s = rest.trim();
        }

        // Split host from path at the first '/'.
        let (host_part, path_part) = match s.find('/') {
            Some(i) => (&s[..i], Some(&s[i..])),
            None => (s, None),
        };

        // Normalise the host: lowercase, strip a leading "*." or "www."-style
        // wildcard, strip credentials/port if present.
        let mut host = host_part.trim().to_ascii_lowercase();
        if let Some(rest) = host.strip_prefix("*.") {
            host = rest.to_string();
        }
        // Strip user@ and :port.
        if let Some(at) = host.rfind('@') {
            host = host[at + 1..].to_string();
        }
        if let Some(colon) = host.find(':') {
            host = host[..colon].to_string();
        }
        host = host.trim_matches('.').to_string();

        if host.is_empty() || !is_plausible_host(&host) {
            return None;
        }

        let host_match = if exact {
            HostMatch::Exact(host)
        } else {
            HostMatch::DomainAndSubdomains(host)
        };

        let path_prefix = path_part.and_then(|p| normalise_path_prefix(p));

        Some(ParsedRule {
            host: host_match,
            path_prefix,
        })
    }

    /// True if this rule should participate in DNS / hosts-file sinkholing.
    pub fn is_host_level(&self) -> bool {
        self.path_prefix.is_none()
    }

    /// Does `query_host` (a bare hostname, no port/scheme) match this rule's
    /// host portion?
    pub fn host_matches(&self, query_host: &str) -> bool {
        let q = query_host.trim_matches('.').to_ascii_lowercase();
        match &self.host {
            HostMatch::Exact(h) => &q == h,
            HostMatch::DomainAndSubdomains(d) => {
                &q == d || q.ends_with(&format!(".{d}"))
            }
        }
    }
}

/// Normalise a path portion such as `/elonmusk/*` or `/foo` into a prefix we
/// match with `starts_with`. A bare `/` or `/*` means "whole host" and yields
/// `None` (i.e. not actually a path rule).
fn normalise_path_prefix(path: &str) -> Option<String> {
    let mut p = path.trim();
    // Strip a trailing glob.
    if let Some(stripped) = p.strip_suffix("/*") {
        p = stripped;
    } else if let Some(stripped) = p.strip_suffix('*') {
        p = stripped;
    }
    // Drop a trailing '/'.
    let p = p.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        return None;
    }
    let p = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    };
    Some(p.to_ascii_lowercase())
}

/// Very light sanity check so we don't sinkhole obvious typos.
fn is_plausible_host(host: &str) -> bool {
    if host.len() > 253 {
        return false;
    }
    // Must contain at least one dot (reject "localhost"-style single labels to
    // avoid footguns) OR be an IP literal.
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    if !is_ip && !host.contains('.') {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// The compiled set of rules the daemon matches against.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    host_rules: Vec<ParsedRule>,
    path_rules: Vec<ParsedRule>,
}

impl RuleSet {
    /// Compile enabled rules into fast-matching buckets.
    pub fn compile(rules: &[SiteRule]) -> RuleSet {
        let mut host_rules = Vec::new();
        let mut path_rules = Vec::new();
        for r in rules {
            if !r.enabled {
                continue;
            }
            if let Some(parsed) = r.parse() {
                if parsed.is_host_level() {
                    host_rules.push(parsed);
                } else {
                    path_rules.push(parsed);
                }
            }
        }
        RuleSet {
            host_rules,
            path_rules,
        }
    }

    /// Hostnames that should be sinkholed at the DNS / hosts layer.
    pub fn is_host_blocked(&self, host: &str) -> bool {
        self.host_rules.iter().any(|r| r.host_matches(host))
    }

    /// Whether a full URL (host + path) should be blocked by the proxy. A
    /// host-level rule blocks every path on that host; a path rule blocks only
    /// matching prefixes.
    pub fn is_url_blocked(&self, host: &str, path: &str) -> bool {
        if self.is_host_blocked(host) {
            return true;
        }
        let path = path.to_ascii_lowercase();
        self.path_rules.iter().any(|r| {
            r.host_matches(host)
                && r.path_prefix
                    .as_ref()
                    .map(|p| path == *p || path.starts_with(&format!("{p}/")) || path.starts_with(p))
                    .unwrap_or(false)
        })
    }

    pub fn host_rule_count(&self) -> usize {
        self.host_rules.len()
    }
    pub fn path_rule_count(&self) -> usize {
        self.path_rules.len()
    }

    /// The concrete hostnames to write into /etc/hosts (exact + domain apexes;
    /// subdomains are covered by the DNS sinkhole, and a couple of common ones
    /// are emitted so the hosts file alone still helps if DNS interception is
    /// off).
    pub fn hosts_entries(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.host_rules {
            match &r.host {
                HostMatch::Exact(h) => out.push(h.clone()),
                HostMatch::DomainAndSubdomains(d) => {
                    out.push(d.clone());
                    out.push(format!("www.{d}"));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

/// Well-known DNS-over-HTTPS / DNS-over-TLS endpoints. When strict mode is on
/// these are sinkholed too, so browsers with secure DNS enabled fall back to
/// the system resolver (which is us).
pub fn doh_bootstrap_hosts() -> &'static [&'static str] {
    &[
        "dns.google",
        "mozilla.cloudflare-dns.com",
        "cloudflare-dns.com",
        "dns.cloudflare.com",
        "chrome.cloudflare-dns.com",
        "doh.opendns.com",
        "dns.quad9.net",
        "dns10.quad9.net",
        "dns.nextdns.io",
        "dns.adguard.com",
        "doh.cleanbrowsing.org",
        "dns.sb",
        "doh.dns.sb",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_and_subdomains() {
        let r = ParsedRule::parse("youtube.com").unwrap();
        assert!(r.is_host_level());
        assert!(r.host_matches("youtube.com"));
        assert!(r.host_matches("www.youtube.com"));
        assert!(r.host_matches("music.youtube.com"));
        assert!(r.host_matches("MUSIC.YouTube.com"));
        assert!(!r.host_matches("notyoutube.com"));
        assert!(!r.host_matches("youtube.com.evil.com"));
    }

    #[test]
    fn wildcard_sugar_equals_domain() {
        let a = ParsedRule::parse("*.youtube.com").unwrap();
        let b = ParsedRule::parse("youtube.com").unwrap();
        assert_eq!(a.host, b.host);
        assert!(a.host_matches("music.youtube.com"));
    }

    #[test]
    fn exact_host() {
        let r = ParsedRule::parse("=mail.google.com").unwrap();
        assert!(r.host_matches("mail.google.com"));
        assert!(!r.host_matches("calendar.google.com"));
        assert!(!r.host_matches("google.com"));
    }

    #[test]
    fn path_rule_is_proxy_only() {
        let r = ParsedRule::parse("x.com/elonmusk/*").unwrap();
        assert!(!r.is_host_level());
        assert_eq!(r.path_prefix.as_deref(), Some("/elonmusk"));
        assert!(r.host_matches("x.com"));
    }

    #[test]
    fn scheme_and_port_stripped() {
        let r = ParsedRule::parse("https://x.com:443/foo").unwrap();
        assert!(r.host_matches("x.com"));
        assert_eq!(r.path_prefix.as_deref(), Some("/foo"));
    }

    #[test]
    fn rejects_bare_single_label() {
        assert!(ParsedRule::parse("localhost").is_none());
        assert!(ParsedRule::parse("   ").is_none());
    }

    #[test]
    fn ruleset_host_vs_path() {
        let rules = vec![
            SiteRule::new("youtube.com"),
            SiteRule::new("x.com/elonmusk/*"),
        ];
        let rs = RuleSet::compile(&rules);
        // DNS layer: youtube blocked, x.com NOT (only a path is blocked).
        assert!(rs.is_host_blocked("music.youtube.com"));
        assert!(!rs.is_host_blocked("x.com"));
        // URL layer.
        assert!(rs.is_url_blocked("music.youtube.com", "/watch"));
        assert!(rs.is_url_blocked("x.com", "/elonmusk/status/1"));
        assert!(!rs.is_url_blocked("x.com", "/someoneelse"));
    }

    #[test]
    fn disabled_rules_ignored() {
        let mut r = SiteRule::new("youtube.com");
        r.enabled = false;
        let rs = RuleSet::compile(&[r]);
        assert!(!rs.is_host_blocked("youtube.com"));
    }

    #[test]
    fn hosts_entries_include_www() {
        let rs = RuleSet::compile(&[SiteRule::new("example.com")]);
        let e = rs.hosts_entries();
        assert!(e.contains(&"example.com".to_string()));
        assert!(e.contains(&"www.example.com".to_string()));
    }
}
