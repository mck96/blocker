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
//! * `x.com/*elonmusk*`     -> a `*` inside the path is a glob (contains)
//! * `~elonmusk`            -> a KEYWORD: blocks any host OR url containing it
//! * `https://x.com/foo`    -> a scheme is accepted and ignored
//!
//! Two important semantics:
//!
//! * A pattern that carries a **path** only ever affects URL-level (proxy)
//!   matching. It must NOT sinkhole the whole host at the DNS layer, otherwise
//!   blocking `x.com/elonmusk/*` would take down all of `x.com`.
//! * A **keyword** (`~foo`) matches as a substring of the hostname (so it works
//!   at the DNS layer across every domain that contains it) and, for traffic
//!   the proxy sees, as a substring of the whole URL.

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

impl HostMatch {
    pub fn matches(&self, query_host: &str) -> bool {
        let q = query_host.trim_matches('.').to_ascii_lowercase();
        match self {
            HostMatch::Exact(h) => &q == h,
            HostMatch::DomainAndSubdomains(d) => &q == d || q.ends_with(&format!(".{d}")),
        }
    }
}

/// A normalised, ready-to-match rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedRule {
    /// A host rule, optionally scoped to a URL path glob.
    Site {
        host: HostMatch,
        /// When present, matches only URLs whose path matches this glob
        /// (supporting `*`). Such rules are proxy-only.
        path: Option<PathGlob>,
    },
    /// A substring keyword match against the hostname and the full URL.
    Keyword(String),
}

/// A tiny path matcher supporting `*` wildcards. With no `*` it behaves as a
/// prefix match (so `/elonmusk` also matches `/elonmusk/status/1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathGlob {
    raw: String,
    /// Literal segments between `*`s; matched in order with `*` meaning "any".
    parts: Vec<String>,
    has_glob: bool,
}

impl PathGlob {
    fn new(pattern: &str) -> PathGlob {
        let has_glob = pattern.contains('*');
        let parts = pattern.split('*').map(|s| s.to_string()).collect();
        PathGlob {
            raw: pattern.to_string(),
            parts,
            has_glob,
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        let path = path.to_ascii_lowercase();
        if !self.has_glob {
            // Prefix semantics: exact, or followed by '/'.
            let p = &self.raw;
            return path == *p || path.starts_with(&format!("{p}/")) || path.starts_with(p);
        }
        // Glob: parts must appear in order; empty leading/trailing part means
        // the glob is unanchored at that end.
        let mut pos = 0usize;
        for (i, part) in self.parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if i == 0 {
                // Must match at the start.
                if !path[pos..].starts_with(part) {
                    return false;
                }
                pos += part.len();
            } else {
                match path[pos..].find(part.as_str()) {
                    Some(found) => pos += found + part.len(),
                    None => return false,
                }
            }
        }
        // If the last part is non-empty, require the path to end with it only
        // when the glob was anchored at the end (no trailing `*`).
        if let Some(last) = self.parts.last() {
            if !last.is_empty() && !self.raw.ends_with('*') && !path.ends_with(last) {
                return false;
            }
        }
        true
    }
}

impl ParsedRule {
    pub fn parse(raw: &str) -> Option<ParsedRule> {
        let s = raw.trim();
        if s.is_empty() || s.starts_with('#') {
            return None;
        }

        // Keyword rule.
        if let Some(kw) = s.strip_prefix('~') {
            let kw = kw.trim().to_ascii_lowercase();
            if kw.len() < 2 {
                return None;
            }
            return Some(ParsedRule::Keyword(kw));
        }

        let mut s = s;
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

        // Normalise the host.
        let mut host = host_part.trim().to_ascii_lowercase();
        if let Some(rest) = host.strip_prefix("*.") {
            host = rest.to_string();
        }
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

        let path = path_part.and_then(normalise_path_prefix).map(|p| PathGlob::new(&p));

        Some(ParsedRule::Site {
            host: host_match,
            path,
        })
    }

    /// True if this rule should participate in DNS / hosts-file sinkholing.
    /// Host rules with no path do; keywords do (they match hostnames); path
    /// rules do not (they only scope a URL).
    pub fn is_host_level(&self) -> bool {
        match self {
            ParsedRule::Site { path, .. } => path.is_none(),
            ParsedRule::Keyword(_) => true,
        }
    }

    /// A short label for the UI.
    pub fn kind_label(&self) -> &'static str {
        match self {
            ParsedRule::Keyword(_) => "keyword",
            ParsedRule::Site { path: None, .. } => "domain",
            ParsedRule::Site { path: Some(_), .. } => "path",
        }
    }

    /// Does the host portion of this rule match `query_host`?
    pub fn host_matches(&self, query_host: &str) -> bool {
        match self {
            ParsedRule::Site { host, .. } => host.matches(query_host),
            ParsedRule::Keyword(kw) => query_host.to_ascii_lowercase().contains(kw),
        }
    }
}

fn normalise_path_prefix(path: &str) -> Option<String> {
    let mut p = path.trim();
    // A trailing `/*` means "this prefix and anything below" -> drop it so the
    // prefix matcher handles it (but keep an interior `*` as a glob).
    if p.ends_with("/*") {
        p = &p[..p.len() - 2];
    }
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

fn is_plausible_host(host: &str) -> bool {
    if host.len() > 253 {
        return false;
    }
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    if !is_ip && !host.contains('.') {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '*'))
}

/// The compiled set of rules the daemon matches against.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    host_rules: Vec<HostMatch>,
    path_rules: Vec<(HostMatch, PathGlob)>,
    keywords: Vec<String>,
}

impl RuleSet {
    pub fn compile(rules: &[SiteRule]) -> RuleSet {
        let mut host_rules = Vec::new();
        let mut path_rules = Vec::new();
        let mut keywords = Vec::new();
        for r in rules {
            if !r.enabled {
                continue;
            }
            match r.parse() {
                Some(ParsedRule::Site { host, path: None }) => host_rules.push(host),
                Some(ParsedRule::Site {
                    host,
                    path: Some(p),
                }) => path_rules.push((host, p)),
                Some(ParsedRule::Keyword(k)) => keywords.push(k),
                None => {}
            }
        }
        RuleSet {
            host_rules,
            path_rules,
            keywords,
        }
    }

    /// Hostnames that should be sinkholed at the DNS / hosts layer.
    pub fn is_host_blocked(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        if self.host_rules.iter().any(|r| r.matches(&h)) {
            return true;
        }
        self.keywords.iter().any(|k| h.contains(k))
    }

    /// Whether a full URL (host + path) should be blocked by the proxy.
    pub fn is_url_blocked(&self, host: &str, path: &str) -> bool {
        if self.is_host_blocked(host) {
            return true;
        }
        let h = host.to_ascii_lowercase();
        let p = path.to_ascii_lowercase();
        if self
            .path_rules
            .iter()
            .any(|(hm, glob)| hm.matches(&h) && glob.matches(&p))
        {
            return true;
        }
        // Keyword can also match in the path portion.
        self.keywords.iter().any(|k| p.contains(k))
    }

    pub fn host_rule_count(&self) -> usize {
        self.host_rules.len()
    }
    pub fn path_rule_count(&self) -> usize {
        self.path_rules.len()
    }
    pub fn keyword_count(&self) -> usize {
        self.keywords.len()
    }

    /// True if any path rule applies to this host. The proxy uses this to
    /// decide whether a host is worth TLS-intercepting.
    pub fn host_has_path_rule(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        self.path_rules.iter().any(|(hm, _)| hm.matches(&h))
    }

    /// Concrete hostnames for /etc/hosts (exact + apexes). Keyword and path
    /// rules cannot be expressed as fixed hosts, so they are omitted here (DNS
    /// handles them live).
    pub fn hosts_entries(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.host_rules {
            match r {
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

/// Well-known DNS-over-HTTPS / DNS-over-TLS endpoints.
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

    fn host_of(r: &ParsedRule) -> &HostMatch {
        match r {
            ParsedRule::Site { host, .. } => host,
            _ => panic!("not a site rule"),
        }
    }

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
        assert_eq!(host_of(&a), host_of(&b));
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
        assert_eq!(r.kind_label(), "path");
        assert!(r.host_matches("x.com"));
    }

    #[test]
    fn path_glob_contains() {
        let rs = RuleSet::compile(&[SiteRule::new("x.com/*elonmusk*")]);
        assert!(rs.is_url_blocked("x.com", "/i/user/elonmusk"));
        assert!(rs.is_url_blocked("x.com", "/elonmusk/status/1"));
        assert!(!rs.is_url_blocked("x.com", "/jack"));
        assert!(!rs.is_host_blocked("x.com"));
    }

    #[test]
    fn keyword_matches_host_and_path() {
        let r = ParsedRule::parse("~elonmusk").unwrap();
        assert_eq!(r.kind_label(), "keyword");
        assert!(r.is_host_level());
        let rs = RuleSet::compile(&[SiteRule::new("~elonmusk")]);
        // host substring
        assert!(rs.is_host_blocked("elonmusk.example.com"));
        // path substring via proxy
        assert!(rs.is_url_blocked("x.com", "/elonmusk/status/1"));
        assert!(!rs.is_url_blocked("x.com", "/someoneelse"));
        assert!(!rs.is_host_blocked("twitter.com"));
    }

    #[test]
    fn keyword_blocks_youtube_variants() {
        let rs = RuleSet::compile(&[SiteRule::new("~youtube")]);
        assert!(rs.is_host_blocked("music.youtube.com"));
        assert!(rs.is_host_blocked("youtube-nocookie.com"));
        assert!(rs.is_host_blocked("youtubei.googleapis.com"));
    }

    #[test]
    fn scheme_and_port_stripped() {
        let r = ParsedRule::parse("https://x.com:443/foo").unwrap();
        assert!(r.host_matches("x.com"));
        assert_eq!(r.kind_label(), "path");
    }

    #[test]
    fn rejects_bare_single_label() {
        assert!(ParsedRule::parse("localhost").is_none());
        assert!(ParsedRule::parse("   ").is_none());
        assert!(ParsedRule::parse("~a").is_none()); // too short
    }

    #[test]
    fn ruleset_host_vs_path() {
        let rules = vec![
            SiteRule::new("youtube.com"),
            SiteRule::new("x.com/elonmusk/*"),
        ];
        let rs = RuleSet::compile(&rules);
        assert!(rs.is_host_blocked("music.youtube.com"));
        assert!(!rs.is_host_blocked("x.com"));
        assert!(rs.is_url_blocked("music.youtube.com", "/watch"));
        assert!(rs.is_url_blocked("x.com", "/elonmusk/status/1"));
        assert!(!rs.is_url_blocked("x.com", "/someoneelse"));
        assert!(rs.host_has_path_rule("x.com"));
        assert!(!rs.host_has_path_rule("youtube.com"));
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
