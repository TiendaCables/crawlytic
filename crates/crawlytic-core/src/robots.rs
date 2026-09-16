//! Robots access policy, separate from authentication and from crawl-delay.
//!
//! Handling (RFC 9309 plus common Sitemap/Crawl-delay extensions):
//! - User-agent: case-insensitive prefix of the crawler product token; longest
//!   match wins; `*` is used only when no named group matches.
//! - Allow/Disallow: longest matching pattern wins; equal length prefers Allow.
//!   `*` matches any sequence; `$` anchors the end; otherwise the pattern is a
//!   prefix. These rules are access policy only.
//! - Crawl-delay is recorded and never used as allow/disallow.
//! - Sitemap declarations are collected globally, not as access rules.
//! - Missing robots (404/410) allow all. Unreachable/5xx robots allow all and
//!   are recorded as a failed fetch, not a page failure or a denial.
//! - UTF-8 (optional BOM) is preferred; invalid UTF-8 is decoded as ISO-8859-1
//!   with a format note. UTF-16 BOM is a format error and yields an empty file.
//! - Unknown or malformed lines are format errors; valid records still apply.
//! - `bypass_robots` is an explicit owner-audit override. Signed requests still
//!   evaluate robots; a denial is blocked evidence unless that override is on
//!   and recorded in run metadata. Meta noindex is a distinct block kind and is
//!   never produced from robots.txt.

use crate::profile::Profile;
use crate::transport::{AccessError, FetchRecord, ResourceKind, SignedTransport};
use std::collections::HashMap;
use std::sync::Mutex;
use url::Url;

const ROBOTS_PATH: &str = "/robots.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    RobotsTxt,
    MetaNoindex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedEvidence {
    pub url: Url,
    pub kind: BlockKind,
    pub group: Option<String>,
    pub rule: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowReason {
    AllowedByRule { group: String, rule: String },
    NoMatchingRule { group: Option<String> },
    RobotsMissing,
    RobotsUnavailable,
    OwnerAuditBypass { would_block: Box<BlockedEvidence> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlAccess {
    Allowed { reason: AllowReason },
    Blocked(BlockedEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RobotsFetchState {
    Fetched { status: u16 },
    NotFound { status: u16 },
    Unavailable { observation: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotsRunMetadata {
    pub origin: String,
    pub user_agent: String,
    pub product_token: String,
    pub selected_group: Option<String>,
    pub bypass_robots: bool,
    pub bypass_meta: bool,
    pub fetch: RobotsFetchState,
    pub sitemaps: Vec<Url>,
    pub crawl_delay_notes: Vec<String>,
    pub format_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct PathRule {
    allow: bool,
    pattern: String,
}

#[derive(Debug, Clone)]
struct Group {
    agents: Vec<String>,
    rules: Vec<PathRule>,
    crawl_delays: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RobotsFile {
    groups: Vec<Group>,
    sitemaps: Vec<Url>,
    format_errors: Vec<String>,
    fetch: RobotsFetchState,
}

pub struct RobotsCache {
    files: Mutex<HashMap<String, RobotsFile>>,
}

impl RobotsCache {
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
        }
    }

    pub async fn for_url(
        &self,
        transport: &SignedTransport,
        url: &Url,
    ) -> std::result::Result<RobotsFile, AccessError> {
        let origin = origin_key(url);
        if let Some(existing) = self.files.lock().expect("robots cache").get(&origin) {
            return Ok(existing.clone());
        }
        let file = fetch_robots(transport, url).await?;
        self.files
            .lock()
            .expect("robots cache")
            .insert(origin, file.clone());
        Ok(file)
    }
}

impl Default for RobotsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RobotsFile {
    pub fn parse(body: &[u8]) -> Self {
        parse_robots(body, RobotsFetchState::Fetched { status: 200 })
    }

    pub fn from_fetch(record: &FetchRecord, body: &[u8]) -> Self {
        file_from_record(record, body)
    }

    pub fn unavailable(observation: impl Into<String>) -> Self {
        Self {
            groups: Vec::new(),
            sitemaps: Vec::new(),
            format_errors: Vec::new(),
            fetch: RobotsFetchState::Unavailable {
                observation: observation.into(),
            },
        }
    }

    pub fn sitemaps(&self) -> &[Url] {
        &self.sitemaps
    }

    pub fn format_errors(&self) -> &[String] {
        &self.format_errors
    }

    pub fn fetch_state(&self) -> &RobotsFetchState {
        &self.fetch
    }

    pub fn decide(&self, profile: &Profile, url: &Url) -> UrlAccess {
        decide(self, profile, url)
    }

    pub fn metadata(&self, profile: &Profile, url: &Url) -> RobotsRunMetadata {
        metadata(self, profile, url)
    }
}

pub fn product_token(user_agent: &str) -> &str {
    user_agent
        .split(['/', ' ', '\t', '('])
        .next()
        .filter(|token| !token.is_empty())
        .unwrap_or(user_agent)
}

pub async fn evaluate_url(
    cache: &RobotsCache,
    transport: &SignedTransport,
    profile: &Profile,
    url: &Url,
) -> std::result::Result<(UrlAccess, RobotsRunMetadata), AccessError> {
    let file = cache.for_url(transport, url).await?;
    Ok((file.decide(profile, url), file.metadata(profile, url)))
}

fn origin_key(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn robots_url(url: &Url) -> Url {
    let mut robots = url.clone();
    robots.set_path(ROBOTS_PATH);
    robots.set_query(None);
    robots.set_fragment(None);
    robots
}

async fn fetch_robots(
    transport: &SignedTransport,
    url: &Url,
) -> std::result::Result<RobotsFile, AccessError> {
    let robots = robots_url(url);
    match transport
        .fetch_with_body(&robots, ResourceKind::Robots)
        .await
    {
        Ok((record, body)) => Ok(file_from_record(&record, &body)),
        Err(err) if err.blocking_status() => Err(err),
        Err(err) => Ok(RobotsFile {
            groups: Vec::new(),
            sitemaps: Vec::new(),
            format_errors: Vec::new(),
            fetch: RobotsFetchState::Unavailable {
                observation: err.observation().to_owned(),
            },
        }),
    }
}

fn file_from_record(record: &FetchRecord, body: &[u8]) -> RobotsFile {
    match record.status {
        404 | 410 => RobotsFile {
            groups: Vec::new(),
            sitemaps: Vec::new(),
            format_errors: Vec::new(),
            fetch: RobotsFetchState::NotFound {
                status: record.status,
            },
        },
        200..=299 => parse_robots(
            body,
            RobotsFetchState::Fetched {
                status: record.status,
            },
        ),
        status => RobotsFile {
            groups: Vec::new(),
            sitemaps: Vec::new(),
            format_errors: Vec::new(),
            fetch: RobotsFetchState::Unavailable {
                observation: format!("HTTP {status} from {}", record.destination_url),
            },
        },
    }
}

fn parse_robots(body: &[u8], fetch: RobotsFetchState) -> RobotsFile {
    let (text, mut format_errors) = decode_body(body);
    let mut groups: Vec<Group> = Vec::new();
    let mut sitemaps = Vec::new();
    let mut current: Option<Group> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let without_comment = strip_comment(raw);
        let line = without_comment.trim();
        if line.is_empty() {
            if let Some(group) = current.take() {
                groups.push(group);
            }
            continue;
        }
        let Some((field, value)) = split_field(line) else {
            format_errors.push(format!("Line {line_no}: missing ':' in robots.txt record"));
            continue;
        };
        let field_l = field.to_ascii_lowercase();
        match field_l.as_str() {
            "user-agent" => {
                let agent = value.trim();
                if agent.is_empty() {
                    format_errors.push(format!("Line {line_no}: empty User-agent"));
                    continue;
                }
                if let Some(group) = current.as_mut()
                    && group.rules.is_empty()
                    && group.crawl_delays.is_empty()
                {
                    group.agents.push(agent.to_owned());
                } else {
                    if let Some(group) = current.take() {
                        groups.push(group);
                    }
                    current = Some(Group {
                        agents: vec![agent.to_owned()],
                        rules: Vec::new(),
                        crawl_delays: Vec::new(),
                    });
                }
            }
            "allow" | "disallow" => {
                let Some(group) = current.as_mut() else {
                    format_errors.push(format!(
                        "Line {line_no}: {field} before any User-agent group"
                    ));
                    continue;
                };
                let pattern = value.trim();
                if !pattern.is_empty() && !pattern.starts_with('/') && !pattern.starts_with('*') {
                    format_errors.push(format!(
                        "Line {line_no}: {field} path must be empty or start with '/' or '*'"
                    ));
                    continue;
                }
                // Empty Disallow is a no-op (allow all). Empty Allow matches every path.
                if pattern.is_empty() && field_l == "disallow" {
                    continue;
                }
                group.rules.push(PathRule {
                    allow: field_l == "allow",
                    pattern: pattern.to_owned(),
                });
            }
            "crawl-delay" => {
                let Some(group) = current.as_mut() else {
                    format_errors.push(format!(
                        "Line {line_no}: Crawl-delay before any User-agent group"
                    ));
                    continue;
                };
                let trimmed = value.trim();
                if trimmed.parse::<f64>().is_err() {
                    format_errors.push(format!("Line {line_no}: Crawl-delay is not a number"));
                }
                group.crawl_delays.push(trimmed.to_owned());
            }
            "sitemap" => {
                let trimmed = value.trim();
                match Url::parse(trimmed) {
                    Ok(url) if matches!(url.scheme(), "https" | "http") => {
                        if !sitemaps.iter().any(|existing| existing == &url) {
                            sitemaps.push(url);
                        }
                    }
                    _ => format_errors.push(format!("Line {line_no}: invalid Sitemap URL")),
                }
            }
            _ => format_errors.push(format!("Line {line_no}: unknown field '{field}'")),
        }
    }
    if let Some(group) = current.take() {
        groups.push(group);
    }

    RobotsFile {
        groups,
        sitemaps,
        format_errors,
        fetch,
    }
}

fn decode_body(body: &[u8]) -> (String, Vec<String>) {
    if body.starts_with(&[0xFF, 0xFE]) || body.starts_with(&[0xFE, 0xFF]) {
        return (
            String::new(),
            vec!["robots.txt used a UTF-16 BOM; the file was not parsed".into()],
        );
    }
    let bytes = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_owned(), Vec::new()),
        Err(_) => (
            bytes.iter().map(|byte| *byte as char).collect(),
            vec!["robots.txt was not valid UTF-8; decoded as ISO-8859-1".into()],
        ),
    }
}

fn strip_comment(line: &str) -> String {
    match line.find('#') {
        Some(idx) => line[..idx].to_owned(),
        None => line.to_owned(),
    }
}

fn split_field(line: &str) -> Option<(&str, &str)> {
    let colon = line.find(':')?;
    Some((line[..colon].trim(), &line[colon + 1..]))
}

fn decide(file: &RobotsFile, profile: &Profile, url: &Url) -> UrlAccess {
    let verdict = access_verdict(file, profile, url);
    match verdict {
        UrlAccess::Blocked(evidence) if profile.bypass_robots => UrlAccess::Allowed {
            reason: AllowReason::OwnerAuditBypass {
                would_block: Box::new(evidence),
            },
        },
        other => other,
    }
}

fn access_verdict(file: &RobotsFile, profile: &Profile, url: &Url) -> UrlAccess {
    match &file.fetch {
        RobotsFetchState::NotFound { .. } => {
            return UrlAccess::Allowed {
                reason: AllowReason::RobotsMissing,
            };
        }
        RobotsFetchState::Unavailable { .. } => {
            return UrlAccess::Allowed {
                reason: AllowReason::RobotsUnavailable,
            };
        }
        RobotsFetchState::Fetched { .. } => {}
    }
    let token = product_token(&profile.user_agent);
    let Some(group) = select_group(&file.groups, token) else {
        return UrlAccess::Allowed {
            reason: AllowReason::NoMatchingRule { group: None },
        };
    };
    let target = match_target(url);
    let agents = group.agents.join(", ");
    match best_rule(&group.rules, &target) {
        Some(rule) if !rule.allow => UrlAccess::Blocked(BlockedEvidence {
            url: url.clone(),
            kind: BlockKind::RobotsTxt,
            group: Some(agents),
            rule: Some(format!("Disallow: {}", rule.pattern)),
            note: "Blocked by robots.txt access policy. This is not a broken page and not a meta noindex finding.".into(),
        }),
        Some(rule) => UrlAccess::Allowed {
            reason: AllowReason::AllowedByRule {
                group: agents,
                rule: format!("Allow: {}", rule.pattern),
            },
        },
        None => UrlAccess::Allowed {
            reason: AllowReason::NoMatchingRule {
                group: Some(agents),
            },
        },
    }
}

fn metadata(file: &RobotsFile, profile: &Profile, url: &Url) -> RobotsRunMetadata {
    let token = product_token(&profile.user_agent).to_owned();
    let selected = select_group(&file.groups, &token).map(|group| group.agents.join(", "));
    let mut crawl_delay_notes = Vec::new();
    for group in &file.groups {
        for delay in &group.crawl_delays {
            crawl_delay_notes.push(format!(
                "Crawl-delay {} for User-agent {} (not used as access policy)",
                delay,
                group.agents.join(", ")
            ));
        }
    }
    RobotsRunMetadata {
        origin: origin_key(url),
        user_agent: profile.user_agent.clone(),
        product_token: token,
        selected_group: selected,
        bypass_robots: profile.bypass_robots,
        bypass_meta: profile.bypass_meta,
        fetch: file.fetch.clone(),
        sitemaps: file.sitemaps.clone(),
        crawl_delay_notes,
        format_errors: file.format_errors.clone(),
    }
}

fn select_group(groups: &[Group], token: &str) -> Option<Group> {
    let token_l = token.to_ascii_lowercase();
    let mut best_len = 0usize;
    for group in groups {
        for agent in &group.agents {
            if agent == "*" {
                continue;
            }
            let agent_l = agent.to_ascii_lowercase();
            if token_l.starts_with(&agent_l) {
                best_len = best_len.max(agent_l.len());
            }
        }
    }
    let matched: Vec<&Group> = if best_len == 0 {
        groups
            .iter()
            .filter(|group| group.agents.iter().any(|agent| agent == "*"))
            .collect()
    } else {
        groups
            .iter()
            .filter(|group| {
                group.agents.iter().any(|agent| {
                    agent != "*"
                        && token_l.starts_with(&agent.to_ascii_lowercase())
                        && agent.len() == best_len
                })
            })
            .collect()
    };
    if matched.is_empty() {
        return None;
    }
    Some(Group {
        agents: matched
            .iter()
            .flat_map(|group| group.agents.iter().cloned())
            .collect(),
        rules: matched
            .iter()
            .flat_map(|group| group.rules.iter().cloned())
            .collect(),
        crawl_delays: matched
            .iter()
            .flat_map(|group| group.crawl_delays.iter().cloned())
            .collect(),
    })
}

fn match_target(url: &Url) -> String {
    let path = percent_decode_path(url.path());
    match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    }
}

fn percent_decode_path(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_owned())
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn best_rule<'a>(rules: &'a [PathRule], target: &str) -> Option<&'a PathRule> {
    let mut best: Option<&PathRule> = None;
    for rule in rules {
        if !path_matches(&rule.pattern, target) {
            continue;
        }
        match best {
            None => best = Some(rule),
            Some(current) => {
                let longer = rule.pattern.len() > current.pattern.len();
                let tie_allow = rule.pattern.len() == current.pattern.len() && rule.allow;
                if longer || tie_allow {
                    best = Some(rule);
                }
            }
        }
    }
    best
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(rest) => (rest, true),
        None => (pattern, false),
    };
    glob_match(pattern.as_bytes(), path.as_bytes(), anchored)
}

fn glob_match(pattern: &[u8], path: &[u8], anchored: bool) -> bool {
    fn rec(pattern: &[u8], path: &[u8], anchored: bool) -> bool {
        match pattern.first() {
            None => {
                if anchored {
                    path.is_empty()
                } else {
                    true
                }
            }
            Some(b'*') => {
                if rec(&pattern[1..], path, anchored) {
                    return true;
                }
                if path.is_empty() {
                    return false;
                }
                rec(pattern, &path[1..], anchored)
            }
            Some(expected) => {
                path.first() == Some(expected) && rec(&pattern[1..], &path[1..], anchored)
            }
        }
    }
    rec(pattern, path, anchored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    fn profile_with(ua: &str, bypass_robots: bool) -> Profile {
        let mut toml = include_str!("../../../profile.example.toml").to_owned();
        toml = toml.replace(
            "user_agent = \"Crawlytic/0.1 (self-hosted SEO audit)\"",
            &format!("user_agent = \"{ua}\""),
        );
        toml = toml.replace(
            "bypass_robots = false",
            &format!("bypass_robots = {bypass_robots}"),
        );
        Profile::load(&toml).unwrap()
    }

    fn own_profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn url(path: &str) -> Url {
        Url::parse(&format!("https://www.tiendacables.com{path}")).unwrap()
    }

    #[test]
    fn user_agent_selects_the_longest_matching_group() {
        let file = RobotsFile::parse(
            b"User-agent: *\nDisallow: /\n\nUser-agent: Crawlytic\nAllow: /\nDisallow: /private\n\nUser-agent: CrawlyticBot\nDisallow: /only-bot\n",
        );
        let crawlytic = profile_with("Crawlytic/0.1 (self-hosted SEO audit)", false);
        assert!(matches!(
            file.decide(&crawlytic, &url("/ok")),
            UrlAccess::Allowed {
                reason: AllowReason::AllowedByRule { .. }
            }
        ));
        assert!(matches!(
            file.decide(&crawlytic, &url("/private")),
            UrlAccess::Blocked(BlockedEvidence {
                kind: BlockKind::RobotsTxt,
                ..
            })
        ));
        let other = profile_with("OtherBot/1.0", false);
        assert!(matches!(
            file.decide(&other, &url("/ok")),
            UrlAccess::Blocked(_)
        ));
        let bot = profile_with("CrawlyticBot/2.0", false);
        assert!(matches!(
            file.decide(&bot, &url("/only-bot")),
            UrlAccess::Blocked(_)
        ));
        assert!(matches!(
            file.decide(&bot, &url("/private")),
            UrlAccess::Allowed { .. }
        ));
    }

    #[test]
    fn longest_rule_wins_and_equal_length_prefers_allow() {
        let file = RobotsFile::parse(
            b"User-agent: *\nDisallow: /fish\nAllow: /fish.html\nAllow: /fish\nDisallow: /fish\nDisallow: /fish/\n",
        );
        let profile = own_profile();
        assert!(matches!(
            file.decide(&profile, &url("/fish.html")),
            UrlAccess::Allowed {
                reason: AllowReason::AllowedByRule { rule, .. }
            } if rule.contains("/fish.html")
        ));
        assert!(matches!(
            file.decide(&profile, &url("/fish")),
            UrlAccess::Allowed { .. }
        ));
        assert!(matches!(
            file.decide(&profile, &url("/fish/salmon")),
            UrlAccess::Blocked(_)
        ));
    }

    #[test]
    fn wildcards_and_end_anchors_match_paths() {
        let file = RobotsFile::parse(
            b"User-agent: *\nDisallow: /*.php$\nAllow: /ok/*.php$\nDisallow: /private*/\n",
        );
        let profile = own_profile();
        assert!(matches!(
            file.decide(&profile, &url("/page.php")),
            UrlAccess::Blocked(_)
        ));
        assert!(matches!(
            file.decide(&profile, &url("/page.php?x=1")),
            UrlAccess::Allowed { .. }
        ));
        assert!(matches!(
            file.decide(&profile, &url("/ok/page.php")),
            UrlAccess::Allowed { .. }
        ));
        assert!(matches!(
            file.decide(&profile, &url("/private-area/secret")),
            UrlAccess::Blocked(_)
        ));
    }

    #[test]
    fn encodings_are_documented() {
        let bom = b"\xEF\xBB\xBFUser-agent: *\nDisallow: /secret\n".to_vec();
        let file = RobotsFile::parse(&bom);
        assert!(matches!(
            file.decide(&own_profile(), &url("/secret")),
            UrlAccess::Blocked(_)
        ));
        assert!(file.format_errors().is_empty());

        let latin1 = {
            let mut bytes = b"User-agent: *\nDisallow: /caf".to_vec();
            bytes.push(0xE9);
            bytes.extend_from_slice(b"\n");
            bytes
        };
        let file = RobotsFile::parse(&latin1);
        assert!(
            file.format_errors()
                .iter()
                .any(|err| err.contains("ISO-8859-1")),
            "{:?}",
            file.format_errors()
        );
        assert!(matches!(
            file.decide(&own_profile(), &url("/café")),
            UrlAccess::Blocked(_)
        ));

        let utf16 = [0xFF, 0xFE, b'U', 0, b's', 0];
        let file = RobotsFile::parse(&utf16);
        assert!(
            file.format_errors()
                .iter()
                .any(|err| err.contains("UTF-16"))
        );
        assert!(matches!(
            file.decide(&own_profile(), &url("/anything")),
            UrlAccess::Allowed {
                reason: AllowReason::NoMatchingRule { .. }
            }
        ));
    }

    #[test]
    fn missing_or_unavailable_robots_are_not_denials_or_broken_pages() {
        let missing = RobotsFile {
            groups: Vec::new(),
            sitemaps: Vec::new(),
            format_errors: Vec::new(),
            fetch: RobotsFetchState::NotFound { status: 404 },
        };
        assert!(matches!(
            missing.decide(&own_profile(), &url("/")),
            UrlAccess::Allowed {
                reason: AllowReason::RobotsMissing
            }
        ));
        let down = RobotsFile {
            groups: Vec::new(),
            sitemaps: Vec::new(),
            format_errors: Vec::new(),
            fetch: RobotsFetchState::Unavailable {
                observation: "HTTP 500 from https://www.tiendacables.com/robots.txt".into(),
            },
        };
        let access = down.decide(&own_profile(), &url("/"));
        assert!(matches!(
            access,
            UrlAccess::Allowed {
                reason: AllowReason::RobotsUnavailable
            }
        ));
        assert!(!matches!(access, UrlAccess::Blocked(_)));
    }

    #[test]
    fn robots_denial_is_blocked_evidence_not_a_broken_page() {
        let file = RobotsFile::parse(b"User-agent: *\nDisallow: /hidden\n");
        let UrlAccess::Blocked(evidence) = file.decide(&own_profile(), &url("/hidden")) else {
            panic!("expected denial");
        };
        assert_eq!(evidence.kind, BlockKind::RobotsTxt);
        assert_ne!(evidence.kind, BlockKind::MetaNoindex);
        assert!(
            evidence.note.contains("not a broken page"),
            "{}",
            evidence.note
        );
        assert!(evidence.note.to_lowercase().contains("not a meta noindex"));
        assert_eq!(evidence.rule.as_deref(), Some("Disallow: /hidden"));
    }

    #[test]
    fn default_tiendacables_profile_keeps_bypass_off_for_signed_requests() {
        let own = own_profile();
        let comparison = Profile::load(include_str!("../../../profile.comparison.toml")).unwrap();
        assert!(!own.bypass_robots);
        assert!(!own.bypass_meta);
        assert!(own.web_bot_auth_required);
        assert!(!comparison.bypass_robots);
        let file = RobotsFile::parse(b"User-agent: *\nDisallow: /\n");
        assert!(matches!(
            file.decide(&own, &url("/")),
            UrlAccess::Blocked(_)
        ));
        let meta = file.metadata(&own, &url("/"));
        assert!(!meta.bypass_robots);
        assert!(!meta.bypass_meta);
    }

    #[test]
    fn owner_audit_override_is_explicit_and_retained() {
        let file = RobotsFile::parse(b"User-agent: *\nDisallow: /secret\nSitemap: https://www.tiendacables.com/sitemap.xml\n");
        let bypass = profile_with("Crawlytic/0.1 (self-hosted SEO audit)", true);
        assert!(bypass.bypass_robots);
        match file.decide(&bypass, &url("/secret")) {
            UrlAccess::Allowed {
                reason: AllowReason::OwnerAuditBypass { would_block },
            } => {
                assert_eq!(would_block.kind, BlockKind::RobotsTxt);
                assert_ne!(would_block.kind, BlockKind::MetaNoindex);
            }
            other => panic!("expected recorded bypass, got {other:?}"),
        }
        let meta = file.metadata(&bypass, &url("/secret"));
        assert!(meta.bypass_robots);
        assert!(!meta.bypass_meta);
        assert_eq!(
            meta.sitemaps,
            vec![Url::parse("https://www.tiendacables.com/sitemap.xml").unwrap()]
        );
    }

    #[test]
    fn crawl_delay_is_not_access_policy_and_sitemaps_are_extracted() {
        let file = RobotsFile::parse(
            b"User-agent: *\nCrawl-delay: 10\nAllow: /\nSitemap: https://www.tiendacables.com/sitemap.xml\nSitemap: https://www.tiendacables.com/sitemap.xml\nSitemap: https://www.tiendacables.com/sitemap_products_1.xml\nHost: ignored.example\n",
        );
        let profile = own_profile();
        assert!(matches!(
            file.decide(&profile, &url("/slow")),
            UrlAccess::Allowed { .. }
        ));
        let meta = file.metadata(&profile, &url("/slow"));
        assert!(
            meta.crawl_delay_notes
                .iter()
                .any(|note| note.contains("not used as access policy")),
            "{:?}",
            meta.crawl_delay_notes
        );
        assert_eq!(meta.sitemaps.len(), 2);
        assert!(
            meta.format_errors
                .iter()
                .any(|err| err.contains("unknown field")),
            "{:?}",
            meta.format_errors
        );
    }

    #[test]
    fn conflicting_groups_do_not_merge_across_blank_lines() {
        let file = RobotsFile::parse(
            b"User-agent: Crawlytic\nUser-agent: OtherBot\nDisallow: /shared\n\nUser-agent: Crawlytic\nAllow: /shared\n",
        );
        let profile = own_profile();
        assert!(matches!(
            file.decide(&profile, &url("/shared")),
            UrlAccess::Allowed { .. }
        ));
    }
}
