//! Canonical, indexability, robots and sitemap checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::crawl::{SitemapFileState, SitemapInventory, UrlState};
use crate::extract::ExtractedObservations;
use crate::robots::{RobotsFetchState, RobotsRunMetadata};
use crate::scope::FetchIdentity;
use std::collections::BTreeMap;
use url::Url;

/// sitemaps.org protocol limit, not a Semrush formula. Override with `max_sitemap_urls`.
pub const DEFAULT_MAX_SITEMAP_URLS: usize = 50_000;
/// sitemaps.org 50 MiB uncompressed limit. Override with `max_sitemap_bytes`.
pub const DEFAULT_MAX_SITEMAP_BYTES: u64 = 52_428_800;

pub fn indexability_registry() -> Registry {
    let mut registry = Registry::new();
    register_indexability(&mut registry);
    registry
}

pub fn register_indexability(registry: &mut Registry) {
    registry.register(CanonicalBroken);
    registry.register(CanonicalMultiple);
    registry.register(IndexabilityXRobotsNoindex);
    registry.register(SitemapFormatErrors);
    registry.register(SitemapIncorrectPages);
    registry.register(SitemapOversized);
    registry.register(SitemapNotDeclaredInRobots);
    registry.register(SitemapNotFound);
    registry.register(SitemapHttpUrlsInHttps);
    registry.register(RobotsFormatErrors);
    registry.register(RobotsNotFound);
    registry.register(RobotsPagesBlocked);
}

fn incomplete() -> CheckerOutput {
    CheckerOutput {
        applicable: true,
        evidence_complete: false,
        findings: Vec::new(),
    }
}

fn not_applicable() -> CheckerOutput {
    CheckerOutput {
        applicable: false,
        evidence_complete: true,
        findings: Vec::new(),
    }
}

fn complete(findings: Vec<FindingDraft>) -> CheckerOutput {
    CheckerOutput {
        applicable: true,
        evidence_complete: true,
        findings,
    }
}

fn pointer(
    identity: impl Into<String>,
    field: &str,
    excerpt: impl Into<String>,
) -> EvidencePointer {
    EvidencePointer {
        observation_identity: identity.into(),
        field: field.into(),
        excerpt: excerpt.into(),
    }
}

fn usize_threshold(config: &AuditConfig, key: &str, default: usize) -> usize {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn normalize_identity(value: &str) -> String {
    match Url::parse(value) {
        Ok(url) => FetchIdentity::from_url(&url).as_str().to_owned(),
        Err(_) => value.to_owned(),
    }
}

fn resolve_href(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() {
        return None;
    }
    let base = Url::parse(base).ok()?;
    let resolved = base.join(href).ok()?;
    Some(FetchIdentity::from_url(&resolved).as_str().to_owned())
}

fn resolved_canonicals(obs: &ExtractedObservations) -> Vec<String> {
    let mut out = Vec::new();
    for href in &obs.page.canonicals {
        let Some(resolved) = resolve_href(&obs.identity, href) else {
            continue;
        };
        if !out.contains(&resolved) {
            out.push(resolved);
        }
    }
    out
}

fn has_noindex(values: &[String]) -> bool {
    values.iter().any(|value| {
        value.to_ascii_lowercase().split([',', ';']).any(|token| {
            token
                .split_whitespace()
                .any(|part| part.trim() == "noindex")
        })
    })
}

fn header_noindex(obs: &ExtractedObservations) -> bool {
    has_noindex(&obs.page.robots_headers)
}

fn meta_noindex(obs: &ExtractedObservations) -> bool {
    has_noindex(&obs.page.robots_meta)
}

fn page_noindex(obs: &ExtractedObservations) -> bool {
    header_noindex(obs) || meta_noindex(obs)
}

fn complete_html<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    evidence
        .observations
        .iter()
        .filter(|observation| observation.page.is_complete())
        .collect()
}

struct Target<'a> {
    status: Option<u16>,
    failed_reason: Option<&'a str>,
    state: Option<UrlState>,
    observation: Option<&'a ExtractedObservations>,
}

fn target_index<'a>(evidence: &'a EvidenceBundle<'_>) -> BTreeMap<String, Target<'a>> {
    let mut map = BTreeMap::new();
    for record in evidence.urls {
        let key = match &record.identity {
            Some(identity) => normalize_identity(identity.as_str()),
            None => normalize_identity(&record.original),
        };
        let failed = (record.state == UrlState::Failed).then_some(record.reason.as_str());
        map.insert(
            key,
            Target {
                status: None,
                failed_reason: failed,
                state: Some(record.state),
                observation: None,
            },
        );
    }
    for observation in evidence.observations {
        let key = normalize_identity(&observation.identity);
        let entry = map.entry(key).or_insert(Target {
            status: None,
            failed_reason: None,
            state: None,
            observation: None,
        });
        entry.status = Some(observation.page.status);
        entry.observation = Some(observation);
    }
    map
}

fn lookup<'a>(index: &'a BTreeMap<String, Target<'a>>, url: &str) -> Option<&'a Target<'a>> {
    index.get(&normalize_identity(url))
}

fn in_sitemap(evidence: &EvidenceBundle<'_>, identity: &str) -> bool {
    let Some(sitemap) = evidence.sitemap else {
        return false;
    };
    let key = normalize_identity(identity);
    sitemap.urls.iter().any(|listed| {
        listed.skip_reason.is_none()
            && listed
                .identity
                .as_ref()
                .map(|id| normalize_identity(id.as_str()) == key)
                .unwrap_or_else(|| normalize_identity(&listed.original) == key)
    })
}

fn robots_url(robots: &RobotsRunMetadata) -> String {
    format!("{}/robots.txt", robots.origin.trim_end_matches('/'))
}

fn expected_sitemap(robots: Option<&RobotsRunMetadata>) -> String {
    if let Some(url) = robots.and_then(|meta| meta.sitemaps.first()) {
        return url.as_str().to_owned();
    }
    robots
        .map(|meta| format!("{}/sitemap.xml", meta.origin.trim_end_matches('/')))
        .unwrap_or_else(|| "/sitemap.xml".into())
}

struct CanonicalBroken;
struct CanonicalMultiple;
struct IndexabilityXRobotsNoindex;
struct SitemapFormatErrors;
struct SitemapIncorrectPages;
struct SitemapOversized;
struct SitemapNotDeclaredInRobots;
struct SitemapNotFound;
struct SitemapHttpUrlsInHttps;
struct RobotsFormatErrors;
struct RobotsNotFound;
struct RobotsPagesBlocked;

impl Checker for CanonicalBroken {
    fn rule_id(&self) -> &'static str {
        "canonical.broken"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let declared: Vec<_> = pages
            .into_iter()
            .filter(|page| !page.page.canonicals.is_empty())
            .collect();
        if declared.is_empty() {
            return not_applicable();
        }
        let index = target_index(evidence);
        let mut findings = Vec::new();
        let mut missing = false;
        for page in declared {
            let mut visited = vec![normalize_identity(&page.identity)];
            for href in &page.page.canonicals {
                let Some(target_url) = resolve_href(&page.identity, href) else {
                    findings.push(FindingDraft {
                        entity_key: page.identity.clone(),
                        fact: format!(
                            "Page {} declares an unresolvable canonical href {}.",
                            page.identity, href
                        ),
                        recommendation: "Publish a single absolute, fetchable canonical URL."
                            .into(),
                        evidence: vec![pointer(page.identity.clone(), "canonical", href.clone())],
                    });
                    continue;
                };
                if visited.contains(&target_url) {
                    continue;
                }
                visited.push(target_url.clone());
                match lookup(&index, &target_url) {
                    None => missing = true,
                    Some(target) => {
                        if matches!(
                            target.state,
                            Some(UrlState::Excluded | UrlState::Pending | UrlState::InFlight)
                        ) && target.observation.is_none()
                        {
                            missing = true;
                            continue;
                        }
                        if let Some(status) = target.status {
                            if (400..600).contains(&status) {
                                findings.push(FindingDraft {
                                    entity_key: page.identity.clone(),
                                    fact: format!(
                                        "Page {} canonical {} resolved from {} returns HTTP {status}.",
                                        page.identity, target_url, href
                                    ),
                                    recommendation:
                                        "Point rel=canonical at a URL that returns HTTP 200."
                                            .into(),
                                    evidence: vec![pointer(
                                        page.identity.clone(),
                                        "canonical",
                                        format!("{href} -> {target_url} HTTP {status}"),
                                    )],
                                });
                                continue;
                            }
                        } else if let Some(reason) = target.failed_reason {
                            findings.push(FindingDraft {
                                entity_key: page.identity.clone(),
                                fact: format!(
                                    "Page {} canonical {} resolved from {} failed ({reason}).",
                                    page.identity, target_url, href
                                ),
                                recommendation: "Point rel=canonical at a reachable URL.".into(),
                                evidence: vec![pointer(
                                    page.identity.clone(),
                                    "canonical",
                                    format!("{href} -> {target_url} {reason}"),
                                )],
                            });
                            continue;
                        } else {
                            missing = true;
                            continue;
                        }
                        if let Some(obs) = target.observation
                            && page_noindex(obs)
                        {
                            let intended = if in_sitemap(evidence, &page.identity) {
                                "source is listed in the sitemap (intended indexable)"
                            } else {
                                "source is not listed in the sitemap"
                            };
                            findings.push(FindingDraft {
                                entity_key: page.identity.clone(),
                                fact: format!(
                                    "Page {} canonical {} is non-indexable (noindex). {intended}.",
                                    page.identity, target_url
                                ),
                                recommendation: "Canonicalize to an indexable URL, or align noindex with the intended page.".into(),
                                evidence: vec![pointer(
                                    page.identity.clone(),
                                    "canonical",
                                    format!("{href} -> {target_url} noindex"),
                                )],
                            });
                        }
                    }
                }
            }
        }
        if missing {
            return incomplete();
        }
        complete(findings)
    }
}

impl Checker for CanonicalMultiple {
    fn rule_id(&self) -> &'static str {
        "canonical.multiple"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for page in pages {
            let resolved = resolved_canonicals(page);
            if resolved.len() > 1 {
                findings.push(FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: format!(
                        "Page {} declares {} distinct canonicals: {}.",
                        page.identity,
                        resolved.len(),
                        resolved.join(" | ")
                    ),
                    recommendation: "Keep a single distinct rel=canonical target per page.".into(),
                    evidence: vec![pointer(
                        page.identity.clone(),
                        "canonical",
                        page.page.canonicals.join(" | "),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for IndexabilityXRobotsNoindex {
    fn rule_id(&self) -> &'static str {
        "indexability.x_robots_noindex"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for obs in evidence.observations {
            if !header_noindex(obs) {
                continue;
            }
            let meta = if obs.page.robots_meta.is_empty() {
                "meta robots absent".into()
            } else {
                format!("meta robots={}", obs.page.robots_meta.join(" | "))
            };
            let intended = if in_sitemap(evidence, &obs.identity) {
                "page is listed in the sitemap (intended indexable)"
            } else {
                "page is not listed in the sitemap"
            };
            findings.push(FindingDraft {
                entity_key: obs.identity.clone(),
                fact: format!(
                    "Page {} sends X-Robots-Tag: {}. This is separate from fetch permission ({meta}); {intended}.",
                    obs.identity,
                    obs.page.robots_headers.join(" | ")
                ),
                recommendation: "Remove noindex from X-Robots-Tag when the page should be indexed, especially if it is in the sitemap.".into(),
                evidence: vec![pointer(
                    obs.identity.clone(),
                    "x_robots_tag",
                    obs.page.robots_headers.join(" | "),
                )],
            });
        }
        complete(findings)
    }
}

fn sitemap_or_incomplete<'a>(
    evidence: &'a EvidenceBundle<'a>,
) -> Result<&'a SitemapInventory, CheckerOutput> {
    match evidence.sitemap {
        Some(sitemap) if evidence.sitemap_done => Ok(sitemap),
        Some(_) | None => Err(incomplete()),
    }
}

impl Checker for SitemapFormatErrors {
    fn rule_id(&self) -> &'static str {
        "sitemap.format_errors"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let sitemap = match sitemap_or_incomplete(evidence) {
            Ok(sitemap) => sitemap,
            Err(output) => return output,
        };
        if sitemap.files.is_empty() {
            return not_applicable();
        }
        let mut findings = Vec::new();
        for file in &sitemap.files {
            if file.state == SitemapFileState::ParseError {
                findings.push(FindingDraft {
                    entity_key: file.url.clone(),
                    fact: format!(
                        "Sitemap {} is not valid sitemap XML ({})",
                        file.url, file.reason
                    ),
                    recommendation: "Serve a well-formed urlset or sitemapindex document.".into(),
                    evidence: vec![pointer(
                        file.url.clone(),
                        "sitemap_xml",
                        file.reason.clone(),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for SitemapIncorrectPages {
    fn rule_id(&self) -> &'static str {
        "sitemap.incorrect_pages"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let sitemap = match sitemap_or_incomplete(evidence) {
            Ok(sitemap) => sitemap,
            Err(output) => return output,
        };
        let listed: Vec<_> = sitemap
            .urls
            .iter()
            .filter(|url| url.skip_reason.is_none())
            .collect();
        if listed.is_empty() {
            return not_applicable();
        }
        let index = target_index(evidence);
        let mut findings = Vec::new();
        for listed in listed {
            let key = listed
                .identity
                .as_ref()
                .map(|id| normalize_identity(id.as_str()))
                .unwrap_or_else(|| normalize_identity(&listed.original));
            let Some(target) = lookup(&index, &key) else {
                return incomplete();
            };
            match target.state {
                Some(UrlState::Excluded | UrlState::Pending | UrlState::InFlight) => {
                    return incomplete();
                }
                Some(UrlState::Blocked) => {
                    findings.push(FindingDraft {
                        entity_key: key.clone(),
                        fact: format!(
                            "Sitemap {} lists {} which is blocked by robots.txt ({}) and conflicts with indexing policy.",
                            listed.source_sitemap,
                            listed.original,
                            target.failed_reason.unwrap_or("blocked")
                        ),
                        recommendation: "Remove blocked URLs from the sitemap or allow them in robots.txt.".into(),
                        evidence: vec![pointer(
                            listed.source_sitemap.clone(),
                            "sitemap_url",
                            format!("{} blocked", listed.original),
                        )],
                    });
                    continue;
                }
                _ => {}
            }
            let Some(obs) = target.observation else {
                if target.failed_reason.is_some() {
                    findings.push(FindingDraft {
                        entity_key: key.clone(),
                        fact: format!(
                            "Sitemap {} lists {} which failed to fetch ({}).",
                            listed.source_sitemap,
                            listed.original,
                            target.failed_reason.unwrap_or("failed")
                        ),
                        recommendation: "Remove failing URLs from the sitemap or restore the page."
                            .into(),
                        evidence: vec![pointer(
                            listed.source_sitemap.clone(),
                            "sitemap_url",
                            listed.original.clone(),
                        )],
                    });
                    continue;
                }
                return incomplete();
            };
            if (400..600).contains(&obs.page.status) {
                findings.push(FindingDraft {
                    entity_key: key.clone(),
                    fact: format!(
                        "Sitemap {} lists {} which returns HTTP {}.",
                        listed.source_sitemap, listed.original, obs.page.status
                    ),
                    recommendation: "List only URLs that return HTTP 200 without errors.".into(),
                    evidence: vec![pointer(
                        obs.identity.clone(),
                        "page_http_status",
                        obs.page.status.to_string(),
                    )],
                });
            }
            if !obs.redirect_chain.is_empty() || matches!(obs.page.status, 301 | 302 | 307 | 308) {
                let hops = if obs.redirect_chain.is_empty() {
                    format!("HTTP {}", obs.page.status)
                } else {
                    let mut path = obs.redirect_chain[0].from.clone();
                    for hop in &obs.redirect_chain {
                        path.push_str(&format!(" -{}-> {}", hop.status, hop.to));
                    }
                    path
                };
                findings.push(FindingDraft {
                    entity_key: key.clone(),
                    fact: format!(
                        "Sitemap {} lists {} which redirects ({hops}).",
                        listed.source_sitemap, listed.original
                    ),
                    recommendation: "List the final canonical URL instead of a redirecting alias."
                        .into(),
                    evidence: vec![pointer(obs.identity.clone(), "sitemap_url", hops)],
                });
            }
            let canonicals = resolved_canonicals(obs);
            if let Some(canonical) = canonicals.first()
                && normalize_identity(canonical) != key
            {
                findings.push(FindingDraft {
                    entity_key: key.clone(),
                    fact: format!(
                        "Sitemap {} lists {} which canonicalizes to {} (off-canonical).",
                        listed.source_sitemap, listed.original, canonical
                    ),
                    recommendation: "List the canonical URL in the sitemap.".into(),
                    evidence: vec![pointer(
                        obs.identity.clone(),
                        "canonical",
                        canonical.clone(),
                    )],
                });
            }
            if page_noindex(obs) {
                findings.push(FindingDraft {
                    entity_key: key.clone(),
                    fact: format!(
                        "Sitemap {} lists {} which is noindex and conflicts with indexing policy.",
                        listed.source_sitemap, listed.original
                    ),
                    recommendation: "Remove noindex pages from the sitemap or make them indexable."
                        .into(),
                    evidence: vec![pointer(obs.identity.clone(), "sitemap_url", "noindex")],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for SitemapOversized {
    fn rule_id(&self) -> &'static str {
        "sitemap.oversized"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let sitemap = match sitemap_or_incomplete(evidence) {
            Ok(sitemap) => sitemap,
            Err(output) => return output,
        };
        if sitemap.files.is_empty() {
            return not_applicable();
        }
        let max_urls = usize_threshold(config, "max_sitemap_urls", DEFAULT_MAX_SITEMAP_URLS);
        let mut findings = Vec::new();
        for file in &sitemap.files {
            let over_count = file.listed_urls > max_urls;
            let over_size = file.state == SitemapFileState::Oversized;
            if over_count || over_size {
                findings.push(FindingDraft {
                    entity_key: file.url.clone(),
                    fact: format!(
                        "Sitemap {} exceeds sitemaps.org limits ({} URLs, state {:?}, cap {max_urls} URLs / {} bytes).",
                        file.url, file.listed_urls, file.state, DEFAULT_MAX_SITEMAP_BYTES
                    ),
                    recommendation: "Split the sitemap so each file stays under 50,000 URLs and 50 MiB.".into(),
                    evidence: vec![pointer(
                        file.url.clone(),
                        "sitemap_url_count",
                        format!("{} {}", file.listed_urls, file.reason),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for SitemapNotDeclaredInRobots {
    fn rule_id(&self) -> &'static str {
        "sitemap.not_declared_in_robots"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(robots) = evidence.robots else {
            return incomplete();
        };
        match robots.fetch {
            RobotsFetchState::Fetched { .. } => {}
            RobotsFetchState::NotFound { .. } | RobotsFetchState::Unavailable { .. } => {
                return incomplete();
            }
        }
        if !robots.sitemaps.is_empty() {
            return complete(Vec::new());
        }
        let robots_txt = robots_url(robots);
        complete(vec![FindingDraft {
            entity_key: robots.origin.clone(),
            fact: format!("{robots_txt} has no Sitemap directive."),
            recommendation: "Declare the sitemap with a Sitemap: line in robots.txt.".into(),
            evidence: vec![pointer(
                robots_txt,
                "robots_txt",
                "Sitemap directive absent",
            )],
        }])
    }
}

impl Checker for SitemapNotFound {
    fn rule_id(&self) -> &'static str {
        "sitemap.not_found"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let sitemap = match sitemap_or_incomplete(evidence) {
            Ok(sitemap) => sitemap,
            Err(output) => return output,
        };
        let mut findings = Vec::new();
        if sitemap.files.is_empty() {
            let expected = expected_sitemap(evidence.robots);
            findings.push(FindingDraft {
                entity_key: expected.clone(),
                fact: format!("No sitemap was fetched; expected {expected} was not found."),
                recommendation: "Publish a reachable sitemap and declare it in robots.txt.".into(),
                evidence: vec![pointer(expected, "sitemap_http_status", "not requested")],
            });
            return complete(findings);
        }
        for file in &sitemap.files {
            if file.state == SitemapFileState::Inaccessible {
                findings.push(FindingDraft {
                    entity_key: file.url.clone(),
                    fact: format!("Sitemap {} was not found ({})", file.url, file.reason),
                    recommendation: "Serve the sitemap at the declared URL with HTTP 200.".into(),
                    evidence: vec![pointer(
                        file.url.clone(),
                        "sitemap_http_status",
                        file.reason.clone(),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for SitemapHttpUrlsInHttps {
    fn rule_id(&self) -> &'static str {
        "sitemap.http_urls_in_https"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let sitemap = match sitemap_or_incomplete(evidence) {
            Ok(sitemap) => sitemap,
            Err(output) => return output,
        };
        let https_files: Vec<_> = sitemap
            .files
            .iter()
            .filter(|file| {
                Url::parse(&file.url)
                    .map(|url| url.scheme() == "https")
                    .unwrap_or(false)
            })
            .collect();
        if https_files.is_empty() {
            return not_applicable();
        }
        let fetched: Vec<_> = https_files
            .iter()
            .filter(|file| file.state == SitemapFileState::Fetched)
            .map(|file| file.url.as_str())
            .collect();
        if fetched.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for listed in &sitemap.urls {
            let Ok(source) = Url::parse(&listed.source_sitemap) else {
                continue;
            };
            if source.scheme() != "https" || !fetched.contains(&listed.source_sitemap.as_str()) {
                continue;
            }
            let loc = resolve_href(&listed.source_sitemap, &listed.original)
                .unwrap_or_else(|| listed.original.clone());
            let Ok(loc_url) = Url::parse(&loc) else {
                continue;
            };
            if loc_url.scheme() == "http" {
                findings.push(FindingDraft {
                    entity_key: loc.clone(),
                    fact: format!(
                        "HTTPS sitemap {} lists HTTP URL {}.",
                        listed.source_sitemap, listed.original
                    ),
                    recommendation: "List HTTPS loc values in HTTPS sitemaps.".into(),
                    evidence: vec![pointer(
                        listed.source_sitemap.clone(),
                        "sitemap_xml",
                        listed.original.clone(),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for RobotsFormatErrors {
    fn rule_id(&self) -> &'static str {
        "robots.format_errors"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(robots) = evidence.robots else {
            return incomplete();
        };
        match robots.fetch {
            RobotsFetchState::Fetched { .. } => {}
            RobotsFetchState::NotFound { .. } | RobotsFetchState::Unavailable { .. } => {
                return not_applicable();
            }
        }
        if robots.format_errors.is_empty() {
            return complete(Vec::new());
        }
        let robots_txt = robots_url(robots);
        complete(vec![FindingDraft {
            entity_key: robots.origin.clone(),
            fact: format!(
                "{robots_txt} has format errors: {}.",
                robots.format_errors.join("; ")
            ),
            recommendation: "Fix unknown or malformed robots.txt directives.".into(),
            evidence: vec![pointer(
                robots_txt,
                "robots_txt",
                robots.format_errors.join("\n"),
            )],
        }])
    }
}

impl Checker for RobotsNotFound {
    fn rule_id(&self) -> &'static str {
        "robots.not_found"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(robots) = evidence.robots else {
            return incomplete();
        };
        let robots_txt = robots_url(robots);
        match robots.fetch {
            RobotsFetchState::NotFound { status } => complete(vec![FindingDraft {
                entity_key: robots.origin.clone(),
                fact: format!("{robots_txt} returns HTTP {status} (missing robots.txt is not a fetch denial)."),
                recommendation: "Publish robots.txt if you need crawl policy; missing is allowed and not treated as a block.".into(),
                evidence: vec![pointer(
                    robots_txt,
                    "robots_http_status",
                    status.to_string(),
                )],
            }]),
            RobotsFetchState::Fetched { .. } => complete(Vec::new()),
            RobotsFetchState::Unavailable { .. } => incomplete(),
        }
    }
}

impl Checker for RobotsPagesBlocked {
    fn rule_id(&self) -> &'static str {
        "robots.pages_blocked_from_crawling"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.robots.is_none() {
            return incomplete();
        }
        if evidence.urls.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for record in evidence.urls {
            if record.state != UrlState::Blocked {
                continue;
            }
            let identity = record
                .identity
                .as_ref()
                .map(FetchIdentity::as_str)
                .unwrap_or(record.original.as_str());
            findings.push(FindingDraft {
                entity_key: identity.to_owned(),
                fact: format!(
                    "URL {identity} is blocked by robots.txt access policy ({}). Fetch permission is separate from meta robots noindex.",
                    record.reason
                ),
                recommendation: "Allow the path in robots.txt if it should be crawled, or keep it blocked intentionally.".into(),
                evidence: vec![pointer(identity, "url", record.reason.clone())],
            });
        }
        complete(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::RuleState;
    use crate::crawl::{SitemapFileRecord, SitemapUrlRecord, UrlRecord};
    use crate::extract::{ExtractHeader, ExtractInput, extract};
    use crate::profile::Profile;
    use crate::store::Store;

    fn page(url: &str, body: &str) -> ExtractedObservations {
        page_full(url, 200, "text/html", body.as_bytes(), &[])
    }

    fn page_full(
        url: &str,
        status: u16,
        content_type: &str,
        body: &[u8],
        headers: &[ExtractHeader<'_>],
    ) -> ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status,
            content_type,
            headers,
            body,
            truncated: false,
            duration_ms: Some(1),
        })
    }

    fn identity(url: &str) -> FetchIdentity {
        FetchIdentity::from_url(&Url::parse(url).unwrap())
    }

    fn url_rec(url: &str, state: UrlState, reason: &str, via_sitemap: bool) -> UrlRecord {
        UrlRecord {
            original: url.to_owned(),
            identity: Some(identity(url)),
            state,
            reason: reason.to_owned(),
            click_depth: Some(0),
            via_website: true,
            via_sitemap,
        }
    }

    fn sitemap_file(
        url: &str,
        state: SitemapFileState,
        reason: &str,
        listed: usize,
    ) -> SitemapFileRecord {
        SitemapFileRecord {
            url: url.to_owned(),
            identity: Some(identity(url)),
            state,
            reason: reason.to_owned(),
            listed_urls: listed,
        }
    }

    fn sitemap_url(original: &str, source: &str, skip: Option<&str>) -> SitemapUrlRecord {
        SitemapUrlRecord {
            original: original.to_owned(),
            identity: skip.is_none().then(|| identity(original)),
            skip_reason: skip.map(str::to_owned),
            source_sitemap: source.to_owned(),
        }
    }

    fn robots_meta(
        fetch: RobotsFetchState,
        sitemaps: &[&str],
        format_errors: &[&str],
    ) -> RobotsRunMetadata {
        RobotsRunMetadata {
            origin: "https://audit.example".into(),
            user_agent: "Crawlytic".into(),
            product_token: "Crawlytic".into(),
            selected_group: Some("*".into()),
            bypass_robots: false,
            bypass_meta: false,
            fetch,
            sitemaps: sitemaps
                .iter()
                .map(|url| Url::parse(url).unwrap())
                .collect(),
            crawl_delay_notes: Vec::new(),
            format_errors: format_errors
                .iter()
                .map(|line| (*line).to_owned())
                .collect(),
        }
    }

    fn run(
        obs: &[ExtractedObservations],
        urls: &[UrlRecord],
        sitemap: Option<&SitemapInventory>,
        robots: Option<&RobotsRunMetadata>,
    ) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls,
                sitemap,
                sitemap_done: sitemap.is_some(),
                robots,
                resource_fetches: &[],
            },
            &AuditConfig::default(),
            &indexability_registry(),
            &[],
        )
    }

    fn html(canonical: &str) -> String {
        format!(
            r#"<!DOCTYPE html><html><head><link rel="canonical" href="{canonical}"></head><body>p</body></html>"#
        )
    }

    #[test]
    fn relative_canonicals_resolve_and_cycles_do_not_loop() {
        let relative = page("https://audit.example/dir/p", &html("../missing"));
        let missing = page_full(
            "https://audit.example/missing",
            404,
            "text/html",
            b"<html>gone</html>",
            &[],
        );
        let a = page("https://audit.example/a", &html("https://audit.example/b"));
        let b = page("https://audit.example/b", &html("https://audit.example/a"));
        let report = run(&[relative, missing, a, b], &[], None, None);
        assert_eq!(
            report.outcome("canonical.broken"),
            Some(RuleState::Findings)
        );
        let finding = report.findings_for("canonical.broken").next().unwrap();
        assert!(finding.fact.contains("https://audit.example/missing"));
        assert!(finding.fact.contains("404"));
        assert_eq!(finding.id.entity_key, "https://audit.example/dir/p");
        assert!(
            report
                .findings_for("canonical.broken")
                .all(|item| item.id.entity_key.ends_with("/dir/p"))
        );
        assert_eq!(
            report.outcome("canonical.multiple"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn inaccessible_canonical_targets_are_incomplete() {
        let page_obs = page(
            "https://audit.example/p",
            &html("https://audit.example/missing"),
        );
        let report = run(&[page_obs], &[], None, None);
        assert_eq!(
            report.outcome("canonical.broken"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn broken_and_multiple_canonicals() {
        let broken = page(
            "https://audit.example/p",
            &html("https://audit.example/missing"),
        );
        let missing = page_full(
            "https://audit.example/missing",
            404,
            "text/html",
            b"<html>gone</html>",
            &[],
        );
        let multiple = page(
            "https://audit.example/m",
            r#"<!DOCTYPE html><html><head>
              <link rel="canonical" href="/one">
              <link rel="canonical" href="/two">
            </head><body>m</body></html>"#,
        );
        let one = page(
            "https://audit.example/one",
            &html("https://audit.example/one"),
        );
        let two = page(
            "https://audit.example/two",
            &html("https://audit.example/two"),
        );
        let report = run(&[broken, missing, multiple, one, two], &[], None, None);
        assert_eq!(
            report.outcome("canonical.broken"),
            Some(RuleState::Findings)
        );
        let fact = report
            .findings_for("canonical.broken")
            .next()
            .unwrap()
            .fact
            .clone();
        assert!(fact.contains("404") || fact.contains("missing"));
        assert_eq!(
            report.outcome("canonical.multiple"),
            Some(RuleState::Findings)
        );
        let multi = report.findings_for("canonical.multiple").next().unwrap();
        assert!(multi.fact.contains("2") || multi.fact.contains("two"));
    }

    #[test]
    fn x_robots_noindex_is_separate_from_meta_and_fetch_permission() {
        let headers = [ExtractHeader {
            name: "X-Robots-Tag",
            value: "noindex, nofollow",
        }];
        let obs = page_full(
            "https://audit.example/p",
            200,
            "text/html",
            br#"<!DOCTYPE html><html><head>
              <meta name="robots" content="index,follow">
              <link rel="canonical" href="https://audit.example/p">
            </head><body>p</body></html>"#,
            &headers,
        );
        let sitemap = SitemapInventory {
            files: vec![sitemap_file(
                "https://audit.example/sitemap.xml",
                SitemapFileState::Fetched,
                "Fetched",
                1,
            )],
            urls: vec![sitemap_url(
                "https://audit.example/p",
                "https://audit.example/sitemap.xml",
                None,
            )],
        };
        let urls = [url_rec(
            "https://audit.example/p",
            UrlState::Fetched,
            "Fetched",
            true,
        )];
        let report = run(&[obs], &urls, Some(&sitemap), None);
        let finding = report
            .findings_for("indexability.x_robots_noindex")
            .next()
            .unwrap();
        assert!(finding.fact.to_ascii_lowercase().contains("x-robots"));
        assert!(finding.fact.contains("index,follow") || finding.fact.contains("meta"));
        assert!(finding.fact.contains("sitemap") || finding.recommendation.contains("index"));
        assert_ne!(
            report.outcome("robots.pages_blocked_from_crawling"),
            Some(RuleState::Findings)
        );
    }

    #[test]
    fn sitemap_entries_explain_redirects_failures_and_index_conflicts() {
        let source = "https://audit.example/sitemap.xml";
        let sitemap = SitemapInventory {
            files: vec![sitemap_file(
                source,
                SitemapFileState::Fetched,
                "Fetched",
                4,
            )],
            urls: vec![
                sitemap_url("https://audit.example/gone", source, None),
                sitemap_url("https://audit.example/redir", source, None),
                sitemap_url("https://audit.example/alias", source, None),
                sitemap_url("https://audit.example/hidden", source, None),
            ],
        };
        let gone = page_full(
            "https://audit.example/gone",
            404,
            "text/html",
            b"<html>gone</html>",
            &[],
        );
        let mut redir = page(
            "https://audit.example/redir",
            &html("https://audit.example/ok"),
        );
        redir.redirect_chain = vec![crate::extract::RedirectHop {
            from: "https://audit.example/redir".into(),
            to: "https://audit.example/ok".into(),
            status: 301,
        }];
        let alias = page(
            "https://audit.example/alias",
            &html("https://audit.example/ok"),
        );
        let headers = [ExtractHeader {
            name: "X-Robots-Tag",
            value: "noindex",
        }];
        let hidden = page_full(
            "https://audit.example/hidden",
            200,
            "text/html",
            html("https://audit.example/hidden").as_bytes(),
            &headers,
        );
        let ok = page(
            "https://audit.example/ok",
            &html("https://audit.example/ok"),
        );
        let urls = [
            url_rec(
                "https://audit.example/gone",
                UrlState::Fetched,
                "Fetched",
                true,
            ),
            url_rec(
                "https://audit.example/redir",
                UrlState::Fetched,
                "Fetched",
                true,
            ),
            url_rec(
                "https://audit.example/alias",
                UrlState::Fetched,
                "Fetched",
                true,
            ),
            url_rec(
                "https://audit.example/hidden",
                UrlState::Fetched,
                "Fetched",
                true,
            ),
            url_rec(
                "https://audit.example/ok",
                UrlState::Fetched,
                "Fetched",
                false,
            ),
        ];
        let report = run(
            &[gone, redir, alias, hidden, ok],
            &urls,
            Some(&sitemap),
            None,
        );
        assert_eq!(
            report.outcome("sitemap.incorrect_pages"),
            Some(RuleState::Findings)
        );
        let dump = report
            .findings_for("sitemap.incorrect_pages")
            .map(|finding| finding.fact.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(dump.contains("404") || dump.contains("gone"));
        assert!(dump.to_ascii_lowercase().contains("redirect"));
        assert!(dump.contains("canonical") || dump.contains("alias"));
        assert!(dump.to_ascii_lowercase().contains("noindex"));
    }

    #[test]
    fn excluded_or_unfetched_sitemap_targets_are_incomplete() {
        let source = "https://audit.example/sitemap.xml";
        let sitemap = SitemapInventory {
            files: vec![sitemap_file(
                source,
                SitemapFileState::Fetched,
                "Fetched",
                1,
            )],
            urls: vec![sitemap_url("https://audit.example/private", source, None)],
        };
        let urls = [url_rec(
            "https://audit.example/private",
            UrlState::Excluded,
            "Out of scope",
            true,
        )];
        let report = run(&[], &urls, Some(&sitemap), None);
        assert_eq!(
            report.outcome("sitemap.incorrect_pages"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn robots_and_sitemap_site_checks() {
        let robots = robots_meta(
            RobotsFetchState::Fetched { status: 200 },
            &[],
            &["Line 4: unknown field 'Foo'"],
        );
        let sitemap = SitemapInventory {
            files: vec![sitemap_file(
                "https://audit.example/sitemap.xml",
                SitemapFileState::Inaccessible,
                "Sitemap inaccessible: HTTP 404 from https://audit.example/sitemap.xml",
                0,
            )],
            urls: Vec::new(),
        };
        let blocked = url_rec(
            "https://audit.example/private",
            UrlState::Blocked,
            "Blocked by robots.txt access policy. This is not a broken page and not a meta noindex finding.",
            false,
        );
        let report = run(&[], &[blocked], Some(&sitemap), Some(&robots));
        assert_eq!(
            report.outcome("robots.format_errors"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("sitemap.not_declared_in_robots"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("sitemap.not_found"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("robots.pages_blocked_from_crawling"),
            Some(RuleState::Findings)
        );
        let blocked_fact = report
            .findings_for("robots.pages_blocked_from_crawling")
            .next()
            .unwrap()
            .fact
            .clone();
        assert!(blocked_fact.contains("robots.txt"));
        assert!(!blocked_fact.to_ascii_lowercase().contains("x-robots"));

        let missing_robots = robots_meta(RobotsFetchState::NotFound { status: 404 }, &[], &[]);
        let missing = run(&[], &[], None, Some(&missing_robots));
        assert_eq!(
            missing.outcome("robots.not_found"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            missing.outcome("robots.format_errors"),
            Some(RuleState::NotApplicable)
        );
        assert_eq!(
            run(&[], &[], None, None).outcome("robots.not_found"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn http_urls_in_https_sitemaps_and_format_size() {
        let https_file = "https://audit.example/sitemap.xml";
        let sitemap = SitemapInventory {
            files: vec![
                sitemap_file(https_file, SitemapFileState::Fetched, "Fetched", 1),
                sitemap_file(
                    "https://audit.example/big.xml",
                    SitemapFileState::Oversized,
                    "Sitemap exceeded size cap",
                    50_001,
                ),
                sitemap_file(
                    "https://audit.example/bad.xml",
                    SitemapFileState::ParseError,
                    "Sitemap parse error: Not a sitemap urlset or index",
                    0,
                ),
            ],
            urls: vec![sitemap_url("http://audit.example/p", https_file, None)],
        };
        let report = run(&[], &[], Some(&sitemap), None);
        assert_eq!(
            report.outcome("sitemap.http_urls_in_https"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("sitemap.http_urls_in_https")
                .next()
                .unwrap()
                .fact
                .contains("http://audit.example/p")
        );
        assert_eq!(
            report.outcome("sitemap.oversized"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("sitemap.format_errors"),
            Some(RuleState::Findings)
        );
    }

    #[test]
    fn stored_observations_evaluate_without_recrawl() {
        let store = Store::open_in_memory().unwrap();
        let profile = Profile::load(include_str!("../../../../profile.example.toml")).unwrap();
        let run_id = store.begin_run(&profile).unwrap();
        store
            .put_observation(
                run_id,
                &page(
                    "https://audit.example/m",
                    r#"<html><head>
                      <link rel="canonical" href="/one">
                      <link rel="canonical" href="/two">
                    </head><body>m</body></html>"#,
                ),
            )
            .unwrap();
        store
            .save_robots(
                run_id,
                &robots_meta(
                    RobotsFetchState::Fetched { status: 200 },
                    &["https://audit.example/sitemap.xml"],
                    &[],
                ),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &indexability_registry(),
        )
        .unwrap();
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &indexability_registry(),
        )
        .unwrap();
        assert_eq!(
            first.outcome("canonical.multiple"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            first.outcome("sitemap.not_declared_in_robots"),
            Some(RuleState::Passed)
        );
        assert_eq!(first.findings, second.findings);
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(
            &[page(
                "https://audit.example/ok",
                &html("https://audit.example/ok"),
            )],
            &[],
            None,
            None,
        );
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
    }
}
