//! Links, anchors, redirects and URL-shape checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::crawl::UrlState;
use crate::extract::{ExtractedObservations, HostOwner, RedirectHop};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

/// Crawlytic heuristic, not a Semrush formula. Override with `max_on_page_links`.
pub const DEFAULT_MAX_ON_PAGE_LINKS: usize = 2500;
/// Crawlytic heuristic, not a Semrush formula. Override with `max_query_params`.
pub const DEFAULT_MAX_QUERY_PARAMS: usize = 4;
/// Crawlytic heuristic, not a Semrush formula. Override with `max_link_chars`.
pub const DEFAULT_MAX_LINK_CHARS: usize = 2048;
/// Inventory baseline stated in TC-448/TC-459. Override with `max_url_chars`.
pub const DEFAULT_MAX_URL_CHARS: usize = 200;
/// More hops than this is a chain. Loops always find. Override with `max_redirects`.
pub const DEFAULT_MAX_REDIRECTS: usize = 1;
/// Crawlytic stop-list, not a Semrush formula. Override with `generic_anchor_list`.
pub const DEFAULT_GENERIC_ANCHORS: &str =
    "click here,click,here,more,read more,learn more,this,link,continue";

pub fn link_audit_registry() -> Registry {
    let mut registry = Registry::new();
    register_link_audit(&mut registry);
    registry
}

pub fn register_link_audit(registry: &mut Registry) {
    registry.register(Http5xx);
    registry.register(Http4xx);
    registry.register(BrokenInternal);
    registry.register(BrokenExternal);
    registry.register(ExternalHttp403);
    registry.register(MalformedLink);
    registry.register(MetaRefresh);
    registry.register(RedirectChainsLoops);
    registry.register(TemporaryRedirect);
    registry.register(PermanentRedirects);
    registry.register(TooManyOnPage);
    registry.register(TooManyParameters);
    registry.register(UrlUnderscores);
    registry.register(UrlLongerThan200);
    registry.register(LinkUrlTooLong);
    registry.register(InternalNofollow);
    registry.register(ExternalNofollow);
    registry.register(NonDescriptiveAnchors);
    registry.register(MissingAnchorText);
    registry.register(ResourcesAsPageLink);
}

fn complete_html<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    evidence
        .observations
        .iter()
        .filter(|observation| observation.page.is_complete())
        .collect()
}

fn pointer(
    obs: &ExtractedObservations,
    field: &str,
    excerpt: impl Into<String>,
) -> EvidencePointer {
    EvidencePointer {
        observation_identity: obs.identity.clone(),
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

fn normalize_identity(value: &str) -> String {
    match Url::parse(value) {
        Ok(mut url) => {
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => value.to_owned(),
    }
}

fn crawl_identities(evidence: &EvidenceBundle<'_>) -> Option<BTreeSet<String>> {
    if evidence.urls.is_empty() {
        return None;
    }
    Some(
        evidence
            .urls
            .iter()
            .filter(|record| record.state == UrlState::Fetched)
            .filter_map(|record| {
                record
                    .identity
                    .as_ref()
                    .map(|identity| normalize_identity(identity.as_str()))
            })
            .collect(),
    )
}

fn in_crawl_set(crawl: &Option<BTreeSet<String>>, identity: &str) -> bool {
    match crawl {
        None => true,
        Some(set) => set.contains(&normalize_identity(identity)),
    }
}

struct TargetEvidence<'a> {
    status: Option<u16>,
    content_type: Option<&'a str>,
    failed_reason: Option<&'a str>,
    observation: Option<&'a ExtractedObservations>,
}

fn target_index<'a>(evidence: &'a EvidenceBundle<'_>) -> BTreeMap<String, TargetEvidence<'a>> {
    let mut map = BTreeMap::new();
    for record in evidence.urls {
        let key = match &record.identity {
            Some(identity) => normalize_identity(identity.as_str()),
            None => normalize_identity(&record.original),
        };
        let failed = (record.state == UrlState::Failed).then_some(record.reason.as_str());
        map.insert(
            key,
            TargetEvidence {
                status: None,
                content_type: None,
                failed_reason: failed,
                observation: None,
            },
        );
    }
    for observation in evidence.observations {
        let key = normalize_identity(&observation.identity);
        let entry = map.entry(key).or_insert(TargetEvidence {
            status: None,
            content_type: None,
            failed_reason: None,
            observation: None,
        });
        entry.status = Some(observation.page.status);
        entry.content_type = Some(observation.page.content_type.as_str());
        entry.observation = Some(observation);
    }
    map
}

fn lookup<'a>(
    index: &'a BTreeMap<String, TargetEvidence<'a>>,
    destination: &str,
) -> Option<&'a TargetEvidence<'a>> {
    index.get(&normalize_identity(destination))
}

fn is_transport_failure(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("connection failed")
        || lower.contains("dns")
        || lower.contains("timed out")
        || lower.contains("timeout")
}

fn exceeded_redirect_limit(reason: &str) -> bool {
    reason
        .to_ascii_lowercase()
        .contains("exceeded the redirect limit")
}

fn is_nav_link(link: &crate::extract::LinkObservation) -> bool {
    matches!(link.host_owner, HostOwner::SameHost | HostOwner::OtherHost)
        && link.destination.is_some()
}

fn has_nofollow(rel: &str) -> bool {
    rel.split([' ', ',', ';'])
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case("nofollow"))
}

fn generic_list(config: &AuditConfig) -> Vec<String> {
    config
        .threshold("generic_anchor_list")
        .unwrap_or(DEFAULT_GENERIC_ANCHORS)
        .split(',')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn normalize_anchor(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn resource_content_type(content_type: &str) -> bool {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    media.starts_with("image/")
        || media.starts_with("audio/")
        || media.starts_with("video/")
        || media.starts_with("font/")
        || matches!(
            media.as_str(),
            "text/css"
                | "text/javascript"
                | "application/javascript"
                | "application/ecmascript"
                | "application/pdf"
                | "application/zip"
                | "application/font-woff"
                | "application/font-woff2"
        )
}

fn query_param_count(identity: &str) -> Option<usize> {
    Url::parse(identity)
        .ok()
        .map(|url| url.query_pairs().count())
}

fn path_has_underscore(identity: &str) -> bool {
    Url::parse(identity)
        .ok()
        .map(|url| url.path().contains('_'))
        .unwrap_or(false)
}

fn http_class(
    evidence: &EvidenceBundle<'_>,
    low: u16,
    high: u16,
    fact: &str,
    recommendation: &str,
) -> CheckerOutput {
    if evidence.observations.is_empty() {
        return incomplete();
    }
    let crawl = crawl_identities(evidence);
    let mut findings = Vec::new();
    for observation in evidence.observations {
        if !in_crawl_set(&crawl, &observation.identity) {
            continue;
        }
        let status = observation.page.status;
        if status >= low && status <= high {
            findings.push(FindingDraft {
                entity_key: observation.identity.clone(),
                fact: format!("{fact} HTTP {status}."),
                recommendation: recommendation.into(),
                evidence: vec![pointer(observation, "http_status", status.to_string())],
            });
        }
    }
    complete(findings)
}

struct LinkHit<'a> {
    page: &'a ExtractedObservations,
    link: &'a crate::extract::LinkObservation,
    seq: usize,
    target: Option<&'a TargetEvidence<'a>>,
}

fn collect_nav<'a>(
    pages: &[&'a ExtractedObservations],
    index: &'a BTreeMap<String, TargetEvidence<'a>>,
    mut include: impl FnMut(&crate::extract::LinkObservation) -> bool,
) -> Vec<LinkHit<'a>> {
    let mut hits = Vec::new();
    for page in pages {
        for (seq, link) in page.links.iter().enumerate() {
            if !include(link) {
                continue;
            }
            let target = link
                .destination
                .as_deref()
                .and_then(|destination| lookup(index, destination));
            hits.push(LinkHit {
                page,
                link,
                seq,
                target,
            });
        }
    }
    hits
}

fn link_entity(hit: &LinkHit<'_>) -> String {
    let dest = hit.link.destination.as_deref().unwrap_or(&hit.link.href);
    format!("{} -> {dest} #{}", hit.page.identity, hit.seq)
}

fn link_fact(hit: &LinkHit<'_>, status_label: &str) -> String {
    format!(
        "Referring page {} original anchor {:?} (href={}) target {}.",
        hit.page.identity, hit.link.anchor, hit.link.href, status_label
    )
}

fn target_status_label(hit: &LinkHit<'_>) -> String {
    if let Some(target) = hit.target {
        if let Some(status) = target.status {
            return format!("HTTP {status}");
        }
        if let Some(reason) = target.failed_reason {
            return format!("fetch failed ({reason})");
        }
    }
    "status unknown".into()
}

fn broken_output(
    evidence: &EvidenceBundle<'_>,
    internal: bool,
    skip_external_403: bool,
) -> CheckerOutput {
    let pages = complete_html(evidence);
    if pages.is_empty() {
        return incomplete();
    }
    let index = target_index(evidence);
    let owner = if internal {
        HostOwner::SameHost
    } else {
        HostOwner::OtherHost
    };
    let hits = collect_nav(&pages, &index, |link| {
        is_nav_link(link) && link.host_owner == owner
    });
    if hits.is_empty() {
        return not_applicable();
    }
    if hits.iter().any(|hit| {
        hit.target
            .map(|target| target.status.is_none() && target.failed_reason.is_none())
            .unwrap_or(true)
    }) {
        return incomplete();
    }
    let mut findings = Vec::new();
    for hit in hits {
        let Some(target) = hit.target else {
            continue;
        };
        let broken = if let Some(status) = target.status {
            let client_or_server = (400..600).contains(&status);
            let external_403 = skip_external_403 && !internal && status == 403;
            client_or_server && !external_403
        } else {
            target.failed_reason.is_some_and(is_transport_failure)
        };
        if broken {
            let status_label = target_status_label(&hit);
            findings.push(FindingDraft {
                entity_key: link_entity(&hit),
                fact: link_fact(&hit, &status_label),
                recommendation: if internal {
                    "Fix or remove the internal link so it reaches a usable target.".into()
                } else {
                    "Fix or remove the external link, or replace it with a working URL.".into()
                },
                evidence: vec![pointer(
                    hit.page,
                    "anchor_href",
                    format!(
                        "anchor={:?} href={} {status_label}",
                        hit.link.anchor, hit.link.href
                    ),
                )],
            });
        }
    }
    complete(findings)
}

fn first_redirect_status(observation: &ExtractedObservations) -> Option<u16> {
    observation
        .redirect_chain
        .first()
        .map(|hop| hop.status)
        .or_else(|| {
            matches!(observation.page.status, 301 | 302 | 307 | 308)
                .then_some(observation.page.status)
        })
}

fn redirect_path(observation: &ExtractedObservations) -> Vec<String> {
    if observation.redirect_chain.is_empty() {
        if matches!(observation.page.status, 301 | 302 | 307 | 308) {
            return vec![observation.identity.clone()];
        }
        return Vec::new();
    }
    let mut path = vec![observation.redirect_chain[0].from.clone()];
    for hop in &observation.redirect_chain {
        path.push(hop.to.clone());
    }
    path
}

fn path_loops(path: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    for url in path {
        if !seen.insert(normalize_identity(url)) {
            return true;
        }
    }
    false
}

fn describe_chain(hops: &[RedirectHop]) -> String {
    if hops.is_empty() {
        return "no hops".into();
    }
    let mut out = hops[0].from.clone();
    for hop in hops {
        out.push_str(&format!(" -{}-> {}", hop.status, hop.to));
    }
    out
}

struct Http5xx;
struct Http4xx;
struct BrokenInternal;
struct BrokenExternal;
struct ExternalHttp403;
struct MalformedLink;
struct MetaRefresh;
struct RedirectChainsLoops;
struct TemporaryRedirect;
struct PermanentRedirects;
struct TooManyOnPage;
struct TooManyParameters;
struct UrlUnderscores;
struct UrlLongerThan200;
struct LinkUrlTooLong;
struct InternalNofollow;
struct ExternalNofollow;
struct NonDescriptiveAnchors;
struct MissingAnchorText;
struct ResourcesAsPageLink;

impl Checker for Http5xx {
    fn rule_id(&self) -> &'static str {
        "crawl.http_5xx"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        http_class(
            evidence,
            500,
            599,
            "The crawled page returned",
            "Investigate the server error and restore a successful response.",
        )
    }
}

impl Checker for Http4xx {
    fn rule_id(&self) -> &'static str {
        "crawl.http_4xx"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        http_class(
            evidence,
            400,
            499,
            "The crawled page returned",
            "Restore the document or replace links that point at this URL.",
        )
    }
}

impl Checker for BrokenInternal {
    fn rule_id(&self) -> &'static str {
        "links.broken_internal"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        broken_output(evidence, true, true)
    }
}

impl Checker for BrokenExternal {
    fn rule_id(&self) -> &'static str {
        "links.broken_external"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        broken_output(evidence, false, true)
    }
}

impl Checker for ExternalHttp403 {
    fn rule_id(&self) -> &'static str {
        "links.external_http_403"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let index = target_index(evidence);
        let hits = collect_nav(&pages, &index, |link| {
            is_nav_link(link) && link.host_owner == HostOwner::OtherHost
        });
        let resource_findings = super::resources::external_resource_403(evidence);
        if hits.is_empty() && resource_findings.is_empty() {
            return not_applicable();
        }
        if hits.iter().any(|hit| {
            hit.target
                .map(|target| target.status.is_none() && target.failed_reason.is_none())
                .unwrap_or(true)
        }) {
            return incomplete();
        }
        let mut findings = Vec::new();
        for hit in hits {
            if hit.target.and_then(|target| target.status) == Some(403) {
                findings.push(FindingDraft {
                    entity_key: link_entity(&hit),
                    fact: format!(
                        "{} Access limitation, not a confirmed broken target.",
                        link_fact(&hit, "HTTP 403")
                    ),
                    recommendation: "Treat HTTP 403 as an access limitation (bot-blocking, auth, or geo). Do not report it as a confirmed broken external target.".into(),
                    evidence: vec![pointer(
                        hit.page,
                        "target_http_status",
                        format!(
                            "anchor={:?} href={} HTTP 403",
                            hit.link.anchor, hit.link.href
                        ),
                    )],
                });
            }
        }
        findings.extend(resource_findings);
        complete(findings)
    }
}

impl Checker for MalformedLink {
    fn rule_id(&self) -> &'static str {
        "url.malformed_link"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for page in pages {
            for (seq, link) in page.links.iter().enumerate() {
                if link.href.trim().is_empty() {
                    continue;
                }
                if link.destination.is_none() && link.host_owner == HostOwner::Opaque {
                    findings.push(FindingDraft {
                        entity_key: format!("{} href={} #{seq}", page.identity, link.href),
                        fact: format!(
                            "Referring page {} original anchor {:?} has malformed href {}.",
                            page.identity, link.anchor, link.href
                        ),
                        recommendation:
                            "Replace the href with a URL that parses under the WHATWG URL Standard."
                                .into(),
                        evidence: vec![pointer(page, "anchor_href", link.href.clone())],
                    });
                }
            }
        }
        complete(findings)
    }
}

impl Checker for MetaRefresh {
    fn rule_id(&self) -> &'static str {
        "links.meta_refresh"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let findings = pages
            .into_iter()
            .filter(|page| !page.page.meta_refresh.is_empty())
            .map(|page| FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!(
                    "The page uses meta http-equiv=refresh ({:?}).",
                    page.page.meta_refresh
                ),
                recommendation: "Replace meta refresh with an HTTP redirect or in-page navigation."
                    .into(),
                evidence: vec![pointer(
                    page,
                    "meta_refresh",
                    page.page.meta_refresh.join(" | "),
                )],
            })
            .collect();
        complete(findings)
    }
}

impl Checker for RedirectChainsLoops {
    fn rule_id(&self) -> &'static str {
        "links.redirect_chains_loops"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let max = usize_threshold(config, "max_redirects", DEFAULT_MAX_REDIRECTS);
        if evidence.observations.is_empty() && evidence.urls.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for observation in evidence.observations {
            let hops = &observation.redirect_chain;
            let path = redirect_path(observation);
            let looping = path_loops(&path);
            let chained = hops.len() > max;
            if looping || chained {
                let kind = if looping { "loop" } else { "chain" };
                findings.push(FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: format!(
                        "Redirect {kind} on {}: {}.",
                        observation.identity,
                        describe_chain(hops)
                    ),
                    recommendation: format!(
                        "Collapse the redirect {kind} to a single hop. Configured max_redirects={max} (Crawlytic heuristic, not a Semrush hop count). Loops always find."
                    ),
                    evidence: vec![pointer(observation, "redirect_chain", describe_chain(hops))],
                });
            }
        }
        for record in evidence.urls {
            if record.state == UrlState::Failed && exceeded_redirect_limit(&record.reason) {
                let key = record
                    .identity
                    .as_ref()
                    .map(|identity| identity.as_str().to_owned())
                    .unwrap_or_else(|| record.original.clone());
                findings.push(FindingDraft {
                    entity_key: key.clone(),
                    fact: format!("Redirect chain or loop stopped: {}.", record.reason),
                    recommendation: format!(
                        "Collapse the redirect chain. Configured max_redirects={max} (Crawlytic heuristic, not a Semrush hop count). Loops always find."
                    ),
                    evidence: vec![EvidencePointer {
                        observation_identity: key,
                        field: "redirect_chain".into(),
                        excerpt: record.reason.clone(),
                    }],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for TemporaryRedirect {
    fn rule_id(&self) -> &'static str {
        "links.temporary_redirect"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let findings = evidence
            .observations
            .iter()
            .filter(|observation| matches!(first_redirect_status(observation), Some(302 | 307)))
            .map(|observation| {
                let status = first_redirect_status(observation).unwrap();
                FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: format!(
                        "{} returns HTTP {status} (temporary redirect).",
                        observation.identity
                    ),
                    recommendation:
                        "Use a permanent redirect (301/308) if the move is not temporary.".into(),
                    evidence: vec![pointer(observation, "http_status", status.to_string())],
                }
            })
            .collect();
        complete(findings)
    }
}

impl Checker for PermanentRedirects {
    fn rule_id(&self) -> &'static str {
        "links.permanent_redirects"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let findings = evidence
            .observations
            .iter()
            .filter(|observation| matches!(first_redirect_status(observation), Some(301 | 308)))
            .map(|observation| {
                let status = first_redirect_status(observation).unwrap();
                FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: format!(
                        "{} returns HTTP {status} (permanent redirect).",
                        observation.identity
                    ),
                    recommendation:
                        "Point links at the final URL so crawlers do not need the permanent hop."
                            .into(),
                    evidence: vec![pointer(observation, "http_status", status.to_string())],
                }
            })
            .collect();
        complete(findings)
    }
}

impl Checker for TooManyOnPage {
    fn rule_id(&self) -> &'static str {
        "links.too_many_on_page"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let max = usize_threshold(config, "max_on_page_links", DEFAULT_MAX_ON_PAGE_LINKS);
        let findings = pages
            .into_iter()
            .filter(|page| page.links.len() > max)
            .map(|page| FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!("The page has {} on-page links.", page.links.len()),
                recommendation: format!(
                    "Reduce on-page links to at most {max} (configured max_on_page_links={max}; Crawlytic heuristic, not a Semrush cap)."
                ),
                evidence: vec![pointer(page, "anchor_href", page.links.len().to_string())],
            })
            .collect();
        complete(findings)
    }
}

impl Checker for TooManyParameters {
    fn rule_id(&self) -> &'static str {
        "url.too_many_parameters"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let max = usize_threshold(config, "max_query_params", DEFAULT_MAX_QUERY_PARAMS);
        let findings = evidence
            .observations
            .iter()
            .filter_map(|observation| {
                let count = query_param_count(&observation.identity)?;
                (count > max).then(|| FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: format!(
                        "{} has {count} query parameters.",
                        observation.identity
                    ),
                    recommendation: format!(
                        "Keep query parameters to at most {max} (configured max_query_params={max}; Crawlytic heuristic, not a Semrush cap)."
                    ),
                    evidence: vec![pointer(observation, "url", observation.identity.clone())],
                })
            })
            .collect();
        complete(findings)
    }
}

impl Checker for UrlUnderscores {
    fn rule_id(&self) -> &'static str {
        "url.underscores"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let findings = evidence
            .observations
            .iter()
            .filter(|observation| path_has_underscore(&observation.identity))
            .map(|observation| FindingDraft {
                entity_key: observation.identity.clone(),
                fact: format!(
                    "{} contains an underscore in the path.",
                    observation.identity
                ),
                recommendation:
                    "Prefer hyphens over underscores in paths. Heuristic only; no universal SEO benefit is asserted."
                        .into(),
                evidence: vec![pointer(observation, "url", observation.identity.clone())],
            })
            .collect();
        complete(findings)
    }
}

impl Checker for UrlLongerThan200 {
    fn rule_id(&self) -> &'static str {
        "url.longer_than_200"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let max = usize_threshold(config, "max_url_chars", DEFAULT_MAX_URL_CHARS);
        let findings = evidence
            .observations
            .iter()
            .filter(|observation| observation.identity.chars().count() > max)
            .map(|observation| {
                let chars = observation.identity.chars().count();
                FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: format!("The page URL is {chars} characters."),
                    recommendation: format!(
                        "Shorten the page URL to at most {max} characters (configured max_url_chars={max}; inventory baseline, not a Semrush formula)."
                    ),
                    evidence: vec![pointer(observation, "url", observation.identity.clone())],
                }
            })
            .collect();
        complete(findings)
    }
}

impl Checker for LinkUrlTooLong {
    fn rule_id(&self) -> &'static str {
        "links.url_too_long"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let max = usize_threshold(config, "max_link_chars", DEFAULT_MAX_LINK_CHARS);
        let mut findings = Vec::new();
        for page in pages {
            for (seq, link) in page.links.iter().enumerate() {
                let candidate = link.destination.as_deref().unwrap_or(link.href.as_str());
                let chars = candidate.chars().count();
                if chars > max {
                    findings.push(FindingDraft {
                        entity_key: format!("{} -> {candidate} #{seq}", page.identity),
                        fact: format!(
                            "Referring page {} original anchor {:?} target URL is {chars} characters.",
                            page.identity, link.anchor
                        ),
                        recommendation: format!(
                            "Shorten the link URL to at most {max} characters (configured max_link_chars={max}; Crawlytic heuristic, not a Semrush cap)."
                        ),
                        evidence: vec![pointer(page, "anchor_href", candidate.to_owned())],
                    });
                }
            }
        }
        complete(findings)
    }
}

fn nofollow_output(evidence: &EvidenceBundle<'_>, internal: bool) -> CheckerOutput {
    let pages = complete_html(evidence);
    if pages.is_empty() {
        return incomplete();
    }
    let owner = if internal {
        HostOwner::SameHost
    } else {
        HostOwner::OtherHost
    };
    let index = target_index(evidence);
    let hits = collect_nav(&pages, &index, |link| {
        is_nav_link(link) && link.host_owner == owner
    });
    if hits.is_empty() {
        return not_applicable();
    }
    let findings = hits
        .into_iter()
        .filter(|hit| has_nofollow(&hit.link.rel))
        .map(|hit| FindingDraft {
            entity_key: link_entity(&hit),
            fact: format!(
                "Referring page {} original anchor {:?} (href={}) has rel=nofollow.",
                hit.page.identity, hit.link.anchor, hit.link.href
            ),
            recommendation: if internal {
                "Remove nofollow from internal links unless the target must stay out of the graph."
                    .into()
            } else {
                "Recorded only. No universal SEO benefit is asserted for adding or removing external nofollow.".into()
            },
            evidence: vec![pointer(
                hit.page,
                "anchor_rel",
                format!("rel={} href={}", hit.link.rel, hit.link.href),
            )],
        })
        .collect();
    complete(findings)
}

impl Checker for InternalNofollow {
    fn rule_id(&self) -> &'static str {
        "links.internal_outgoing_nofollow"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        nofollow_output(evidence, true)
    }
}

impl Checker for ExternalNofollow {
    fn rule_id(&self) -> &'static str {
        "links.external_outgoing_nofollow"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        nofollow_output(evidence, false)
    }
}

impl Checker for NonDescriptiveAnchors {
    fn rule_id(&self) -> &'static str {
        "links.non_descriptive_anchors"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let stop = generic_list(config);
        let mut findings = Vec::new();
        for page in pages {
            for (seq, link) in page.links.iter().enumerate() {
                if !is_nav_link(link) {
                    continue;
                }
                let normalized = normalize_anchor(&link.anchor);
                if normalized.is_empty() {
                    continue;
                }
                if stop.iter().any(|item| item == &normalized) {
                    findings.push(FindingDraft {
                        entity_key: format!(
                            "{} -> {} #{seq}",
                            page.identity,
                            link.destination.as_deref().unwrap_or(&link.href)
                        ),
                        fact: format!(
                            "Referring page {} original anchor {:?} (href={}) is non-descriptive.",
                            page.identity, link.anchor, link.href
                        ),
                        recommendation: "Use anchor text that names the target. Stop-list is configured generic_anchor_list (Crawlytic heuristic, not a Semrush list).".into(),
                        evidence: vec![pointer(page, "anchor_text", link.anchor.clone())],
                    });
                }
            }
        }
        complete(findings)
    }
}

impl Checker for MissingAnchorText {
    fn rule_id(&self) -> &'static str {
        "links.missing_anchor_text"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        for page in pages {
            for (seq, link) in page.links.iter().enumerate() {
                if !is_nav_link(link) {
                    continue;
                }
                if !link.anchor.trim().is_empty() {
                    continue;
                }
                findings.push(FindingDraft {
                    entity_key: format!(
                        "{} -> {} #{seq}",
                        page.identity,
                        link.destination.as_deref().unwrap_or(&link.href)
                    ),
                    fact: format!(
                        "Referring page {} has an empty accessible name for href {}.",
                        page.identity, link.href
                    ),
                    recommendation:
                        "Give the link visible text or an img alt that names the target.".into(),
                    evidence: vec![pointer(page, "anchor_text", String::new())],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for ResourcesAsPageLink {
    fn rule_id(&self) -> &'static str {
        "links.resources_as_page_link"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let index = target_index(evidence);
        let hits = collect_nav(&pages, &index, is_nav_link);
        if hits.is_empty() {
            return not_applicable();
        }
        if hits
            .iter()
            .any(|hit| hit.target.and_then(|target| target.content_type).is_none())
        {
            return incomplete();
        }
        let mut findings = Vec::new();
        for hit in hits {
            let Some(content_type) = hit.target.and_then(|target| target.content_type) else {
                continue;
            };
            if resource_content_type(content_type) {
                findings.push(FindingDraft {
                    entity_key: link_entity(&hit),
                    fact: format!(
                        "Referring page {} original anchor {:?} (href={}) points at a resource (content-type {content_type}).",
                        hit.page.identity, hit.link.anchor, hit.link.href
                    ),
                    recommendation: "Do not use <a href> for files that are not HTML pages. Classification uses HTTP content-type, not the file extension. This is a Crawlytic heuristic; Semrush resources-as-page-links parity is not claimed.".into(),
                    evidence: vec![pointer(
                        hit.page,
                        "anchor_href",
                        format!("href={} content-type={content_type}", hit.link.href),
                    )],
                });
            }
        }
        complete(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::{CapturedCurrent, InventoryUnit, RuleState, rule_by_id};
    use crate::crawl::UrlRecord;
    use crate::extract::{ExtractInput, extract};
    use crate::profile::Profile;
    use crate::scope::FetchIdentity;
    use crate::store::Store;
    use url::Url;

    fn page(url: &str, body: &str) -> ExtractedObservations {
        page_status(url, 200, "text/html", body.as_bytes(), false)
    }

    fn page_status(
        url: &str,
        status: u16,
        content_type: &str,
        body: &[u8],
        truncated: bool,
    ) -> ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status,
            content_type,
            headers: &[],
            body,
            truncated,
            duration_ms: Some(1),
        })
    }

    fn with_redirects(
        mut observation: ExtractedObservations,
        hops: Vec<RedirectHop>,
    ) -> ExtractedObservations {
        observation.redirect_chain = hops;
        observation
    }

    fn config() -> AuditConfig {
        let mut config = AuditConfig::default();
        config
            .thresholds
            .insert("max_on_page_links".into(), "3".into());
        config
            .thresholds
            .insert("max_query_params".into(), "2".into());
        config
            .thresholds
            .insert("max_link_chars".into(), "40".into());
        config
            .thresholds
            .insert("max_url_chars".into(), "200".into());
        config.thresholds.insert("max_redirects".into(), "1".into());
        config
            .thresholds
            .insert("generic_anchor_list".into(), "click here,more".into());
        config
    }

    fn run_with(obs: &[ExtractedObservations], urls: &[UrlRecord]) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls,
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: &[],
            },
            &config(),
            &link_audit_registry(),
            &[],
        )
    }

    fn run(obs: &[ExtractedObservations]) -> AuditReport {
        run_with(obs, &[])
    }

    fn ok_page(url: &str) -> ExtractedObservations {
        page(
            url,
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Ok</title></head>
            <body><a href="https://audit.example/ok">Shop cables</a></body></html>"#,
        )
    }

    fn hop(from: &str, to: &str, status: u16) -> RedirectHop {
        RedirectHop {
            from: from.into(),
            to: to.into(),
            status,
        }
    }

    #[test]
    fn http_4xx_and_5xx_use_recorded_status() {
        let not_found = page_status(
            "https://audit.example/missing",
            404,
            "text/html",
            b"<html>missing</html>",
            false,
        );
        let fail = page_status(
            "https://audit.example/fail",
            500,
            "text/html",
            b"<html>fail</html>",
            false,
        );
        let report = run(&[not_found, fail, ok_page("https://audit.example/ok")]);
        assert_eq!(report.outcome("crawl.http_4xx"), Some(RuleState::Findings));
        assert_eq!(report.outcome("crawl.http_5xx"), Some(RuleState::Findings));
        assert!(
            report
                .findings_for("crawl.http_4xx")
                .next()
                .unwrap()
                .fact
                .contains("404")
        );
        assert_eq!(
            run(&[]).outcome("crawl.http_4xx"),
            Some(RuleState::Incomplete)
        );
        assert_eq!(
            run(&[ok_page("https://audit.example/ok")]).outcome("crawl.http_4xx"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn broken_links_include_referrer_anchor_and_status_and_403_is_distinct() {
        let from = page(
            "https://audit.example/from",
            r#"<html><body>
              <a href="https://audit.example/missing">Internal cables</a>
              <a href="https://ext.audit.example/missing">External cables</a>
              <a href="https://ext.audit.example/private">Gated</a>
              <a href="https://audit.example/ok">Ok</a>
            </body></html>"#,
        );
        let missing = page_status(
            "https://audit.example/missing",
            404,
            "text/html",
            b"<html>404</html>",
            false,
        );
        let ext_missing = page_status(
            "https://ext.audit.example/missing",
            404,
            "text/html",
            b"<html>404</html>",
            false,
        );
        let gated = page_status(
            "https://ext.audit.example/private",
            403,
            "text/html",
            b"<html>no</html>",
            false,
        );
        let ok = ok_page("https://audit.example/ok");
        let report = run(&[from, missing, ext_missing, gated, ok]);

        let internal = report.findings_for("links.broken_internal").next().unwrap();
        assert!(internal.fact.contains("https://audit.example/from"));
        assert!(internal.fact.contains("Internal cables"));
        assert!(internal.fact.contains("HTTP 404"));
        assert_eq!(
            report.outcome("links.broken_internal"),
            Some(RuleState::Findings)
        );

        let external = report.findings_for("links.broken_external").next().unwrap();
        assert!(external.fact.contains("https://audit.example/from"));
        assert!(external.fact.contains("External cables"));
        assert!(external.fact.contains("HTTP 404"));
        assert!(
            !report
                .findings_for("links.broken_external")
                .any(|finding| finding.fact.contains("HTTP 403"))
        );

        let limited = report
            .findings_for("links.external_http_403")
            .next()
            .unwrap();
        assert!(limited.fact.contains("HTTP 403"));
        assert!(limited.fact.contains("Access limitation"));
        assert!(limited.fact.contains("Gated"));
        assert_eq!(
            report.outcome("links.external_http_403"),
            Some(RuleState::Findings)
        );
    }

    #[test]
    fn unfetched_targets_are_incomplete_not_passed() {
        let from = page(
            "https://audit.example/from",
            r#"<html><body><a href="https://audit.example/missing">Go</a></body></html>"#,
        );
        let report = run(&[from]);
        assert_eq!(
            report.outcome("links.broken_internal"),
            Some(RuleState::Incomplete)
        );
        assert!(
            report
                .findings_for("links.broken_internal")
                .next()
                .is_none()
        );
        assert_eq!(
            report.outcome("links.broken_external"),
            Some(RuleState::NotApplicable)
        );
    }

    #[test]
    fn malformed_meta_refresh_and_redirects() {
        let malformed = page(
            "https://audit.example/from",
            r#"<html><body><a href="http://[broken">Broken</a><a href="https://audit.example/ok">Ok</a></body></html>"#,
        );
        let refresh = page(
            "https://audit.example/old",
            r#"<html><head><meta http-equiv="refresh" content="0;url=/next"></head><body></body></html>"#,
        );
        let looped = with_redirects(
            page("https://audit.example/a", "<html><body>loop</body></html>"),
            vec![
                hop("https://audit.example/a", "https://audit.example/b", 301),
                hop("https://audit.example/b", "https://audit.example/a", 301),
            ],
        );
        let temporary = with_redirects(
            page("https://audit.example/tmp", "<html><body>tmp</body></html>"),
            vec![hop(
                "https://audit.example/tmp",
                "https://audit.example/ok",
                302,
            )],
        );
        let permanent = with_redirects(
            page(
                "https://audit.example/moved",
                "<html><body>moved</body></html>",
            ),
            vec![hop(
                "https://audit.example/moved",
                "https://audit.example/ok",
                301,
            )],
        );
        let ok = ok_page("https://audit.example/ok");
        let report = run(&[malformed, refresh, looped, temporary, permanent, ok]);
        assert_eq!(
            report.outcome("url.malformed_link"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("url.malformed_link")
                .next()
                .unwrap()
                .fact
                .contains("http://[broken")
        );
        assert_eq!(
            report.outcome("links.meta_refresh"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("links.redirect_chains_loops"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("links.redirect_chains_loops")
                .next()
                .unwrap()
                .recommendation
                .contains("max_redirects=1")
        );
        assert_eq!(
            report.outcome("links.temporary_redirect"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("links.permanent_redirects"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            run(&[ok_page("https://audit.example/ok")]).outcome("links.meta_refresh"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            run(&[]).outcome("links.temporary_redirect"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn failed_redirect_limit_from_url_record() {
        let urls = [UrlRecord {
            original: "https://audit.example/a".into(),
            identity: Some(FetchIdentity::from_url(
                &Url::parse("https://audit.example/a").unwrap(),
            )),
            state: UrlState::Failed,
            reason: "HTTP 302 from https://audit.example/a exceeded the redirect limit".into(),
            click_depth: Some(0),
            via_website: true,
            via_sitemap: false,
        }];
        let report = run_with(&[], &urls);
        assert_eq!(
            report.outcome("links.redirect_chains_loops"),
            Some(RuleState::Findings)
        );
    }

    #[test]
    fn url_shape_and_on_page_link_heuristics() {
        let hub = page(
            "https://audit.example/hub",
            r#"<html><body>
              <a href="/a">A</a><a href="/b">B</a><a href="/c">C</a><a href="/d">D</a>
            </body></html>"#,
        );
        let params = page(
            "https://audit.example/p?a=1&b=2&c=3",
            "<html><body>ok</body></html>",
        );
        let underscored = page(
            "https://audit.example/foo_bar",
            "<html><body>ok</body></html>",
        );
        let long_identity = format!("https://audit.example/{}", "a".repeat(180));
        let long_page = page(&long_identity, "<html><body>ok</body></html>");
        let long_href = format!("https://audit.example/{}", "b".repeat(40));
        let long_link = page(
            "https://audit.example/from",
            &format!(r#"<html><body><a href="{long_href}">Long</a></body></html>"#),
        );
        let report = run(&[hub, params, underscored, long_page, long_link]);
        assert_eq!(
            report.outcome("links.too_many_on_page"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("links.too_many_on_page")
                .next()
                .unwrap()
                .recommendation
                .contains("max_on_page_links=3")
        );
        assert_eq!(
            report.outcome("url.too_many_parameters"),
            Some(RuleState::Findings)
        );
        assert_eq!(report.outcome("url.underscores"), Some(RuleState::Findings));
        let long = report.findings_for("url.longer_than_200").next().unwrap();
        assert!(long.recommendation.contains("max_url_chars=200"));
        assert!(long.fact.contains("characters"));
        assert_eq!(
            report.outcome("links.url_too_long"),
            Some(RuleState::Findings)
        );
        match rule_by_id("url.longer_than_200").unwrap().captured_current {
            CapturedCurrent::Count {
                value: 3,
                unit: InventoryUnit::Page,
            } => {}
            other => panic!("{other:?}"),
        }
        assert_ne!(report.affected_identities("url.longer_than_200").len(), 3);
    }

    #[test]
    fn anchors_nofollow_and_resources_use_content_type() {
        let page_html = page(
            "https://audit.example/p",
            r#"<html><body>
              <a href="https://audit.example/to">click here</a>
              <a href="https://audit.example/empty"></a>
              <a href="https://audit.example/img"><img src="/x.png"></a>
              <a href="https://audit.example/named"><img src="/y.png" alt="Buy cables"></a>
              <a href="https://audit.example/app.js">Download script</a>
              <a href="https://audit.example/ok" rel="nofollow">Internal</a>
              <a href="https://ext.audit.example/" rel="nofollow">External</a>
            </body></html>"#,
        );
        let js = page_status(
            "https://audit.example/app.js",
            200,
            "application/javascript",
            b"console.log(1)",
            false,
        );
        let to = page("https://audit.example/to", "<html><body>to</body></html>");
        let empty = page(
            "https://audit.example/empty",
            "<html><body>empty</body></html>",
        );
        let img = page("https://audit.example/img", "<html><body>img</body></html>");
        let named = page(
            "https://audit.example/named",
            "<html><body>named</body></html>",
        );
        let ext = page_status(
            "https://ext.audit.example/",
            200,
            "text/html",
            b"<html>ext</html>",
            false,
        );
        let ok = ok_page("https://audit.example/ok");
        let report = run(&[page_html, js, to, empty, img, named, ext, ok]);

        let generic = report
            .findings_for("links.non_descriptive_anchors")
            .next()
            .unwrap();
        assert!(generic.fact.contains("click here"));
        assert!(generic.fact.contains("https://audit.example/p"));
        assert_eq!(
            report.outcome("links.missing_anchor_text"),
            Some(RuleState::Findings)
        );
        let missing: Vec<_> = report
            .findings_for("links.missing_anchor_text")
            .map(|finding| finding.fact.as_str())
            .collect();
        assert!(missing.iter().any(|fact| fact.contains("/empty")));
        assert!(missing.iter().any(|fact| fact.contains("/img")));
        assert!(!missing.iter().any(|fact| fact.contains("/named")));

        assert_eq!(
            report.outcome("links.internal_outgoing_nofollow"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("links.external_outgoing_nofollow"),
            Some(RuleState::Findings)
        );

        let resource = report
            .findings_for("links.resources_as_page_link")
            .next()
            .unwrap();
        assert!(resource.fact.contains("application/javascript"));
        assert!(resource.recommendation.contains("not claimed"));
        assert!(
            rule_by_id("links.resources_as_page_link")
                .unwrap()
                .ambiguous
        );
        match rule_by_id("links.resources_as_page_link")
            .unwrap()
            .captured_current
        {
            CapturedCurrent::Count {
                value: 9,
                unit: InventoryUnit::Resource,
            } => {}
            other => panic!("{other:?}"),
        }
        assert_ne!(
            report
                .affected_identities("links.resources_as_page_link")
                .len(),
            9
        );

        let unfetched_js = page(
            "https://audit.example/q",
            r#"<html><body><a href="https://audit.example/missing.js">file</a></body></html>"#,
        );
        assert_eq!(
            run(&[unfetched_js]).outcome("links.resources_as_page_link"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn truncated_html_is_incomplete_for_anchor_rules() {
        let truncated = page_status(
            "https://audit.example/partial",
            200,
            "text/html",
            b"<html><a href='/x'>",
            true,
        );
        let report = run(&[truncated]);
        assert_eq!(
            report.outcome("links.broken_internal"),
            Some(RuleState::Incomplete)
        );
        assert_eq!(
            report.outcome("links.meta_refresh"),
            Some(RuleState::Incomplete)
        );
        assert_ne!(
            report.outcome("links.meta_refresh"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn healthy_page_passes_applicable_link_rules() {
        let report = run(&[ok_page("https://audit.example/ok")]);
        for id in [
            "crawl.http_4xx",
            "crawl.http_5xx",
            "links.broken_internal",
            "url.malformed_link",
            "links.meta_refresh",
            "links.redirect_chains_loops",
            "links.temporary_redirect",
            "links.permanent_redirects",
            "links.too_many_on_page",
            "url.too_many_parameters",
            "url.underscores",
            "url.longer_than_200",
            "links.url_too_long",
            "links.internal_outgoing_nofollow",
            "links.non_descriptive_anchors",
            "links.missing_anchor_text",
            "links.resources_as_page_link",
        ] {
            assert_eq!(report.outcome(id), Some(RuleState::Passed), "{id}");
        }
        assert_eq!(
            report.outcome("links.broken_external"),
            Some(RuleState::NotApplicable)
        );
        assert_eq!(
            report.outcome("links.external_http_403"),
            Some(RuleState::NotApplicable)
        );
        assert_eq!(
            report.outcome("links.external_outgoing_nofollow"),
            Some(RuleState::NotApplicable)
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
                    "https://audit.example/from",
                    r#"<html><body><a href="https://audit.example/missing">Go</a></body></html>"#,
                ),
            )
            .unwrap();
        store
            .put_observation(
                run_id,
                &page_status(
                    "https://audit.example/missing",
                    404,
                    "text/html",
                    b"<html>404</html>",
                    false,
                ),
            )
            .unwrap();
        let first = evaluate_stored(&store, run_id, &config(), &link_audit_registry()).unwrap();
        let second = evaluate_stored(&store, run_id, &config(), &link_audit_registry()).unwrap();
        assert_eq!(first.findings_for("links.broken_internal").count(), 1);
        assert_eq!(first.findings, second.findings);
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(&[ok_page("https://audit.example/ok")]);
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
    }
}
