//! Hreflang, lang and locale-relationship checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::crawl::UrlState;
use crate::extract::{ExtractedObservations, ResourceFetch};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

/// Distinctive function-word hits required before the content-language
/// heuristic may fire. Override with `min_language_hits`. Crawlytic value, not
/// a Semrush formula.
pub const DEFAULT_MIN_LANGUAGE_HITS: usize = 8;
/// Winner share of scored hits (0.0–1.0). Override with `min_language_confidence`.
pub const DEFAULT_MIN_LANGUAGE_CONFIDENCE: f64 = 0.6;

pub fn hreflang_registry() -> Registry {
    let mut registry = Registry::new();
    register_hreflang(&mut registry);
    registry
}

pub fn register_hreflang(registry: &mut Registry) {
    registry.register(HreflangValuesInvalid);
    registry.register(HreflangSourceConflicts);
    registry.register(HreflangIncorrectLinks);
    registry.register(HreflangMissingHreflangAndLang);
    registry.register(HreflangLanguageMismatch);
}

struct HreflangValuesInvalid;
struct HreflangSourceConflicts;
struct HreflangIncorrectLinks;
struct HreflangMissingHreflangAndLang;
struct HreflangLanguageMismatch;

impl Checker for HreflangValuesInvalid {
    fn rule_id(&self) -> &'static str {
        "hreflang.values_invalid"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(pages) = declaring_pages(evidence) else {
            return incomplete();
        };
        if pages.is_empty() {
            return not_applicable();
        }
        let mut findings = Vec::new();
        for page in pages {
            for item in &page.page.hreflangs {
                if is_valid_hreflang(&item.lang) {
                    continue;
                }
                findings.push(FindingDraft {
                    entity_key: format!("{} hreflang={}", page.identity, item.lang),
                    fact: format!(
                        "Page {} declares invalid hreflang value '{}'.",
                        page.identity, item.lang
                    ),
                    recommendation:
                        "Use a BCP 47 language tag (language[-script][-region]) or x-default."
                            .into(),
                    evidence: vec![pointer(
                        page.identity.clone(),
                        "hreflang",
                        format!("{} -> {}", item.lang, item.href),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for HreflangSourceConflicts {
    fn rule_id(&self) -> &'static str {
        "hreflang.source_conflicts"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(pages) = declaring_pages(evidence) else {
            return incomplete();
        };
        if pages.is_empty() {
            return not_applicable();
        }
        let mut findings = Vec::new();
        for page in pages {
            let mut by_lang: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
            for item in &page.page.hreflangs {
                let key = normalize_lang_key(&item.lang);
                let resolved =
                    resolve_href(&page.identity, &item.href).unwrap_or_else(|| item.href.clone());
                let entry = by_lang
                    .entry(key)
                    .or_insert_with(|| (item.lang.clone(), Vec::new()));
                if !entry.1.contains(&resolved) {
                    entry.1.push(resolved);
                }
            }
            for (_key, (lang, urls)) in by_lang {
                if urls.len() < 2 {
                    continue;
                }
                findings.push(FindingDraft {
                    entity_key: format!("{} hreflang={lang}", page.identity),
                    fact: format!(
                        "Page {} maps hreflang {lang} to {} URLs: {}.",
                        page.identity,
                        urls.len(),
                        urls.join(" | ")
                    ),
                    recommendation: "Keep a single target URL per hreflang value on a page.".into(),
                    evidence: vec![pointer(
                        page.identity.clone(),
                        "hreflang",
                        format!("{lang} -> {}", urls.join(" | ")),
                    )],
                });
            }
        }
        complete(findings)
    }
}

impl Checker for HreflangIncorrectLinks {
    fn rule_id(&self) -> &'static str {
        "hreflang.incorrect_links"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(pages) = declaring_pages(evidence) else {
            return incomplete();
        };
        if pages.is_empty() {
            return not_applicable();
        }
        let index = target_index(evidence);
        let crawl = crawl_identities(evidence);
        let sources: Vec<_> = pages
            .into_iter()
            .filter(|page| in_crawl_set(&crawl, &page.identity))
            .collect();
        if sources.is_empty() {
            return not_applicable();
        }
        let mut findings = Vec::new();
        let mut missing = false;
        for page in sources {
            let preferred = preferred_url(page);
            let mut saw_self = false;
            let mut seen_targets = BTreeSet::new();
            for item in &page.page.hreflangs {
                let Some(target_url) = resolve_href(&page.identity, &item.href) else {
                    findings.push(relationship(
                        page,
                        &item.lang,
                        &item.href,
                        format!(
                            "Page {} hreflang {} href {} is unresolvable.",
                            page.identity, item.lang, item.href
                        ),
                        "Publish an absolute, fetchable hreflang URL.",
                        pointer(
                            page.identity.clone(),
                            "hreflang",
                            format!("{} -> {}", item.lang, item.href),
                        ),
                        pointer(item.href.clone(), "hreflang", "unresolvable href"),
                    ));
                    continue;
                };
                if is_self(&target_url, page, &preferred) {
                    saw_self = true;
                }
                if !seen_targets.insert(target_url.clone()) {
                    continue;
                }
                match lookup(&index, &target_url) {
                    None => missing = true,
                    Some(target) => {
                        if matches!(
                            target.state,
                            Some(UrlState::Excluded | UrlState::Pending | UrlState::InFlight)
                        ) && target.observation.is_none()
                            && target.fetch.is_none()
                        {
                            missing = true;
                            continue;
                        }
                        if let Some(status) =
                            target.status.filter(|status| (400..600).contains(status))
                        {
                            findings.push(relationship(
                                page,
                                &item.lang,
                                &target_url,
                                format!(
                                    "Page {} hreflang {} target {} returns HTTP {status}.",
                                    page.identity, item.lang, target_url
                                ),
                                "Point hreflang at URLs that return HTTP 200.",
                                pointer(
                                    page.identity.clone(),
                                    "hreflang",
                                    format!("{} -> {target_url} HTTP {status}", item.lang),
                                ),
                                pointer(
                                    target_url.clone(),
                                    "target_http_status",
                                    status.to_string(),
                                ),
                            ));
                            continue;
                        }
                        if let Some(reason) = target.failed_reason {
                            findings.push(relationship(
                                page,
                                &item.lang,
                                &target_url,
                                format!(
                                    "Page {} hreflang {} target {} is inaccessible ({reason}).",
                                    page.identity, item.lang, target_url
                                ),
                                "Point hreflang at a reachable URL.",
                                pointer(
                                    page.identity.clone(),
                                    "hreflang",
                                    format!("{} -> {target_url}", item.lang),
                                ),
                                pointer(target_url.clone(), "target_http_status", reason),
                            ));
                            continue;
                        }
                        if target.robots_blocked {
                            findings.push(relationship(
                                page,
                                &item.lang,
                                &target_url,
                                format!(
                                    "Page {} hreflang {} target {} is blocked by robots.txt.",
                                    page.identity, item.lang, target_url
                                ),
                                "Allow the locale URL in robots.txt or drop the annotation.",
                                pointer(
                                    page.identity.clone(),
                                    "hreflang",
                                    format!("{} -> {target_url}", item.lang),
                                ),
                                pointer(target_url.clone(), "target_http_status", "robots blocked"),
                            ));
                            continue;
                        }
                        let Some(obs) = target.observation else {
                            if target.status.is_some() {
                                continue;
                            }
                            missing = true;
                            continue;
                        };
                        if page_noindex(obs) {
                            findings.push(relationship(
                                page,
                                &item.lang,
                                &target_url,
                                format!(
                                    "Page {} hreflang {} target {} is noindex.",
                                    page.identity, item.lang, target_url
                                ),
                                "Hreflang must point at indexable canonical URLs.",
                                pointer(
                                    page.identity.clone(),
                                    "hreflang",
                                    format!("{} -> {target_url}", item.lang),
                                ),
                                pointer(obs.identity.clone(), "robots", "noindex"),
                            ));
                        }
                        let target_preferred = preferred_url(obs);
                        if normalize_identity(&target_url) != normalize_identity(&target_preferred)
                        {
                            findings.push(relationship(
                                page,
                                &item.lang,
                                &target_url,
                                format!(
                                    "Page {} hreflang {} target {} canonicalizes to {}.",
                                    page.identity, item.lang, target_url, target_preferred
                                ),
                                "Point hreflang at the target's canonical URL.",
                                pointer(
                                    page.identity.clone(),
                                    "hreflang",
                                    format!("{} -> {target_url}", item.lang),
                                ),
                                pointer(
                                    obs.identity.clone(),
                                    "canonical",
                                    target_preferred.clone(),
                                ),
                            ));
                        }
                        if is_self(&target_url, page, &preferred) {
                            continue;
                        }
                        if !returns_to(obs, page, &preferred) {
                            findings.push(relationship(
                                page,
                                &item.lang,
                                &target_url,
                                format!(
                                    "Page {} hreflang {} target {} has no return link to {}.",
                                    page.identity, item.lang, target_url, page.identity
                                ),
                                "Each locale URL must list the others, including a return link.",
                                pointer(
                                    page.identity.clone(),
                                    "hreflang",
                                    format!("{} -> {target_url}", item.lang),
                                ),
                                pointer(obs.identity.clone(), "hreflang", format_hreflangs(obs)),
                            ));
                        }
                    }
                }
            }
            if !saw_self {
                findings.push(FindingDraft {
                    entity_key: format!("{} self-reference", page.identity),
                    fact: format!(
                        "Page {} hreflang set has no self-reference to {preferred}.",
                        page.identity
                    ),
                    recommendation: "Include a self-referencing hreflang annotation.".into(),
                    evidence: vec![
                        pointer(page.identity.clone(), "hreflang", format_hreflangs(page)),
                        pointer(preferred.clone(), "hreflang", "self-reference missing"),
                    ],
                });
            }
        }
        if missing {
            return incomplete();
        }
        complete(findings)
    }
}

impl Checker for HreflangMissingHreflangAndLang {
    fn rule_id(&self) -> &'static str {
        "hreflang.missing_hreflang_and_lang"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if evidence.observations.is_empty() || pages.is_empty() {
            return incomplete();
        }
        let crawl = crawl_identities(evidence);
        let mut findings = Vec::new();
        for page in pages {
            if !in_crawl_set(&crawl, &page.identity) {
                continue;
            }
            let has_lang = page
                .page
                .html_lang
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            if has_lang || !page.page.hreflangs.is_empty() {
                continue;
            }
            findings.push(FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!(
                    "Page {} has neither html lang nor hreflang. Missing hreflang alone on a single-language page is not an error.",
                    page.identity
                ),
                recommendation: "Add an html lang attribute; add hreflang only for a locale cluster."
                    .into(),
                evidence: vec![pointer(
                    page.identity.clone(),
                    "html_lang",
                    "html lang and hreflang absent",
                )],
            });
        }
        complete(findings)
    }
}

impl Checker for HreflangLanguageMismatch {
    fn rule_id(&self) -> &'static str {
        "hreflang.language_mismatch"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if evidence.observations.is_empty() || pages.is_empty() {
            return incomplete();
        }
        let crawl = crawl_identities(evidence);
        let min_hits = usize_threshold(config, "min_language_hits", DEFAULT_MIN_LANGUAGE_HITS);
        let min_confidence = f64_threshold(
            config,
            "min_language_confidence",
            DEFAULT_MIN_LANGUAGE_CONFIDENCE,
        );
        let mut findings = Vec::new();
        let mut declared = false;
        for page in pages {
            if !in_crawl_set(&crawl, &page.identity) {
                continue;
            }
            let html_lang = page.page.html_lang.as_deref().and_then(primary_language);
            let self_lang = self_hreflang_language(page);
            if html_lang.is_none() && self_lang.is_none() {
                continue;
            }
            declared = true;
            if let (Some(html), Some(hreflang)) = (html_lang.clone(), self_lang.clone())
                && html != hreflang
            {
                findings.push(FindingDraft {
                    entity_key: format!("{} declared", page.identity),
                    fact: format!(
                        "Page {} declares html lang={html} while self hreflang={hreflang} (declared-signal mismatch, confidence 1.00).",
                        page.identity
                    ),
                    recommendation: "Align html lang with the self-referencing hreflang language."
                        .into(),
                    evidence: vec![
                        pointer(
                            page.identity.clone(),
                            "html_lang",
                            page.page.html_lang.clone().unwrap_or_default(),
                        ),
                        pointer(page.identity.clone(), "hreflang", format_hreflangs(page)),
                    ],
                });
            }
            let declared_lang = html_lang.or(self_lang);
            if let Some(declared_lang) = declared_lang
                && let Some((detected, confidence, hits)) = detect_content_language(&page.page.text)
                && hits >= min_hits
                && confidence + f64::EPSILON >= min_confidence
                && detected != declared_lang
            {
                findings.push(FindingDraft {
                    entity_key: format!("{} content", page.identity),
                    fact: format!(
                        "Page {} declared language {declared_lang} but content-language heuristic detected {detected} (confidence {confidence:.2}, {hits} hits). This is a heuristic, not a parser result.",
                        page.identity
                    ),
                    recommendation: format!(
                        "Review copy and language annotations. Heuristic gates: min_language_hits={min_hits}, min_language_confidence={min_confidence}."
                    ),
                    evidence: vec![pointer(
                        page.identity.clone(),
                        "text_language",
                        format!("{detected} confidence={confidence:.2}"),
                    )],
                });
            }
        }
        if !declared {
            return not_applicable();
        }
        complete(findings)
    }
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

fn relationship(
    page: &ExtractedObservations,
    lang: &str,
    target: &str,
    fact: String,
    recommendation: &str,
    source: EvidencePointer,
    target_ev: EvidencePointer,
) -> FindingDraft {
    FindingDraft {
        entity_key: format!("{} hreflang={lang} -> {target}", page.identity),
        fact,
        recommendation: recommendation.into(),
        evidence: vec![source, target_ev],
    }
}

fn usize_threshold(config: &AuditConfig, key: &str, default: usize) -> usize {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn f64_threshold(config: &AuditConfig, key: &str, default: f64) -> f64 {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn normalize_identity(value: &str) -> String {
    match Url::parse(value) {
        Ok(url) => crate::scope::FetchIdentity::from_url(&url)
            .as_str()
            .to_owned(),
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
    Some(
        crate::scope::FetchIdentity::from_url(&resolved)
            .as_str()
            .to_owned(),
    )
}

fn complete_html<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    evidence
        .observations
        .iter()
        .filter(|observation| observation.page.is_complete())
        .collect()
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

fn declaring_pages<'a>(evidence: &'a EvidenceBundle<'_>) -> Option<Vec<&'a ExtractedObservations>> {
    if evidence.observations.is_empty() {
        return None;
    }
    let pages = complete_html(evidence);
    if pages.is_empty() {
        return None;
    }
    Some(
        pages
            .into_iter()
            .filter(|page| !page.page.hreflangs.is_empty())
            .collect(),
    )
}

struct Target<'a> {
    status: Option<u16>,
    failed_reason: Option<&'a str>,
    state: Option<UrlState>,
    robots_blocked: bool,
    observation: Option<&'a ExtractedObservations>,
    fetch: Option<&'a ResourceFetch>,
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
                robots_blocked: false,
                observation: None,
                fetch: None,
            },
        );
    }
    for fetch in evidence.resource_fetches {
        let key = normalize_identity(&fetch.identity);
        let entry = map.entry(key).or_insert(Target {
            status: None,
            failed_reason: None,
            state: None,
            robots_blocked: false,
            observation: None,
            fetch: None,
        });
        entry.status = fetch.status.or(entry.status);
        entry.failed_reason = fetch.failed_reason.as_deref().or(entry.failed_reason);
        entry.robots_blocked = fetch.robots_blocked;
        entry.fetch = Some(fetch);
    }
    for observation in evidence.observations {
        let key = normalize_identity(&observation.identity);
        let entry = map.entry(key).or_insert(Target {
            status: None,
            failed_reason: None,
            state: None,
            robots_blocked: false,
            observation: None,
            fetch: None,
        });
        entry.status = Some(observation.page.status);
        entry.observation = Some(observation);
    }
    map
}

fn lookup<'a>(index: &'a BTreeMap<String, Target<'a>>, url: &str) -> Option<&'a Target<'a>> {
    index.get(&normalize_identity(url))
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

fn page_noindex(obs: &ExtractedObservations) -> bool {
    has_noindex(&obs.page.robots_headers) || has_noindex(&obs.page.robots_meta)
}

fn preferred_url(page: &ExtractedObservations) -> String {
    page.page
        .canonicals
        .iter()
        .find_map(|href| resolve_href(&page.identity, href))
        .unwrap_or_else(|| normalize_identity(&page.identity))
}

fn is_self(target: &str, page: &ExtractedObservations, preferred: &str) -> bool {
    let target = normalize_identity(target);
    target == normalize_identity(&page.identity) || target == normalize_identity(preferred)
}

fn returns_to(
    target: &ExtractedObservations,
    source: &ExtractedObservations,
    preferred: &str,
) -> bool {
    target.page.hreflangs.iter().any(|item| {
        resolve_href(&target.identity, &item.href)
            .map(|url| is_self(&url, source, preferred))
            .unwrap_or(false)
    })
}

fn format_hreflangs(page: &ExtractedObservations) -> String {
    page.page
        .hreflangs
        .iter()
        .map(|item| format!("{} -> {}", item.lang, item.href))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn normalize_lang_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_valid_hreflang(value: &str) -> bool {
    let value = value.trim();
    if value.eq_ignore_ascii_case("x-default") {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains('_') || lower.is_empty() {
        return false;
    }
    let mut parts = lower.split('-');
    let Some(lang) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&lang.len()) || !lang.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    match rest.as_slice() {
        [] => true,
        [script] if is_script(script) => true,
        [region] if is_region(region) => true,
        [script, region] if is_script(script) && is_region(region) => true,
        _ => false,
    }
}

fn is_script(value: &str) -> bool {
    value.len() == 4 && value.chars().all(|c| c.is_ascii_lowercase())
}

fn is_region(value: &str) -> bool {
    (value.len() == 2 && value.chars().all(|c| c.is_ascii_lowercase()))
        || (value.len() == 3 && value.chars().all(|c| c.is_ascii_digit()))
}

fn primary_language(tag: &str) -> Option<String> {
    let tag = tag.trim();
    if tag.is_empty() || tag.eq_ignore_ascii_case("x-default") {
        return None;
    }
    let primary = tag.split(['-', '_']).next().unwrap_or(tag);
    let lower = primary.to_ascii_lowercase();
    if (2..=3).contains(&lower.len()) && lower.chars().all(|c| c.is_ascii_lowercase()) {
        Some(lower)
    } else {
        None
    }
}

fn self_hreflang_language(page: &ExtractedObservations) -> Option<String> {
    let preferred = preferred_url(page);
    page.page.hreflangs.iter().find_map(|item| {
        let resolved = resolve_href(&page.identity, &item.href)?;
        is_self(&resolved, page, &preferred)
            .then(|| primary_language(&item.lang))
            .flatten()
    })
}

const LANG_WORDS: &[(&str, &[&str])] = &[
    (
        "en",
        &[
            "the", "this", "that", "with", "from", "have", "were", "their", "they", "not",
        ],
    ),
    (
        "es",
        &[
            "que", "los", "las", "una", "del", "por", "para", "como", "más", "pero", "sus", "está",
        ],
    ),
    (
        "fr",
        &[
            "les", "des", "une", "dans", "pour", "qui", "est", "pas", "plus", "sont", "aux",
            "cette",
        ],
    ),
    (
        "de",
        &[
            "und", "der", "die", "das", "den", "nicht", "ich", "sie", "ein", "eine", "auf", "auch",
        ],
    ),
    (
        "pt",
        &[
            "não", "uma", "para", "mais", "como", "mas", "dos", "das", "pela", "pelo", "está",
            "são",
        ],
    ),
    (
        "it",
        &[
            "che", "per", "non", "una", "sono", "più", "della", "degli", "anche", "come", "questo",
        ],
    ),
];

fn detect_content_language(text: &str) -> Option<(String, f64, usize)> {
    let tokens: Vec<String> = text
        .split(|c: char| !c.is_alphabetic())
        .filter(|token| token.len() >= 2)
        .map(|token| token.to_ascii_lowercase())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let mut scores: BTreeMap<&str, usize> = BTreeMap::new();
    for (lang, words) in LANG_WORDS {
        let hits = tokens
            .iter()
            .filter(|token| words.iter().any(|word| word.eq_ignore_ascii_case(token)))
            .count();
        if hits > 0 {
            scores.insert(*lang, hits);
        }
    }
    let total: usize = scores.values().sum();
    if total == 0 {
        return None;
    }
    let (lang, hits) = scores.into_iter().max_by_key(|(_, hits)| *hits)?;
    Some((lang.to_owned(), hits as f64 / total as f64, hits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::RuleState;
    use crate::crawl::UrlRecord;
    use crate::extract::{ExtractHeader, ExtractInput, extract};
    use crate::profile::Profile;
    use crate::scope::FetchIdentity;
    use crate::store::Store;
    use url::Url;

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

    fn url_rec(url: &str, state: UrlState) -> UrlRecord {
        UrlRecord {
            original: url.to_owned(),
            identity: Some(identity(url)),
            state,
            reason: "Fetched".into(),
            click_depth: Some(0),
            via_website: true,
            via_sitemap: false,
        }
    }

    fn alts(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(lang, href)| {
                format!(r#"<link rel="alternate" hreflang="{lang}" href="{href}">"#)
            })
            .collect::<Vec<_>>()
            .join("")
    }

    fn html(url_lang: Option<&str>, pairs: &[(&str, &str)], body: &str) -> String {
        let lang = url_lang
            .map(|value| format!(r#" lang="{value}""#))
            .unwrap_or_default();
        format!(
            r#"<!DOCTYPE html><html{lang}><head>{}</head><body>{body}</body></html>"#,
            alts(pairs)
        )
    }

    fn run(obs: &[ExtractedObservations], urls: &[UrlRecord]) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls,
                sitemap: None,
                sitemap_done: true,
                robots: None,
                resource_fetches: &[],
            },
            &AuditConfig::default(),
            &hreflang_registry(),
            &[],
        )
    }

    fn run_with_fetches(
        obs: &[ExtractedObservations],
        urls: &[UrlRecord],
        fetches: &[ResourceFetch],
    ) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls,
                sitemap: None,
                sitemap_done: true,
                robots: None,
                resource_fetches: fetches,
            },
            &AuditConfig::default(),
            &hreflang_registry(),
            &[],
        )
    }

    #[test]
    fn invalid_tags_conflict_with_valid_bcp47_and_x_default() {
        let invalid = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("espanol", "https://audit.example/es"),
                    ("es_ES", "https://audit.example/es"),
                ],
                "pagina",
            ),
        );
        let valid = page(
            "https://audit.example/ok",
            &html(
                Some("es"),
                &[
                    ("es-ES", "https://audit.example/ok"),
                    ("x-default", "https://audit.example/ok"),
                    ("zh-Hans", "https://audit.example/zh"),
                    ("es-419", "https://audit.example/latam"),
                ],
                "pagina",
            ),
        );
        let zh = page(
            "https://audit.example/zh",
            &html(
                Some("zh-Hans"),
                &[
                    ("es-ES", "https://audit.example/ok"),
                    ("zh-Hans", "https://audit.example/zh"),
                    ("x-default", "https://audit.example/ok"),
                    ("es-419", "https://audit.example/latam"),
                ],
                "页",
            ),
        );
        let latam = page(
            "https://audit.example/latam",
            &html(
                Some("es"),
                &[
                    ("es-ES", "https://audit.example/ok"),
                    ("zh-Hans", "https://audit.example/zh"),
                    ("x-default", "https://audit.example/ok"),
                    ("es-419", "https://audit.example/latam"),
                ],
                "pagina",
            ),
        );
        let report = run(&[invalid, valid.clone(), zh.clone(), latam.clone()], &[]);
        assert_eq!(
            report.outcome("hreflang.values_invalid"),
            Some(RuleState::Findings)
        );
        let dump = report
            .findings_for("hreflang.values_invalid")
            .map(|finding| finding.fact.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(dump.contains("espanol"), "{dump}");
        assert!(
            dump.contains("es_ES") || dump.contains("underscore"),
            "{dump}"
        );
        assert!(
            report
                .findings_for("hreflang.values_invalid")
                .all(|finding| finding.id.entity_key.contains("/es"))
        );
        let ok = run(&[valid, zh, latam], &[]);
        assert_eq!(
            ok.outcome("hreflang.values_invalid"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn source_conflicts_when_one_language_maps_to_two_urls() {
        let conflict = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es-ES", "https://audit.example/es"),
                    ("es-ES", "https://audit.example/es-alt"),
                    ("en", "https://audit.example/en"),
                ],
                "hola",
            ),
        );
        let report = run(&[conflict], &[]);
        assert_eq!(
            report.outcome("hreflang.source_conflicts"),
            Some(RuleState::Findings)
        );
        let finding = report
            .findings_for("hreflang.source_conflicts")
            .next()
            .unwrap();
        assert!(finding.fact.contains("es-ES"), "{}", finding.fact);
        assert!(!finding.evidence.is_empty());
    }

    #[test]
    fn multi_locale_x_default_cluster_passes_when_reciprocal() {
        let es = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://audit.example/en"),
                    ("x-default", "https://audit.example/en"),
                ],
                "hola que tal los amigos para mas",
            ),
        );
        let en = page(
            "https://audit.example/en",
            &html(
                Some("en"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://audit.example/en"),
                    ("x-default", "https://audit.example/en"),
                ],
                "hello there this and that with their",
            ),
        );
        let urls = [
            url_rec("https://audit.example/es", UrlState::Fetched),
            url_rec("https://audit.example/en", UrlState::Fetched),
        ];
        let report = run(&[es, en], &urls);
        assert_eq!(
            report.outcome("hreflang.incorrect_links"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("hreflang.source_conflicts"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("hreflang.values_invalid"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("hreflang.missing_hreflang_and_lang"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("hreflang.language_mismatch"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn absent_return_link_includes_source_and_target_evidence() {
        let es = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://audit.example/en"),
                ],
                "hola",
            ),
        );
        let en = page(
            "https://audit.example/en",
            &html(Some("en"), &[("en", "https://audit.example/en")], "hello"),
        );
        let urls = [
            url_rec("https://audit.example/es", UrlState::Fetched),
            url_rec("https://audit.example/en", UrlState::Fetched),
        ];
        let report = run(&[es, en], &urls);
        assert_eq!(
            report.outcome("hreflang.incorrect_links"),
            Some(RuleState::Findings)
        );
        let finding = report
            .findings_for("hreflang.incorrect_links")
            .find(|item| item.fact.to_ascii_lowercase().contains("return"))
            .unwrap();
        let identities: Vec<_> = finding
            .evidence
            .iter()
            .map(|pointer| pointer.observation_identity.as_str())
            .collect();
        assert!(
            identities.iter().any(|id| id.contains("/es")),
            "{identities:?}"
        );
        assert!(
            identities.iter().any(|id| id.contains("/en")),
            "{identities:?}"
        );
    }

    #[test]
    fn inaccessible_target_includes_source_and_target_evidence() {
        let es = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://audit.example/missing"),
                ],
                "hola",
            ),
        );
        let missing = page_full(
            "https://audit.example/missing",
            404,
            "text/html",
            b"<html>gone</html>",
            &[],
        );
        let urls = [
            url_rec("https://audit.example/es", UrlState::Fetched),
            url_rec("https://audit.example/missing", UrlState::Fetched),
        ];
        let report = run(&[es, missing], &urls);
        assert_eq!(
            report.outcome("hreflang.incorrect_links"),
            Some(RuleState::Findings)
        );
        let finding = report
            .findings_for("hreflang.incorrect_links")
            .next()
            .unwrap();
        assert!(
            finding.fact.contains("404")
                || finding.fact.to_ascii_lowercase().contains("inaccessible"),
            "{}",
            finding.fact
        );
        let identities: Vec<_> = finding
            .evidence
            .iter()
            .map(|pointer| pointer.observation_identity.as_str())
            .collect();
        assert!(identities.iter().any(|id| id.contains("/es")));
        assert!(identities.iter().any(|id| id.contains("/missing")));
    }

    #[test]
    fn unfetched_target_is_incomplete() {
        let es = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://audit.example/en"),
                ],
                "hola",
            ),
        );
        let urls = [url_rec("https://audit.example/es", UrlState::Fetched)];
        let report = run(&[es], &urls);
        assert_eq!(
            report.outcome("hreflang.incorrect_links"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn missing_hreflang_on_single_language_page_is_not_an_error() {
        let with_lang = page(
            "https://audit.example/p",
            &html(Some("es"), &[], "solo castellano"),
        );
        let neither = page(
            "https://audit.example/bare",
            &html(None, &[], "no language marks"),
        );
        let ok = run(
            &[with_lang],
            &[url_rec("https://audit.example/p", UrlState::Fetched)],
        );
        assert_eq!(
            ok.outcome("hreflang.missing_hreflang_and_lang"),
            Some(RuleState::Passed)
        );
        assert_ne!(
            ok.outcome("hreflang.incorrect_links"),
            Some(RuleState::Findings)
        );
        let missing = run(
            &[neither],
            &[url_rec("https://audit.example/bare", UrlState::Fetched)],
        );
        assert_eq!(
            missing.outcome("hreflang.missing_hreflang_and_lang"),
            Some(RuleState::Findings)
        );
    }

    #[test]
    fn language_mismatch_is_heuristic_with_confidence() {
        let declared = page(
            "https://audit.example/es",
            &html(Some("en"), &[("es", "https://audit.example/es")], "hola"),
        );
        let content = page(
            "https://audit.example/mix",
            &html(
                Some("en"),
                &[("en", "https://audit.example/mix")],
                "que los las una del por para como más pero sus está que los las una del por para",
            ),
        );
        let report = run(
            &[declared, content],
            &[
                url_rec("https://audit.example/es", UrlState::Fetched),
                url_rec("https://audit.example/mix", UrlState::Fetched),
            ],
        );
        assert_eq!(
            report.outcome("hreflang.language_mismatch"),
            Some(RuleState::Findings)
        );
        let dump = report
            .findings_for("hreflang.language_mismatch")
            .map(|finding| finding.fact.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            dump.to_ascii_lowercase().contains("heuristic") || dump.contains("confidence"),
            "{dump}"
        );
        assert!(
            dump.contains("html") || dump.contains("hreflang") || dump.contains("es"),
            "{dump}"
        );
    }

    #[test]
    fn noindex_and_off_canonical_targets_are_incorrect() {
        let es = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://audit.example/en"),
                ],
                "hola",
            ),
        );
        let en = page(
            "https://audit.example/en",
            r#"<!DOCTYPE html><html lang="en"><head>
              <link rel="canonical" href="https://audit.example/en-canonical">
              <meta name="robots" content="noindex">
              <link rel="alternate" hreflang="es" href="https://audit.example/es">
              <link rel="alternate" hreflang="en" href="https://audit.example/en">
            </head><body>hello</body></html>"#,
        );
        let report = run(
            &[es, en],
            &[
                url_rec("https://audit.example/es", UrlState::Fetched),
                url_rec("https://audit.example/en", UrlState::Fetched),
            ],
        );
        assert_eq!(
            report.outcome("hreflang.incorrect_links"),
            Some(RuleState::Findings)
        );
        let dump = report
            .findings_for("hreflang.incorrect_links")
            .map(|finding| finding.fact.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            dump.to_ascii_lowercase().contains("noindex") || dump.contains("canonical"),
            "{dump}"
        );
    }

    #[test]
    fn failed_unsigned_target_is_a_finding_not_incomplete() {
        let es = page(
            "https://audit.example/es",
            &html(
                Some("es"),
                &[
                    ("es", "https://audit.example/es"),
                    ("en", "https://locale.example/en"),
                ],
                "hola",
            ),
        );
        let fetch = ResourceFetch {
            identity: "https://locale.example/en".into(),
            status: None,
            failed_reason: Some("Connection failed to https://locale.example/en".into()),
            challenge: false,
            credentials_attached: false,
            robots_blocked: false,
            robots_known: true,
            content_type: String::new(),
        };
        let report = run_with_fetches(
            &[es],
            &[url_rec("https://audit.example/es", UrlState::Fetched)],
            std::slice::from_ref(&fetch),
        );
        assert_eq!(
            report.outcome("hreflang.incorrect_links"),
            Some(RuleState::Findings)
        );
        let finding = report
            .findings_for("hreflang.incorrect_links")
            .next()
            .unwrap();
        assert!(!fetch.credentials_attached);
        assert!(
            finding
                .evidence
                .iter()
                .any(|pointer| { pointer.observation_identity.contains("locale.example") })
        );
    }

    #[test]
    fn empty_observations_are_incomplete_and_no_hreflang_is_not_applicable() {
        let empty = run(&[], &[]);
        assert_eq!(
            empty.outcome("hreflang.values_invalid"),
            Some(RuleState::Incomplete)
        );
        let single = page("https://audit.example/p", &html(Some("es"), &[], "texto"));
        let none = run(
            &[single],
            &[url_rec("https://audit.example/p", UrlState::Fetched)],
        );
        assert_eq!(
            none.outcome("hreflang.values_invalid"),
            Some(RuleState::NotApplicable)
        );
        assert_eq!(
            none.outcome("hreflang.incorrect_links"),
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
                    "https://audit.example/es",
                    &html(Some("es"), &[("espanol", "/es")], "hola"),
                ),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &hreflang_registry(),
        )
        .unwrap();
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &hreflang_registry(),
        )
        .unwrap();
        assert_eq!(
            first.outcome("hreflang.values_invalid"),
            Some(RuleState::Findings)
        );
        assert_eq!(first.findings, second.findings);
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(
            &[page(
                "https://audit.example/es",
                &html(Some("es"), &[("es", "https://audit.example/es")], "hola"),
            )],
            &[],
        );
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
        assert!(!dump.contains("TESTSIGNATURE"));
    }
}
