//! Titles, descriptions, headings and HTML metadata checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::extract::ExtractedObservations;
use std::collections::BTreeMap;

/// Crawlytic heuristic, not a Semrush formula. Override with `max_title_chars`.
pub const DEFAULT_MAX_TITLE_CHARS: usize = 60;
/// Crawlytic heuristic, not a Semrush formula. Override with `min_title_chars`.
pub const DEFAULT_MIN_TITLE_CHARS: usize = 30;
/// Crawlytic heuristic, not a Semrush formula. Override with `max_html_bytes`.
pub const DEFAULT_MAX_HTML_BYTES: u64 = 1_048_576;

pub fn normalize_meta(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn html_metadata_registry() -> Registry {
    let mut registry = Registry::new();
    register_html_metadata(&mut registry);
    registry
}

pub fn register_html_metadata(registry: &mut Registry) {
    registry.register(DuplicateDescription);
    registry.register(MissingTitle);
    registry.register(DuplicateTitle);
    registry.register(MissingViewport);
    registry.register(OversizedHtml);
    registry.register(MissingViewportWidth);
    registry.register(LongTitle);
    registry.register(ShortTitle);
    registry.register(MissingH1);
    registry.register(H1MatchesTitle);
    registry.register(MissingDescription);
    registry.register(MissingCharset);
    registry.register(MissingDoctype);
    registry.register(IncompatiblePlugin);
    registry.register(Frames);
    registry.register(MultipleH1);
}

fn complete_pages<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    evidence
        .observations
        .iter()
        .filter(|observation| observation.page.is_complete())
        .collect()
}

fn first_non_empty(values: &[String]) -> Option<&str> {
    values
        .iter()
        .map(String::as_str)
        .find(|value| !value.is_empty())
}

fn presence_kind(values: &[String]) -> Presence {
    if values.is_empty() {
        Presence::Missing
    } else if first_non_empty(values).is_none() {
        Presence::Empty
    } else {
        Presence::Present
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Presence {
    Missing,
    Empty,
    Present,
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

fn noindex(obs: &ExtractedObservations) -> bool {
    obs.page
        .robots_meta
        .iter()
        .chain(obs.page.robots_headers.iter())
        .any(|value| {
            value.to_ascii_lowercase().split([',', ';']).any(|token| {
                token
                    .split_whitespace()
                    .any(|part| part.trim() == "noindex")
            })
        })
}

fn indexability(obs: &ExtractedObservations) -> &'static str {
    if noindex(obs) { "noindex" } else { "indexable" }
}

fn canonical_label(obs: &ExtractedObservations) -> String {
    if obs.page.canonicals.is_empty() {
        "canonical=none".into()
    } else {
        format!("canonical={}", obs.page.canonicals.join(" | "))
    }
}

fn page_context(obs: &ExtractedObservations) -> String {
    format!(
        "{} ({}, {})",
        obs.identity,
        indexability(obs),
        canonical_label(obs)
    )
}

fn usize_threshold(config: &AuditConfig, key: &str, default: usize) -> usize {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn u64_threshold(config: &AuditConfig, key: &str, default: u64) -> u64 {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn viewport_has_width(content: &str) -> bool {
    content.split([',', ';']).any(|part| {
        let Some((key, value)) = part.split_once('=') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case("width") && !value.trim().is_empty()
    })
}

fn scan_each(
    evidence: &EvidenceBundle<'_>,
    check: impl FnMut(&ExtractedObservations) -> Option<FindingDraft>,
) -> CheckerOutput {
    let pages = complete_pages(evidence);
    if pages.is_empty() {
        return CheckerOutput {
            applicable: true,
            evidence_complete: false,
            findings: Vec::new(),
        };
    }
    let findings = pages.into_iter().filter_map(check).collect();
    CheckerOutput {
        applicable: true,
        evidence_complete: true,
        findings,
    }
}

fn scan_filtered(
    evidence: &EvidenceBundle<'_>,
    mut applicable: impl FnMut(&ExtractedObservations) -> bool,
    check: impl FnMut(&ExtractedObservations) -> Option<FindingDraft>,
) -> CheckerOutput {
    let pages = complete_pages(evidence);
    if pages.is_empty() {
        return CheckerOutput {
            applicable: true,
            evidence_complete: false,
            findings: Vec::new(),
        };
    }
    let subset: Vec<_> = pages
        .iter()
        .copied()
        .filter(|page| applicable(page))
        .collect();
    if subset.is_empty() {
        return CheckerOutput {
            applicable: false,
            evidence_complete: true,
            findings: Vec::new(),
        };
    }
    let findings = subset.into_iter().filter_map(check).collect();
    CheckerOutput {
        applicable: true,
        evidence_complete: true,
        findings,
    }
}

fn duplicate_groups<'a>(
    pages: &[&'a ExtractedObservations],
    value: impl Fn(&ExtractedObservations) -> Option<String>,
) -> BTreeMap<String, Vec<&'a ExtractedObservations>> {
    let mut groups = BTreeMap::new();
    for page in pages {
        if let Some(key) = value(page) {
            groups.entry(key).or_insert_with(Vec::new).push(*page);
        }
    }
    groups
}

fn duplicate_output(
    evidence: &EvidenceBundle<'_>,
    field: &str,
    value: impl Fn(&ExtractedObservations) -> Option<String>,
    per_page: bool,
    fact_label: &str,
) -> CheckerOutput {
    let pages = complete_pages(evidence);
    if pages.is_empty() {
        return CheckerOutput {
            applicable: true,
            evidence_complete: false,
            findings: Vec::new(),
        };
    }
    let groups = duplicate_groups(&pages, value);
    let mut findings = Vec::new();
    for (normalized, members) in groups {
        if members.len() < 2 {
            continue;
        }
        let contexts: Vec<_> = members.iter().map(|page| page_context(page)).collect();
        let joined = contexts.join("; ");
        let fact = format!(
            "{n} pages share this {fact_label} after trim-and-collapse-whitespace normalization ({normalized:?}). Affected URLs with canonical/indexability context: {joined}.",
            n = members.len()
        );
        let recommendation = format!(
            "Give each indexable URL a unique {fact_label}. Normalization is trim and collapse whitespace; it is not a Semrush formula."
        );
        let evidence_points: Vec<_> = members
            .iter()
            .map(|page| pointer(page, field, normalized.clone()))
            .collect();
        if per_page {
            for page in &members {
                findings.push(FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: fact.clone(),
                    recommendation: recommendation.clone(),
                    evidence: evidence_points.clone(),
                });
            }
        } else {
            let entity = if normalized.is_empty() {
                format!("{field}:(empty)")
            } else {
                format!("{field}:{normalized}")
            };
            findings.push(FindingDraft {
                entity_key: entity,
                fact,
                recommendation,
                evidence: evidence_points,
            });
        }
    }
    CheckerOutput {
        applicable: true,
        evidence_complete: true,
        findings,
    }
}

struct MissingTitle;
struct DuplicateTitle;
struct LongTitle;
struct ShortTitle;
struct MissingDescription;
struct DuplicateDescription;
struct MissingH1;
struct MultipleH1;
struct H1MatchesTitle;
struct MissingViewport;
struct MissingViewportWidth;
struct MissingCharset;
struct MissingDoctype;
struct OversizedHtml;
struct Frames;
struct IncompatiblePlugin;

impl Checker for MissingTitle {
    fn rule_id(&self) -> &'static str {
        "meta.missing_title"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| match presence_kind(&page.page.titles) {
            Presence::Present => None,
            kind => {
                let fact = match kind {
                    Presence::Missing => "The page has no title element.",
                    Presence::Empty => "The page has an empty title element.",
                    Presence::Present => unreachable!(),
                };
                Some(FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: fact.into(),
                    recommendation: "Add a single descriptive title element.".into(),
                    evidence: vec![pointer(
                        page,
                        "title",
                        page.page.titles.first().cloned().unwrap_or_default(),
                    )],
                })
            }
        })
    }
}

impl Checker for DuplicateTitle {
    fn rule_id(&self) -> &'static str {
        "meta.duplicate_title"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["meta.missing_title"]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        duplicate_output(
            evidence,
            "title",
            |page| {
                presence_kind(&page.page.titles)
                    .eq(&Presence::Present)
                    .then(|| normalize_meta(first_non_empty(&page.page.titles).unwrap_or("")))
            },
            false,
            "title",
        )
    }
}

impl Checker for LongTitle {
    fn rule_id(&self) -> &'static str {
        "meta.long_title"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["meta.missing_title"]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let max = usize_threshold(config, "max_title_chars", DEFAULT_MAX_TITLE_CHARS);
        scan_filtered(
            evidence,
            |page| presence_kind(&page.page.titles) == Presence::Present,
            |page| {
                let title = first_non_empty(&page.page.titles)?.to_owned();
                let chars = title.chars().count();
                (chars > max).then(|| FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: format!("The title is {chars} characters."),
                    recommendation: format!(
                        "Shorten the title to at most {max} characters (configured max_title_chars={max}; Crawlytic heuristic, not a Semrush formula)."
                    ),
                    evidence: vec![pointer(page, "title", title)],
                })
            },
        )
    }
}

impl Checker for ShortTitle {
    fn rule_id(&self) -> &'static str {
        "meta.short_title"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["meta.missing_title"]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let min = usize_threshold(config, "min_title_chars", DEFAULT_MIN_TITLE_CHARS);
        scan_filtered(
            evidence,
            |page| presence_kind(&page.page.titles) == Presence::Present,
            |page| {
                let title = first_non_empty(&page.page.titles)?.to_owned();
                let chars = title.chars().count();
                (chars < min).then(|| FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: format!("The title is {chars} characters."),
                    recommendation: format!(
                        "Lengthen the title to at least {min} characters (configured min_title_chars={min}; Crawlytic heuristic, not a Semrush formula)."
                    ),
                    evidence: vec![pointer(page, "title", title)],
                })
            },
        )
    }
}

impl Checker for MissingDescription {
    fn rule_id(&self) -> &'static str {
        "meta.missing_description"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            match presence_kind(&page.page.descriptions) {
                Presence::Present => None,
                kind => {
                    let fact = match kind {
                        Presence::Missing => "The page has no meta description element.",
                        Presence::Empty => "The page has an empty meta description.",
                        Presence::Present => unreachable!(),
                    };
                    Some(FindingDraft {
                        entity_key: page.identity.clone(),
                        fact: fact.into(),
                        recommendation: "Add a unique non-empty meta description.".into(),
                        evidence: vec![pointer(
                            page,
                            "description",
                            page.page.descriptions.first().cloned().unwrap_or_default(),
                        )],
                    })
                }
            }
        })
    }
}

impl Checker for DuplicateDescription {
    fn rule_id(&self) -> &'static str {
        "meta.duplicate_description"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["meta.missing_description"]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        duplicate_output(
            evidence,
            "description",
            |page| {
                presence_kind(&page.page.descriptions)
                    .eq(&Presence::Present)
                    .then(|| normalize_meta(first_non_empty(&page.page.descriptions).unwrap_or("")))
            },
            true,
            "meta description",
        )
    }
}

impl Checker for MissingH1 {
    fn rule_id(&self) -> &'static str {
        "heading.missing_h1"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            let h1s: Vec<_> = page
                .page
                .headings
                .iter()
                .filter(|heading| heading.level == 1)
                .collect();
            h1s.is_empty().then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: "The page has no h1 element.".into(),
                recommendation:
                    "Add one h1 that describes the page. No universal SEO benefit is asserted."
                        .into(),
                evidence: vec![pointer(page, "h1", "")],
            })
        })
    }
}

impl Checker for MultipleH1 {
    fn rule_id(&self) -> &'static str {
        "heading.multiple_h1"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            let h1s: Vec<_> = page
                .page
                .headings
                .iter()
                .filter(|heading| heading.level == 1)
                .collect();
            (h1s.len() > 1).then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!("The page has {} h1 elements.", h1s.len()),
                recommendation: "Keep a single h1. No universal SEO benefit is asserted.".into(),
                evidence: vec![pointer(
                    page,
                    "h1",
                    h1s.iter()
                        .map(|heading| heading.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" | "),
                )],
            })
        })
    }
}

impl Checker for H1MatchesTitle {
    fn rule_id(&self) -> &'static str {
        "heading.h1_matches_title"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["meta.missing_title", "heading.missing_h1"]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_filtered(
            evidence,
            |page| {
                first_non_empty(&page.page.titles).is_some()
                    && page
                        .page
                        .headings
                        .iter()
                        .any(|heading| heading.level == 1 && !heading.text.is_empty())
            },
            |page| {
                let title = normalize_meta(first_non_empty(&page.page.titles)?);
                let h1 = page
                    .page
                    .headings
                    .iter()
                    .find(|heading| heading.level == 1 && !heading.text.is_empty())?;
                let heading = normalize_meta(&h1.text);
                (title == heading).then(|| FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: "The title and first non-empty h1 are identical after trim-and-collapse-whitespace normalization.".into(),
                    recommendation: "Differentiate the h1 from the title when they should describe distinct roles. No universal SEO benefit is asserted.".into(),
                    evidence: vec![
                        pointer(page, "title", title),
                        pointer(page, "h1", heading),
                    ],
                })
            },
        )
    }
}

impl Checker for MissingViewport {
    fn rule_id(&self) -> &'static str {
        "meta.missing_viewport"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            page.page.viewport.is_none().then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: "The page has no viewport meta tag.".into(),
                recommendation: "Add a viewport meta tag that includes a width directive.".into(),
                evidence: vec![pointer(page, "viewport", "")],
            })
        })
    }
}

impl Checker for MissingViewportWidth {
    fn rule_id(&self) -> &'static str {
        "meta.missing_viewport_width"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["meta.missing_viewport"]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_filtered(
            evidence,
            |page| page.page.viewport.is_some(),
            |page| {
                let content = page.page.viewport.clone().unwrap_or_default();
                (!viewport_has_width(&content)).then(|| FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: format!(
                        "The viewport meta tag has no width directive (content={content:?})."
                    ),
                    recommendation: "Add a width directive such as width=device-width.".into(),
                    evidence: vec![pointer(page, "viewport", content)],
                })
            },
        )
    }
}

impl Checker for MissingCharset {
    fn rule_id(&self) -> &'static str {
        "meta.missing_charset"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            (!page.page.charset_declared).then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: "The page has no charset declaration in Content-Type or a meta charset.".into(),
                recommendation: "Declare UTF-8 with a meta charset or Content-Type charset parameter. A UTF-8 BOM is not treated as a declaration.".into(),
                evidence: vec![pointer(page, "charset", page.page.encoding.clone())],
            })
        })
    }
}

impl Checker for MissingDoctype {
    fn rule_id(&self) -> &'static str {
        "meta.missing_doctype"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            page.page
                .doctype
                .as_ref()
                .map(|value| value.is_empty())
                .unwrap_or(true)
                .then(|| FindingDraft {
                    entity_key: page.identity.clone(),
                    fact: "The page has no doctype.".into(),
                    recommendation: "Start the document with <!DOCTYPE html>.".into(),
                    evidence: vec![pointer(
                        page,
                        "doctype",
                        page.page.doctype.clone().unwrap_or_default(),
                    )],
                })
        })
    }
}

impl Checker for OversizedHtml {
    fn rule_id(&self) -> &'static str {
        "meta.oversized_html"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let max = u64_threshold(config, "max_html_bytes", DEFAULT_MAX_HTML_BYTES);
        scan_each(evidence, |page| {
            (page.page.raw_bytes > max).then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!("The HTML body is {} bytes.", page.page.raw_bytes),
                recommendation: format!(
                    "Reduce the HTML body to at most {max} bytes (configured max_html_bytes={max}; Crawlytic heuristic, not a Semrush formula)."
                ),
                evidence: vec![pointer(page, "html_bytes", page.page.raw_bytes.to_string())],
            })
        })
    }
}

impl Checker for Frames {
    fn rule_id(&self) -> &'static str {
        "meta.frames"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            page.page.has_frames.then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: "The page uses frameset or frame markup.".into(),
                recommendation:
                    "Replace frameset/frame with modern layout. iframe is out of this rule.".into(),
                evidence: vec![pointer(page, "frameset_or_frame", "frameset/frame")],
            })
        })
    }
}

impl Checker for IncompatiblePlugin {
    fn rule_id(&self) -> &'static str {
        "meta.incompatible_plugin_content"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        scan_each(evidence, |page| {
            page.page.has_plugin_markup.then(|| FindingDraft {
                entity_key: page.identity.clone(),
                fact: "The page embeds object, embed or applet plugin markup.".into(),
                recommendation: "Remove legacy plugin embeds.".into(),
                evidence: vec![pointer(page, "embed_object_applet", "object/embed/applet")],
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::{CapturedCurrent, InventoryUnit, RuleState, rule_by_id};
    use crate::extract::{ExtractInput, extract};
    use crate::profile::Profile;
    use crate::store::Store;
    use std::collections::BTreeSet;
    use url::Url;

    fn page(url: &str, body: &str) -> ExtractedObservations {
        page_status(url, body, false)
    }

    fn page_status(url: &str, body: &str, truncated: bool) -> ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status: 200,
            content_type: "text/html",
            headers: &[],
            body: body.as_bytes(),
            truncated,
            duration_ms: Some(1),
        })
    }

    fn config() -> AuditConfig {
        let mut config = AuditConfig::default();
        config
            .thresholds
            .insert("max_title_chars".into(), "60".into());
        config
            .thresholds
            .insert("min_title_chars".into(), "30".into());
        config
            .thresholds
            .insert("max_html_bytes".into(), "2048".into());
        config
    }

    fn run(obs: &[ExtractedObservations]) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls: &[],
            },
            &config(),
            &html_metadata_registry(),
            &[],
        )
    }

    fn ok_page(url: &str) -> ExtractedObservations {
        page(
            url,
            r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>A reasonably long shop title here!!</title>
            <meta name="description" content="Unique cables for this URL">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            </head><body><h1>Cables</h1><p>Hello</p></body></html>"#,
        )
    }

    #[test]
    fn missing_and_empty_titles_are_distinguishable() {
        let missing = page(
            "https://audit.example/untitled",
            "<html><head></head><body>Hi</body></html>",
        );
        let empty = page(
            "https://audit.example/empty-title",
            "<html><head><title></title></head><body>Hi</body></html>",
        );
        let report = run(&[missing, empty]);
        let facts: BTreeSet<_> = report
            .findings_for("meta.missing_title")
            .map(|finding| finding.fact.as_str())
            .collect();
        assert!(facts.contains("The page has no title element."));
        assert!(facts.contains("The page has an empty title element."));
        assert_ne!(
            report
                .findings_for("meta.missing_title")
                .find(|finding| finding.id.entity_key.ends_with("/untitled"))
                .map(|finding| finding.fact.as_str()),
            report
                .findings_for("meta.missing_title")
                .find(|finding| finding.id.entity_key.ends_with("/empty-title"))
                .map(|finding| finding.fact.as_str())
        );
    }

    #[test]
    fn missing_and_empty_descriptions_are_distinguishable() {
        let missing = page(
            "https://audit.example/no-desc",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Has a non-empty title here!!</title></head><body><h1>H</h1></body></html>"#,
        );
        let empty = page(
            "https://audit.example/empty-desc",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Has a non-empty title here!!</title>
            <meta name="description" content="  "></head><body><h1>H</h1></body></html>"#,
        );
        let report = run(&[missing, empty]);
        let facts: BTreeSet<_> = report
            .findings_for("meta.missing_description")
            .map(|finding| finding.fact.as_str())
            .collect();
        assert!(facts.contains("The page has no meta description element."));
        assert!(facts.contains("The page has an empty meta description."));
    }

    #[test]
    fn duplicate_descriptions_expose_group_urls_and_indexability() {
        let shared = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>A reasonably long shop title here!!</title>
            <meta name="description" content="  Shared   cables  ">
            <meta name="viewport" content="width=device-width">
            <link rel="canonical" href="/dup">
            <meta name="robots" content="noindex">
            </head><body><h1>One</h1></body></html>"#;
        let indexable = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>Another reasonably long title here!!</title>
            <meta name="description" content="Shared cables">
            <meta name="viewport" content="width=device-width">
            </head><body><h1>Two</h1></body></html>"#;
        let unique = ok_page("https://audit.example/unique");
        let a = page("https://audit.example/a", shared);
        let b = page("https://audit.example/b", indexable);
        let report = run(&[a, b, unique]);
        assert_eq!(
            report.outcome("meta.duplicate_description"),
            Some(RuleState::Findings)
        );
        let urls = report.affected_identities("meta.duplicate_description");
        assert_eq!(
            urls,
            vec!["https://audit.example/a", "https://audit.example/b"]
        );
        let finding = report
            .findings_for("meta.duplicate_description")
            .next()
            .unwrap();
        assert!(finding.fact.contains("indexable"));
        assert!(finding.fact.contains("noindex"));
        assert!(finding.fact.contains("canonical=/dup"));
        assert!(finding.fact.contains("canonical=none"));
        assert!(finding.fact.contains("trim-and-collapse-whitespace"));
        assert_eq!(finding.id.entity_key, "https://audit.example/a");
    }

    #[test]
    fn duplicate_titles_are_one_issue_per_group() {
        let body = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>  Same   Title  Here For Two Pages!!</title>
            <meta name="description" content="A">
            <meta name="viewport" content="width=device-width">
            </head><body><h1>H</h1></body></html>"#;
        let report = run(&[
            page("https://audit.example/t1", body),
            page(
                "https://audit.example/t2",
                &body.replace("content=\"A\"", "content=\"B\""),
            ),
        ]);
        let findings: Vec<_> = report.findings_for("meta.duplicate_title").collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.entity_key.starts_with("title:"));
        assert_eq!(
            report.affected_identities("meta.duplicate_title"),
            vec!["https://audit.example/t1", "https://audit.example/t2"]
        );
    }

    #[test]
    fn threshold_recommendations_quote_configured_values() {
        let long = page(
            "https://audit.example/long",
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{}</title>
                <meta name="description" content="Unique long">
                <meta name="viewport" content="width=device-width"></head>
                <body><h1>Heading text</h1></body></html>"#,
                "L".repeat(80)
            ),
        );
        let short = page(
            "https://audit.example/short",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hi</title>
            <meta name="description" content="Unique short">
            <meta name="viewport" content="width=device-width"></head>
            <body><h1>Heading text</h1></body></html>"#,
        );
        let huge_body = format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="Unique huge">
            <meta name="viewport" content="width=device-width"></head>
            <body><h1>Heading text</h1><p>{}</p></body></html>"#,
            "x".repeat(3000)
        );
        let huge = page("https://audit.example/huge", &huge_body);
        let report = run(&[long, short, huge]);
        let long_rec = report
            .findings_for("meta.long_title")
            .next()
            .unwrap()
            .recommendation
            .clone();
        assert!(long_rec.contains("max_title_chars=60"), "{long_rec}");
        let short_rec = report
            .findings_for("meta.short_title")
            .next()
            .unwrap()
            .recommendation
            .clone();
        assert!(short_rec.contains("min_title_chars=30"), "{short_rec}");
        let size_rec = report
            .findings_for("meta.oversized_html")
            .next()
            .unwrap()
            .recommendation
            .clone();
        assert!(size_rec.contains("max_html_bytes=2048"), "{size_rec}");
    }

    #[test]
    fn headings_viewport_encoding_doctype_frames_and_plugins() {
        let missing_h1 = page(
            "https://audit.example/no-h1",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="n"><meta name="viewport" content="width=device-width"></head><body><p>Hi</p></body></html>"#,
        );
        let many_h1 = page(
            "https://audit.example/many-h1",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="m"><meta name="viewport" content="width=device-width"></head>
            <body><h1>One</h1><h1>Two</h1></body></html>"#,
        );
        let match_h1 = page(
            "https://audit.example/match",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Same Heading Text Here For Match!!</title>
            <meta name="description" content="k"><meta name="viewport" content="width=device-width"></head>
            <body><h1>Same Heading Text Here For Match!!</h1></body></html>"#,
        );
        let no_view = page(
            "https://audit.example/desktop",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="v"></head><body><h1>H</h1></body></html>"#,
        );
        let no_width = page(
            "https://audit.example/p",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="w"><meta name="viewport" content="initial-scale=1"></head>
            <body><h1>H</h1></body></html>"#,
        );
        let no_charset = page(
            "https://audit.example/encoding",
            r#"<!DOCTYPE html><html><head><title>A reasonably long shop title here!!</title>
            <meta name="description" content="e"><meta name="viewport" content="width=device-width"></head>
            <body><h1>H</h1></body></html>"#,
        );
        let no_doctype = page(
            "https://audit.example/doctype",
            r#"<html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="d"><meta name="viewport" content="width=device-width"></head>
            <body><h1>H</h1></body></html>"#,
        );
        let frames = page(
            "https://audit.example/legacy",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="f"><meta name="viewport" content="width=device-width"></head>
            <frameset><frame src="/a"></frameset></html>"#,
        );
        let plugin = page(
            "https://audit.example/flash",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="p"><meta name="viewport" content="width=device-width"></head>
            <body><h1>H</h1><embed src="a.swf"></body></html>"#,
        );
        let iframe_ok = page(
            "https://audit.example/iframe",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="i"><meta name="viewport" content="width=device-width"></head>
            <body><h1>H</h1><iframe src="/a"></iframe></body></html>"#,
        );
        let report = run(&[
            missing_h1, many_h1, match_h1, no_view, no_width, no_charset, no_doctype, frames,
            plugin, iframe_ok,
        ]);
        assert_eq!(
            report.outcome("heading.missing_h1"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("heading.multiple_h1"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("heading.h1_matches_title"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("meta.missing_viewport"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("meta.missing_viewport_width"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("meta.missing_charset"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("meta.missing_doctype"),
            Some(RuleState::Findings)
        );
        assert_eq!(report.outcome("meta.frames"), Some(RuleState::Findings));
        assert_eq!(
            report.outcome("meta.incompatible_plugin_content"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .affected_identities("meta.frames")
                .contains(&"https://audit.example/legacy")
        );
        assert!(
            !report
                .affected_identities("meta.frames")
                .contains(&"https://audit.example/iframe")
        );
        assert_eq!(
            report
                .findings_for("meta.missing_viewport_width")
                .next()
                .unwrap()
                .id
                .entity_key,
            "https://audit.example/p"
        );
    }

    #[test]
    fn truncated_evidence_is_incomplete_never_passed() {
        let truncated = page_status(
            "https://audit.example/partial",
            "<html><title>Partial",
            true,
        );
        let report = run(&[truncated]);
        assert_eq!(
            report.outcome("meta.missing_title"),
            Some(RuleState::Incomplete)
        );
        assert_ne!(
            report.outcome("meta.missing_title"),
            Some(RuleState::Passed)
        );
        assert!(report.findings_for("meta.missing_title").next().is_none());
        assert_eq!(
            report.outcome("meta.duplicate_title"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn healthy_page_passes_metadata_rules() {
        let report = run(&[ok_page("https://audit.example/ok")]);
        for id in [
            "meta.missing_title",
            "meta.duplicate_title",
            "meta.long_title",
            "meta.short_title",
            "meta.missing_description",
            "meta.duplicate_description",
            "heading.missing_h1",
            "heading.multiple_h1",
            "heading.h1_matches_title",
            "meta.missing_viewport",
            "meta.missing_viewport_width",
            "meta.missing_charset",
            "meta.missing_doctype",
            "meta.oversized_html",
            "meta.frames",
            "meta.incompatible_plugin_content",
        ] {
            assert_eq!(report.outcome(id), Some(RuleState::Passed), "{id}");
        }
    }

    #[test]
    fn viewport_width_not_applicable_without_viewport() {
        let report = run(&[page(
            "https://audit.example/desktop",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>A reasonably long shop title here!!</title>
            <meta name="description" content="v"></head><body><h1>H</h1></body></html>"#,
        )]);
        assert_eq!(
            report.outcome("meta.missing_viewport"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("meta.missing_viewport_width"),
            Some(RuleState::NotApplicable)
        );
    }

    #[test]
    fn historical_baseline_is_compared_by_urls_not_totals() {
        let desc = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <title>A reasonably long shop title TITLE!!</title>
            <meta name="description" content="Shared historical">
            <meta name="viewport" content="width=device-width"></head>
            <body><h1>H</h1></body></html>"#;
        let pages: Vec<_> = (1..=3)
            .map(|i| {
                page(
                    &format!("https://audit.example/d{i}"),
                    &desc.replace("TITLE", &format!("N{i}")),
                )
            })
            .collect();
        let long = page(
            "https://audit.example/long-a",
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{}</title>
                <meta name="description" content="L1"><meta name="viewport" content="width=device-width">
                </head><body><h1>H</h1></body></html>"#,
                "T".repeat(80)
            ),
        );
        let long_b = page(
            "https://audit.example/long-b",
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{}</title>
                <meta name="description" content="L2"><meta name="viewport" content="width=device-width">
                </head><body><h1>H</h1></body></html>"#,
                "U".repeat(80)
            ),
        );
        let mut obs = pages;
        obs.push(long);
        obs.push(long_b);
        let report = run(&obs);
        let desc_urls = report.affected_identities("meta.duplicate_description");
        assert_eq!(desc_urls.len(), 3);
        assert!(
            desc_urls
                .iter()
                .all(|url| url.starts_with("https://audit.example/d"))
        );
        let title_urls = report.affected_identities("meta.long_title");
        assert_eq!(title_urls.len(), 2);

        match rule_by_id("meta.duplicate_description")
            .unwrap()
            .captured_current
        {
            CapturedCurrent::Count {
                value: 5,
                unit: InventoryUnit::Page,
            } => {}
            other => panic!("{other:?}"),
        }
        match rule_by_id("meta.long_title").unwrap().captured_current {
            CapturedCurrent::Count {
                value: 73,
                unit: InventoryUnit::Page,
            } => {}
            other => panic!("{other:?}"),
        }
        assert_ne!(desc_urls.len(), 5);
        assert_ne!(title_urls.len(), 73);
        assert_ne!(title_urls.len(), 78);
        assert!(!desc_urls.iter().any(|url| url.contains("tiendacables.com")));
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
                    "https://audit.example/untitled",
                    "<html><head></head><body>Hi</body></html>",
                ),
            )
            .unwrap();
        let first = evaluate_stored(&store, run_id, &config(), &html_metadata_registry()).unwrap();
        let second = evaluate_stored(&store, run_id, &config(), &html_metadata_registry()).unwrap();
        assert_eq!(first.findings_for("meta.missing_title").count(), 1);
        assert_eq!(first.findings, second.findings);
        assert_eq!(
            first.outcome("meta.missing_title"),
            Some(RuleState::Findings)
        );
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(&[ok_page("https://audit.example/ok")]);
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
        assert_eq!(normalize_meta("  Shared   cables  "), "Shared cables");
    }
}
