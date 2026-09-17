//! Versioned audit rule catalogue and fixture contract.
//!
//! This module records every transcribed Site Audit check as a stable Crawlytic
//! rule. It does not run checkers. Owner issues implement evaluation. Live runs
//! without a checker must report [`RuleState::Unsupported`], never a finding.

mod data;

pub const CATALOGUE_VERSION: u32 = 1;
pub const FIXTURE_CONTRACT_VERSION: u32 = 1;
pub const HISTORICAL_BASELINE_DATE: &str = "2026-09-14";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Notice,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Notice => "notice",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "error" => Some(Self::Error),
            "warning" => Some(Self::Warning),
            "notice" => Some(Self::Notice),
            _ => None,
        }
    }
}

/// Inventory unit as captured from the baseline UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryUnit {
    Page,
    Link,
    Resource,
    Site,
    Image,
    File,
    Url,
    Issue,
    Conflict,
    AmpPage,
    Subdomain,
    Item,
    Unspecified,
}

/// Coarse unit required by the catalogue contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoarseUnit {
    Page,
    Link,
    Resource,
    Site,
}

impl InventoryUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Link => "link",
            Self::Resource => "resource",
            Self::Site => "site",
            Self::Image => "image",
            Self::File => "file",
            Self::Url => "url",
            Self::Issue => "issue",
            Self::Conflict => "conflict",
            Self::AmpPage => "amp_page",
            Self::Subdomain => "subdomain",
            Self::Item => "item",
            Self::Unspecified => "unspecified",
        }
    }

    pub fn coarse(self) -> CoarseUnit {
        match self {
            Self::Page | Self::AmpPage => CoarseUnit::Page,
            Self::Link | Self::Url => CoarseUnit::Link,
            Self::Site | Self::Unspecified => CoarseUnit::Site,
            Self::Resource
            | Self::Image
            | Self::File
            | Self::Issue
            | Self::Conflict
            | Self::Subdomain
            | Self::Item => CoarseUnit::Resource,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Crawl,
    UrlIdentity,
    Robots,
    Sitemap,
    HtmlMetadata,
    Content,
    Links,
    Images,
    Resources,
    CanonicalIndexability,
    Hreflang,
    Https,
    Tls,
    Amp,
    StructuredData,
    Performance,
    Analytics,
    Ai,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStatus {
    /// Mapped and waiting for the owner issue's checker.
    Specified,
    /// Legacy, AI, analytics, or otherwise out of the current product slice.
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleState {
    Passed,
    Findings,
    Incomplete,
    NotApplicable,
    Disabled,
    Unsupported,
}

impl RuleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Findings => "findings",
            Self::Incomplete => "incomplete",
            Self::NotApplicable => "not_applicable",
            Self::Disabled => "disabled",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "passed" => Some(Self::Passed),
            "findings" => Some(Self::Findings),
            "incomplete" => Some(Self::Incomplete),
            "not_applicable" => Some(Self::NotApplicable),
            "disabled" => Some(Self::Disabled),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedCurrent {
    Count { value: u32, unit: InventoryUnit },
    NoCount,
}

impl CapturedCurrent {
    pub fn is_current_finding(self) -> bool {
        matches!(self, Self::Count { value, .. } if value > 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub key: &'static str,
    pub default: Option<&'static str>,
    pub research_required: bool,
    pub notes: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureSet {
    pub version: u32,
    pub positive: &'static str,
    pub negative: &'static str,
    pub incomplete: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    pub captured_label: &'static str,
    pub severity: Severity,
    pub unit: InventoryUnit,
    pub stage: Stage,
    pub evidence: &'static [&'static str],
    pub applicability: &'static str,
    pub threshold: Threshold,
    pub references: &'static [&'static str],
    pub owner_issues: &'static [&'static str],
    pub status: RuleStatus,
    pub captured_current: CapturedCurrent,
    pub ambiguous: bool,
    pub notes: &'static str,
    pub fixtures: FixtureSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewIssuesExample {
    pub captured_label: &'static str,
    pub current_count: u32,
    pub current_unit: InventoryUnit,
    pub new_issues_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateInput {
    pub supported: bool,
    pub enabled: bool,
    pub applicable: bool,
    pub evidence_complete: bool,
    pub has_findings: bool,
}

pub fn rules() -> &'static [Rule] {
    data::RULES
}

pub fn rule_by_id(id: &str) -> Option<&'static Rule> {
    rules().iter().find(|rule| rule.id == id)
}

pub fn current_findings() -> impl Iterator<Item = &'static Rule> {
    rules()
        .iter()
        .filter(|rule| rule.captured_current.is_current_finding())
}

pub fn new_issues_examples() -> &'static [NewIssuesExample] {
    &[
        NewIssuesExample {
            captured_label: "Long title",
            current_count: 73,
            current_unit: InventoryUnit::Page,
            new_issues_count: 78,
        },
        NewIssuesExample {
            captured_label: "Low text/HTML ratio",
            current_count: 0,
            current_unit: InventoryUnit::Page,
            new_issues_count: 260,
        },
    ]
}

/// Precedence: unsupported, disabled, not-applicable, incomplete, findings, passed.
pub fn resolve_state(input: StateInput) -> RuleState {
    if !input.supported {
        RuleState::Unsupported
    } else if !input.enabled {
        RuleState::Disabled
    } else if !input.applicable {
        RuleState::NotApplicable
    } else if !input.evidence_complete {
        RuleState::Incomplete
    } else if input.has_findings {
        RuleState::Findings
    } else {
        RuleState::Passed
    }
}

pub fn checker_supported(rule: &Rule) -> bool {
    rule.status == RuleStatus::Specified && data::CHECKERS_SHIPPED
}

pub fn expected_fixture_state(kind: FixtureKind) -> RuleState {
    match kind {
        FixtureKind::Positive => RuleState::Findings,
        FixtureKind::Negative => RuleState::Passed,
        FixtureKind::Incomplete => RuleState::Incomplete,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureKind {
    Positive,
    Negative,
    Incomplete,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const INVENTORY: &[(&str, Severity, &str)] = &[
        ("Duplicate meta descriptions", Severity::Error, "5 pages"),
        ("HTTP 5xx", Severity::Error, "0 pages"),
        ("HTTP 4xx", Severity::Error, "0 pages"),
        ("Missing title", Severity::Error, "0 pages"),
        ("Duplicate titles", Severity::Error, "0 issues"),
        ("Duplicate content", Severity::Error, "0 pages"),
        ("Broken internal links", Severity::Error, "0 links"),
        ("Page could not be crawled", Severity::Error, "0 pages"),
        ("DNS resolution failure", Severity::Error, "0 pages"),
        ("Incorrect page URL format", Severity::Error, "0 pages"),
        ("Broken internal images", Severity::Error, "0 images"),
        ("Robots format errors", Severity::Error, "no_count"),
        ("Sitemap format errors", Severity::Error, "0 files"),
        ("Incorrect sitemap pages", Severity::Error, "0 pages"),
        ("WWW resolve issue", Severity::Error, "0 pages"),
        ("Missing viewport tag", Severity::Error, "0 pages"),
        ("Oversized HTML", Severity::Error, "0 pages"),
        ("AMP missing canonical", Severity::Error, "0 AMP pages"),
        ("Hreflang values invalid", Severity::Error, "0 issues"),
        (
            "Hreflang conflicts in source",
            Severity::Error,
            "0 conflicts",
        ),
        ("Incorrect hreflang links", Severity::Error, "0 issues"),
        ("Non-secure pages", Severity::Error, "0 pages"),
        ("Expiring/expired certificate", Severity::Error, "0 issues"),
        ("Old security protocol", Severity::Error, "0 issues"),
        ("Incorrect certificate name", Severity::Error, "0 issues"),
        ("Mixed content", Severity::Error, "0 issues"),
        (
            "No HTTP-homepage redirect/canonical to HTTPS",
            Severity::Error,
            "no_count",
        ),
        ("Redirect chains and loops", Severity::Error, "0"),
        ("Broken canonical", Severity::Error, "0 pages"),
        ("Multiple canonicals", Severity::Error, "0 pages"),
        ("Meta refresh", Severity::Error, "0 pages"),
        ("Broken internal JS/CSS", Severity::Error, "0 issues"),
        (
            "Insecure encryption algorithms",
            Severity::Error,
            "0 subdomains",
        ),
        ("Oversized sitemap", Severity::Error, "0 files"),
        ("Malformed link URLs", Severity::Error, "0 links"),
        ("Invalid structured data", Severity::Error, "0 items"),
        ("Missing viewport width", Severity::Error, "0 pages"),
        ("Slow load speed", Severity::Error, "0 pages"),
        ("Long title", Severity::Warning, "73 pages"),
        ("Broken external links", Severity::Warning, "0 links"),
        ("Broken external images", Severity::Warning, "0 images"),
        ("HTTPS page links to HTTP", Severity::Warning, "0 links"),
        ("Short title", Severity::Warning, "0 pages"),
        ("Missing H1", Severity::Warning, "0 pages"),
        ("Matching H1 and title", Severity::Warning, "0 pages"),
        ("Missing description", Severity::Warning, "0 pages"),
        ("Too many on-page links", Severity::Warning, "0 pages"),
        ("Temporary redirect", Severity::Warning, "0 URLs"),
        ("Missing image alt attribute", Severity::Warning, "0 images"),
        ("Low text/HTML ratio", Severity::Warning, "0 pages"),
        ("Too many URL parameters", Severity::Warning, "0 pages"),
        (
            "No hreflang and lang attributes",
            Severity::Warning,
            "0 pages",
        ),
        ("Missing character encoding", Severity::Warning, "0 pages"),
        ("Missing doctype", Severity::Warning, "0 pages"),
        ("Low word count", Severity::Warning, "0 pages"),
        ("Incompatible plugin content", Severity::Warning, "0 pages"),
        ("Frames", Severity::Warning, "0 pages"),
        ("URL underscores", Severity::Warning, "0 pages"),
        ("Internal outgoing nofollow", Severity::Warning, "0 links"),
        (
            "Sitemap not declared in robots",
            Severity::Warning,
            "no_count",
        ),
        ("Sitemap not found", Severity::Warning, "no_count"),
        ("Homepage does not use HTTPS", Severity::Warning, "no_count"),
        ("No SNI support", Severity::Warning, "0 subdomains"),
        ("HTTP URLs in HTTPS sitemap", Severity::Warning, "0 URLs"),
        ("Uncompressed pages", Severity::Warning, "0 pages"),
        (
            "Blocked internal resources in robots",
            Severity::Warning,
            "0 issues",
        ),
        ("Uncompressed JS/CSS", Severity::Warning, "0 issues"),
        ("Uncached JS/CSS", Severity::Warning, "0 issues"),
        ("JS/CSS total size too large", Severity::Warning, "0 pages"),
        ("Too many JS/CSS files", Severity::Warning, "0 pages"),
        ("Unminified JS/CSS", Severity::Warning, "0 issues"),
        ("Link URLs too long", Severity::Warning, "0 links"),
        (
            "Blocked external resources in robots",
            Severity::Notice,
            "433 issues",
        ),
        ("Depth greater than 3 clicks", Severity::Notice, "302 pages"),
        (
            "Resources formatted as page link",
            Severity::Notice,
            "9 resources",
        ),
        ("Content optimization required", Severity::Notice, "4 pages"),
        (
            "Page URL longer than 200 characters",
            Severity::Notice,
            "3 pages",
        ),
        ("Non-descriptive anchors", Severity::Notice, "3 links"),
        ("Multiple H1", Severity::Notice, "0 pages"),
        ("llms.txt missing", Severity::Notice, "no_count"),
        ("Pages blocked from crawling", Severity::Notice, "0 pages"),
        ("External outgoing nofollow", Severity::Notice, "0 links"),
        ("Robots not found", Severity::Notice, "no_count"),
        ("Hreflang language mismatch", Severity::Notice, "0 pages"),
        ("No HSTS", Severity::Notice, "0 subdomains"),
        ("Orphans in Google Analytics", Severity::Notice, "0 pages"),
        ("Orphans in sitemaps", Severity::Notice, "0 pages"),
        ("X-Robots-Tag noindex", Severity::Notice, "0 pages"),
        ("Broken external JS/CSS", Severity::Notice, "0 issues"),
        (
            "Only one incoming internal link",
            Severity::Notice,
            "0 pages",
        ),
        ("Permanent redirects", Severity::Notice, "0 URLs"),
        ("Missing anchor text", Severity::Notice, "0 links"),
        (
            "External page/resource HTTP 403",
            Severity::Notice,
            "0 links",
        ),
        ("llms.txt formatting", Severity::Notice, "no_count"),
        ("Too much content", Severity::Notice, "0 pages"),
        ("Outdated content", Severity::Notice, "0 pages"),
        ("Low semantic HTML usage", Severity::Notice, "0 pages"),
    ];

    #[test]
    fn catalogue_is_versioned() {
        assert_eq!(CATALOGUE_VERSION, 1);
        assert_eq!(FIXTURE_CONTRACT_VERSION, 1);
        assert_eq!(HISTORICAL_BASELINE_DATE, "2026-09-14");
    }

    #[test]
    fn every_inventory_check_is_mapped() {
        let labels: BTreeSet<_> = rules().iter().map(|r| r.captured_label).collect();
        for (label, severity, _) in INVENTORY {
            assert!(labels.contains(label), "missing inventory label: {label}");
            let rule = rules().iter().find(|r| r.captured_label == *label).unwrap();
            assert_eq!(rule.severity, *severity, "{label}");
        }
        let extra = labels
            .iter()
            .copied()
            .filter(|label| *label != "AMP checks hidden by upgrade message")
            .filter(|label| INVENTORY.iter().all(|(inv, _, _)| inv != label))
            .collect::<Vec<_>>();
        assert!(extra.is_empty(), "unlisted labels: {extra:?}");
        assert_eq!(INVENTORY.len(), 97);
    }

    #[test]
    fn rule_ids_are_unique_and_stable() {
        let mut ids = BTreeSet::new();
        for rule in rules() {
            assert!(rule.id.contains('.'), "{}", rule.id);
            assert!(
                rule.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.'),
                "{}",
                rule.id
            );
            assert!(ids.insert(rule.id), "duplicate id {}", rule.id);
            assert!(!rule.owner_issues.is_empty(), "{}", rule.id);
            assert!(
                rule.owner_issues
                    .iter()
                    .all(|issue| issue.starts_with("TC-")),
                "{}",
                rule.id
            );
            assert!(!rule.evidence.is_empty(), "{}", rule.id);
            assert!(!rule.applicability.is_empty(), "{}", rule.id);
        }
        assert_eq!(ids.len(), rules().len());
        assert!(rule_by_id("meta.duplicate_description").is_some());
        assert!(rule_by_id("amp.hidden_catalogue").is_some());
    }

    #[test]
    fn no_count_is_not_a_finding() {
        let no_count_labels = INVENTORY
            .iter()
            .filter(|(_, _, current)| *current == "no_count")
            .map(|(label, _, _)| *label)
            .collect::<BTreeSet<_>>();
        assert!(!no_count_labels.is_empty());
        for rule in rules() {
            if no_count_labels.contains(rule.captured_label) {
                assert_eq!(
                    rule.captured_current,
                    CapturedCurrent::NoCount,
                    "{}",
                    rule.id
                );
                assert!(!rule.captured_current.is_current_finding());
            }
        }
        assert!(
            current_findings()
                .all(|rule| !matches!(rule.captured_current, CapturedCurrent::NoCount))
        );
    }

    #[test]
    fn current_findings_match_the_14_september_2026_baseline() {
        let findings: Vec<_> = current_findings()
            .map(|rule| (rule.captured_label, rule.captured_current))
            .collect();
        assert_eq!(
            findings,
            vec![
                (
                    "Duplicate meta descriptions",
                    CapturedCurrent::Count {
                        value: 5,
                        unit: InventoryUnit::Page
                    }
                ),
                (
                    "Long title",
                    CapturedCurrent::Count {
                        value: 73,
                        unit: InventoryUnit::Page
                    }
                ),
                (
                    "Blocked external resources in robots",
                    CapturedCurrent::Count {
                        value: 433,
                        unit: InventoryUnit::Issue
                    }
                ),
                (
                    "Depth greater than 3 clicks",
                    CapturedCurrent::Count {
                        value: 302,
                        unit: InventoryUnit::Page
                    }
                ),
                (
                    "Resources formatted as page link",
                    CapturedCurrent::Count {
                        value: 9,
                        unit: InventoryUnit::Resource
                    }
                ),
                (
                    "Content optimization required",
                    CapturedCurrent::Count {
                        value: 4,
                        unit: InventoryUnit::Page
                    }
                ),
                (
                    "Page URL longer than 200 characters",
                    CapturedCurrent::Count {
                        value: 3,
                        unit: InventoryUnit::Page
                    }
                ),
                (
                    "Non-descriptive anchors",
                    CapturedCurrent::Count {
                        value: 3,
                        unit: InventoryUnit::Link
                    }
                ),
            ]
        );
    }

    #[test]
    fn new_issues_column_is_not_merged_into_current_counts() {
        for example in new_issues_examples() {
            let current = rules()
                .iter()
                .find(|rule| rule.captured_label == example.captured_label)
                .expect(example.captured_label);
            match current.captured_current {
                CapturedCurrent::Count { value, unit } => {
                    assert_eq!(value, example.current_count);
                    assert_eq!(unit, example.current_unit);
                    assert_ne!(value, example.new_issues_count);
                }
                CapturedCurrent::NoCount => panic!("{}", example.captured_label),
            }
            assert!(current_findings().all(|rule| match rule.captured_current {
                CapturedCurrent::Count { value, .. } => value != example.new_issues_count,
                CapturedCurrent::NoCount => true,
            }));
        }
        assert_eq!(new_issues_examples()[0].new_issues_count, 78);
        assert_eq!(new_issues_examples()[1].new_issues_count, 260);
    }

    #[test]
    fn every_rule_has_fixture_examples_and_a_version() {
        for rule in rules() {
            assert_eq!(
                rule.fixtures.version, FIXTURE_CONTRACT_VERSION,
                "{}",
                rule.id
            );
            assert!(
                rule.fixtures.positive.contains("audit.example"),
                "{}",
                rule.id
            );
            assert!(
                rule.fixtures.negative.contains("audit.example"),
                "{}",
                rule.id
            );
            assert!(
                rule.fixtures.incomplete.contains("audit.example"),
                "{}",
                rule.id
            );
            assert!(!rule.fixtures.positive.to_lowercase().contains("signature"));
            assert_eq!(
                expected_fixture_state(FixtureKind::Positive),
                RuleState::Findings
            );
            assert_eq!(
                expected_fixture_state(FixtureKind::Negative),
                RuleState::Passed
            );
            assert_eq!(
                expected_fixture_state(FixtureKind::Incomplete),
                RuleState::Incomplete
            );
        }
    }

    #[test]
    fn states_cover_the_contract() {
        assert_eq!(
            resolve_state(StateInput {
                supported: false,
                enabled: true,
                applicable: true,
                evidence_complete: true,
                has_findings: true,
            }),
            RuleState::Unsupported
        );
        assert_eq!(
            resolve_state(StateInput {
                supported: true,
                enabled: false,
                applicable: true,
                evidence_complete: true,
                has_findings: true,
            }),
            RuleState::Disabled
        );
        assert_eq!(
            resolve_state(StateInput {
                supported: true,
                enabled: true,
                applicable: false,
                evidence_complete: true,
                has_findings: true,
            }),
            RuleState::NotApplicable
        );
        assert_eq!(
            resolve_state(StateInput {
                supported: true,
                enabled: true,
                applicable: true,
                evidence_complete: false,
                has_findings: true,
            }),
            RuleState::Incomplete
        );
        assert_eq!(
            resolve_state(StateInput {
                supported: true,
                enabled: true,
                applicable: true,
                evidence_complete: true,
                has_findings: true,
            }),
            RuleState::Findings
        );
        assert_eq!(
            resolve_state(StateInput {
                supported: true,
                enabled: true,
                applicable: true,
                evidence_complete: true,
                has_findings: false,
            }),
            RuleState::Passed
        );
    }

    #[test]
    fn deferred_and_amp_entries_are_not_active_failures() {
        let amp_known = rule_by_id("amp.missing_canonical").unwrap();
        assert_eq!(amp_known.captured_label, "AMP missing canonical");
        assert_eq!(
            amp_known.captured_current,
            CapturedCurrent::Count {
                value: 0,
                unit: InventoryUnit::AmpPage
            }
        );
        assert!(!amp_known.captured_current.is_current_finding());
        assert_eq!(amp_known.stage, Stage::Amp);
        assert_eq!(amp_known.owner_issues, &["TC-479"]);

        let hidden = rule_by_id("amp.hidden_catalogue").unwrap();
        assert_eq!(hidden.status, RuleStatus::Deferred);
        assert_eq!(hidden.captured_current, CapturedCurrent::NoCount);
        assert!(!checker_supported(hidden));
        assert_eq!(
            resolve_state(StateInput {
                supported: checker_supported(hidden),
                enabled: true,
                applicable: true,
                evidence_complete: true,
                has_findings: false,
            }),
            RuleState::Unsupported
        );

        for id in [
            "content.optimization_required",
            "content.low_text_html_ratio",
            "content.low_word_count",
            "content.too_much",
            "content.outdated",
            "content.low_semantic_html",
            "ai.llms_txt_missing",
            "ai.llms_txt_formatting",
            "analytics.orphans_in_ga",
        ] {
            let rule = rule_by_id(id).unwrap_or_else(|| panic!("{id}"));
            assert_eq!(rule.status, RuleStatus::Deferred, "{id}");
            assert!(!checker_supported(rule), "{id}");
        }
    }

    #[test]
    fn ambiguous_labels_are_documented_without_semrush_formulas() {
        let resources = rule_by_id("links.resources_as_page_link").unwrap();
        assert!(resources.ambiguous);
        assert!(resources.threshold.research_required);
        assert!(resources.notes.to_lowercase().contains("not infer"));
        assert_eq!(resources.unit.coarse(), CoarseUnit::Resource);

        let optimization = rule_by_id("content.optimization_required").unwrap();
        assert!(optimization.ambiguous);
        assert!(optimization.threshold.research_required);
        assert!(optimization.notes.to_lowercase().contains("not infer"));

        let mismatch = rule_by_id("hreflang.language_mismatch").unwrap();
        assert!(mismatch.ambiguous);
        assert!(mismatch.threshold.research_required);

        let long_title = rule_by_id("meta.long_title").unwrap();
        assert!(long_title.threshold.research_required);
        assert_eq!(long_title.threshold.default, None);
        assert_eq!(
            rule_by_id("url.longer_than_200").unwrap().threshold.default,
            Some("200")
        );
        assert_eq!(
            rule_by_id("crawl.depth_gt_3").unwrap().threshold.default,
            Some("3")
        );
        assert!(
            !rule_by_id("url.longer_than_200")
                .unwrap()
                .threshold
                .research_required
        );
        assert!(
            !rule_by_id("crawl.depth_gt_3")
                .unwrap()
                .threshold
                .research_required
        );
    }

    #[test]
    fn captured_zero_is_not_a_current_finding() {
        let http_5xx = rule_by_id("crawl.http_5xx").unwrap();
        assert_eq!(
            http_5xx.captured_current,
            CapturedCurrent::Count {
                value: 0,
                unit: InventoryUnit::Page
            }
        );
        assert!(!http_5xx.captured_current.is_current_finding());
        assert!(current_findings().all(|rule| rule.id != "crawl.http_5xx"));
    }

    #[test]
    fn no_checkers_ship_in_this_slice() {
        assert!(rules().iter().all(|rule| !checker_supported(rule)));
    }
}
