//! Scoped-audit validation against the Semrush comparison baseline.
//!
//! Accounts for every discovered URL, classifies coverage differences from the
//! 3,725-page snapshot without forcing equal totals, and records remaining gaps
//! before any replacement claim. Historical aggregate counts are not a live
//! URL-set oracle.

use crate::audit::{AuditReport, RULE_CONFIG_VERSION, Registry};
use crate::catalogue::{
    CATALOGUE_VERSION, CapturedCurrent, HISTORICAL_BASELINE_DATE, Rule, RuleState, RuleStatus,
    Severity, current_findings, rules,
};
use crate::crawl::{UrlRecord, UrlState};
use crate::engine::CrawlCounters;
use crate::exchange::BaselineImport;
use crate::profile::Profile;
use crate::scope::classify_absolute;
use std::collections::{BTreeMap, BTreeSet};

/// Historical Semrush page observation. Not a URL set and not catalogue size.
pub const SNAPSHOT_PAGE_COUNT: u64 = 3_725;

/// Captured SiteAuditBot user-agent. Comparison metadata only; do not impersonate.
pub const COMPARISON_USER_AGENT: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25 (compatible; SiteAuditBot/0.97; +http://www.semrush.com/bot.html)";

/// Specified Error rules covered by crawl/URL-identity evidence without a checker.
const ENGINE_COVERED: &[(&str, &str)] = &[
    (
        "crawl.page_uncrawlable",
        "Failed URL records already classify transport/protocol failures; a dedicated checker is not registered.",
    ),
    (
        "crawl.dns_failure",
        "DNS failures are recorded as failed URL records with a reason; a dedicated checker is not registered.",
    ),
    (
        "url.incorrect_format",
        "Malformed and unsupported-scheme URLs stay in skip coverage without fetching.",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UrlDisposition {
    Fetched,
    Excluded,
    Blocked,
    Failed,
    Pending,
    InFlight,
    BaselineOnly,
}

impl UrlDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fetched => "fetched",
            Self::Excluded => "excluded",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::Pending => "pending",
            Self::InFlight => "in_flight",
            Self::BaselineOnly => "baseline_only",
        }
    }

    fn from_state(state: UrlState) -> Self {
        match state {
            UrlState::Fetched => Self::Fetched,
            UrlState::Excluded => Self::Excluded,
            UrlState::Blocked => Self::Blocked,
            UrlState::Failed => Self::Failed,
            UrlState::Pending => Self::Pending,
            UrlState::InFlight => Self::InFlight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlAccount {
    pub url: String,
    pub disposition: UrlDisposition,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixClass {
    Covered,
    EngineCovered,
    DeferredExplained,
    AggregateOnly,
    EntityOverlap,
    EntityMissExplained,
    EntityMissUnexplained,
    PassingRegressionPinned,
}

impl MatrixClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::EngineCovered => "engine_covered",
            Self::DeferredExplained => "deferred_explained",
            Self::AggregateOnly => "aggregate_only",
            Self::EntityOverlap => "entity_overlap",
            Self::EntityMissExplained => "entity_miss_explained",
            Self::EntityMissUnexplained => "entity_miss_unexplained",
            Self::PassingRegressionPinned => "passing_regression_pinned",
        }
    }

    pub fn unexplained_high_impact(self) -> bool {
        matches!(self, Self::EntityMissUnexplained)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixImpact {
    High,
    Other,
}

impl MatrixImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixRow {
    pub rule_id: String,
    pub label: String,
    pub severity: Severity,
    pub impact: MatrixImpact,
    pub class: MatrixClass,
    pub explanation: String,
    pub baseline_current: Option<u32>,
    pub crawlytic_count: u64,
    pub crawlytic_state: RuleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemainingGap {
    pub id: &'static str,
    pub summary: String,
    pub blocks_replacement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalPrerequisite {
    pub id: &'static str,
    pub summary: String,
    pub satisfied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementClaim {
    NotClaimed,
    Claimed,
}

impl ReplacementClaim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotClaimed => "not_claimed",
            Self::Claimed => "claimed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationInput<'a> {
    pub profile: &'a Profile,
    pub urls: &'a [UrlRecord],
    pub report: &'a AuditReport,
    pub registry: &'a Registry,
    pub baseline: Option<&'a BaselineImport>,
    pub crawl_observed_at: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub accounts: Vec<UrlAccount>,
    pub discovered: u64,
    pub snapshot_pages: u64,
    pub require_equal_totals: bool,
    pub coverage_explanation: String,
    pub matrix: Vec<MatrixRow>,
    pub unexplained_high_impact: Vec<MatrixRow>,
    pub remaining_gaps: Vec<RemainingGap>,
    pub prerequisites: Vec<OperationalPrerequisite>,
    pub replacement_claim: ReplacementClaim,
    pub user_agent_own: String,
    pub user_agent_comparison: String,
    pub crawl_date: Option<String>,
    pub baseline_date: String,
    pub catalogue_version: u32,
    pub config_version: u32,
    pub max_pages: usize,
}

impl ValidationReport {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "Scoped audit vs Semrush".into(),
            format!(
                "Discovered {} unique URL records vs {}-page snapshot from {}. Totals are not forced equal.",
                self.discovered, self.snapshot_pages, self.baseline_date
            ),
            format!(
                "Own-bot UA: {} | Comparison UA: {} (do not impersonate)",
                self.user_agent_own, self.user_agent_comparison
            ),
            format!(
                "Cap {} | catalogue v{} | rule config v{} | crawl date {}",
                self.max_pages,
                self.catalogue_version,
                self.config_version,
                self.crawl_date.as_deref().unwrap_or("unspecified")
            ),
            format!(
                "Unexplained high-impact misses: {} | Replacement: {}",
                self.unexplained_high_impact.len(),
                self.replacement_claim.as_str()
            ),
            self.coverage_explanation.clone(),
            "Gaps:".into(),
        ];
        for gap in &self.remaining_gaps {
            let flag = if gap.blocks_replacement {
                "blocks"
            } else {
                "note"
            };
            lines.push(format!("  [{flag}] {}: {}", gap.id, gap.summary));
        }
        lines.push("Prerequisites:".into());
        for item in &self.prerequisites {
            let mark = if item.satisfied { "x" } else { " " };
            lines.push(format!("  [{mark}] {}: {}", item.id, item.summary));
        }
        lines
    }
}

pub fn validate_scoped_audit(input: &ValidationInput<'_>) -> ValidationReport {
    let counters = CrawlCounters::from_records(input.urls);
    let discovered = counters.discovered();
    let mut accounts: Vec<UrlAccount> = input
        .urls
        .iter()
        .map(|record| UrlAccount {
            url: record_url(record),
            disposition: UrlDisposition::from_state(record.state),
            reason: record.reason.clone(),
        })
        .collect();

    let mut matrix = Vec::new();
    for rule in rules() {
        matrix.push(classify_rule(rule, input, &mut accounts));
    }

    let unexplained_high_impact: Vec<MatrixRow> = matrix
        .iter()
        .filter(|row| row.impact == MatrixImpact::High && row.class.unexplained_high_impact())
        .cloned()
        .collect();

    let remaining_gaps = remaining_gaps(input, &unexplained_high_impact);
    let prerequisites = prerequisites(input);
    let blocking_gaps = remaining_gaps.iter().any(|gap| gap.blocks_replacement);
    let blocking_prereqs = prerequisites.iter().any(|item| !item.satisfied);
    let replacement_claim =
        if unexplained_high_impact.is_empty() && !blocking_gaps && !blocking_prereqs {
            ReplacementClaim::Claimed
        } else {
            ReplacementClaim::NotClaimed
        };

    ValidationReport {
        accounts,
        discovered,
        snapshot_pages: SNAPSHOT_PAGE_COUNT,
        require_equal_totals: false,
        coverage_explanation: coverage_explanation(input, discovered),
        matrix,
        unexplained_high_impact,
        remaining_gaps,
        prerequisites,
        replacement_claim,
        user_agent_own: input.profile.user_agent.clone(),
        user_agent_comparison: COMPARISON_USER_AGENT.to_string(),
        crawl_date: input.crawl_observed_at.map(str::to_string),
        baseline_date: HISTORICAL_BASELINE_DATE.to_string(),
        catalogue_version: CATALOGUE_VERSION,
        config_version: RULE_CONFIG_VERSION,
        max_pages: input.profile.max_pages,
    }
}

fn coverage_explanation(input: &ValidationInput<'_>, discovered: u64) -> String {
    let date = input.crawl_observed_at.unwrap_or("unspecified");
    format!(
        "Discovered {discovered} unique URL records versus the {SNAPSHOT_PAGE_COUNT}-page snapshot from {HISTORICAL_BASELINE_DATE}. \
         Totals are not forced equal across dates. The snapshot is a historical count, not a URL set. \
         Configured page cap is {} (not catalogue size). Own-bot user-agent differs from SiteAuditBot; do not impersonate Semrush. \
         JavaScript rendering is {}. Crawl observed_at={date}. Excluded paths={}, ignored parameters={}. \
         Catalogue v{CATALOGUE_VERSION}, rule config v{RULE_CONFIG_VERSION}.",
        input.profile.max_pages,
        input.profile.javascript_rendering,
        input.profile.exclude_paths.len(),
        input.profile.skip_parameters.len(),
    )
}

fn classify_rule(
    rule: &Rule,
    input: &ValidationInput<'_>,
    accounts: &mut Vec<UrlAccount>,
) -> MatrixRow {
    let impact = if rule.severity == Severity::Error || rule.captured_current.is_current_finding() {
        MatrixImpact::High
    } else {
        MatrixImpact::Other
    };
    let crawlytic_count = input.report.findings_for(rule.id).count() as u64;
    let crawlytic_state = input
        .report
        .outcome(rule.id)
        .unwrap_or(RuleState::Unsupported);
    let baseline_current = match rule.captured_current {
        CapturedCurrent::Count { value, .. } => Some(value),
        CapturedCurrent::NoCount => None,
    };
    let entities = baseline_entities(input.baseline, rule);
    let (class, explanation) = if !entities.is_empty() {
        classify_entities(rule, input, &entities, accounts)
    } else if let Some((_, note)) = ENGINE_COVERED.iter().find(|(id, _)| *id == rule.id) {
        (MatrixClass::EngineCovered, (*note).to_string())
    } else if rule.status == RuleStatus::Deferred {
        (
            MatrixClass::DeferredExplained,
            format!(
                "Deferred under {}. Not an unexplained miss. No-count and heuristic labels are not live defects.",
                rule.owner_issues.join(", ")
            ),
        )
    } else if input.registry.contains(rule.id)
        && matches!(
            rule.captured_current,
            CapturedCurrent::Count { value: 0, .. } | CapturedCurrent::NoCount
        )
        && crawlytic_state == RuleState::Passed
    {
        (
            MatrixClass::PassingRegressionPinned,
            "Currently passing captured check stays detectable; negative evidence must remain Passed.".into(),
        )
    } else if input.registry.contains(rule.id) {
        (
            MatrixClass::Covered,
            "Checker is registered over stored observations. Historical aggregates are not a URL-set oracle.".into(),
        )
    } else {
        (
            MatrixClass::AggregateOnly,
            "No affected-URL rows were supplied. Aggregate historical counts are context, not an unexplained miss.".into(),
        )
    };
    MatrixRow {
        rule_id: rule.id.to_string(),
        label: rule.captured_label.to_string(),
        severity: rule.severity,
        impact,
        class,
        explanation,
        baseline_current,
        crawlytic_count,
        crawlytic_state,
    }
}

fn classify_entities(
    rule: &Rule,
    input: &ValidationInput<'_>,
    entities: &[String],
    accounts: &mut Vec<UrlAccount>,
) -> (MatrixClass, String) {
    let finding_keys = finding_keys(input.report, rule.id);
    let mut unexplained = Vec::new();
    let mut explained = Vec::new();
    let mut overlap = 0usize;
    for entity in entities {
        if finding_keys.contains(entity.as_str()) || finding_contains(&finding_keys, entity) {
            overlap += 1;
            continue;
        }
        if let Some(reason) = explain_entity_gap(entity, input) {
            explained.push(format!("{entity} ({reason})"));
            if !accounts.iter().any(|account| account.url == *entity) {
                accounts.push(UrlAccount {
                    url: entity.clone(),
                    disposition: UrlDisposition::BaselineOnly,
                    reason,
                });
            }
        } else {
            unexplained.push(entity.clone());
        }
    }
    if !unexplained.is_empty() {
        (
            MatrixClass::EntityMissUnexplained,
            format!(
                "High-impact baseline URLs not found and not classified: {}",
                unexplained.join(", ")
            ),
        )
    } else if !explained.is_empty() {
        (
            MatrixClass::EntityMissExplained,
            format!("Baseline-only URLs classified: {}", explained.join("; ")),
        )
    } else if overlap > 0 {
        (
            MatrixClass::EntityOverlap,
            format!("{overlap} affected URLs overlap the evaluated run."),
        )
    } else {
        (
            MatrixClass::AggregateOnly,
            "Affected-URL rows did not match this rule's findings.".into(),
        )
    }
}

fn explain_entity_gap(entity: &str, input: &ValidationInput<'_>) -> Option<String> {
    if let Some(record) = find_record(input.urls, entity) {
        return match record.state {
            UrlState::Fetched => None,
            other => Some(format!(
                "in-run {} ({})",
                UrlDisposition::from_state(other).as_str(),
                record.reason
            )),
        };
    }
    let classified = classify_absolute(input.profile, entity);
    if let Some(reason) = classified.skip_reason {
        return Some(reason.to_string());
    }
    if input
        .crawl_observed_at
        .is_some_and(|date| date != HISTORICAL_BASELINE_DATE)
    {
        return Some(format!(
            "crawl date {} differs from snapshot {HISTORICAL_BASELINE_DATE}; URL not in this run",
            input.crawl_observed_at.unwrap()
        ));
    }
    if input.profile.user_agent != COMPARISON_USER_AGENT {
        return Some(
            "own-bot user-agent differs from SiteAuditBot; URL not discovered in this run".into(),
        );
    }
    None
}

fn remaining_gaps(input: &ValidationInput<'_>, unexplained: &[MatrixRow]) -> Vec<RemainingGap> {
    let entity_rows = input
        .baseline
        .map(|baseline| baseline.entity_rows().count())
        .unwrap_or(0);
    vec![
        RemainingGap {
            id: "affected-url-export",
            summary: if entity_rows == 0 {
                format!(
                    "Semrush affected-URL rows are not supplied. Workbook adapter stays blocked until {} is available. Full URL-set comparison cannot run.",
                    crate::exchange::EXPECTED_SEMRUSH_EXPORT_NAME
                )
            } else {
                format!("{entity_rows} affected-entity rows imported via generic CSV; XLSX adapter still blocked.")
            },
            blocks_replacement: entity_rows == 0,
        },
        RemainingGap {
            id: "user-agent",
            summary: "Own-bot user-agent is not SiteAuditBot. Document the difference; do not impersonate Semrush.".into(),
            blocks_replacement: input.profile.user_agent != COMPARISON_USER_AGENT,
        },
        RemainingGap {
            id: "javascript-off",
            summary: "JavaScript rendering is off. JS-injected markup and mixed content stay incomplete.".into(),
            blocks_replacement: false,
        },
        RemainingGap {
            id: "deferred-catalogue",
            summary: "AMP remainder, specialist TLS, performance, analytics and explainable content/AI checks stay deferred.".into(),
            blocks_replacement: current_findings().any(|rule| rule.status == RuleStatus::Deferred),
        },
        RemainingGap {
            id: "heuristic-thresholds",
            summary: "Title length, click depth and similar caps are Crawlytic heuristics, not Semrush formulas.".into(),
            blocks_replacement: false,
        },
        RemainingGap {
            id: "snapshot-count",
            summary: format!(
                "{SNAPSHOT_PAGE_COUNT} is a historical page count from {HISTORICAL_BASELINE_DATE}, not an invariant URL set."
            ),
            blocks_replacement: false,
        },
        RemainingGap {
            id: "unexplained-high-impact",
            summary: if unexplained.is_empty() {
                "No unexplained high-impact misses in the agreed coverage matrix.".into()
            } else {
                format!(
                    "{} unexplained high-impact miss(es) remain.",
                    unexplained.len()
                )
            },
            blocks_replacement: !unexplained.is_empty(),
        },
    ]
}

fn prerequisites(input: &ValidationInput<'_>) -> Vec<OperationalPrerequisite> {
    let entity_rows = input
        .baseline
        .map(|baseline| baseline.entity_rows().count())
        .unwrap_or(0);
    vec![
        OperationalPrerequisite {
            id: "local-web-bot-auth",
            summary: "Shopify Web Bot Auth signatures must be supplied locally, never in fixtures or issue comments.".into(),
            satisfied: true,
        },
        OperationalPrerequisite {
            id: "matching-scope",
            summary: "Discovery, exclusions and ignored parameters match the captured TiendaCables lists.".into(),
            satisfied: input.profile.lists_complete && input.profile.exclude_paths_complete,
        },
        OperationalPrerequisite {
            id: "affected-url-rows",
            summary: "Import actual Semrush affected-URL rows before claiming URL-set parity.".into(),
            satisfied: entity_rows > 0,
        },
        OperationalPrerequisite {
            id: "document-ua-and-dates",
            summary: "Record crawl date, rule versions, exclusions, cap and user-agent differences on every comparison.".into(),
            satisfied: input.crawl_observed_at.is_some(),
        },
        OperationalPrerequisite {
            id: "inspect-representative-pages",
            summary: "Operator inspects representative mismatch pages with live evidence (not recorded in this repository).".into(),
            satisfied: false,
        },
    ]
}

fn baseline_entities(baseline: Option<&BaselineImport>, rule: &Rule) -> Vec<String> {
    let Some(baseline) = baseline else {
        return Vec::new();
    };
    baseline
        .entity_rows()
        .filter(|row| row_matches_rule(row.source_check.as_str(), rule))
        .filter_map(|row| row.entity_url.clone())
        .collect()
}

fn row_matches_rule(source_check: &str, rule: &Rule) -> bool {
    let needle = source_check.trim().to_ascii_lowercase();
    needle == rule.id || needle == rule.captured_label.to_ascii_lowercase()
}

fn finding_keys(report: &AuditReport, rule_id: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for finding in report.findings_for(rule_id) {
        keys.insert(finding.id.entity_key.clone());
        for pointer in &finding.evidence {
            keys.insert(pointer.observation_identity.clone());
        }
    }
    keys
}

fn finding_contains(keys: &BTreeSet<String>, entity: &str) -> bool {
    keys.iter().any(|key| key == entity || key.contains(entity))
}

fn find_record<'a>(urls: &'a [UrlRecord], entity: &str) -> Option<&'a UrlRecord> {
    urls.iter().find(|record| {
        record.original == entity
            || record
                .identity
                .as_ref()
                .is_some_and(|identity| identity.as_str() == entity)
    })
}

fn record_url(record: &UrlRecord) -> String {
    record
        .identity
        .as_ref()
        .map(|identity| identity.as_str().to_string())
        .unwrap_or_else(|| record.original.clone())
}

pub fn high_impact_rules() -> impl Iterator<Item = &'static Rule> {
    rules().iter().filter(|rule| {
        rule.severity == Severity::Error || rule.captured_current.is_current_finding()
    })
}

pub fn passing_regression_rule_ids(registry: &Registry) -> Vec<&'static str> {
    rules()
        .iter()
        .filter(|rule| {
            registry.contains(rule.id)
                && matches!(
                    rule.captured_current,
                    CapturedCurrent::Count { value: 0, .. }
                )
        })
        .map(|rule| rule.id)
        .collect()
}

pub fn counts_by_disposition(accounts: &[UrlAccount]) -> BTreeMap<UrlDisposition, u64> {
    let mut counts = BTreeMap::new();
    for account in accounts {
        *counts.entry(account.disposition).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditConfig, EvidenceBundle, evaluate, evaluate_stored};
    use crate::extract::{ExtractInput, extract};
    use crate::rules::{audit_registry, html_metadata_registry};
    use crate::store::Store;
    use crate::{FieldMap, import_baseline};
    use url::Url;

    fn profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn url(original: &str, state: UrlState, reason: &str) -> UrlRecord {
        UrlRecord {
            original: original.into(),
            identity: Url::parse(original)
                .ok()
                .map(|parsed| crate::scope::FetchIdentity::from_url(&parsed)),
            state,
            reason: reason.into(),
            click_depth: Some(1),
            via_website: true,
            via_sitemap: false,
        }
    }

    fn empty_report() -> AuditReport {
        evaluate(
            1,
            &EvidenceBundle {
                observations: &[],
                urls: &[],
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: &[],
                tls_inspections: &[],
                host_probes: &[],
                start_url: None,
            },
            &AuditConfig::default(),
            &audit_registry(),
            &[],
        )
    }

    fn page(url: &str, body: &str) -> crate::extract::ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status: 200,
            content_type: "text/html",
            headers: &[],
            body: body.as_bytes(),
            truncated: false,
            duration_ms: Some(1),
        })
    }

    fn ok_html(url: &str, description: &str, title: &str) -> crate::extract::ExtractedObservations {
        page(
            url,
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8">
                <title>{title}</title>
                <meta name="description" content="{description}">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                </head><body><h1>Cables</h1><p>Hello</p></body></html>"#
            ),
        )
    }

    fn mapping() -> FieldMap {
        FieldMap {
            source_check: "Check".into(),
            entity_url: "URL".into(),
            referrer_url: None,
            unit: None,
            severity: None,
            observed_at: None,
            source_report: None,
            current_count: Some("Current".into()),
            historical_delta: Some("New issues".into()),
            row_kind: Some("Row kind".into()),
        }
    }

    fn input<'a>(
        profile: &'a Profile,
        urls: &'a [UrlRecord],
        report: &'a AuditReport,
        registry: &'a Registry,
        baseline: Option<&'a BaselineImport>,
        crawl_observed_at: Option<&'a str>,
    ) -> ValidationInput<'a> {
        ValidationInput {
            profile,
            urls,
            report,
            registry,
            baseline,
            crawl_observed_at,
        }
    }

    #[test]
    fn every_discovered_url_is_accounted_without_forcing_snapshot_totals() {
        let profile = profile();
        let urls = vec![
            url("https://www.tiendacables.com/", UrlState::Fetched, "ok"),
            url(
                "https://www.tiendacables.com/cart",
                UrlState::Excluded,
                "Excluded path prefix",
            ),
            url(
                "https://www.tiendacables.com/pending",
                UrlState::Pending,
                "cancelled",
            ),
        ];
        let report = empty_report();
        let registry = audit_registry();
        let validation = validate_scoped_audit(&input(
            &profile,
            &urls,
            &report,
            &registry,
            None,
            Some("2026-09-18"),
        ));
        let run_accounts: Vec<_> = validation
            .accounts
            .iter()
            .filter(|account| account.disposition != UrlDisposition::BaselineOnly)
            .collect();
        assert_eq!(run_accounts.len(), urls.len());
        assert_eq!(validation.discovered, 3);
        assert_eq!(validation.snapshot_pages, SNAPSHOT_PAGE_COUNT);
        assert_ne!(validation.discovered, validation.snapshot_pages);
        assert!(!validation.require_equal_totals);
        assert!(
            validation.coverage_explanation.contains("not forced equal"),
            "{}",
            validation.coverage_explanation
        );
        assert!(
            validation
                .coverage_explanation
                .contains("historical count, not a URL set"),
            "{}",
            validation.coverage_explanation
        );
        assert!(validation.coverage_explanation.contains("2026-09-18"));
        assert!(validation.coverage_explanation.contains("20000"));
        let dump = format!("{validation:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("sig1="), "{dump}");
        assert!(!lower.contains("signature-input"), "{dump}");
        assert!(!dump.contains("CRAWL_SIGNATURE"));
    }

    #[test]
    fn agreed_matrix_has_no_unexplained_high_impact_without_url_rows() {
        let profile = profile();
        let urls = vec![url(
            "https://www.tiendacables.com/",
            UrlState::Fetched,
            "ok",
        )];
        let report = empty_report();
        let registry = audit_registry();
        let validation = validate_scoped_audit(&input(
            &profile,
            &urls,
            &report,
            &registry,
            None,
            Some("2026-09-18"),
        ));
        assert!(
            validation.unexplained_high_impact.is_empty(),
            "{:?}",
            validation.unexplained_high_impact
        );
        for row in validation
            .matrix
            .iter()
            .filter(|row| row.impact == MatrixImpact::High)
        {
            assert_ne!(
                row.class,
                MatrixClass::EntityMissUnexplained,
                "{}",
                row.rule_id
            );
        }
        let engine: Vec<_> = validation
            .matrix
            .iter()
            .filter(|row| row.class == MatrixClass::EngineCovered)
            .map(|row| row.rule_id.as_str())
            .collect();
        assert!(engine.contains(&"crawl.page_uncrawlable"));
        assert!(engine.contains(&"crawl.dns_failure"));
        assert!(engine.contains(&"url.incorrect_format"));
        let deferred = validation
            .matrix
            .iter()
            .find(|row| row.rule_id == "content.optimization_required")
            .unwrap();
        assert_eq!(deferred.class, MatrixClass::DeferredExplained);
        assert_eq!(deferred.impact, MatrixImpact::High);
        let covered = validation
            .matrix
            .iter()
            .find(|row| row.rule_id == "meta.duplicate_description")
            .unwrap();
        assert_eq!(covered.class, MatrixClass::Covered);
        assert_ne!(covered.baseline_current, Some(78));
        assert_eq!(validation.replacement_claim, ReplacementClaim::NotClaimed);
        assert!(
            validation
                .remaining_gaps
                .iter()
                .any(|gap| gap.id == "affected-url-export" && gap.blocks_replacement)
        );
        assert!(
            validation
                .prerequisites
                .iter()
                .any(|item| item.id == "inspect-representative-pages" && !item.satisfied)
        );
        assert!(
            validation
                .prerequisites
                .iter()
                .any(|item| item.id == "local-web-bot-auth" && item.satisfied)
        );
    }

    #[test]
    fn excluded_baseline_url_is_explained_and_fetched_miss_is_not() {
        let profile = profile();
        let urls = vec![url(
            "https://www.tiendacables.com/",
            UrlState::Fetched,
            "ok",
        )];
        let report = empty_report();
        let registry = audit_registry();
        let csv = "Check,URL,Current,New issues,Row kind\n\
Duplicate meta descriptions,https://www.tiendacables.com/cart,5,0,entity\n\
Duplicate meta descriptions,https://www.tiendacables.com/unseen-product,5,0,entity\n";
        let baseline = import_baseline(csv.as_bytes(), "baseline.csv", &mapping()).unwrap();
        let validation = validate_scoped_audit(&input(
            &profile,
            &urls,
            &report,
            &registry,
            Some(&baseline),
            Some("2026-09-18"),
        ));
        let row = validation
            .matrix
            .iter()
            .find(|row| row.rule_id == "meta.duplicate_description")
            .unwrap();
        assert_ne!(
            row.class,
            MatrixClass::EntityMissUnexplained,
            "{}",
            row.explanation
        );
        assert!(
            row.explanation.contains("cart") || row.explanation.contains("Excluded"),
            "{}",
            row.explanation
        );
        assert!(validation.unexplained_high_impact.is_empty(), "{row:?}");
        assert!(
            validation
                .accounts
                .iter()
                .any(|account| account.disposition == UrlDisposition::BaselineOnly)
        );
    }

    #[test]
    fn unexplained_high_impact_fires_when_fetched_url_is_missing() {
        let profile = profile();
        let target = "https://www.tiendacables.com/cables";
        let urls = vec![url(target, UrlState::Fetched, "ok")];
        let report = AuditReport {
            run_id: 1,
            config_version: RULE_CONFIG_VERSION,
            config_fingerprint: "v1;e:;t:".into(),
            outcomes: vec![crate::RuleOutcome {
                rule_id: "meta.duplicate_description".into(),
                state: RuleState::Passed,
            }],
            findings: Vec::new(),
        };
        let registry = audit_registry();
        let csv = format!(
            "Check,URL,Current,New issues,Row kind\n\
Duplicate meta descriptions,{target},5,0,entity\n"
        );
        let baseline = import_baseline(csv.as_bytes(), "baseline.csv", &mapping()).unwrap();
        let validation = validate_scoped_audit(&input(
            &profile,
            &urls,
            &report,
            &registry,
            Some(&baseline),
            Some(HISTORICAL_BASELINE_DATE),
        ));
        let row = validation
            .matrix
            .iter()
            .find(|row| row.rule_id == "meta.duplicate_description")
            .unwrap();
        assert_eq!(row.class, MatrixClass::EntityMissUnexplained);
        assert_eq!(validation.unexplained_high_impact.len(), 1);
        assert_eq!(validation.replacement_claim, ReplacementClaim::NotClaimed);
    }

    #[test]
    fn historical_aggregates_are_not_an_oracle() {
        let profile = profile();
        let urls = vec![url("https://audit.example/a", UrlState::Fetched, "ok")];
        let obs = [
            ok_html(
                "https://audit.example/a",
                "Shared historical",
                "A reasonably long shop title A!!",
            ),
            ok_html(
                "https://audit.example/b",
                "Shared historical",
                "A reasonably long shop title B!!",
            ),
        ];
        let report = evaluate(
            2,
            &EvidenceBundle {
                observations: &obs,
                urls: &urls,
                sitemap: None,
                sitemap_done: true,
                robots: None,
                resource_fetches: &[],
                tls_inspections: &[],
                host_probes: &[],
                start_url: None,
            },
            &AuditConfig::default(),
            &html_metadata_registry(),
            &[],
        );
        let registry = html_metadata_registry();
        let csv = "Check,URL,Current,New issues,Row kind\n\
Duplicate meta descriptions,,,5,78,aggregate\n\
Long title,,,73,78,aggregate\n";
        let baseline = import_baseline(csv.as_bytes(), "baseline.csv", &mapping()).unwrap();
        let validation = validate_scoped_audit(&input(
            &profile,
            &urls,
            &report,
            &registry,
            Some(&baseline),
            Some("2026-09-18"),
        ));
        let dup = validation
            .matrix
            .iter()
            .find(|row| row.rule_id == "meta.duplicate_description")
            .unwrap();
        assert_eq!(dup.baseline_current, Some(5));
        assert_eq!(dup.crawlytic_count, 2);
        assert_ne!(dup.crawlytic_count, 5);
        assert_ne!(dup.class, MatrixClass::EntityMissUnexplained);
        assert!(validation.unexplained_high_impact.is_empty());
        assert!(!format!("{validation:?}").contains("78 new"));
    }

    #[test]
    fn passing_metadata_checks_stay_passed_on_healthy_pages() {
        let obs = [ok_html(
            "https://audit.example/ok",
            "Unique cables for this URL",
            "A reasonably long shop title here!!",
        )];
        let report = evaluate(
            0,
            &EvidenceBundle {
                observations: &obs,
                urls: &[],
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: &[],
                tls_inspections: &[],
                host_probes: &[],
                start_url: None,
            },
            &AuditConfig::default(),
            &html_metadata_registry(),
            &[],
        );
        for id in [
            "meta.missing_title",
            "meta.duplicate_title",
            "meta.missing_viewport",
            "meta.oversized_html",
            "meta.missing_viewport_width",
            "meta.missing_description",
            "heading.missing_h1",
            "heading.multiple_h1",
        ] {
            assert_eq!(report.outcome(id), Some(RuleState::Passed), "{id}");
            assert!(report.findings_for(id).next().is_none());
        }
        let registry = html_metadata_registry();
        assert!(passing_regression_rule_ids(&registry).contains(&"meta.missing_title"));
    }

    #[test]
    fn known_duplicate_description_fix_reruns_without_recrawl() {
        let store = Store::open_in_memory().unwrap();
        let profile = profile();
        let run_id = store.begin_run(&profile).unwrap();
        let shared = "Shared cables description";
        store
            .put_observation(
                run_id,
                &ok_html(
                    "https://audit.example/a",
                    shared,
                    "A reasonably long shop title A!!",
                ),
            )
            .unwrap();
        store
            .put_observation(
                run_id,
                &ok_html(
                    "https://audit.example/b",
                    shared,
                    "A reasonably long shop title B!!",
                ),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &html_metadata_registry(),
        )
        .unwrap();
        assert_eq!(
            first.outcome("meta.duplicate_description"),
            Some(RuleState::Findings)
        );
        assert_eq!(first.findings_for("meta.duplicate_description").count(), 2);
        store
            .put_observation(
                run_id,
                &ok_html(
                    "https://audit.example/b",
                    "Unique cables description B",
                    "A reasonably long shop title B!!",
                ),
            )
            .unwrap();
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &html_metadata_registry(),
        )
        .unwrap();
        assert_eq!(
            second.outcome("meta.duplicate_description"),
            Some(RuleState::Passed)
        );
        assert_eq!(second.findings_for("meta.duplicate_description").count(), 0);
        let dump = format!("{first:?}{second:?}");
        assert!(!dump.to_ascii_lowercase().contains("signature"));
    }

    #[test]
    fn summary_does_not_claim_replacement_or_embed_secrets() {
        let profile = profile();
        let urls = vec![url(
            "https://www.tiendacables.com/",
            UrlState::Fetched,
            "ok",
        )];
        let report = empty_report();
        let registry = audit_registry();
        let validation = validate_scoped_audit(&input(
            &profile,
            &urls,
            &report,
            &registry,
            None,
            Some("2026-09-18"),
        ));
        let summary = validation.summary_lines().join("\n");
        assert!(summary.contains("not_claimed"), "{summary}");
        assert!(summary.contains("3725"), "{summary}");
        let lower = summary.to_ascii_lowercase();
        assert!(!lower.contains("sig1="), "{summary}");
        assert!(!lower.contains("signature-input"), "{summary}");
        assert!(!summary.contains("CRAWL_SIGNATURE"));
    }
}
