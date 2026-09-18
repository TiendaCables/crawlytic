//! Cross-run finding history.
//!
//! Current totals count unsuppressed findings on the later run. Historical
//! deltas count new, persistent, resolved, suppressed, out-of-scope and
//! not-rechecked identities against a baseline run. Those deltas are not the
//! catalogue "new issues" column.

use crate::audit::{AuditReport, Finding, FindingId, Suppression};
use crate::catalogue::{RuleState, Severity};
use crate::crawl::{UrlRecord, UrlState};
use crate::profile::Profile;
use crate::scope::classify_absolute;
use std::collections::{BTreeMap, BTreeSet};

/// Current total = unsuppressed findings on the later run. Denominator is that
/// run's finding rows, not crawled-page count and not the Semrush snapshot.
pub const CURRENT_TOTAL_SEMANTICS: &str = "Current total counts unsuppressed findings on the later run. The denominator is that run's finding rows, not crawled pages and not the Semrush snapshot.";

/// Historical delta = new/persistent/resolved (plus suppressed, out-of-scope,
/// not-rechecked). Resolved uses rechecked baseline identities as denominator.
/// Not the catalogue historical "new issues" column.
pub const HISTORICAL_DELTA_SEMANTICS: &str = "Historical delta counts new, persistent and resolved finding identities versus the baseline run. Resolved uses rechecked baseline identities as the denominator. Out-of-scope, suppressed and not-rechecked are listed separately and never counted as resolved. This is not the catalogue historical \"new issues\" column.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingChange {
    New,
    Persistent,
    Resolved,
    Suppressed,
    OutOfScope,
    NotRechecked,
}

impl FindingChange {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Persistent => "persistent",
            Self::Resolved => "resolved",
            Self::Suppressed => "suppressed",
            Self::OutOfScope => "out_of_scope",
            Self::NotRechecked => "not_rechecked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityKind {
    CatalogueVersion,
    RuleConfigVersion,
    Exclusions,
    SkipParameters,
    IncompleteLaterRun,
    StartUrl,
}

impl CompatibilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CatalogueVersion => "catalogue_version",
            Self::RuleConfigVersion => "rule_config_version",
            Self::Exclusions => "exclusions",
            Self::SkipParameters => "skip_parameters",
            Self::IncompleteLaterRun => "incomplete_later_run",
            Self::StartUrl => "start_url",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityNote {
    pub kind: CompatibilityKind,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Resource,
    Template,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Template => "template",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RunView<'a> {
    pub run_id: i64,
    pub completed: bool,
    pub cancelled: bool,
    pub catalogue_version: u32,
    pub profile: &'a Profile,
    pub urls: &'a [UrlRecord],
    pub report: &'a AuditReport,
    pub suppressions: &'a [Suppression],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDelta {
    pub id: FindingId,
    pub change: FindingChange,
    pub severity: Severity,
    pub fact: String,
    pub group_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueGroup {
    pub key: String,
    pub rule_id: String,
    pub kind: GroupKind,
    pub count: u64,
    pub members: Vec<FindingId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountSummary {
    pub current_total: u64,
    pub current_denominator: u64,
    pub baseline_findings: u64,
    pub rechecked_baseline: u64,
    pub new: u64,
    pub persistent: u64,
    pub resolved: u64,
    pub suppressed: u64,
    pub out_of_scope: u64,
    pub not_rechecked: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunComparison {
    pub baseline_run_id: i64,
    pub later_run_id: i64,
    pub notes: Vec<CompatibilityNote>,
    pub deltas: Vec<FindingDelta>,
    pub groups: Vec<IssueGroup>,
    pub counts: CountSummary,
}

impl RunComparison {
    pub fn change_of(&self, rule_id: &str, entity_key: &str) -> Option<FindingChange> {
        self.deltas
            .iter()
            .find(|delta| delta.id.rule_id == rule_id && delta.id.entity_key == entity_key)
            .map(|delta| delta.change)
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "Run history {} → {}",
                self.baseline_run_id, self.later_run_id
            ),
            CURRENT_TOTAL_SEMANTICS.to_string(),
            HISTORICAL_DELTA_SEMANTICS.to_string(),
            format!(
                "Current {} / {} finding rows | baseline {} | rechecked {}",
                self.counts.current_total,
                self.counts.current_denominator,
                self.counts.baseline_findings,
                self.counts.rechecked_baseline
            ),
            format!(
                "new {} persistent {} resolved {} suppressed {} out_of_scope {} not_rechecked {}",
                self.counts.new,
                self.counts.persistent,
                self.counts.resolved,
                self.counts.suppressed,
                self.counts.out_of_scope,
                self.counts.not_rechecked
            ),
        ];
        if self.notes.is_empty() {
            lines.push("Compatibility: matching profile and rule versions.".into());
        } else {
            lines.push("Compatibility notes:".into());
            for note in &self.notes {
                lines.push(format!("  [{}] {}", note.kind.as_str(), note.summary));
            }
        }
        if !self.groups.is_empty() {
            lines.push("Widespread groups:".into());
            for group in &self.groups {
                lines.push(format!(
                    "  [{}] {} ×{} {}",
                    group.kind.as_str(),
                    group.rule_id,
                    group.count,
                    group.key
                ));
            }
        }
        lines
    }
}

pub fn compare_runs(baseline: &RunView<'_>, later: &RunView<'_>) -> RunComparison {
    let notes = compatibility_notes(baseline, later);
    let baseline_index = index_findings(&baseline.report.findings);
    let later_index = index_findings(&later.report.findings);
    let mut identities: BTreeSet<(String, String)> = BTreeSet::new();
    identities.extend(baseline_index.keys().cloned());
    identities.extend(later_index.keys().cloned());

    let mut deltas = Vec::new();
    for key in identities {
        let base = baseline_index.get(&key);
        let late = later_index.get(&key);
        let sample = late.or(base).expect("union identity has a finding");
        let change = classify(later, base, late, sample);
        deltas.push(FindingDelta {
            id: FindingId::new(key.0, key.1),
            change,
            severity: sample.severity,
            fact: sample.fact.clone(),
            group_key: None,
        });
    }
    deltas.sort_by(|a, b| a.id.cmp(&b.id));

    let groups = group_issues(&later.report.findings);
    for delta in &mut deltas {
        delta.group_key = groups.iter().find_map(|group| {
            group
                .members
                .iter()
                .any(|id| id == &delta.id)
                .then(|| group.key.clone())
        });
    }

    let counts = summarize(&deltas, later.report, baseline.report);
    RunComparison {
        baseline_run_id: baseline.run_id,
        later_run_id: later.run_id,
        notes,
        deltas,
        groups,
        counts,
    }
}

fn later_run_incomplete(later: &RunView<'_>) -> bool {
    !later.completed
        || later.cancelled
        || later
            .urls
            .iter()
            .any(|record| matches!(record.state, UrlState::Pending | UrlState::InFlight))
}

fn index_findings(findings: &[Finding]) -> BTreeMap<(String, String), &Finding> {
    let mut index = BTreeMap::new();
    for finding in findings {
        index.insert(
            (finding.id.rule_id.clone(), finding.id.entity_key.clone()),
            finding,
        );
    }
    index
}

fn classify(
    later: &RunView<'_>,
    baseline: Option<&&Finding>,
    later_finding: Option<&&Finding>,
    sample: &Finding,
) -> FindingChange {
    if let Some(late) = later_finding {
        if late.suppressed || suppressed(later, &late.id) {
            return FindingChange::Suppressed;
        }
        if baseline.is_some() {
            return FindingChange::Persistent;
        }
        return FindingChange::New;
    }
    if is_out_of_scope(later, sample) {
        return FindingChange::OutOfScope;
    }
    if !was_rechecked(later, sample) {
        return FindingChange::NotRechecked;
    }
    FindingChange::Resolved
}

fn suppressed(run: &RunView<'_>, id: &FindingId) -> bool {
    run.suppressions
        .iter()
        .any(|suppression| suppression.matches(&id.rule_id, &id.entity_key))
}

fn was_rechecked(later: &RunView<'_>, finding: &Finding) -> bool {
    if !entity_fetched(later, finding) {
        return false;
    }
    matches!(
        later.report.outcome(&finding.id.rule_id),
        Some(RuleState::Passed | RuleState::Findings | RuleState::NotApplicable)
    )
}

fn entity_fetched(run: &RunView<'_>, finding: &Finding) -> bool {
    identities_of(finding)
        .any(|key| record_for(run, key).is_some_and(|record| record.state == UrlState::Fetched))
}

fn is_out_of_scope(run: &RunView<'_>, finding: &Finding) -> bool {
    let mut seen_record = false;
    for key in identities_of(finding) {
        if let Some(record) = record_for(run, key) {
            seen_record = true;
            if matches!(record.state, UrlState::Excluded | UrlState::Blocked) {
                return true;
            }
        }
    }
    if seen_record {
        return false;
    }
    identities_of(finding).any(|key| {
        if key.starts_with("http://") || key.starts_with("https://") {
            classify_absolute(run.profile, key).skip_reason.is_some()
        } else {
            false
        }
    })
}

fn identities_of(finding: &Finding) -> impl Iterator<Item = &str> {
    std::iter::once(finding.id.entity_key.as_str()).chain(
        finding
            .evidence
            .iter()
            .map(|pointer| pointer.observation_identity.as_str()),
    )
}

fn record_for<'a>(run: &'a RunView<'a>, key: &str) -> Option<&'a UrlRecord> {
    run.urls.iter().find(|record| {
        record.original == key
            || record
                .identity
                .as_ref()
                .is_some_and(|identity| identity.as_str() == key)
    })
}

fn compatibility_notes(baseline: &RunView<'_>, later: &RunView<'_>) -> Vec<CompatibilityNote> {
    let mut notes = Vec::new();
    if baseline.catalogue_version != later.catalogue_version {
        notes.push(CompatibilityNote {
            kind: CompatibilityKind::CatalogueVersion,
            summary: format!(
                "Catalogue version {} → {}",
                baseline.catalogue_version, later.catalogue_version
            ),
        });
    }
    if baseline.report.config_version != later.report.config_version
        || baseline.report.config_fingerprint != later.report.config_fingerprint
    {
        notes.push(CompatibilityNote {
            kind: CompatibilityKind::RuleConfigVersion,
            summary: format!(
                "Rule config {} ({}) → {} ({})",
                baseline.report.config_version,
                baseline.report.config_fingerprint,
                later.report.config_version,
                later.report.config_fingerprint
            ),
        });
    }
    if baseline.profile.exclude_paths != later.profile.exclude_paths {
        notes.push(CompatibilityNote {
            kind: CompatibilityKind::Exclusions,
            summary: format!(
                "Exclusions changed ({} → {} prefixes)",
                baseline.profile.exclude_paths.len(),
                later.profile.exclude_paths.len()
            ),
        });
    }
    if baseline.profile.skip_parameters != later.profile.skip_parameters {
        notes.push(CompatibilityNote {
            kind: CompatibilityKind::SkipParameters,
            summary: format!(
                "Ignored parameters changed ({} → {})",
                baseline.profile.skip_parameters.len(),
                later.profile.skip_parameters.len()
            ),
        });
    }
    if baseline.profile.start_url != later.profile.start_url {
        notes.push(CompatibilityNote {
            kind: CompatibilityKind::StartUrl,
            summary: format!(
                "Start URL {} → {}",
                baseline.profile.start_url, later.profile.start_url
            ),
        });
    }
    if later_run_incomplete(later) {
        notes.push(CompatibilityNote {
            kind: CompatibilityKind::IncompleteLaterRun,
            summary:
                "Later run is incomplete; unvisited findings stay not_rechecked, never resolved."
                    .into(),
        });
    }
    notes
}

fn group_issues(findings: &[Finding]) -> Vec<IssueGroup> {
    let mut templates: BTreeMap<(String, String), Vec<FindingId>> = BTreeMap::new();
    let mut groups = Vec::new();
    for finding in findings {
        let distinct: BTreeSet<&str> = finding
            .evidence
            .iter()
            .map(|pointer| pointer.observation_identity.as_str())
            .collect();
        if distinct.len() >= 2 {
            groups.push(IssueGroup {
                key: finding.id.entity_key.clone(),
                rule_id: finding.id.rule_id.clone(),
                kind: GroupKind::Resource,
                count: distinct.len() as u64,
                members: vec![finding.id.clone()],
            });
        }
        if let Some(excerpt) = finding
            .evidence
            .first()
            .map(|pointer| pointer.excerpt.as_str())
        {
            templates
                .entry((finding.id.rule_id.clone(), excerpt.to_string()))
                .or_default()
                .push(finding.id.clone());
        }
    }
    for ((rule_id, excerpt), members) in templates {
        if members.len() < 2 {
            continue;
        }
        groups.push(IssueGroup {
            key: excerpt,
            rule_id,
            kind: GroupKind::Template,
            count: members.len() as u64,
            members,
        });
    }
    groups.sort_by(|a, b| a.rule_id.cmp(&b.rule_id).then(a.key.cmp(&b.key)));
    groups
}

fn summarize(deltas: &[FindingDelta], later: &AuditReport, baseline: &AuditReport) -> CountSummary {
    let mut counts = CountSummary {
        current_total: later
            .findings
            .iter()
            .filter(|finding| !finding.suppressed)
            .count() as u64,
        current_denominator: later.findings.len() as u64,
        baseline_findings: baseline.findings.len() as u64,
        rechecked_baseline: 0,
        new: 0,
        persistent: 0,
        resolved: 0,
        suppressed: 0,
        out_of_scope: 0,
        not_rechecked: 0,
    };
    let baseline_keys: BTreeSet<_> = baseline
        .findings
        .iter()
        .map(|finding| (finding.id.rule_id.as_str(), finding.id.entity_key.as_str()))
        .collect();
    for delta in deltas {
        match delta.change {
            FindingChange::New => counts.new += 1,
            FindingChange::Persistent => counts.persistent += 1,
            FindingChange::Resolved => counts.resolved += 1,
            FindingChange::Suppressed => counts.suppressed += 1,
            FindingChange::OutOfScope => counts.out_of_scope += 1,
            FindingChange::NotRechecked => counts.not_rechecked += 1,
        }
        if baseline_keys.contains(&(delta.id.rule_id.as_str(), delta.id.entity_key.as_str()))
            && matches!(
                delta.change,
                FindingChange::Persistent | FindingChange::Resolved | FindingChange::Suppressed
            )
        {
            counts.rechecked_baseline += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditConfig, EvidenceBundle, EvidencePointer, FindingId, RULE_CONFIG_VERSION, RuleOutcome,
        evaluate, evaluate_stored,
    };
    use crate::catalogue::{CATALOGUE_VERSION, new_issues_examples};
    use crate::extract::{ExtractInput, extract};
    use crate::rules::html_metadata_registry;
    use crate::store::Store;
    use url::Url;

    fn profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn url(original: &str, state: UrlState) -> UrlRecord {
        UrlRecord {
            original: original.into(),
            identity: Url::parse(original)
                .ok()
                .map(|parsed| crate::scope::FetchIdentity::from_url(&parsed)),
            state,
            reason: match state {
                UrlState::Fetched => "Fetched".into(),
                UrlState::Excluded => "Excluded path prefix".into(),
                UrlState::Pending => "cancelled".into(),
                other => format!("{other:?}"),
            },
            click_depth: Some(1),
            via_website: true,
            via_sitemap: false,
        }
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

    fn untitled(url: &str) -> crate::extract::ExtractedObservations {
        page(
            url,
            r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <meta name="description" content="Unique cables for this URL">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            </head><body><h1>Cables</h1><p>Hello</p></body></html>"#,
        )
    }

    fn titled(url: &str, title: &str) -> crate::extract::ExtractedObservations {
        page(
            url,
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8">
                <title>{title}</title>
                <meta name="description" content="Unique cables for this URL {title}">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                </head><body><h1>Cables</h1><p>Hello</p></body></html>"#
            ),
        )
    }

    fn evaluate_pages(run_id: i64, pages: &[crate::extract::ExtractedObservations]) -> AuditReport {
        let urls: Vec<UrlRecord> = pages
            .iter()
            .map(|obs| url(&obs.identity, UrlState::Fetched))
            .collect();
        evaluate(
            run_id,
            &EvidenceBundle {
                observations: pages,
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
        )
    }

    fn view<'a>(
        run_id: i64,
        completed: bool,
        profile: &'a Profile,
        urls: &'a [UrlRecord],
        report: &'a AuditReport,
        suppressions: &'a [Suppression],
    ) -> RunView<'a> {
        RunView {
            run_id,
            completed,
            cancelled: !completed,
            catalogue_version: CATALOGUE_VERSION,
            profile,
            urls,
            report,
            suppressions,
        }
    }

    fn synthetic(rule_id: &str, entity: &str, excerpt: &str, suppressed: bool) -> Finding {
        Finding {
            id: FindingId::new(rule_id, entity),
            catalogue_version: CATALOGUE_VERSION,
            config_version: RULE_CONFIG_VERSION,
            severity: Severity::Error,
            state: RuleState::Findings,
            fact: format!("{rule_id} on {entity}"),
            recommendation: "Fix the issue.".into(),
            evidence: vec![EvidencePointer {
                observation_identity: entity.into(),
                field: "title".into(),
                excerpt: excerpt.into(),
            }],
            suppressed,
        }
    }

    fn report_from(run_id: i64, findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            run_id,
            config_version: RULE_CONFIG_VERSION,
            config_fingerprint: "v1;e:;t:".into(),
            outcomes: vec![RuleOutcome {
                rule_id: "meta.missing_title".into(),
                state: RuleState::Findings,
            }],
            findings,
        }
    }

    #[test]
    fn incomplete_later_run_never_resolves_unvisited_findings() {
        let profile = profile();
        let a = "https://audit.example/a";
        let b = "https://audit.example/b";
        let baseline_urls = vec![url(a, UrlState::Fetched), url(b, UrlState::Fetched)];
        let baseline_report = report_from(
            1,
            vec![
                synthetic("meta.missing_title", a, "(empty)", false),
                synthetic("meta.missing_title", b, "(empty)", false),
            ],
        );
        let later_urls = vec![url(a, UrlState::Fetched), url(b, UrlState::Pending)];
        let later_report = report_from(
            2,
            vec![synthetic("meta.missing_title", a, "(empty)", false)],
        );
        let none = [];
        let comparison = compare_runs(
            &view(1, true, &profile, &baseline_urls, &baseline_report, &none),
            &view(2, false, &profile, &later_urls, &later_report, &none),
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", a),
            Some(FindingChange::Persistent)
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", b),
            Some(FindingChange::NotRechecked)
        );
        assert_ne!(
            comparison.change_of("meta.missing_title", b),
            Some(FindingChange::Resolved)
        );
        assert!(
            comparison
                .notes
                .iter()
                .any(|note| note.kind == CompatibilityKind::IncompleteLaterRun)
        );
        assert_eq!(comparison.counts.resolved, 0);
        assert_eq!(comparison.counts.not_rechecked, 1);
    }

    #[test]
    fn exclusion_and_rule_version_changes_are_surfaced() {
        let baseline_profile = profile();
        let mut later_profile = profile();
        later_profile.exclude_paths.push("/secret".into());
        let a = "https://www.tiendacables.com/secret/page";
        let baseline_urls = vec![url(a, UrlState::Fetched)];
        let later_urls = vec![url(a, UrlState::Excluded)];
        let baseline_report = report_from(
            1,
            vec![synthetic("meta.missing_title", a, "(empty)", false)],
        );
        let later_report = AuditReport {
            run_id: 2,
            config_version: RULE_CONFIG_VERSION + 1,
            config_fingerprint: "v2;e:;t:".into(),
            outcomes: vec![RuleOutcome {
                rule_id: "meta.missing_title".into(),
                state: RuleState::Passed,
            }],
            findings: Vec::new(),
        };
        let none = [];
        let mut later = view(2, true, &later_profile, &later_urls, &later_report, &none);
        later.catalogue_version = CATALOGUE_VERSION + 1;
        let comparison = compare_runs(
            &view(
                1,
                true,
                &baseline_profile,
                &baseline_urls,
                &baseline_report,
                &none,
            ),
            &later,
        );
        assert!(
            comparison
                .notes
                .iter()
                .any(|note| note.kind == CompatibilityKind::Exclusions),
            "{:?}",
            comparison.notes
        );
        assert!(
            comparison
                .notes
                .iter()
                .any(|note| note.kind == CompatibilityKind::RuleConfigVersion),
            "{:?}",
            comparison.notes
        );
        assert!(
            comparison
                .notes
                .iter()
                .any(|note| note.kind == CompatibilityKind::CatalogueVersion),
            "{:?}",
            comparison.notes
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", a),
            Some(FindingChange::OutOfScope)
        );
        assert_ne!(
            comparison.change_of("meta.missing_title", a),
            Some(FindingChange::Resolved)
        );
    }

    #[test]
    fn known_fixture_changes_classify_new_persistent_and_resolved() {
        let profile = profile();
        let a = "https://audit.example/a";
        let b = "https://audit.example/b";
        let c = "https://audit.example/c";
        let baseline_pages = [untitled(a), untitled(b)];
        let later_pages = [
            untitled(a),
            titled(b, "A reasonably long shop title B!!"),
            untitled(c),
        ];
        let baseline_report = evaluate_pages(1, &baseline_pages);
        let later_report = evaluate_pages(2, &later_pages);
        assert_eq!(
            baseline_report.outcome("meta.missing_title"),
            Some(RuleState::Findings)
        );
        let baseline_urls = vec![url(a, UrlState::Fetched), url(b, UrlState::Fetched)];
        let later_urls = vec![
            url(a, UrlState::Fetched),
            url(b, UrlState::Fetched),
            url(c, UrlState::Fetched),
        ];
        let none = [];
        let comparison = compare_runs(
            &view(1, true, &profile, &baseline_urls, &baseline_report, &none),
            &view(2, true, &profile, &later_urls, &later_report, &none),
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", a),
            Some(FindingChange::Persistent)
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", b),
            Some(FindingChange::Resolved)
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", c),
            Some(FindingChange::New)
        );
        let missing: Vec<_> = comparison
            .deltas
            .iter()
            .filter(|delta| delta.id.rule_id == "meta.missing_title")
            .collect();
        assert_eq!(
            missing
                .iter()
                .filter(|delta| delta.change == FindingChange::New)
                .count(),
            1
        );
        assert_eq!(
            missing
                .iter()
                .filter(|delta| delta.change == FindingChange::Persistent)
                .count(),
            1
        );
        assert_eq!(
            missing
                .iter()
                .filter(|delta| delta.change == FindingChange::Resolved)
                .count(),
            1
        );
    }

    #[test]
    fn current_totals_are_not_historical_new_issues() {
        let profile = profile();
        let a = "https://audit.example/a";
        let report = evaluate_pages(2, &[untitled(a)]);
        let urls = vec![url(a, UrlState::Fetched)];
        let empty = report_from(1, Vec::new());
        let none = [];
        let comparison = compare_runs(
            &view(1, true, &profile, &urls, &empty, &none),
            &view(2, true, &profile, &urls, &report, &none),
        );
        let missing = report.findings_for("meta.missing_title").count() as u64;
        assert_eq!(comparison.counts.current_total, missing);
        assert_eq!(
            comparison.counts.current_denominator,
            report.findings.len() as u64
        );
        let long_title = new_issues_examples()
            .iter()
            .find(|example| example.captured_label == "Long title")
            .unwrap();
        assert_eq!(long_title.new_issues_count, 78);
        assert_ne!(
            comparison.counts.current_total,
            u64::from(long_title.new_issues_count)
        );
        assert_ne!(
            comparison.counts.new,
            u64::from(long_title.new_issues_count)
        );
        let summary = comparison.summary_lines().join("\n");
        assert!(summary.contains("finding rows"), "{summary}");
        assert!(
            summary.contains("not the catalogue historical"),
            "{summary}"
        );
        assert!(!summary.contains("78 new"), "{summary}");
        assert!(CURRENT_TOTAL_SEMANTICS.contains("later run"));
        assert!(HISTORICAL_DELTA_SEMANTICS.contains("new issues"));
    }

    #[test]
    fn suppressed_and_template_groups_are_distinct() {
        let profile = profile();
        let a = "https://audit.example/a";
        let b = "https://audit.example/b";
        let shared = "template-empty-title";
        let baseline_report = report_from(
            1,
            vec![
                synthetic("meta.missing_title", a, shared, false),
                synthetic("meta.missing_title", b, shared, false),
            ],
        );
        let later_report = report_from(
            2,
            vec![
                synthetic("meta.missing_title", a, shared, true),
                synthetic("meta.missing_title", b, shared, false),
            ],
        );
        let urls = vec![url(a, UrlState::Fetched), url(b, UrlState::Fetched)];
        let suppressions = vec![Suppression {
            id: 1,
            run_id: 2,
            rule_id: Some("meta.missing_title".into()),
            entity_key: Some(a.into()),
            reason: "accepted empty title on homepage template".into(),
            created_at: 1,
            revoked_at: None,
        }];
        let none = [];
        let comparison = compare_runs(
            &view(1, true, &profile, &urls, &baseline_report, &none),
            &view(2, true, &profile, &urls, &later_report, &suppressions),
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", a),
            Some(FindingChange::Suppressed)
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", b),
            Some(FindingChange::Persistent)
        );
        assert!(
            comparison
                .groups
                .iter()
                .any(|group| group.kind == GroupKind::Template && group.count >= 2),
            "{:?}",
            comparison.groups
        );
        assert!(
            !format!("{comparison:?}")
                .to_ascii_lowercase()
                .contains("sig1=")
        );
    }

    #[test]
    fn live_store_round_trip_keeps_stable_identities() {
        let store = Store::open_in_memory().unwrap();
        let profile = profile();
        let a = "https://audit.example/a";
        let b = "https://audit.example/b";
        let first = store.begin_run(&profile).unwrap();
        store.put_observation(first, &untitled(a)).unwrap();
        store.put_observation(first, &untitled(b)).unwrap();
        store.upsert_url(first, &url(a, UrlState::Fetched)).unwrap();
        store.upsert_url(first, &url(b, UrlState::Fetched)).unwrap();
        store
            .finish_run(first, crate::store::RunStatus::Completed, true, false, None)
            .unwrap();
        evaluate_stored(
            &store,
            first,
            &AuditConfig::default(),
            &html_metadata_registry(),
        )
        .unwrap();

        let second = store.begin_run(&profile).unwrap();
        store.put_observation(second, &untitled(a)).unwrap();
        store
            .put_observation(second, &titled(b, "A reasonably long shop title B!!"))
            .unwrap();
        store
            .upsert_url(second, &url(a, UrlState::Fetched))
            .unwrap();
        store
            .upsert_url(second, &url(b, UrlState::Fetched))
            .unwrap();
        store
            .finish_run(
                second,
                crate::store::RunStatus::Completed,
                true,
                false,
                None,
            )
            .unwrap();
        evaluate_stored(
            &store,
            second,
            &AuditConfig::default(),
            &html_metadata_registry(),
        )
        .unwrap();

        let comparison = store.compare_runs(first, second).unwrap();
        assert_eq!(
            comparison.change_of("meta.missing_title", a),
            Some(FindingChange::Persistent)
        );
        assert_eq!(
            comparison.change_of("meta.missing_title", b),
            Some(FindingChange::Resolved)
        );
        let dump = format!("{comparison:?}");
        assert!(!dump.to_ascii_lowercase().contains("signature"));
        assert!(!dump.contains("CRAWL_SIGNATURE"));
    }
}
