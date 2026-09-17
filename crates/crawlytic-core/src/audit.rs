//! Evidence-based rule execution and finding lifecycle.
//!
//! Checkers evaluate stored observations with no network access. Findings keep
//! fact, recommendation and severity apart. Suppressions hide a finding without
//! deleting evidence.

use crate::catalogue::{
    CATALOGUE_VERSION, RuleState, Severity, StateInput, resolve_state, rule_by_id, rules,
};
use crate::crawl::{SitemapInventory, UrlRecord};
use crate::extract::{ExtractedObservations, ResourceFetch};
use crate::https::{HostProbe, TlsInspection};
use crate::robots::RobotsRunMetadata;
use crate::store::{Store, StoreError};
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

pub const RULE_CONFIG_VERSION: u32 = 1;
const EXCERPT_MAX_CHARS: usize = 240;

/// Versioned checker configuration. Thresholds are keyed independently of
/// severity so a recommendation can quote the value that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub version: u32,
    pub enabled: BTreeMap<String, bool>,
    pub thresholds: BTreeMap<String, String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            version: RULE_CONFIG_VERSION,
            enabled: BTreeMap::new(),
            thresholds: BTreeMap::new(),
        }
    }
}

impl AuditConfig {
    pub fn is_enabled(&self, rule_id: &str) -> bool {
        self.enabled.get(rule_id).copied().unwrap_or(true)
    }

    pub fn threshold(&self, key: &str) -> Option<&str> {
        self.thresholds.get(key).map(String::as_str)
    }

    pub fn fingerprint(&self) -> String {
        let mut out = format!("v{}", self.version);
        out.push_str(";e:");
        for (i, (key, enabled)) in self.enabled.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push('=');
            out.push(if *enabled { '1' } else { '0' });
        }
        out.push_str(";t:");
        for (i, (key, value)) in self.thresholds.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push('=');
            out.push_str(value);
        }
        out
    }
}

/// Stored observations a checker may read. Never a live fetch.
#[derive(Debug, Clone, Copy)]
pub struct EvidenceBundle<'a> {
    pub observations: &'a [ExtractedObservations],
    pub urls: &'a [UrlRecord],
    pub sitemap: Option<&'a SitemapInventory>,
    pub sitemap_done: bool,
    pub robots: Option<&'a RobotsRunMetadata>,
    pub resource_fetches: &'a [ResourceFetch],
    pub tls_inspections: &'a [TlsInspection],
    pub host_probes: &'a [HostProbe],
    pub start_url: Option<&'a url::Url>,
}

/// Stable identity: rule id plus affected entity. Config changes update the
/// row; they do not mint a second identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingId {
    pub rule_id: String,
    pub entity_key: String,
}

impl FindingId {
    pub fn new(rule_id: impl Into<String>, entity_key: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            entity_key: entity_key.into(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}::{}", self.rule_id, self.entity_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePointer {
    pub observation_identity: String,
    pub field: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDraft {
    pub entity_key: String,
    pub fact: String,
    pub recommendation: String,
    pub evidence: Vec<EvidencePointer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: FindingId,
    pub catalogue_version: u32,
    pub config_version: u32,
    pub severity: Severity,
    pub state: RuleState,
    pub fact: String,
    pub recommendation: String,
    pub evidence: Vec<EvidencePointer>,
    pub suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckerOutput {
    pub applicable: bool,
    pub evidence_complete: bool,
    pub findings: Vec<FindingDraft>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOutcome {
    pub rule_id: String,
    pub state: RuleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub run_id: i64,
    pub config_version: u32,
    pub config_fingerprint: String,
    pub outcomes: Vec<RuleOutcome>,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn outcome(&self, rule_id: &str) -> Option<RuleState> {
        self.outcomes
            .iter()
            .find(|outcome| outcome.rule_id == rule_id)
            .map(|outcome| outcome.state)
    }

    pub fn findings_for<'a>(&'a self, rule_id: &'a str) -> impl Iterator<Item = &'a Finding> {
        self.findings
            .iter()
            .filter(move |finding| finding.id.rule_id == rule_id)
    }

    /// Observation identities attached to a rule's findings. Duplicate-group
    /// findings are compared by this URL set, not by the historical totals.
    pub fn affected_identities(&self, rule_id: &str) -> Vec<&str> {
        let mut seen = std::collections::BTreeSet::new();
        for finding in &self.findings {
            if finding.id.rule_id != rule_id {
                continue;
            }
            for pointer in &finding.evidence {
                seen.insert(pointer.observation_identity.as_str());
            }
        }
        seen.into_iter().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    pub id: i64,
    pub run_id: i64,
    pub rule_id: Option<String>,
    pub entity_key: Option<String>,
    pub reason: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

impl Suppression {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    pub fn matches(&self, rule_id: &str, entity_key: &str) -> bool {
        if !self.is_active() {
            return false;
        }
        match (&self.rule_id, &self.entity_key) {
            (None, None) => false,
            (Some(rule), None) => rule == rule_id,
            (None, Some(entity)) => entity == entity_key,
            (Some(rule), Some(entity)) => rule == rule_id && entity == entity_key,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionAction {
    Apply,
    Revoke,
}

impl SuppressionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Revoke => "revoke",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "apply" => Some(Self::Apply),
            "revoke" => Some(Self::Revoke),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionEvent {
    pub id: i64,
    pub suppression_id: i64,
    pub action: SuppressionAction,
    pub reason: String,
    pub at: i64,
}

pub trait Checker: Send + Sync + 'static {
    fn rule_id(&self) -> &'static str;

    fn depends_on(&self) -> &'static [&'static str] {
        &[]
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput;
}

#[derive(Clone, Default)]
pub struct Registry {
    checkers: BTreeMap<&'static str, Arc<dyn Checker>>,
}

impl Debug for Registry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("rules", &self.checkers.keys().copied().collect::<Vec<_>>())
            .finish()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, checker: impl Checker) {
        self.checkers.insert(checker.rule_id(), Arc::new(checker));
    }

    pub fn get(&self, rule_id: &str) -> Option<&dyn Checker> {
        self.checkers.get(rule_id).map(Arc::as_ref)
    }

    pub fn contains(&self, rule_id: &str) -> bool {
        self.checkers.contains_key(rule_id)
    }
}

/// Evaluate checkers against an in-memory evidence bundle. No I/O.
pub fn evaluate(
    run_id: i64,
    evidence: &EvidenceBundle<'_>,
    config: &AuditConfig,
    registry: &Registry,
    suppressions: &[Suppression],
) -> AuditReport {
    let order = checker_order(registry);
    let mut states = BTreeMap::new();
    let mut findings = Vec::new();

    for id in &order {
        let checker = registry.get(id).expect("topo order is registered");
        if let Some(blocked) = blocked_by_prereq(checker.depends_on(), &states) {
            states.insert((*id).to_string(), blocked);
            continue;
        }
        if !config.is_enabled(id) {
            states.insert((*id).to_string(), RuleState::Disabled);
            continue;
        }
        let output = checker.evaluate(evidence, config);
        let drafts: Vec<_> = output.findings.into_iter().filter(draft_is_valid).collect();
        let state = resolve_state(StateInput {
            supported: true,
            enabled: true,
            applicable: output.applicable,
            evidence_complete: output.evidence_complete,
            has_findings: !drafts.is_empty(),
        });
        if state == RuleState::Findings {
            for draft in drafts {
                findings.push(finding_from_draft(id, draft, config));
            }
        }
        states.insert((*id).to_string(), state);
    }

    for id in registry.checkers.keys() {
        states
            .entry((*id).to_string())
            .or_insert(RuleState::Unsupported);
    }
    for rule in rules() {
        states.entry(rule.id.to_string()).or_insert_with(|| {
            resolve_state(StateInput {
                supported: false,
                enabled: config.is_enabled(rule.id),
                applicable: true,
                evidence_complete: true,
                has_findings: false,
            })
        });
    }

    for finding in &mut findings {
        finding.suppressed = suppressions
            .iter()
            .any(|suppression| suppression.matches(&finding.id.rule_id, &finding.id.entity_key));
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings.dedup_by(|left, right| left.id == right.id);

    let outcomes = states
        .into_iter()
        .map(|(rule_id, state)| RuleOutcome { rule_id, state })
        .collect();

    AuditReport {
        run_id,
        config_version: config.version,
        config_fingerprint: config.fingerprint(),
        outcomes,
        findings,
    }
}

/// Load stored observations, evaluate, persist outcomes and return the report.
pub fn evaluate_stored(
    store: &Store,
    run_id: i64,
    config: &AuditConfig,
    registry: &Registry,
) -> Result<AuditReport, StoreError> {
    let run = store.load_run(run_id)?;
    let suppressions = store.suppressions(run_id)?;
    let evidence = EvidenceBundle {
        observations: &run.observations,
        urls: &run.urls,
        sitemap: Some(&run.sitemap),
        sitemap_done: run.sitemap_done,
        robots: run.robots.as_ref(),
        resource_fetches: &run.resource_fetches,
        tls_inspections: &run.tls_inspections,
        host_probes: &run.host_probes,
        start_url: Some(&run.profile.start_url),
    };
    let report = evaluate(run_id, &evidence, config, registry, &suppressions);
    store.save_audit_report(&report)?;
    Ok(report)
}

fn draft_is_valid(draft: &FindingDraft) -> bool {
    !draft.entity_key.is_empty()
        && !draft.fact.is_empty()
        && !draft.recommendation.is_empty()
        && !draft.evidence.is_empty()
}

fn finding_from_draft(rule_id: &str, draft: FindingDraft, config: &AuditConfig) -> Finding {
    let severity = rule_by_id(rule_id)
        .map(|rule| rule.severity)
        .unwrap_or(Severity::Notice);
    Finding {
        id: FindingId::new(rule_id, draft.entity_key),
        catalogue_version: CATALOGUE_VERSION,
        config_version: config.version,
        severity,
        state: RuleState::Findings,
        fact: draft.fact,
        recommendation: draft.recommendation,
        evidence: draft
            .evidence
            .into_iter()
            .map(|pointer| EvidencePointer {
                observation_identity: pointer.observation_identity,
                field: pointer.field,
                excerpt: truncate_excerpt(&pointer.excerpt),
            })
            .collect(),
        suppressed: false,
    }
}

fn truncate_excerpt(value: &str) -> String {
    value.chars().take(EXCERPT_MAX_CHARS).collect()
}

fn checker_order(registry: &Registry) -> Vec<&'static str> {
    let mut indegree: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut adjacency: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    for id in registry.checkers.keys().copied() {
        indegree.entry(id).or_insert(0);
        adjacency.entry(id).or_default();
    }
    for (id, checker) in &registry.checkers {
        for dep in checker.depends_on() {
            if registry.contains(dep) {
                adjacency.entry(*dep).or_default().push(*id);
                *indegree.entry(*id).or_insert(0) += 1;
            }
        }
    }
    for children in adjacency.values_mut() {
        children.sort_unstable();
        children.dedup();
    }
    let mut ready: Vec<&'static str> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| *id)
        .collect();
    ready.sort_unstable();
    let mut order = Vec::new();
    let mut index = 0;
    while index < ready.len() {
        let id = ready[index];
        index += 1;
        order.push(id);
        if let Some(children) = adjacency.get(id) {
            for child in children {
                if let Some(degree) = indegree.get_mut(child) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        ready.push(*child);
                    }
                }
            }
        }
    }
    order
}

fn blocked_by_prereq(deps: &[&str], states: &BTreeMap<String, RuleState>) -> Option<RuleState> {
    let mut incomplete = false;
    for dep in deps {
        match states.get(*dep).copied().unwrap_or(RuleState::Unsupported) {
            RuleState::Unsupported => return Some(RuleState::Unsupported),
            RuleState::Incomplete | RuleState::Disabled => incomplete = true,
            RuleState::Passed | RuleState::Findings | RuleState::NotApplicable => {}
        }
    }
    incomplete.then_some(RuleState::Incomplete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{ExtractInput, extract};
    use crate::profile::Profile;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use url::Url;

    struct MissingTitle;

    impl Checker for MissingTitle {
        fn rule_id(&self) -> &'static str {
            "meta.missing_title"
        }

        fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
            title_presence(evidence, false)
        }
    }

    struct DuplicateTitle;

    impl Checker for DuplicateTitle {
        fn rule_id(&self) -> &'static str {
            "meta.duplicate_title"
        }

        fn depends_on(&self) -> &'static [&'static str] {
            &["meta.missing_title"]
        }

        fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
            title_presence(evidence, true)
        }
    }

    struct LongTitle;

    impl Checker for LongTitle {
        fn rule_id(&self) -> &'static str {
            "meta.long_title"
        }

        fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
            let max = config
                .threshold("long_title")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(60);
            let mut findings = Vec::new();
            let mut saw_complete = false;
            let mut saw_incomplete = false;
            for observation in evidence.observations {
                if !observation.page.is_complete() {
                    saw_incomplete = true;
                    continue;
                }
                saw_complete = true;
                let title = observation.page.titles.first().cloned().unwrap_or_default();
                let chars = title.chars().count();
                if chars > max {
                    findings.push(FindingDraft {
                        entity_key: observation.identity.clone(),
                        fact: format!("The title is {chars} characters."),
                        recommendation: format!("Shorten the title to at most {max} characters."),
                        evidence: vec![EvidencePointer {
                            observation_identity: observation.identity.clone(),
                            field: "title".into(),
                            excerpt: title,
                        }],
                    });
                }
            }
            CheckerOutput {
                applicable: true,
                evidence_complete: saw_complete && !saw_incomplete,
                findings,
            }
        }
    }

    fn title_presence(evidence: &EvidenceBundle<'_>, always_pass: bool) -> CheckerOutput {
        let mut findings = Vec::new();
        let mut saw_complete = false;
        let mut saw_incomplete = false;
        for observation in evidence.observations {
            if !observation.page.is_complete() {
                saw_incomplete = true;
                continue;
            }
            saw_complete = true;
            if always_pass {
                continue;
            }
            let has_title = observation
                .page
                .titles
                .iter()
                .any(|title| !title.trim().is_empty());
            if !has_title {
                findings.push(FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: "The page has no non-empty title element.".into(),
                    recommendation: "Add a single descriptive title element.".into(),
                    evidence: vec![EvidencePointer {
                        observation_identity: observation.identity.clone(),
                        field: "title".into(),
                        excerpt: observation.page.titles.first().cloned().unwrap_or_default(),
                    }],
                });
            }
        }
        CheckerOutput {
            applicable: true,
            evidence_complete: saw_complete && !saw_incomplete,
            findings,
        }
    }

    fn page(url: &str, body: &[u8], truncated: bool) -> ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status: 200,
            content_type: "text/html",
            headers: &[],
            body,
            truncated,
            duration_ms: Some(1),
        })
    }

    fn untitled() -> ExtractedObservations {
        page(
            "https://audit.example/untitled",
            b"<html><head></head><body>Hello</body></html>",
            false,
        )
    }

    fn titled() -> ExtractedObservations {
        page(
            "https://audit.example/titled",
            b"<html><head><title>Shop cables</title></head><body>Hello</body></html>",
            false,
        )
    }

    fn truncated() -> ExtractedObservations {
        page(
            "https://audit.example/partial",
            b"<html><title>Partial",
            true,
        )
    }

    fn long_titled() -> ExtractedObservations {
        page(
            "https://audit.example/long",
            b"<html><head><title>This title is deliberately longer than sixty characters for the fixture</title></head><body>Hello</body></html>",
            false,
        )
    }

    fn title_registry() -> Registry {
        let mut registry = Registry::new();
        registry.register(MissingTitle);
        registry
    }

    fn run(
        obs: &[ExtractedObservations],
        registry: &Registry,
        config: &AuditConfig,
    ) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls: &[],
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: &[],
                tls_inspections: &[],
                host_probes: &[],
                start_url: None,
            },
            config,
            registry,
            &[],
        )
    }

    fn sample_profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn temp_path() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "crawlytic-audit-{}-{}.sqlite",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn cleanup(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
        let wal = format!("{}-wal", path.display());
        let shm = format!("{}-shm", path.display());
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(&shm);
    }

    #[test]
    fn empty_registry_marks_catalogue_unsupported_never_passed() {
        let report = run(&[], &Registry::new(), &AuditConfig::default());
        assert_eq!(report.outcomes.len(), rules().len());
        assert!(
            report
                .outcomes
                .iter()
                .all(|outcome| outcome.state == RuleState::Unsupported)
        );
        assert!(report.findings.is_empty());
        assert!(
            report
                .outcomes
                .iter()
                .all(|outcome| outcome.state != RuleState::Passed)
        );
    }

    #[test]
    fn identical_evidence_and_config_produce_stable_findings() {
        let registry = title_registry();
        let config = AuditConfig::default();
        let obs = [untitled()];
        let first = run(&obs, &registry, &config);
        let second = run(&obs, &registry, &config);
        assert_eq!(first.findings, second.findings);
        assert_eq!(first.outcomes, second.outcomes);
        assert_eq!(first.config_fingerprint, second.config_fingerprint);
        assert_eq!(
            first.findings[0].id.key(),
            "meta.missing_title::https://audit.example/untitled"
        );
    }

    #[test]
    fn missing_and_truncated_evidence_is_incomplete_never_passed() {
        let registry = title_registry();
        let config = AuditConfig::default();
        let empty = run(&[], &registry, &config);
        assert_eq!(
            empty.outcome("meta.missing_title"),
            Some(RuleState::Incomplete)
        );
        assert_ne!(empty.outcome("meta.missing_title"), Some(RuleState::Passed));
        assert!(empty.findings_for("meta.missing_title").next().is_none());

        let partial = run(&[truncated()], &registry, &config);
        assert_eq!(
            partial.outcome("meta.missing_title"),
            Some(RuleState::Incomplete)
        );
        assert_ne!(
            partial.outcome("meta.missing_title"),
            Some(RuleState::Passed)
        );
        assert!(partial.findings.is_empty());
    }

    #[test]
    fn finding_carries_entity_evidence_fact_recommendation_and_severity() {
        let report = run(&[untitled()], &title_registry(), &AuditConfig::default());
        assert_eq!(
            report.outcome("meta.missing_title"),
            Some(RuleState::Findings)
        );
        let finding = report.findings_for("meta.missing_title").next().unwrap();
        assert_eq!(finding.id.entity_key, "https://audit.example/untitled");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.fact, "The page has no non-empty title element.");
        assert_eq!(
            finding.recommendation,
            "Add a single descriptive title element."
        );
        assert_eq!(finding.evidence[0].field, "title");
        assert_eq!(
            finding.evidence[0].observation_identity,
            "https://audit.example/untitled"
        );
        assert!(!finding.fact.to_ascii_lowercase().contains("error"));
        assert!(!finding.recommendation.is_empty());
        let dump = format!("{finding:?}");
        assert!(!dump.to_ascii_lowercase().contains("signature"));
    }

    #[test]
    fn complete_titled_page_passes_without_findings() {
        let report = run(&[titled()], &title_registry(), &AuditConfig::default());
        assert_eq!(
            report.outcome("meta.missing_title"),
            Some(RuleState::Passed)
        );
        assert!(report.findings_for("meta.missing_title").next().is_none());
    }

    #[test]
    fn unregistered_dependency_is_unsupported_never_passed() {
        let mut registry = Registry::new();
        registry.register(DuplicateTitle);
        let report = run(&[titled()], &registry, &AuditConfig::default());
        assert_eq!(
            report.outcome("meta.duplicate_title"),
            Some(RuleState::Unsupported)
        );
        assert_ne!(
            report.outcome("meta.duplicate_title"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn incomplete_dependency_is_incomplete_never_passed() {
        let mut registry = title_registry();
        registry.register(DuplicateTitle);
        let report = run(&[truncated()], &registry, &AuditConfig::default());
        assert_eq!(
            report.outcome("meta.missing_title"),
            Some(RuleState::Incomplete)
        );
        assert_eq!(
            report.outcome("meta.duplicate_title"),
            Some(RuleState::Incomplete)
        );
        assert_ne!(
            report.outcome("meta.duplicate_title"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn disabled_registered_rule_is_disabled() {
        let mut config = AuditConfig::default();
        config.enabled.insert("meta.missing_title".into(), false);
        let report = run(&[untitled()], &title_registry(), &config);
        assert_eq!(
            report.outcome("meta.missing_title"),
            Some(RuleState::Disabled)
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn config_change_keeps_identity_and_updates_recommendation() {
        let mut registry = Registry::new();
        registry.register(LongTitle);
        let obs = [long_titled()];
        let mut short = AuditConfig::default();
        short.thresholds.insert("long_title".into(), "40".into());
        let mut tall = AuditConfig::default();
        tall.thresholds.insert("long_title".into(), "200".into());
        let findings = run(&obs, &registry, &short);
        let passed = run(&obs, &registry, &tall);
        assert_eq!(
            findings.outcome("meta.long_title"),
            Some(RuleState::Findings)
        );
        assert_eq!(passed.outcome("meta.long_title"), Some(RuleState::Passed));
        let finding = findings.findings_for("meta.long_title").next().unwrap();
        assert_eq!(
            finding.id.key(),
            "meta.long_title::https://audit.example/long"
        );
        assert!(finding.recommendation.contains("40"));
        assert_eq!(finding.severity, Severity::Warning);
        assert_ne!(findings.config_fingerprint, passed.config_fingerprint);
    }

    struct DuplicateEntity;

    impl Checker for DuplicateEntity {
        fn rule_id(&self) -> &'static str {
            "meta.missing_title"
        }

        fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
            let Some(observation) = evidence.observations.first() else {
                return CheckerOutput {
                    applicable: true,
                    evidence_complete: false,
                    findings: Vec::new(),
                };
            };
            let draft = FindingDraft {
                entity_key: observation.identity.clone(),
                fact: "Duplicate entity fixture.".into(),
                recommendation: "Keep one finding identity per entity.".into(),
                evidence: vec![EvidencePointer {
                    observation_identity: observation.identity.clone(),
                    field: "title".into(),
                    excerpt: "dup".into(),
                }],
            };
            CheckerOutput {
                applicable: true,
                evidence_complete: true,
                findings: vec![draft.clone(), draft],
            }
        }
    }

    #[test]
    fn duplicate_finding_identities_persist_once() {
        let path = temp_path();
        let store = Store::open(&path).unwrap();
        let run_id = store.begin_run(&sample_profile()).unwrap();
        store.put_observation(run_id, &untitled()).unwrap();
        let mut registry = Registry::new();
        registry.register(DuplicateEntity);
        let report = evaluate_stored(&store, run_id, &AuditConfig::default(), &registry)
            .expect("duplicate finding identities must not fail UNIQUE");
        assert_eq!(report.findings_for("meta.missing_title").count(), 1);
        cleanup(&path);
    }

    #[test]
    fn stored_observations_evaluate_without_recrawl() {
        let path = temp_path();
        let obs = untitled();
        let run_id;
        {
            let store = Store::open(&path).unwrap();
            run_id = store.begin_run(&sample_profile()).unwrap();
            store.put_observation(run_id, &obs).unwrap();
            store.flush().unwrap();
        }
        let store = Store::open(&path).unwrap();
        let first =
            evaluate_stored(&store, run_id, &AuditConfig::default(), &title_registry()).unwrap();
        let second =
            evaluate_stored(&store, run_id, &AuditConfig::default(), &title_registry()).unwrap();
        assert_eq!(first.findings, second.findings);
        assert_eq!(
            first.outcome("meta.missing_title"),
            Some(RuleState::Findings)
        );
        let loaded = store.load_run(run_id).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].rule_id, "meta.missing_title");
        assert_eq!(loaded.findings[0].fact, first.findings[0].fact);
        assert_eq!(
            loaded.findings[0].recommendation,
            first.findings[0].recommendation
        );
        assert_eq!(loaded.findings[0].severity, "error");
        cleanup(&path);
    }

    #[test]
    fn suppressions_are_auditable_and_keep_evidence() {
        let store = Store::open_in_memory().unwrap();
        let run_id = store.begin_run(&sample_profile()).unwrap();
        store.put_observation(run_id, &untitled()).unwrap();
        let registry = title_registry();
        let config = AuditConfig::default();
        let before = evaluate_stored(&store, run_id, &config, &registry).unwrap();
        assert_eq!(before.findings.len(), 1);
        assert!(!before.findings[0].suppressed);

        let suppression_id = store
            .apply_suppression(
                run_id,
                Some("meta.missing_title"),
                Some("https://audit.example/untitled"),
                "accepted duplicate listing template",
            )
            .unwrap();
        let after = evaluate_stored(&store, run_id, &config, &registry).unwrap();
        assert_eq!(after.findings.len(), 1);
        assert!(after.findings[0].suppressed);
        assert_eq!(after.findings[0].fact, before.findings[0].fact);
        assert_eq!(after.findings[0].id, before.findings[0].id);

        store
            .revoke_suppression(suppression_id, "template retired")
            .unwrap();
        let restored = evaluate_stored(&store, run_id, &config, &registry).unwrap();
        assert!(!restored.findings[0].suppressed);

        let events = store.suppression_events(run_id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, SuppressionAction::Apply);
        assert_eq!(events[0].reason, "accepted duplicate listing template");
        assert_eq!(events[1].action, SuppressionAction::Revoke);
        assert_eq!(events[1].reason, "template retired");
        let persisted = store.load_run(run_id).unwrap();
        assert_eq!(persisted.findings.len(), 1);
        assert_eq!(
            persisted.findings[0].entity_key,
            "https://audit.example/untitled"
        );
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(&[untitled()], &title_registry(), &AuditConfig::default());
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!lower.contains("sig1="));
        assert!(!dump.contains("CRAWL_"));
        let ids: BTreeSet<_> = report.outcomes.iter().map(|o| o.rule_id.as_str()).collect();
        assert!(ids.contains("meta.missing_title"));
    }
}
