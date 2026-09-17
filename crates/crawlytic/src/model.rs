use crawlytic_core::{
    AuditReport, CoverageLink, EvidencePointer, Finding, RuleState, Severity, rule_by_id,
};
use std::fmt::{Debug, Formatter};

#[derive(Clone, Default)]
pub struct SecretBuffer {
    inner: String,
}

impl SecretBuffer {
    pub fn push(&mut self, c: char) {
        self.inner.push(c);
    }

    pub fn pop(&mut self) {
        self.inner.pop();
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn masked(&self) -> String {
        mask_secret(&self.inner)
    }

    pub fn take(&mut self) -> String {
        std::mem::take(&mut self.inner)
    }

    pub fn as_secret(&self) -> &str {
        &self.inner
    }
}

impl Debug for SecretBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBuffer([redacted])")
    }
}

pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        "•".repeat(value.chars().count().clamp(4, 12))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPresence {
    Missing,
    Set,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub rule_id: String,
    pub rule_label: String,
    pub severity: Severity,
    pub entity_key: String,
    pub fact: String,
    pub recommendation: String,
    pub evidence: Vec<EvidencePointer>,
    pub suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSection {
    pub rule_id: String,
    pub label: String,
    pub severity: Severity,
    pub state: RuleState,
    pub findings: Vec<FindingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Investigation {
    pub by_severity: Vec<(Severity, Vec<RuleSection>)>,
    pub incomplete: Vec<RuleSection>,
    pub unsupported: Vec<RuleSection>,
}

impl Investigation {
    pub fn is_empty(&self) -> bool {
        self.by_severity.iter().all(|(_, rules)| rules.is_empty())
            && self.incomplete.is_empty()
            && self.unsupported.is_empty()
    }

    pub fn finding_count(&self) -> usize {
        self.by_severity
            .iter()
            .flat_map(|(_, rules)| rules)
            .map(|rule| rule.findings.len())
            .sum()
    }
}

pub fn investigation_from_report(report: &AuditReport) -> Investigation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut notices = Vec::new();
    let mut incomplete = Vec::new();
    let mut unsupported = Vec::new();

    let mut findings_by_rule: std::collections::BTreeMap<String, Vec<FindingRow>> =
        std::collections::BTreeMap::new();
    for finding in &report.findings {
        findings_by_rule
            .entry(finding.id.rule_id.clone())
            .or_default()
            .push(row_from_finding(finding));
    }

    for outcome in &report.outcomes {
        let meta = rule_by_id(&outcome.rule_id);
        let label = meta
            .map(|rule| rule.captured_label.to_string())
            .unwrap_or_else(|| outcome.rule_id.clone());
        let severity = meta.map(|rule| rule.severity).unwrap_or(Severity::Notice);
        let findings = findings_by_rule
            .remove(&outcome.rule_id)
            .unwrap_or_default();
        let section = RuleSection {
            rule_id: outcome.rule_id.clone(),
            label,
            severity,
            state: outcome.state,
            findings,
        };
        match outcome.state {
            RuleState::Findings => match section.severity {
                Severity::Error => errors.push(section),
                Severity::Warning => warnings.push(section),
                Severity::Notice => notices.push(section),
            },
            RuleState::Incomplete => incomplete.push(section),
            RuleState::Unsupported => unsupported.push(section),
            RuleState::Passed | RuleState::NotApplicable | RuleState::Disabled => {}
        }
    }

    let mut by_severity = Vec::new();
    if !errors.is_empty() {
        by_severity.push((Severity::Error, errors));
    }
    if !warnings.is_empty() {
        by_severity.push((Severity::Warning, warnings));
    }
    if !notices.is_empty() {
        by_severity.push((Severity::Notice, notices));
    }

    Investigation {
        by_severity,
        incomplete,
        unsupported,
    }
}

fn row_from_finding(finding: &Finding) -> FindingRow {
    let label = rule_by_id(&finding.id.rule_id)
        .map(|rule| rule.captured_label.to_string())
        .unwrap_or_else(|| finding.id.rule_id.clone());
    FindingRow {
        rule_id: finding.id.rule_id.clone(),
        rule_label: label,
        severity: finding.severity,
        entity_key: finding.id.entity_key.clone(),
        fact: finding.fact.clone(),
        recommendation: finding.recommendation.clone(),
        evidence: finding.evidence.clone(),
        suppressed: finding.suppressed,
    }
}

pub fn inlinks_for<'a>(links: &'a [CoverageLink], entity: &str) -> Vec<&'a CoverageLink> {
    links
        .iter()
        .filter(|link| {
            link.to_original == entity
                || link
                    .to_identity
                    .as_ref()
                    .is_some_and(|identity| identity.as_str() == entity)
        })
        .collect()
}

pub fn looks_like_placeholder_score(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("site health")
        || lower.contains("placeholder score")
        || lower.contains("/100")
        || lower.contains("synthetic finding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crawlytic_core::{
        CATALOGUE_VERSION, EvidencePointer, Finding, FindingId, RULE_CONFIG_VERSION, RuleOutcome,
        RuleState, Severity,
    };

    fn report() -> AuditReport {
        AuditReport {
            run_id: 1,
            config_version: RULE_CONFIG_VERSION,
            config_fingerprint: "v1;e:;t:".into(),
            outcomes: vec![
                RuleOutcome {
                    rule_id: "meta.missing_title".into(),
                    state: RuleState::Findings,
                },
                RuleOutcome {
                    rule_id: "meta.long_title".into(),
                    state: RuleState::Incomplete,
                },
                RuleOutcome {
                    rule_id: "content.low_text_html_ratio".into(),
                    state: RuleState::Unsupported,
                },
            ],
            findings: vec![Finding {
                id: FindingId::new("meta.missing_title", "https://audit.example/untitled"),
                catalogue_version: CATALOGUE_VERSION,
                config_version: RULE_CONFIG_VERSION,
                severity: Severity::Error,
                state: RuleState::Findings,
                fact: "The page has no non-empty title element.".into(),
                recommendation: "Add a single descriptive title element.".into(),
                evidence: vec![EvidencePointer {
                    observation_identity: "https://audit.example/untitled".into(),
                    field: "title".into(),
                    excerpt: "(empty)".into(),
                }],
                suppressed: false,
            }],
        }
    }

    #[test]
    fn groups_live_findings_and_lists_incomplete_and_unsupported() {
        let investigation = investigation_from_report(&report());
        assert_eq!(investigation.finding_count(), 1);
        assert_eq!(investigation.by_severity[0].0, Severity::Error);
        assert_eq!(
            investigation.by_severity[0].1[0].rule_id,
            "meta.missing_title"
        );
        assert_eq!(investigation.incomplete[0].rule_id, "meta.long_title");
        assert_eq!(
            investigation.unsupported[0].rule_id,
            "content.low_text_html_ratio"
        );
        assert!(!looks_like_placeholder_score("fetched 3 pending 1"));
        assert!(looks_like_placeholder_score("Site health 92/100"));
    }

    #[test]
    fn secret_buffer_never_debugs_plaintext() {
        let mut secret = SecretBuffer::default();
        secret.push('s');
        secret.push('e');
        secret.push('c');
        secret.push('r');
        secret.push('e');
        secret.push('t');
        let dump = format!("{secret:?}");
        assert!(!dump.contains("secret"), "{dump}");
        assert_eq!(secret.masked(), "••••••");
        assert_eq!(secret.as_secret(), "secret");
    }
}
