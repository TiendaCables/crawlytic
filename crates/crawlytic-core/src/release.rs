//! Secret-free first-release metadata: product name, license, and rule coverage.
//!
//! Crates stay unpublished. Coverage is derived from the catalogue and the
//! registered checker set; it never reads profiles, stores, or the environment.

use crate::audit::Registry;
use crate::catalogue::{CATALOGUE_VERSION, RuleStatus, rules};
use crate::compare::is_engine_covered;
use crate::rules::audit_registry;
use crate::store::STORE_SCHEMA_VERSION;
use serde::Serialize;

pub const PRODUCT_NAME: &str = "Crawlytic";
pub const LICENSE: &str = "MIT";
pub const REPOSITORY: &str = "https://github.com/TiendaCables/crawlytic";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageKind {
    Checker,
    Engine,
    SpecifiedUnregistered,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageEntry {
    pub id: String,
    pub label: String,
    pub kind: CoverageKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseCoverage {
    pub product: String,
    pub version: String,
    pub license: String,
    pub repository: String,
    pub publish_crates: bool,
    pub catalogue_version: u32,
    pub store_schema_version: i64,
    pub supported: Vec<CoverageEntry>,
    pub deferred: Vec<CoverageEntry>,
    pub unregistered: Vec<CoverageEntry>,
}

pub fn rule_coverage(registry: &Registry) -> ReleaseCoverage {
    let mut supported = Vec::new();
    let mut deferred = Vec::new();
    let mut unregistered = Vec::new();
    for rule in rules() {
        let entry = CoverageEntry {
            id: rule.id.to_owned(),
            label: rule.captured_label.to_owned(),
            kind: if rule.status == RuleStatus::Deferred {
                CoverageKind::Deferred
            } else if registry.contains(rule.id) {
                CoverageKind::Checker
            } else if is_engine_covered(rule.id) {
                CoverageKind::Engine
            } else {
                CoverageKind::SpecifiedUnregistered
            },
        };
        match entry.kind {
            CoverageKind::Checker | CoverageKind::Engine => supported.push(entry),
            CoverageKind::Deferred => deferred.push(entry),
            CoverageKind::SpecifiedUnregistered => unregistered.push(entry),
        }
    }
    ReleaseCoverage {
        product: PRODUCT_NAME.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        license: LICENSE.to_owned(),
        repository: REPOSITORY.to_owned(),
        publish_crates: false,
        catalogue_version: CATALOGUE_VERSION,
        store_schema_version: STORE_SCHEMA_VERSION,
        supported,
        deferred,
        unregistered,
    }
}

pub fn release_coverage_json() -> Result<String, serde_json::Error> {
    let mut json = serde_json::to_string_pretty(&rule_coverage(&audit_registry()))?;
    json.push('\n');
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn coverage_lists_supported_and_deferred_rules_without_secrets() {
        let json = release_coverage_json().unwrap();
        let coverage = rule_coverage(&audit_registry());
        assert_eq!(coverage.product, PRODUCT_NAME);
        assert_eq!(coverage.license, LICENSE);
        assert!(!coverage.publish_crates);
        assert!(!coverage.supported.is_empty());
        assert!(!coverage.deferred.is_empty());
        assert!(
            coverage.supported.iter().any(
                |entry| entry.id == "meta.missing_title" && entry.kind == CoverageKind::Checker
            )
        );
        assert!(
            coverage
                .deferred
                .iter()
                .any(|entry| entry.id == "amp.hidden_catalogue")
        );
        assert!(
            coverage
                .supported
                .iter()
                .any(|entry| entry.id == "crawl.dns_failure" && entry.kind == CoverageKind::Engine)
        );
        let seen: BTreeSet<_> = coverage
            .supported
            .iter()
            .chain(coverage.deferred.iter())
            .chain(coverage.unregistered.iter())
            .map(|entry| entry.id.as_str())
            .collect();
        assert_eq!(seen.len(), rules().len());
        let lowered = json.to_ascii_lowercase();
        for needle in [
            "crawl_signature",
            "signature-input",
            "signature_agent",
            "password",
            "authorization",
        ] {
            assert!(!lowered.contains(needle), "{needle} leaked in {json}");
        }
    }
}
