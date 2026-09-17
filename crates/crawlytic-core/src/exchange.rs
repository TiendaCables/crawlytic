//! Audit evidence export and a read-only comparison-baseline importer.
//!
//! CSV/JSON export our finding schema. The generic CSV mapper uses internal
//! logical fields, not claimed Semrush headers. A Semrush XLSX adapter is
//! blocked until a real workbook is supplied.

use crate::audit::{AuditReport, EvidencePointer};
use crate::catalogue::rule_by_id;
use crate::crawl::UrlRecord;
use crate::engine::CrawlCounters;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

pub const EXPECTED_SEMRUSH_EXPORT_NAME: &str = "www.tiendacables.com_mega_export_20260914.xlsx";

const CSV_HEADER: &str = "finding_id,rule_id,severity,unit,entity_url,evidence,status,fact,recommendation,suppressed,run_id,coverage_fetched,coverage_excluded,coverage_blocked,coverage_failed,coverage_pending,coverage_in_flight,coverage_discovered";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeErrorKind {
    Secrets,
    WorkbookAdapterBlocked,
    Csv,
    Json,
    Io,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeError {
    pub kind: ExchangeErrorKind,
    message: String,
}

impl ExchangeError {
    fn new(kind: ExchangeErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn is_secrets(&self) -> bool {
        self.kind == ExchangeErrorKind::Secrets
    }

    pub fn is_workbook_blocked(&self) -> bool {
        self.kind == ExchangeErrorKind::WorkbookAdapterBlocked
    }
}

impl Display for ExchangeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExchangeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct ExportCoverage {
    pub fetched: u64,
    pub excluded: u64,
    pub blocked: u64,
    pub failed: u64,
    pub pending: u64,
    pub in_flight: u64,
    pub discovered: u64,
}

impl From<CrawlCounters> for ExportCoverage {
    fn from(counters: CrawlCounters) -> Self {
        Self {
            fetched: counters.fetched,
            excluded: counters.excluded,
            blocked: counters.blocked,
            failed: counters.failed,
            pending: counters.pending,
            in_flight: counters.in_flight,
            discovered: counters.discovered(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportEvidence {
    pub observation_identity: String,
    pub field: String,
    pub excerpt: String,
}

impl From<&EvidencePointer> for ExportEvidence {
    fn from(pointer: &EvidencePointer) -> Self {
        Self {
            observation_identity: pointer.observation_identity.clone(),
            field: pointer.field.clone(),
            excerpt: pointer.excerpt.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub unit: String,
    pub entity_url: String,
    pub evidence: Vec<ExportEvidence>,
    pub status: String,
    pub fact: String,
    pub recommendation: String,
    pub suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportOutcome {
    pub rule_id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportDocument {
    pub run_id: i64,
    pub coverage: ExportCoverage,
    pub findings: Vec<ExportFinding>,
    pub outcomes: Vec<ExportOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenExport {
    pub csv_path: PathBuf,
    pub json_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMap {
    pub source_check: String,
    pub entity_url: String,
    pub referrer_url: Option<String>,
    pub unit: Option<String>,
    pub severity: Option<String>,
    pub observed_at: Option<String>,
    pub source_report: Option<String>,
    pub current_count: Option<String>,
    pub historical_delta: Option<String>,
    pub row_kind: Option<String>,
}

impl FieldMap {
    fn mapped_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        names.insert(normalize_header(&self.source_check));
        names.insert(normalize_header(&self.entity_url));
        for optional in [
            self.referrer_url.as_deref(),
            self.unit.as_deref(),
            self.severity.as_deref(),
            self.observed_at.as_deref(),
            self.source_report.as_deref(),
            self.current_count.as_deref(),
            self.historical_delta.as_deref(),
            self.row_kind.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            names.insert(normalize_header(optional));
        }
        names
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineRowKind {
    Aggregate,
    AffectedEntity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineRow {
    pub kind: BaselineRowKind,
    pub source_check: String,
    pub entity_url: Option<String>,
    pub referrer_url: Option<String>,
    pub unit: Option<String>,
    pub severity: Option<String>,
    pub observed_at: Option<String>,
    pub source_report: Option<String>,
    pub current_count: Option<i64>,
    pub historical_delta: Option<i64>,
    pub unmatched: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineImport {
    pub source_name: String,
    pub source_report: Option<String>,
    pub unmatched_columns: Vec<String>,
    pub rows: Vec<BaselineRow>,
}

impl BaselineImport {
    pub fn aggregate_rows(&self) -> impl Iterator<Item = &BaselineRow> {
        self.rows
            .iter()
            .filter(|row| row.kind == BaselineRowKind::Aggregate)
    }

    pub fn entity_rows(&self) -> impl Iterator<Item = &BaselineRow> {
        self.rows
            .iter()
            .filter(|row| row.kind == BaselineRowKind::AffectedEntity)
    }
}

pub fn export_document(
    report: &AuditReport,
    urls: &[UrlRecord],
) -> Result<ExportDocument, ExchangeError> {
    let document = ExportDocument {
        run_id: report.run_id,
        coverage: ExportCoverage::from(CrawlCounters::from_records(urls)),
        findings: report
            .findings
            .iter()
            .map(|finding| {
                let unit = rule_by_id(&finding.id.rule_id)
                    .map(|rule| rule.unit.as_str())
                    .unwrap_or("unspecified");
                ExportFinding {
                    finding_id: finding.id.key(),
                    rule_id: finding.id.rule_id.clone(),
                    severity: finding.severity.as_str().to_string(),
                    unit: unit.to_string(),
                    entity_url: finding.id.entity_key.clone(),
                    evidence: finding.evidence.iter().map(ExportEvidence::from).collect(),
                    status: finding.state.as_str().to_string(),
                    fact: finding.fact.clone(),
                    recommendation: finding.recommendation.clone(),
                    suppressed: finding.suppressed,
                }
            })
            .collect(),
        outcomes: report
            .outcomes
            .iter()
            .map(|outcome| ExportOutcome {
                rule_id: outcome.rule_id.clone(),
                status: outcome.state.as_str().to_string(),
            })
            .collect(),
    };
    reject_secrets(&render_json(&document)?)?;
    Ok(document)
}

pub fn render_csv(document: &ExportDocument) -> Result<String, ExchangeError> {
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    let coverage = document.coverage;
    for finding in &document.findings {
        let evidence = evidence_csv(&finding.evidence);
        let row = [
            csv_escape(&finding.finding_id),
            csv_escape(&finding.rule_id),
            csv_escape(&finding.severity),
            csv_escape(&finding.unit),
            csv_escape(&finding.entity_url),
            csv_escape(&evidence),
            csv_escape(&finding.status),
            csv_escape(&finding.fact),
            csv_escape(&finding.recommendation),
            csv_escape(if finding.suppressed { "true" } else { "false" }),
            csv_escape(&document.run_id.to_string()),
            csv_escape(&coverage.fetched.to_string()),
            csv_escape(&coverage.excluded.to_string()),
            csv_escape(&coverage.blocked.to_string()),
            csv_escape(&coverage.failed.to_string()),
            csv_escape(&coverage.pending.to_string()),
            csv_escape(&coverage.in_flight.to_string()),
            csv_escape(&coverage.discovered.to_string()),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    reject_secrets(&out)?;
    Ok(out)
}

pub fn render_json(document: &ExportDocument) -> Result<String, ExchangeError> {
    let json = serde_json::to_string_pretty(document)
        .map_err(|err| ExchangeError::new(ExchangeErrorKind::Json, err.to_string()))?;
    reject_secrets(&json)?;
    Ok(json)
}

pub fn write_export(dir: &Path, document: &ExportDocument) -> Result<WrittenExport, ExchangeError> {
    let csv = render_csv(document)?;
    let json = render_json(document)?;
    let csv_path = dir.join(format!("crawlytic-run-{}-audit.csv", document.run_id));
    let json_path = dir.join(format!("crawlytic-run-{}-audit.json", document.run_id));
    std::fs::write(&csv_path, csv.as_bytes()).map_err(io_error)?;
    std::fs::write(&json_path, json.as_bytes()).map_err(io_error)?;
    Ok(WrittenExport {
        csv_path,
        json_path,
    })
}

pub fn import_baseline(
    bytes: &[u8],
    source_name: &str,
    mapping: &FieldMap,
) -> Result<BaselineImport, ExchangeError> {
    if looks_like_xlsx(bytes, source_name) {
        return Err(ExchangeError::new(
            ExchangeErrorKind::WorkbookAdapterBlocked,
            format!(
                "Semrush workbook adapter is blocked until a real XLSX/CSV export is supplied as a Linear attachment or repository fixture. Original expected filename: {EXPECTED_SEMRUSH_EXPORT_NAME}. Sheet names, column names and affected URLs are not assumed."
            ),
        ));
    }
    import_csv(bytes, source_name, mapping)
}

fn import_csv(
    bytes: &[u8],
    source_name: &str,
    mapping: &FieldMap,
) -> Result<BaselineImport, ExchangeError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|err| ExchangeError::new(ExchangeErrorKind::Csv, err.to_string()))?;
    let rows = parse_csv(text)?;
    if rows.is_empty() {
        return Ok(BaselineImport {
            source_name: source_name.to_string(),
            source_report: None,
            unmatched_columns: Vec::new(),
            rows: Vec::new(),
        });
    }
    let headers: Vec<String> = rows[0]
        .iter()
        .map(|header| normalize_header(header))
        .collect();
    if column_index(&headers, &mapping.source_check).is_none()
        || column_index(&headers, &mapping.entity_url).is_none()
    {
        return Err(ExchangeError::new(
            ExchangeErrorKind::Csv,
            "CSV mapping requires source_check and entity_url columns",
        ));
    }
    let mapped = mapping.mapped_names();
    let unmatched_columns: Vec<String> = headers
        .iter()
        .filter(|header| !header.is_empty() && !mapped.contains(*header))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut imported_rows = Vec::new();
    let mut source_report = None;
    for raw in rows.iter().skip(1) {
        let source_check = match field(raw, &headers, &mapping.source_check) {
            Some(value) => value,
            None => continue,
        };
        let entity_url = field(raw, &headers, &mapping.entity_url);
        let referrer_url = mapping
            .referrer_url
            .as_deref()
            .and_then(|name| field(raw, &headers, name));
        let unit = mapping
            .unit
            .as_deref()
            .and_then(|name| field(raw, &headers, name));
        let severity = mapping
            .severity
            .as_deref()
            .and_then(|name| field(raw, &headers, name));
        let observed_at = mapping
            .observed_at
            .as_deref()
            .and_then(|name| field(raw, &headers, name));
        let row_source_report = mapping
            .source_report
            .as_deref()
            .and_then(|name| field(raw, &headers, name));
        if source_report.is_none() {
            source_report = row_source_report.clone();
        }
        let current_count = mapping
            .current_count
            .as_deref()
            .and_then(|name| field(raw, &headers, name))
            .and_then(|value| value.parse().ok());
        let historical_delta = mapping
            .historical_delta
            .as_deref()
            .and_then(|name| field(raw, &headers, name))
            .and_then(|value| value.parse().ok());
        let kind = row_kind(
            mapping
                .row_kind
                .as_deref()
                .and_then(|name| field(raw, &headers, name))
                .as_deref(),
            entity_url.is_some(),
        );
        let mut unmatched = BTreeMap::new();
        for column in &unmatched_columns {
            if let Some(value) = field(raw, &headers, column) {
                unmatched.insert(column.clone(), value);
            }
        }
        imported_rows.push(BaselineRow {
            kind,
            source_check,
            entity_url,
            referrer_url,
            unit,
            severity,
            observed_at,
            source_report: row_source_report,
            current_count,
            historical_delta,
            unmatched,
        });
    }
    Ok(BaselineImport {
        source_name: source_name.to_string(),
        source_report,
        unmatched_columns,
        rows: imported_rows,
    })
}

fn row_kind(explicit: Option<&str>, has_entity: bool) -> BaselineRowKind {
    match explicit.map(normalize_header).as_deref() {
        Some("aggregate") => BaselineRowKind::Aggregate,
        Some("entity" | "affected" | "affected_entity") => BaselineRowKind::AffectedEntity,
        _ if has_entity => BaselineRowKind::AffectedEntity,
        _ => BaselineRowKind::Aggregate,
    }
}

fn field(row: &[String], headers: &[String], name: &str) -> Option<String> {
    let index = column_index(headers, name)?;
    row.get(index)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn column_index(headers: &[String], name: &str) -> Option<usize> {
    let needle = normalize_header(name);
    headers.iter().position(|header| header == &needle)
}

fn parse_csv(text: &str) -> Result<Vec<Vec<String>>, ExchangeError> {
    let text = text.trim_start_matches('\u{feff}');
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = text.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\n' => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|value| !value.is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            '\r' => {}
            other => field.push(other),
        }
    }
    if in_quotes {
        return Err(ExchangeError::new(
            ExchangeErrorKind::Csv,
            "Unterminated quoted CSV field",
        ));
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        if row.iter().any(|value| !value.is_empty()) {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn looks_like_xlsx(bytes: &[u8], name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".xlsx") || lower.ends_with(".xlsm") || bytes.starts_with(b"PK\x03\x04")
}

fn evidence_csv(evidence: &[ExportEvidence]) -> String {
    evidence
        .iter()
        .map(|item| {
            format!(
                "{}#{}: {}",
                item.observation_identity,
                item.field,
                neutralize_formula(&item.excerpt)
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn csv_escape(value: &str) -> String {
    let value = neutralize_formula(value);
    if value.contains([',', '"', '\n', '\r']) {
        let mut out = String::from("\"");
        out.push_str(&value.replace('"', "\"\""));
        out.push('"');
        out
    } else {
        value
    }
}

fn neutralize_formula(value: &str) -> String {
    match value.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{value}"),
        _ => value.to_string(),
    }
}

fn reject_secrets(text: &str) -> Result<(), ExchangeError> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("sig1=")
        || lower.contains("signature-input:")
        || lower.contains("signature:")
        || lower.contains("signature-input =")
        || lower.contains("crawl_signature=")
    {
        return Err(ExchangeError::new(
            ExchangeErrorKind::Secrets,
            "Refusing to export credentials. Do not store secrets in findings or exports.",
        ));
    }
    Ok(())
}

fn io_error(err: std::io::Error) -> ExchangeError {
    ExchangeError::new(ExchangeErrorKind::Io, err.to_string())
}

fn normalize_header(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::RULE_CONFIG_VERSION;
    use crate::audit::{EvidencePointer, Finding, FindingId};
    use crate::catalogue::CATALOGUE_VERSION;
    use crate::crawl::{UrlRecord, UrlState};
    use crate::engine::CrawlCounters;
    use crate::{AuditReport, RuleOutcome, RuleState, Severity};

    fn url(original: &str, state: UrlState) -> UrlRecord {
        UrlRecord {
            original: original.into(),
            identity: None,
            state,
            reason: "fixture".into(),
            click_depth: None,
            via_website: true,
            via_sitemap: false,
        }
    }

    fn report() -> AuditReport {
        AuditReport {
            run_id: 7,
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
            ],
            findings: vec![Finding {
                id: FindingId::new(
                    "meta.missing_title",
                    "https://audit.example/café?q=\"quoted\"",
                ),
                catalogue_version: CATALOGUE_VERSION,
                config_version: RULE_CONFIG_VERSION,
                severity: Severity::Error,
                state: RuleState::Findings,
                fact: "Title is missing; said \"none\".".into(),
                recommendation: "=cmd|' /C calc'!A0".into(),
                evidence: vec![EvidencePointer {
                    observation_identity: "https://audit.example/café?q=\"quoted\"".into(),
                    field: "title".into(),
                    excerpt: "+1+1".into(),
                }],
                suppressed: false,
            }],
        }
    }

    fn urls() -> Vec<UrlRecord> {
        vec![
            url("https://audit.example/", UrlState::Fetched),
            url("https://audit.example/café?q=\"quoted\"", UrlState::Fetched),
            url("https://audit.example/cart", UrlState::Excluded),
        ]
    }

    fn mapping() -> FieldMap {
        FieldMap {
            source_check: "Check".into(),
            entity_url: "URL".into(),
            referrer_url: Some("Referrer".into()),
            unit: Some("Unit".into()),
            severity: Some("Severity".into()),
            observed_at: Some("Observed at".into()),
            source_report: Some("Report".into()),
            current_count: Some("Current".into()),
            historical_delta: Some("New issues".into()),
            row_kind: Some("Row kind".into()),
        }
    }

    #[test]
    fn csv_handles_quotes_unicode_and_formula_injection() {
        let document = export_document(&report(), &urls()).unwrap();
        let csv = render_csv(&document).unwrap();
        assert!(csv.starts_with(CSV_HEADER), "{csv}");
        assert!(csv.contains("café"), "{csv}");
        assert!(csv.contains("\"\"quoted\"\""), "{csv}");
        assert!(
            csv.contains("'=cmd|' /C calc'!A0") || csv.contains("\"'=cmd|' /C calc'!A0\""),
            "{csv}"
        );
        assert!(csv.contains("'+1+1"), "{csv}");
        assert!(!csv.contains("\n=cmd"), "{csv}");
        assert!(!csv.lines().any(|line| {
            line.split(',').any(|cell| {
                let trimmed = cell.trim_start_matches('"');
                trimmed.starts_with('=') || trimmed.starts_with('+') || trimmed.starts_with('@')
            })
        }));
    }

    #[test]
    fn json_preserves_unicode_quotes_and_stable_ids() {
        let document = export_document(&report(), &urls()).unwrap();
        let json = render_json(&document).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["run_id"], 7);
        assert_eq!(parsed["coverage"]["fetched"], 2);
        assert_eq!(parsed["coverage"]["excluded"], 1);
        assert_eq!(parsed["coverage"]["discovered"], 3);
        assert_eq!(
            parsed["findings"][0]["finding_id"],
            "meta.missing_title::https://audit.example/café?q=\"quoted\""
        );
        assert_eq!(parsed["findings"][0]["unit"], "page");
        assert_eq!(parsed["findings"][0]["severity"], "error");
        assert_eq!(parsed["findings"][0]["status"], "findings");
        assert!(json.contains("café"), "{json}");
        assert!(json.contains("said \\\"none\\\""), "{json}");
    }

    #[test]
    fn counts_reconcile_with_ui_and_stable_identities() {
        let report = report();
        let urls = urls();
        let document = export_document(&report, &urls).unwrap();
        assert_eq!(document.findings.len(), report.findings.len());
        assert_eq!(document.outcomes.len(), report.outcomes.len());
        assert_eq!(document.findings[0].finding_id, report.findings[0].id.key());
        assert_eq!(
            document.coverage,
            ExportCoverage::from(CrawlCounters::from_records(&urls))
        );
        let csv = render_csv(&document).unwrap();
        let data_rows = csv.lines().skip(1).filter(|line| !line.is_empty()).count();
        assert_eq!(data_rows, document.findings.len());
    }

    #[test]
    fn credentials_are_not_exported() {
        let mut tainted = report();
        tainted.findings[0].fact = "sig1=:TESTSIGNATUREVALUE:".into();
        let err = export_document(&tainted, &urls()).unwrap_err();
        assert!(err.is_secrets(), "{err}");
        assert!(!err.to_string().contains("TESTSIGNATUREVALUE"), "{err}");

        let document = export_document(&report(), &urls()).unwrap();
        let csv = render_csv(&document).unwrap();
        let json = render_json(&document).unwrap();
        for body in [&csv, &json] {
            let lower = body.to_ascii_lowercase();
            assert!(!lower.contains("sig1="), "{body}");
            assert!(!lower.contains("signature-input:"), "{body}");
            assert!(!body.contains("CRAWL_SIGNATURE="), "{body}");
        }
    }

    #[test]
    fn importer_distinguishes_counts_and_records_unmatched_fields() {
        let csv = "Check,URL,Referrer,Unit,Severity,Observed at,Report,Current,New issues,Row kind,Notes,Extra\n\
Long title,,,page,warning,2026-09-14,Site Audit,73,78,aggregate,historical delta is separate,keep-me\n\
Long title,https://example.com/a,https://example.com/,page,warning,2026-09-14,Site Audit,,,entity,affected row,also-keep\n";
        let imported = import_baseline(csv.as_bytes(), "baseline.csv", &mapping()).unwrap();
        assert_eq!(imported.source_name, "baseline.csv");
        assert_eq!(
            imported.unmatched_columns,
            vec!["extra".to_string(), "notes".to_string()]
        );
        let aggregates: Vec<_> = imported.aggregate_rows().collect();
        let entities: Vec<_> = imported.entity_rows().collect();
        assert_eq!(aggregates.len(), 1);
        assert_eq!(entities.len(), 1);
        assert_eq!(aggregates[0].current_count, Some(73));
        assert_eq!(aggregates[0].historical_delta, Some(78));
        assert_ne!(aggregates[0].current_count, aggregates[0].historical_delta);
        assert!(aggregates[0].entity_url.is_none());
        assert_eq!(
            entities[0].entity_url.as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(
            entities[0].referrer_url.as_deref(),
            Some("https://example.com/")
        );
        assert_eq!(
            aggregates[0].unmatched.get("notes").map(String::as_str),
            Some("historical delta is separate")
        );
        assert_eq!(
            entities[0].unmatched.get("extra").map(String::as_str),
            Some("also-keep")
        );
    }

    #[test]
    fn xlsx_adapter_is_blocked_without_workbook_assumptions() {
        let bytes = b"PK\x03\x04not-a-real-workbook";
        let err = import_baseline(bytes, EXPECTED_SEMRUSH_EXPORT_NAME, &mapping()).unwrap_err();
        assert!(err.is_workbook_blocked(), "{err}");
        let text = err.to_string();
        assert!(text.contains(EXPECTED_SEMRUSH_EXPORT_NAME), "{text}");
        assert!(!text.to_ascii_lowercase().contains("issues"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("all issues"), "{text}");
    }

    #[test]
    fn write_export_roundtrip_without_secrets() {
        let document = export_document(&report(), &urls()).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "crawlytic-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let written = write_export(&dir, &document).unwrap();
        let csv = std::fs::read_to_string(&written.csv_path).unwrap();
        let json = std::fs::read_to_string(&written.json_path).unwrap();
        assert_eq!(csv, render_csv(&document).unwrap());
        assert_eq!(json, render_json(&document).unwrap());
        assert!(!csv.to_ascii_lowercase().contains("sig1="));
        assert!(!json.to_ascii_lowercase().contains("sig1="));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_does_not_modify_source_bytes() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "crawlytic-baseline-{}-{}.csv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let original = "Check,URL\nMissing title,https://example.com/\n";
        std::fs::write(&path, original).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let imported = import_baseline(&bytes, "fixture.csv", &mapping()).unwrap();
        assert_eq!(imported.entity_rows().count(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        let _ = std::fs::remove_file(&path);
    }
}
