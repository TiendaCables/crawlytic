//! Ecommerce structured-data validation with explicit coverage.
//!
//! JSON-LD is parsed. Microdata and RDFa are inventoried, not validated.
//! Syntax, vocabulary and search-feature layers are separate findings.
//! Local rules do not determine Google rich-result eligibility or appearance.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::extract::{ExtractedObservations, StructuredBlock, StructuredFormat};
use serde_json::{Map, Value};

/// Coverage and rule-set identity. Override is not offered: the set is explicit.
pub const STRUCTURED_DATA_VALIDATOR_VERSION: u32 = 1;
pub const VOCABULARY_RULE_VERSION: u32 = 1;
pub const SEARCH_FEATURE_RULE_VERSION: u32 = 1;

pub const JSON_LD_COVERAGE: &str = "json-ld";
pub const MICRODATA_COVERAGE: &str = "inventory-only";
pub const RDFA_COVERAGE: &str = "inventory-only";

const SCHEMA_ORG: &str = "https://schema.org/";
const SCHEMA_ORG_HTTP: &str = "http://schema.org/";
const DISCLAIMER: &str = "Local Crawlytic validation does not determine Google rich-result eligibility or actual search appearance.";
const SYNTAX_REF: &str = "https://www.w3.org/TR/json-ld11/";
const VOCAB_REF: &str = "https://schema.org/docs/gs.html";
const SEARCH_REF: &str =
    "https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data";
const MICRODATA_REF: &str = "https://html.spec.whatwg.org/multipage/microdata.html";
const RDFA_REF: &str = "https://www.w3.org/TR/rdfa-lite/";

const SUPPORTED_TYPES: &[&str] = &[
    "Product",
    "Offer",
    "AggregateOffer",
    "BreadcrumbList",
    "ListItem",
    "Organization",
];
const GENERIC_TYPES: &[&str] = &["Thing", "CreativeWork", "Intangible", "StructuredValue"];

pub fn structured_data_registry() -> Registry {
    let mut registry = Registry::new();
    register_structured_data(&mut registry);
    registry
}

pub fn register_structured_data(registry: &mut Registry) {
    registry.register(InvalidStructuredData);
}

struct InvalidStructuredData;

impl Checker for InvalidStructuredData {
    fn rule_id(&self) -> &'static str {
        "structured_data.invalid"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() {
            return incomplete();
        }
        let mut saw_complete = false;
        let mut saw_structured = false;
        let mut findings = Vec::new();
        for observation in evidence.observations {
            if !observation.page.is_complete() {
                continue;
            }
            saw_complete = true;
            if observation.page.structured.is_empty() {
                continue;
            }
            saw_structured = true;
            findings.extend(validate_page(observation));
        }
        if !saw_complete {
            return incomplete();
        }
        if !saw_structured {
            return not_applicable();
        }
        complete(findings)
    }
}

fn validate_page(observation: &ExtractedObservations) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    for block in &observation.page.structured {
        match block.format {
            StructuredFormat::JsonLd => findings.extend(validate_json_ld(observation, block)),
            StructuredFormat::Microdata => findings.push(unsupported_format(
                observation,
                block,
                "Microdata",
                MICRODATA_REF,
            )),
            StructuredFormat::Rdfa => {
                findings.push(unsupported_format(observation, block, "RDFa", RDFA_REF))
            }
        }
    }
    findings
}

fn validate_json_ld(
    observation: &ExtractedObservations,
    block: &StructuredBlock,
) -> Vec<FindingDraft> {
    let path = format!("jsonld[{}]", block.index);
    if block.raw.trim().is_empty() {
        return vec![syntax_finding(
            observation,
            &path,
            "JSON-LD script is empty.",
            block.raw.clone(),
        )];
    }
    match serde_json::from_str::<Value>(&block.raw) {
        Ok(value) => walk_top_level(observation, &path, &value),
        Err(err) => vec![syntax_finding(
            observation,
            &path,
            &format!("JSON-LD is not valid JSON ({err})."),
            excerpt_raw(&block.raw),
        )],
    }
}

fn walk_top_level(
    observation: &ExtractedObservations,
    path: &str,
    value: &Value,
) -> Vec<FindingDraft> {
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return vec![syntax_finding(
                    observation,
                    path,
                    "JSON-LD array is empty.",
                    "[]".into(),
                )];
            }
            items
                .iter()
                .enumerate()
                .flat_map(|(index, item)| {
                    walk_top_level(observation, &format!("{path}/{index}"), item)
                })
                .collect()
        }
        Value::Object(map) => {
            let mut findings = Vec::new();
            if let Some(graph) = map.get("@graph") {
                findings.extend(walk_top_level(
                    observation,
                    &format!("{path}/@graph"),
                    graph,
                ));
            }
            let types = node_types(map);
            if types.is_empty() {
                if !map.contains_key("@graph") {
                    findings.push(unsupported_type(
                        observation,
                        path,
                        "(missing @type)",
                        value,
                    ));
                }
                return findings;
            }
            let mut validated = false;
            for typ in &types {
                if is_generic_type(typ) {
                    continue;
                }
                if is_supported_type(typ) {
                    findings.extend(validate_supported(observation, path, typ, map));
                    validated = true;
                } else {
                    findings.push(unsupported_type(observation, path, typ, value));
                }
            }
            if !validated && types.iter().all(|typ| is_generic_type(typ)) {
                findings.push(unsupported_type(observation, path, &types.join(","), value));
            }
            findings
        }
        _ => vec![syntax_finding(
            observation,
            path,
            "JSON-LD root must be an object or array.",
            value.to_string(),
        )],
    }
}

fn validate_supported(
    observation: &ExtractedObservations,
    path: &str,
    typ: &str,
    map: &Map<String, Value>,
) -> Vec<FindingDraft> {
    match typ {
        "Product" => validate_product(observation, path, map),
        "Offer" => validate_offer(observation, path, map, false),
        "AggregateOffer" => validate_aggregate_offer(observation, path, map),
        "BreadcrumbList" => validate_breadcrumb(observation, path, map),
        "ListItem" => validate_list_item(observation, path, map, false),
        "Organization" => validate_organization(observation, path, map),
        _ => Vec::new(),
    }
}

fn validate_product(
    observation: &ExtractedObservations,
    path: &str,
    map: &Map<String, Value>,
) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    if !has_text(map, "name") {
        findings.push(vocab_missing(observation, path, "Product", "name", map));
    }
    if !has_image(map) {
        findings.push(search_missing(observation, path, "Product", "image", map));
    }
    let offers = property(map, "offers");
    let review = property(map, "review");
    let rating = property(map, "aggregateRating");
    if offers.is_none() && review.is_none() && rating.is_none() {
        findings.push(search_missing(
            observation,
            path,
            "Product",
            "offers|review|aggregateRating",
            map,
        ));
    }
    if let Some(offers) = offers {
        findings.extend(validate_offer_nodes(
            observation,
            &format!("{path}/offers"),
            offers,
        ));
    }
    findings
}

fn validate_offer_nodes(
    observation: &ExtractedObservations,
    path: &str,
    value: &Value,
) -> Vec<FindingDraft> {
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(index, item)| {
                validate_offer_nodes(observation, &format!("{path}/{index}"), item)
            })
            .collect(),
        Value::Object(map) => {
            let types = node_types(map);
            if types.iter().any(|typ| typ == "AggregateOffer") {
                validate_aggregate_offer(observation, path, map)
            } else if types.iter().any(|typ| typ == "Offer") || types.is_empty() {
                validate_offer(observation, path, map, types.is_empty())
            } else {
                types
                    .into_iter()
                    .filter(|typ| !is_generic_type(typ) && !is_supported_type(typ))
                    .map(|typ| unsupported_type(observation, path, &typ, value))
                    .collect()
            }
        }
        Value::String(_) => vec![vocab_missing(
            observation,
            path,
            "Offer",
            "@id-reference",
            value,
        )],
        _ => vec![vocab_missing(observation, path, "Offer", "object", value)],
    }
}

fn validate_offer(
    observation: &ExtractedObservations,
    path: &str,
    map: &Map<String, Value>,
    untyped: bool,
) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    if untyped {
        findings.push(unsupported_type(
            observation,
            path,
            "(missing @type)",
            &Value::Object(map.clone()),
        ));
    }
    if !has_text(map, "price") && !has_number(map, "price") {
        findings.push(vocab_missing(observation, path, "Offer", "price", map));
    }
    if !has_text(map, "priceCurrency") {
        findings.push(vocab_missing(
            observation,
            path,
            "Offer",
            "priceCurrency",
            map,
        ));
    }
    if !has_text(map, "availability") {
        findings.push(search_missing(
            observation,
            path,
            "Offer",
            "availability",
            map,
        ));
    }
    findings
}

fn validate_aggregate_offer(
    observation: &ExtractedObservations,
    path: &str,
    map: &Map<String, Value>,
) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    if !has_text(map, "lowPrice")
        && !has_number(map, "lowPrice")
        && !has_text(map, "price")
        && !has_number(map, "price")
    {
        findings.push(vocab_missing(
            observation,
            path,
            "AggregateOffer",
            "lowPrice",
            map,
        ));
    }
    if !has_text(map, "priceCurrency") {
        findings.push(vocab_missing(
            observation,
            path,
            "AggregateOffer",
            "priceCurrency",
            map,
        ));
    }
    findings
}

fn validate_breadcrumb(
    observation: &ExtractedObservations,
    path: &str,
    map: &Map<String, Value>,
) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    let Some(elements) = property(map, "itemListElement") else {
        findings.push(vocab_missing(
            observation,
            path,
            "BreadcrumbList",
            "itemListElement",
            map,
        ));
        return findings;
    };
    let items = match elements {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    if items.is_empty() {
        findings.push(vocab_missing(
            observation,
            path,
            "BreadcrumbList",
            "itemListElement",
            map,
        ));
        return findings;
    }
    let last = items.len() - 1;
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}/itemListElement/{index}");
        match item {
            Value::Object(item_map) => {
                findings.extend(validate_list_item(
                    observation,
                    &item_path,
                    item_map,
                    index == last,
                ));
            }
            _ => findings.push(vocab_missing(
                observation,
                &item_path,
                "ListItem",
                "object",
                item,
            )),
        }
    }
    findings
}

fn validate_list_item(
    observation: &ExtractedObservations,
    path: &str,
    map: &Map<String, Value>,
    last: bool,
) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    if !has_text(map, "name") && !has_item_name(map) {
        findings.push(vocab_missing(observation, path, "ListItem", "name", map));
    }
    if !has_text(map, "position") && !has_number(map, "position") {
        findings.push(vocab_missing(
            observation,
            path,
            "ListItem",
            "position",
            map,
        ));
    }
    if !last && !has_item_url(map) {
        findings.push(search_missing(observation, path, "ListItem", "item", map));
    }
    findings
}

fn validate_organization(
    observation: &ExtractedObservations,
    path: &str,
    map: &Map<String, Value>,
) -> Vec<FindingDraft> {
    let mut findings = Vec::new();
    if !has_text(map, "name") {
        findings.push(vocab_missing(
            observation,
            path,
            "Organization",
            "name",
            map,
        ));
    }
    if !has_text(map, "url") {
        findings.push(search_missing(
            observation,
            path,
            "Organization",
            "url",
            map,
        ));
    }
    findings
}

fn node_types(map: &Map<String, Value>) -> Vec<String> {
    match map.get("@type") {
        Some(Value::String(value)) => vec![normalize_type(value)],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(value_text)
            .map(|value| normalize_type(&value))
            .filter(|value| !value.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn normalize_type(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix(SCHEMA_ORG) {
        return rest.to_owned();
    }
    if let Some(rest) = trimmed.strip_prefix(SCHEMA_ORG_HTTP) {
        return rest.to_owned();
    }
    if let Some((_, local)) = trimmed.rsplit_once('/')
        && !local.is_empty()
    {
        return local.to_owned();
    }
    trimmed.to_owned()
}

fn is_supported_type(typ: &str) -> bool {
    SUPPORTED_TYPES.contains(&typ)
}

fn is_generic_type(typ: &str) -> bool {
    GENERIC_TYPES.contains(&typ)
}

fn property<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    map.get(name)
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Object(map) => map
            .get("@value")
            .and_then(value_text)
            .or_else(|| map.get("name").and_then(value_text))
            .or_else(|| map.get("url").and_then(value_text)),
        Value::Array(items) => items.iter().find_map(value_text),
        _ => None,
    }
}

fn has_text(map: &Map<String, Value>, name: &str) -> bool {
    map.get(name).and_then(value_text).is_some()
}

fn has_number(map: &Map<String, Value>, name: &str) -> bool {
    matches!(map.get(name), Some(Value::Number(_)))
}

fn has_image(map: &Map<String, Value>) -> bool {
    match map.get("image") {
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(Value::Array(items)) => items.iter().any(|item| value_text(item).is_some()),
        Some(Value::Object(image)) => {
            has_text(image, "url")
                || has_text(image, "contentUrl")
                || value_text(&Value::Object(image.clone())).is_some()
        }
        _ => false,
    }
}

fn has_item_name(map: &Map<String, Value>) -> bool {
    match map.get("item") {
        Some(Value::Object(item)) => has_text(item, "name"),
        _ => false,
    }
}

fn has_item_url(map: &Map<String, Value>) -> bool {
    match map.get("item") {
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(Value::Object(item)) => {
            has_text(item, "url") || has_text(item, "@id") || has_text(item, "name")
        }
        Some(Value::Array(items)) => items.iter().any(|item| value_text(item).is_some()),
        _ => false,
    }
}

fn excerpt_raw(raw: &str) -> String {
    raw.chars().take(160).collect()
}

fn excerpt_value(value: &Value) -> String {
    let rendered = value.to_string();
    rendered.chars().take(160).collect()
}

fn pointer(
    observation: &ExtractedObservations,
    field: &str,
    excerpt: impl Into<String>,
) -> EvidencePointer {
    EvidencePointer {
        observation_identity: observation.identity.clone(),
        field: field.to_owned(),
        excerpt: excerpt.into(),
    }
}

fn syntax_finding(
    observation: &ExtractedObservations,
    path: &str,
    fact: &str,
    excerpt: String,
) -> FindingDraft {
    FindingDraft {
        entity_key: format!("{} {path} syntax", observation.identity),
        fact: format!(
            "JSON syntax (validator v{STRUCTURED_DATA_VALIDATOR_VERSION}, {JSON_LD_COVERAGE}): {fact}"
        ),
        recommendation: format!(
            "Fix the JSON-LD syntax so the block parses. Source: {SYNTAX_REF}. {DISCLAIMER}"
        ),
        evidence: vec![pointer(observation, path, excerpt)],
    }
}

fn vocab_missing(
    observation: &ExtractedObservations,
    path: &str,
    typ: &str,
    field: &str,
    value: impl ValueExcerpt,
) -> FindingDraft {
    let field_path = format!("{path}.{field}");
    FindingDraft {
        entity_key: format!("{} {field_path}", observation.identity),
        fact: format!(
            "Vocabulary rule v{VOCABULARY_RULE_VERSION} ({typ}): missing '{field}' at {field_path}."
        ),
        recommendation: format!(
            "Add the required {typ} property '{field}'. Coverage is limited to Product, Offer, BreadcrumbList and Organization. Source: {VOCAB_REF}. {DISCLAIMER}"
        ),
        evidence: vec![pointer(observation, &field_path, value.excerpt())],
    }
}

fn search_missing(
    observation: &ExtractedObservations,
    path: &str,
    typ: &str,
    field: &str,
    value: impl ValueExcerpt,
) -> FindingDraft {
    let field_path = format!("{path}.{field}");
    FindingDraft {
        entity_key: format!("{} {field_path} search", observation.identity),
        fact: format!(
            "Search-feature rule v{SEARCH_FEATURE_RULE_VERSION} ({typ}): missing '{field}' at {field_path}."
        ),
        recommendation: format!(
            "Add '{field}' if you are targeting that search feature. This local rule is not a Google eligibility or appearance result. Source: {SEARCH_REF}. {DISCLAIMER}"
        ),
        evidence: vec![pointer(observation, &field_path, value.excerpt())],
    }
}

fn unsupported_format(
    observation: &ExtractedObservations,
    block: &StructuredBlock,
    label: &str,
    reference: &str,
) -> FindingDraft {
    let path = format!("{}[{}]", block.format.as_str(), block.index);
    let types = if block.types.is_empty() {
        "untyped".to_owned()
    } else {
        block.types.join(", ")
    };
    FindingDraft {
        entity_key: format!("{} {path} format", observation.identity),
        fact: format!(
            "{label} {types} at {path} is inventoried only ({}) under validator v{STRUCTURED_DATA_VALIDATOR_VERSION}; it is not JSON-LD-validated.",
            if block.format == StructuredFormat::Microdata {
                MICRODATA_COVERAGE
            } else {
                RDFA_COVERAGE
            }
        ),
        recommendation: format!(
            "Provide JSON-LD for Product, Offer, BreadcrumbList or Organization, or treat this {label} block as uncovered. Source: {reference}. {DISCLAIMER}"
        ),
        evidence: vec![pointer(
            observation,
            &path,
            if block.types.is_empty() {
                label.to_owned()
            } else {
                types
            },
        )],
    }
}

fn unsupported_type(
    observation: &ExtractedObservations,
    path: &str,
    typ: &str,
    value: &Value,
) -> FindingDraft {
    FindingDraft {
        entity_key: format!("{} {path} type={typ}", observation.identity),
        fact: format!(
            "Type '{typ}' at {path} is outside JSON-LD coverage v{STRUCTURED_DATA_VALIDATOR_VERSION} (Product, Offer, BreadcrumbList, Organization)."
        ),
        recommendation: format!(
            "This type is visible and not passed. Supported JSON-LD types are Product, Offer, AggregateOffer, BreadcrumbList, ListItem and Organization. Source: {VOCAB_REF}. {DISCLAIMER}"
        ),
        evidence: vec![pointer(observation, path, excerpt_value(value))],
    }
}

trait ValueExcerpt {
    fn excerpt(&self) -> String;
}

impl ValueExcerpt for &Map<String, Value> {
    fn excerpt(&self) -> String {
        excerpt_value(&Value::Object((*self).clone()))
    }
}

impl ValueExcerpt for &Value {
    fn excerpt(&self) -> String {
        excerpt_value(self)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::RuleState;
    use crate::extract::{ExtractInput, extract};
    use crate::profile::Profile;
    use crate::store::Store;
    use url::Url;

    fn page(url: &str, body: &str) -> ExtractedObservations {
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

    fn truncated(url: &str, body: &str) -> ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status: 200,
            content_type: "text/html",
            headers: &[],
            body: body.as_bytes(),
            truncated: true,
            duration_ms: Some(1),
        })
    }

    fn script(json: &str) -> String {
        format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <script type="application/ld+json">{json}</script>
            </head><body><h1>Product</h1></body></html>"#
        )
    }

    fn run(obs: &[ExtractedObservations]) -> AuditReport {
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
            &AuditConfig::default(),
            &structured_data_registry(),
            &[],
        )
    }

    fn findings(report: &AuditReport) -> Vec<&crate::audit::Finding> {
        report.findings_for("structured_data.invalid").collect()
    }

    fn valid_product() -> &'static str {
        r#"{
            "@context": "https://schema.org",
            "@type": "Product",
            "name": "USB-C cable",
            "image": "https://audit.example/usb.png",
            "offers": {
                "@type": "Offer",
                "price": "9.99",
                "priceCurrency": "EUR",
                "availability": "https://schema.org/InStock"
            }
        }"#
    }

    #[test]
    fn arrays_graph_and_multiple_offers_are_validated() {
        let json = r#"{
            "@context": "https://schema.org",
            "@graph": [
                {
                    "@type": "Organization",
                    "name": "Tienda Cables",
                    "url": "https://audit.example/"
                },
                {
                    "@type": "Product",
                    "name": "USB-C cable",
                    "image": "https://audit.example/usb.png",
                    "offers": [
                        {"@type": "Offer", "price": "9.99", "priceCurrency": "EUR",
                         "availability": "https://schema.org/InStock"},
                        {"@type": "Offer", "price": "8.50", "priceCurrency": "EUR",
                         "availability": "https://schema.org/InStock"}
                    ]
                }
            ]
        }"#;
        let report = run(&[page("https://audit.example/product", &script(json))]);
        assert_eq!(
            report.outcome("structured_data.invalid"),
            Some(RuleState::Passed)
        );
        assert!(findings(&report).is_empty());

        let array =
            r#"[{"@type":"Organization","name":"Tienda Cables","url":"https://audit.example/"}]"#;
        let report = run(&[page("https://audit.example/org", &script(array))]);
        assert_eq!(
            report.outcome("structured_data.invalid"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn malformed_json_and_missing_required_properties_point_at_type_path_and_field() {
        let malformed = run(&[page(
            "https://audit.example/product",
            &script(r#"{ "name": "#),
        )]);
        assert_eq!(
            malformed.outcome("structured_data.invalid"),
            Some(RuleState::Findings)
        );
        let malformed_findings = findings(&malformed);
        let syntax = malformed_findings
            .iter()
            .find(|finding| finding.fact.contains("JSON syntax"))
            .unwrap();
        assert!(syntax.id.entity_key.contains("jsonld[0]"));
        assert!(
            syntax
                .evidence
                .iter()
                .any(|pointer| pointer.field == "jsonld[0]")
        );
        assert!(syntax.recommendation.contains(DISCLAIMER));

        let missing = run(&[page(
            "https://audit.example/product",
            &script(r#"{"@type":"Product","offers":{"@type":"Offer","priceCurrency":"EUR"}}"#),
        )]);
        let facts: Vec<_> = findings(&missing)
            .iter()
            .map(|finding| finding.fact.as_str())
            .collect();
        assert!(
            facts
                .iter()
                .any(|fact| fact.contains("Product") && fact.contains("name")),
            "{facts:?}"
        );
        assert!(
            facts
                .iter()
                .any(|fact| fact.contains("Offer") && fact.contains("price")),
            "{facts:?}"
        );
        assert!(findings(&missing).iter().any(|finding| {
            finding
                .evidence
                .iter()
                .any(|pointer| pointer.field.contains("Product") || pointer.field.contains("name"))
        }));
        assert!(
            findings(&missing)
                .iter()
                .all(|finding| finding.recommendation.contains(DISCLAIMER))
        );
        assert!(findings(&missing).iter().all(|finding| {
            !finding
                .recommendation
                .to_ascii_lowercase()
                .contains("will appear")
                && !finding
                    .fact
                    .to_ascii_lowercase()
                    .contains("rich result eligibility")
        }));
    }

    #[test]
    fn unsupported_formats_and_types_are_visible_not_passed() {
        let microdata = page(
            "https://audit.example/product",
            r#"<!DOCTYPE html><html><body>
              <div itemscope itemtype="https://schema.org/Product">
                <span itemprop="name">HDMI cable</span>
              </div>
            </body></html>"#,
        );
        let report = run(&[microdata]);
        assert_eq!(
            report.outcome("structured_data.invalid"),
            Some(RuleState::Findings)
        );
        let finding = findings(&report)[0];
        assert!(finding.fact.contains("Microdata"));
        assert!(finding.fact.contains("inventoried"));
        assert!(finding.id.entity_key.contains("microdata[0]"));
        assert!(finding.recommendation.contains(DISCLAIMER));

        let rdfa = page(
            "https://audit.example/org",
            r#"<!DOCTYPE html><html><body>
              <div vocab="https://schema.org/" typeof="Organization">
                <span property="name">Tienda Cables</span>
              </div>
            </body></html>"#,
        );
        let report = run(&[rdfa]);
        assert_eq!(
            report.outcome("structured_data.invalid"),
            Some(RuleState::Findings)
        );
        assert!(findings(&report)[0].fact.contains("RDFa"));

        let faq = run(&[page(
            "https://audit.example/faq",
            &script(r#"{"@type":"FAQPage","mainEntity":[]}"#),
        )]);
        assert_eq!(
            faq.outcome("structured_data.invalid"),
            Some(RuleState::Findings)
        );
        let finding = findings(&faq)[0];
        assert!(finding.fact.contains("FAQPage"));
        assert!(finding.id.entity_key.contains("type=FAQPage"));
        assert!(finding.recommendation.contains("not passed"));
    }

    #[test]
    fn valid_json_ld_does_not_claim_google_appearance() {
        let report = run(&[page(
            "https://audit.example/product",
            &script(valid_product()),
        )]);
        assert_eq!(
            report.outcome("structured_data.invalid"),
            Some(RuleState::Passed)
        );
        assert!(findings(&report).is_empty());
        assert_eq!(STRUCTURED_DATA_VALIDATOR_VERSION, 1);
        assert_eq!(JSON_LD_COVERAGE, "json-ld");
        assert_eq!(MICRODATA_COVERAGE, "inventory-only");
        assert_eq!(RDFA_COVERAGE, "inventory-only");
    }

    #[test]
    fn incomplete_html_is_incomplete_and_no_markup_is_not_applicable() {
        let empty = run(&[]);
        assert_eq!(
            empty.outcome("structured_data.invalid"),
            Some(RuleState::Incomplete)
        );
        let truncated = run(&[truncated(
            "https://audit.example/product",
            &script(valid_product()),
        )]);
        assert_eq!(
            truncated.outcome("structured_data.invalid"),
            Some(RuleState::Incomplete)
        );
        let none = run(&[page(
            "https://audit.example/p",
            "<html><head><title>A</title></head><body>Hi</body></html>",
        )]);
        assert_eq!(
            none.outcome("structured_data.invalid"),
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
                &page("https://audit.example/product", &script(r#"{ "name": "#)),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &structured_data_registry(),
        )
        .unwrap();
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &structured_data_registry(),
        )
        .unwrap();
        assert_eq!(
            first.outcome("structured_data.invalid"),
            Some(RuleState::Findings)
        );
        assert_eq!(first.findings, second.findings);
        assert!(
            first
                .findings_for("structured_data.invalid")
                .all(
                    |finding| !finding.fact.to_ascii_lowercase().contains("signature")
                        && !finding.recommendation.contains("CRAWL_")
                )
        );
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(&[page(
            "https://audit.example/product",
            &script(valid_product()),
        )]);
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
    }
}
