//! Exact and near-duplicate page content checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::crawl::UrlState;
use crate::extract::ExtractedObservations;
use std::collections::{BTreeMap, BTreeSet};

/// Crawlytic heuristic, not a Semrush formula. Override with
/// `near_duplicate_max_hamming`.
pub const DEFAULT_NEAR_DUPLICATE_MAX_HAMMING: u32 = 3;
/// Recurring navigation shingles must appear on at least this many pages.
/// Override with `boilerplate_min_pages`.
pub const DEFAULT_BOILERPLATE_MIN_PAGES: usize = 3;
/// Near-duplicate comparison is skipped when remaining tokens fall below this.
/// Override with `min_main_tokens`.
pub const DEFAULT_MIN_MAIN_TOKENS: usize = 12;
const SHINGLE_SIZE: usize = 5;
const LSH_BANDS: usize = 4;
const LSH_BAND_BITS: u32 = 16;

pub fn content_registry() -> Registry {
    let mut registry = Registry::new();
    register_content(&mut registry);
    registry
}

pub fn register_content(registry: &mut Registry) {
    registry.register(DuplicateContent);
}

struct DuplicateContent;

struct ClusterStats {
    groups: Vec<DuplicateGroup>,
    #[allow(dead_code)]
    candidate_pairs: usize,
}

struct DuplicateGroup {
    method: DuplicateMethod,
    members: Vec<usize>,
    fingerprint: String,
    hamming: Option<u32>,
}

#[derive(Clone, Copy)]
enum DuplicateMethod {
    ExactHash,
    Simhash,
}

impl DuplicateMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactHash => "exact_hash",
            Self::Simhash => "simhash",
        }
    }
}

struct PreparedPage {
    remaining: String,
    tokens: Vec<String>,
    fingerprint: String,
    simhash: u64,
}

fn cluster_duplicates(pages: &[&ExtractedObservations], config: &AuditConfig) -> ClusterStats {
    let boilerplate_min_pages = usize_threshold(
        config,
        "boilerplate_min_pages",
        DEFAULT_BOILERPLATE_MIN_PAGES,
    );
    let min_main_tokens = usize_threshold(config, "min_main_tokens", DEFAULT_MIN_MAIN_TOKENS);
    let max_hamming = u32_threshold(
        config,
        "near_duplicate_max_hamming",
        DEFAULT_NEAR_DUPLICATE_MAX_HAMMING,
    );

    let tokenized: Vec<Vec<String>> = pages.iter().map(|page| tokenize(&page.page.text)).collect();
    let boilerplate = boilerplate_shingles(&tokenized, boilerplate_min_pages);
    let prepared: Vec<Option<PreparedPage>> = tokenized
        .iter()
        .map(|tokens| {
            let remaining_tokens = strip_boilerplate(tokens, &boilerplate);
            if remaining_tokens.is_empty() {
                return None;
            }
            let remaining = remaining_tokens.join(" ");
            let fingerprint = format!("{:016x}", fnv1a64(remaining.as_bytes()));
            let simhash = simhash(&remaining_tokens);
            Some(PreparedPage {
                remaining,
                tokens: remaining_tokens,
                fingerprint,
                simhash,
            })
        })
        .collect();

    let mut exact: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (idx, page) in prepared.iter().enumerate() {
        if let Some(page) = page {
            exact.entry(page.remaining.as_str()).or_default().push(idx);
        }
    }

    let mut groups = Vec::new();
    let mut in_exact = vec![false; pages.len()];
    for members in exact.values() {
        if members.len() < 2 {
            continue;
        }
        for &idx in members {
            in_exact[idx] = true;
        }
        let fingerprint = prepared[members[0]]
            .as_ref()
            .map(|page| page.fingerprint.clone())
            .unwrap_or_default();
        groups.push(DuplicateGroup {
            method: DuplicateMethod::ExactHash,
            members: members.clone(),
            fingerprint,
            hamming: None,
        });
    }

    let near_indices: Vec<usize> = prepared
        .iter()
        .enumerate()
        .filter(|(idx, page)| {
            !in_exact[*idx]
                && page
                    .as_ref()
                    .is_some_and(|page| page.tokens.len() >= min_main_tokens)
        })
        .map(|(idx, _)| idx)
        .collect();

    let (candidate_pairs, near_groups) =
        banded_near_duplicates(&prepared, &near_indices, max_hamming);
    groups.extend(near_groups);
    for group in &mut groups {
        group
            .members
            .sort_by(|&a, &b| pages[a].identity.cmp(&pages[b].identity));
    }
    groups.sort_by(|a, b| {
        a.fingerprint
            .cmp(&b.fingerprint)
            .then(a.method.as_str().cmp(b.method.as_str()))
    });
    ClusterStats {
        groups,
        candidate_pairs,
    }
}

fn banded_near_duplicates(
    prepared: &[Option<PreparedPage>],
    indices: &[usize],
    max_hamming: u32,
) -> (usize, Vec<DuplicateGroup>) {
    let mut buckets: BTreeMap<(usize, u16), Vec<usize>> = BTreeMap::new();
    for &idx in indices {
        let Some(page) = prepared[idx].as_ref() else {
            continue;
        };
        for (band, key) in band_keys(page.simhash).into_iter().enumerate() {
            buckets.entry((band, key)).or_default().push(idx);
        }
    }

    let mut uf = UnionFind::new(prepared.len());
    let mut compared = BTreeSet::new();
    let mut pair_hamming: BTreeMap<(usize, usize), u32> = BTreeMap::new();
    for members in buckets.values() {
        if members.len() < 2 {
            continue;
        }
        let mut unique = members.clone();
        unique.sort_unstable();
        unique.dedup();
        for i in 0..unique.len() {
            for j in (i + 1)..unique.len() {
                let a = unique[i].min(unique[j]);
                let b = unique[i].max(unique[j]);
                if !compared.insert((a, b)) {
                    continue;
                }
                let Some(left) = prepared[a].as_ref() else {
                    continue;
                };
                let Some(right) = prepared[b].as_ref() else {
                    continue;
                };
                let distance = (left.simhash ^ right.simhash).count_ones();
                pair_hamming.insert((a, b), distance);
                if distance <= max_hamming {
                    uf.union(a, b);
                }
            }
        }
    }

    let mut clustered: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &idx in indices {
        clustered.entry(uf.find(idx)).or_default().push(idx);
    }
    let mut groups = Vec::new();
    for mut members in clustered.into_values() {
        if members.len() < 2 {
            continue;
        }
        members.sort_unstable();
        let mut hamming = 0;
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                let key = (members[i], members[j]);
                hamming = hamming.max(pair_hamming.get(&key).copied().unwrap_or(u32::MAX));
            }
        }
        let fingerprint = prepared[members[0]]
            .as_ref()
            .map(|page| format!("{:016x}", page.simhash))
            .unwrap_or_default();
        groups.push(DuplicateGroup {
            method: DuplicateMethod::Simhash,
            members,
            fingerprint,
            hamming: Some(hamming),
        });
    }
    (compared.len(), groups)
}

fn band_keys(hash: u64) -> [u16; LSH_BANDS] {
    let mask = (1u64 << LSH_BAND_BITS) - 1;
    std::array::from_fn(|band| ((hash >> (band as u32 * LSH_BAND_BITS)) & mask) as u16)
}

fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn boilerplate_shingles(pages: &[Vec<String>], min_pages: usize) -> BTreeSet<String> {
    if pages.len() < min_pages {
        return BTreeSet::new();
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for tokens in pages {
        let mut seen = BTreeSet::new();
        if tokens.len() < SHINGLE_SIZE {
            continue;
        }
        for window in tokens.windows(SHINGLE_SIZE) {
            let key = window.join(" ");
            if seen.insert(key.clone()) {
                *counts.entry(key).or_insert(0) += 1;
            }
        }
    }
    counts
        .into_iter()
        .filter(|(_, count)| *count >= min_pages)
        .map(|(key, _)| key)
        .collect()
}

fn strip_boilerplate(tokens: &[String], boilerplate: &BTreeSet<String>) -> Vec<String> {
    if boilerplate.is_empty() || tokens.len() < SHINGLE_SIZE {
        return tokens.to_vec();
    }
    let mut drop = vec![false; tokens.len()];
    for (i, window) in tokens.windows(SHINGLE_SIZE).enumerate() {
        if boilerplate.contains(&window.join(" ")) {
            for slot in drop.iter_mut().skip(i).take(SHINGLE_SIZE) {
                *slot = true;
            }
        }
    }
    tokens
        .iter()
        .enumerate()
        .filter(|(idx, _)| !drop[*idx])
        .map(|(_, token)| token.clone())
        .collect()
}

fn simhash(tokens: &[String]) -> u64 {
    let mut votes = [0i32; 64];
    for token in tokens {
        let hash = fnv1a64(token.as_bytes());
        for (bit, vote) in votes.iter_mut().enumerate() {
            if (hash >> bit) & 1 == 1 {
                *vote += 1;
            } else {
                *vote -= 1;
            }
        }
    }
    let mut out = 0u64;
    for (bit, vote) in votes.iter().enumerate() {
        if *vote >= 0 {
            out |= 1 << bit;
        }
    }
    out
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, mut i: usize) -> usize {
        while self.parent[i] != i {
            self.parent[i] = self.parent[self.parent[i]];
            i = self.parent[i];
        }
        i
    }

    fn union(&mut self, a: usize, b: usize) {
        let mut ra = self.find(a);
        let mut rb = self.find(b);
        if ra == rb {
            return;
        }
        if self.rank[ra] < self.rank[rb] {
            std::mem::swap(&mut ra, &mut rb);
        }
        self.parent[rb] = ra;
        if self.rank[ra] == self.rank[rb] {
            self.rank[ra] += 1;
        }
    }
}

fn usize_threshold(config: &AuditConfig, key: &str, default: usize) -> usize {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn u32_threshold(config: &AuditConfig, key: &str, default: u32) -> u32 {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn eligible_pages<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    let blocked = blocked_identities(evidence);
    evidence
        .observations
        .iter()
        .filter(|observation| {
            observation.page.is_complete() && !blocked.contains(observation.identity.as_str())
        })
        .collect()
}

fn blocked_identities<'a>(evidence: &'a EvidenceBundle<'_>) -> BTreeSet<&'a str> {
    evidence
        .urls
        .iter()
        .filter(|url| url.state == UrlState::Blocked)
        .flat_map(|url| {
            let identity = url.identity.as_ref().map(|id| id.as_str());
            [Some(url.original.as_str()), identity]
        })
        .flatten()
        .collect()
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

fn incomplete() -> CheckerOutput {
    CheckerOutput {
        applicable: true,
        evidence_complete: false,
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

fn group_finding(
    pages: &[&ExtractedObservations],
    group: &DuplicateGroup,
    config: &AuditConfig,
) -> FindingDraft {
    let max_hamming = u32_threshold(
        config,
        "near_duplicate_max_hamming",
        DEFAULT_NEAR_DUPLICATE_MAX_HAMMING,
    );
    let boilerplate_min_pages = usize_threshold(
        config,
        "boilerplate_min_pages",
        DEFAULT_BOILERPLATE_MIN_PAGES,
    );
    let min_main_tokens = usize_threshold(config, "min_main_tokens", DEFAULT_MIN_MAIN_TOKENS);
    let members: Vec<_> = group
        .members
        .iter()
        .filter_map(|&idx| pages.get(idx).copied())
        .collect();
    let contexts: Vec<_> = members.iter().map(|page| page_context(page)).collect();
    let method = group.method.as_str();
    let hamming = group
        .hamming
        .map(|value| format!(" hamming={value}"))
        .unwrap_or_default();
    let fact = format!(
        "{n} pages share duplicate main content (method={method} fingerprint={}{hamming}) after chrome-tag omission, trim-and-collapse-whitespace normalization, and recurring {SHINGLE_SIZE}-gram boilerplate removal (boilerplate_min_pages={boilerplate_min_pages}). Near-duplicate uses 64-bit simhash with {LSH_BANDS}×{LSH_BAND_BITS}-bit LSH bands so comparisons stay bounded; grouping is transitive and uncertain. Affected URLs with canonical/indexability context: {}.",
        group.fingerprint,
        contexts.join("; "),
        n = members.len()
    );
    let recommendation = format!(
        "Give each indexable URL unique main content or consolidate with a canonical. Thresholds: near_duplicate_max_hamming={max_hamming}, boilerplate_min_pages={boilerplate_min_pages}, min_main_tokens={min_main_tokens}. Crawlytic heuristic, not a Semrush formula."
    );
    let mut evidence = Vec::new();
    for &idx in &group.members {
        let Some(page) = pages.get(idx).copied() else {
            continue;
        };
        evidence.push(pointer(page, "content_hash", group.fingerprint.clone()));
        if let Some(distance) = group.hamming {
            evidence.push(pointer(page, "simhash_hamming", distance.to_string()));
        }
        evidence.push(pointer(page, "method", method));
    }
    let prefix = match group.method {
        DuplicateMethod::ExactHash => "exact",
        DuplicateMethod::Simhash => "near",
    };
    FindingDraft {
        entity_key: format!("{prefix}:{}", group.fingerprint),
        fact,
        recommendation,
        evidence,
    }
}

impl Checker for DuplicateContent {
    fn rule_id(&self) -> &'static str {
        "content.duplicate"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let pages = eligible_pages(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let stats = cluster_duplicates(&pages, config);
        let findings = stats
            .groups
            .iter()
            .map(|group| group_finding(&pages, group, config))
            .collect();
        complete(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::RuleState;
    use crate::crawl::UrlRecord;
    use crate::extract::{ExtractInput, extract};
    use crate::profile::Profile;
    use crate::store::Store;
    use url::Url;

    fn page(url: &str, body: &str) -> ExtractedObservations {
        page_status(url, 200, "text/html", body.as_bytes(), false)
    }

    fn page_status(
        url: &str,
        status: u16,
        content_type: &str,
        body: &[u8],
        truncated: bool,
    ) -> ExtractedObservations {
        let destination_url = Url::parse(url).unwrap();
        extract(&ExtractInput {
            destination_url: &destination_url,
            status,
            content_type,
            headers: &[],
            body,
            truncated,
            duration_ms: Some(1),
        })
    }

    fn config() -> AuditConfig {
        AuditConfig::default()
    }

    fn run(obs: &[ExtractedObservations]) -> AuditReport {
        run_with_urls(obs, &[])
    }

    fn run_with_urls(obs: &[ExtractedObservations], urls: &[UrlRecord]) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls,
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: &[],
                tls_inspections: &[],
                host_probes: &[],
                start_url: None,
            },
            &config(),
            &content_registry(),
            &[],
        )
    }

    fn chrome() -> &'static str {
        r#"<nav><a href="/">Home</a> Shop Cart Account Help Blog Contact FAQs Warranty</nav>
        <header>Tienda Cables online store banner</header>
        <footer>Shipping Returns Privacy Cookies Terms Help desk hours</footer>"#
    }

    fn product(url: &str, name: &str, description: &str) -> ExtractedObservations {
        page(
            url,
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8">
                <title>{name}</title>
                <link rel="canonical" href="{url}">
                </head><body>
                {chrome}
                <main><h1>{name}</h1><p>{description}</p></main>
                </body></html>"#,
                chrome = chrome()
            ),
        )
    }

    fn article(url: &str, body: &str, canonical: &str, noindex: bool) -> ExtractedObservations {
        let robots = if noindex {
            r#"<meta name="robots" content="noindex">"#
        } else {
            ""
        };
        page(
            url,
            &format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8">
                <title>Guide</title>
                <link rel="canonical" href="{canonical}">
                {robots}
                </head><body>
                {chrome}
                <main><h1>Guide</h1><p>{body}</p></main>
                </body></html>"#,
                chrome = chrome()
            ),
        )
    }

    const SHARED_ARTICLE: &str = "Copper strands carry current through PVC jackets designed for indoor routing between consumer units and socket outlets across a typical dwelling. Installers should isolate the circuit, confirm conductor size against the load, and label both ends before closing the enclosure. Replacement is only needed when insulation cracks or the protective earth continuity fails a measured test.";

    #[test]
    fn copied_pages_form_an_exact_group_with_method_and_context() {
        let a = article(
            "https://audit.example/copy-a",
            SHARED_ARTICLE,
            "https://audit.example/copy-a",
            false,
        );
        let b = article(
            "https://audit.example/copy-b",
            SHARED_ARTICLE,
            "/copy-a",
            true,
        );
        let report = run(&[a, b]);
        assert_eq!(
            report.outcome("content.duplicate"),
            Some(RuleState::Findings)
        );
        let findings: Vec<_> = report.findings_for("content.duplicate").collect();
        assert_eq!(findings.len(), 1);
        let finding = findings[0];
        assert!(
            finding.fact.contains("method=exact_hash"),
            "{}",
            finding.fact
        );
        assert!(finding.fact.contains("indexable"), "{}", finding.fact);
        assert!(finding.fact.contains("noindex"), "{}", finding.fact);
        assert!(finding.fact.contains("canonical="), "{}", finding.fact);
        assert!(finding.id.entity_key.starts_with("exact:"));
        assert_eq!(
            report.affected_identities("content.duplicate"),
            vec![
                "https://audit.example/copy-a",
                "https://audit.example/copy-b"
            ]
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|pointer| pointer.field == "content_hash")
        );
        assert!(
            finding
                .recommendation
                .contains("near_duplicate_max_hamming=")
        );
    }

    #[test]
    fn distinct_products_sharing_a_template_are_not_duplicates() {
        let usb = product(
            "https://audit.example/usb-c-2m",
            "USB-C 2m nylon braided cable black",
            "This two-metre USB-C lead uses 20 AWG power conductors and a foil-plus-braid shield so laptops can draw 60 watts without dropping the data lanes. The nylon jacket is rated for repeated coiling in a toolkit, and the moulded strain relief is tested to 5000 bends.",
        );
        let hdmi = product(
            "https://audit.example/hdmi-3m",
            "HDMI 2.1 3m ultra high speed cable",
            "The three-metre HDMI 2.1 assembly carries 48 Gbps for 4K 120 Hz and eARC, with an aluminium shell and ferrite near the source end. Colour space remains 4:4:4 when the source and display both advertise the full bandwidth.",
        );
        let ethernet = product(
            "https://audit.example/cat6-5m",
            "Cat6 UTP 5m patch lead LSZH",
            "A five-metre Cat6 unshielded patch lead with LSZH jacket for risers, 24 AWG solid cores, and snagless boots. Insertion loss stays within class E up to 250 MHz in the factory sweep.",
        );
        let report = run(&[usb, hdmi, ethernet]);
        assert_eq!(report.outcome("content.duplicate"), Some(RuleState::Passed));
        assert!(report.findings_for("content.duplicate").next().is_none());
    }

    #[test]
    fn boilerplate_heavy_pages_with_unique_main_copy_are_not_grouped() {
        let pages: Vec<_> = ["alpha", "bravo", "charlie"]
            .into_iter()
            .map(|name| {
                product(
                    &format!("https://audit.example/{name}"),
                    &format!("Unique {name} product heading for this SKU"),
                    &format!(
                        "Body copy for {name} describes a distinct accessory with measurements, materials, and a warranty clause that does not appear on sibling SKUs."
                    ),
                )
            })
            .collect();
        let report = run(&pages);
        assert_eq!(report.outcome("content.duplicate"), Some(RuleState::Passed));
    }

    #[test]
    fn near_duplicates_report_simhash_hamming_evidence() {
        let a = article(
            "https://audit.example/near-a",
            SHARED_ARTICLE,
            "https://audit.example/near-a",
            false,
        );
        let tweaked = SHARED_ARTICLE.replace("dwelling", "residence");
        let b = article(
            "https://audit.example/near-b",
            &tweaked,
            "https://audit.example/near-b",
            false,
        );
        let report = run(&[a, b]);
        assert_eq!(
            report.outcome("content.duplicate"),
            Some(RuleState::Findings)
        );
        let finding = report.findings_for("content.duplicate").next().unwrap();
        assert!(finding.fact.contains("method=simhash"), "{}", finding.fact);
        assert!(finding.fact.contains("hamming="), "{}", finding.fact);
        assert!(finding.id.entity_key.starts_with("near:"));
        assert!(
            finding
                .recommendation
                .contains("Crawlytic heuristic, not a Semrush formula")
        );
    }

    #[test]
    fn truncated_non_html_and_blocked_responses_never_enter_groups() {
        let copied = article(
            "https://audit.example/ok-copy",
            SHARED_ARTICLE,
            "https://audit.example/ok-copy",
            false,
        );
        let truncated = page_status(
            "https://audit.example/truncated",
            200,
            "text/html",
            format!(
                "<!DOCTYPE html><html><body>{chrome}<main><p>{SHARED_ARTICLE}</p></main></body></html>",
                chrome = chrome()
            )
            .as_bytes(),
            true,
        );
        let json = page_status(
            "https://audit.example/json",
            200,
            "application/json",
            br#"{"text":"Copper strands carry current through PVC jackets"}"#,
            false,
        );
        let forbidden = page_status(
            "https://audit.example/forbidden",
            403,
            "text/html",
            format!(
                "<!DOCTYPE html><html><body>{chrome}<main><p>{SHARED_ARTICLE}</p></main></body></html>",
                chrome = chrome()
            )
            .as_bytes(),
            false,
        );
        let challenge = page_status(
            "https://audit.example/challenge",
            200,
            "text/html",
            b"<html><title>Just a moment</title><body>cf-chl-bypass</body></html>",
            false,
        );
        let blocked_obs = article(
            "https://audit.example/blocked",
            SHARED_ARTICLE,
            "https://audit.example/blocked",
            false,
        );
        let urls = [UrlRecord {
            original: "https://audit.example/blocked".into(),
            identity: None,
            state: UrlState::Blocked,
            reason: "robots".into(),
            click_depth: None,
            via_website: true,
            via_sitemap: false,
        }];
        let report = run_with_urls(
            &[copied, truncated, json, forbidden, challenge, blocked_obs],
            &urls,
        );
        assert_ne!(
            report.outcome("content.duplicate"),
            Some(RuleState::Findings)
        );
        assert!(report.affected_identities("content.duplicate").is_empty());
    }

    #[test]
    fn only_unusable_responses_are_incomplete_never_passed() {
        let truncated = page_status(
            "https://audit.example/partial",
            200,
            "text/html",
            b"<html><p>Partial",
            true,
        );
        let report = run(&[truncated]);
        assert_eq!(
            report.outcome("content.duplicate"),
            Some(RuleState::Incomplete)
        );
        assert_ne!(report.outcome("content.duplicate"), Some(RuleState::Passed));
    }

    #[test]
    fn unique_complete_page_passes() {
        let report = run(&[product(
            "https://audit.example/solo",
            "Solo SKU heading that is unique",
            "A single complete product page with enough distinctive copy to fingerprint.",
        )]);
        assert_eq!(report.outcome("content.duplicate"), Some(RuleState::Passed));
    }

    #[test]
    fn near_duplicate_candidates_are_banded_not_all_pairs() {
        let vocab = [
            "amber", "basalt", "cedar", "dune", "ember", "fjord", "garnet", "hazel", "ivory",
            "jasper", "kelp", "linen", "maple", "nimbus", "onyx", "pebble", "quartz", "river",
            "slate", "topaz", "umber", "violet", "willow", "xenon", "yarrow", "zinc", "anvil",
            "brine", "cocoa", "drift", "epoch", "flint", "grain", "honey", "inlet", "jade",
            "knoll", "lotus", "myrrh", "notch", "olive", "prism", "quill", "reef", "silo", "thyme",
            "ulna", "vapor",
        ];
        let pages: Vec<_> = vocab
            .iter()
            .enumerate()
            .map(|(i, word)| {
                product(
                    &format!("https://audit.example/sku-{i}"),
                    &format!("{word} {word} cable heading {i}"),
                    &format!(
                        "{word} core {word} jacket {word} ferrule {word} rating {i} ampacity {word} spool {word} lot {i}"
                    ),
                )
            })
            .collect();
        let refs: Vec<_> = pages.iter().collect();
        let stats = cluster_duplicates(&refs, &config());
        let all_pairs = 48 * 47 / 2;
        assert!(
            stats.candidate_pairs < all_pairs,
            "candidate_pairs={} all_pairs={all_pairs}",
            stats.candidate_pairs
        );
        assert!(
            stats.candidate_pairs <= 48 * 8,
            "candidate_pairs={}",
            stats.candidate_pairs
        );
        assert!(stats.groups.is_empty());
    }

    #[test]
    fn stored_observations_evaluate_without_recrawl() {
        let store = Store::open_in_memory().unwrap();
        let profile = Profile::load(include_str!("../../../../profile.example.toml")).unwrap();
        let run_id = store.begin_run(&profile).unwrap();
        store
            .put_observation(
                run_id,
                &article(
                    "https://audit.example/copy-a",
                    SHARED_ARTICLE,
                    "https://audit.example/copy-a",
                    false,
                ),
            )
            .unwrap();
        store
            .put_observation(
                run_id,
                &article(
                    "https://audit.example/copy-b",
                    SHARED_ARTICLE,
                    "https://audit.example/copy-b",
                    false,
                ),
            )
            .unwrap();
        let first = evaluate_stored(&store, run_id, &config(), &content_registry()).unwrap();
        let second = evaluate_stored(&store, run_id, &config(), &content_registry()).unwrap();
        assert_eq!(
            first.outcome("content.duplicate"),
            Some(RuleState::Findings)
        );
        assert_eq!(first.findings, second.findings);
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(&[product(
            "https://audit.example/ok",
            "Credential-free product title here",
            "No secrets in this description of a mains lead.",
        )]);
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
    }
}
