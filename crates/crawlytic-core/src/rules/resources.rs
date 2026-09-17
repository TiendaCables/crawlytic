//! Images, scripts, styles and blocked-resource checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::extract::{EmbeddedKind, ExtractedObservations, HostOwner, ResourceFetch};
use std::collections::BTreeMap;
use url::Url;

pub fn resource_audit_registry() -> Registry {
    let mut registry = Registry::new();
    register_resource_audit(&mut registry);
    registry
}

pub fn register_resource_audit(registry: &mut Registry) {
    registry.register(BrokenInternalImages);
    registry.register(BrokenInternalJsCss);
    registry.register(BrokenExternalImages);
    registry.register(MissingAlt);
    registry.register(BlockedInternalRobots);
    registry.register(BlockedExternalRobots);
    registry.register(BrokenExternalJsCss);
}

fn complete_html<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    evidence
        .observations
        .iter()
        .filter(|observation| observation.page.is_complete())
        .collect()
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

fn normalize_identity(value: &str) -> String {
    match Url::parse(value) {
        Ok(mut url) => {
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => value.to_owned(),
    }
}

fn host_label(identity: &str) -> String {
    Url::parse(identity)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| identity.to_owned())
}

fn fetch_index<'a>(evidence: &'a EvidenceBundle<'_>) -> BTreeMap<String, &'a ResourceFetch> {
    evidence
        .resource_fetches
        .iter()
        .map(|fetch| (normalize_identity(&fetch.identity), fetch))
        .collect()
}

struct ResourceHit<'a> {
    page: &'a ExtractedObservations,
    resource: &'a crate::extract::ResourceObservation,
    dest: String,
    fetch: Option<&'a ResourceFetch>,
}

fn collect_hits<'a>(
    pages: &[&'a ExtractedObservations],
    fetches: &BTreeMap<String, &'a ResourceFetch>,
    owner: HostOwner,
    kinds: &[EmbeddedKind],
) -> Vec<ResourceHit<'a>> {
    let mut hits = Vec::new();
    for page in pages {
        for resource in &page.resources {
            if resource.host_owner != owner || !kinds.contains(&resource.kind) {
                continue;
            }
            let Some(destination) = resource.destination.as_deref() else {
                continue;
            };
            let dest = normalize_identity(destination);
            let fetch = fetches.get(&dest).copied();
            hits.push(ResourceHit {
                page,
                resource,
                dest,
                fetch,
            });
        }
    }
    hits
}

fn fetch_known(fetch: &ResourceFetch) -> bool {
    fetch.robots_blocked
        || fetch.status.is_some()
        || fetch.failed_reason.is_some()
        || fetch.challenge
}

fn is_transport_failure(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("connection failed")
        || lower.contains("dns")
        || lower.contains("timed out")
        || lower.contains("timeout")
}

fn access_limitation(fetch: &ResourceFetch) -> bool {
    fetch.challenge
        || matches!(fetch.status, Some(401 | 403 | 429))
        || fetch
            .failed_reason
            .as_deref()
            .is_some_and(|reason| reason.to_ascii_lowercase().contains("challenge"))
}

fn is_broken(fetch: &ResourceFetch) -> bool {
    if access_limitation(fetch) || fetch.robots_blocked {
        return false;
    }
    if let Some(status) = fetch.status {
        return (400..600).contains(&status);
    }
    fetch
        .failed_reason
        .as_deref()
        .is_some_and(is_transport_failure)
}

fn grouped_referrers<'a>(
    hits: &'a [ResourceHit<'a>],
) -> BTreeMap<String, Vec<&'a ResourceHit<'a>>> {
    let mut groups: BTreeMap<String, Vec<&ResourceHit<'_>>> = BTreeMap::new();
    for hit in hits {
        groups.entry(hit.dest.clone()).or_default().push(hit);
    }
    groups
}

fn referring_list(hits: &[&ResourceHit<'_>]) -> String {
    let mut pages: Vec<&str> = hits.iter().map(|hit| hit.page.identity.as_str()).collect();
    pages.sort_unstable();
    pages.dedup();
    pages.join(", ")
}

fn status_label(fetch: &ResourceFetch) -> String {
    if fetch.challenge {
        return "challenge page".into();
    }
    if let Some(status) = fetch.status {
        return format!("HTTP {status}");
    }
    if let Some(reason) = &fetch.failed_reason {
        return format!("fetch failed ({reason})");
    }
    "status unknown".into()
}

fn broken_output(
    evidence: &EvidenceBundle<'_>,
    owner: HostOwner,
    kinds: &[EmbeddedKind],
    noun: &str,
    recommendation: &str,
) -> CheckerOutput {
    let pages = complete_html(evidence);
    if pages.is_empty() {
        return incomplete();
    }
    let hits = collect_hits(&pages, &fetch_index(evidence), owner, kinds);
    if hits.is_empty() {
        return not_applicable();
    }
    if hits
        .iter()
        .any(|hit| hit.fetch.is_none_or(|fetch| !fetch_known(fetch)))
    {
        return incomplete();
    }
    let mut findings = Vec::new();
    for (dest, group) in grouped_referrers(&hits) {
        let fetch = group[0].fetch.expect("known fetch");
        if !is_broken(fetch) {
            continue;
        }
        let host = host_label(&dest);
        let pages = referring_list(&group);
        let label = status_label(fetch);
        findings.push(FindingDraft {
            entity_key: dest.clone(),
            fact: format!("{noun} {dest} (host {host}) {label}. Referring pages: {pages}."),
            recommendation: recommendation.into(),
            evidence: group
                .iter()
                .map(|hit| {
                    pointer(
                        hit.page,
                        "resource_http_status",
                        format!(
                            "kind={} href={} {label}",
                            hit.resource.kind.as_str(),
                            hit.resource.href
                        ),
                    )
                })
                .collect(),
        });
    }
    complete(findings)
}

fn blocked_output(
    evidence: &EvidenceBundle<'_>,
    owner: HostOwner,
    recommendation: &str,
) -> CheckerOutput {
    let pages = complete_html(evidence);
    if pages.is_empty() {
        return incomplete();
    }
    let kinds = [
        EmbeddedKind::Image,
        EmbeddedKind::Script,
        EmbeddedKind::Style,
    ];
    let hits = collect_hits(&pages, &fetch_index(evidence), owner, &kinds);
    if hits.is_empty() {
        return not_applicable();
    }
    if hits
        .iter()
        .any(|hit| hit.fetch.map(|fetch| !fetch.robots_known).unwrap_or(true))
    {
        return incomplete();
    }
    let mut findings = Vec::new();
    for (dest, group) in grouped_referrers(&hits) {
        let fetch = group[0].fetch.expect("known robots evidence");
        if !fetch.robots_blocked {
            continue;
        }
        let host = host_label(&dest);
        let pages = referring_list(&group);
        findings.push(FindingDraft {
            entity_key: dest.clone(),
            fact: format!(
                "Resource {dest} (host {host}) is disallowed by that origin robots.txt. Referring pages: {pages}."
            ),
            recommendation: recommendation.into(),
            evidence: group
                .iter()
                .map(|hit| {
                    pointer(
                        hit.page,
                        "resource_url",
                        format!(
                            "kind={} href={} blocked by robots.txt",
                            hit.resource.kind.as_str(),
                            hit.resource.href
                        ),
                    )
                })
                .collect(),
        });
    }
    complete(findings)
}

pub(crate) fn external_resource_403(evidence: &EvidenceBundle<'_>) -> Vec<FindingDraft> {
    let pages = complete_html(evidence);
    if pages.is_empty() {
        return Vec::new();
    }
    let kinds = [
        EmbeddedKind::Image,
        EmbeddedKind::Script,
        EmbeddedKind::Style,
    ];
    let hits = collect_hits(&pages, &fetch_index(evidence), HostOwner::OtherHost, &kinds);
    let mut findings = Vec::new();
    for (dest, group) in grouped_referrers(&hits) {
        let Some(fetch) = group[0].fetch else {
            continue;
        };
        if fetch.challenge || fetch.status != Some(403) {
            continue;
        }
        let host = host_label(&dest);
        let pages = referring_list(&group);
        findings.push(FindingDraft {
            entity_key: format!("resource::{dest}"),
            fact: format!(
                "External resource {dest} (host {host}) returned HTTP 403. Access limitation, not a confirmed broken target. Referring pages: {pages}."
            ),
            recommendation: "Treat HTTP 403 as an access limitation (bot-blocking, auth, or geo). Do not report it as a confirmed broken external target.".into(),
            evidence: group
                .iter()
                .map(|hit| {
                    pointer(
                        hit.page,
                        "target_http_status",
                        format!("href={} HTTP 403", hit.resource.href),
                    )
                })
                .collect(),
        });
    }
    findings
}

struct BrokenInternalImages;
struct BrokenInternalJsCss;
struct BrokenExternalImages;
struct MissingAlt;
struct BlockedInternalRobots;
struct BlockedExternalRobots;
struct BrokenExternalJsCss;

impl Checker for BrokenInternalImages {
    fn rule_id(&self) -> &'static str {
        "images.broken_internal"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        broken_output(
            evidence,
            HostOwner::SameHost,
            &[EmbeddedKind::Image],
            "Image",
            "Fix or replace the internal image so referring pages load a usable asset.",
        )
    }
}

impl Checker for BrokenInternalJsCss {
    fn rule_id(&self) -> &'static str {
        "resources.broken_internal_js_css"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        broken_output(
            evidence,
            HostOwner::SameHost,
            &[EmbeddedKind::Script, EmbeddedKind::Style],
            "Script/style",
            "Fix or replace the internal script or stylesheet.",
        )
    }
}

impl Checker for BrokenExternalImages {
    fn rule_id(&self) -> &'static str {
        "images.broken_external"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        broken_output(
            evidence,
            HostOwner::OtherHost,
            &[EmbeddedKind::Image],
            "Image",
            "Fix or replace the external image, or remove the reference.",
        )
    }
}

impl Checker for MissingAlt {
    fn rule_id(&self) -> &'static str {
        "images.missing_alt"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        let mut saw_image = false;
        for page in pages {
            for (seq, resource) in page.resources.iter().enumerate() {
                if resource.kind != EmbeddedKind::Image {
                    continue;
                }
                saw_image = true;
                if resource.alt.is_none() {
                    let dest = resource.destination.as_deref().unwrap_or(&resource.href);
                    findings.push(FindingDraft {
                        entity_key: format!("{} -> {dest} #{}", page.identity, seq),
                        fact: format!(
                            "Referring page {} image href={} has no alt attribute.",
                            page.identity, resource.href
                        ),
                        recommendation: "Add a descriptive alt attribute. Use alt=\"\" only for decorative images.".into(),
                        evidence: vec![pointer(
                            page,
                            "img_alt",
                            format!("href={} alt=missing", resource.href),
                        )],
                    });
                }
            }
        }
        if !saw_image {
            return not_applicable();
        }
        complete(findings)
    }
}

impl Checker for BlockedInternalRobots {
    fn rule_id(&self) -> &'static str {
        "resources.blocked_internal_robots"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        blocked_output(
            evidence,
            HostOwner::SameHost,
            "Allow the resource in robots.txt if it should be fetched, or keep it blocked intentionally.",
        )
    }
}

impl Checker for BlockedExternalRobots {
    fn rule_id(&self) -> &'static str {
        "resources.blocked_external_robots"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        blocked_output(
            evidence,
            HostOwner::OtherHost,
            "Treat the third-party robots.txt disallow as an access limitation for that host, not a missing page.",
        )
    }
}

impl Checker for BrokenExternalJsCss {
    fn rule_id(&self) -> &'static str {
        "resources.broken_external_js_css"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        broken_output(
            evidence,
            HostOwner::OtherHost,
            &[EmbeddedKind::Script, EmbeddedKind::Style],
            "Script/style",
            "Fix or replace the external script or stylesheet, or remove the reference.",
        )
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

    fn fetch(
        identity: &str,
        status: Option<u16>,
        failed_reason: Option<&str>,
        challenge: bool,
        robots_blocked: bool,
        robots_known: bool,
    ) -> ResourceFetch {
        ResourceFetch {
            identity: identity.into(),
            status,
            failed_reason: failed_reason.map(str::to_owned),
            challenge,
            credentials_attached: false,
            robots_blocked,
            robots_known,
            content_type: "application/octet-stream".into(),
        }
    }

    fn run_with(obs: &[ExtractedObservations], fetches: &[ResourceFetch]) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls: &[],
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: fetches,
            },
            &AuditConfig::default(),
            &resource_audit_registry(),
            &[],
        )
    }

    fn run(obs: &[ExtractedObservations]) -> AuditReport {
        run_with(obs, &[])
    }

    #[test]
    fn missing_alt_differs_from_empty_decorative_alt() {
        let mixed = page(
            "https://audit.example/p",
            r#"<html><body>
              <img src="https://audit.example/a.png">
              <img src="https://audit.example/b.png" alt="">
              <img src="https://audit.example/c.png" alt="Logo">
            </body></html>"#,
        );
        let report = run(&[mixed]);
        let findings: Vec<_> = report.findings_for("images.missing_alt").collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fact.contains("https://audit.example/a.png"));
        assert!(findings[0].fact.contains("https://audit.example/p"));
        assert!(!findings[0].fact.contains("b.png"));
        assert_eq!(
            report.outcome("images.missing_alt"),
            Some(RuleState::Findings)
        );
        let ok = page(
            "https://audit.example/ok",
            r#"<html><body><img src="/ok.png" alt="Ok"><img src="/deco.png" alt=""></body></html>"#,
        );
        assert_eq!(
            run(&[ok]).outcome("images.missing_alt"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn grouped_resource_findings_keep_referring_pages_and_host() {
        let a = page(
            "https://audit.example/a",
            r#"<html><body>
              <img src="https://cdn.audit.example/x.png" alt="x">
              <script src="https://cdn.audit.example/app.js"></script>
            </body></html>"#,
        );
        let b = page(
            "https://audit.example/b",
            r#"<html><body><img src="https://cdn.audit.example/x.png" alt="x"></body></html>"#,
        );
        let fetches = [
            fetch(
                "https://cdn.audit.example/x.png",
                None,
                None,
                false,
                true,
                true,
            ),
            fetch(
                "https://cdn.audit.example/app.js",
                None,
                None,
                false,
                true,
                true,
            ),
        ];
        let report = run_with(&[a, b], &fetches);
        let blocked: Vec<_> = report
            .findings_for("resources.blocked_external_robots")
            .collect();
        assert_eq!(blocked.len(), 2, "one finding per resource, not per page");
        let image = blocked
            .iter()
            .find(|finding| finding.id.entity_key.contains("x.png"))
            .unwrap();
        assert!(image.fact.contains("host cdn.audit.example"));
        assert!(image.fact.contains("https://audit.example/a"));
        assert!(image.fact.contains("https://audit.example/b"));
        assert_eq!(image.evidence.len(), 2);
        match rule_by_id("resources.blocked_external_robots")
            .unwrap()
            .captured_current
        {
            CapturedCurrent::Count {
                value: 433,
                unit: InventoryUnit::Issue,
            } => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(
            rule_by_id("resources.blocked_external_robots")
                .unwrap()
                .unit,
            InventoryUnit::Issue
        );
        assert_ne!(
            rule_by_id("resources.blocked_external_robots")
                .unwrap()
                .unit,
            InventoryUnit::Page
        );
    }

    #[test]
    fn broken_internal_and_external_assets_and_incomplete_unfetched() {
        let page_a = page(
            "https://audit.example/page",
            r#"<html><body>
              <img src="https://audit.example/gone.png" alt="gone">
              <link rel="stylesheet" href="https://audit.example/gone.css">
              <img src="https://cdn.audit.example/gone.png" alt="ext">
              <script src="https://cdn.audit.example/gone.js"></script>
              <img src="https://audit.example/ok.png" alt="ok">
            </body></html>"#,
        );
        let fetches = [
            fetch(
                "https://audit.example/gone.png",
                Some(404),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://audit.example/gone.css",
                Some(404),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://cdn.audit.example/gone.png",
                Some(404),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://cdn.audit.example/gone.js",
                Some(500),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://audit.example/ok.png",
                Some(200),
                None,
                false,
                false,
                true,
            ),
        ];
        let report = run_with(&[page_a], &fetches);
        assert_eq!(
            report.outcome("images.broken_internal"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("images.broken_internal")
                .next()
                .unwrap()
                .fact
                .contains("HTTP 404")
        );
        assert_eq!(
            report.outcome("resources.broken_internal_js_css"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("images.broken_external"),
            Some(RuleState::Findings)
        );
        assert_eq!(
            report.outcome("resources.broken_external_js_css"),
            Some(RuleState::Findings)
        );

        let unfetched = page(
            "https://audit.example/page",
            r#"<html><body><img src="https://audit.example/gone.png" alt="gone"></body></html>"#,
        );
        assert_eq!(
            run(&[unfetched]).outcome("images.broken_internal"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn challenge_and_403_are_not_missing_assets() {
        let page_a = page(
            "https://audit.example/page",
            r#"<html><body>
              <img src="https://cdn.audit.example/challenge.png" alt="c">
              <script src="https://cdn.audit.example/private.js"></script>
              <img src="https://cdn.audit.example/ok.png" alt="ok">
            </body></html>"#,
        );
        let fetches = [
            fetch(
                "https://cdn.audit.example/challenge.png",
                Some(200),
                None,
                true,
                false,
                true,
            ),
            fetch(
                "https://cdn.audit.example/private.js",
                Some(403),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://cdn.audit.example/ok.png",
                Some(200),
                None,
                false,
                false,
                true,
            ),
        ];
        let report = run_with(std::slice::from_ref(&page_a), &fetches);
        assert_eq!(
            report.outcome("images.broken_external"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("resources.broken_external_js_css"),
            Some(RuleState::Passed)
        );
        let limited = super::external_resource_403(&EvidenceBundle {
            observations: std::slice::from_ref(&page_a),
            urls: &[],
            sitemap: None,
            sitemap_done: false,
            robots: None,
            resource_fetches: &fetches,
        });
        assert_eq!(limited.len(), 1);
        assert!(limited[0].fact.contains("HTTP 403"));
        assert!(limited[0].fact.contains("Access limitation"));
        assert!(
            !limited[0]
                .fact
                .to_ascii_lowercase()
                .contains("challenge.png")
        );
    }

    #[test]
    fn resource_findings_are_not_page_units_and_credentials_stay_off() {
        let page_a = page(
            "https://audit.example/page",
            r#"<html><body><img src="https://audit.example/gone.png" alt="gone"></body></html>"#,
        );
        let mut probe = fetch(
            "https://audit.example/gone.png",
            Some(404),
            None,
            false,
            false,
            true,
        );
        probe.credentials_attached = false;
        let report = run_with(&[page_a], &[probe.clone()]);
        let finding = report
            .findings_for("images.broken_internal")
            .next()
            .unwrap();
        assert_eq!(finding.id.entity_key, "https://audit.example/gone.png");
        assert_eq!(
            rule_by_id("images.broken_internal").unwrap().unit,
            InventoryUnit::Image
        );
        assert!(!probe.credentials_attached);
        assert!(!format!("{finding:?}").contains("CRAWL_SIGNATURE"));
        assert!(
            !format!("{finding:?}")
                .to_ascii_lowercase()
                .contains("sig1=")
        );
    }

    #[test]
    fn blocked_internal_robots_and_healthy_pass() {
        let blocked = page(
            "https://audit.example/page",
            r#"<html><body><script src="https://audit.example/app.js"></script></body></html>"#,
        );
        let report = run_with(
            &[blocked],
            &[fetch(
                "https://audit.example/app.js",
                None,
                None,
                false,
                true,
                true,
            )],
        );
        assert_eq!(
            report.outcome("resources.blocked_internal_robots"),
            Some(RuleState::Findings)
        );
        let healthy = page(
            "https://audit.example/ok",
            r#"<html><body>
              <img src="https://audit.example/ok.png" alt="Ok">
              <link rel="stylesheet" href="https://audit.example/ok.css">
              <script src="https://audit.example/ok.js"></script>
            </body></html>"#,
        );
        let ok = [
            fetch(
                "https://audit.example/ok.png",
                Some(200),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://audit.example/ok.css",
                Some(200),
                None,
                false,
                false,
                true,
            ),
            fetch(
                "https://audit.example/ok.js",
                Some(200),
                None,
                false,
                false,
                true,
            ),
        ];
        let report = run_with(&[healthy], &ok);
        for id in [
            "images.broken_internal",
            "images.missing_alt",
            "resources.broken_internal_js_css",
            "resources.blocked_internal_robots",
        ] {
            assert_eq!(report.outcome(id), Some(RuleState::Passed), "{id}");
        }
        for id in [
            "images.broken_external",
            "resources.broken_external_js_css",
            "resources.blocked_external_robots",
        ] {
            assert_eq!(report.outcome(id), Some(RuleState::NotApplicable), "{id}");
        }
    }

    #[test]
    fn stored_resource_fetches_evaluate_without_recrawl() {
        let store = Store::open_in_memory().unwrap();
        let profile = Profile::load(include_str!("../../../../profile.example.toml")).unwrap();
        let run_id = store.begin_run(&profile).unwrap();
        store
            .put_observation(
                run_id,
                &page(
                    "https://audit.example/p",
                    r#"<html><body><img src="https://audit.example/a.png"></body></html>"#,
                ),
            )
            .unwrap();
        store
            .put_resource_fetch(
                run_id,
                &fetch(
                    "https://audit.example/a.png",
                    Some(200),
                    None,
                    false,
                    false,
                    true,
                ),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &resource_audit_registry(),
        )
        .unwrap();
        assert_eq!(
            first.outcome("images.missing_alt"),
            Some(RuleState::Findings)
        );
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &resource_audit_registry(),
        )
        .unwrap();
        assert_eq!(first.findings, second.findings);
    }
}
