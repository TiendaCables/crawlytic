//! Crawl depth, inbound internal links and sitemap orphan candidates.
//!
//! Navigation edges are raw HTML `<a href>` links on the same host. Canonicals,
//! asset/resource URLs and sitemap membership never create a navigation edge.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::crawl::UrlState;
use crate::extract::{ExtractedObservations, HostOwner};
use crate::scope::FetchIdentity;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use url::Url;

/// Inventory baseline stated in TC-448/TC-461. Override with `max_clicks`.
pub const DEFAULT_MAX_CLICKS: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageNavigation {
    pub identity: String,
    pub depth: Option<u32>,
    pub path: Vec<String>,
    pub inbound: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NavigationGraph {
    pub homepage: Option<String>,
    pub pages: BTreeMap<String, PageNavigation>,
}

impl NavigationGraph {
    pub fn page(&self, identity: &str) -> Option<&PageNavigation> {
        self.pages.get(&normalize_identity(identity))
    }
}

pub fn navigation_registry() -> Registry {
    let mut registry = Registry::new();
    register_navigation(&mut registry);
    registry
}

pub fn register_navigation(registry: &mut Registry) {
    registry.register(DepthGt3);
    registry.register(OnlyOneIncoming);
    registry.register(OrphansInSitemaps);
}

pub fn build_navigation_graph(evidence: &EvidenceBundle<'_>) -> NavigationGraph {
    let mut inbound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut outbound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    if let Some(home) = homepage_identity(evidence) {
        ensure_node(&mut inbound, &mut outbound, &home);
    }
    for observation in evidence.observations {
        ensure_node(
            &mut inbound,
            &mut outbound,
            &normalize_identity(&observation.identity),
        );
    }
    for record in evidence.urls {
        if let Some(identity) = record.identity.as_ref() {
            ensure_node(
                &mut inbound,
                &mut outbound,
                &normalize_identity(identity.as_str()),
            );
        }
    }
    if let Some(sitemap) = evidence.sitemap {
        for listed in &sitemap.urls {
            if let Some(identity) = listed.identity.as_ref() {
                ensure_node(
                    &mut inbound,
                    &mut outbound,
                    &normalize_identity(identity.as_str()),
                );
            }
        }
    }

    for observation in evidence.observations {
        if !observation.page.is_complete() {
            continue;
        }
        let source = normalize_identity(&observation.identity);
        for dest in nav_destinations(observation) {
            if dest == source {
                continue;
            }
            ensure_node(&mut inbound, &mut outbound, &source);
            ensure_node(&mut inbound, &mut outbound, &dest);
            outbound
                .entry(source.clone())
                .or_default()
                .insert(dest.clone());
            inbound.entry(dest).or_default().insert(source.clone());
        }
    }

    let homepage = homepage_identity(evidence);
    let mut depth: BTreeMap<String, u32> = BTreeMap::new();
    let mut parent: BTreeMap<String, String> = BTreeMap::new();
    if let Some(home) = &homepage {
        let mut queue = VecDeque::new();
        depth.insert(home.clone(), 0);
        queue.push_back(home.clone());
        while let Some(node) = queue.pop_front() {
            let Some(next) = outbound.get(&node) else {
                continue;
            };
            let next_depth = depth.get(&node).copied().unwrap_or(0).saturating_add(1);
            for child in next {
                if depth.contains_key(child) {
                    continue;
                }
                depth.insert(child.clone(), next_depth);
                parent.insert(child.clone(), node.clone());
                queue.push_back(child.clone());
            }
        }
    }

    let mut pages = BTreeMap::new();
    let identities: BTreeSet<_> = inbound
        .keys()
        .cloned()
        .chain(outbound.keys().cloned())
        .collect();
    for identity in identities {
        let hops = depth.get(&identity).copied();
        let path = match hops {
            Some(0) => vec![identity.clone()],
            Some(_) => reconstruct_path(&identity, &parent),
            None => Vec::new(),
        };
        pages.insert(
            identity.clone(),
            PageNavigation {
                inbound: inbound.remove(&identity).unwrap_or_default(),
                identity,
                depth: hops,
                path,
            },
        );
    }

    NavigationGraph { homepage, pages }
}

fn ensure_node(
    inbound: &mut BTreeMap<String, BTreeSet<String>>,
    outbound: &mut BTreeMap<String, BTreeSet<String>>,
    identity: &str,
) {
    inbound.entry(identity.to_owned()).or_default();
    outbound.entry(identity.to_owned()).or_default();
}

fn reconstruct_path(identity: &str, parent: &BTreeMap<String, String>) -> Vec<String> {
    let mut rev = vec![identity.to_owned()];
    let mut cursor = identity;
    let mut guard = 0;
    while let Some(prev) = parent.get(cursor) {
        rev.push(prev.clone());
        cursor = prev;
        guard += 1;
        if guard > parent.len() + 1 {
            break;
        }
    }
    rev.reverse();
    rev
}

fn homepage_identity(evidence: &EvidenceBundle<'_>) -> Option<String> {
    let mut found = None;
    for record in evidence.urls {
        if record.click_depth != Some(0) {
            continue;
        }
        let identity = record
            .identity
            .as_ref()
            .map(|id| normalize_identity(id.as_str()))
            .unwrap_or_else(|| normalize_identity(&record.original));
        match found {
            None => found = Some(identity),
            Some(current) if identity < current => found = Some(identity),
            Some(_) => {}
        }
    }
    found
}

fn nav_destinations(observation: &ExtractedObservations) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for link in &observation.links {
        if link.element != "a" || link.host_owner != HostOwner::SameHost {
            continue;
        }
        let Some(destination) = link.destination.as_deref() else {
            continue;
        };
        let destination = normalize_identity(destination);
        if !destination.is_empty() {
            out.insert(destination);
        }
    }
    out
}

fn normalize_identity(value: &str) -> String {
    match Url::parse(value) {
        Ok(url) => FetchIdentity::from_url(&url).as_str().to_owned(),
        Err(_) => value.to_owned(),
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

fn pointer(
    identity: impl Into<String>,
    field: &str,
    excerpt: impl Into<String>,
) -> EvidencePointer {
    EvidencePointer {
        observation_identity: identity.into(),
        field: field.into(),
        excerpt: excerpt.into(),
    }
}

fn u32_threshold(config: &AuditConfig, key: &str, default: u32) -> u32 {
    config
        .threshold(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn format_path(path: &[String]) -> String {
    path.join(" → ")
}

fn coverage_incomplete(evidence: &EvidenceBundle<'_>) -> bool {
    if !evidence.sitemap_done {
        return true;
    }
    evidence
        .urls
        .iter()
        .any(|record| matches!(record.state, UrlState::Pending | UrlState::InFlight))
        || evidence
            .observations
            .iter()
            .any(|observation| !observation.page.is_complete())
}

fn has_complete_html(evidence: &EvidenceBundle<'_>) -> bool {
    evidence
        .observations
        .iter()
        .any(|observation| observation.page.is_complete())
}

struct DepthGt3;
struct OnlyOneIncoming;
struct OrphansInSitemaps;

impl Checker for DepthGt3 {
    fn rule_id(&self) -> &'static str {
        "crawl.depth_gt_3"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        if evidence.urls.is_empty() && evidence.observations.is_empty() {
            return incomplete();
        }
        if !has_complete_html(evidence) {
            return incomplete();
        }
        let graph = build_navigation_graph(evidence);
        let Some(homepage) = graph.homepage.clone() else {
            return incomplete();
        };
        let max_clicks = u32_threshold(config, "max_clicks", DEFAULT_MAX_CLICKS);
        let mut findings = Vec::new();
        for page in graph.pages.values() {
            let Some(depth) = page.depth else {
                continue;
            };
            if depth <= max_clicks {
                continue;
            }
            let path = format_path(&page.path);
            findings.push(FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!(
                    "{} is {depth} clicks from {homepage} via {path}. Unique referring pages: {}.",
                    page.identity,
                    page.inbound.len()
                ),
                recommendation: format!(
                    "Shorten the navigation path from the homepage so the page is within max_clicks={max_clicks} clicks."
                ),
                evidence: vec![pointer(
                    page.identity.clone(),
                    "link_depth",
                    format!("depth={depth}; path={path}"),
                )],
            });
        }
        complete(findings)
    }
}

impl Checker for OnlyOneIncoming {
    fn rule_id(&self) -> &'static str {
        "crawl.only_one_incoming_internal"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if !has_complete_html(evidence) {
            return incomplete();
        }
        let graph = build_navigation_graph(evidence);
        let homepage = graph.homepage.as_deref();
        let mut evaluated = 0usize;
        let mut findings = Vec::new();
        for page in graph.pages.values() {
            if homepage == Some(page.identity.as_str()) {
                continue;
            }
            if page.depth.is_none() && page.inbound.is_empty() {
                continue;
            }
            evaluated += 1;
            if page.inbound.len() != 1 {
                continue;
            }
            let referrer = page.inbound.iter().next().cloned().unwrap_or_default();
            findings.push(FindingDraft {
                entity_key: page.identity.clone(),
                fact: format!(
                    "{} has exactly one inbound internal link from {referrer}.",
                    page.identity
                ),
                recommendation:
                    "Add another internal link if the page should be discoverable from more than one place."
                        .into(),
                evidence: vec![pointer(
                    page.identity.clone(),
                    "link_graph",
                    format!("inbound=1 from {referrer}"),
                )],
            });
        }
        if evaluated == 0 && homepage.is_some() && graph.pages.len() <= 1 {
            return not_applicable();
        }
        if evaluated == 0 && homepage.is_none() {
            return incomplete();
        }
        complete(findings)
    }
}

impl Checker for OrphansInSitemaps {
    fn rule_id(&self) -> &'static str {
        "crawl.orphans_in_sitemaps"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(sitemap) = evidence.sitemap else {
            return incomplete();
        };
        if sitemap.urls.is_empty() {
            return not_applicable();
        }
        if !has_complete_html(evidence) && evidence.urls.is_empty() {
            return incomplete();
        }
        let graph = build_navigation_graph(evidence);
        let homepage = graph.homepage.as_deref();
        let incomplete_coverage = coverage_incomplete(evidence);
        let mut findings = Vec::new();
        for listed in &sitemap.urls {
            let Some(identity) = listed.identity.as_ref() else {
                continue;
            };
            let identity = normalize_identity(identity.as_str());
            if homepage == Some(identity.as_str()) {
                continue;
            }
            let inbound = graph
                .page(&identity)
                .map(|page| page.inbound.len())
                .unwrap_or(0);
            if inbound > 0 {
                continue;
            }
            let (fact, recommendation) = if incomplete_coverage {
                (
                    format!(
                        "{identity} is an orphan candidate listed in {} with no observed internal inbound link; crawl coverage is incomplete, so this is not a definite site-wide orphan.",
                        listed.source_sitemap
                    ),
                    "Treat this as a coverage-qualified candidate until the crawl finishes, then confirm whether internal links exist.".to_owned(),
                )
            } else {
                (
                    format!(
                        "{identity} is listed in {} with no observed internal inbound link.",
                        listed.source_sitemap
                    ),
                    "Add an internal navigational link if the sitemap URL should be reachable from the site.".to_owned(),
                )
            };
            findings.push(FindingDraft {
                entity_key: identity.clone(),
                fact,
                recommendation,
                evidence: vec![pointer(
                    identity,
                    "sitemap_url",
                    format!("source={}", listed.source_sitemap),
                )],
            });
        }
        complete(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::RuleState;
    use crate::crawl::{
        SitemapFileRecord, SitemapFileState, SitemapInventory, SitemapUrlRecord, UrlRecord,
    };
    use crate::extract::{ExtractHeader, ExtractInput, extract};
    use crate::profile::Profile;
    use crate::store::Store;

    fn page(url: &str, body: &str) -> ExtractedObservations {
        page_full(url, 200, "text/html", body.as_bytes(), false)
    }

    fn page_full(
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
            headers: &[] as &[ExtractHeader<'_>],
            body,
            truncated,
            duration_ms: Some(1),
        })
    }

    fn identity(url: &str) -> FetchIdentity {
        FetchIdentity::from_url(&Url::parse(url).unwrap())
    }

    fn url_rec(
        url: &str,
        depth: Option<u32>,
        via_website: bool,
        via_sitemap: bool,
        state: UrlState,
    ) -> UrlRecord {
        UrlRecord {
            original: url.to_owned(),
            identity: Some(identity(url)),
            state,
            reason: "Fetched".into(),
            click_depth: depth,
            via_website,
            via_sitemap,
        }
    }

    fn sitemap_url(original: &str, source: &str) -> SitemapUrlRecord {
        SitemapUrlRecord {
            original: original.to_owned(),
            identity: Some(identity(original)),
            skip_reason: None,
            source_sitemap: source.to_owned(),
        }
    }

    fn sitemap(urls: &[SitemapUrlRecord]) -> SitemapInventory {
        SitemapInventory {
            files: vec![SitemapFileRecord {
                url: "https://audit.example/sitemap.xml".into(),
                identity: Some(identity("https://audit.example/sitemap.xml")),
                state: SitemapFileState::Fetched,
                reason: "Fetched".into(),
                listed_urls: urls.len(),
            }],
            urls: urls.to_vec(),
        }
    }

    fn links(url: &str, hrefs: &[&str]) -> ExtractedObservations {
        let anchors: String = hrefs
            .iter()
            .map(|href| format!(r#"<a href="{href}">{href}</a>"#))
            .collect();
        page(url, &format!("<html><body>{anchors}</body></html>"))
    }

    fn canonical_only(url: &str, canonical: &str) -> ExtractedObservations {
        page(
            url,
            &format!(
                r#"<html><head><link rel="canonical" href="{canonical}"></head><body>home</body></html>"#
            ),
        )
    }

    fn with_asset(url: &str, asset: &str, nav: &str) -> ExtractedObservations {
        page(
            url,
            &format!(
                r#"<html><body><img src="{asset}" alt="x"><a href="{nav}">go</a></body></html>"#
            ),
        )
    }

    fn bundle<'a>(
        obs: &'a [ExtractedObservations],
        urls: &'a [UrlRecord],
        sitemap: Option<&'a SitemapInventory>,
        sitemap_done: bool,
    ) -> EvidenceBundle<'a> {
        EvidenceBundle {
            observations: obs,
            urls,
            sitemap,
            sitemap_done,
            robots: None,
            resource_fetches: &[],
        }
    }

    fn run(
        obs: &[ExtractedObservations],
        urls: &[UrlRecord],
        sitemap: Option<&SitemapInventory>,
        sitemap_done: bool,
        config: &AuditConfig,
    ) -> AuditReport {
        evaluate(
            0,
            &bundle(obs, urls, sitemap, sitemap_done),
            config,
            &navigation_registry(),
            &[],
        )
    }

    fn home_urls(extra: &[UrlRecord]) -> Vec<UrlRecord> {
        let mut urls = vec![url_rec(
            "https://audit.example/",
            Some(0),
            true,
            false,
            UrlState::Fetched,
        )];
        urls.extend_from_slice(extra);
        urls
    }

    #[test]
    fn diamond_cycle_and_disconnected_depths_are_shortest_and_stable() {
        let obs = [
            links(
                "https://audit.example/",
                &["https://audit.example/a", "https://audit.example/b"],
            ),
            links("https://audit.example/a", &["https://audit.example/deep"]),
            links("https://audit.example/b", &["https://audit.example/deep"]),
            links("https://audit.example/deep", &[]),
            links(
                "https://audit.example/cycle-a",
                &["https://audit.example/cycle-b"],
            ),
            links(
                "https://audit.example/cycle-b",
                &[
                    "https://audit.example/cycle-a",
                    "https://audit.example/cycle-end",
                ],
            ),
            links("https://audit.example/cycle-end", &[]),
            links("https://audit.example/lonely", &[]),
        ];
        let urls = home_urls(&[
            url_rec(
                "https://audit.example/a",
                Some(1),
                true,
                false,
                UrlState::Fetched,
            ),
            url_rec(
                "https://audit.example/b",
                Some(1),
                true,
                false,
                UrlState::Fetched,
            ),
            url_rec(
                "https://audit.example/deep",
                Some(2),
                true,
                false,
                UrlState::Fetched,
            ),
        ]);
        let graph = build_navigation_graph(&bundle(&obs, &urls, None, true));
        let deep = graph.page("https://audit.example/deep").unwrap();
        assert_eq!(deep.depth, Some(2));
        assert_eq!(
            deep.path,
            [
                "https://audit.example/",
                "https://audit.example/a",
                "https://audit.example/deep"
            ]
        );
        assert_eq!(deep.inbound.len(), 2);

        let home_cycle = [
            links("https://audit.example/", &["https://audit.example/cycle-a"]),
            links(
                "https://audit.example/cycle-a",
                &["https://audit.example/cycle-b"],
            ),
            links(
                "https://audit.example/cycle-b",
                &["https://audit.example/cycle-a"],
            ),
        ];
        let cycle = build_navigation_graph(&bundle(&home_cycle, &urls[..1], None, true));
        assert_eq!(
            cycle.page("https://audit.example/cycle-a").unwrap().depth,
            Some(1)
        );
        assert_eq!(
            cycle.page("https://audit.example/cycle-b").unwrap().depth,
            Some(2)
        );

        let disconnected = [
            links("https://audit.example/", &["https://audit.example/ok"]),
            links("https://audit.example/ok", &[]),
            links("https://audit.example/lonely", &[]),
        ];
        let graph = build_navigation_graph(&bundle(&disconnected, &urls[..1], None, true));
        assert_eq!(
            graph.page("https://audit.example/ok").unwrap().depth,
            Some(1)
        );
        assert_eq!(
            graph.page("https://audit.example/lonely").unwrap().depth,
            None
        );
        assert!(
            graph
                .page("https://audit.example/lonely")
                .unwrap()
                .path
                .is_empty()
        );
    }

    #[test]
    fn canonical_asset_and_sitemap_never_create_navigation_edges() {
        let obs = [
            canonical_only("https://audit.example/", "https://audit.example/canon"),
            links("https://audit.example/canon", &[]),
            with_asset(
                "https://audit.example/from-asset",
                "https://audit.example/asset-page",
                "https://audit.example/ok",
            ),
            links("https://audit.example/asset-page", &[]),
            links("https://audit.example/ok", &[]),
        ];
        let urls = [url_rec(
            "https://audit.example/from-asset",
            Some(0),
            true,
            false,
            UrlState::Fetched,
        )];
        let listed = sitemap(&[
            sitemap_url(
                "https://audit.example/sitemap-only",
                "https://audit.example/sitemap.xml",
            ),
            sitemap_url(
                "https://audit.example/ok",
                "https://audit.example/sitemap.xml",
            ),
        ]);
        let graph = build_navigation_graph(&bundle(&obs, &urls, Some(&listed), true));
        assert!(
            graph
                .page("https://audit.example/canon")
                .unwrap()
                .inbound
                .is_empty(),
            "canonical must not count as inbound"
        );
        assert!(
            graph
                .page("https://audit.example/asset-page")
                .unwrap()
                .inbound
                .is_empty(),
            "asset edges must not count as inbound"
        );
        assert_eq!(
            graph
                .page("https://audit.example/ok")
                .unwrap()
                .inbound
                .len(),
            1
        );
        assert!(
            graph
                .page("https://audit.example/sitemap-only")
                .unwrap()
                .inbound
                .is_empty(),
            "sitemap membership must not count as inbound"
        );
        assert_eq!(
            graph.page("https://audit.example/ok").unwrap().depth,
            Some(1)
        );
        assert_eq!(
            graph
                .page("https://audit.example/sitemap-only")
                .unwrap()
                .depth,
            None
        );
    }

    #[test]
    fn depth_findings_quote_reproducible_homepage_path() {
        let obs = [
            links("https://audit.example/", &["https://audit.example/1"]),
            links("https://audit.example/1", &["https://audit.example/2"]),
            links("https://audit.example/2", &["https://audit.example/3"]),
            links("https://audit.example/3", &["https://audit.example/4"]),
            links("https://audit.example/4", &[]),
            links("https://audit.example/ok", &[]),
        ];
        let urls = home_urls(&[url_rec(
            "https://audit.example/ok",
            None,
            false,
            true,
            UrlState::Fetched,
        )]);
        let shallow = [
            links("https://audit.example/", &["https://audit.example/ok"]),
            links("https://audit.example/ok", &[]),
        ];
        let report = run(&obs, &urls, None, true, &AuditConfig::default());
        assert_eq!(
            report.outcome("crawl.depth_gt_3"),
            Some(RuleState::Findings)
        );
        let finding = report.findings_for("crawl.depth_gt_3").next().unwrap();
        assert_eq!(finding.id.entity_key, "https://audit.example/4");
        assert!(finding.fact.contains("4 clicks"));
        assert!(finding.fact.contains(
            "https://audit.example/ → https://audit.example/1 → https://audit.example/2 → https://audit.example/3 → https://audit.example/4"
        ));
        assert!(finding.recommendation.contains("max_clicks=3"));
        assert_eq!(
            run(&shallow, &urls[..1], None, true, &AuditConfig::default())
                .outcome("crawl.depth_gt_3"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            run(&[], &[], None, true, &AuditConfig::default()).outcome("crawl.depth_gt_3"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn one_incoming_and_sitemap_orphans_qualify_incomplete_coverage() {
        let obs = [
            links(
                "https://audit.example/",
                &["https://audit.example/one", "https://audit.example/two-a"],
            ),
            links("https://audit.example/one", &[]),
            links(
                "https://audit.example/two-a",
                &["https://audit.example/shared"],
            ),
            links(
                "https://audit.example/two-b",
                &["https://audit.example/shared"],
            ),
            links("https://audit.example/shared", &[]),
            links("https://audit.example/orphan", &[]),
        ];
        let urls = home_urls(&[
            url_rec(
                "https://audit.example/one",
                Some(1),
                true,
                false,
                UrlState::Fetched,
            ),
            url_rec(
                "https://audit.example/shared",
                Some(2),
                true,
                false,
                UrlState::Fetched,
            ),
        ]);
        let listed = sitemap(&[
            sitemap_url(
                "https://audit.example/orphan",
                "https://audit.example/sitemap.xml",
            ),
            sitemap_url(
                "https://audit.example/one",
                "https://audit.example/sitemap.xml",
            ),
            sitemap_url(
                "https://audit.example/",
                "https://audit.example/sitemap.xml",
            ),
        ]);
        let report = run(&obs, &urls, Some(&listed), true, &AuditConfig::default());
        assert_eq!(
            report.outcome("crawl.only_one_incoming_internal"),
            Some(RuleState::Findings)
        );
        let one = report
            .findings_for("crawl.only_one_incoming_internal")
            .find(|finding| finding.id.entity_key == "https://audit.example/one")
            .unwrap();
        assert!(one.fact.contains("exactly one inbound"));
        assert!(
            report
                .findings_for("crawl.only_one_incoming_internal")
                .all(|finding| finding.id.entity_key != "https://audit.example/shared")
        );
        assert_eq!(
            report.outcome("crawl.orphans_in_sitemaps"),
            Some(RuleState::Findings)
        );
        let orphan = report
            .findings_for("crawl.orphans_in_sitemaps")
            .next()
            .unwrap();
        assert_eq!(orphan.id.entity_key, "https://audit.example/orphan");
        assert!(!orphan.fact.to_ascii_lowercase().contains("candidate"));
        assert!(
            report
                .findings_for("crawl.orphans_in_sitemaps")
                .all(|finding| finding.id.entity_key != "https://audit.example/one")
        );
        assert!(
            report
                .findings_for("crawl.orphans_in_sitemaps")
                .all(|finding| finding.id.entity_key != "https://audit.example/")
        );

        let pending = [url_rec(
            "https://audit.example/unseen",
            None,
            true,
            false,
            UrlState::Pending,
        )];
        let mut incomplete_urls = urls.clone();
        incomplete_urls.extend_from_slice(&pending);
        let candidate = run(
            &obs,
            &incomplete_urls,
            Some(&listed),
            false,
            &AuditConfig::default(),
        );
        let fact = candidate
            .findings_for("crawl.orphans_in_sitemaps")
            .next()
            .unwrap()
            .fact
            .clone();
        assert!(fact.contains("orphan candidate"));
        assert!(fact.contains("not a definite site-wide orphan"));
        assert_eq!(
            run(&obs, &urls, None, true, &AuditConfig::default())
                .outcome("crawl.orphans_in_sitemaps"),
            Some(RuleState::Incomplete)
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
                &links("https://audit.example/", &["https://audit.example/deep"]),
            )
            .unwrap();
        store
            .upsert_url(
                run_id,
                &url_rec(
                    "https://audit.example/",
                    Some(0),
                    true,
                    false,
                    UrlState::Fetched,
                ),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &navigation_registry(),
        )
        .unwrap();
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &navigation_registry(),
        )
        .unwrap();
        assert_eq!(first.outcome("crawl.depth_gt_3"), Some(RuleState::Passed));
        assert_eq!(first.findings, second.findings);
    }

    #[test]
    fn fixtures_do_not_embed_credentials() {
        let report = run(
            &[links("https://audit.example/", &[])],
            &[url_rec(
                "https://audit.example/",
                Some(0),
                true,
                false,
                UrlState::Fetched,
            )],
            None,
            true,
            &AuditConfig::default(),
        );
        let dump = format!("{report:?}");
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("signature"));
        assert!(!dump.contains("CRAWL_"));
    }
}
