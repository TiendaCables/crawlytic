//! HTTPS consistency, mixed content and certificate checkers.

use crate::audit::{
    AuditConfig, Checker, CheckerOutput, EvidenceBundle, EvidencePointer, FindingDraft, Registry,
};
use crate::extract::{ExtractedObservations, HostOwner};
use crate::https::{
    DEFAULT_DAYS_BEFORE_EXPIRY, HostProbe, HostProbeKind, MIXED_CONTENT_DYNAMIC_COVERAGE,
    MIXED_CONTENT_STATIC_COVERAGE, TlsInspection, apex_and_www, names_include_host,
};
use std::collections::BTreeSet;
use url::Url;

pub fn https_audit_registry() -> Registry {
    let mut registry = Registry::new();
    register_https_audit(&mut registry);
    registry
}

pub fn register_https_audit(registry: &mut Registry) {
    registry.register(WwwResolve);
    registry.register(NonSecurePages);
    registry.register(CertificateExpiry);
    registry.register(CertificateName);
    registry.register(MixedContent);
    registry.register(HomepageHttpNoRedirect);
    registry.register(HttpsLinksToHttp);
    registry.register(HomepageNotHttps);
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

fn complete_html<'a>(evidence: &'a EvidenceBundle<'_>) -> Vec<&'a ExtractedObservations> {
    evidence
        .observations
        .iter()
        .filter(|observation| observation.page.is_complete())
        .collect()
}

fn parse_url(value: &str) -> Option<Url> {
    Url::parse(value).ok()
}

fn identity_url(identity: &str) -> Option<Url> {
    parse_url(identity)
}

fn start_host(evidence: &EvidenceBundle<'_>) -> Option<String> {
    evidence
        .start_url
        .and_then(|url| url.host_str().map(str::to_owned))
}

fn preferred_host(evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> Option<String> {
    config
        .threshold("preferred_host")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| start_host(evidence))
}

fn probe<'a>(evidence: &'a EvidenceBundle<'a>, kind: HostProbeKind) -> Option<&'a HostProbe> {
    evidence.host_probes.iter().find(|probe| probe.kind == kind)
}

fn destination_host(probe: &HostProbe) -> Option<String> {
    probe
        .destination_url
        .as_deref()
        .and_then(parse_url)
        .and_then(|url| url.host_str().map(str::to_owned))
}

fn days_before_expiry(config: &AuditConfig) -> u32 {
    config
        .threshold("days_before_expiry")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_DAYS_BEFORE_EXPIRY)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn same_host_http(url: &Url, start: Option<&Url>) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    let Some(start) = start else {
        return true;
    };
    url.host_str() == start.host_str()
}

struct WwwResolve;
struct NonSecurePages;
struct CertificateExpiry;
struct CertificateName;
struct MixedContent;
struct HomepageHttpNoRedirect;
struct HttpsLinksToHttp;
struct HomepageNotHttps;

impl Checker for WwwResolve {
    fn rule_id(&self) -> &'static str {
        "https.www_resolve"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        let Some(host) = start_host(evidence) else {
            return incomplete();
        };
        let Some((apex, www)) = apex_and_www(&host) else {
            return not_applicable();
        };
        let preferred = preferred_host(evidence, config).unwrap_or(host);
        let Some(www_probe) = probe(evidence, HostProbeKind::HttpsWww) else {
            return incomplete();
        };
        let Some(apex_probe) = probe(evidence, HostProbeKind::HttpsApex) else {
            return incomplete();
        };
        let www_host = destination_host(www_probe);
        let apex_host = destination_host(apex_probe);
        if www_host.is_none() && www_probe.failed_reason.is_none()
            || apex_host.is_none() && apex_probe.failed_reason.is_none()
        {
            return incomplete();
        }
        let mut findings = Vec::new();
        let www_ok = www_host.as_deref() == Some(preferred.as_str());
        let apex_ok = apex_host.as_deref() == Some(preferred.as_str());
        if !www_ok || !apex_ok {
            findings.push(FindingDraft {
                entity_key: format!("{www} / {apex}"),
                fact: format!(
                    "https://{www}/ destination {} and https://{apex}/ destination {} fail to resolve to preferred host {preferred}.",
                    www_host.as_deref().unwrap_or("unresolved"),
                    apex_host.as_deref().unwrap_or("unresolved")
                ),
                recommendation: format!(
                    "Redirect both apex and www hosts to the configured preferred host ({preferred})."
                ),
                evidence: vec![
                    pointer(
                        www_probe.requested_url.clone(),
                        "redirect_chain",
                        format!(
                            "www -> {}",
                            www_probe
                                .destination_url
                                .as_deref()
                                .unwrap_or("unresolved")
                        ),
                    ),
                    pointer(
                        apex_probe.requested_url.clone(),
                        "redirect_chain",
                        format!(
                            "apex -> {}",
                            apex_probe
                                .destination_url
                                .as_deref()
                                .unwrap_or("unresolved")
                        ),
                    ),
                ],
            });
        }
        complete(findings)
    }
}

impl Checker for NonSecurePages {
    fn rule_id(&self) -> &'static str {
        "https.non_secure_pages"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.observations.is_empty() && evidence.urls.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        let mut pending_without_scheme = false;
        let mut seen = BTreeSet::new();
        for observation in evidence.observations {
            let Some(url) = identity_url(&observation.identity) else {
                pending_without_scheme = true;
                continue;
            };
            if same_host_http(&url, evidence.start_url) && seen.insert(observation.identity.clone())
            {
                findings.push(FindingDraft {
                    entity_key: observation.identity.clone(),
                    fact: format!(
                        "{} is an in-scope page served over HTTP.",
                        observation.identity
                    ),
                    recommendation: "Serve the page over HTTPS and redirect HTTP requests to it."
                        .into(),
                    evidence: vec![pointer(
                        observation.identity.clone(),
                        "url_scheme",
                        url.scheme().to_owned(),
                    )],
                });
            }
        }
        for record in evidence.urls {
            let Some(identity) = record.identity.as_ref() else {
                if record.reason.to_ascii_lowercase().contains("queued")
                    || matches!(record.state, crate::crawl::UrlState::Pending)
                {
                    pending_without_scheme = true;
                }
                continue;
            };
            let Some(url) = parse_url(identity.as_str()) else {
                pending_without_scheme = true;
                continue;
            };
            if same_host_http(&url, evidence.start_url) && seen.insert(identity.as_str().to_owned())
            {
                findings.push(FindingDraft {
                    entity_key: identity.as_str().to_owned(),
                    fact: format!(
                        "{} is an in-scope page served over HTTP.",
                        identity.as_str()
                    ),
                    recommendation: "Serve the page over HTTPS and redirect HTTP requests to it."
                        .into(),
                    evidence: vec![pointer(
                        identity.as_str(),
                        "url_scheme",
                        url.scheme().to_owned(),
                    )],
                });
            }
        }
        if findings.is_empty() && pending_without_scheme {
            return incomplete();
        }
        complete(findings)
    }
}

impl Checker for CertificateExpiry {
    fn rule_id(&self) -> &'static str {
        "https.certificate_expiry"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, config: &AuditConfig) -> CheckerOutput {
        if evidence.tls_inspections.is_empty() {
            return incomplete();
        }
        let window = days_before_expiry(config);
        let now = now_unix();
        let mut findings = Vec::new();
        let mut any_inspected = false;
        for cert in evidence.tls_inspections {
            if !cert.inspected {
                continue;
            }
            any_inspected = true;
            let Some(not_after) = cert.not_after_unix else {
                continue;
            };
            let remaining_days = (not_after - now) / 86_400;
            if remaining_days < 0 {
                findings.push(expiry_finding(
                    cert,
                    format!(
                        "https://{}/ presents a certificate that expired {} days ago.",
                        cert.host,
                        remaining_days.abs()
                    ),
                    "Replace the expired TLS certificate.",
                ));
            } else if remaining_days <= i64::from(window) {
                findings.push(expiry_finding(
                    cert,
                    format!(
                        "https://{}/ presents a certificate that expires in {remaining_days} days (warning window {window} days).",
                        cert.host
                    ),
                    format!(
                        "Renew the TLS certificate before it expires. Warning window is days_before_expiry={window} (Crawlytic heuristic, not a Semrush formula)."
                    ),
                ));
            }
        }
        if !any_inspected {
            return incomplete();
        }
        complete(findings)
    }
}

fn expiry_finding(
    cert: &TlsInspection,
    fact: String,
    recommendation: impl Into<String>,
) -> FindingDraft {
    FindingDraft {
        entity_key: format!("{}:{}", cert.host, cert.port),
        fact,
        recommendation: recommendation.into(),
        evidence: vec![pointer(
            format!("https://{}/", cert.host),
            "tls_certificate",
            format!(
                "not_after={} names={}",
                cert.not_after_unix.unwrap_or_default(),
                cert.names.join(",")
            ),
        )],
    }
}

impl Checker for CertificateName {
    fn rule_id(&self) -> &'static str {
        "https.certificate_name"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        if evidence.tls_inspections.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        let mut any_inspected = false;
        for cert in evidence.tls_inspections {
            if !cert.inspected {
                continue;
            }
            any_inspected = true;
            let matches = cert.hostname_ok || names_include_host(&cert.names, &cert.host);
            if !matches {
                findings.push(FindingDraft {
                    entity_key: format!("{}:{}", cert.host, cert.port),
                    fact: format!(
                        "https://{}/ certificate SAN/CN [{}] does not include {}.",
                        cert.host,
                        cert.names.join(", "),
                        cert.host
                    ),
                    recommendation:
                        "Serve a certificate whose SAN includes the requested hostname.".into(),
                    evidence: vec![pointer(
                        format!("https://{}/", cert.host),
                        "tls_certificate",
                        format!("hostname={} names={}", cert.host, cert.names.join(",")),
                    )],
                });
            }
        }
        if !any_inspected {
            return incomplete();
        }
        complete(findings)
    }
}

impl Checker for MixedContent {
    fn rule_id(&self) -> &'static str {
        "https.mixed_content"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        let mut saw_https = false;
        for page in pages {
            let Some(url) = identity_url(&page.identity) else {
                continue;
            };
            if url.scheme() != "https" {
                continue;
            }
            saw_https = true;
            for (seq, resource) in page.resources.iter().enumerate() {
                let Some(destination) = resource
                    .destination
                    .as_deref()
                    .or(Some(resource.href.as_str()))
                else {
                    continue;
                };
                let Some(dest) = parse_url(destination).or_else(|| parse_url(&resource.href))
                else {
                    continue;
                };
                if dest.scheme() != "http" {
                    continue;
                }
                findings.push(FindingDraft {
                    entity_key: format!("{} -> {destination} #{seq}", page.identity),
                    fact: format!(
                        "HTTPS page {} loads HTTP {} {} ({} coverage; dynamic mixed content is {MIXED_CONTENT_DYNAMIC_COVERAGE}).",
                        page.identity,
                        resource.kind.as_str(),
                        destination,
                        MIXED_CONTENT_STATIC_COVERAGE
                    ),
                    recommendation: "Serve subresources over HTTPS. Dynamic mixed content injected by JavaScript is not observed without rendering.".into(),
                    evidence: vec![pointer(
                        page.identity.clone(),
                        "resource_url",
                        format!("kind={} href={}", resource.kind.as_str(), resource.href),
                    )],
                });
            }
        }
        if !saw_https {
            return not_applicable();
        }
        complete(findings)
    }
}

impl Checker for HomepageHttpNoRedirect {
    fn rule_id(&self) -> &'static str {
        "https.homepage_http_no_redirect"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(probe) = probe(evidence, HostProbeKind::HttpHomepage) else {
            return incomplete();
        };
        if probe.destination_url.is_none() && probe.failed_reason.is_some() {
            return incomplete();
        }
        let redirected = probe.redirected_to_https();
        let canonical = probe.canonical_https();
        if redirected || canonical {
            return complete(Vec::new());
        }
        let dest = probe
            .destination_url
            .as_deref()
            .unwrap_or(probe.requested_url.as_str());
        complete(vec![FindingDraft {
            entity_key: "homepage".into(),
            fact: format!(
                "HTTP homepage {} stays on HTTP with no HTTPS redirect (actual redirects: none) and no HTTPS canonical hint (canonicals: {}).",
                probe.requested_url,
                if probe.canonicals.is_empty() {
                    "none".into()
                } else {
                    probe.canonicals.join(", ")
                }
            ),
            recommendation: "Redirect the HTTP homepage to HTTPS. A rel=canonical HTTPS hint is not a redirect; prefer a protocol upgrade plus a matching canonical.".into(),
            evidence: vec![
                pointer(
                    probe.requested_url.clone(),
                    "redirect_chain",
                    if probe.redirect_chain.is_empty() {
                        format!("no redirect; destination {dest}")
                    } else {
                        probe
                            .redirect_chain
                            .iter()
                            .map(|hop| format!("{} -> {} ({})", hop.from, hop.to, hop.status))
                            .collect::<Vec<_>>()
                            .join("; ")
                    },
                ),
                pointer(
                    probe.requested_url.clone(),
                    "canonical",
                    if probe.canonicals.is_empty() {
                        "no canonical".into()
                    } else {
                        probe.canonicals.join(", ")
                    },
                ),
            ],
        }])
    }
}

impl Checker for HttpsLinksToHttp {
    fn rule_id(&self) -> &'static str {
        "https.https_links_to_http"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let pages = complete_html(evidence);
        if pages.is_empty() {
            return incomplete();
        }
        let mut findings = Vec::new();
        let mut saw_https = false;
        for page in pages {
            let Some(url) = identity_url(&page.identity) else {
                continue;
            };
            if url.scheme() != "https" {
                continue;
            }
            saw_https = true;
            for (seq, link) in page.links.iter().enumerate() {
                if link.host_owner == HostOwner::Opaque {
                    continue;
                }
                let Some(destination) = link.destination.as_deref().or(Some(link.href.as_str()))
                else {
                    continue;
                };
                let Some(dest) = parse_url(destination).or_else(|| parse_url(&link.href)) else {
                    continue;
                };
                if dest.scheme() != "http" {
                    continue;
                }
                findings.push(FindingDraft {
                    entity_key: format!("{} -> {destination} #{seq}", page.identity),
                    fact: format!(
                        "HTTPS page {} links to HTTP {} (anchor {}).",
                        page.identity, destination, link.anchor
                    ),
                    recommendation: "Point navigation links at HTTPS URLs.".into(),
                    evidence: vec![pointer(
                        page.identity.clone(),
                        "anchor_href",
                        format!("href={} dest={destination}", link.href),
                    )],
                });
            }
        }
        if !saw_https {
            return not_applicable();
        }
        complete(findings)
    }
}

impl Checker for HomepageNotHttps {
    fn rule_id(&self) -> &'static str {
        "https.homepage_not_https"
    }

    fn evaluate(&self, evidence: &EvidenceBundle<'_>, _config: &AuditConfig) -> CheckerOutput {
        let Some(start) = evidence.start_url else {
            return incomplete();
        };
        if start.scheme() == "https" {
            return complete(Vec::new());
        }
        complete(vec![FindingDraft {
            entity_key: "homepage".into(),
            fact: format!("{start} is the configured homepage and does not use HTTPS."),
            recommendation: "Set the storefront start URL to HTTPS.".into(),
            evidence: vec![pointer(start.as_str(), "start_url", start.scheme())],
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditReport, evaluate, evaluate_stored};
    use crate::catalogue::RuleState;
    use crate::crawl::{UrlRecord, UrlState};
    use crate::extract::{ExtractInput, extract};
    use crate::https::{HostProbe, HostProbeKind, TlsInspection};
    use crate::profile::Profile;
    use crate::scope::FetchIdentity;
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

    fn identity(url: &str) -> FetchIdentity {
        FetchIdentity::from_url(&Url::parse(url).unwrap())
    }

    fn url_rec(url: &str, state: UrlState) -> UrlRecord {
        UrlRecord {
            original: url.to_owned(),
            identity: Some(identity(url)),
            state,
            reason: "Fetched".into(),
            click_depth: Some(0),
            via_website: true,
            via_sitemap: false,
        }
    }

    fn probe_http(dest: &str, redirects: &[(&str, &str, u16)], canonicals: &[&str]) -> HostProbe {
        HostProbe {
            kind: HostProbeKind::HttpHomepage,
            requested_url: "http://audit.example/".into(),
            destination_url: Some(dest.into()),
            status: Some(200),
            redirect_chain: redirects
                .iter()
                .copied()
                .map(|(from, to, status)| crate::extract::RedirectHop {
                    from: from.into(),
                    to: to.into(),
                    status,
                })
                .collect(),
            canonicals: canonicals.iter().map(|value| (*value).to_owned()).collect(),
            failed_reason: None,
            credentials_attached: false,
        }
    }

    fn host_probe(kind: HostProbeKind, requested: &str, dest: Option<&str>) -> HostProbe {
        HostProbe {
            kind,
            requested_url: requested.into(),
            destination_url: dest.map(str::to_owned),
            status: dest.map(|_| 200),
            redirect_chain: Vec::new(),
            canonicals: Vec::new(),
            failed_reason: dest.is_none().then(|| "Connection failed".to_owned()),
            credentials_attached: false,
        }
    }

    fn tls(
        host: &str,
        inspected: bool,
        hostname_ok: bool,
        not_after: Option<i64>,
        names: &[&str],
    ) -> TlsInspection {
        TlsInspection {
            host: host.into(),
            port: 443,
            inspected,
            verified: inspected && hostname_ok,
            hostname_ok,
            not_before_unix: inspected.then_some(1),
            not_after_unix: not_after,
            names: names.iter().map(|value| (*value).to_owned()).collect(),
            error: None,
            credentials_attached: false,
        }
    }

    fn start() -> Url {
        Url::parse("https://audit.example/").unwrap()
    }

    fn run(
        obs: &[ExtractedObservations],
        urls: &[UrlRecord],
        probes: &[HostProbe],
        certs: &[TlsInspection],
        start_url: Option<&Url>,
    ) -> AuditReport {
        evaluate(
            0,
            &EvidenceBundle {
                observations: obs,
                urls,
                sitemap: None,
                sitemap_done: false,
                robots: None,
                resource_fetches: &[],
                tls_inspections: certs,
                host_probes: probes,
                start_url,
            },
            &AuditConfig::default(),
            &https_audit_registry(),
            &[],
        )
    }

    #[test]
    fn non_secure_pages_and_https_links_and_static_mixed_content() {
        let insecure = page(
            "http://audit.example/insecure",
            r#"<html><body><a href="/ok">ok</a></body></html>"#,
        );
        let mixed = page(
            "https://audit.example/secure",
            r#"<html><body>
              <script src="http://audit.example/script.js"></script>
              <img src="https://audit.example/ok.png" alt="ok">
              <a href="http://audit.example/other">Away</a>
              <a href="https://audit.example/ok">Ok</a>
            </body></html>"#,
        );
        let report = run(&[insecure, mixed], &[], &[], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.non_secure_pages"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("https.non_secure_pages")
                .next()
                .unwrap()
                .fact
                .contains("http://audit.example/insecure")
        );
        assert_eq!(
            report.outcome("https.mixed_content"),
            Some(RuleState::Findings)
        );
        let mixed_fact = &report
            .findings_for("https.mixed_content")
            .next()
            .unwrap()
            .fact;
        assert!(mixed_fact.contains("http://audit.example/script.js"));
        assert!(mixed_fact.contains(MIXED_CONTENT_STATIC_COVERAGE));
        assert!(mixed_fact.contains(MIXED_CONTENT_DYNAMIC_COVERAGE));
        assert_eq!(
            report.outcome("https.https_links_to_http"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("https.https_links_to_http")
                .next()
                .unwrap()
                .fact
                .contains("http://audit.example/other")
        );

        let ok = page(
            "https://audit.example/ok",
            r#"<html><body>
              <script src="https://audit.example/app.js"></script>
              <a href="https://audit.example/other">Ok</a>
            </body></html>"#,
        );
        let report = run(&[ok], &[], &[], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.non_secure_pages"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("https.mixed_content"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            report.outcome("https.https_links_to_http"),
            Some(RuleState::Passed)
        );
    }

    #[test]
    fn dynamic_mixed_content_is_explicitly_incomplete_without_rendering() {
        assert_eq!(
            MIXED_CONTENT_DYNAMIC_COVERAGE,
            "incomplete-without-rendering"
        );
        let injected = page(
            "https://audit.example/secure",
            r#"<html><body><script>
              document.write('<script src="http://audit.example/dyn.js"><\/script>');
            </script></body></html>"#,
        );
        let report = run(&[injected], &[], &[], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.mixed_content"),
            Some(RuleState::Passed),
            "JS-injected HTTP scripts are not in the static HTML resource list"
        );
        assert!(report.findings_for("https.mixed_content").next().is_none());
    }

    #[test]
    fn missing_html_is_incomplete_for_mixed_content_and_http_links() {
        assert_eq!(
            run(&[], &[], &[], &[], Some(&start())).outcome("https.mixed_content"),
            Some(RuleState::Incomplete)
        );
        assert_eq!(
            run(&[], &[], &[], &[], Some(&start())).outcome("https.https_links_to_http"),
            Some(RuleState::Incomplete)
        );
        let queued = UrlRecord {
            original: "https://audit.example/queued".into(),
            identity: None,
            state: UrlState::Pending,
            reason: "Queued".into(),
            click_depth: None,
            via_website: true,
            via_sitemap: false,
        };
        assert_eq!(
            run(&[], &[queued], &[], &[], Some(&start())).outcome("https.non_secure_pages"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn homepage_http_distinguishes_redirect_from_canonical_hint() {
        let redirect = probe_http(
            "https://audit.example/",
            &[("http://audit.example/", "https://audit.example/", 301)],
            &[],
        );
        assert!(redirect.redirected_to_https());
        assert!(!redirect.canonical_https());
        let report = run(&[], &[], &[redirect], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.homepage_http_no_redirect"),
            Some(RuleState::Passed)
        );

        let canonical_only = probe_http("http://audit.example/", &[], &["https://audit.example/"]);
        assert!(!canonical_only.redirected_to_https());
        assert!(canonical_only.canonical_https());
        let report = run(&[], &[], &[canonical_only], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.homepage_http_no_redirect"),
            Some(RuleState::Passed),
            "canonical HTTPS is allowed by the rule but is not treated as a redirect"
        );

        let neither = probe_http("http://audit.example/", &[], &["http://audit.example/"]);
        let report = run(&[], &[], &[neither], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.homepage_http_no_redirect"),
            Some(RuleState::Findings)
        );
        let fact = &report
            .findings_for("https.homepage_http_no_redirect")
            .next()
            .unwrap()
            .fact;
        assert!(fact.contains("no HTTPS redirect"));
        assert!(fact.contains("canonical"));
        assert!(!fact.contains("CRAWL_SIGNATURE"));

        assert_eq!(
            run(&[], &[], &[], &[], Some(&start())).outcome("https.homepage_http_no_redirect"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn www_and_certificate_fixtures() {
        let www_ok = host_probe(
            HostProbeKind::HttpsWww,
            "https://www.audit.example/",
            Some("https://audit.example/"),
        );
        let apex_ok = host_probe(
            HostProbeKind::HttpsApex,
            "https://audit.example/",
            Some("https://audit.example/"),
        );
        let report = run(&[], &[], &[www_ok, apex_ok], &[], Some(&start()));
        assert_eq!(report.outcome("https.www_resolve"), Some(RuleState::Passed));

        let www_bad = host_probe(
            HostProbeKind::HttpsWww,
            "https://www.audit.example/",
            Some("https://www.audit.example/"),
        );
        let apex_bad = host_probe(
            HostProbeKind::HttpsApex,
            "https://audit.example/",
            Some("https://audit.example/"),
        );
        let report = run(&[], &[], &[www_bad, apex_bad], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.www_resolve"),
            Some(RuleState::Findings)
        );

        assert_eq!(
            run(&[], &[], &[], &[], Some(&start())).outcome("https.www_resolve"),
            Some(RuleState::Incomplete)
        );

        let expired = tls(
            "audit.example",
            true,
            true,
            Some(1_600_000_000),
            &["audit.example"],
        );
        let report = run(&[], &[], &[], &[expired], Some(&start()));
        assert_eq!(
            report.outcome("https.certificate_expiry"),
            Some(RuleState::Findings)
        );
        assert!(
            report
                .findings_for("https.certificate_expiry")
                .next()
                .unwrap()
                .fact
                .contains("expired")
        );

        let far = now_unix() + 86_400 * 400;
        let ok = tls("audit.example", true, true, Some(far), &["audit.example"]);
        let report = run(&[], &[], &[], &[ok], Some(&start()));
        assert_eq!(
            report.outcome("https.certificate_expiry"),
            Some(RuleState::Passed)
        );

        let mismatch = tls("audit.example", true, false, Some(far), &["other.example"]);
        let report = run(&[], &[], &[], &[mismatch], Some(&start()));
        assert_eq!(
            report.outcome("https.certificate_name"),
            Some(RuleState::Findings)
        );

        let match_ok = tls("audit.example", true, true, Some(far), &["audit.example"]);
        let report = run(&[], &[], &[], &[match_ok], Some(&start()));
        assert_eq!(
            report.outcome("https.certificate_name"),
            Some(RuleState::Passed)
        );

        let not_inspected = tls("audit.example", false, false, None, &[]);
        let report = run(&[], &[], &[], &[not_inspected], Some(&start()));
        assert_eq!(
            report.outcome("https.certificate_expiry"),
            Some(RuleState::Incomplete)
        );
        assert_eq!(
            report.outcome("https.certificate_name"),
            Some(RuleState::Incomplete)
        );
    }

    #[test]
    fn homepage_scheme_and_stored_rerun() {
        let http_home = Url::parse("http://audit.example/").unwrap();
        let report = run(&[], &[], &[], &[], Some(&http_home));
        assert_eq!(
            report.outcome("https.homepage_not_https"),
            Some(RuleState::Findings)
        );
        let report = run(&[], &[], &[], &[], Some(&start()));
        assert_eq!(
            report.outcome("https.homepage_not_https"),
            Some(RuleState::Passed)
        );
        assert_eq!(
            run(&[], &[], &[], &[], None).outcome("https.homepage_not_https"),
            Some(RuleState::Incomplete)
        );

        let store = Store::open_in_memory().unwrap();
        let profile = Profile::load(include_str!("../../../../profile.example.toml")).unwrap();
        let run_id = store.begin_run(&profile).unwrap();
        store
            .put_observation(
                run_id,
                &page(
                    "https://audit.example/secure",
                    r#"<html><body><a href="http://audit.example/other">x</a></body></html>"#,
                ),
            )
            .unwrap();
        store
            .put_host_probe(
                run_id,
                &probe_http(
                    "https://www.tiendacables.com/",
                    &[(
                        "http://www.tiendacables.com/",
                        "https://www.tiendacables.com/",
                        301,
                    )],
                    &[],
                ),
            )
            .unwrap();
        store
            .put_tls_inspection(
                run_id,
                &tls(
                    "www.tiendacables.com",
                    true,
                    true,
                    Some(now_unix() + 86_400 * 400),
                    &["www.tiendacables.com"],
                ),
            )
            .unwrap();
        let first = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &https_audit_registry(),
        )
        .unwrap();
        let second = evaluate_stored(
            &store,
            run_id,
            &AuditConfig::default(),
            &https_audit_registry(),
        )
        .unwrap();
        assert_eq!(first.findings, second.findings);
        assert_eq!(
            first.outcome("https.https_links_to_http"),
            Some(RuleState::Findings)
        );
        assert!(!format!("{first:?}").contains("CRAWL_SIGNATURE"));
    }

    #[test]
    fn url_records_count_as_non_secure_pages() {
        let report = run(
            &[],
            &[url_rec("http://audit.example/insecure", UrlState::Fetched)],
            &[],
            &[],
            Some(&start()),
        );
        assert_eq!(
            report.outcome("https.non_secure_pages"),
            Some(RuleState::Findings)
        );
    }
}
