//! URL identity, scope and exclusion.
//!
//! Resolve discovered hrefs against the document URL and an optional HTML
//! `<base href>`. Fetch identity normalizes scheme, host and default port and
//! drops the fragment. Distinct paths, query values, query order, duplicate
//! parameters and pagination stay distinct. A rel=canonical target is never
//! consulted and never merges two identities.
//!
//! Profile origin, path and parameter rules decide whether the identity may be
//! fetched. Skipped URLs stay in coverage and link relationships.

use crate::profile::Profile;
use std::collections::BTreeMap;
use url::Url;

pub const SKIP_MALFORMED: &str = "Malformed URL";
pub const SKIP_UNSUPPORTED_SCHEME: &str = "Unsupported scheme";

/// Normalized fetch key: scheme/host/port/path/query, no fragment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FetchIdentity {
    url: Url,
}

impl FetchIdentity {
    pub fn from_url(url: &Url) -> Self {
        let mut url = url.clone();
        url.set_fragment(None);
        if matches!(
            (url.scheme(), url.port()),
            ("https", Some(443)) | ("http", Some(80))
        ) {
            let _ = url.set_port(None);
        }
        Self { url }
    }

    pub fn as_url(&self) -> &Url {
        &self.url
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

impl std::fmt::Display for FetchIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedUrl {
    pub original: String,
    pub resolved: Option<Url>,
    pub identity: Option<FetchIdentity>,
    pub skip_reason: Option<&'static str>,
}

impl ClassifiedUrl {
    pub fn would_fetch(&self) -> bool {
        self.identity.is_some() && self.skip_reason.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageUrl {
    pub original: String,
    pub identity: Option<FetchIdentity>,
    pub skip_reason: Option<&'static str>,
    pub fetched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageLink {
    pub from_identity: FetchIdentity,
    pub href: String,
    pub to_original: String,
    pub to_identity: Option<FetchIdentity>,
    pub skip_reason: Option<&'static str>,
}

#[derive(Debug, Default)]
pub struct Coverage {
    urls: BTreeMap<String, CoverageUrl>,
    links: Vec<CoverageLink>,
}

impl Coverage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&mut self, profile: &Profile, href: &str) -> ClassifiedUrl {
        let classified = classify_absolute(profile, href);
        insert_url(&mut self.urls, &classified);
        classified
    }

    pub fn observe_link(
        &mut self,
        profile: &Profile,
        from_identity: &FetchIdentity,
        document_url: &Url,
        base_href: Option<&str>,
        href: &str,
    ) -> ClassifiedUrl {
        let classified = classify_href(profile, document_url, base_href, href);
        insert_url(&mut self.urls, &classified);
        self.links.push(CoverageLink {
            from_identity: from_identity.clone(),
            href: href.to_owned(),
            to_original: classified.original.clone(),
            to_identity: classified.identity.clone(),
            skip_reason: classified.skip_reason,
        });
        classified
    }

    pub fn mark_fetched(&mut self, identity: &FetchIdentity) -> Result<(), &'static str> {
        let entry = self
            .urls
            .get_mut(&identity_key(identity))
            .ok_or("Unknown URL")?;
        if let Some(reason) = entry.skip_reason {
            return Err(reason);
        }
        entry.fetched = true;
        Ok(())
    }

    pub fn url(&self, identity: &FetchIdentity) -> Option<&CoverageUrl> {
        self.urls.get(&identity_key(identity))
    }

    pub fn unresolved(&self, original: &str) -> Option<&CoverageUrl> {
        self.urls.get(&unresolved_key(original))
    }

    pub fn urls(&self) -> impl Iterator<Item = &CoverageUrl> {
        self.urls.values()
    }

    pub fn links(&self) -> &[CoverageLink] {
        &self.links
    }
}

pub fn classify_href(
    profile: &Profile,
    document_url: &Url,
    base_href: Option<&str>,
    href: &str,
) -> ClassifiedUrl {
    let original = href.to_owned();
    let resolved = match resolve_link(document_url, base_href, href) {
        Ok(url) => url,
        Err(()) => {
            return ClassifiedUrl {
                original,
                resolved: None,
                identity: None,
                skip_reason: Some(SKIP_MALFORMED),
            };
        }
    };
    if !matches!(resolved.scheme(), "http" | "https") {
        return ClassifiedUrl {
            original,
            resolved: Some(resolved),
            identity: None,
            skip_reason: Some(SKIP_UNSUPPORTED_SCHEME),
        };
    }
    let identity = FetchIdentity::from_url(&resolved);
    let skip_reason = profile.exclusion(identity.as_url());
    ClassifiedUrl {
        original,
        resolved: Some(resolved),
        identity: Some(identity),
        skip_reason,
    }
}

pub fn classify_absolute(profile: &Profile, href: &str) -> ClassifiedUrl {
    classify_href(profile, &profile.start_url, None, href)
}

fn resolve_link(document_url: &Url, base_href: Option<&str>, href: &str) -> Result<Url, ()> {
    let href = href.trim();
    let base = match base_href.map(str::trim).filter(|value| !value.is_empty()) {
        Some(base_href) => document_url
            .join(base_href)
            .unwrap_or_else(|_| document_url.clone()),
        None => document_url.clone(),
    };
    base.join(href).map_err(|_| ())
}

fn insert_url(urls: &mut BTreeMap<String, CoverageUrl>, classified: &ClassifiedUrl) {
    let key = match &classified.identity {
        Some(identity) => identity_key(identity),
        None => unresolved_key(&classified.original),
    };
    urls.entry(key).or_insert(CoverageUrl {
        original: classified.original.clone(),
        identity: classified.identity.clone(),
        skip_reason: classified.skip_reason,
        fetched: false,
    });
}

fn identity_key(identity: &FetchIdentity) -> String {
    format!("i:{}", identity.as_str())
}

fn unresolved_key(original: &str) -> String {
    format!("o:{original}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with(
        allow_subfolders: &str,
        exclude_paths: &str,
        skip_parameters: &str,
        captured: usize,
        extra: &str,
    ) -> Profile {
        Profile::load(&format!(
            r#"
schema_version = 1
role = "own_bot"
start_url = "https://www.tiendacables.com/"
max_pages = 20000
observed_pages_baseline = 3725
user_agent = "Crawlytic/0.1 (self-hosted SEO audit)"
discovery_mode = "homepage_internal_links"
crawl_delay = "minimum"
javascript_rendering = false
bypass_robots = false
bypass_meta = false
password_authentication = false
web_bot_auth_required = true
allow_subfolders = {allow_subfolders}
exclude_paths = {exclude_paths}
ignored_parameter_mode = "skip"
parameter_names_case_sensitive = true
skip_parameters = {skip_parameters}
schedule_cadence = "weekly"
schedule_weekday = "monday"
completion_email = false
auth_signature_env = "CRAWL_SIGNATURE"
auth_signature_input_env = "CRAWL_SIGNATURE_INPUT"
auth_signature_agent_env = "CRAWL_SIGNATURE_AGENT"
ignored_parameters_captured = {captured}
ignored_parameters_source_count = 27
exclude_paths_complete = false
lists_complete = false
{extra}
"#
        ))
        .unwrap()
    }

    fn profile() -> Profile {
        profile_with(
            "[]",
            r#"["/search", "/en/blogs/noticias/tagged/"]"#,
            r#"["variant", "fbclid"]"#,
            2,
            "",
        )
    }

    fn doc() -> Url {
        Url::parse("https://www.tiendacables.com/collections/cables").unwrap()
    }

    fn classify(href: &str) -> ClassifiedUrl {
        classify_href(&profile(), &doc(), None, href)
    }

    fn identity_str(classified: &ClassifiedUrl) -> &str {
        classified
            .identity
            .as_ref()
            .unwrap_or_else(|| panic!("expected identity for {}", classified.original))
            .as_str()
    }

    #[test]
    fn relative_links_resolve_against_the_document_url() {
        let root = classify("/products/x");
        assert_eq!(root.original, "/products/x");
        assert_eq!(
            root.resolved.as_ref().map(Url::as_str),
            Some("https://www.tiendacables.com/products/x")
        );
        assert_eq!(
            identity_str(&root),
            "https://www.tiendacables.com/products/x"
        );
        assert!(root.would_fetch());

        let parent = classify("../search");
        assert_eq!(
            parent.resolved.as_ref().map(Url::as_str),
            Some("https://www.tiendacables.com/search")
        );
        assert_eq!(parent.skip_reason, Some("Excluded path prefix"));
        assert!(!parent.would_fetch());

        let sibling = classify("x");
        assert_eq!(
            identity_str(&sibling),
            "https://www.tiendacables.com/collections/x"
        );

        let query_only = classify("?page=2");
        assert_eq!(
            identity_str(&query_only),
            "https://www.tiendacables.com/collections/cables?page=2"
        );
        assert!(query_only.would_fetch());
    }

    #[test]
    fn base_href_resolves_before_the_link() {
        let p = profile();
        let document = Url::parse("https://www.tiendacables.com/collections/cables").unwrap();
        let classified = classify_href(&p, &document, Some("/en/"), "products/x");
        assert_eq!(
            identity_str(&classified),
            "https://www.tiendacables.com/en/products/x"
        );

        let tagged = classify_href(&p, &document, Some("/en/blogs/noticias/tagged/"), "oferta");
        assert_eq!(tagged.skip_reason, Some("Excluded subfolder"));

        let invalid_base = classify_href(&p, &document, Some("http://["), "/products/x");
        assert_eq!(
            identity_str(&invalid_base),
            "https://www.tiendacables.com/products/x",
            "an unusable base href falls back to the document URL"
        );
    }

    #[test]
    fn encoded_paths_stay_distinct_when_reserved() {
        let slash = classify("/a%2Fb");
        let nested = classify("/a/b");
        assert_eq!(identity_str(&slash), "https://www.tiendacables.com/a%2Fb");
        assert_eq!(identity_str(&nested), "https://www.tiendacables.com/a/b");
        assert_ne!(slash.identity, nested.identity);

        let encoded = classify("/caf%C3%A9");
        let unicode = classify("/café");
        assert_eq!(encoded.identity, unicode.identity);
        assert_eq!(
            identity_str(&encoded),
            "https://www.tiendacables.com/caf%C3%A9"
        );
    }

    #[test]
    fn duplicate_and_ordered_parameters_are_not_collapsed() {
        let duplicated = classify("/p?a=1&a=2");
        let reversed = classify("/p?a=2&a=1");
        let single = classify("/p?a=1");
        assert_ne!(duplicated.identity, reversed.identity);
        assert_ne!(duplicated.identity, single.identity);
        assert_eq!(
            identity_str(&duplicated),
            "https://www.tiendacables.com/p?a=1&a=2"
        );
        assert!(duplicated.would_fetch());
        assert!(reversed.would_fetch());
    }

    #[test]
    fn fragments_are_dropped_from_identity_and_kept_on_the_original() {
        let with_frag = classify("/products/x#reviews");
        let without = classify("/products/x");
        assert_eq!(with_frag.original, "/products/x#reviews");
        assert_eq!(
            with_frag.resolved.as_ref().map(Url::as_str),
            Some("https://www.tiendacables.com/products/x#reviews")
        );
        assert_eq!(with_frag.identity, without.identity);
        assert_eq!(
            identity_str(&with_frag),
            "https://www.tiendacables.com/products/x"
        );
        assert!(with_frag.would_fetch());
    }

    #[test]
    fn scheme_host_and_default_port_normalize_without_touching_the_path() {
        let mixed = classify("HTTPS://WWW.TiendaCables.COM:443/Path#Frag");
        assert_eq!(mixed.original, "HTTPS://WWW.TiendaCables.COM:443/Path#Frag");
        assert_eq!(identity_str(&mixed), "https://www.tiendacables.com/Path");
        let slash = classify("/Path/");
        assert_ne!(
            mixed.identity, slash.identity,
            "trailing slashes stay distinct"
        );
    }

    #[test]
    fn malformed_and_non_http_targets_are_skipped_with_exact_reasons() {
        let malformed = classify("http://[");
        assert_eq!(malformed.original, "http://[");
        assert_eq!(malformed.resolved, None);
        assert_eq!(malformed.identity, None);
        assert_eq!(malformed.skip_reason, Some(SKIP_MALFORMED));
        assert!(!malformed.would_fetch());

        let script = classify("javascript:void(0)");
        assert_eq!(script.skip_reason, Some(SKIP_UNSUPPORTED_SCHEME));
        assert_eq!(script.identity, None);
        assert!(script.resolved.is_some());

        let mail = classify("mailto:x@y.com");
        assert_eq!(mail.skip_reason, Some(SKIP_UNSUPPORTED_SCHEME));
    }

    #[test]
    fn external_targets_keep_identity_and_are_not_fetched() {
        let external = classify("https://evil.example/products/x#x");
        assert_eq!(external.original, "https://evil.example/products/x#x");
        assert_eq!(identity_str(&external), "https://evil.example/products/x");
        assert_eq!(external.skip_reason, Some("Outside configured origin"));
        assert!(!external.would_fetch());

        let cdn = classify("//cdn.example/asset.js");
        assert_eq!(identity_str(&cdn), "https://cdn.example/asset.js");
        assert_eq!(cdn.skip_reason, Some("Outside configured origin"));

        let http = classify("http://www.tiendacables.com/products/x");
        assert_eq!(http.skip_reason, Some("Outside configured origin"));
    }

    #[test]
    fn pagination_stays_discoverable_unless_the_parameter_is_excluded() {
        let open = classify("?page=2");
        let first = classify("/collections/cables");
        assert!(open.would_fetch());
        assert_ne!(open.identity, first.identity);
        assert_eq!(
            identity_str(&open),
            "https://www.tiendacables.com/collections/cables?page=2"
        );

        let shipped = Profile::load(include_str!("../../../profile.example.toml")).unwrap();
        let excluded = classify_href(&shipped, &doc(), None, "/collections/cables?page=2");
        assert_eq!(excluded.skip_reason, Some("Ignored parameter"));
        assert_eq!(
            identity_str(&excluded),
            "https://www.tiendacables.com/collections/cables?page=2",
            "exclusion must not collapse the paginated identity"
        );
        assert!(!excluded.would_fetch());
    }

    #[test]
    fn ignored_parameters_and_path_rules_use_profile_reasons() {
        let variant = classify("/products/x?variant=1&color=red");
        assert_eq!(variant.skip_reason, Some("Ignored parameter"));
        assert_eq!(
            identity_str(&variant),
            "https://www.tiendacables.com/products/x?variant=1&color=red"
        );

        let allowed = profile_with(r#"["/collections/"]"#, "[]", "[]", 0, "");
        let product = classify_href(&allowed, &doc(), None, "/products/x");
        assert_eq!(product.skip_reason, Some("Not in allowed subfolders"));
        let collection = classify_href(&allowed, &doc(), None, "/collections/cables");
        assert!(collection.would_fetch());
    }

    #[test]
    fn canonical_is_not_proof_of_identity() {
        let a = classify("/products/a");
        let b = classify("/products/b");
        let _canonical = Url::parse("https://www.tiendacables.com/products/canonical").unwrap();
        assert_ne!(
            a.identity, b.identity,
            "a shared canonical must not merge fetched identities"
        );
        assert_eq!(
            a.identity.as_ref().map(FetchIdentity::as_str),
            Some("https://www.tiendacables.com/products/a")
        );
        assert_eq!(
            b.identity.as_ref().map(FetchIdentity::as_str),
            Some("https://www.tiendacables.com/products/b")
        );
    }

    #[test]
    fn coverage_keeps_excluded_urls_and_link_relationships_without_fetching() {
        let p = profile();
        let mut coverage = Coverage::new();
        let start = coverage.seed(&p, "https://www.tiendacables.com/");
        assert!(start.would_fetch());
        coverage
            .mark_fetched(start.identity.as_ref().unwrap())
            .unwrap();

        let from = start.identity.as_ref().unwrap();
        let document = Url::parse("https://www.tiendacables.com/").unwrap();
        coverage.observe_link(&p, from, &document, None, "/search?q=cables#top");
        coverage.observe_link(&p, from, &document, None, "https://evil.example/");
        coverage.observe_link(&p, from, &document, None, "http://[");
        coverage.observe_link(&p, from, &document, None, "/collections/cables?page=2");
        coverage.observe_link(&p, from, &document, None, "/products/x?variant=1");

        let search_id = FetchIdentity::from_url(
            &Url::parse("https://www.tiendacables.com/search?q=cables").unwrap(),
        );
        let search = coverage.url(&search_id).unwrap();
        assert_eq!(search.original, "/search?q=cables#top");
        assert_eq!(search.skip_reason, Some("Excluded path prefix"));
        assert!(!search.fetched);
        assert_eq!(
            coverage.mark_fetched(&search_id),
            Err("Excluded path prefix")
        );
        assert!(!coverage.url(&search_id).unwrap().fetched);

        let external = coverage
            .url(&FetchIdentity::from_url(
                &Url::parse("https://evil.example/").unwrap(),
            ))
            .unwrap();
        assert_eq!(external.skip_reason, Some("Outside configured origin"));
        assert!(!external.fetched);

        let malformed = coverage.unresolved("http://[").unwrap();
        assert_eq!(malformed.skip_reason, Some(SKIP_MALFORMED));
        assert!(!malformed.fetched);

        let page = coverage
            .url(&FetchIdentity::from_url(
                &Url::parse("https://www.tiendacables.com/collections/cables?page=2").unwrap(),
            ))
            .unwrap();
        assert!(page.skip_reason.is_none());
        assert!(!page.fetched);

        assert_eq!(coverage.links().len(), 5);
        assert!(
            coverage
                .links()
                .iter()
                .any(|link| link.href == "/search?q=cables#top"
                    && link.skip_reason == Some("Excluded path prefix"))
        );
        assert!(
            coverage
                .links()
                .iter()
                .any(|link| link.href == "http://[" && link.to_identity.is_none())
        );
        assert!(coverage.urls().any(|url| url.fetched));
        assert!(coverage.urls().filter(|url| !url.fetched).count() >= 4);
    }
}
