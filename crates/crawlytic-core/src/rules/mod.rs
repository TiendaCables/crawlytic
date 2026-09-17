//! Inventory checkers over stored observations.
//!
//! HTML metadata (TC-458), link/URL-shape (TC-459), canonical/indexability
//! (TC-460), crawl-depth/orphan (TC-461), image/script/style (TC-462) and
//! hreflang/lang (TC-465) checkers live here. Other catalogue stages stay
//! unregistered and resolve to [`crate::catalogue::RuleState::Unsupported`].

mod hreflang;
mod indexability;
mod links;
mod meta;
mod navigation;
mod resources;

pub use hreflang::{
    DEFAULT_MIN_LANGUAGE_CONFIDENCE, DEFAULT_MIN_LANGUAGE_HITS, hreflang_registry,
    register_hreflang,
};
pub use indexability::{
    DEFAULT_MAX_SITEMAP_BYTES, DEFAULT_MAX_SITEMAP_URLS, indexability_registry,
    register_indexability,
};
pub use links::{
    DEFAULT_GENERIC_ANCHORS, DEFAULT_MAX_LINK_CHARS, DEFAULT_MAX_ON_PAGE_LINKS,
    DEFAULT_MAX_QUERY_PARAMS, DEFAULT_MAX_REDIRECTS, DEFAULT_MAX_URL_CHARS, link_audit_registry,
    register_link_audit,
};
pub use meta::{
    DEFAULT_MAX_HTML_BYTES, DEFAULT_MAX_TITLE_CHARS, DEFAULT_MIN_TITLE_CHARS,
    html_metadata_registry, normalize_meta, register_html_metadata,
};
pub use navigation::{
    DEFAULT_MAX_CLICKS, NavigationGraph, PageNavigation, build_navigation_graph,
    navigation_registry, register_navigation,
};
pub use resources::{register_resource_audit, resource_audit_registry};

use crate::audit::Registry;

pub fn audit_registry() -> Registry {
    let mut registry = Registry::new();
    register_html_metadata(&mut registry);
    register_link_audit(&mut registry);
    register_indexability(&mut registry);
    register_navigation(&mut registry);
    register_resource_audit(&mut registry);
    register_hreflang(&mut registry);
    registry
}
