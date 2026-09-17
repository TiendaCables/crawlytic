//! Inventory checkers over stored observations.
//!
//! HTML metadata (TC-458) and link/URL-shape (TC-459) checkers live here.
//! Other catalogue stages stay unregistered and resolve to
//! [`crate::catalogue::RuleState::Unsupported`].

mod links;
mod meta;

pub use links::{
    DEFAULT_GENERIC_ANCHORS, DEFAULT_MAX_LINK_CHARS, DEFAULT_MAX_ON_PAGE_LINKS,
    DEFAULT_MAX_QUERY_PARAMS, DEFAULT_MAX_REDIRECTS, DEFAULT_MAX_URL_CHARS, link_audit_registry,
    register_link_audit,
};
pub use meta::{
    DEFAULT_MAX_HTML_BYTES, DEFAULT_MAX_TITLE_CHARS, DEFAULT_MIN_TITLE_CHARS,
    html_metadata_registry, normalize_meta, register_html_metadata,
};

use crate::audit::Registry;

pub fn audit_registry() -> Registry {
    let mut registry = Registry::new();
    register_html_metadata(&mut registry);
    register_link_audit(&mut registry);
    registry
}
