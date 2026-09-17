//! Inventory checkers over stored observations.
//!
//! HTML metadata rules owned by TC-458 live here. Other catalogue stages stay
//! unregistered and resolve to [`crate::catalogue::RuleState::Unsupported`].

mod meta;

pub use meta::{
    DEFAULT_MAX_HTML_BYTES, DEFAULT_MAX_TITLE_CHARS, DEFAULT_MIN_TITLE_CHARS,
    html_metadata_registry, normalize_meta, register_html_metadata,
};
