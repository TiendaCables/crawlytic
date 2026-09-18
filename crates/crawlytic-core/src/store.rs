//! SQLite persistence for crawl runs, observations and a resumable frontier.
//!
//! Secrets never enter the store. Signature and Signature-Input values are
//! rejected before a profile snapshot is written. Raw HTML is optional and
//! quota-bounded. Writer statements share a transaction until the batch limit
//! is reached or `flush` is called.

use crate::audit::{
    AuditReport, EvidencePointer, Finding, FindingId, RULE_CONFIG_VERSION, RuleOutcome,
    Suppression, SuppressionAction, SuppressionEvent,
};
use crate::catalogue::{CATALOGUE_VERSION, FIXTURE_CONTRACT_VERSION};
use crate::catalogue::{RuleState, Severity};
use crate::crawl::{
    SitemapFileRecord, SitemapFileState, SitemapInventory, SitemapUrlRecord, UrlRecord, UrlState,
};
use crate::extract::{
    EmbeddedKind, ExtractedObservations, Heading, HostOwner, Hreflang, LinkObservation,
    ObservationFlags, PageObservation, RedirectHop, ResourceFetch, ResourceObservation,
    StructuredBlock, StructuredFormat,
};
use crate::history::{RunComparison, RunView, compare_runs as classify_runs};
use crate::https::{HostProbe, HostProbeKind, TlsInspection};
use crate::profile::Profile;
use crate::robots::{RobotsFetchState, RobotsRunMetadata};
use crate::scope::{CoverageLink, CoverageUrl, FetchIdentity};
use crate::transport::{FetchRecord, ResourceKind};
use rusqlite::{Connection, OptionalExtension, params};
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

pub const STORE_SCHEMA_VERSION: i64 = 9;
const DEFAULT_BATCH_SIZE: usize = 32;

const MIGRATION_1: &str = "
CREATE TABLE profiles (
    id INTEGER PRIMARY KEY,
    toml TEXT NOT NULL
);
CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profiles(id),
    catalogue_version INTEGER NOT NULL,
    fixture_contract_version INTEGER NOT NULL,
    status TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    cancelled INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    sitemap_done INTEGER NOT NULL DEFAULT 0,
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE url_states (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    record_key TEXT NOT NULL,
    original TEXT NOT NULL,
    identity TEXT,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    click_depth INTEGER,
    via_website INTEGER NOT NULL,
    via_sitemap INTEGER NOT NULL,
    PRIMARY KEY (run_id, record_key)
);
CREATE TABLE frontier (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    identity TEXT NOT NULL,
    PRIMARY KEY (run_id, position)
);
CREATE TABLE fetches (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    identity TEXT NOT NULL,
    requested_url TEXT NOT NULL,
    destination_url TEXT NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    bytes_sampled INTEGER NOT NULL,
    resource_kind TEXT NOT NULL,
    credentials_attached INTEGER NOT NULL,
    truncated INTEGER NOT NULL,
    UNIQUE (run_id, identity, resource_kind)
);
CREATE TABLE html_bodies (
    fetch_id INTEGER PRIMARY KEY REFERENCES fetches(id) ON DELETE CASCADE,
    body BLOB NOT NULL
);
CREATE TABLE links (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    from_identity TEXT NOT NULL,
    href TEXT NOT NULL,
    to_original TEXT NOT NULL,
    to_identity TEXT,
    skip_reason TEXT,
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE resource_refs (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    identity TEXT NOT NULL,
    kind TEXT NOT NULL,
    referring_identity TEXT,
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE sitemap_files (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    url TEXT NOT NULL,
    identity TEXT,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    listed_urls INTEGER NOT NULL,
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE sitemap_urls (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    original TEXT NOT NULL,
    identity TEXT,
    skip_reason TEXT,
    source_sitemap TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE findings (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    evidence TEXT NOT NULL,
    PRIMARY KEY (run_id, rule_id, entity_key)
);
CREATE TABLE store_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

const MIGRATION_2: &str = "
CREATE TABLE page_observations (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    identity TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    complete INTEGER NOT NULL,
    truncated INTEGER NOT NULL,
    challenge INTEGER NOT NULL,
    error_status INTEGER NOT NULL,
    non_html INTEGER NOT NULL,
    encoding_fallback INTEGER NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    duration_ms INTEGER,
    raw_bytes INTEGER NOT NULL,
    decoded_bytes INTEGER NOT NULL,
    encoding TEXT NOT NULL,
    doctype TEXT,
    html_lang TEXT,
    viewport TEXT,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity)
);
CREATE TABLE observation_titles (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_descriptions (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_headings (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    level INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_robots_meta (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_robots_headers (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_canonicals (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_hreflangs (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    lang TEXT NOT NULL,
    href TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE link_observations (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    source TEXT NOT NULL,
    href TEXT NOT NULL,
    destination TEXT,
    anchor TEXT NOT NULL,
    rel TEXT NOT NULL,
    element TEXT NOT NULL,
    host_owner TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE resource_observations (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    referring TEXT NOT NULL,
    kind TEXT NOT NULL,
    href TEXT NOT NULL,
    destination TEXT,
    alt TEXT,
    host_owner TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
";

const MIGRATION_3: &str = "
ALTER TABLE findings ADD COLUMN fact TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN recommendation TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN severity TEXT NOT NULL DEFAULT 'notice';
ALTER TABLE findings ADD COLUMN state TEXT NOT NULL DEFAULT 'findings';
ALTER TABLE findings ADD COLUMN config_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN catalogue_version INTEGER NOT NULL DEFAULT 1;
UPDATE findings SET fact = evidence WHERE fact = '';
CREATE TABLE finding_evidence (
    run_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    seq INTEGER NOT NULL,
    observation_identity TEXT NOT NULL,
    field TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    PRIMARY KEY (run_id, rule_id, entity_key, seq),
    FOREIGN KEY (run_id, rule_id, entity_key) REFERENCES findings(run_id, rule_id, entity_key) ON DELETE CASCADE
);
CREATE TABLE rule_outcomes (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    state TEXT NOT NULL,
    config_version INTEGER NOT NULL,
    PRIMARY KEY (run_id, rule_id)
);
CREATE TABLE suppressions (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id TEXT,
    entity_key TEXT,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE suppression_events (
    id INTEGER PRIMARY KEY,
    suppression_id INTEGER NOT NULL REFERENCES suppressions(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE TABLE audit_evaluations (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    evaluated_at INTEGER NOT NULL,
    config_version INTEGER NOT NULL,
    config_fingerprint TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
";

const MIGRATION_4: &str = "
ALTER TABLE page_observations ADD COLUMN charset_declared INTEGER NOT NULL DEFAULT 0;
ALTER TABLE page_observations ADD COLUMN has_frames INTEGER NOT NULL DEFAULT 0;
ALTER TABLE page_observations ADD COLUMN has_plugin_markup INTEGER NOT NULL DEFAULT 0;
";

const MIGRATION_5: &str = "
CREATE TABLE observation_meta_refresh (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
CREATE TABLE observation_redirects (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    from_url TEXT NOT NULL,
    to_url TEXT NOT NULL,
    status INTEGER NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
";

const MIGRATION_6: &str = "
CREATE TABLE robots_runs (
    run_id INTEGER PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    product_token TEXT NOT NULL,
    selected_group TEXT,
    bypass_robots INTEGER NOT NULL,
    bypass_meta INTEGER NOT NULL,
    fetch_kind TEXT NOT NULL,
    fetch_status INTEGER,
    fetch_observation TEXT,
    sitemaps TEXT NOT NULL,
    format_errors TEXT NOT NULL,
    crawl_delay_notes TEXT NOT NULL
);
";

const MIGRATION_7: &str = "
CREATE TABLE resource_fetches (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    identity TEXT NOT NULL,
    status INTEGER,
    failed_reason TEXT,
    challenge INTEGER NOT NULL,
    credentials_attached INTEGER NOT NULL,
    robots_blocked INTEGER NOT NULL,
    robots_known INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    PRIMARY KEY (run_id, identity)
);
";

const MIGRATION_8: &str = "
CREATE TABLE observation_structured (
    run_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    seq INTEGER NOT NULL,
    format TEXT NOT NULL,
    block_index INTEGER NOT NULL,
    raw TEXT NOT NULL,
    types TEXT NOT NULL,
    PRIMARY KEY (run_id, identity, seq)
);
";

const MIGRATION_9: &str = "
CREATE TABLE tls_inspections (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    inspected INTEGER NOT NULL,
    verified INTEGER NOT NULL,
    hostname_ok INTEGER NOT NULL,
    not_before_unix INTEGER,
    not_after_unix INTEGER,
    names TEXT NOT NULL,
    error TEXT,
    credentials_attached INTEGER NOT NULL,
    PRIMARY KEY (run_id, host, port)
);
CREATE TABLE host_probes (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    requested_url TEXT NOT NULL,
    destination_url TEXT,
    status INTEGER,
    canonicals TEXT NOT NULL,
    failed_reason TEXT,
    credentials_attached INTEGER NOT NULL,
    PRIMARY KEY (run_id, kind)
);
CREATE TABLE host_probe_redirects (
    run_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    seq INTEGER NOT NULL,
    from_url TEXT NOT NULL,
    to_url TEXT NOT NULL,
    status INTEGER NOT NULL,
    PRIMARY KEY (run_id, kind, seq)
);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorKind {
    DiskFull,
    Migration,
    Secrets,
    Other,
}

#[derive(Debug)]
pub struct StoreError {
    kind: StoreErrorKind,
    message: String,
}

impl StoreError {
    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    pub fn is_disk_full(&self) -> bool {
        self.kind == StoreErrorKind::DiskFull
    }

    pub fn is_migration(&self) -> bool {
        self.kind == StoreErrorKind::Migration
    }

    pub fn is_secrets(&self) -> bool {
        self.kind == StoreErrorKind::Secrets
    }

    fn disk_full(message: impl Into<String>) -> Self {
        Self {
            kind: StoreErrorKind::DiskFull,
            message: message.into(),
        }
    }

    fn migration(message: impl Into<String>) -> Self {
        Self {
            kind: StoreErrorKind::Migration,
            message: message.into(),
        }
    }

    fn secrets(message: impl Into<String>) -> Self {
        Self {
            kind: StoreErrorKind::Secrets,
            message: message.into(),
        }
    }

    fn other(message: impl Into<String>) -> Self {
        Self {
            kind: StoreErrorKind::Other,
            message: message.into(),
        }
    }
}

impl Display for StoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self.kind {
            StoreErrorKind::DiskFull => "Disk full",
            StoreErrorKind::Migration => "Migration failed",
            StoreErrorKind::Secrets => "Refusing to store secrets",
            StoreErrorKind::Other => "Store error",
        };
        write!(f, "{label}: {}", self.message)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Running,
    Completed,
    Incomplete,
    Failed,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "incomplete" => Ok(Self::Incomplete),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::other(format!("Unknown run status {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionPolicy {
    pub retain_raw_html: bool,
    pub max_html_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    pub id: i64,
    pub status: RunStatus,
    pub completed: bool,
    pub cancelled: bool,
    pub error: Option<String>,
    pub started_at: i64,
    pub updated_at: i64,
    pub start_url: String,
    pub url_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRecord {
    pub rule_id: String,
    pub entity_key: String,
    pub evidence: String,
    pub fact: String,
    pub recommendation: String,
    pub severity: String,
    pub state: String,
    pub config_version: u32,
    pub catalogue_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    pub identity: String,
    pub kind: String,
    pub referring_identity: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoadedRun {
    pub id: i64,
    pub profile: Profile,
    pub profile_toml: String,
    pub status: RunStatus,
    pub completed: bool,
    pub cancelled: bool,
    pub error: Option<String>,
    pub catalogue_version: u32,
    pub urls: Vec<UrlRecord>,
    pub frontier: Vec<FetchIdentity>,
    pub links: Vec<CoverageLink>,
    pub coverage_urls: Vec<CoverageUrl>,
    pub fetches: Vec<FetchRecord>,
    pub resources: Vec<ResourceRef>,
    pub sitemap: SitemapInventory,
    pub sitemap_done: bool,
    pub robots: Option<RobotsRunMetadata>,
    pub findings: Vec<FindingRecord>,
    pub observations: Vec<ExtractedObservations>,
    pub resource_fetches: Vec<ResourceFetch>,
    pub tls_inspections: Vec<TlsInspection>,
    pub host_probes: Vec<HostProbe>,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    conn: Connection,
    batch_size: usize,
    pending: usize,
    in_tx: bool,
    retention: RetentionPolicy,
    html_bytes: u64,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(|err| {
            if is_disk_full(&err) {
                StoreError::disk_full(err.to_string())
            } else {
                StoreError::migration(err.to_string())
            }
        })?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn =
            Connection::open_in_memory().map_err(|err| StoreError::migration(err.to_string()))?;
        Self::from_connection(conn)
    }

    fn from_connection(mut conn: Connection) -> Result<Self, StoreError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|err| StoreError::other(err.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|err| StoreError::other(err.to_string()))?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        migrate(&mut conn)?;
        let retention = load_retention(&conn)?;
        let html_bytes = load_html_bytes(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                conn,
                batch_size: DEFAULT_BATCH_SIZE,
                pending: 0,
                in_tx: false,
                retention,
                html_bytes,
            })),
        })
    }

    pub fn with_batch_size(self, batch_size: usize) -> Self {
        self.lock().batch_size = batch_size.max(1);
        self
    }

    pub fn set_retention(&self, policy: RetentionPolicy) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT INTO store_settings(key, value) VALUES ('retain_raw_html', ?1)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![if policy.retain_raw_html { "1" } else { "0" }],
            )?;
            conn.execute(
                "INSERT INTO store_settings(key, value) VALUES ('max_html_bytes', ?1)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![policy.max_html_bytes.to_string()],
            )?;
            Ok(())
        })?;
        inner.retention = policy;
        inner.commit()
    }

    pub fn retention(&self) -> RetentionPolicy {
        self.lock().retention
    }

    /// Write a consistent SQLite snapshot with `VACUUM INTO`.
    /// The destination must not already exist. Secrets never enter the store.
    pub fn backup(&self, dest: &Path) -> Result<(), StoreError> {
        let dest_str = dest
            .to_str()
            .ok_or_else(|| StoreError::other("backup destination is not valid UTF-8"))?;
        if dest_str.is_empty() {
            return Err(StoreError::other("backup destination is required"));
        }
        let mut inner = self.lock();
        inner.commit()?;
        inner
            .conn
            .execute("VACUUM INTO ?1", params![dest_str])
            .map_err(map_write)?;
        Ok(())
    }

    pub fn begin_run(&self, profile: &Profile) -> Result<i64, StoreError> {
        let toml = serialize_profile(profile)?;
        let mut inner = self.lock();
        let now = now_secs();
        inner
            .write(|conn| {
                conn.execute("INSERT INTO profiles(toml) VALUES (?1)", params![toml])?;
                let profile_id = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO runs(
                    profile_id, catalogue_version, fixture_contract_version,
                    status, completed, cancelled, sitemap_done, started_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 0, 0, 0, ?5, ?5)",
                    params![
                        profile_id,
                        CATALOGUE_VERSION,
                        FIXTURE_CONTRACT_VERSION,
                        RunStatus::Running.as_str(),
                        now,
                    ],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .and_then(|id| {
                inner.commit()?;
                Ok(id)
            })
    }

    pub fn upsert_url(&self, run_id: i64, record: &UrlRecord) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT INTO url_states(
                    run_id, record_key, original, identity, state, reason,
                    click_depth, via_website, via_sitemap
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(run_id, record_key) DO UPDATE SET
                    original=excluded.original,
                    identity=excluded.identity,
                    state=excluded.state,
                    reason=excluded.reason,
                    click_depth=excluded.click_depth,
                    via_website=excluded.via_website,
                    via_sitemap=excluded.via_sitemap",
                params![
                    run_id,
                    record_key(record),
                    record.original,
                    record.identity.as_ref().map(FetchIdentity::as_str),
                    url_state_str(record.state),
                    record.reason,
                    record.click_depth,
                    record.via_website as i64,
                    record.via_sitemap as i64,
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn replace_frontier(
        &self,
        run_id: i64,
        frontier: impl IntoIterator<Item = FetchIdentity>,
    ) -> Result<(), StoreError> {
        let identities: Vec<String> = frontier
            .into_iter()
            .map(|identity| identity.as_str().to_owned())
            .collect();
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute("DELETE FROM frontier WHERE run_id = ?1", params![run_id])?;
            for (position, identity) in identities.iter().enumerate() {
                conn.execute(
                    "INSERT INTO frontier(run_id, position, identity) VALUES (?1, ?2, ?3)",
                    params![run_id, position as i64, identity],
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn replace_links(&self, run_id: i64, links: &[CoverageLink]) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute("DELETE FROM links WHERE run_id = ?1", params![run_id])?;
            for (seq, link) in links.iter().enumerate() {
                conn.execute(
                    "INSERT INTO links(
                        run_id, seq, from_identity, href, to_original, to_identity, skip_reason
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        run_id,
                        seq as i64,
                        link.from_identity.as_str(),
                        link.href,
                        link.to_original,
                        link.to_identity.as_ref().map(FetchIdentity::as_str),
                        link.skip_reason,
                    ],
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn upsert_fetch(
        &self,
        run_id: i64,
        identity: &FetchIdentity,
        record: &FetchRecord,
        body: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        let retain = inner.retention;
        let used = inner.html_bytes;
        let fetch_id = inner.write(|conn| {
            conn.execute(
                "INSERT INTO fetches(
                    run_id, identity, requested_url, destination_url, status, content_type,
                    bytes_sampled, resource_kind, credentials_attached, truncated
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(run_id, identity, resource_kind) DO UPDATE SET
                    requested_url=excluded.requested_url,
                    destination_url=excluded.destination_url,
                    status=excluded.status,
                    content_type=excluded.content_type,
                    bytes_sampled=excluded.bytes_sampled,
                    credentials_attached=excluded.credentials_attached,
                    truncated=excluded.truncated",
                params![
                    run_id,
                    identity.as_str(),
                    record.requested_url.as_str(),
                    record.destination_url.as_str(),
                    record.status,
                    record.content_type,
                    record.bytes_sampled as i64,
                    resource_kind_str(record.resource_kind),
                    record.credentials_attached as i64,
                    record.truncated as i64,
                ],
            )?;
            let id: i64 = conn.query_row(
                "SELECT id FROM fetches WHERE run_id = ?1 AND identity = ?2 AND resource_kind = ?3",
                params![
                    run_id,
                    identity.as_str(),
                    resource_kind_str(record.resource_kind)
                ],
                |row| row.get(0),
            )?;
            Ok(id)
        })?;
        if let Some(body) = body
            && retain.retain_raw_html
            && !body.is_empty()
        {
            let add = body.len() as u64;
            if used.saturating_add(add) <= retain.max_html_bytes {
                inner.write(|conn| {
                    conn.execute(
                        "INSERT INTO html_bodies(fetch_id, body) VALUES (?1, ?2)
                         ON CONFLICT(fetch_id) DO UPDATE SET body=excluded.body",
                        params![fetch_id, body],
                    )?;
                    Ok(())
                })?;
                inner.html_bytes = used + add;
            }
        }
        Ok(())
    }

    pub fn add_resource_ref(
        &self,
        run_id: i64,
        identity: &str,
        kind: ResourceKind,
        referring_identity: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            let seq: i64 = conn.query_row(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM resource_refs WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )?;
            conn.execute(
                "INSERT INTO resource_refs(run_id, seq, identity, kind, referring_identity)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    run_id,
                    seq,
                    identity,
                    resource_kind_str(kind),
                    referring_identity
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn put_resource_fetch(&self, run_id: i64, fetch: &ResourceFetch) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT INTO resource_fetches(
                    run_id, identity, status, failed_reason, challenge, credentials_attached,
                    robots_blocked, robots_known, content_type
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(run_id, identity) DO UPDATE SET
                    status=excluded.status,
                    failed_reason=excluded.failed_reason,
                    challenge=excluded.challenge,
                    credentials_attached=excluded.credentials_attached,
                    robots_blocked=excluded.robots_blocked,
                    robots_known=excluded.robots_known,
                    content_type=excluded.content_type",
                params![
                    run_id,
                    fetch.identity,
                    fetch.status.map(|status| status as i64),
                    fetch.failed_reason.as_deref(),
                    fetch.challenge as i64,
                    fetch.credentials_attached as i64,
                    fetch.robots_blocked as i64,
                    fetch.robots_known as i64,
                    fetch.content_type,
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn put_tls_inspection(
        &self,
        run_id: i64,
        inspection: &TlsInspection,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT INTO tls_inspections(
                    run_id, host, port, inspected, verified, hostname_ok,
                    not_before_unix, not_after_unix, names, error, credentials_attached
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(run_id, host, port) DO UPDATE SET
                    inspected=excluded.inspected,
                    verified=excluded.verified,
                    hostname_ok=excluded.hostname_ok,
                    not_before_unix=excluded.not_before_unix,
                    not_after_unix=excluded.not_after_unix,
                    names=excluded.names,
                    error=excluded.error,
                    credentials_attached=excluded.credentials_attached",
                params![
                    run_id,
                    inspection.host,
                    inspection.port as i64,
                    inspection.inspected as i64,
                    inspection.verified as i64,
                    inspection.hostname_ok as i64,
                    inspection.not_before_unix,
                    inspection.not_after_unix,
                    inspection.names.join("\n"),
                    inspection.error.as_deref(),
                    inspection.credentials_attached as i64,
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn put_host_probe(&self, run_id: i64, probe: &HostProbe) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT INTO host_probes(
                    run_id, kind, requested_url, destination_url, status, canonicals,
                    failed_reason, credentials_attached
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(run_id, kind) DO UPDATE SET
                    requested_url=excluded.requested_url,
                    destination_url=excluded.destination_url,
                    status=excluded.status,
                    canonicals=excluded.canonicals,
                    failed_reason=excluded.failed_reason,
                    credentials_attached=excluded.credentials_attached",
                params![
                    run_id,
                    probe.kind.as_str(),
                    probe.requested_url,
                    probe.destination_url.as_deref(),
                    probe.status.map(|status| status as i64),
                    probe.canonicals.join("\n"),
                    probe.failed_reason.as_deref(),
                    probe.credentials_attached as i64,
                ],
            )?;
            conn.execute(
                "DELETE FROM host_probe_redirects WHERE run_id = ?1 AND kind = ?2",
                params![run_id, probe.kind.as_str()],
            )?;
            for (seq, hop) in probe.redirect_chain.iter().enumerate() {
                conn.execute(
                    "INSERT INTO host_probe_redirects(
                        run_id, kind, seq, from_url, to_url, status
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        run_id,
                        probe.kind.as_str(),
                        seq as i64,
                        hop.from,
                        hop.to,
                        hop.status as i64,
                    ],
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn save_robots(&self, run_id: i64, robots: &RobotsRunMetadata) -> Result<(), StoreError> {
        let (fetch_kind, fetch_status, fetch_observation) = match &robots.fetch {
            RobotsFetchState::Fetched { status } => ("fetched", Some(*status as i64), None),
            RobotsFetchState::NotFound { status } => ("not_found", Some(*status as i64), None),
            RobotsFetchState::Unavailable { observation } => {
                ("unavailable", None, Some(observation.as_str()))
            }
        };
        let sitemaps = robots
            .sitemaps
            .iter()
            .map(Url::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        let format_errors = robots.format_errors.join("\n");
        let crawl_delay_notes = robots.crawl_delay_notes.join("\n");
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT INTO robots_runs(
                    run_id, origin, user_agent, product_token, selected_group,
                    bypass_robots, bypass_meta, fetch_kind, fetch_status, fetch_observation,
                    sitemaps, format_errors, crawl_delay_notes
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(run_id) DO UPDATE SET
                    origin=excluded.origin,
                    user_agent=excluded.user_agent,
                    product_token=excluded.product_token,
                    selected_group=excluded.selected_group,
                    bypass_robots=excluded.bypass_robots,
                    bypass_meta=excluded.bypass_meta,
                    fetch_kind=excluded.fetch_kind,
                    fetch_status=excluded.fetch_status,
                    fetch_observation=excluded.fetch_observation,
                    sitemaps=excluded.sitemaps,
                    format_errors=excluded.format_errors,
                    crawl_delay_notes=excluded.crawl_delay_notes",
                params![
                    run_id,
                    robots.origin,
                    robots.user_agent,
                    robots.product_token,
                    robots.selected_group,
                    robots.bypass_robots as i64,
                    robots.bypass_meta as i64,
                    fetch_kind,
                    fetch_status,
                    fetch_observation,
                    sitemaps,
                    format_errors,
                    crawl_delay_notes,
                ],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn save_sitemap(&self, run_id: i64, sitemap: &SitemapInventory) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "DELETE FROM sitemap_files WHERE run_id = ?1",
                params![run_id],
            )?;
            conn.execute(
                "DELETE FROM sitemap_urls WHERE run_id = ?1",
                params![run_id],
            )?;
            for (seq, file) in sitemap.files.iter().enumerate() {
                conn.execute(
                    "INSERT INTO sitemap_files(
                        run_id, seq, url, identity, state, reason, listed_urls
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        run_id,
                        seq as i64,
                        file.url,
                        file.identity.as_ref().map(FetchIdentity::as_str),
                        sitemap_file_state_str(file.state),
                        file.reason,
                        file.listed_urls as i64,
                    ],
                )?;
            }
            for (seq, listed) in sitemap.urls.iter().enumerate() {
                conn.execute(
                    "INSERT INTO sitemap_urls(
                        run_id, seq, original, identity, skip_reason, source_sitemap
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        run_id,
                        seq as i64,
                        listed.original,
                        listed.identity.as_ref().map(FetchIdentity::as_str),
                        listed.skip_reason,
                        listed.source_sitemap,
                    ],
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn mark_sitemap_done(&self, run_id: i64) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "UPDATE runs SET sitemap_done = 1, updated_at = ?2 WHERE id = ?1",
                params![run_id, now_secs()],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn put_observation(
        &self,
        run_id: i64,
        observation: &ExtractedObservations,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            let identity = observation.identity.as_str();
            conn.execute(
                "DELETE FROM observation_titles WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_descriptions WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_headings WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_robots_meta WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_robots_headers WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_canonicals WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_hreflangs WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_meta_refresh WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_redirects WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM observation_structured WHERE run_id = ?1 AND identity = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM link_observations WHERE run_id = ?1 AND source = ?2",
                params![run_id, identity],
            )?;
            conn.execute(
                "DELETE FROM resource_observations WHERE run_id = ?1 AND referring = ?2",
                params![run_id, identity],
            )?;
            let page = &observation.page;
            conn.execute(
                "INSERT INTO page_observations(
                    run_id, identity, schema_version, complete, truncated, challenge,
                    error_status, non_html, encoding_fallback, status, content_type,
                    duration_ms, raw_bytes, decoded_bytes, encoding, doctype, html_lang,
                    viewport, text, charset_declared, has_frames, has_plugin_markup
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)
                 ON CONFLICT(run_id, identity) DO UPDATE SET
                    schema_version=excluded.schema_version,
                    complete=excluded.complete,
                    truncated=excluded.truncated,
                    challenge=excluded.challenge,
                    error_status=excluded.error_status,
                    non_html=excluded.non_html,
                    encoding_fallback=excluded.encoding_fallback,
                    status=excluded.status,
                    content_type=excluded.content_type,
                    duration_ms=excluded.duration_ms,
                    raw_bytes=excluded.raw_bytes,
                    decoded_bytes=excluded.decoded_bytes,
                    encoding=excluded.encoding,
                    doctype=excluded.doctype,
                    html_lang=excluded.html_lang,
                    viewport=excluded.viewport,
                    text=excluded.text,
                    charset_declared=excluded.charset_declared,
                    has_frames=excluded.has_frames,
                    has_plugin_markup=excluded.has_plugin_markup",
                params![
                    run_id,
                    identity,
                    page.schema_version as i64,
                    page.is_complete() as i64,
                    page.flags.truncated as i64,
                    page.flags.challenge as i64,
                    page.flags.error_status as i64,
                    page.flags.non_html as i64,
                    page.flags.encoding_fallback as i64,
                    page.status,
                    page.content_type,
                    page.duration_ms.map(|ms| ms as i64),
                    page.raw_bytes as i64,
                    page.decoded_bytes as i64,
                    page.encoding,
                    page.doctype,
                    page.html_lang,
                    page.viewport,
                    page.text,
                    page.charset_declared as i64,
                    page.has_frames as i64,
                    page.has_plugin_markup as i64,
                ],
            )?;
            insert_strings(conn, "observation_titles", run_id, identity, &page.titles)?;
            insert_strings(
                conn,
                "observation_descriptions",
                run_id,
                identity,
                &page.descriptions,
            )?;
            for (seq, heading) in page.headings.iter().enumerate() {
                conn.execute(
                    "INSERT INTO observation_headings(run_id, identity, seq, level, text)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![run_id, identity, seq as i64, heading.level, heading.text],
                )?;
            }
            insert_strings(
                conn,
                "observation_robots_meta",
                run_id,
                identity,
                &page.robots_meta,
            )?;
            insert_strings(
                conn,
                "observation_robots_headers",
                run_id,
                identity,
                &page.robots_headers,
            )?;
            insert_strings(
                conn,
                "observation_canonicals",
                run_id,
                identity,
                &page.canonicals,
            )?;
            insert_strings(
                conn,
                "observation_meta_refresh",
                run_id,
                identity,
                &page.meta_refresh,
            )?;
            for (seq, hop) in observation.redirect_chain.iter().enumerate() {
                conn.execute(
                    "INSERT INTO observation_redirects(run_id, identity, seq, from_url, to_url, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        run_id,
                        identity,
                        seq as i64,
                        hop.from,
                        hop.to,
                        hop.status
                    ],
                )?;
            }
            for (seq, item) in page.hreflangs.iter().enumerate() {
                conn.execute(
                    "INSERT INTO observation_hreflangs(run_id, identity, seq, lang, href)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![run_id, identity, seq as i64, item.lang, item.href],
                )?;
            }
            for (seq, block) in page.structured.iter().enumerate() {
                let types = serde_json::to_string(&block.types).unwrap_or_else(|_| "[]".into());
                conn.execute(
                    "INSERT INTO observation_structured(
                        run_id, identity, seq, format, block_index, raw, types
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        run_id,
                        identity,
                        seq as i64,
                        block.format.as_str(),
                        block.index as i64,
                        block.raw,
                        types
                    ],
                )?;
            }
            let link_start: i64 = conn.query_row(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM link_observations WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )?;
            for (offset, link) in observation.links.iter().enumerate() {
                conn.execute(
                    "INSERT INTO link_observations(
                        run_id, seq, source, href, destination, anchor, rel, element, host_owner
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        run_id,
                        link_start + offset as i64,
                        link.source,
                        link.href,
                        link.destination,
                        link.anchor,
                        link.rel,
                        link.element,
                        link.host_owner.as_str(),
                    ],
                )?;
            }
            let resource_start: i64 = conn.query_row(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM resource_observations WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )?;
            for (offset, resource) in observation.resources.iter().enumerate() {
                conn.execute(
                    "INSERT INTO resource_observations(
                        run_id, seq, referring, kind, href, destination, alt, host_owner
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        run_id,
                        resource_start + offset as i64,
                        resource.referring,
                        resource.kind.as_str(),
                        resource.href,
                        resource.destination,
                        resource.alt,
                        resource.host_owner.as_str(),
                    ],
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn put_finding(
        &self,
        run_id: i64,
        rule_id: &str,
        entity_key: &str,
        evidence: &str,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO findings(
                    run_id, rule_id, entity_key, evidence, fact, recommendation,
                    severity, state, config_version, catalogue_version
                 ) VALUES (?1, ?2, ?3, ?4, ?4, '', 'notice', 'findings', 1, ?5)",
                params![run_id, rule_id, entity_key, evidence, CATALOGUE_VERSION],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn findings(&self, run_id: i64) -> Result<Vec<FindingRecord>, StoreError> {
        self.load_run(run_id).map(|run| run.findings)
    }

    pub fn save_audit_report(&self, report: &AuditReport) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| persist_audit_report(conn, report))?;
        inner.commit()?;
        Ok(())
    }

    pub fn apply_suppression(
        &self,
        run_id: i64,
        rule_id: Option<&str>,
        entity_key: Option<&str>,
        reason: &str,
    ) -> Result<i64, StoreError> {
        if reason.trim().is_empty() {
            return Err(StoreError::other("Suppression reason is required"));
        }
        if rule_id.is_none() && entity_key.is_none() {
            return Err(StoreError::other(
                "Suppression must name a rule, an entity, or both",
            ));
        }
        let mut inner = self.lock();
        let now = now_secs();
        inner
            .write(|conn| {
                conn.execute(
                    "INSERT INTO suppressions(run_id, rule_id, entity_key, reason, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![run_id, rule_id, entity_key, reason, now],
                )?;
                let id = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO suppression_events(suppression_id, action, reason, at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![id, SuppressionAction::Apply.as_str(), reason, now],
                )?;
                Ok(id)
            })
            .and_then(|id| {
                inner.commit()?;
                Ok(id)
            })
    }

    pub fn revoke_suppression(&self, id: i64, reason: &str) -> Result<(), StoreError> {
        if reason.trim().is_empty() {
            return Err(StoreError::other("Suppression reason is required"));
        }
        let mut inner = self.lock();
        let now = now_secs();
        inner.write(|conn| {
            let updated = conn.execute(
                "UPDATE suppressions SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                params![id, now],
            )?;
            if updated == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            conn.execute(
                "INSERT INTO suppression_events(suppression_id, action, reason, at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, SuppressionAction::Revoke.as_str(), reason, now],
            )?;
            Ok(())
        })?;
        inner.commit()?;
        Ok(())
    }

    pub fn suppressions(&self, run_id: i64) -> Result<Vec<Suppression>, StoreError> {
        let inner = self.lock();
        load_suppressions(&inner.conn, run_id)
    }

    pub fn suppression_events(&self, run_id: i64) -> Result<Vec<SuppressionEvent>, StoreError> {
        let inner = self.lock();
        load_suppression_events(&inner.conn, run_id)
    }

    pub fn mark_incomplete(&self, run_id: i64, error: &str) -> Result<(), StoreError> {
        self.finish_run(run_id, RunStatus::Incomplete, false, false, Some(error))
    }

    pub fn finish_run(
        &self,
        run_id: i64,
        status: RunStatus,
        completed: bool,
        cancelled: bool,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.write(|conn| {
            conn.execute(
                "UPDATE runs SET status = ?2, completed = ?3, cancelled = ?4, error = ?5, updated_at = ?6
                 WHERE id = ?1",
                params![
                    run_id,
                    status.as_str(),
                    completed as i64,
                    cancelled as i64,
                    error,
                    now_secs(),
                ],
            )?;
            Ok(())
        })?;
        inner.commit()
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.lock().commit()
    }

    pub fn stored_profile_toml(&self, run_id: i64) -> Result<String, StoreError> {
        Ok(self.load_run(run_id)?.profile_toml)
    }

    pub fn html_body(
        &self,
        run_id: i64,
        identity: &str,
        kind: ResourceKind,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let inner = self.lock();
        inner
            .conn
            .query_row(
                "SELECT b.body FROM html_bodies b
                 JOIN fetches f ON f.id = b.fetch_id
                 WHERE f.run_id = ?1 AND f.identity = ?2 AND f.resource_kind = ?3",
                params![run_id, identity, resource_kind_str(kind)],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_write)
    }

    pub fn load_run(&self, run_id: i64) -> Result<LoadedRun, StoreError> {
        let inner = self.lock();
        load_run_from(&inner.conn, run_id)
    }

    pub fn list_runs(&self) -> Result<Vec<RunSummary>, StoreError> {
        let inner = self.lock();
        list_runs_from(&inner.conn)
    }

    pub fn load_audit_report(&self, run_id: i64) -> Result<AuditReport, StoreError> {
        let inner = self.lock();
        let suppressions = load_suppressions(&inner.conn, run_id)?;
        load_audit_report_from(&inner.conn, run_id, &suppressions)
    }

    pub fn compare_runs(
        &self,
        baseline_run_id: i64,
        later_run_id: i64,
    ) -> Result<RunComparison, StoreError> {
        let baseline = self.load_run(baseline_run_id)?;
        let later = self.load_run(later_run_id)?;
        let baseline_report = self.load_audit_report(baseline_run_id)?;
        let later_report = self.load_audit_report(later_run_id)?;
        let baseline_suppressions = self.suppressions(baseline_run_id)?;
        let later_suppressions = self.suppressions(later_run_id)?;
        Ok(classify_runs(
            &RunView {
                run_id: baseline.id,
                completed: baseline.completed,
                cancelled: baseline.cancelled,
                catalogue_version: baseline.catalogue_version,
                profile: &baseline.profile,
                urls: &baseline.urls,
                report: &baseline_report,
                suppressions: &baseline_suppressions,
            },
            &RunView {
                run_id: later.id,
                completed: later.completed,
                cancelled: later.cancelled,
                catalogue_version: later.catalogue_version,
                profile: &later.profile,
                urls: &later.urls,
                report: &later_report,
                suppressions: &later_suppressions,
            },
        ))
    }

    #[cfg(test)]
    fn limit_pages_to_current(&self) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.commit()?;
        let pages: i64 = inner
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(map_write)?;
        inner
            .conn
            .pragma_update(None, "max_page_count", pages)
            .map_err(map_write)?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl Inner {
    fn write<T>(
        &mut self,
        op: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        if !self.in_tx {
            self.conn
                .execute("BEGIN IMMEDIATE", [])
                .map_err(map_write)?;
            self.in_tx = true;
        }
        match op(&self.conn) {
            Ok(value) => {
                self.pending += 1;
                if self.pending >= self.batch_size {
                    self.commit()?;
                }
                Ok(value)
            }
            Err(err) => {
                self.rollback();
                Err(map_write(err))
            }
        }
    }

    fn commit(&mut self) -> Result<(), StoreError> {
        if self.in_tx {
            self.conn.execute("COMMIT", []).map_err(map_write)?;
            self.in_tx = false;
            self.pending = 0;
        }
        Ok(())
    }

    fn rollback(&mut self) {
        if self.in_tx {
            let _ = self.conn.execute("ROLLBACK", []);
            self.in_tx = false;
            self.pending = 0;
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.rollback();
    }
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn
        .transaction()
        .map_err(|err| StoreError::migration(err.to_string()))?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );",
    )
    .map_err(|err| StoreError::migration(err.to_string()))?;
    let mut current: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
    if current > STORE_SCHEMA_VERSION {
        return Err(StoreError::migration(format!(
            "database schema {current} is newer than {STORE_SCHEMA_VERSION}"
        )));
    }
    if current < 1 {
        tx.execute_batch(MIGRATION_1)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![1, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 1;
    }
    if current < 2 {
        tx.execute_batch(MIGRATION_2)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![2, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 2;
    }
    if current < 3 {
        tx.execute_batch(MIGRATION_3)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![3, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 3;
    }
    if current < 4 {
        tx.execute_batch(MIGRATION_4)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![4, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 4;
    }
    if current < 5 {
        tx.execute_batch(MIGRATION_5)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![5, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 5;
    }
    if current < 6 {
        tx.execute_batch(MIGRATION_6)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![6, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 6;
    }
    if current < 7 {
        tx.execute_batch(MIGRATION_7)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![7, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 7;
    }
    if current < 8 {
        tx.execute_batch(MIGRATION_8)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![8, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
        current = 8;
    }
    if current < 9 {
        tx.execute_batch(MIGRATION_9)
            .map_err(|err| StoreError::migration(err.to_string()))?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            params![9, now_secs()],
        )
        .map_err(|err| StoreError::migration(err.to_string()))?;
    }
    tx.commit()
        .map_err(|err| StoreError::migration(err.to_string()))?;
    Ok(())
}

fn load_retention(conn: &Connection) -> Result<RetentionPolicy, StoreError> {
    let retain = setting(conn, "retain_raw_html")?
        .map(|value| value == "1")
        .unwrap_or(false);
    let max_html_bytes = setting(conn, "max_html_bytes")?
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    Ok(RetentionPolicy {
        retain_raw_html: retain,
        max_html_bytes,
    })
}

fn load_html_bytes(conn: &Connection) -> Result<u64, StoreError> {
    let bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(length(body)), 0) FROM html_bodies",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(bytes as u64)
}

fn setting(conn: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    conn.query_row(
        "SELECT value FROM store_settings WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(map_write)
}

fn list_runs_from(conn: &Connection) -> Result<Vec<RunSummary>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT r.id, r.status, r.completed, r.cancelled, r.error,
                    r.started_at, r.updated_at, p.toml,
                    (SELECT COUNT(*) FROM url_states u WHERE u.run_id = r.id)
             FROM runs r JOIN profiles p ON p.id = r.profile_id
             ORDER BY r.id DESC",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(map_write)?;
    let mut runs = Vec::new();
    for row in rows {
        let (id, status, completed, cancelled, error, started_at, updated_at, toml, url_count) =
            row.map_err(map_write)?;
        reject_secrets(&toml)?;
        let start_url = Profile::load(&toml)
            .map(|profile| profile.start_url.to_string())
            .unwrap_or_else(|_| "(invalid profile snapshot)".into());
        runs.push(RunSummary {
            id,
            status: RunStatus::parse(&status)?,
            completed: completed != 0,
            cancelled: cancelled != 0,
            error,
            started_at,
            updated_at,
            start_url,
            url_count: url_count as u64,
        });
    }
    Ok(runs)
}

fn load_run_from(conn: &Connection, run_id: i64) -> Result<LoadedRun, StoreError> {
    let (profile_toml, status, completed, cancelled, error, catalogue_version, sitemap_done): (
        String,
        String,
        i64,
        i64,
        Option<String>,
        u32,
        i64,
    ) = conn
        .query_row(
            "SELECT p.toml, r.status, r.completed, r.cancelled, r.error,
                    r.catalogue_version, r.sitemap_done
             FROM runs r JOIN profiles p ON p.id = r.profile_id
             WHERE r.id = ?1",
            params![run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(map_write)?;
    reject_secrets(&profile_toml)?;
    let profile = Profile::load(&profile_toml).map_err(|err| StoreError::other(err.to_string()))?;
    let urls = load_urls(conn, run_id)?;
    let frontier = load_frontier(conn, run_id)?;
    let links = load_links(conn, run_id)?;
    let coverage_urls = coverage_from_urls(&urls);
    let fetches = load_fetches(conn, run_id)?;
    let resources = load_resources(conn, run_id)?;
    let sitemap = load_sitemap(conn, run_id)?;
    let findings = load_findings(conn, run_id)?;
    let observations = load_observations(conn, run_id)?;
    Ok(LoadedRun {
        id: run_id,
        profile,
        profile_toml,
        status: RunStatus::parse(&status)?,
        completed: completed != 0,
        cancelled: cancelled != 0,
        error,
        catalogue_version,
        urls,
        frontier,
        links,
        coverage_urls,
        fetches,
        resources,
        sitemap,
        sitemap_done: sitemap_done != 0,
        robots: load_robots(conn, run_id)?,
        findings,
        observations,
        resource_fetches: load_resource_fetches(conn, run_id)?,
        tls_inspections: load_tls_inspections(conn, run_id)?,
        host_probes: load_host_probes(conn, run_id)?,
    })
}

fn load_urls(conn: &Connection, run_id: i64) -> Result<Vec<UrlRecord>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT original, identity, state, reason, click_depth, via_website, via_sitemap
             FROM url_states WHERE run_id = ?1 ORDER BY record_key",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<u32>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(map_write)?;
    let mut urls = Vec::new();
    for row in rows {
        let (original, identity, state, reason, click_depth, via_website, via_sitemap) =
            row.map_err(map_write)?;
        urls.push(UrlRecord {
            original,
            identity: identity.as_deref().map(parse_identity).transpose()?,
            state: parse_url_state(&state)?,
            reason,
            click_depth,
            via_website: via_website != 0,
            via_sitemap: via_sitemap != 0,
        });
    }
    Ok(urls)
}

fn load_frontier(conn: &Connection, run_id: i64) -> Result<Vec<FetchIdentity>, StoreError> {
    let mut stmt = conn
        .prepare("SELECT identity FROM frontier WHERE run_id = ?1 ORDER BY position")
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| row.get::<_, String>(0))
        .map_err(map_write)?;
    let mut frontier = Vec::new();
    for row in rows {
        frontier.push(parse_identity(&row.map_err(map_write)?)?);
    }
    Ok(frontier)
}

fn load_links(conn: &Connection, run_id: i64) -> Result<Vec<CoverageLink>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT from_identity, href, to_original, to_identity, skip_reason
             FROM links WHERE run_id = ?1 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(map_write)?;
    let mut links = Vec::new();
    for row in rows {
        let (from, href, to_original, to_identity, skip_reason) = row.map_err(map_write)?;
        links.push(CoverageLink {
            from_identity: parse_identity(&from)?,
            href,
            to_original,
            to_identity: to_identity.as_deref().map(parse_identity).transpose()?,
            skip_reason: intern_reason(skip_reason),
        });
    }
    Ok(links)
}

fn coverage_from_urls(urls: &[UrlRecord]) -> Vec<CoverageUrl> {
    urls.iter()
        .map(|record| CoverageUrl {
            original: record.original.clone(),
            identity: record.identity.clone(),
            skip_reason: intern_reason(
                matches!(record.state, UrlState::Excluded | UrlState::Blocked)
                    .then(|| record.reason.clone()),
            ),
            fetched: record.state == UrlState::Fetched,
        })
        .collect()
}

fn load_fetches(conn: &Connection, run_id: i64) -> Result<Vec<FetchRecord>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT requested_url, destination_url, status, content_type, bytes_sampled,
                    resource_kind, credentials_attached, truncated
             FROM fetches WHERE run_id = ?1 ORDER BY id",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(map_write)?;
    let mut fetches = Vec::new();
    for row in rows {
        let (
            requested,
            destination,
            status,
            content_type,
            bytes_sampled,
            kind,
            credentials_attached,
            truncated,
        ) = row.map_err(map_write)?;
        fetches.push(FetchRecord {
            requested_url: parse_url(&requested)?,
            destination_url: parse_url(&destination)?,
            status,
            content_type,
            bytes_sampled: bytes_sampled as usize,
            resource_kind: parse_resource_kind(&kind)?,
            credentials_attached: credentials_attached != 0,
            truncated: truncated != 0,
            duration_ms: 0,
            robots_tag_headers: Vec::new(),
            link_headers: Vec::new(),
            redirect_chain: Vec::new(),
        });
    }
    Ok(fetches)
}

fn load_resources(conn: &Connection, run_id: i64) -> Result<Vec<ResourceRef>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT identity, kind, referring_identity FROM resource_refs
             WHERE run_id = ?1 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(map_write)?;
    let mut refs = Vec::new();
    for row in rows {
        let (identity, kind, referring_identity) = row.map_err(map_write)?;
        refs.push(ResourceRef {
            identity,
            kind,
            referring_identity,
        });
    }
    Ok(refs)
}

fn load_resource_fetches(conn: &Connection, run_id: i64) -> Result<Vec<ResourceFetch>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT identity, status, failed_reason, challenge, credentials_attached,
                    robots_blocked, robots_known, content_type
             FROM resource_fetches WHERE run_id = ?1 ORDER BY identity",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(map_write)?;
    let mut fetches = Vec::new();
    for row in rows {
        let (
            identity,
            status,
            failed_reason,
            challenge,
            credentials_attached,
            robots_blocked,
            robots_known,
            content_type,
        ) = row.map_err(map_write)?;
        fetches.push(ResourceFetch {
            identity,
            status: status.map(|value| value as u16),
            failed_reason,
            challenge: challenge != 0,
            credentials_attached: credentials_attached != 0,
            robots_blocked: robots_blocked != 0,
            robots_known: robots_known != 0,
            content_type,
        });
    }
    Ok(fetches)
}

fn load_tls_inspections(conn: &Connection, run_id: i64) -> Result<Vec<TlsInspection>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT host, port, inspected, verified, hostname_ok, not_before_unix,
                    not_after_unix, names, error, credentials_attached
             FROM tls_inspections WHERE run_id = ?1 ORDER BY host, port",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })
        .map_err(map_write)?;
    let mut inspections = Vec::new();
    for row in rows {
        let (
            host,
            port,
            inspected,
            verified,
            hostname_ok,
            not_before_unix,
            not_after_unix,
            names,
            error,
            credentials_attached,
        ) = row.map_err(map_write)?;
        inspections.push(TlsInspection {
            host,
            port: port as u16,
            inspected: inspected != 0,
            verified: verified != 0,
            hostname_ok: hostname_ok != 0,
            not_before_unix,
            not_after_unix,
            names: split_lines(&names),
            error,
            credentials_attached: credentials_attached != 0,
        });
    }
    Ok(inspections)
}

fn load_host_probes(conn: &Connection, run_id: i64) -> Result<Vec<HostProbe>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, requested_url, destination_url, status, canonicals,
                    failed_reason, credentials_attached
             FROM host_probes WHERE run_id = ?1 ORDER BY kind",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(map_write)?;
    let mut collected = Vec::new();
    for row in rows {
        collected.push(row.map_err(map_write)?);
    }
    drop(stmt);
    let mut probes = Vec::new();
    for (
        kind,
        requested_url,
        destination_url,
        status,
        canonicals,
        failed_reason,
        credentials_attached,
    ) in collected
    {
        let kind = HostProbeKind::parse(&kind)
            .ok_or_else(|| StoreError::other(format!("unknown host probe kind {kind}")))?;
        let redirect_chain = load_host_probe_redirects(conn, run_id, kind.as_str())?;
        probes.push(HostProbe {
            kind,
            requested_url,
            destination_url,
            status: status.map(|value| value as u16),
            redirect_chain,
            canonicals: split_lines(&canonicals),
            failed_reason,
            credentials_attached: credentials_attached != 0,
        });
    }
    Ok(probes)
}

fn load_host_probe_redirects(
    conn: &Connection,
    run_id: i64,
    kind: &str,
) -> Result<Vec<RedirectHop>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT from_url, to_url, status FROM host_probe_redirects
             WHERE run_id = ?1 AND kind = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, kind], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(map_write)?;
    let mut hops = Vec::new();
    for row in rows {
        let (from, to, status) = row.map_err(map_write)?;
        hops.push(RedirectHop {
            from,
            to,
            status: status as u16,
        });
    }
    Ok(hops)
}

fn load_sitemap(conn: &Connection, run_id: i64) -> Result<SitemapInventory, StoreError> {
    let mut files_stmt = conn
        .prepare(
            "SELECT url, identity, state, reason, listed_urls FROM sitemap_files
             WHERE run_id = ?1 ORDER BY seq",
        )
        .map_err(map_write)?;
    let file_rows = files_stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(map_write)?;
    let mut files = Vec::new();
    for row in file_rows {
        let (url, identity, state, reason, listed_urls) = row.map_err(map_write)?;
        files.push(SitemapFileRecord {
            url,
            identity: identity.as_deref().map(parse_identity).transpose()?,
            state: parse_sitemap_file_state(&state)?,
            reason,
            listed_urls: listed_urls as usize,
        });
    }
    let mut urls_stmt = conn
        .prepare(
            "SELECT original, identity, skip_reason, source_sitemap FROM sitemap_urls
             WHERE run_id = ?1 ORDER BY seq",
        )
        .map_err(map_write)?;
    let url_rows = urls_stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(map_write)?;
    let mut urls = Vec::new();
    for row in url_rows {
        let (original, identity, skip_reason, source_sitemap) = row.map_err(map_write)?;
        urls.push(SitemapUrlRecord {
            original,
            identity: identity.as_deref().map(parse_identity).transpose()?,
            skip_reason,
            source_sitemap,
        });
    }
    Ok(SitemapInventory { files, urls })
}

fn load_robots(conn: &Connection, run_id: i64) -> Result<Option<RobotsRunMetadata>, StoreError> {
    let row = conn
        .query_row(
            "SELECT origin, user_agent, product_token, selected_group, bypass_robots, bypass_meta,
                    fetch_kind, fetch_status, fetch_observation, sitemaps, format_errors,
                    crawl_delay_notes
             FROM robots_runs WHERE run_id = ?1",
            params![run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()
        .map_err(map_write)?;
    let Some((
        origin,
        user_agent,
        product_token,
        selected_group,
        bypass_robots,
        bypass_meta,
        fetch_kind,
        fetch_status,
        fetch_observation,
        sitemaps,
        format_errors,
        crawl_delay_notes,
    )) = row
    else {
        return Ok(None);
    };
    let fetch = match (fetch_kind.as_str(), fetch_status, fetch_observation) {
        ("fetched", Some(status), _) => RobotsFetchState::Fetched {
            status: status as u16,
        },
        ("not_found", Some(status), _) => RobotsFetchState::NotFound {
            status: status as u16,
        },
        ("unavailable", _, observation) => RobotsFetchState::Unavailable {
            observation: observation.unwrap_or_default(),
        },
        (other, _, _) => {
            return Err(StoreError::other(format!(
                "Unknown robots fetch kind {other}"
            )));
        }
    };
    let sitemaps = if sitemaps.is_empty() {
        Vec::new()
    } else {
        sitemaps
            .split('\n')
            .map(|value| Url::parse(value).map_err(|err| StoreError::other(err.to_string())))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(Some(RobotsRunMetadata {
        origin,
        user_agent,
        product_token,
        selected_group,
        bypass_robots: bypass_robots != 0,
        bypass_meta: bypass_meta != 0,
        fetch,
        sitemaps,
        format_errors: split_lines(&format_errors),
        crawl_delay_notes: split_lines(&crawl_delay_notes),
    }))
}

fn split_lines(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split('\n').map(str::to_owned).collect()
    }
}

fn load_audit_report_from(
    conn: &Connection,
    run_id: i64,
    suppressions: &[Suppression],
) -> Result<AuditReport, StoreError> {
    let evaluation: Option<(i64, String)> = conn
        .query_row(
            "SELECT config_version, config_fingerprint FROM audit_evaluations
             WHERE run_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_write)?;
    let (config_version, config_fingerprint) =
        evaluation.unwrap_or((i64::from(RULE_CONFIG_VERSION), String::new()));
    let outcomes = load_rule_outcomes(conn, run_id)?;
    let findings = load_audit_findings(conn, run_id, suppressions)?;
    Ok(AuditReport {
        run_id,
        config_version: config_version as u32,
        config_fingerprint,
        outcomes,
        findings,
    })
}

fn load_rule_outcomes(conn: &Connection, run_id: i64) -> Result<Vec<RuleOutcome>, StoreError> {
    let mut stmt = conn
        .prepare("SELECT rule_id, state FROM rule_outcomes WHERE run_id = ?1 ORDER BY rule_id")
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(map_write)?;
    let mut outcomes = Vec::new();
    for row in rows {
        let (rule_id, state) = row.map_err(map_write)?;
        let state = RuleState::parse(&state)
            .ok_or_else(|| StoreError::other(format!("Unknown rule state {state}")))?;
        outcomes.push(RuleOutcome { rule_id, state });
    }
    Ok(outcomes)
}

fn load_audit_findings(
    conn: &Connection,
    run_id: i64,
    suppressions: &[Suppression],
) -> Result<Vec<Finding>, StoreError> {
    let records = load_findings(conn, run_id)?;
    let evidence = load_all_finding_evidence(conn, run_id)?;
    let mut findings = Vec::new();
    for record in records {
        let pointers = evidence
            .get(&(record.rule_id.clone(), record.entity_key.clone()))
            .cloned()
            .unwrap_or_default();
        let suppressed = suppressions
            .iter()
            .any(|suppression| suppression.matches(&record.rule_id, &record.entity_key));
        findings.push(Finding {
            id: FindingId::new(&record.rule_id, &record.entity_key),
            catalogue_version: record.catalogue_version,
            config_version: record.config_version,
            severity: Severity::parse(&record.severity).unwrap_or(Severity::Notice),
            state: RuleState::parse(&record.state).unwrap_or(RuleState::Findings),
            fact: record.fact,
            recommendation: record.recommendation,
            evidence: pointers,
            suppressed,
        });
    }
    Ok(findings)
}

fn load_all_finding_evidence(
    conn: &Connection,
    run_id: i64,
) -> Result<std::collections::BTreeMap<(String, String), Vec<EvidencePointer>>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT rule_id, entity_key, observation_identity, field, excerpt
             FROM finding_evidence WHERE run_id = ?1
             ORDER BY rule_id, entity_key, seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(map_write)?;
    let mut evidence = std::collections::BTreeMap::new();
    for row in rows {
        let (rule_id, entity_key, observation_identity, field, excerpt) = row.map_err(map_write)?;
        evidence
            .entry((rule_id, entity_key))
            .or_insert_with(Vec::new)
            .push(EvidencePointer {
                observation_identity,
                field,
                excerpt,
            });
    }
    Ok(evidence)
}

fn load_findings(conn: &Connection, run_id: i64) -> Result<Vec<FindingRecord>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT rule_id, entity_key, evidence, fact, recommendation, severity, state,
                    config_version, catalogue_version
             FROM findings
             WHERE run_id = ?1 ORDER BY rule_id, entity_key",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok(FindingRecord {
                rule_id: row.get(0)?,
                entity_key: row.get(1)?,
                evidence: row.get(2)?,
                fact: row.get(3)?,
                recommendation: row.get(4)?,
                severity: row.get(5)?,
                state: row.get(6)?,
                config_version: row.get::<_, i64>(7)? as u32,
                catalogue_version: row.get::<_, i64>(8)? as u32,
            })
        })
        .map_err(map_write)?;
    let mut findings = Vec::new();
    for row in rows {
        findings.push(row.map_err(map_write)?);
    }
    Ok(findings)
}

fn insert_strings(
    conn: &Connection,
    table: &str,
    run_id: i64,
    identity: &str,
    values: &[String],
) -> rusqlite::Result<()> {
    let sql = format!("INSERT INTO {table}(run_id, identity, seq, text) VALUES (?1, ?2, ?3, ?4)");
    for (seq, text) in values.iter().enumerate() {
        conn.execute(&sql, params![run_id, identity, seq as i64, text])?;
    }
    Ok(())
}

fn load_string_list(
    conn: &Connection,
    table: &str,
    run_id: i64,
    identity: &str,
) -> Result<Vec<String>, StoreError> {
    let sql = format!("SELECT text FROM {table} WHERE run_id = ?1 AND identity = ?2 ORDER BY seq");
    let mut stmt = conn.prepare(&sql).map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| row.get::<_, String>(0))
        .map_err(map_write)?;
    let mut values = Vec::new();
    for row in rows {
        values.push(row.map_err(map_write)?);
    }
    Ok(values)
}

fn load_observations(
    conn: &Connection,
    run_id: i64,
) -> Result<Vec<ExtractedObservations>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT identity, schema_version, complete, truncated, challenge, error_status,
                    non_html, encoding_fallback, status, content_type, duration_ms,
                    raw_bytes, decoded_bytes, encoding, doctype, html_lang, viewport, text,
                    charset_declared, has_frames, has_plugin_markup
             FROM page_observations WHERE run_id = ?1 ORDER BY identity",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, u16>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, i64>(18)?,
                row.get::<_, i64>(19)?,
                row.get::<_, i64>(20)?,
            ))
        })
        .map_err(map_write)?;
    let mut pages = Vec::new();
    for row in rows {
        pages.push(row.map_err(map_write)?);
    }
    let mut observations = Vec::new();
    for page in pages {
        let (
            identity,
            schema_version,
            _complete,
            truncated,
            challenge,
            error_status,
            non_html,
            encoding_fallback,
            status,
            content_type,
            duration_ms,
            raw_bytes,
            decoded_bytes,
            encoding,
            doctype,
            html_lang,
            viewport,
            text,
            charset_declared,
            has_frames,
            has_plugin_markup,
        ) = page;
        let headings = load_headings(conn, run_id, &identity)?;
        let hreflangs = load_hreflangs(conn, run_id, &identity)?;
        observations.push(ExtractedObservations {
            schema_version: schema_version as u32,
            identity: identity.clone(),
            page: PageObservation {
                schema_version: schema_version as u32,
                flags: ObservationFlags {
                    truncated: truncated != 0,
                    challenge: challenge != 0,
                    error_status: error_status != 0,
                    non_html: non_html != 0,
                    encoding_fallback: encoding_fallback != 0,
                },
                status,
                content_type,
                duration_ms: duration_ms.map(|ms| ms as u64),
                raw_bytes: raw_bytes as u64,
                decoded_bytes: decoded_bytes as u64,
                encoding,
                charset_declared: charset_declared != 0,
                doctype,
                html_lang,
                titles: load_string_list(conn, "observation_titles", run_id, &identity)?,
                descriptions: load_string_list(
                    conn,
                    "observation_descriptions",
                    run_id,
                    &identity,
                )?,
                headings,
                robots_meta: load_string_list(conn, "observation_robots_meta", run_id, &identity)?,
                robots_headers: load_string_list(
                    conn,
                    "observation_robots_headers",
                    run_id,
                    &identity,
                )?,
                canonicals: load_string_list(conn, "observation_canonicals", run_id, &identity)?,
                hreflangs,
                viewport,
                has_frames: has_frames != 0,
                has_plugin_markup: has_plugin_markup != 0,
                meta_refresh: load_string_list(
                    conn,
                    "observation_meta_refresh",
                    run_id,
                    &identity,
                )?,
                structured: load_structured(conn, run_id, &identity)?,
                text,
            },
            links: load_link_observations(conn, run_id, &identity)?,
            resources: load_resource_observations(conn, run_id, &identity)?,
            redirect_chain: load_redirects(conn, run_id, &identity)?,
        });
    }
    Ok(observations)
}

fn load_headings(
    conn: &Connection,
    run_id: i64,
    identity: &str,
) -> Result<Vec<Heading>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT level, text FROM observation_headings
             WHERE run_id = ?1 AND identity = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| {
            Ok((row.get::<_, u8>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(map_write)?;
    let mut headings = Vec::new();
    for row in rows {
        let (level, text) = row.map_err(map_write)?;
        headings.push(Heading { level, text });
    }
    Ok(headings)
}

fn load_hreflangs(
    conn: &Connection,
    run_id: i64,
    identity: &str,
) -> Result<Vec<Hreflang>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT lang, href FROM observation_hreflangs
             WHERE run_id = ?1 AND identity = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(map_write)?;
    let mut items = Vec::new();
    for row in rows {
        let (lang, href) = row.map_err(map_write)?;
        items.push(Hreflang { lang, href });
    }
    Ok(items)
}

fn load_structured(
    conn: &Connection,
    run_id: i64,
    identity: &str,
) -> Result<Vec<StructuredBlock>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT format, block_index, raw, types FROM observation_structured
             WHERE run_id = ?1 AND identity = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(map_write)?;
    let mut blocks = Vec::new();
    for row in rows {
        let (format, index, raw, types) = row.map_err(map_write)?;
        let Some(format) = StructuredFormat::parse(&format) else {
            continue;
        };
        let types: Vec<String> = serde_json::from_str(&types).unwrap_or_default();
        blocks.push(StructuredBlock {
            format,
            index: index as u32,
            raw,
            types,
        });
    }
    Ok(blocks)
}

fn load_redirects(
    conn: &Connection,
    run_id: i64,
    identity: &str,
) -> Result<Vec<RedirectHop>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT from_url, to_url, status FROM observation_redirects
             WHERE run_id = ?1 AND identity = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
            ))
        })
        .map_err(map_write)?;
    let mut hops = Vec::new();
    for row in rows {
        let (from, to, status) = row.map_err(map_write)?;
        hops.push(RedirectHop { from, to, status });
    }
    Ok(hops)
}

fn load_link_observations(
    conn: &Connection,
    run_id: i64,
    identity: &str,
) -> Result<Vec<LinkObservation>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT source, href, destination, anchor, rel, element, host_owner
             FROM link_observations WHERE run_id = ?1 AND source = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(map_write)?;
    let mut links = Vec::new();
    for row in rows {
        let (source, href, destination, anchor, rel, element, host_owner) =
            row.map_err(map_write)?;
        links.push(LinkObservation {
            source,
            href,
            destination,
            anchor,
            rel,
            element,
            host_owner: HostOwner::parse(&host_owner)
                .ok_or_else(|| StoreError::other(format!("Unknown host owner {host_owner}")))?,
        });
    }
    Ok(links)
}

fn load_resource_observations(
    conn: &Connection,
    run_id: i64,
    identity: &str,
) -> Result<Vec<ResourceObservation>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT referring, kind, href, destination, alt, host_owner
             FROM resource_observations WHERE run_id = ?1 AND referring = ?2 ORDER BY seq",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id, identity], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(map_write)?;
    let mut resources = Vec::new();
    for row in rows {
        let (referring, kind, href, destination, alt, host_owner) = row.map_err(map_write)?;
        resources.push(ResourceObservation {
            referring,
            kind: EmbeddedKind::parse(&kind)
                .ok_or_else(|| StoreError::other(format!("Unknown resource kind {kind}")))?,
            href,
            destination,
            alt,
            host_owner: HostOwner::parse(&host_owner)
                .ok_or_else(|| StoreError::other(format!("Unknown host owner {host_owner}")))?,
        });
    }
    Ok(resources)
}

pub(crate) fn serialize_profile(profile: &Profile) -> Result<String, StoreError> {
    let text = toml::to_string_pretty(profile).map_err(|err| StoreError::other(err.to_string()))?;
    reject_secrets(&text)?;
    Ok(text)
}

fn reject_secrets(text: &str) -> Result<(), StoreError> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("sig1=")
        || lower.contains("signature-input:")
        || lower.contains("signature:")
        || lower.contains("signature-input =")
    {
        return Err(StoreError::secrets(
            "stored settings must not contain Signature or Signature-Input values",
        ));
    }
    Ok(())
}

fn record_key(record: &UrlRecord) -> String {
    match &record.identity {
        Some(identity) => format!("i:{}", identity.as_str()),
        None => format!("o:{}", record.original),
    }
}

fn url_state_str(state: UrlState) -> &'static str {
    match state {
        UrlState::Fetched => "fetched",
        UrlState::Excluded => "excluded",
        UrlState::Blocked => "blocked",
        UrlState::Failed => "failed",
        UrlState::Pending => "pending",
        UrlState::InFlight => "in_flight",
    }
}

fn parse_url_state(value: &str) -> Result<UrlState, StoreError> {
    match value {
        "fetched" => Ok(UrlState::Fetched),
        "excluded" => Ok(UrlState::Excluded),
        "blocked" => Ok(UrlState::Blocked),
        "failed" => Ok(UrlState::Failed),
        "pending" => Ok(UrlState::Pending),
        "in_flight" => Ok(UrlState::InFlight),
        other => Err(StoreError::other(format!("Unknown URL state {other}"))),
    }
}

fn resource_kind_str(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Page => "page",
        ResourceKind::Robots => "robots",
        ResourceKind::Sitemap => "sitemap",
        ResourceKind::SameOrigin => "same_origin",
    }
}

fn parse_resource_kind(value: &str) -> Result<ResourceKind, StoreError> {
    match value {
        "page" => Ok(ResourceKind::Page),
        "robots" => Ok(ResourceKind::Robots),
        "sitemap" => Ok(ResourceKind::Sitemap),
        "same_origin" => Ok(ResourceKind::SameOrigin),
        other => Err(StoreError::other(format!("Unknown resource kind {other}"))),
    }
}

fn sitemap_file_state_str(state: SitemapFileState) -> &'static str {
    match state {
        SitemapFileState::Fetched => "fetched",
        SitemapFileState::Inaccessible => "inaccessible",
        SitemapFileState::ParseError => "parse_error",
        SitemapFileState::Oversized => "oversized",
        SitemapFileState::Cycle => "cycle",
        SitemapFileState::DepthLimit => "depth_limit",
        SitemapFileState::CrossOrigin => "cross_origin",
        SitemapFileState::Blocked => "blocked",
        SitemapFileState::Capped => "capped",
    }
}

fn parse_sitemap_file_state(value: &str) -> Result<SitemapFileState, StoreError> {
    match value {
        "fetched" => Ok(SitemapFileState::Fetched),
        "inaccessible" => Ok(SitemapFileState::Inaccessible),
        "parse_error" => Ok(SitemapFileState::ParseError),
        "oversized" => Ok(SitemapFileState::Oversized),
        "cycle" => Ok(SitemapFileState::Cycle),
        "depth_limit" => Ok(SitemapFileState::DepthLimit),
        "cross_origin" => Ok(SitemapFileState::CrossOrigin),
        "blocked" => Ok(SitemapFileState::Blocked),
        "capped" => Ok(SitemapFileState::Capped),
        other => Err(StoreError::other(format!(
            "Unknown sitemap file state {other}"
        ))),
    }
}

fn parse_identity(value: &str) -> Result<FetchIdentity, StoreError> {
    Ok(FetchIdentity::from_url(&parse_url(value)?))
}

fn parse_url(value: &str) -> Result<Url, StoreError> {
    Url::parse(value).map_err(|err| StoreError::other(err.to_string()))
}

fn intern_reason(reason: Option<String>) -> Option<&'static str> {
    reason.map(|value| Box::leak(value.into_boxed_str()) as &'static str)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn is_disk_full(err: &rusqlite::Error) -> bool {
    err.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull)
}

fn persist_audit_report(conn: &Connection, report: &AuditReport) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM rule_outcomes WHERE run_id = ?1",
        params![report.run_id],
    )?;
    for outcome in &report.outcomes {
        conn.execute(
            "DELETE FROM finding_evidence WHERE run_id = ?1 AND rule_id = ?2",
            params![report.run_id, outcome.rule_id],
        )?;
        conn.execute(
            "DELETE FROM findings WHERE run_id = ?1 AND rule_id = ?2",
            params![report.run_id, outcome.rule_id],
        )?;
        conn.execute(
            "INSERT INTO rule_outcomes(run_id, rule_id, state, config_version)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                report.run_id,
                outcome.rule_id,
                outcome.state.as_str(),
                report.config_version as i64,
            ],
        )?;
    }
    let mut seen_findings = std::collections::BTreeSet::new();
    for finding in &report.findings {
        if !seen_findings.insert((finding.id.rule_id.as_str(), finding.id.entity_key.as_str())) {
            continue;
        }
        conn.execute(
            "INSERT INTO findings(
                run_id, rule_id, entity_key, evidence, fact, recommendation,
                severity, state, config_version, catalogue_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                report.run_id,
                finding.id.rule_id,
                finding.id.entity_key,
                finding.fact,
                finding.fact,
                finding.recommendation,
                finding.severity.as_str(),
                finding.state.as_str(),
                finding.config_version as i64,
                finding.catalogue_version as i64,
            ],
        )?;
        for (seq, pointer) in finding.evidence.iter().enumerate() {
            conn.execute(
                "INSERT INTO finding_evidence(
                    run_id, rule_id, entity_key, seq, observation_identity, field, excerpt
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    report.run_id,
                    finding.id.rule_id,
                    finding.id.entity_key,
                    seq as i64,
                    pointer.observation_identity,
                    pointer.field,
                    pointer.excerpt,
                ],
            )?;
        }
    }
    let seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM audit_evaluations WHERE run_id = ?1",
        params![report.run_id],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO audit_evaluations(
            run_id, seq, evaluated_at, config_version, config_fingerprint
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            report.run_id,
            seq,
            now_secs(),
            report.config_version as i64,
            report.config_fingerprint,
        ],
    )?;
    Ok(())
}

fn load_suppressions(conn: &Connection, run_id: i64) -> Result<Vec<Suppression>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, run_id, rule_id, entity_key, reason, created_at, revoked_at
             FROM suppressions WHERE run_id = ?1 ORDER BY id",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok(Suppression {
                id: row.get(0)?,
                run_id: row.get(1)?,
                rule_id: row.get(2)?,
                entity_key: row.get(3)?,
                reason: row.get(4)?,
                created_at: row.get(5)?,
                revoked_at: row.get(6)?,
            })
        })
        .map_err(map_write)?;
    let mut suppressions = Vec::new();
    for row in rows {
        suppressions.push(row.map_err(map_write)?);
    }
    Ok(suppressions)
}

fn load_suppression_events(
    conn: &Connection,
    run_id: i64,
) -> Result<Vec<SuppressionEvent>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT e.id, e.suppression_id, e.action, e.reason, e.at
             FROM suppression_events e
             JOIN suppressions s ON s.id = e.suppression_id
             WHERE s.run_id = ?1
             ORDER BY e.id",
        )
        .map_err(map_write)?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            let action: String = row.get(2)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                action,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(map_write)?;
    let mut events = Vec::new();
    for row in rows {
        let (id, suppression_id, action, reason, at) = row.map_err(map_write)?;
        let action = SuppressionAction::parse(&action)
            .ok_or_else(|| StoreError::other(format!("Unknown suppression action {action}")))?;
        events.push(SuppressionEvent {
            id,
            suppression_id,
            action,
            reason,
            at,
        });
    }
    Ok(events)
}

fn map_write(err: rusqlite::Error) -> StoreError {
    if is_disk_full(&err) {
        StoreError::disk_full(err.to_string())
    } else {
        StoreError::other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawl::REASON_FETCHED;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "crawlytic-store-{}-{}.sqlite",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let wal = format!("{}-wal", path.display());
        let shm = format!("{}-shm", path.display());
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(&shm);
    }

    fn sample_profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn identity(url: &str) -> FetchIdentity {
        FetchIdentity::from_url(&Url::parse(url).unwrap())
    }

    fn fetched(url: &str) -> UrlRecord {
        UrlRecord {
            original: url.to_owned(),
            identity: Some(identity(url)),
            state: UrlState::Fetched,
            reason: REASON_FETCHED.to_owned(),
            click_depth: Some(0),
            via_website: true,
            via_sitemap: false,
        }
    }

    #[test]
    fn stored_settings_contain_no_signature_values() {
        let path = temp_path();
        let store = Store::open(&path).unwrap();
        let profile = sample_profile();
        let run_id = store.begin_run(&profile).unwrap();
        let toml = store.stored_profile_toml(run_id).unwrap();
        let lower = toml.to_ascii_lowercase();
        assert!(toml.contains("CRAWL_SIGNATURE"));
        assert!(toml.contains("auth_signature_env"));
        assert!(!lower.contains("sig1="), "{toml}");
        assert!(!lower.contains("signature-input:"), "{toml}");
        assert!(!lower.contains("signature:"), "{toml}");
        assert!(!toml.contains("TESTSIGNATUREVALUE"));
        cleanup(&path);
    }

    #[test]
    fn signature_material_in_serialized_settings_is_refused() {
        let mut profile = sample_profile();
        profile.user_agent = r#"Crawlytic sig1=:TESTSIGNATUREVALUE:"#.into();
        let err = serialize_profile(&profile).unwrap_err();
        assert!(err.is_secrets(), "{err}");
        assert!(
            err.to_string().contains("Refusing to store secrets"),
            "{err}"
        );
    }

    #[test]
    fn list_runs_summarizes_status_and_start_url_without_secrets() {
        let store = Store::open_in_memory().unwrap();
        let profile = sample_profile();
        let first = store.begin_run(&profile).unwrap();
        store
            .upsert_url(first, &fetched("https://www.tiendacables.com/"))
            .unwrap();
        store.flush().unwrap();
        let second = store.begin_run(&profile).unwrap();
        store
            .mark_incomplete(second, "cancelled by operator")
            .unwrap();
        store.flush().unwrap();

        let runs = store.list_runs().unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].id, second);
        assert_eq!(runs[0].status, RunStatus::Incomplete);
        assert_eq!(runs[0].start_url, "https://www.tiendacables.com/");
        assert_eq!(runs[1].id, first);
        assert_eq!(runs[1].url_count, 1);
        let dump = format!("{runs:?}");
        assert!(!dump.to_ascii_lowercase().contains("sig1="), "{dump}");
        assert!(!dump.contains("TESTSIGNATURE"), "{dump}");
    }

    #[test]
    fn findings_are_idempotent_across_reopen() {
        let path = temp_path();
        let url = "https://www.tiendacables.com/";
        {
            let store = Store::open(&path).unwrap();
            let run_id = store.begin_run(&sample_profile()).unwrap();
            store.upsert_url(run_id, &fetched(url)).unwrap();
            store
                .put_finding(run_id, "title.duplicate", url, "first")
                .unwrap();
            store.flush().unwrap();
        }
        let store = Store::open(&path).unwrap();
        let run_id = 1;
        store
            .put_finding(run_id, "title.duplicate", url, "second")
            .unwrap();
        store.flush().unwrap();
        let findings = store.findings(run_id).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "first");
        assert!(!store.load_run(run_id).unwrap().completed);
        cleanup(&path);
    }

    #[test]
    fn writer_batches_until_flush() {
        let path = temp_path();
        let store = Store::open(&path).unwrap().with_batch_size(8);
        let run_id = store.begin_run(&sample_profile()).unwrap();
        store
            .upsert_url(run_id, &fetched("https://www.tiendacables.com/a"))
            .unwrap();
        let reader = Store::open(&path).unwrap();
        assert!(
            reader.load_run(run_id).unwrap().urls.is_empty(),
            "unflushed writes must not be visible to another connection"
        );
        store.flush().unwrap();
        assert_eq!(reader.load_run(run_id).unwrap().urls.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn raw_html_retention_is_optional_and_quota_bounded() {
        let store = Store::open_in_memory().unwrap();
        let run_id = store.begin_run(&sample_profile()).unwrap();
        let id = identity("https://www.tiendacables.com/");
        let record = FetchRecord {
            requested_url: id.as_url().clone(),
            destination_url: id.as_url().clone(),
            status: 200,
            content_type: "text/html".into(),
            bytes_sampled: 5,
            resource_kind: ResourceKind::Page,
            credentials_attached: true,
            truncated: false,
            duration_ms: 0,
            robots_tag_headers: Vec::new(),
            link_headers: Vec::new(),
            redirect_chain: Vec::new(),
        };
        store
            .upsert_fetch(run_id, &id, &record, Some(b"<html>"))
            .unwrap();
        store.flush().unwrap();
        assert!(
            store
                .html_body(run_id, id.as_str(), ResourceKind::Page)
                .unwrap()
                .is_none()
        );

        store
            .set_retention(RetentionPolicy {
                retain_raw_html: true,
                max_html_bytes: 8,
            })
            .unwrap();
        let other = identity("https://www.tiendacables.com/b");
        let mut second = record.clone();
        second.requested_url = other.as_url().clone();
        second.destination_url = other.as_url().clone();
        store
            .upsert_fetch(run_id, &id, &record, Some(b"<html>"))
            .unwrap();
        store
            .upsert_fetch(run_id, &other, &second, Some(b"<overflow>"))
            .unwrap();
        store.flush().unwrap();
        assert_eq!(
            store
                .html_body(run_id, id.as_str(), ResourceKind::Page)
                .unwrap()
                .as_deref(),
            Some(&b"<html>"[..])
        );
        assert!(
            store
                .html_body(run_id, other.as_str(), ResourceKind::Page)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn migration_failure_is_visible() {
        let path = temp_path();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("CREATE TABLE runs (nope INTEGER)", [])
                .unwrap();
        }
        let err = match Store::open(&path) {
            Err(err) => err,
            Ok(_) => panic!("expected migration failure"),
        };
        assert!(err.is_migration(), "{err}");
        assert!(err.to_string().starts_with("Migration failed"), "{err}");
        cleanup(&path);
    }

    #[test]
    fn disk_full_is_visible_and_leaves_the_run_incomplete() {
        let path = temp_path();
        let store = Store::open(&path).unwrap().with_batch_size(1);
        let run_id = store.begin_run(&sample_profile()).unwrap();
        store.limit_pages_to_current().unwrap();
        let err = store
            .put_finding(run_id, "rule.x", "entity", &"n".repeat(64 * 1024))
            .unwrap_err();
        assert!(err.is_disk_full(), "{err}");
        assert!(err.to_string().starts_with("Disk full"), "{err}");
        let loaded = Store::open(&path).unwrap().load_run(run_id).unwrap();
        assert!(!loaded.completed);
        assert_ne!(loaded.status, RunStatus::Completed);
        cleanup(&path);
    }

    #[test]
    fn extracted_observations_round_trip_without_severity() {
        use crate::extract::{ExtractHeader, ExtractInput, extract};
        let store = Store::open_in_memory().unwrap();
        let run_id = store.begin_run(&sample_profile()).unwrap();
        let url = Url::parse("https://www.tiendacables.com/es").unwrap();
        let headers = [ExtractHeader {
            name: "X-Robots-Tag",
            value: "noindex",
        }];
        let obs = extract(&ExtractInput {
            destination_url: &url,
            status: 200,
            content_type: "text/html",
            headers: &headers,
            body: br#"<html><head><title>Hi</title>
                <link rel="canonical" href="/es">
                <script type="application/ld+json">{"@type":"Organization","name":"Tienda"}</script>
                </head><body>
                <a href="/next">Next</a>
                <img src="https://cdn.example.com/a.png" alt="A">
                <div itemscope itemtype="https://schema.org/Product"></div>
                </body></html>"#,
            truncated: false,
            duration_ms: Some(9),
        });
        assert!(obs.page.is_complete());
        store.put_observation(run_id, &obs).unwrap();
        store.flush().unwrap();
        let loaded = store.load_run(run_id).unwrap();
        assert_eq!(loaded.observations, vec![obs]);
        let dump = format!("{:?}", loaded.observations);
        assert!(!dump.to_ascii_lowercase().contains("severity"));
    }

    #[test]
    fn truncated_observation_is_not_stored_as_complete() {
        use crate::extract::{ExtractInput, extract};
        let store = Store::open_in_memory().unwrap();
        let run_id = store.begin_run(&sample_profile()).unwrap();
        let url = Url::parse("https://www.tiendacables.com/").unwrap();
        let obs = extract(&ExtractInput {
            destination_url: &url,
            status: 200,
            content_type: "text/html",
            headers: &[],
            body: b"<html><title>Partial",
            truncated: true,
            duration_ms: None,
        });
        store.put_observation(run_id, &obs).unwrap();
        store.flush().unwrap();
        let loaded = store.load_run(run_id).unwrap();
        assert!(!loaded.observations[0].page.is_complete());
        assert!(loaded.observations[0].page.flags.truncated);
    }

    #[test]
    fn schema_upgrade_preserves_existing_run_data() {
        let path = temp_path();
        let profile = include_str!("../../../profile.example.toml");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATION_1).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, 0)",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO profiles(id, toml) VALUES (1, ?1)", [profile])
                .unwrap();
            conn.execute(
                "INSERT INTO runs(
                    id, profile_id, catalogue_version, fixture_contract_version,
                    status, completed, cancelled, sitemap_done, started_at, updated_at
                 ) VALUES (1, 1, 1, 1, 'completed', 1, 0, 1, 1, 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO url_states(
                    run_id, record_key, original, identity, state, reason,
                    click_depth, via_website, via_sitemap
                 ) VALUES (1, 'https://www.tiendacables.com/',
                    'https://www.tiendacables.com/',
                    'https://www.tiendacables.com/', 'fetched', 'fetched', 0, 1, 0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO findings(run_id, rule_id, entity_key, evidence)
                 VALUES (1, 'meta.missing_title', 'https://www.tiendacables.com/', 'title missing')",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let runs = store.list_runs().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, 1);
        assert_eq!(runs[0].status, RunStatus::Completed);
        let findings = store.findings(1).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "meta.missing_title");
        assert_eq!(findings[0].evidence, "title missing");
        assert_eq!(findings[0].fact, "title missing");
        cleanup(&path);
    }

    #[test]
    fn backup_restores_an_audit_without_copying_secrets() {
        let path = temp_path();
        let dest = temp_path();
        let store = Store::open(&path).unwrap();
        let run_id = store.begin_run(&sample_profile()).unwrap();
        store
            .put_finding(
                run_id,
                "meta.missing_title",
                "https://www.tiendacables.com/",
                "title missing",
            )
            .unwrap();
        store
            .set_retention(RetentionPolicy {
                retain_raw_html: true,
                max_html_bytes: 2048,
            })
            .unwrap();
        store.flush().unwrap();
        store.backup(&dest).unwrap();
        drop(store);

        let restored = Store::open(&dest).unwrap();
        let findings = restored.findings(run_id).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "title missing");
        assert_eq!(
            restored.retention(),
            RetentionPolicy {
                retain_raw_html: true,
                max_html_bytes: 2048,
            }
        );
        let dump = std::fs::read(&dest).unwrap();
        let text = String::from_utf8_lossy(&dump);
        let lower = text.to_ascii_lowercase();
        assert!(text.contains("CRAWL_SIGNATURE"));
        assert!(!lower.contains("sig1="));
        assert!(!text.contains("TESTSIGNATUREVALUE"));
        cleanup(&path);
        cleanup(&dest);
    }
}
