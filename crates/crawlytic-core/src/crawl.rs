//! Bounded async crawl: frontier, paced workers, backoff, cancellation and
//! discovery.
//!
//! Website mode starts at the homepage and follows raw HTML `<a href>` links.
//! Sitemaps are independent inventory: they never create a navigation edge or
//! assign click depth. Duplicate identities are not scheduled twice. Caps for
//! unique fetches, queue depth, response size and sitemap expansion are
//! independent. `crawl_delay = minimum` is a paced policy with bounded
//! concurrency, not an unbounded worker pool.

use crate::auth::WebBotAuth;
use crate::discovery::{
    ParsedSitemap, decode_sitemap_body, extract_navigational_links, parse_sitemap_xml,
};
use crate::profile::Profile;
use crate::robots::{AllowReason, RobotsCache, RobotsFile, RobotsRunMetadata, UrlAccess};
use crate::scope::{ClassifiedUrl, Coverage, CoverageLink, FetchIdentity, classify_href};
use crate::transport::{ResourceKind, SignedTransport};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use url::Url;

pub const REASON_QUEUED: &str = "Queued";
pub const REASON_QUEUE_CAP: &str = "Queue cap";
pub const REASON_URL_CAP: &str = "URL cap";
pub const REASON_CANCELLED: &str = "Cancelled";
pub const REASON_FETCHED: &str = "Fetched";
pub const REASON_TRUNCATED: &str = "Fetched; response truncated at size cap";
pub const REASON_RETRY_BUDGET: &str = "Retry budget exhausted";
pub const REASON_AUTH: &str = "Authentication failure; unsigned fallback is disabled";
pub const REASON_SITEMAP_CROSS_ORIGIN: &str =
    "Cross-origin sitemap; explicit scope required; credentials were not forwarded";
pub const REASON_SITEMAP_CYCLE: &str = "Sitemap cycle";
pub const REASON_SITEMAP_DEPTH: &str = "Sitemap index depth cap";
pub const REASON_SITEMAP_OVERSIZED: &str = "Sitemap exceeded size cap";
pub const REASON_SITEMAP_PARSE: &str = "Sitemap parse error";
pub const REASON_SITEMAP_INACCESSIBLE: &str = "Sitemap inaccessible";
pub const REASON_SITEMAP_FILE_CAP: &str = "Sitemap file cap";

#[derive(Clone)]
pub struct CancelHandle {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancelHandle {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for CancelHandle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct CrawlLimits {
    pub max_urls: usize,
    pub max_queue: usize,
    pub max_response_bytes: usize,
    pub max_sitemap_bytes: usize,
    pub max_sitemap_depth: usize,
    pub max_sitemap_files: usize,
    pub retry_budget: usize,
    pub min_delay: Duration,
    pub concurrency: usize,
    pub max_backoff: Duration,
    skip_sleep: bool,
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl CrawlLimits {
    pub fn from_profile(profile: &Profile) -> Self {
        Self {
            max_urls: profile.max_pages,
            max_queue: 1024,
            max_response_bytes: 65_536,
            max_sitemap_bytes: 1_048_576,
            max_sitemap_depth: 4,
            max_sitemap_files: 64,
            retry_budget: 3,
            min_delay: Duration::from_millis(100),
            concurrency: 2,
            max_backoff: Duration::from_secs(30),
            skip_sleep: false,
            sleeps: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn deterministic(mut self) -> Self {
        self.skip_sleep = true;
        self.min_delay = Duration::ZERO;
        self.concurrency = self.concurrency.max(1);
        self
    }

    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn sleep(&self, delay: Duration) {
        if delay.is_zero() {
            return;
        }
        self.sleeps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(delay);
        if !self.skip_sleep {
            tokio::time::sleep(delay).await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlState {
    Fetched,
    Excluded,
    Blocked,
    Failed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRecord {
    pub original: String,
    pub identity: Option<FetchIdentity>,
    pub state: UrlState,
    pub reason: String,
    pub click_depth: Option<u32>,
    pub via_website: bool,
    pub via_sitemap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitemapFileState {
    Fetched,
    Inaccessible,
    ParseError,
    Oversized,
    Cycle,
    DepthLimit,
    CrossOrigin,
    Blocked,
    Capped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitemapFileRecord {
    pub url: String,
    pub identity: Option<FetchIdentity>,
    pub state: SitemapFileState,
    pub reason: String,
    pub listed_urls: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitemapUrlRecord {
    pub original: String,
    pub identity: Option<FetchIdentity>,
    pub skip_reason: Option<String>,
    pub source_sitemap: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SitemapInventory {
    pub files: Vec<SitemapFileRecord>,
    pub urls: Vec<SitemapUrlRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlReport {
    pub completed: bool,
    pub cancelled: bool,
    pub urls: Vec<UrlRecord>,
    pub robots: Option<RobotsRunMetadata>,
    pub sitemap: SitemapInventory,
    pub links: Vec<CoverageLink>,
}

impl CrawlReport {
    pub fn url(&self, identity: &FetchIdentity) -> Option<&UrlRecord> {
        self.urls
            .iter()
            .find(|record| record.identity.as_ref() == Some(identity))
    }

    pub fn by_original(&self, original: &str) -> Option<&UrlRecord> {
        self.urls.iter().find(|record| record.original == original)
    }
}

pub struct Crawler {
    profile: Profile,
    transport: SignedTransport,
    limits: CrawlLimits,
    cancel: CancelHandle,
    coverage: Coverage,
    records: BTreeMap<String, UrlRecord>,
    frontier: VecDeque<FetchIdentity>,
}

impl Crawler {
    pub fn new(
        profile: Profile,
        auth: &WebBotAuth,
        limits: CrawlLimits,
        cancel: CancelHandle,
    ) -> Result<Self> {
        let transport = SignedTransport::new(&profile, auth)?;
        Ok(Self::new_with_transport(profile, transport, limits, cancel))
    }

    pub(crate) fn new_with_transport(
        profile: Profile,
        transport: SignedTransport,
        limits: CrawlLimits,
        cancel: CancelHandle,
    ) -> Self {
        Self {
            profile,
            transport,
            limits,
            cancel,
            coverage: Coverage::new(),
            records: BTreeMap::new(),
            frontier: VecDeque::new(),
        }
    }

    pub fn limits(&self) -> &CrawlLimits {
        &self.limits
    }

    pub fn offer(&mut self, href: &str) -> &UrlRecord {
        let classified = self.coverage.seed(&self.profile, href);
        let key = record_key(&classified);
        queue_page(
            &mut self.records,
            &mut self.frontier,
            &self.limits,
            PageOffer {
                classified,
                click_depth: None,
                via_website: true,
                via_sitemap: false,
                enqueue_fetch: true,
            },
        );
        self.records.get(&key).expect("inserted URL record")
    }

    pub async fn run(&mut self) -> CrawlReport {
        let robots_cache = RobotsCache::new();
        let robots_file = match robots_cache
            .for_url(&self.transport, &self.profile.start_url)
            .await
        {
            Ok(file) => Some(file),
            Err(err) if err.is_auth_failure() => {
                reclassify_queued(&mut self.records, UrlState::Failed, REASON_AUTH);
                return report(
                    &self.records,
                    false,
                    self.cancel.is_cancelled(),
                    None,
                    SitemapInventory::default(),
                    self.coverage.links(),
                );
            }
            Err(_) => None,
        };
        let robots_meta = robots_file
            .as_ref()
            .map(|file| file.metadata(&self.profile, &self.profile.start_url));

        if self.profile.discovery_mode.follows_website_links() && self.records.is_empty() {
            let start = self.profile.start_url.as_str().to_owned();
            let classified = self.coverage.seed(&self.profile, &start);
            queue_page(
                &mut self.records,
                &mut self.frontier,
                &self.limits,
                PageOffer {
                    classified,
                    click_depth: Some(0),
                    via_website: true,
                    via_sitemap: false,
                    enqueue_fetch: true,
                },
            );
        }

        let sitemap = match inventory_sitemaps(
            &self.transport,
            &self.profile,
            &self.limits,
            &self.cancel,
            robots_file.as_ref(),
            &mut self.records,
            &mut self.frontier,
            &mut self.coverage,
        )
        .await
        {
            Ok(inventory) => inventory,
            Err(inventory) => {
                reclassify_queued(&mut self.records, UrlState::Failed, REASON_AUTH);
                stamp_sitemap_provenance(&mut self.records, &inventory);
                return report(
                    &self.records,
                    false,
                    self.cancel.is_cancelled(),
                    robots_meta,
                    inventory,
                    self.coverage.links(),
                );
            }
        };

        if self.cancel.is_cancelled() {
            reclassify_queued(&mut self.records, UrlState::Pending, REASON_CANCELLED);
            stamp_sitemap_provenance(&mut self.records, &sitemap);
            return report(
                &self.records,
                false,
                true,
                robots_meta,
                sitemap,
                self.coverage.links(),
            );
        }

        let shared = Arc::new(tokio::sync::Mutex::new(RunState {
            records: std::mem::take(&mut self.records),
            frontier: std::mem::take(&mut self.frontier),
            coverage: std::mem::take(&mut self.coverage),
            auth_failed: false,
        }));
        let gate = Arc::new(tokio::sync::Mutex::new(None::<tokio::time::Instant>));
        let mut tasks = tokio::task::JoinSet::new();
        let mut stop_scheduling = false;
        let concurrency = self.limits.concurrency.max(1);
        let transport = self.transport.clone();
        let profile = self.profile.clone();
        let limits = self.limits.clone();
        let cancel = self.cancel.clone();
        let robots_file = robots_file.map(Arc::new);

        loop {
            if cancel.is_cancelled() {
                stop_scheduling = true;
            }
            {
                let state = shared.lock().await;
                if state.auth_failed {
                    stop_scheduling = true;
                }
            }

            while !stop_scheduling && tasks.len() < concurrency {
                let Some(identity) = shared.lock().await.frontier.pop_front() else {
                    break;
                };
                let shared = shared.clone();
                let transport = transport.clone();
                let profile = profile.clone();
                let limits = limits.clone();
                let cancel = cancel.clone();
                let gate = gate.clone();
                let robots_file = robots_file.clone();
                tasks.spawn(async move {
                    process_one(
                        identity,
                        transport,
                        profile,
                        limits,
                        cancel,
                        gate,
                        robots_file,
                        shared,
                    )
                    .await
                });
            }

            if tasks.is_empty() {
                break;
            }

            tokio::select! {
                _ = cancel.cancelled() => {
                    stop_scheduling = true;
                    tasks.abort_all();
                }
                joined = tasks.join_next() => {
                    if let Some(Ok(WorkerOut::Auth | WorkerOut::Cancelled)) = joined {
                        stop_scheduling = true;
                    }
                }
            }
        }

        while tasks.join_next().await.is_some() {}

        let cancelled = cancel.is_cancelled();
        let mut state = shared.lock().await;
        let auth_failed = state.auth_failed;
        for record in state.records.values_mut() {
            if record.state == UrlState::Pending && record.reason == REASON_QUEUED {
                if cancelled {
                    record.reason = REASON_CANCELLED.to_owned();
                } else if auth_failed {
                    record.state = UrlState::Failed;
                    record.reason = REASON_AUTH.to_owned();
                }
            }
        }
        self.records = std::mem::take(&mut state.records);
        self.frontier = std::mem::take(&mut state.frontier);
        self.coverage = std::mem::take(&mut state.coverage);
        stamp_sitemap_provenance(&mut self.records, &sitemap);
        report(
            &self.records,
            !cancelled,
            cancelled,
            robots_meta,
            sitemap,
            self.coverage.links(),
        )
    }
}

struct RunState {
    records: BTreeMap<String, UrlRecord>,
    frontier: VecDeque<FetchIdentity>,
    coverage: Coverage,
    auth_failed: bool,
}

struct PageOffer {
    classified: ClassifiedUrl,
    click_depth: Option<u32>,
    via_website: bool,
    via_sitemap: bool,
    enqueue_fetch: bool,
}

enum WorkerOut {
    Done,
    Auth,
    Cancelled,
}

#[allow(clippy::too_many_arguments)]
async fn process_one(
    identity: FetchIdentity,
    transport: SignedTransport,
    profile: Profile,
    limits: CrawlLimits,
    cancel: CancelHandle,
    gate: Arc<tokio::sync::Mutex<Option<tokio::time::Instant>>>,
    robots_file: Option<Arc<RobotsFile>>,
    shared: Arc<tokio::sync::Mutex<RunState>>,
) -> WorkerOut {
    if cancel.is_cancelled() {
        set_record(&shared, &identity, UrlState::Pending, REASON_CANCELLED).await;
        return WorkerOut::Cancelled;
    }

    let url = identity.as_url().clone();
    let access = match robots_file.as_deref() {
        Some(file) => file.decide(&profile, &url),
        None => UrlAccess::Allowed {
            reason: AllowReason::RobotsUnavailable,
        },
    };
    if let UrlAccess::Blocked(evidence) = access {
        set_record(&shared, &identity, UrlState::Blocked, evidence.note).await;
        return WorkerOut::Done;
    }

    for attempt in 0..=limits.retry_budget {
        if cancel.is_cancelled() {
            set_record(&shared, &identity, UrlState::Pending, REASON_CANCELLED).await;
            return WorkerOut::Cancelled;
        }
        pace(&gate, &limits).await;
        if cancel.is_cancelled() {
            set_record(&shared, &identity, UrlState::Pending, REASON_CANCELLED).await;
            return WorkerOut::Cancelled;
        }

        let result = tokio::select! {
            _ = cancel.cancelled() => {
                set_record(
                    &shared,
                    &identity,
                    UrlState::Pending,
                    REASON_CANCELLED,
                )
                .await;
                return WorkerOut::Cancelled;
            }
            result = transport.fetch_with_body_limit(
                &url,
                ResourceKind::Page,
                limits.max_response_bytes,
            ) => result,
        };

        match result {
            Ok((record, body)) => {
                let reason = if record.truncated {
                    REASON_TRUNCATED
                } else {
                    REASON_FETCHED
                };
                set_record(&shared, &identity, UrlState::Fetched, reason).await;
                if profile.discovery_mode.follows_website_links() {
                    discover_html_links(&profile, &limits, &identity, &body, &shared).await;
                }
                return WorkerOut::Done;
            }
            Err(err) if err.is_auth_failure() => {
                shared.lock().await.auth_failed = true;
                set_record(
                    &shared,
                    &identity,
                    UrlState::Failed,
                    err.observation().to_owned(),
                )
                .await;
                return WorkerOut::Auth;
            }
            Err(err) if err.is_retryable() && attempt < limits.retry_budget => {
                limits
                    .sleep(backoff_delay(
                        attempt,
                        err.retry_after(),
                        limits.max_backoff,
                    ))
                    .await;
            }
            Err(err) if err.is_retryable() => {
                set_record(&shared, &identity, UrlState::Failed, REASON_RETRY_BUDGET).await;
                return WorkerOut::Done;
            }
            Err(err) => {
                set_record(
                    &shared,
                    &identity,
                    UrlState::Failed,
                    err.observation().to_owned(),
                )
                .await;
                return WorkerOut::Done;
            }
        }
    }
    set_record(&shared, &identity, UrlState::Failed, REASON_RETRY_BUDGET).await;
    WorkerOut::Done
}

async fn pace(gate: &tokio::sync::Mutex<Option<tokio::time::Instant>>, limits: &CrawlLimits) {
    loop {
        let wait = {
            let mut next_allowed = gate.lock().await;
            let now = tokio::time::Instant::now();
            if let Some(next) = *next_allowed
                && next > now
            {
                Some(next - now)
            } else {
                *next_allowed = Some(now + limits.min_delay);
                None
            }
        };
        match wait {
            Some(delay) => limits.sleep(delay).await,
            None => return,
        }
    }
}

async fn set_record(
    shared: &tokio::sync::Mutex<RunState>,
    identity: &FetchIdentity,
    state: UrlState,
    reason: impl Into<String>,
) {
    let key = identity_key(identity);
    let mut shared = shared.lock().await;
    if let Some(record) = shared.records.get_mut(&key) {
        record.state = state;
        record.reason = reason.into();
    }
}

fn reclassify_queued(records: &mut BTreeMap<String, UrlRecord>, state: UrlState, reason: &str) {
    for record in records.values_mut() {
        if record.state == UrlState::Pending && record.reason == REASON_QUEUED {
            record.state = state;
            record.reason = reason.to_owned();
        }
    }
}

fn report(
    records: &BTreeMap<String, UrlRecord>,
    completed: bool,
    cancelled: bool,
    robots: Option<RobotsRunMetadata>,
    sitemap: SitemapInventory,
    links: &[CoverageLink],
) -> CrawlReport {
    CrawlReport {
        completed,
        cancelled,
        urls: records.values().cloned().collect(),
        robots,
        sitemap,
        links: links.to_vec(),
    }
}

fn stamp_sitemap_provenance(records: &mut BTreeMap<String, UrlRecord>, sitemap: &SitemapInventory) {
    let members: BTreeSet<String> = sitemap
        .urls
        .iter()
        .filter_map(|listed| listed.identity.as_ref().map(identity_key))
        .collect();
    for record in records.values_mut() {
        if let Some(identity) = &record.identity
            && members.contains(&identity_key(identity))
        {
            record.via_sitemap = true;
        }
    }
}

fn min_depth(current: Option<u32>, offered: Option<u32>) -> Option<u32> {
    match (current, offered) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn queue_page(
    records: &mut BTreeMap<String, UrlRecord>,
    frontier: &mut VecDeque<FetchIdentity>,
    limits: &CrawlLimits,
    offer: PageOffer,
) {
    let key = record_key(&offer.classified);
    if let Some(existing) = records.get_mut(&key) {
        existing.via_website |= offer.via_website;
        existing.via_sitemap |= offer.via_sitemap;
        existing.click_depth = min_depth(existing.click_depth, offer.click_depth);
        return;
    }
    if !offer.enqueue_fetch {
        return;
    }
    let identity = offer.classified.identity.clone();
    let (state, reason, enqueue) = if let Some(skip) = offer.classified.skip_reason {
        (UrlState::Excluded, skip.to_owned(), false)
    } else if slots_used(records) >= limits.max_urls {
        (UrlState::Pending, REASON_URL_CAP.to_owned(), false)
    } else if frontier.len() >= limits.max_queue {
        (UrlState::Pending, REASON_QUEUE_CAP.to_owned(), false)
    } else {
        (UrlState::Pending, REASON_QUEUED.to_owned(), true)
    };
    if enqueue && let Some(identity) = &identity {
        frontier.push_back(identity.clone());
    }
    records.insert(
        key,
        UrlRecord {
            original: offer.classified.original,
            identity,
            state,
            reason,
            click_depth: offer.click_depth,
            via_website: offer.via_website,
            via_sitemap: offer.via_sitemap,
        },
    );
}

async fn discover_html_links(
    profile: &Profile,
    limits: &CrawlLimits,
    from: &FetchIdentity,
    body: &[u8],
    shared: &tokio::sync::Mutex<RunState>,
) {
    let html = String::from_utf8_lossy(body);
    let links = extract_navigational_links(&html);
    let document_url = from.as_url().clone();
    let mut state = shared.lock().await;
    let RunState {
        records,
        frontier,
        coverage,
        ..
    } = &mut *state;
    let from_depth = records
        .get(&identity_key(from))
        .and_then(|record| record.click_depth);
    let child_depth = from_depth.map(|depth| depth.saturating_add(1));
    for href in &links.hrefs {
        let classified = coverage.observe_link(
            profile,
            from,
            &document_url,
            links.base_href.as_deref(),
            href,
        );
        queue_page(
            records,
            frontier,
            limits,
            PageOffer {
                classified,
                click_depth: child_depth,
                via_website: true,
                via_sitemap: false,
                enqueue_fetch: true,
            },
        );
    }
}

fn sitemap_file(
    url: String,
    identity: Option<FetchIdentity>,
    state: SitemapFileState,
    reason: impl Into<String>,
    listed_urls: usize,
) -> SitemapFileRecord {
    SitemapFileRecord {
        url,
        identity,
        state,
        reason: reason.into(),
        listed_urls,
    }
}

fn conventional_sitemap(start: &Url) -> Url {
    let mut url = start.clone();
    url.set_path("/sitemap.xml");
    url.set_query(None);
    url.set_fragment(None);
    url
}

#[allow(clippy::too_many_arguments)]
async fn inventory_sitemaps(
    transport: &SignedTransport,
    profile: &Profile,
    limits: &CrawlLimits,
    cancel: &CancelHandle,
    robots_file: Option<&RobotsFile>,
    records: &mut BTreeMap<String, UrlRecord>,
    frontier: &mut VecDeque<FetchIdentity>,
    coverage: &mut Coverage,
) -> Result<SitemapInventory, SitemapInventory> {
    let mut inventory = SitemapInventory::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<(String, Url, usize)> = VecDeque::new();
    let seeds: Vec<Url> = match robots_file {
        Some(file) if !file.sitemaps().is_empty() => file.sitemaps().to_vec(),
        _ if profile.discovery_mode.enqueues_sitemap_urls() => {
            vec![conventional_sitemap(&profile.start_url)]
        }
        _ => Vec::new(),
    };
    for seed in seeds {
        queue.push_back((seed.to_string(), profile.start_url.clone(), 0));
    }

    while let Some((href, document, depth)) = queue.pop_front() {
        if cancel.is_cancelled() {
            break;
        }
        if inventory.files.len() >= limits.max_sitemap_files {
            inventory.files.push(sitemap_file(
                href,
                None,
                SitemapFileState::Capped,
                REASON_SITEMAP_FILE_CAP,
                0,
            ));
            continue;
        }
        if depth > limits.max_sitemap_depth {
            inventory.files.push(sitemap_file(
                href,
                None,
                SitemapFileState::DepthLimit,
                REASON_SITEMAP_DEPTH,
                0,
            ));
            continue;
        }

        let classified = classify_href(profile, &document, None, &href);
        let Some(resolved) = classified.resolved.clone() else {
            inventory.files.push(sitemap_file(
                href,
                None,
                SitemapFileState::ParseError,
                REASON_SITEMAP_PARSE,
                0,
            ));
            continue;
        };
        if resolved.origin() != profile.start_url.origin() {
            inventory.files.push(sitemap_file(
                href,
                classified.identity.clone(),
                SitemapFileState::CrossOrigin,
                REASON_SITEMAP_CROSS_ORIGIN,
                0,
            ));
            continue;
        }
        let identity = FetchIdentity::from_url(&resolved);
        let file_key = identity.as_str().to_owned();
        if !seen.insert(file_key) {
            inventory.files.push(sitemap_file(
                href,
                Some(identity),
                SitemapFileState::Cycle,
                REASON_SITEMAP_CYCLE,
                0,
            ));
            continue;
        }
        if let Some(file) = robots_file
            && let UrlAccess::Blocked(evidence) = file.decide(profile, identity.as_url())
        {
            inventory.files.push(sitemap_file(
                href,
                Some(identity),
                SitemapFileState::Blocked,
                evidence.note,
                0,
            ));
            continue;
        }

        limits.sleep(limits.min_delay).await;
        let fetched = transport
            .fetch_with_body_limit(
                identity.as_url(),
                ResourceKind::Sitemap,
                limits.max_sitemap_bytes,
            )
            .await;
        match fetched {
            Err(err) if err.is_auth_failure() => {
                inventory.files.push(sitemap_file(
                    href,
                    Some(identity),
                    SitemapFileState::Inaccessible,
                    err.observation().to_owned(),
                    0,
                ));
                return Err(inventory);
            }
            Err(err) => {
                inventory.files.push(sitemap_file(
                    href,
                    Some(identity),
                    SitemapFileState::Inaccessible,
                    format!("{REASON_SITEMAP_INACCESSIBLE}: {}", err.observation()),
                    0,
                ));
            }
            Ok((record, body)) => {
                if record.truncated {
                    inventory.files.push(sitemap_file(
                        href,
                        Some(identity),
                        SitemapFileState::Oversized,
                        REASON_SITEMAP_OVERSIZED,
                        0,
                    ));
                    continue;
                }
                if !(200..300).contains(&record.status) {
                    inventory.files.push(sitemap_file(
                        href,
                        Some(identity),
                        SitemapFileState::Inaccessible,
                        format!(
                            "{REASON_SITEMAP_INACCESSIBLE}: HTTP {} from {}",
                            record.status, record.destination_url
                        ),
                        0,
                    ));
                    continue;
                }
                let decoded = match decode_sitemap_body(&body, limits.max_sitemap_bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        inventory.files.push(sitemap_file(
                            href,
                            Some(identity),
                            SitemapFileState::Oversized,
                            REASON_SITEMAP_OVERSIZED,
                            0,
                        ));
                        continue;
                    }
                };
                let xml = String::from_utf8_lossy(&decoded);
                match parse_sitemap_xml(&xml) {
                    Err(err) => {
                        inventory.files.push(sitemap_file(
                            href,
                            Some(identity),
                            SitemapFileState::ParseError,
                            format!("{REASON_SITEMAP_PARSE}: {err}"),
                            0,
                        ));
                    }
                    Ok(ParsedSitemap::Index(locs)) => {
                        inventory.files.push(sitemap_file(
                            href.clone(),
                            Some(identity.clone()),
                            SitemapFileState::Fetched,
                            REASON_FETCHED,
                            locs.len(),
                        ));
                        let parent = identity.as_url().clone();
                        for loc in locs {
                            queue.push_back((loc, parent.clone(), depth + 1));
                        }
                    }
                    Ok(ParsedSitemap::Urlset(locs)) => {
                        inventory.files.push(sitemap_file(
                            href.clone(),
                            Some(identity.clone()),
                            SitemapFileState::Fetched,
                            REASON_FETCHED,
                            locs.len(),
                        ));
                        let parent = identity.as_url().clone();
                        for loc in locs {
                            let listed = classify_href(profile, &parent, None, &loc);
                            inventory.urls.push(SitemapUrlRecord {
                                original: listed.original.clone(),
                                identity: listed.identity.clone(),
                                skip_reason: listed.skip_reason.map(str::to_owned),
                                source_sitemap: parent.as_str().to_owned(),
                            });
                            let _ = coverage.seed(profile, listed.original.as_str());
                            queue_page(
                                records,
                                frontier,
                                limits,
                                PageOffer {
                                    classified: listed,
                                    click_depth: None,
                                    via_website: false,
                                    via_sitemap: true,
                                    enqueue_fetch: profile.discovery_mode.enqueues_sitemap_urls(),
                                },
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(inventory)
}

fn record_key(classified: &ClassifiedUrl) -> String {
    match &classified.identity {
        Some(identity) => format!("i:{}", identity.as_str()),
        None => format!("o:{}", classified.original),
    }
}

fn slots_used(records: &BTreeMap<String, UrlRecord>) -> usize {
    records
        .values()
        .filter(|record| {
            record.state == UrlState::Fetched
                || record.state == UrlState::Failed
                || (record.state == UrlState::Pending && record.reason == REASON_QUEUED)
        })
        .count()
}

fn identity_key(identity: &FetchIdentity) -> String {
    format!("i:{}", identity.as_str())
}

fn backoff_delay(attempt: usize, retry_after: Option<Duration>, max: Duration) -> Duration {
    let fallback = Duration::from_secs(1u64 << attempt.min(4));
    retry_after.unwrap_or(fallback).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::WebBotAuth;
    use crate::profile::DiscoveryMode;
    use crate::transport::SignedTransport;
    use reqwest::{Client, redirect::Policy};
    use std::collections::{HashMap, VecDeque};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Once, mpsc};
    use std::thread;
    use std::time::Duration as StdDuration;
    use url::Url;

    fn origin_path(start: &Url, path: &str) -> Url {
        let mut url = start.clone();
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    const SIGNATURE: &str = "sig1=:TESTSIGNATUREVALUE:";
    const SIGNATURE_INPUT: &str =
        r#"sig1=("@authority" "@path");created=2000000000;keyid="test";tag="web-bot-auth""#;
    const AGENT: &str = "\"https://shopify.com\"";

    #[derive(Clone)]
    enum Planned {
        Stall(Arc<Mutex<mpsc::Receiver<()>>>),
        Respond {
            status: u16,
            location: Option<String>,
            content_type: String,
            body: Vec<u8>,
            retry_after: Option<String>,
        },
    }

    #[derive(Clone)]
    struct Recorded {
        path: String,
        headers: HashMap<String, String>,
    }

    struct TestOrigin {
        addr: SocketAddr,
        recorded: Arc<Mutex<Vec<Recorded>>>,
        plans: Arc<Mutex<HashMap<String, VecDeque<Planned>>>>,
        _server: thread::JoinHandle<()>,
    }

    impl TestOrigin {
        fn https() -> Self {
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            let listener =
                TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let plans = Arc::new(Mutex::new(HashMap::new()));
            let rec = recorded.clone();
            let plan_map = plans.clone();
            let tls = tls_config(&cert);
            let server = thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(StdDuration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(StdDuration::from_secs(2)));
                    let conn = rustls::ServerConnection::new(tls.clone()).unwrap();
                    let mut stream = rustls::StreamOwned::new(conn, stream);
                    serve(&mut stream, &rec, &plan_map);
                }
            });
            Self {
                addr,
                recorded,
                plans,
                _server: server,
            }
        }

        fn url(&self) -> Url {
            Url::parse(&format!("https://127.0.0.1:{}/", self.addr.port())).unwrap()
        }

        fn href(&self, path: &str) -> String {
            origin_path(&self.url(), path).to_string()
        }

        fn on(&self, path: &str, status: u16, content_type: &str, body: &str) {
            self.on_bytes(path, status, content_type, body.as_bytes());
        }

        fn on_bytes(&self, path: &str, status: u16, content_type: &str, body: &[u8]) {
            self.push(
                path,
                Planned::Respond {
                    status,
                    location: None,
                    content_type: content_type.into(),
                    body: body.to_vec(),
                    retry_after: None,
                },
            );
        }

        fn status_retry_after(&self, path: &str, status: u16, retry_after: &str) {
            self.push(
                path,
                Planned::Respond {
                    status,
                    location: None,
                    content_type: "text/plain".into(),
                    body: Vec::new(),
                    retry_after: Some(retry_after.into()),
                },
            );
        }

        fn stall(&self, path: &str) -> mpsc::Sender<()> {
            let (tx, rx) = mpsc::channel();
            self.push(path, Planned::Stall(Arc::new(Mutex::new(rx))));
            tx
        }

        fn allow_robots(&self) {
            self.on(
                "/robots.txt",
                200,
                "text/plain",
                "User-agent: *\nAllow: /\nDisallow: /secret\n",
            );
        }

        fn push(&self, path: &str, planned: Planned) {
            self.plans
                .lock()
                .unwrap()
                .entry(path.to_owned())
                .or_default()
                .push_back(planned);
        }

        fn recorded(&self) -> Vec<Recorded> {
            self.recorded.lock().unwrap().clone()
        }

        fn page_paths(&self) -> Vec<String> {
            self.recorded()
                .into_iter()
                .map(|r| r.path)
                .filter(|path| path != "/robots.txt")
                .collect()
        }
    }

    fn tls_config(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> Arc<rustls::ServerConfig> {
        static PROVIDER: Once = Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
        let cert_der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    fn serve(
        stream: &mut impl ReadWrite,
        recorded: &Arc<Mutex<Vec<Recorded>>>,
        plans: &Arc<Mutex<HashMap<String, VecDeque<Planned>>>>,
    ) {
        let Ok(req) = read_request(stream) else {
            return;
        };
        let planned = {
            let mut plans = plans.lock().unwrap();
            plans
                .get_mut(&req.path)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Planned::Respond {
                    status: 404,
                    location: None,
                    content_type: "text/plain".into(),
                    body: b"missing".to_vec(),
                    retry_after: None,
                })
        };
        recorded.lock().unwrap().push(req);
        match planned {
            Planned::Stall(rx) => {
                let rx = rx.lock().unwrap();
                let _ = rx.recv_timeout(StdDuration::from_secs(5));
            }
            Planned::Respond {
                status,
                location,
                content_type,
                body,
                retry_after,
            } => {
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    429 => "Too Many Requests",
                    503 => "Service Unavailable",
                    _ => "Status",
                };
                let mut out = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(location) = location {
                    out.push_str(&format!("Location: {location}\r\n"));
                }
                if let Some(retry_after) = retry_after {
                    out.push_str(&format!("Retry-After: {retry_after}\r\n"));
                }
                out.push_str("\r\n");
                let mut bytes = out.into_bytes();
                bytes.extend_from_slice(&body);
                let _ = stream.write_all(&bytes);
                let _ = stream.flush();
            }
        }
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    fn read_request(stream: &mut impl Read) -> std::io::Result<Recorded> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64_000 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines = text.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_owned();
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
        }
        Ok(Recorded { path, headers })
    }

    fn auth() -> WebBotAuth {
        WebBotAuth::new(SIGNATURE, SIGNATURE_INPUT, AGENT).unwrap()
    }

    fn client() -> Client {
        Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    fn profile_for(origin: &TestOrigin) -> Profile {
        static N: AtomicU64 = AtomicU64::new(0);
        let _ = N.fetch_add(1, Ordering::Relaxed);
        Profile::load(&format!(
            r#"
schema_version = 1
role = "own_bot"
start_url = "{}"
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
allow_subfolders = []
exclude_paths = ["/search"]
ignored_parameter_mode = "skip"
parameter_names_case_sensitive = true
skip_parameters = ["fbclid"]
schedule_cadence = "weekly"
schedule_weekday = "monday"
completion_email = false
auth_signature_env = "CRAWL_SIGNATURE"
auth_signature_input_env = "CRAWL_SIGNATURE_INPUT"
auth_signature_agent_env = "CRAWL_SIGNATURE_AGENT"
ignored_parameters_captured = 1
ignored_parameters_source_count = 27
exclude_paths_complete = false
lists_complete = false
"#,
            origin.url()
        ))
        .unwrap()
    }

    fn limits() -> CrawlLimits {
        CrawlLimits::from_profile(
            &Profile::load(include_str!("../../../profile.example.toml")).unwrap(),
        )
        .deterministic()
    }

    fn crawler_with(origin: &TestOrigin, limits: CrawlLimits, cancel: CancelHandle) -> Crawler {
        let profile = profile_for(origin);
        let transport = SignedTransport::new_with_client(client(), origin.url(), &auth());
        Crawler::new_with_transport(profile, transport, limits, cancel)
    }

    fn crawler(origin: &TestOrigin, limits: CrawlLimits) -> Crawler {
        crawler_with(origin, limits, CancelHandle::new())
    }

    fn crawler_mode(origin: &TestOrigin, limits: CrawlLimits, mode: DiscoveryMode) -> Crawler {
        let mut profile = profile_for(origin);
        profile.discovery_mode = mode;
        let transport = SignedTransport::new_with_client(client(), origin.url(), &auth());
        Crawler::new_with_transport(profile, transport, limits, CancelHandle::new())
    }

    fn robots_listing_sitemap(origin: &TestOrigin, sitemap_path: &str) {
        origin.on(
            "/robots.txt",
            200,
            "text/plain",
            &format!(
                "User-agent: *\nAllow: /\nDisallow: /secret\nSitemap: {}\n",
                origin.href(sitemap_path)
            ),
        );
    }

    fn assert_signed(origin: &TestOrigin) {
        for req in origin.recorded() {
            assert_eq!(
                req.headers.get("signature").map(String::as_str),
                Some(SIGNATURE)
            );
            assert_eq!(
                req.headers.get("signature-input").map(String::as_str),
                Some(SIGNATURE_INPUT)
            );
            assert!(
                !req.headers.is_empty(),
                "requests must carry Web Bot Auth headers"
            );
        }
    }

    fn identity(origin: &TestOrigin, path: &str) -> FetchIdentity {
        FetchIdentity::from_url(&origin_path(&origin.url(), path))
    }

    #[tokio::test]
    async fn duplicate_discoveries_do_not_schedule_duplicate_fetches() {
        let origin = TestOrigin::https();
        origin.allow_robots();
        origin.on("/a", 200, "text/html", "<html>a</html>");
        let mut limits = limits();
        limits.concurrency = 1;
        let mut crawl = crawler(&origin, limits);
        let page = origin.href("/a");
        crawl.offer(&page);
        crawl.offer(&format!("{page}#frag"));
        crawl.offer(&page);
        let report = crawl.run().await;
        assert_eq!(origin.page_paths(), vec!["/a"]);
        assert_eq!(
            report
                .urls
                .iter()
                .filter(|u| u.identity.as_ref() == Some(&identity(&origin, "/a")))
                .count(),
            1
        );
        assert_eq!(
            report.url(&identity(&origin, "/a")).unwrap().state,
            UrlState::Fetched
        );
        assert_signed(&origin);
    }

    #[tokio::test]
    async fn url_queue_and_response_size_caps_are_independent() {
        let origin = TestOrigin::https();
        origin.allow_robots();
        origin.on("/one", 200, "text/html", "<html>1234567890</html>");
        origin.on("/two", 200, "text/html", "<html>two</html>");
        origin.on("/three", 200, "text/html", "<html>three</html>");
        origin.on("/four", 200, "text/html", "<html>four</html>");

        let mut url_cap = limits();
        url_cap.max_urls = 1;
        url_cap.max_queue = 10;
        url_cap.max_response_bytes = 8;
        url_cap.concurrency = 1;
        let mut crawl = crawler(&origin, url_cap);
        crawl.offer(&origin.href("/one"));
        crawl.offer(&origin.href("/two"));
        let url_report = crawl.run().await;
        assert_eq!(
            url_report.url(&identity(&origin, "/one")).unwrap().state,
            UrlState::Fetched
        );
        assert_eq!(
            url_report.url(&identity(&origin, "/one")).unwrap().reason,
            REASON_TRUNCATED
        );
        assert_eq!(
            url_report.url(&identity(&origin, "/two")).unwrap().state,
            UrlState::Pending
        );
        assert_eq!(
            url_report.url(&identity(&origin, "/two")).unwrap().reason,
            REASON_URL_CAP
        );
        assert_eq!(origin.page_paths(), vec!["/one"]);

        let origin_q = TestOrigin::https();
        origin_q.allow_robots();
        origin_q.on("/one", 200, "text/html", "<html>one</html>");
        origin_q.on("/two", 200, "text/html", "<html>two</html>");
        origin_q.on("/three", 200, "text/html", "<html>three</html>");
        let mut queue_cap = limits();
        queue_cap.max_urls = 10;
        queue_cap.max_queue = 1;
        queue_cap.max_response_bytes = 65_536;
        queue_cap.concurrency = 1;
        let mut crawl = crawler(&origin_q, queue_cap);
        crawl.offer(&origin_q.href("/one"));
        crawl.offer(&origin_q.href("/two"));
        crawl.offer(&origin_q.href("/three"));
        let queue_report = crawl.run().await;
        assert_eq!(
            queue_report
                .url(&identity(&origin_q, "/one"))
                .unwrap()
                .state,
            UrlState::Fetched
        );
        assert_eq!(
            queue_report
                .url(&identity(&origin_q, "/two"))
                .unwrap()
                .reason,
            REASON_QUEUE_CAP
        );
        assert_eq!(
            queue_report
                .url(&identity(&origin_q, "/three"))
                .unwrap()
                .reason,
            REASON_QUEUE_CAP
        );
        assert_eq!(origin_q.page_paths(), vec!["/one"]);
        assert_signed(&origin);
        assert_signed(&origin_q);
    }

    #[tokio::test]
    async fn status_429_and_503_use_bounded_backoff_and_auth_does_not_continue_unsigned() {
        let origin = TestOrigin::https();
        origin.allow_robots();
        origin.status_retry_after("/retry", 429, "2");
        origin.on("/retry", 200, "text/html", "<html>ok</html>");
        origin.status_retry_after("/soft", 503, "1");
        origin.on("/soft", 200, "text/html", "<html>soft</html>");
        let mut backoff = limits();
        backoff.retry_budget = 2;
        backoff.concurrency = 1;
        backoff.max_backoff = Duration::from_secs(5);
        let mut crawl = crawler(&origin, backoff.clone());
        crawl.offer(&origin.href("/retry"));
        crawl.offer(&origin.href("/soft"));
        let report = crawl.run().await;
        assert_eq!(
            report.url(&identity(&origin, "/retry")).unwrap().state,
            UrlState::Fetched
        );
        assert_eq!(
            report.url(&identity(&origin, "/soft")).unwrap().state,
            UrlState::Fetched
        );
        let sleeps = backoff.sleeps();
        assert!(
            sleeps.contains(&Duration::from_secs(2)),
            "429 Retry-After should be recorded, got {sleeps:?}"
        );
        assert!(
            sleeps.contains(&Duration::from_secs(1)),
            "503 Retry-After should be recorded, got {sleeps:?}"
        );
        let pages = origin.page_paths();
        assert_eq!(
            pages.iter().filter(|p| *p == "/retry").count(),
            2,
            "{pages:?}"
        );
        assert_eq!(
            pages.iter().filter(|p| *p == "/soft").count(),
            2,
            "{pages:?}"
        );
        assert_signed(&origin);

        let denied = TestOrigin::https();
        denied.allow_robots();
        denied.on("/a", 401, "text/plain", "nope");
        denied.on("/b", 200, "text/html", "<html>b</html>");
        let mut auth_limits = limits();
        auth_limits.concurrency = 1;
        let mut crawl = crawler(&denied, auth_limits);
        crawl.offer(&denied.href("/a"));
        crawl.offer(&denied.href("/b"));
        let report = crawl.run().await;
        assert_eq!(
            report.url(&identity(&denied, "/a")).unwrap().state,
            UrlState::Failed
        );
        assert!(
            report
                .url(&identity(&denied, "/a"))
                .unwrap()
                .reason
                .contains("401")
                || report.url(&identity(&denied, "/a")).unwrap().reason == REASON_AUTH
        );
        let b = report.url(&identity(&denied, "/b")).unwrap();
        assert_ne!(b.state, UrlState::Fetched);
        assert!(
            b.reason.contains("unsigned")
                || b.reason == REASON_AUTH
                || b.reason == REASON_CANCELLED,
            "{}",
            b.reason
        );
        assert_eq!(denied.page_paths(), vec!["/a"]);
        assert_signed(&denied);
        assert!(
            !format!("{report:?}").contains("TESTSIGNATUREVALUE"),
            "credentials must not appear in reports"
        );
    }

    #[tokio::test]
    async fn every_url_has_a_reason_and_cancellation_is_not_complete() {
        let origin = TestOrigin::https();
        origin.allow_robots();
        origin.on("/", 200, "text/html", "<html>home</html>");
        origin.on("/ok", 200, "text/html", "<html>ok</html>");
        origin.on("/secret", 200, "text/html", "<html>no</html>");
        let mut lim = limits();
        lim.concurrency = 1;
        let mut crawl = crawler(&origin, lim);
        crawl.offer(&origin.href("/"));
        crawl.offer(&origin.href("/ok"));
        crawl.offer(&origin.href("/search"));
        crawl.offer(&origin.href("/secret"));
        crawl.offer("http://[");
        let report = crawl.run().await;
        assert!(report.completed);
        assert!(!report.cancelled);
        for url in &report.urls {
            assert!(!url.reason.is_empty(), "{url:?}");
            assert!(
                matches!(
                    url.state,
                    UrlState::Fetched
                        | UrlState::Excluded
                        | UrlState::Blocked
                        | UrlState::Failed
                        | UrlState::Pending
                ),
                "{url:?}"
            );
        }
        assert_eq!(
            report.url(&identity(&origin, "/")).unwrap().state,
            UrlState::Fetched
        );
        assert_eq!(
            report.url(&identity(&origin, "/ok")).unwrap().state,
            UrlState::Fetched
        );
        assert_eq!(
            report.url(&identity(&origin, "/search")).unwrap().state,
            UrlState::Excluded
        );
        assert_eq!(
            report.url(&identity(&origin, "/secret")).unwrap().state,
            UrlState::Blocked
        );
        assert!(
            !origin.page_paths().contains(&"/secret".to_owned()),
            "{:?}",
            origin.page_paths()
        );
        assert!(
            report
                .by_original("http://[")
                .is_some_and(|u| u.state == UrlState::Excluded)
        );

        let held = TestOrigin::https();
        held.allow_robots();
        let _stall = held.stall("/slow");
        held.on("/later", 200, "text/html", "<html>later</html>");
        let cancel = CancelHandle::new();
        let mut lim = limits();
        lim.concurrency = 1;
        let mut crawl = crawler_with(&held, lim, cancel.clone());
        crawl.offer(&held.href("/slow"));
        crawl.offer(&held.href("/later"));
        let task = tokio::spawn(async move { crawl.run().await });
        let started = tokio::time::Instant::now();
        loop {
            if held.page_paths().iter().any(|path| path == "/slow") {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "timed out waiting for stalled fetch"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
        let report = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("run should finish after cancel")
            .unwrap();
        assert!(
            !report.completed,
            "cancellation must not mark the run complete"
        );
        assert!(report.cancelled);
        assert_eq!(
            report.url(&identity(&held, "/later")).unwrap().state,
            UrlState::Pending
        );
        assert_eq!(
            report.url(&identity(&held, "/later")).unwrap().reason,
            REASON_CANCELLED
        );
        let slow = report.url(&identity(&held, "/slow")).unwrap();
        assert!(
            slow.state == UrlState::Pending || slow.state == UrlState::Failed,
            "{slow:?}"
        );
        assert_ne!(slow.state, UrlState::Fetched);
        assert!(!held.page_paths().contains(&"/later".to_owned()));
        assert_signed(&held);
    }

    #[tokio::test]
    async fn homepage_mode_follows_internal_links_and_ignores_js_only_hrefs() {
        let origin = TestOrigin::https();
        origin.allow_robots();
        origin.on(
            "/",
            200,
            "text/html",
            r#"<html><head><base href="/shop/"></head><body>
                <a href="about">About</a>
                <a href="/secret">blocked</a>
                <a href="https://evil.example/out">out</a>
                <script>document.write('<a href="/js-only">js</a>');</script>
            </body></html>"#,
        );
        origin.on("/shop/about", 200, "text/html", "<html>about</html>");
        origin.on("/secret", 200, "text/html", "<html>no</html>");
        origin.on("/js-only", 200, "text/html", "<html>js</html>");
        let mut lim = limits();
        lim.concurrency = 1;
        let mut crawl = crawler(&origin, lim);
        let report = crawl.run().await;
        assert!(report.completed);
        assert_eq!(
            report.url(&identity(&origin, "/")).unwrap().state,
            UrlState::Fetched
        );
        assert_eq!(
            report.url(&identity(&origin, "/")).unwrap().click_depth,
            Some(0)
        );
        assert_eq!(
            report.url(&identity(&origin, "/shop/about")).unwrap().state,
            UrlState::Fetched
        );
        assert_eq!(
            report
                .url(&identity(&origin, "/shop/about"))
                .unwrap()
                .click_depth,
            Some(1)
        );
        assert_eq!(
            report.url(&identity(&origin, "/secret")).unwrap().state,
            UrlState::Blocked
        );
        assert!(report.url(&identity(&origin, "/js-only")).is_none());
        let external = report
            .url(&FetchIdentity::from_url(
                &Url::parse("https://evil.example/out").unwrap(),
            ))
            .unwrap();
        assert_eq!(external.state, UrlState::Excluded);
        assert!(!external.via_sitemap);
        assert!(external.via_website);
        let paths = origin.page_paths();
        assert!(paths.contains(&"/".to_owned()), "{paths:?}");
        assert!(paths.contains(&"/shop/about".to_owned()), "{paths:?}");
        assert!(!paths.contains(&"/js-only".to_owned()), "{paths:?}");
        assert!(!paths.contains(&"/secret".to_owned()), "{paths:?}");
        assert_signed(&origin);
    }

    #[tokio::test]
    async fn website_mode_keeps_sitemap_inventory_without_zero_click_depth() {
        let origin = TestOrigin::https();
        robots_listing_sitemap(&origin, "/sitemap.xml");
        origin.on(
            "/",
            200,
            "text/html",
            r#"<html><a href="/about">About</a></html>"#,
        );
        origin.on("/about", 200, "text/html", "<html>about</html>");
        origin.on(
            "/sitemap.xml",
            200,
            "application/xml",
            &format!(
                "<urlset><url><loc>{}</loc></url><url><loc>{}</loc></url></urlset>",
                origin.href("/about"),
                origin.href("/orphan")
            ),
        );
        origin.on("/orphan", 200, "text/html", "<html>orphan</html>");
        let mut lim = limits();
        lim.concurrency = 1;
        let mut crawl = crawler(&origin, lim);
        let report = crawl.run().await;
        assert_eq!(
            report
                .url(&identity(&origin, "/about"))
                .unwrap()
                .click_depth,
            Some(1)
        );
        assert!(
            report
                .url(&identity(&origin, "/about"))
                .unwrap()
                .via_website
        );
        assert!(
            report
                .url(&identity(&origin, "/about"))
                .unwrap()
                .via_sitemap
        );
        assert!(report.url(&identity(&origin, "/orphan")).is_none());
        assert_eq!(report.sitemap.urls.len(), 2);
        assert!(report.sitemap.urls.iter().any(|u| {
            u.identity.as_ref() == Some(&identity(&origin, "/orphan")) && u.skip_reason.is_none()
        }));
        assert!(!origin.page_paths().contains(&"/orphan".to_owned()));
        assert_signed(&origin);
    }

    #[tokio::test]
    async fn sitemap_and_combined_modes_do_not_invent_click_depth() {
        let origin = TestOrigin::https();
        robots_listing_sitemap(&origin, "/sitemap.xml");
        origin.on(
            "/",
            200,
            "text/html",
            r#"<html><a href="/about">About</a></html>"#,
        );
        origin.on("/about", 200, "text/html", "<html>about</html>");
        origin.on("/orphan", 200, "text/html", "<html>orphan</html>");
        origin.on(
            "/sitemap.xml",
            200,
            "application/xml",
            &format!(
                "<urlset><url><loc>{}</loc></url><url><loc>{}</loc></url></urlset>",
                origin.href("/"),
                origin.href("/orphan")
            ),
        );
        let mut lim = limits();
        lim.concurrency = 1;
        let mut sitemap_only = crawler_mode(&origin, lim.clone(), DiscoveryMode::Sitemap);
        let sitemap_report = sitemap_only.run().await;
        assert!(sitemap_report.url(&identity(&origin, "/")).is_some());
        assert_eq!(
            sitemap_report
                .url(&identity(&origin, "/"))
                .unwrap()
                .click_depth,
            None,
            "sitemap URLs must not receive artificial zero-click depth"
        );
        assert_eq!(
            sitemap_report
                .url(&identity(&origin, "/orphan"))
                .unwrap()
                .click_depth,
            None
        );
        assert!(sitemap_report.url(&identity(&origin, "/about")).is_none());
        assert!(!origin.page_paths().contains(&"/about".to_owned()));

        let origin2 = TestOrigin::https();
        robots_listing_sitemap(&origin2, "/sitemap.xml");
        origin2.on(
            "/",
            200,
            "text/html",
            r#"<html><a href="/about">About</a></html>"#,
        );
        origin2.on("/about", 200, "text/html", "<html>about</html>");
        origin2.on("/orphan", 200, "text/html", "<html>orphan</html>");
        origin2.on(
            "/sitemap.xml",
            200,
            "application/xml",
            &format!(
                "<urlset><url><loc>{}</loc></url><url><loc>{}</loc></url></urlset>",
                origin2.href("/"),
                origin2.href("/orphan")
            ),
        );
        let mut combined = crawler_mode(&origin2, lim, DiscoveryMode::Combined);
        let combined_report = combined.run().await;
        let home = combined_report.url(&identity(&origin2, "/")).unwrap();
        assert_eq!(home.click_depth, Some(0));
        assert!(home.via_website && home.via_sitemap);
        let about = combined_report.url(&identity(&origin2, "/about")).unwrap();
        assert_eq!(about.click_depth, Some(1));
        assert!(about.via_website && !about.via_sitemap);
        let orphan = combined_report.url(&identity(&origin2, "/orphan")).unwrap();
        assert_eq!(orphan.click_depth, None);
        assert!(orphan.via_sitemap && !orphan.via_website);
        assert_signed(&origin);
        assert_signed(&origin2);
    }

    #[tokio::test]
    async fn sitemap_cycles_size_parse_and_inaccessible_are_recorded() {
        let origin = TestOrigin::https();
        robots_listing_sitemap(&origin, "/sitemap-index.xml");
        origin.on(
            "/sitemap-index.xml",
            200,
            "application/xml",
            &format!(
                "<sitemapindex>
                    <sitemap><loc>{}</loc></sitemap>
                    <sitemap><loc>{}</loc></sitemap>
                    <sitemap><loc>{}</loc></sitemap>
                    <sitemap><loc>{}</loc></sitemap>
                 </sitemapindex>",
                origin.href("/sitemap-index.xml"),
                origin.href("/too-big.xml"),
                origin.href("/broken.xml"),
                origin.href("/missing.xml")
            ),
        );
        origin.on(
            "/too-big.xml",
            200,
            "application/xml",
            &"<urlset></urlset>".repeat(100),
        );
        origin.on(
            "/broken.xml",
            200,
            "application/xml",
            "<html>not a sitemap</html>",
        );
        let mut lim = limits();
        lim.concurrency = 1;
        lim.max_sitemap_bytes = 512;
        let mut crawl = crawler_mode(&origin, lim, DiscoveryMode::Sitemap);
        let report = crawl.run().await;
        assert!(
            report
                .sitemap
                .files
                .iter()
                .any(|f| f.state == SitemapFileState::Cycle)
        );
        assert!(
            report
                .sitemap
                .files
                .iter()
                .any(|f| f.state == SitemapFileState::Oversized)
        );
        assert!(
            report
                .sitemap
                .files
                .iter()
                .any(|f| f.state == SitemapFileState::ParseError)
        );
        assert!(
            report
                .sitemap
                .files
                .iter()
                .any(|f| f.state == SitemapFileState::Inaccessible)
        );
        assert_signed(&origin);
    }

    #[tokio::test]
    async fn cross_origin_sitemaps_are_not_fetched_and_gzip_indexes_are() {
        let origin = TestOrigin::https();
        origin.on(
            "/robots.txt",
            200,
            "text/plain",
            &format!(
                "User-agent: *\nAllow: /\nSitemap: https://evil.example/sitemap.xml\nSitemap: {}\n",
                origin.href("/sitemap.xml.gz")
            ),
        );
        let nested = format!(
            "<urlset><url><loc>{}</loc></url></urlset>",
            origin.href("/gzipped")
        );
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, nested.as_bytes()).unwrap();
        let gz = encoder.finish().unwrap();
        origin.on_bytes("/sitemap.xml.gz", 200, "application/gzip", &gz);
        origin.on("/gzipped", 200, "text/html", "<html>gz</html>");
        let mut lim = limits();
        lim.concurrency = 1;
        let mut crawl = crawler_mode(&origin, lim, DiscoveryMode::Sitemap);
        let report = crawl.run().await;
        assert!(report.sitemap.files.iter().any(|f| {
            f.state == SitemapFileState::CrossOrigin && f.reason == REASON_SITEMAP_CROSS_ORIGIN
        }));
        assert!(report.url(&identity(&origin, "/gzipped")).is_some());
        assert_eq!(
            report
                .url(&identity(&origin, "/gzipped"))
                .unwrap()
                .click_depth,
            None
        );
        assert!(!origin.recorded().iter().any(|r| {
            r.headers
                .get("host")
                .is_some_and(|h| h.contains("evil.example"))
        }));
        assert_eq!(
            origin
                .recorded()
                .iter()
                .filter(|r| r.path == "/sitemap.xml.gz")
                .count(),
            1
        );
        assert_signed(&origin);
        assert!(
            !format!("{report:?}").contains("TESTSIGNATUREVALUE"),
            "credentials must not appear in reports"
        );
    }
}
