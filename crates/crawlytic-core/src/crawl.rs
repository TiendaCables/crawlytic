//! Bounded async crawl: frontier, paced workers, backoff and cancellation.
//!
//! Discovery (HTML links, sitemaps) is a later slice. Callers offer URLs.
//! Duplicate identities are not scheduled twice. Caps for unique fetches, queue
//! depth and response size are independent. `crawl_delay = minimum` is a paced
//! policy with bounded concurrency, not an unbounded worker pool.

use crate::auth::WebBotAuth;
use crate::profile::Profile;
use crate::robots::{AllowReason, RobotsCache, RobotsFile, RobotsRunMetadata, UrlAccess};
use crate::scope::{ClassifiedUrl, Coverage, FetchIdentity};
use crate::transport::{ResourceKind, SignedTransport};
use anyhow::Result;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

pub const REASON_QUEUED: &str = "Queued";
pub const REASON_QUEUE_CAP: &str = "Queue cap";
pub const REASON_URL_CAP: &str = "URL cap";
pub const REASON_CANCELLED: &str = "Cancelled";
pub const REASON_FETCHED: &str = "Fetched";
pub const REASON_TRUNCATED: &str = "Fetched; response truncated at size cap";
pub const REASON_RETRY_BUDGET: &str = "Retry budget exhausted";
pub const REASON_AUTH: &str = "Authentication failure; unsigned fallback is disabled";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlReport {
    pub completed: bool,
    pub cancelled: bool,
    pub urls: Vec<UrlRecord>,
    pub robots: Option<RobotsRunMetadata>,
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
        if self.records.contains_key(&key) {
            return self.records.get(&key).expect("inserted URL record");
        }
        let identity = classified.identity.clone();
        let (state, reason, enqueue) = if let Some(skip) = classified.skip_reason {
            (UrlState::Excluded, skip.to_owned(), false)
        } else if slots_used(&self.records) >= self.limits.max_urls {
            (UrlState::Pending, REASON_URL_CAP.to_owned(), false)
        } else if self.frontier.len() >= self.limits.max_queue {
            (UrlState::Pending, REASON_QUEUE_CAP.to_owned(), false)
        } else {
            (UrlState::Pending, REASON_QUEUED.to_owned(), true)
        };
        if enqueue && let Some(identity) = &identity {
            self.frontier.push_back(identity.clone());
        }
        self.records.insert(
            key.clone(),
            UrlRecord {
                original: classified.original,
                identity,
                state,
                reason,
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
                return report(&self.records, false, self.cancel.is_cancelled(), None);
            }
            Err(_) => None,
        };
        let robots_meta = robots_file
            .as_ref()
            .map(|file| file.metadata(&self.profile, &self.profile.start_url));

        if self.cancel.is_cancelled() {
            reclassify_queued(&mut self.records, UrlState::Pending, REASON_CANCELLED);
            return report(&self.records, false, true, robots_meta);
        }

        let shared = Arc::new(tokio::sync::Mutex::new(RunState {
            records: std::mem::take(&mut self.records),
            frontier: std::mem::take(&mut self.frontier),
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
        report(&self.records, !cancelled, cancelled, robots_meta)
    }
}

struct RunState {
    records: BTreeMap<String, UrlRecord>,
    frontier: VecDeque<FetchIdentity>,
    auth_failed: bool,
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
            Ok((record, _)) => {
                let reason = if record.truncated {
                    REASON_TRUNCATED
                } else {
                    REASON_FETCHED
                };
                set_record(&shared, &identity, UrlState::Fetched, reason).await;
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
) -> CrawlReport {
    CrawlReport {
        completed,
        cancelled,
        urls: records.values().cloned().collect(),
        robots,
    }
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
            body: String,
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
            self.push(
                path,
                Planned::Respond {
                    status,
                    location: None,
                    content_type: content_type.into(),
                    body: body.into(),
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
                    body: String::new(),
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
                    body: "missing".into(),
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
                out.push_str(&body);
                let _ = stream.write_all(out.as_bytes());
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
}
