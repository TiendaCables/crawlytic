//! Typed crawl commands and coalesced progress events.
//!
//! Ratatui, a CLI, or a later service can drive the reusable core without a
//! terminal dependency. Durable URL state lives in [`Store`]; the event stream
//! is a bounded live view that coalesces progress so a slow consumer cannot
//! grow memory without bound.
//!
//! The displayed user agent is the HTTP `User-Agent` string. It is not a
//! browser viewport, device width, or rendering target.

use crate::auth::WebBotAuth;
use crate::crawl::{
    CancelHandle, CrawlLimits, CrawlNotify, CrawlObserver, CrawlReport, Crawler, UrlRecord,
    UrlState,
};
use crate::profile::Profile;
use crate::scope::FetchIdentity;
use crate::store::Store;
use crate::transport::SignedTransport;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, watch};

/// Capacity of the discrete event queue (fetch completions and diagnostics).
/// Progress snapshots use a watch channel and always keep the latest value.
pub const DISCRETE_EVENT_CAPACITY: usize = 32;
const COMMAND_CAPACITY: usize = 8;

/// Commands a headless client, TUI, or service may send.
#[derive(Debug, Clone)]
pub enum CrawlCommand {
    /// Begin a new persisted run from `profile`. Credentials stay on the engine.
    Start { profile: Box<Profile> },
    /// Stop scheduling and classify outstanding URLs as pending.
    Cancel,
    /// Continue an incomplete persisted run.
    Resume { run_id: i64 },
}

/// Discrete events. Progress is not queued; consumers read the latest snapshot
/// from [`Engine::progress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrawlEvent {
    Status(StatusEvent),
    FetchCompleted(FetchCompletion),
    Diagnostic(Diagnostic),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEvent {
    pub run_id: i64,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCompletion {
    pub run_id: i64,
    pub original: String,
    pub identity: Option<FetchIdentity>,
    pub state: UrlState,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub run_id: Option<i64>,
    pub kind: DiagnosticKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    Persist,
    Auth,
    Command,
    Transport,
}

/// Engine lifecycle, including idle (no run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Idle,
    Running,
    Completed,
    Incomplete,
    Failed,
}

/// HTTP User-Agent shown to operators and sent on requests.
///
/// This is not a browser viewport, device profile, or rendering target.
/// Viewport metadata is a page observation, not a crawl-command dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayedUserAgent(String);

impl DisplayedUserAgent {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_profile(profile: &Profile) -> Self {
        Self(profile.user_agent.clone())
    }

    fn unknown() -> Self {
        Self(String::new())
    }
}

/// Counts of unique URL records by persisted [`UrlState`].
///
/// Units: one per unique URL record (fetch identity when present, otherwise the
/// original URL). `discovered` is the sum of the six state counts and must
/// equal the number of persisted URL rows for the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CrawlCounters {
    /// Unique records that completed a fetch, including truncated bodies.
    pub fetched: u64,
    /// Unique records skipped by scope, exclusions, or skip-parameters.
    pub excluded: u64,
    /// Unique records denied by robots (or another block kind).
    pub blocked: u64,
    /// Unique records that exhausted retries or failed transport/auth.
    pub failed: u64,
    /// Unique records discovered but not completed (queued, capped, cancelled).
    pub pending: u64,
    /// Unique records currently being fetched. Crash recovery maps these to pending.
    pub in_flight: u64,
}

impl CrawlCounters {
    /// Total unique URL records. Equals the six state counts.
    pub fn discovered(&self) -> u64 {
        self.fetched + self.excluded + self.blocked + self.failed + self.pending + self.in_flight
    }

    pub fn from_records<'a, I>(records: I) -> Self
    where
        I: IntoIterator<Item = &'a UrlRecord>,
    {
        let mut counters = Self::default();
        for record in records {
            match record.state {
                UrlState::Fetched => counters.fetched += 1,
                UrlState::Excluded => counters.excluded += 1,
                UrlState::Blocked => counters.blocked += 1,
                UrlState::Failed => counters.failed += 1,
                UrlState::Pending => counters.pending += 1,
                UrlState::InFlight => counters.in_flight += 1,
            }
        }
        counters
    }

    fn from_map(records: &BTreeMap<String, UrlRecord>) -> Self {
        Self::from_records(records.values())
    }
}

/// Latest coalesced live view. Intermediate snapshots are dropped; storage is
/// the durable source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressSnapshot {
    pub run_id: Option<i64>,
    pub status: SessionStatus,
    /// HTTP User-Agent for this run; never a viewport.
    pub displayed_user_agent: DisplayedUserAgent,
    pub counters: CrawlCounters,
    /// Discrete events dropped because the consumer lagged. Unit: events, not URLs.
    pub dropped_events: u64,
    /// Short live phase text (resource probes, TLS). Empty when idle.
    pub activity: String,
}

impl ProgressSnapshot {
    fn idle() -> Self {
        Self {
            run_id: None,
            status: SessionStatus::Idle,
            displayed_user_agent: DisplayedUserAgent::unknown(),
            counters: CrawlCounters::default(),
            dropped_events: 0,
            activity: String::new(),
        }
    }
}

pub struct EngineConfig {
    pub store: Store,
    pub auth: WebBotAuth,
    pub limits: CrawlLimits,
}

#[derive(Clone)]
pub struct CommandHandle {
    tx: mpsc::Sender<CrawlCommand>,
}

impl CommandHandle {
    pub fn try_send(&self, command: CrawlCommand) -> Result<(), CommandSendError> {
        self.tx
            .try_send(command)
            .map_err(|_| CommandSendError::ClosedOrFull)
    }

    pub async fn send(&self, command: CrawlCommand) -> Result<(), CommandSendError> {
        self.tx
            .send(command)
            .await
            .map_err(|_| CommandSendError::ClosedOrFull)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSendError {
    ClosedOrFull,
}

/// Headless driver: send [`CrawlCommand`]s, watch coalesced progress, receive
/// bounded discrete events.
pub struct Engine {
    commands: CommandHandle,
    progress: watch::Receiver<ProgressSnapshot>,
    events: mpsc::Receiver<CrawlEvent>,
}

impl Engine {
    pub fn spawn(config: EngineConfig) -> Self {
        spawn_inner(config, None)
    }

    #[cfg(test)]
    pub(crate) fn spawn_with_transport(config: EngineConfig, transport: SignedTransport) -> Self {
        spawn_inner(config, Some(transport))
    }

    pub fn commands(&self) -> CommandHandle {
        self.commands.clone()
    }

    pub fn progress(&self) -> watch::Receiver<ProgressSnapshot> {
        self.progress.clone()
    }

    pub fn events(&mut self) -> &mut mpsc::Receiver<CrawlEvent> {
        &mut self.events
    }
}

fn spawn_inner(config: EngineConfig, transport: Option<SignedTransport>) -> Engine {
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CAPACITY);
    let (progress_tx, progress_rx) = watch::channel(ProgressSnapshot::idle());
    let (event_tx, event_rx) = mpsc::channel(DISCRETE_EVENT_CAPACITY);
    let bus = Arc::new(EventBus {
        progress: progress_tx,
        events: event_tx,
        dropped: AtomicU64::new(0),
        run_id: std::sync::Mutex::new(None),
        status: std::sync::Mutex::new(SessionStatus::Idle),
        user_agent: std::sync::Mutex::new(DisplayedUserAgent::unknown()),
        activity: std::sync::Mutex::new(String::new()),
    });
    tokio::spawn(run_engine(config, transport, cmd_rx, bus));
    Engine {
        commands: CommandHandle { tx: cmd_tx },
        progress: progress_rx,
        events: event_rx,
    }
}

struct ActiveRun {
    cancel: CancelHandle,
    join: tokio::task::JoinHandle<CrawlReport>,
    run_id: i64,
}

enum EngineStep {
    Command(Option<CrawlCommand>),
    Finished(Result<Box<CrawlReport>, tokio::task::JoinError>),
}

async fn run_engine(
    config: EngineConfig,
    transport: Option<SignedTransport>,
    mut commands: mpsc::Receiver<CrawlCommand>,
    bus: Arc<EventBus>,
) {
    let mut active: Option<ActiveRun> = None;
    loop {
        let step = if let Some(run) = active.as_mut() {
            tokio::select! {
                cmd = commands.recv() => EngineStep::Command(cmd),
                result = &mut run.join => EngineStep::Finished(result.map(Box::new)),
            }
        } else {
            EngineStep::Command(commands.recv().await)
        };
        match step {
            EngineStep::Command(None) => {
                if let Some(run) = active.take() {
                    run.cancel.cancel();
                    let _ = run.join.await;
                }
                break;
            }
            EngineStep::Command(Some(CrawlCommand::Start { profile })) => {
                if active.is_some() {
                    bus.publish_diagnostic(DiagnosticKind::Command, "A run is already in progress");
                    continue;
                }
                match begin_run(&config, transport.clone(), *profile, bus.clone()) {
                    Ok(run) => active = Some(run),
                    Err(message) => bus.publish_diagnostic(DiagnosticKind::Command, &message),
                }
            }
            EngineStep::Command(Some(CrawlCommand::Cancel)) => {
                if let Some(run) = &active {
                    run.cancel.cancel();
                } else {
                    bus.publish_diagnostic(DiagnosticKind::Command, "No run is in progress");
                }
            }
            EngineStep::Command(Some(CrawlCommand::Resume { run_id })) => {
                if active.is_some() {
                    bus.publish_diagnostic(DiagnosticKind::Command, "A run is already in progress");
                    continue;
                }
                match resume_run(&config, transport.clone(), run_id, bus.clone()) {
                    Ok(run) => active = Some(run),
                    Err(message) => bus.publish_diagnostic(DiagnosticKind::Command, &message),
                }
            }
            EngineStep::Finished(result) => {
                if let Some(run) = active.take() {
                    finish_run(run.run_id, result.map(|report| *report), &bus);
                }
            }
        }
    }
}

fn begin_run(
    config: &EngineConfig,
    transport: Option<SignedTransport>,
    profile: Profile,
    bus: Arc<EventBus>,
) -> Result<ActiveRun, String> {
    let run_id = config
        .store
        .begin_run(&profile)
        .map_err(|err| err.to_string())?;
    let cancel = CancelHandle::new();
    let mut crawler = match transport {
        Some(transport) => Crawler::new_with_transport(
            profile.clone(),
            transport,
            config.limits.clone(),
            cancel.clone(),
        ),
        None => Crawler::new(
            profile.clone(),
            &config.auth,
            config.limits.clone(),
            cancel.clone(),
        )
        .map_err(|err| err.to_string())?,
    };
    crawler.persist_on(config.store.clone(), run_id);
    crawler.observe_with(CrawlNotify::new(Arc::new(BusObserver(bus.clone()))));
    bus.set_user_agent(DisplayedUserAgent::from_profile(&profile));
    bus.reset_dropped();
    bus.publish_status(run_id, SessionStatus::Running);
    let join = tokio::spawn(async move { crawler.run().await });
    Ok(ActiveRun {
        cancel,
        join,
        run_id,
    })
}

fn resume_run(
    config: &EngineConfig,
    transport: Option<SignedTransport>,
    run_id: i64,
    bus: Arc<EventBus>,
) -> Result<ActiveRun, String> {
    let loaded = config
        .store
        .load_run(run_id)
        .map_err(|err| err.to_string())?;
    let cancel = CancelHandle::new();
    let mut crawler = match transport {
        Some(transport) => Crawler::resume_with_transport(
            config.store.clone(),
            run_id,
            transport,
            config.limits.clone(),
            cancel.clone(),
        )
        .map_err(|err| err.to_string())?,
        None => Crawler::resume(
            config.store.clone(),
            run_id,
            &config.auth,
            config.limits.clone(),
            cancel.clone(),
        )
        .map_err(|err| err.to_string())?,
    };
    crawler.observe_with(CrawlNotify::new(Arc::new(BusObserver(bus.clone()))));
    bus.set_user_agent(DisplayedUserAgent::from_profile(&loaded.profile));
    bus.reset_dropped();
    bus.publish_status(run_id, SessionStatus::Running);
    bus.publish_url_list(&loaded.urls);
    let join = tokio::spawn(async move { crawler.run().await });
    Ok(ActiveRun {
        cancel,
        join,
        run_id,
    })
}

fn finish_run(run_id: i64, result: Result<CrawlReport, tokio::task::JoinError>, bus: &EventBus) {
    match result {
        Ok(report) => {
            if let Some(err) = &report.persist_error {
                bus.publish_diagnostic(DiagnosticKind::Persist, err);
            }
            let status = if report.completed {
                SessionStatus::Completed
            } else if report.cancelled || report.persist_error.is_some() {
                SessionStatus::Incomplete
            } else {
                SessionStatus::Failed
            };
            bus.publish_status(run_id, status);
            bus.publish_url_list(&report.urls);
        }
        Err(err) => {
            bus.publish_diagnostic(DiagnosticKind::Transport, &err.to_string());
            bus.publish_status(run_id, SessionStatus::Failed);
        }
    }
}

struct BusObserver(Arc<EventBus>);

impl CrawlObserver for BusObserver {
    fn on_records(&self, records: &BTreeMap<String, UrlRecord>, latest: Option<&UrlRecord>) {
        self.0.publish_records(records, latest);
    }

    fn on_diagnostic(&self, persist: bool, message: &str) {
        self.0.publish_diagnostic(
            if persist {
                DiagnosticKind::Persist
            } else {
                DiagnosticKind::Auth
            },
            message,
        );
    }

    fn on_activity(&self, activity: &str) {
        self.0.set_activity(activity);
    }
}

struct EventBus {
    progress: watch::Sender<ProgressSnapshot>,
    events: mpsc::Sender<CrawlEvent>,
    dropped: AtomicU64,
    run_id: std::sync::Mutex<Option<i64>>,
    status: std::sync::Mutex<SessionStatus>,
    user_agent: std::sync::Mutex<DisplayedUserAgent>,
    activity: std::sync::Mutex<String>,
}

impl EventBus {
    fn publish_records(&self, records: &BTreeMap<String, UrlRecord>, latest: Option<&UrlRecord>) {
        let counters = CrawlCounters::from_map(records);
        self.publish_progress(counters);
        if let Some(record) = latest
            && matches!(
                record.state,
                UrlState::Fetched | UrlState::Failed | UrlState::Blocked | UrlState::Excluded
            )
            && let Some(run_id) = *self.run_id.lock().unwrap_or_else(|e| e.into_inner())
        {
            self.try_emit(CrawlEvent::FetchCompleted(FetchCompletion {
                run_id,
                original: record.original.clone(),
                identity: record.identity.clone(),
                state: record.state,
                reason: record.reason.clone(),
            }));
        }
    }

    fn publish_url_list(&self, urls: &[UrlRecord]) {
        self.publish_progress(CrawlCounters::from_records(urls));
    }

    fn reset_dropped(&self) {
        self.dropped.store(0, Ordering::SeqCst);
    }

    fn publish_progress(&self, counters: CrawlCounters) {
        let snapshot = ProgressSnapshot {
            run_id: *self.run_id.lock().unwrap_or_else(|e| e.into_inner()),
            status: *self.status.lock().unwrap_or_else(|e| e.into_inner()),
            displayed_user_agent: self
                .user_agent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            counters,
            dropped_events: self.dropped.load(Ordering::SeqCst),
            activity: self
                .activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        };
        let _ = self.progress.send(snapshot);
    }

    fn set_activity(&self, activity: &str) {
        *self.activity.lock().unwrap_or_else(|e| e.into_inner()) = activity.to_owned();
        let counters = self.progress.borrow().counters;
        self.publish_progress(counters);
    }

    fn publish_status(&self, run_id: i64, status: SessionStatus) {
        *self.run_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(run_id);
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = status;
        self.try_emit(CrawlEvent::Status(StatusEvent { run_id, status }));
        let counters = self.progress.borrow().counters;
        self.publish_progress(counters);
    }

    fn publish_diagnostic(&self, kind: DiagnosticKind, message: &str) {
        let run_id = *self.run_id.lock().unwrap_or_else(|e| e.into_inner());
        self.try_emit(CrawlEvent::Diagnostic(Diagnostic {
            run_id,
            kind,
            message: message.to_owned(),
        }));
    }

    fn set_user_agent(&self, ua: DisplayedUserAgent) {
        *self.user_agent.lock().unwrap_or_else(|e| e.into_inner()) = ua;
    }

    fn try_emit(&self, event: CrawlEvent) {
        match self.events.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawl::UrlRecord;

    #[test]
    fn core_manifest_does_not_depend_on_ratatui() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            !manifest.contains("ratatui"),
            "crawlytic-core must compile without Ratatui"
        );
    }

    #[test]
    fn counters_have_documented_units_and_sum_to_discovered() {
        let records = vec![
            record(UrlState::Fetched),
            record(UrlState::Fetched),
            record(UrlState::Excluded),
            record(UrlState::Blocked),
            record(UrlState::Failed),
            record(UrlState::Pending),
            record(UrlState::InFlight),
        ];
        let counters = CrawlCounters::from_records(&records);
        assert_eq!(counters.fetched, 2);
        assert_eq!(counters.excluded, 1);
        assert_eq!(counters.blocked, 1);
        assert_eq!(counters.failed, 1);
        assert_eq!(counters.pending, 1);
        assert_eq!(counters.in_flight, 1);
        assert_eq!(counters.discovered(), 7);
        assert_eq!(
            counters.discovered(),
            counters.fetched
                + counters.excluded
                + counters.blocked
                + counters.failed
                + counters.pending
                + counters.in_flight
        );
    }

    #[test]
    fn displayed_user_agent_is_not_a_viewport() {
        let fields = std::any::type_name::<ProgressSnapshot>();
        assert!(
            !fields.contains("viewport"),
            "progress must not model a viewport: {fields}"
        );
        let ua = DisplayedUserAgent("Crawlytic/0.1 (self-hosted SEO audit)".into());
        assert_eq!(ua.as_str(), "Crawlytic/0.1 (self-hosted SEO audit)");
        assert!(!ua.as_str().to_ascii_lowercase().contains("width="));
        assert!(!ua.as_str().to_ascii_lowercase().contains("device-width"));
    }

    #[tokio::test]
    async fn slow_consumer_drops_discrete_events_instead_of_growing() {
        let (progress_tx, progress_rx) = watch::channel(ProgressSnapshot::idle());
        let (event_tx, mut event_rx) = mpsc::channel(DISCRETE_EVENT_CAPACITY);
        let bus = EventBus {
            progress: progress_tx,
            events: event_tx,
            dropped: AtomicU64::new(0),
            run_id: std::sync::Mutex::new(Some(1)),
            status: std::sync::Mutex::new(SessionStatus::Running),
            user_agent: std::sync::Mutex::new(DisplayedUserAgent::unknown()),
            activity: std::sync::Mutex::new(String::new()),
        };
        let n = DISCRETE_EVENT_CAPACITY as u64 + 20;
        for i in 0..n {
            bus.try_emit(CrawlEvent::FetchCompleted(FetchCompletion {
                run_id: 1,
                original: format!("https://example.test/{i}"),
                identity: None,
                state: UrlState::Fetched,
                reason: "Fetched".into(),
            }));
        }
        let mut queued = 0usize;
        while event_rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, DISCRETE_EVENT_CAPACITY);
        assert_eq!(bus.dropped.load(Ordering::SeqCst), 20);
        bus.publish_progress(CrawlCounters::default());
        assert_eq!(progress_rx.borrow().dropped_events, 20);
    }

    fn record(state: UrlState) -> UrlRecord {
        UrlRecord {
            original: "https://example.test/".into(),
            identity: None,
            state,
            reason: "test".into(),
            click_depth: None,
            via_website: true,
            via_sitemap: false,
        }
    }
}
