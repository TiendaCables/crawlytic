//! Noninteractive audit driver sharing Engine, evaluate_stored and export
//! with Ratatui. Overlapping processes are refused. Secrets resolve at runtime.

use crate::auth::{CREDENTIAL_REPLACEMENT_PLAN, WebBotAuth};
use crate::engine::{
    CrawlCommand, CrawlEvent, DiagnosticKind, Engine, EngineConfig, SessionStatus,
};
use crate::exchange::{WrittenExport, export_document, write_export};
use crate::profile::Profile;
use crate::store::Store;
use crate::transport::SignedTransport;
use crate::{AuditConfig, CrawlLimits, audit_registry, evaluate_stored};
use serde::Serialize;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 1;
pub const EXIT_AUTH: i32 = 2;
pub const EXIT_OVERLAP: i32 = 3;
pub const EXIT_CRAWL: i32 = 4;
pub const EXIT_EXPORT: i32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessError {
    pub exit_code: i32,
    message: String,
}

impl HeadlessError {
    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for HeadlessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HeadlessError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeadlessReport {
    pub ok: bool,
    pub exit_code: i32,
    pub kind: String,
    pub run_id: Option<i64>,
    pub status: Option<String>,
    pub csv_path: Option<String>,
    pub json_path: Option<String>,
    pub overlap: bool,
    pub email: bool,
    pub auth_resolved: bool,
    pub message: String,
}

impl HeadlessReport {
    pub fn to_json(&self) -> Result<String, HeadlessError> {
        serde_json::to_string_pretty(self)
            .map_err(|err| HeadlessError::new(EXIT_EXPORT, err.to_string()))
    }
}

#[derive(Debug)]
pub struct RunLock {
    _file: File,
}

impl RunLock {
    pub fn acquire(path: &Path) -> Result<Self, HeadlessError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                HeadlessError::new(EXIT_USAGE, format!("Cannot create lock directory: {err}"))
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|err| {
                HeadlessError::new(EXIT_USAGE, format!("Cannot open lock file: {err}"))
            })?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(HeadlessError::new(
                EXIT_OVERLAP,
                "A run is already in progress; overlapping audits are prevented, not queued.",
            )),
            Err(TryLockError::Error(err)) => Err(HeadlessError::new(
                EXIT_USAGE,
                format!("Cannot acquire run lock: {err}"),
            )),
        }
    }
}

pub fn resolve_runtime_auth(profile: &Profile) -> Result<WebBotAuth, HeadlessError> {
    WebBotAuth::from_profile(profile).map_err(|err| {
        let message = err.to_string();
        let message = if message.contains(CREDENTIAL_REPLACEMENT_PLAN) {
            message
        } else {
            format!("{message} {CREDENTIAL_REPLACEMENT_PLAN}")
        };
        HeadlessError::new(EXIT_AUTH, message)
    })
}

pub fn persist_and_export(
    store: &Store,
    run_id: i64,
    export_dir: &Path,
) -> Result<WrittenExport, HeadlessError> {
    std::fs::create_dir_all(export_dir).map_err(|err| {
        HeadlessError::new(
            EXIT_EXPORT,
            format!("Cannot create export directory: {err}"),
        )
    })?;
    let report = evaluate_stored(store, run_id, &AuditConfig::default(), &audit_registry())
        .map_err(|err| HeadlessError::new(EXIT_EXPORT, err.to_string()))?;
    let urls = store
        .load_run(run_id)
        .map_err(|err| HeadlessError::new(EXIT_EXPORT, err.to_string()))?
        .urls;
    let document = export_document(&report, &urls)
        .map_err(|err| HeadlessError::new(EXIT_EXPORT, err.to_string()))?;
    write_export(export_dir, &document)
        .map_err(|err| HeadlessError::new(EXIT_EXPORT, err.to_string()))
}

pub struct HeadlessRequest {
    pub store: Store,
    pub profile: Profile,
    pub limits: CrawlLimits,
    pub export_dir: PathBuf,
    pub lock_path: PathBuf,
    pub resume: bool,
}

pub async fn run_audit(request: HeadlessRequest) -> HeadlessReport {
    run_audit_inner(request, None).await
}

#[cfg(test)]
pub(crate) async fn run_audit_with_transport(
    request: HeadlessRequest,
    transport: SignedTransport,
) -> HeadlessReport {
    run_audit_inner(request, Some(transport)).await
}

async fn run_audit_inner(
    request: HeadlessRequest,
    transport: Option<SignedTransport>,
) -> HeadlessReport {
    match drive_audit(request, transport).await {
        Ok(report) => report,
        Err(err) => report_from_error(err),
    }
}

async fn drive_audit(
    request: HeadlessRequest,
    transport: Option<SignedTransport>,
) -> Result<HeadlessReport, HeadlessError> {
    let _lock = RunLock::acquire(&request.lock_path)?;
    let auth = if transport.is_some() {
        WebBotAuth::new("sig1=:test:", "sig1=()", "https://shopify.com")
            .map_err(|err| HeadlessError::new(EXIT_AUTH, err.to_string()))?
    } else {
        resolve_runtime_auth(&request.profile)?
    };
    let mut engine = match transport {
        Some(transport) => Engine::spawn_with_transport(
            EngineConfig {
                store: request.store.clone(),
                auth,
                limits: request.limits.clone(),
            },
            transport,
        ),
        None => Engine::spawn(EngineConfig {
            store: request.store.clone(),
            auth,
            limits: request.limits,
        }),
    };
    let command = if request.resume {
        let run_id = request
            .store
            .list_runs()
            .map_err(|err| HeadlessError::new(EXIT_CRAWL, err.to_string()))?
            .into_iter()
            .find(|run| {
                matches!(
                    run.status,
                    crate::store::RunStatus::Running | crate::store::RunStatus::Incomplete
                )
            })
            .map(|run| run.id)
            .ok_or_else(|| {
                HeadlessError::new(EXIT_CRAWL, "No incomplete run to resume in this store")
            })?;
        CrawlCommand::Resume { run_id }
    } else {
        CrawlCommand::Start {
            profile: Box::new(request.profile),
        }
    };
    engine
        .commands()
        .send(command)
        .await
        .map_err(|_| HeadlessError::new(EXIT_CRAWL, "Command queue is full or closed"))?;

    let snapshot = wait_for_terminal(&mut engine).await?;
    let run_id = snapshot
        .run_id
        .ok_or_else(|| HeadlessError::new(EXIT_CRAWL, "Engine finished without a run id"))?;
    if snapshot.status == SessionStatus::Failed {
        return Err(HeadlessError::new(
            EXIT_CRAWL,
            format!("Run {run_id} failed"),
        ));
    }
    let written = persist_and_export(&request.store, run_id, &request.export_dir)?;
    let status = match snapshot.status {
        SessionStatus::Completed => "completed",
        SessionStatus::Incomplete => "incomplete",
        SessionStatus::Failed => "failed",
        SessionStatus::Running => "running",
        SessionStatus::Idle => "idle",
    };
    Ok(HeadlessReport {
        ok: snapshot.status != SessionStatus::Failed,
        exit_code: EXIT_OK,
        kind: status.into(),
        run_id: Some(run_id),
        status: Some(status.into()),
        csv_path: Some(written.csv_path.display().to_string()),
        json_path: Some(written.json_path.display().to_string()),
        overlap: false,
        email: false,
        auth_resolved: true,
        message: format!("Run {run_id} {status}; wrote CSV+JSON without credentials"),
    })
}

fn diagnostic_error(diagnostic: crate::engine::Diagnostic) -> Option<HeadlessError> {
    match diagnostic.kind {
        DiagnosticKind::Auth => Some(HeadlessError::new(EXIT_AUTH, diagnostic.message)),
        DiagnosticKind::Command if diagnostic.message.contains("already in progress") => {
            Some(HeadlessError::new(EXIT_OVERLAP, diagnostic.message))
        }
        DiagnosticKind::Command | DiagnosticKind::Persist | DiagnosticKind::Transport => {
            Some(HeadlessError::new(EXIT_CRAWL, diagnostic.message))
        }
    }
}

async fn wait_for_terminal(
    engine: &mut Engine,
) -> Result<crate::engine::ProgressSnapshot, HeadlessError> {
    let mut progress = engine.progress();
    loop {
        let snapshot = progress.borrow().clone();
        match snapshot.status {
            SessionStatus::Completed | SessionStatus::Incomplete | SessionStatus::Failed => {
                return Ok(snapshot);
            }
            SessionStatus::Idle | SessionStatus::Running => {}
        }
        tokio::select! {
            event = engine.events().recv() => {
                match event {
                    Some(CrawlEvent::Diagnostic(diagnostic)) => {
                        if snapshot.run_id.is_none()
                            && let Some(err) = diagnostic_error(diagnostic)
                        {
                            return Err(err);
                        }
                    }
                    Some(CrawlEvent::Status(status))
                        if matches!(
                            status.status,
                            SessionStatus::Completed
                                | SessionStatus::Incomplete
                                | SessionStatus::Failed
                        ) =>
                    {
                        return Ok(progress.borrow().clone());
                    }
                    None => {
                        return Err(HeadlessError::new(
                            EXIT_CRAWL,
                            "Engine stopped without a terminal status",
                        ));
                    }
                    _ => {}
                }
            }
            changed = progress.changed() => {
                if changed.is_err() {
                    return Err(HeadlessError::new(
                        EXIT_CRAWL,
                        "Engine stopped without a terminal status",
                    ));
                }
            }
        }
    }
}

fn report_from_error(err: HeadlessError) -> HeadlessReport {
    HeadlessReport {
        ok: false,
        exit_code: err.exit_code,
        kind: kind_for(err.exit_code).into(),
        run_id: None,
        status: None,
        csv_path: None,
        json_path: None,
        overlap: err.exit_code == EXIT_OVERLAP,
        email: false,
        auth_resolved: err.exit_code != EXIT_AUTH,
        message: err.message,
    }
}

fn kind_for(code: i32) -> &'static str {
    match code {
        EXIT_OK => "completed",
        EXIT_USAGE => "usage",
        EXIT_AUTH => "auth",
        EXIT_OVERLAP => "overlap",
        EXIT_CRAWL => "crawl",
        EXIT_EXPORT => "export",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp(name: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "crawlytic-headless-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn example_profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    #[test]
    fn overlapping_lock_is_prevented_not_queued() {
        let path = temp("lock");
        let first = RunLock::acquire(&path).unwrap();
        let err = RunLock::acquire(&path).unwrap_err();
        assert_eq!(err.exit_code, EXIT_OVERLAP);
        assert!(
            err.message().to_ascii_lowercase().contains("overlap")
                || err.message().contains("in progress"),
            "{}",
            err.message()
        );
        drop(first);
        let second = RunLock::acquire(&path).unwrap();
        drop(second);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_and_missing_secrets_are_reported_without_echo() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let profile = example_profile();
        let previous = [
            take("CRAWL_SIGNATURE"),
            take("CRAWL_SIGNATURE_INPUT"),
            take("CRAWL_SIGNATURE_AGENT"),
        ];
        let missing = match resolve_runtime_auth(&profile) {
            Err(err) => err,
            Ok(_) => panic!("expected missing credentials"),
        };
        assert_eq!(missing.exit_code, EXIT_AUTH);
        assert!(
            missing.message().contains("CRAWL_SIGNATURE"),
            "{}",
            missing.message()
        );
        assert!(
            missing.message().contains(CREDENTIAL_REPLACEMENT_PLAN),
            "{}",
            missing.message()
        );

        unsafe {
            std::env::set_var("CRAWL_SIGNATURE", "sig1=:super-secret-token:");
            std::env::set_var("CRAWL_SIGNATURE_INPUT", "sig1=();created=1;expires=1");
            std::env::set_var("CRAWL_SIGNATURE_AGENT", "https://shopify.com");
        }
        let expired = match resolve_runtime_auth(&profile) {
            Err(err) => err,
            Ok(_) => panic!("expected expired credentials"),
        };
        restore("CRAWL_SIGNATURE", previous[0].clone());
        restore("CRAWL_SIGNATURE_INPUT", previous[1].clone());
        restore("CRAWL_SIGNATURE_AGENT", previous[2].clone());
        assert_eq!(expired.exit_code, EXIT_AUTH);
        assert!(
            expired.message().contains("expired"),
            "{}",
            expired.message()
        );
        assert!(
            !expired.message().contains("super-secret-token"),
            "{}",
            expired.message()
        );
        assert!(
            expired.message().contains(CREDENTIAL_REPLACEMENT_PLAN),
            "{}",
            expired.message()
        );
    }

    #[test]
    fn persist_and_export_matches_ratatui_schema() {
        let store = Store::open_in_memory().unwrap();
        let profile = example_profile();
        let run_id = store.begin_run(&profile).unwrap();
        store
            .upsert_url(
                run_id,
                &crate::crawl::UrlRecord {
                    original: "https://www.tiendacables.com/".into(),
                    identity: Some(crate::scope::FetchIdentity::from_url(
                        &url::Url::parse("https://www.tiendacables.com/").unwrap(),
                    )),
                    state: crate::crawl::UrlState::Fetched,
                    reason: "Fetched".into(),
                    click_depth: Some(0),
                    via_website: true,
                    via_sitemap: false,
                },
            )
            .unwrap();
        store.flush().unwrap();
        store
            .finish_run(
                run_id,
                crate::store::RunStatus::Completed,
                true,
                false,
                None,
            )
            .unwrap();
        let report =
            evaluate_stored(&store, run_id, &AuditConfig::default(), &audit_registry()).unwrap();
        let urls = store.load_run(run_id).unwrap().urls;
        let expected = export_document(&report, &urls).unwrap();
        let dir = temp("export");
        std::fs::create_dir_all(&dir).unwrap();
        let written = persist_and_export(&store, run_id, &dir).unwrap();
        let json = std::fs::read_to_string(&written.json_path).unwrap();
        assert!(json.contains(&format!("\"run_id\": {run_id}")));
        assert!(json.contains("\"findings\""));
        assert!(json.contains("\"coverage\""));
        assert!(!json.to_ascii_lowercase().contains("sig1="), "{json}");
        assert_eq!(expected.run_id, run_id);
        assert!(
            written
                .csv_path
                .ends_with(format!("crawlytic-run-{run_id}-audit.csv"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn machine_readable_report_never_enables_email() {
        let report = report_from_error(HeadlessError::new(
            EXIT_OVERLAP,
            "A run is already in progress",
        ));
        assert!(!report.email);
        assert!(report.overlap);
        assert_eq!(report.exit_code, EXIT_OVERLAP);
        let json = report.to_json().unwrap();
        assert!(json.contains("\"email\": false"));
        assert!(json.contains("\"overlap\": true"));
    }

    fn take(key: &str) -> Option<String> {
        let value = std::env::var(key).ok();
        unsafe { std::env::remove_var(key) };
        value
    }

    fn restore(key: &str, value: Option<String>) {
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
