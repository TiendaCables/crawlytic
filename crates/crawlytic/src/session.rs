use crate::app::{Action, App, AuthField};
use crawlytic_core::{
    AuditConfig, CrawlCommand, CrawlLimits, Engine, EngineConfig, SessionStatus, Store, WebBotAuth,
    audit_registry, evaluate_stored, export_document, write_export,
};
use std::path::Path;
use std::time::Duration;
use tokio::sync::watch;

pub struct Session {
    runtime: tokio::runtime::Runtime,
    store: Store,
    engine: Option<LiveEngine>,
}

struct LiveEngine {
    engine: Engine,
    progress: watch::Receiver<crawlytic_core::ProgressSnapshot>,
}

impl Session {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let _guard = runtime.enter();
        let store = Store::open(path)?;
        Ok(Self {
            runtime,
            store,
            engine: None,
        })
    }

    pub fn hydrate(&self, app: &mut App) -> anyhow::Result<()> {
        app.set_runs(self.store.list_runs()?);
        Ok(())
    }

    pub fn dispatch(&mut self, action: Action, app: &mut App) -> anyhow::Result<()> {
        match action {
            Action::None | Action::Quit => {}
            Action::Start => self.start(app)?,
            Action::Cancel => self.send(app, CrawlCommand::Cancel)?,
            Action::Resume => {
                if let Some(run_id) = app.last_run_id {
                    self.send(app, CrawlCommand::Resume { run_id })?;
                } else {
                    app.message = "No run to resume.".into();
                }
            }
            Action::Evaluate => self.evaluate(app)?,
            Action::SaveProfile => self.save_profile(app)?,
            Action::ApplyAuth => self.apply_auth(app)?,
            Action::Probe => {
                app.message =
                    "Use s to start a crawl. Connection preflight is no longer a separate live result."
                        .into();
            }
            Action::Export => self.export(app)?,
        }
        Ok(())
    }

    pub fn pump(&mut self, app: &mut App) -> anyhow::Result<()> {
        let completed = if let Some(live) = &mut self.engine {
            let progress = live.progress.borrow().clone();
            let became_idle = matches!(
                progress.status,
                SessionStatus::Completed | SessionStatus::Incomplete | SessionStatus::Failed
            ) && app.progress.status == SessionStatus::Running;
            app.apply_progress(progress);
            while let Ok(event) = live.engine.events().try_recv() {
                app.apply_event(event);
            }
            became_idle
        } else {
            false
        };
        if completed && let Some(run_id) = app.last_run_id {
            if let Err(err) = self.load_run(app, run_id) {
                app.message = err.to_string();
            } else if let Err(err) = self.evaluate(app) {
                app.message = err.to_string();
            }
        }
        Ok(())
    }

    fn start(&mut self, app: &mut App) -> anyhow::Result<()> {
        self.ensure_engine(app)?;
        self.send(
            app,
            CrawlCommand::Start {
                profile: Box::new(app.profile.clone()),
            },
        )
    }

    fn send(&mut self, app: &mut App, command: CrawlCommand) -> anyhow::Result<()> {
        self.ensure_engine(app)?;
        let Some(live) = &self.engine else {
            return Ok(());
        };
        match live.engine.commands().try_send(command) {
            Ok(()) => {
                app.message = "Command sent.".into();
            }
            Err(_) => app.message = "Command queue is full or closed.".into(),
        }
        Ok(())
    }

    fn ensure_engine(&mut self, app: &mut App) -> anyhow::Result<()> {
        if self.engine.is_some() {
            return Ok(());
        }
        let auth = match WebBotAuth::from_profile(&app.profile) {
            Ok(auth) => auth,
            Err(err) => {
                app.message = err.to_string();
                return Ok(());
            }
        };
        let _guard = self.runtime.enter();
        let engine = Engine::spawn(EngineConfig {
            store: self.store.clone(),
            auth,
            limits: CrawlLimits::from_profile(&app.profile),
        });
        let progress = engine.progress();
        self.engine = Some(LiveEngine { engine, progress });
        Ok(())
    }

    fn evaluate(&mut self, app: &mut App) -> anyhow::Result<()> {
        let Some(run_id) = app.last_run_id else {
            app.message = "No run to evaluate.".into();
            return Ok(());
        };
        let report = evaluate_stored(
            &self.store,
            run_id,
            &AuditConfig::default(),
            &audit_registry(),
        )?;
        let loaded = self.store.load_run(run_id)?;
        app.set_urls(loaded.urls, loaded.links);
        app.set_report(report);
        app.set_runs(self.store.list_runs()?);
        Ok(())
    }

    fn load_run(&mut self, app: &mut App, run_id: i64) -> anyhow::Result<()> {
        let loaded = self.store.load_run(run_id)?;
        app.set_urls(loaded.urls, loaded.links);
        app.set_runs(self.store.list_runs()?);
        Ok(())
    }

    fn save_profile(&self, app: &mut App) -> anyhow::Result<()> {
        let Some(file) = app.profiles.get(app.profile_index) else {
            app.message = "No profile file selected.".into();
            return Ok(());
        };
        let text = app.profile.to_toml()?;
        std::fs::write(&file.path, text)?;
        app.message = format!("Wrote {}", file.name);
        Ok(())
    }

    fn export(&self, app: &mut App) -> anyhow::Result<()> {
        let Some(report) = app.last_report.as_ref() else {
            app.message = "No run to export. Evaluate stored observations first.".into();
            return Ok(());
        };
        let document = export_document(report, &app.urls)?;
        let dir = std::env::current_dir()?;
        let written = write_export(&dir, &document)?;
        app.message = format!(
            "Wrote {} and {}",
            written.csv_path.display(),
            written.json_path.display()
        );
        Ok(())
    }

    fn apply_auth(&mut self, app: &mut App) -> anyhow::Result<()> {
        let signature = resolve_secret(app, AuthField::Signature)?;
        let input = resolve_secret(app, AuthField::SignatureInput)?;
        let agent = resolve_secret(app, AuthField::SignatureAgent)?;
        match WebBotAuth::new(&signature, &input, &agent) {
            Ok(_) => {
                set_env(app.auth_env(AuthField::Signature), &signature);
                set_env(app.auth_env(AuthField::SignatureInput), &input);
                set_env(app.auth_env(AuthField::SignatureAgent), &agent);
                app.auth_signature.clear();
                app.auth_input.clear();
                app.auth_agent.clear();
                self.engine = None;
                app.message =
                    "Credentials applied to the process environment (not stored in the profile)."
                        .into();
            }
            Err(err) => {
                let text = err.to_string();
                if text.contains(&signature) || text.contains(&input) || text.contains(&agent) {
                    app.message = "Invalid Web Bot Auth credentials.".into();
                } else {
                    app.message = text;
                }
            }
        }
        Ok(())
    }
}

fn resolve_secret(app: &App, field: AuthField) -> anyhow::Result<String> {
    if let Some(value) = app.auth_value(field) {
        return Ok(value.to_string());
    }
    let key = app.auth_env(field);
    std::env::var(key)
        .map_err(|_| anyhow::anyhow!("Missing {key}. Enter a masked value, then press a."))
}

fn set_env(key: &str, value: &str) {
    unsafe { std::env::set_var(key, value) };
}

pub fn poll_timeout() -> Duration {
    Duration::from_millis(80)
}
