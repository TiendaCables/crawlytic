mod app;
mod cli;
mod keys;
mod model;
mod render;
mod session;

pub use app::{Action, App, Overlay, Screen};
pub use keys::Key;
pub use render::{render, render_plain};
pub use session::Session;

use crate::cli::Invocation;
use crossterm::event::{self, Event, KeyEventKind};
use std::path::PathBuf;

pub fn run() -> anyhow::Result<()> {
    crawlytic_core::load_dotenv()?;
    let cwd = std::env::current_dir()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let store_env = std::env::var("CRAWLYTIC_STORE").ok();
    match cli::parse_args(&args, &cwd, store_env.as_deref()) {
        Ok(Invocation::Tui { selected }) => run_tui(&cwd, selected, store_env),
        Ok(Invocation::Help) => {
            print!("{}", cli::help_text());
            Ok(())
        }
        Ok(Invocation::Audit(audit)) => {
            let report = cli::run_audit_command(audit)?;
            println!("{}", report.to_json()?);
            if report.exit_code != 0 {
                std::process::exit(report.exit_code);
            }
            Ok(())
        }
        Ok(Invocation::Coverage) => {
            print!("{}", cli::render_coverage()?);
            Ok(())
        }
        Ok(Invocation::Backup(backup)) => {
            println!("{}", cli::run_backup(backup)?);
            Ok(())
        }
        Ok(Invocation::RetentionPrint(print)) => {
            println!("{}", cli::render_retention(print)?);
            Ok(())
        }
        Ok(Invocation::RetentionSet(set)) => {
            println!("{}", cli::run_retention_set(set)?);
            Ok(())
        }
        Ok(Invocation::SchedulePrint(print)) => {
            println!("{}", cli::render_schedule(print)?);
            Ok(())
        }
        Err(message) => {
            let report = cli::usage_report(message);
            println!("{}", report.to_json()?);
            std::process::exit(report.exit_code);
        }
    }
}

fn run_tui(
    cwd: &std::path::Path,
    selected: Option<String>,
    store_env: Option<String>,
) -> anyhow::Result<()> {
    let store_path = store_env
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.join("crawlytic.sqlite"));
    let mut app = App::boot(cwd, selected)?;
    let mut session = Session::open(&store_path)?;
    session.hydrate(&mut app)?;
    ratatui::run(|terminal| -> anyhow::Result<()> {
        loop {
            session.pump(&mut app)?;
            terminal.draw(|frame| render(frame, &app))?;
            if event::poll(session::poll_timeout())?
                && let Event::Key(key) = event::read()?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(key) = Key::from_crossterm(key) {
                    let action = app.handle(key);
                    session.dispatch(action, &mut app)?;
                }
                if app.should_quit {
                    break;
                }
            }
        }
        Ok(())
    })
}
