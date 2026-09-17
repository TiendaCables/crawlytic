mod app;
mod keys;
mod model;
mod render;
mod session;

pub use app::{Action, App, Overlay, Screen};
pub use keys::Key;
pub use render::{render, render_plain};
pub use session::Session;

use crossterm::event::{self, Event, KeyEventKind};
use std::path::PathBuf;

pub fn run() -> anyhow::Result<()> {
    crawlytic_core::load_dotenv()?;
    let cwd = std::env::current_dir()?;
    let selected = std::env::args().nth(1);
    let store_path = std::env::var("CRAWLYTIC_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| cwd.join("crawlytic.sqlite"));
    let mut app = App::boot(&cwd, selected)?;
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
