use anyhow::Result;
use crawlytic_core::{Profile, WebBotAuth, load_dotenv, preflight};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Paragraph, Wrap},
};
use std::{sync::mpsc, time::Duration};

fn main() -> Result<()> {
    load_dotenv()?;
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "profile.example.toml".into());
    let profile = Profile::load(&std::fs::read_to_string(path)?)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let (tx, rx) = mpsc::channel::<String>();
    let mut task = None;
    let mut message = "Ready. Press p to send one signed request. No crawl has run.".to_owned();
    let result = ratatui::run(|terminal| -> std::io::Result<()> {
        loop {
            if let Ok(update) = rx.try_recv() {
                message = update;
                task = None;
            }
            terminal.draw(|f| {
                let [header, config, auth, footer] = Layout::vertical([
                    Constraint::Length(3), Constraint::Min(8), Constraint::Min(5), Constraint::Length(3)
                ]).areas(f.area());
                f.render_widget(Paragraph::new("Crawlytic").style(Style::default().fg(Color::Cyan)).block(Block::bordered()), header);
                f.render_widget(Paragraph::new(format!("{}\nCurrent capability: connection preflight only.", profile.summary())).wrap(Wrap { trim: false }).block(Block::bordered().title(" Crawl profile ")), config);
                f.render_widget(Paragraph::new(format!("Web Bot Auth: required\nCredentials: CRAWL_SIGNATURE, CRAWL_SIGNATURE_INPUT, CRAWL_SIGNATURE_AGENT (.env or environment)\n\n{message}")).wrap(Wrap { trim: false }).block(Block::bordered().title(" Shopify access ")), auth);
                f.render_widget(Paragraph::new("p  Test connection     q / Esc / Ctrl-C  Quit").block(Block::bordered()), footer);
            })?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break;
                    }
                    KeyCode::Char('p') if task.is_none() => match WebBotAuth::from_env() {
                        Err(e) => message = e.to_string(),
                        Ok(auth) => {
                            message = "Checking signed storefront access…".into();
                            let p = profile.clone();
                            let tx = tx.clone();
                            task = Some(runtime.spawn(async move {
                                    let text = match preflight(&p, &auth).await {
                                        Ok(r) => format!("HTTP {} | {} | {} bytes sampled.\nHTML reachable with headers attached. This does not prove signature acceptance or full crawl access.", r.status, r.content_type, r.bytes_sampled),
                                        Err(e) => e.to_string(),
                                    };
                                    let _ = tx.send(text);
                                }));
                        }
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    });
    if let Some(task) = task {
        task.abort();
    }
    result?;
    Ok(())
}
