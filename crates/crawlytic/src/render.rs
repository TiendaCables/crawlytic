use crate::app::{
    App, AuthField, FindingsCursor, Overlay, ProfileField, Screen, help_text, url_line,
};
use crate::model::{AuthPresence, inlinks_for, looks_like_placeholder_score, mask_secret};
use crawlytic_core::RuleState;
use ratatui::backend::TestBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width == 0 || area.height == 0 {
        return;
    }
    let header_h = 1;
    let footer_h = if area.height > 2 { 1 } else { 0 };
    let tabs_h = if area.height > 3 { 1 } else { 0 };
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Length(tabs_h),
        Constraint::Min(0),
        Constraint::Length(footer_h),
    ])
    .areas(area);
    render_header(frame, header, app);
    if tabs.height > 0 {
        render_tabs(frame, tabs, app);
    }
    if body.height > 0 {
        match app.screen {
            Screen::Profiles => render_profiles(frame, body, app),
            Screen::Auth => render_auth(frame, body, app),
            Screen::Run => render_run(frame, body, app),
            Screen::Urls => render_urls(frame, body, app),
            Screen::Findings => render_findings(frame, body, app),
        }
    }
    if footer.height > 0 {
        render_footer(frame, footer, app);
    }
    render_overlay(frame, area, app);
}

pub fn render_plain(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width.max(1), height.max(1));
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| render(frame, app)).expect("draw");
    buffer_plain(terminal.backend().buffer())
}

fn buffer_plain(buffer: &ratatui::buffer::Buffer) -> String {
    let mut lines = Vec::new();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        for x in 0..buffer.area.width {
            line.push_str(buffer[(x, y)].symbol());
        }
        lines.push(line.trim_end().to_string());
    }
    lines.join("\n")
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let status = format!("{:?}", app.progress.status).to_ascii_lowercase();
    let run = app
        .progress
        .run_id
        .map(|id| format!(" run {id}"))
        .unwrap_or_default();
    let title = format!("Crawlytic  {status}{run}");
    frame.render_widget(
        Paragraph::new(title).style(Style::default().fg(Color::Cyan)),
        area,
    );
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let labels: Vec<Span> = Screen::all()
        .into_iter()
        .map(|screen| {
            let label = match screen {
                Screen::Profiles => "1 Profiles",
                Screen::Auth => "2 Auth",
                Screen::Run => "3 Run",
                Screen::Urls => "4 URLs",
                Screen::Findings => "5 Findings",
            };
            if screen == app.screen {
                Span::styled(
                    format!(" {label} "),
                    Style::default().add_modifier(Modifier::REVERSED),
                )
            } else {
                Span::raw(format!(" {label} "))
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(Line::from(labels)), area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let filter = if app.filter.is_empty() {
        String::new()
    } else {
        format!("  filter: {}", app.filter)
    };
    let text = if matches!(app.overlay, Overlay::Filter) {
        format!("Filter: {}_   Esc clear  Enter keep", app.filter)
    } else {
        format!(
            "1-5 screens  / filter  s start  x cancel  r resume  o export  ? help  q quit{filter}"
        )
    };
    frame.render_widget(Paragraph::new(text), area);
}

fn render_profiles(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if app.profiles.is_empty() {
        lines.push(Line::from("No profile*.toml files in this directory."));
        lines.push(Line::from(app.profile.summary()));
    } else {
        for (index, file) in app.profiles.iter().enumerate() {
            let mark = if index == app.profile_index { ">" } else { " " };
            let extra = file.error.as_deref().unwrap_or_else(|| {
                file.profile
                    .as_ref()
                    .map(|profile| profile.start_url.as_str())
                    .unwrap_or("")
            });
            lines.push(Line::from(format!("{mark} {}  {extra}", file.name)));
        }
    }
    lines.push(Line::from(""));
    for (index, field) in ProfileField::all().into_iter().enumerate() {
        let mark = if index == app.profile_field { ">" } else { " " };
        let value = match field {
            ProfileField::StartUrl => app.profile.start_url.to_string(),
            ProfileField::MaxPages => app.profile.max_pages.to_string(),
            ProfileField::UserAgent => app.profile.user_agent.clone(),
            ProfileField::DiscoveryMode => format!("{:?}", app.profile.discovery_mode),
        };
        lines.push(Line::from(format!(
            "{mark} {} = {value}",
            field_label(field)
        )));
    }
    lines.push(Line::from(
        "e edit field   w write file   Enter select file",
    ));
    lines.push(Line::from(app.profile.summary()));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Profiles ")),
        area,
    );
}

fn field_label(field: ProfileField) -> &'static str {
    match field {
        ProfileField::StartUrl => "start_url",
        ProfileField::MaxPages => "max_pages",
        ProfileField::UserAgent => "user_agent",
        ProfileField::DiscoveryMode => "discovery_mode",
    }
}

fn render_auth(frame: &mut Frame, area: Rect, app: &App) {
    let rows = [
        AuthField::Signature,
        AuthField::SignatureInput,
        AuthField::SignatureAgent,
    ];
    let mut lines = vec![Line::from(
        "Web Bot Auth values stay in the process environment. They are never shown unmasked.",
    )];
    for (index, field) in rows.into_iter().enumerate() {
        let mark = if index == app.profile_field { ">" } else { " " };
        let presence = match app.auth_presence(field) {
            AuthPresence::Set => "set ••••••••",
            AuthPresence::Missing => "missing",
        };
        let pending = app
            .auth_value(field)
            .map(|_| format!("  pending {}", mask_secret("xxxxxxxx")))
            .unwrap_or_default();
        lines.push(Line::from(format!(
            "{mark} {}  {presence}{pending}",
            app.auth_env(field)
        )));
    }
    lines.push(Line::from(
        "Enter  masked edit    a  apply to environment    Secrets are not written to profiles or SQLite.",
    ));
    lines.push(Line::from(operator_message(app)));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Auth ")),
        area,
    );
}

fn render_run(frame: &mut Frame, area: Rect, app: &App) {
    let counters = app.progress.counters;
    let mut lines = vec![
        Line::from(format!("Status: {:?}", app.progress.status)),
        Line::from(format!(
            "User-Agent: {} (HTTP User-Agent, not a viewport)",
            app.progress.displayed_user_agent.as_str()
        )),
        Line::from(format!(
            "Counters: discovered={} fetched={} excluded={} blocked={} failed={} pending={} in-flight={}",
            counters.discovered(),
            counters.fetched,
            counters.excluded,
            counters.blocked,
            counters.failed,
            counters.pending,
            counters.in_flight
        )),
        Line::from(format!(
            "Dropped events: {} (slow UI consumers drop discrete events)",
            app.progress.dropped_events
        )),
        Line::from(format!(
            "Live findings {}. Incomplete {}. Unsupported {}. No placeholder scores.",
            app.investigation.finding_count(),
            app.investigation.incomplete.len(),
            app.investigation.unsupported.len()
        )),
        Line::from("s start   x cancel   r resume   Enter evaluate stored observations"),
        Line::from("Runs:"),
    ];
    if app.runs.is_empty() {
        lines.push(Line::from("  (none)"));
    } else {
        for (index, run) in app.runs.iter().enumerate() {
            let mark = if index == app.run_index { ">" } else { " " };
            lines.push(Line::from(format!(
                "{mark} #{} {:?} {} urls={} {}",
                run.id,
                run.status,
                run.start_url,
                run.url_count,
                run.error.as_deref().unwrap_or("")
            )));
        }
    }
    if !app.diagnostics.is_empty() {
        lines.push(Line::from("Diagnostics:"));
        for item in app.diagnostics.iter().rev().take(5) {
            lines.push(Line::from(format!("  {item}")));
        }
    }
    lines.push(Line::from(operator_message(app)));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Run ")),
        area,
    );
}

fn render_urls(frame: &mut Frame, area: Rect, app: &App) {
    let [list, detail] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area);
    let urls = app.filtered_urls();
    let mut lines = Vec::new();
    if urls.is_empty() {
        lines.push(Line::from(
            "No URLs yet. Start a crawl to fill the inventory.",
        ));
    } else {
        let start = app
            .url_index
            .saturating_sub(list.height.saturating_sub(2) as usize / 2);
        for (index, url) in urls.iter().enumerate().skip(start) {
            let mark = if index == app.url_index { ">" } else { " " };
            lines.push(Line::from(format!("{mark} {}", url_line(url))));
            if lines.len() as u16 >= list.height.saturating_sub(2) {
                break;
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" URL inventory ")),
        list,
    );
    let mut detail_lines = Vec::new();
    if let Some(url) = app.selected_url() {
        detail_lines.push(Line::from(url.original.as_str()));
        detail_lines.push(Line::from(format!(
            "state={} reason={}",
            crate::app::url_state_label(url.state),
            url.reason
        )));
        if let Some(identity) = &url.identity {
            detail_lines.push(Line::from(format!("identity={}", identity.as_str())));
        }
        let inlinks = inlinks_for(&app.links, &url.original);
        if inlinks.is_empty() {
            detail_lines.push(Line::from("inlinks: none observed"));
        } else {
            detail_lines.push(Line::from("inlinks:"));
            for link in inlinks {
                detail_lines.push(Line::from(format!(
                    "  {} href={}",
                    link.from_identity.as_str(),
                    link.href
                )));
            }
        }
    } else {
        detail_lines.push(Line::from("Select a URL to inspect evidence and inlinks."));
    }
    frame.render_widget(
        Paragraph::new(detail_lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Detail ")),
        detail,
    );
}

fn render_findings(frame: &mut Frame, area: Rect, app: &App) {
    let [list, detail] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area);
    let mut lines = Vec::new();
    if app.investigation.finding_count() == 0
        && app.investigation.incomplete.is_empty()
        && app.investigation.unsupported.is_empty()
    {
        lines.push(Line::from(
            "No live findings. Incomplete and unsupported catalogue checks appear after evaluation.",
        ));
        lines.push(Line::from(
            "Nothing here is a placeholder score or a fabricated live result.",
        ));
    }
    for (severity, rules) in &app.investigation.by_severity {
        lines.push(Line::from(severity.as_str().to_string()));
        for (rule_idx, section) in rules.iter().enumerate() {
            for (finding_idx, row) in section.findings.iter().enumerate() {
                let cursor = FindingsCursor::Finding {
                    severity: severity_index(app, *severity),
                    rule: rule_idx,
                    finding: finding_idx,
                };
                if !app.visible_finding_cursors().contains(&cursor) {
                    continue;
                }
                let mark = if app.findings_cursor == Some(cursor) {
                    ">"
                } else {
                    " "
                };
                lines.push(Line::from(format!(
                    "{mark} {}  {}",
                    section.label, row.entity_key
                )));
            }
        }
    }
    if !app.investigation.incomplete.is_empty() {
        lines.push(Line::from("incomplete"));
        for (index, section) in app.investigation.incomplete.iter().enumerate() {
            if !app
                .visible_finding_cursors()
                .contains(&FindingsCursor::Incomplete(index))
            {
                continue;
            }
            let mark = if app.findings_cursor == Some(FindingsCursor::Incomplete(index)) {
                ">"
            } else {
                " "
            };
            lines.push(Line::from(format!("{mark} {}", section.label)));
        }
    }
    if !app.investigation.unsupported.is_empty() {
        lines.push(Line::from("unsupported"));
        for (index, section) in app.investigation.unsupported.iter().enumerate() {
            if !app
                .visible_finding_cursors()
                .contains(&FindingsCursor::Unsupported(index))
            {
                continue;
            }
            let mark = if app.findings_cursor == Some(FindingsCursor::Unsupported(index)) {
                ">"
            } else {
                " "
            };
            lines.push(Line::from(format!("{mark} {}", section.label)));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" Findings ")),
        list,
    );
    frame.render_widget(
        Paragraph::new(finding_detail_lines(app))
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Detail ")),
        detail,
    );
}

fn severity_index(app: &App, severity: crawlytic_core::Severity) -> usize {
    app.investigation
        .by_severity
        .iter()
        .position(|(item, _)| *item == severity)
        .unwrap_or(0)
}

fn finding_detail_lines(app: &App) -> Vec<Line<'static>> {
    if let Some(row) = app.selected_finding() {
        let mut lines = vec![
            Line::from(format!("Rule: {} ({})", row.rule_id, row.severity.as_str())),
            Line::from(format!("Entity: {}", row.entity_key)),
            Line::from(format!("Fact: {}", row.fact)),
            Line::from(format!("Recommendation: {}", row.recommendation)),
            Line::from("Evidence:"),
        ];
        for pointer in &row.evidence {
            lines.push(Line::from(format!(
                "  {} @ {} : {}",
                pointer.field, pointer.observation_identity, pointer.excerpt
            )));
        }
        let inlinks = inlinks_for(&app.links, &row.entity_key);
        if inlinks.is_empty() {
            lines.push(Line::from("inlinks: none observed"));
        } else {
            lines.push(Line::from("inlinks:"));
            for link in inlinks {
                lines.push(Line::from(format!(
                    "  {} href={}",
                    link.from_identity.as_str(),
                    link.href
                )));
            }
        }
        return lines;
    }
    if let Some(section) = app.selected_section() {
        let state = match section.state {
            RuleState::Incomplete => "incomplete",
            RuleState::Unsupported => "unsupported",
            other => other.as_str(),
        };
        return vec![
            Line::from(format!("Check: {} ({state})", section.label)),
            Line::from(format!("Rule: {}", section.rule_id)),
            Line::from("No live findings for this check."),
            Line::from(
                "Missing evidence is incomplete; unregistered checks are unsupported, never passed.",
            ),
        ];
    }
    vec![
        Line::from("No live findings selected."),
        Line::from("Nothing here is a placeholder score or a fabricated live result."),
    ]
}

fn render_overlay(frame: &mut Frame, area: Rect, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => {
            let popup = centered(
                area,
                area.width.saturating_sub(4).max(10),
                area.height.saturating_sub(4).max(6),
            );
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(help_text())
                    .wrap(Wrap { trim: false })
                    .block(Block::bordered().title(" Help ")),
                popup,
            );
        }
        Overlay::Filter => {}
        Overlay::Edit { field, buffer } => {
            let popup = Rect {
                x: area.x,
                y: area.y.saturating_add(area.height.saturating_sub(3)),
                width: area.width,
                height: 3.min(area.height),
            };
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(format!("{}: {buffer}", field_label(*field)))
                    .block(Block::bordered().title(" Edit ")),
                popup,
            );
        }
        Overlay::AuthEdit { field, buffer } => {
            let popup = Rect {
                x: area.x,
                y: area.y.saturating_add(area.height.saturating_sub(3)),
                width: area.width,
                height: 3.min(area.height),
            };
            let label = match field {
                AuthField::Signature => "signature",
                AuthField::SignatureInput => "signature-input",
                AuthField::SignatureAgent => "signature-agent",
            };
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(format!("{label}: {}", buffer.masked()))
                    .block(Block::bordered().title(" Masked input ")),
                popup,
            );
        }
    }
}

fn operator_message(app: &App) -> &str {
    if looks_like_placeholder_score(&app.message) {
        "Live counters and findings only; placeholder scores are not shown."
    } else {
        app.message.as_str()
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}
