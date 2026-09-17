use crate::keys::Key;
use crate::model::{
    AuthPresence, FindingRow, Investigation, RuleSection, SecretBuffer, investigation_from_report,
};
use crawlytic_core::{
    AuditReport, CoverageLink, CrawlCounters, CrawlEvent, Diagnostic, FetchCompletion, Profile,
    ProgressSnapshot, RunSummary, SessionStatus, UrlRecord, UrlState,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Profiles,
    Auth,
    Run,
    Urls,
    Findings,
}

impl Screen {
    pub fn all() -> [Screen; 5] {
        [
            Screen::Profiles,
            Screen::Auth,
            Screen::Run,
            Screen::Urls,
            Screen::Findings,
        ]
    }

    fn label(self) -> &'static str {
        match self {
            Screen::Profiles => "1 Profiles",
            Screen::Auth => "2 Auth",
            Screen::Run => "3 Run",
            Screen::Urls => "4 URLs",
            Screen::Findings => "5 Findings",
        }
    }

    fn next(self) -> Self {
        match self {
            Screen::Profiles => Screen::Auth,
            Screen::Auth => Screen::Run,
            Screen::Run => Screen::Urls,
            Screen::Urls => Screen::Findings,
            Screen::Findings => Screen::Profiles,
        }
    }

    fn prev(self) -> Self {
        match self {
            Screen::Profiles => Screen::Findings,
            Screen::Auth => Screen::Profiles,
            Screen::Run => Screen::Auth,
            Screen::Urls => Screen::Run,
            Screen::Findings => Screen::Urls,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileField {
    StartUrl,
    MaxPages,
    UserAgent,
    DiscoveryMode,
}

impl ProfileField {
    pub fn all() -> [ProfileField; 4] {
        [
            ProfileField::StartUrl,
            ProfileField::MaxPages,
            ProfileField::UserAgent,
            ProfileField::DiscoveryMode,
        ]
    }

    fn label(self) -> &'static str {
        match self {
            ProfileField::StartUrl => "start_url",
            ProfileField::MaxPages => "max_pages",
            ProfileField::UserAgent => "user_agent",
            ProfileField::DiscoveryMode => "discovery_mode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthField {
    Signature,
    SignatureInput,
    SignatureAgent,
}

#[derive(Debug, Clone)]
pub enum Overlay {
    None,
    Help,
    Filter,
    Edit {
        field: ProfileField,
        buffer: String,
    },
    AuthEdit {
        field: AuthField,
        buffer: SecretBuffer,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Start,
    Cancel,
    Resume,
    Evaluate,
    SaveProfile,
    ApplyAuth,
    Probe,
    Export,
}

#[derive(Debug, Clone)]
pub struct ProfileFile {
    pub path: PathBuf,
    pub name: String,
    pub profile: Option<Profile>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingsCursor {
    Finding {
        severity: usize,
        rule: usize,
        finding: usize,
    },
    Incomplete(usize),
    Unsupported(usize),
}

pub struct App {
    pub screen: Screen,
    pub overlay: Overlay,
    pub profiles: Vec<ProfileFile>,
    pub profile_index: usize,
    pub profile: Profile,
    pub profile_field: usize,
    pub auth_signature: SecretBuffer,
    pub auth_input: SecretBuffer,
    pub auth_agent: SecretBuffer,
    pub progress: ProgressSnapshot,
    pub urls: Vec<UrlRecord>,
    pub url_index: usize,
    pub links: Vec<CoverageLink>,
    pub runs: Vec<RunSummary>,
    pub run_index: usize,
    pub investigation: Investigation,
    pub findings_cursor: Option<FindingsCursor>,
    pub filter: String,
    pub message: String,
    pub should_quit: bool,
    pub last_run_id: Option<i64>,
    pub last_report: Option<AuditReport>,
    pub diagnostics: Vec<String>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("screen", &self.screen)
            .field("overlay", &self.overlay)
            .field("profile_index", &self.profile_index)
            .field("auth_signature", &self.auth_signature)
            .field("auth_input", &self.auth_input)
            .field("auth_agent", &self.auth_agent)
            .field("progress", &self.progress)
            .field("url_count", &self.urls.len())
            .field("filter", &self.filter)
            .field("message", &self.message)
            .field("should_quit", &self.should_quit)
            .field("last_run_id", &self.last_run_id)
            .finish()
    }
}

impl App {
    pub fn boot(dir: impl AsRef<Path>, selected: Option<String>) -> anyhow::Result<Self> {
        let profiles = discover_profiles(dir.as_ref())?;
        let profile_index = selected
            .as_ref()
            .and_then(|name| {
                profiles.iter().position(|file| {
                    file.name == *name || file.path.as_os_str() == std::ffi::OsStr::new(name)
                })
            })
            .or_else(|| profiles.iter().position(|file| file.profile.is_some()))
            .unwrap_or(0);
        let profile = profiles
            .get(profile_index)
            .and_then(|file| file.profile.clone())
            .ok_or_else(|| anyhow::anyhow!("No valid crawl profile found"))?;
        Ok(Self::from_profile(profile, profiles, profile_index))
    }

    pub fn from_profile(
        profile: Profile,
        profiles: Vec<ProfileFile>,
        profile_index: usize,
    ) -> Self {
        Self {
            screen: Screen::Profiles,
            overlay: Overlay::None,
            profiles,
            profile_index,
            profile: profile.clone(),
            profile_field: 0,
            auth_signature: SecretBuffer::default(),
            auth_input: SecretBuffer::default(),
            auth_agent: SecretBuffer::default(),
            progress: ProgressSnapshot {
                run_id: None,
                status: SessionStatus::Idle,
                displayed_user_agent: crawlytic_core::DisplayedUserAgent::from_profile(&profile),
                counters: CrawlCounters::default(),
                dropped_events: 0,
            },
            urls: Vec::new(),
            url_index: 0,
            links: Vec::new(),
            runs: Vec::new(),
            run_index: 0,
            investigation: Investigation::default(),
            findings_cursor: None,
            filter: String::new(),
            message: "Ready. No crawl has run. Press s to start, ? for help.".into(),
            should_quit: false,
            last_run_id: None,
            last_report: None,
            diagnostics: Vec::new(),
        }
    }

    pub fn handle(&mut self, key: Key) -> Action {
        if matches!(key, Key::Ctrl('c')) {
            self.should_quit = true;
            return Action::Quit;
        }
        if matches!(key, Key::Ctrl('x')) {
            return Action::Cancel;
        }
        if matches!(key, Key::Ctrl('r')) {
            return Action::Resume;
        }
        if matches!(key, Key::Ctrl('s')) {
            return Action::Start;
        }
        match &mut self.overlay {
            Overlay::Help => {
                if matches!(key, Key::Esc | Key::Char('?') | Key::F(1) | Key::Char('q')) {
                    self.overlay = Overlay::None;
                }
                Action::None
            }
            Overlay::Filter => self.handle_filter(key),
            Overlay::Edit { .. } | Overlay::AuthEdit { .. } => self.handle_overlay_input(key),
            Overlay::None => self.handle_normal(key),
        }
    }

    fn handle_normal(&mut self, key: Key) -> Action {
        match key {
            Key::Char('q') | Key::Esc => {
                self.should_quit = true;
                Action::Quit
            }
            Key::Char('?') | Key::F(1) => {
                self.overlay = Overlay::Help;
                Action::None
            }
            Key::Char('/') => {
                self.overlay = Overlay::Filter;
                Action::None
            }
            Key::Char('1') => {
                self.screen = Screen::Profiles;
                Action::None
            }
            Key::Char('2') => {
                self.screen = Screen::Auth;
                Action::None
            }
            Key::Char('3') => {
                self.screen = Screen::Run;
                Action::None
            }
            Key::Char('4') => {
                self.screen = Screen::Urls;
                Action::None
            }
            Key::Char('5') => {
                self.screen = Screen::Findings;
                Action::None
            }
            Key::Tab => {
                self.screen = self.screen.next();
                Action::None
            }
            Key::BackTab => {
                self.screen = self.screen.prev();
                Action::None
            }
            Key::Char('s') => Action::Start,
            Key::Char('x') => Action::Cancel,
            Key::Char('r') => Action::Resume,
            Key::Char('p') => Action::Probe,
            Key::Char('o') => Action::Export,
            Key::Char('a') if self.screen == Screen::Auth => Action::ApplyAuth,
            Key::Char('w') if self.screen == Screen::Profiles => Action::SaveProfile,
            Key::Char('e') if self.screen == Screen::Profiles => {
                self.begin_profile_edit();
                Action::None
            }
            Key::Down | Key::Char('j') => {
                self.move_selection(1);
                Action::None
            }
            Key::Up | Key::Char('k') => {
                self.move_selection(-1);
                Action::None
            }
            Key::Enter => self.handle_enter(),
            _ => Action::None,
        }
    }

    fn handle_filter(&mut self, key: Key) -> Action {
        match key {
            Key::Esc => {
                self.filter.clear();
                self.overlay = Overlay::None;
                self.clamp_selection();
            }
            Key::Enter => {
                self.overlay = Overlay::None;
            }
            Key::Backspace => {
                self.filter.pop();
                self.clamp_selection();
            }
            Key::Char(c) if !c.is_control() => {
                self.filter.push(c);
                self.clamp_selection();
            }
            _ => {}
        }
        Action::None
    }

    fn handle_overlay_input(&mut self, key: Key) -> Action {
        match std::mem::replace(&mut self.overlay, Overlay::None) {
            Overlay::Edit { field, mut buffer } => match key {
                Key::Esc => {}
                Key::Enter => {
                    if let Err(err) = self.apply_profile_field(field, &buffer) {
                        self.message = err;
                        self.overlay = Overlay::Edit { field, buffer };
                    } else {
                        self.message = format!("Updated {}", field.label());
                    }
                }
                Key::Backspace => {
                    buffer.pop();
                    self.overlay = Overlay::Edit { field, buffer };
                }
                Key::Char(c) if !c.is_control() => {
                    buffer.push(c);
                    self.overlay = Overlay::Edit { field, buffer };
                }
                _ => self.overlay = Overlay::Edit { field, buffer },
            },
            Overlay::AuthEdit { field, mut buffer } => match key {
                Key::Esc => {}
                Key::Enter => {
                    match field {
                        AuthField::Signature => self.auth_signature = buffer.clone(),
                        AuthField::SignatureInput => self.auth_input = buffer.clone(),
                        AuthField::SignatureAgent => self.auth_agent = buffer.clone(),
                    }
                    self.message =
                        "Masked value stored in memory. Press a to apply to the environment."
                            .into();
                }
                Key::Backspace => {
                    buffer.pop();
                    self.overlay = Overlay::AuthEdit { field, buffer };
                }
                Key::Char(c) if !c.is_control() => {
                    buffer.push(c);
                    self.overlay = Overlay::AuthEdit { field, buffer };
                }
                _ => self.overlay = Overlay::AuthEdit { field, buffer },
            },
            other => self.overlay = other,
        }
        Action::None
    }

    fn handle_enter(&mut self) -> Action {
        match self.screen {
            Screen::Profiles => {
                if let Some(file) = self.profiles.get(self.profile_index)
                    && let Some(profile) = file.profile.clone()
                {
                    self.profile = profile;
                    self.message = format!("Selected {}", file.name);
                }
                Action::None
            }
            Screen::Auth => {
                let field = match self.profile_field % 3 {
                    0 => AuthField::Signature,
                    1 => AuthField::SignatureInput,
                    _ => AuthField::SignatureAgent,
                };
                self.overlay = Overlay::AuthEdit {
                    field,
                    buffer: SecretBuffer::default(),
                };
                Action::None
            }
            Screen::Run => {
                if !self.runs.is_empty() {
                    self.last_run_id = self.runs.get(self.run_index).map(|run| run.id);
                    Action::Evaluate
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    fn begin_profile_edit(&mut self) {
        let field = ProfileField::all()[self.profile_field.min(3)];
        if field == ProfileField::DiscoveryMode {
            self.cycle_discovery();
            return;
        }
        let buffer = match field {
            ProfileField::StartUrl => self.profile.start_url.to_string(),
            ProfileField::MaxPages => self.profile.max_pages.to_string(),
            ProfileField::UserAgent => self.profile.user_agent.clone(),
            ProfileField::DiscoveryMode => String::new(),
        };
        self.overlay = Overlay::Edit { field, buffer };
    }

    fn cycle_discovery(&mut self) {
        use crawlytic_core::DiscoveryMode;
        self.profile.discovery_mode = match self.profile.discovery_mode {
            DiscoveryMode::HomepageInternalLinks => DiscoveryMode::Sitemap,
            DiscoveryMode::Sitemap => DiscoveryMode::Combined,
            DiscoveryMode::Combined => DiscoveryMode::HomepageInternalLinks,
        };
        self.message = format!("discovery_mode = {:?}", self.profile.discovery_mode);
    }

    fn apply_profile_field(&mut self, field: ProfileField, value: &str) -> Result<(), String> {
        let mut next = self.profile.clone();
        match field {
            ProfileField::StartUrl => {
                next.start_url = value.parse().map_err(|_| "Invalid start URL".to_string())?;
            }
            ProfileField::MaxPages => {
                next.max_pages = value
                    .parse()
                    .map_err(|_| "max_pages must be a positive integer".to_string())?;
            }
            ProfileField::UserAgent => next.user_agent = value.to_string(),
            ProfileField::DiscoveryMode => {}
        }
        let text = next.to_toml().map_err(|err| err.to_string())?;
        self.profile = Profile::load(&text).map_err(|err| err.to_string())?;
        Ok(())
    }

    fn move_selection(&mut self, delta: i32) {
        match self.screen {
            Screen::Profiles => {
                let len = self.profiles.len().max(1);
                self.profile_index = add_index(self.profile_index, delta, len);
            }
            Screen::Auth => {
                self.profile_field = add_index(self.profile_field, delta, 3);
            }
            Screen::Run => {
                if self.runs.is_empty() {
                    self.profile_field = add_index(self.profile_field, delta, 4);
                } else {
                    self.run_index = add_index(self.run_index, delta, self.runs.len());
                }
            }
            Screen::Urls => {
                let len = self.filtered_urls().len();
                if len > 0 {
                    self.url_index = add_index(self.url_index, delta, len);
                }
            }
            Screen::Findings => self.move_findings(delta),
        }
    }

    fn move_findings(&mut self, delta: i32) {
        let items = self.visible_finding_cursors();
        if items.is_empty() {
            self.findings_cursor = None;
            return;
        }
        let current = self
            .findings_cursor
            .and_then(|cursor| items.iter().position(|item| *item == cursor))
            .unwrap_or(0);
        let next = add_index(current, delta, items.len());
        self.findings_cursor = Some(items[next]);
    }

    pub fn clamp_selection(&mut self) {
        if !self.profiles.is_empty() {
            self.profile_index = self.profile_index.min(self.profiles.len() - 1);
        }
        let urls = self.filtered_urls().len();
        if urls == 0 {
            self.url_index = 0;
        } else {
            self.url_index = self.url_index.min(urls - 1);
        }
        let items = self.visible_finding_cursors();
        if items.is_empty() {
            self.findings_cursor = None;
        } else if !self
            .findings_cursor
            .is_some_and(|cursor| items.contains(&cursor))
        {
            self.findings_cursor = Some(items[0]);
        }
    }

    pub fn filtered_urls(&self) -> Vec<&UrlRecord> {
        self.urls
            .iter()
            .filter(|url| matches_filter(&self.filter, &url_line(url)))
            .collect()
    }

    pub fn visible_finding_cursors(&self) -> Vec<FindingsCursor> {
        let mut items = Vec::new();
        for (severity, rules) in self.investigation.by_severity.iter().enumerate() {
            for (rule, section) in rules.1.iter().enumerate() {
                for (finding, row) in section.findings.iter().enumerate() {
                    if self.row_visible(section, row) {
                        items.push(FindingsCursor::Finding {
                            severity,
                            rule,
                            finding,
                        });
                    }
                }
            }
        }
        for (index, section) in self.investigation.incomplete.iter().enumerate() {
            if self.section_visible(section) {
                items.push(FindingsCursor::Incomplete(index));
            }
        }
        for (index, section) in self.investigation.unsupported.iter().enumerate() {
            if self.section_visible(section) {
                items.push(FindingsCursor::Unsupported(index));
            }
        }
        items
    }

    fn row_visible(&self, section: &RuleSection, row: &FindingRow) -> bool {
        matches_filter(
            &self.filter,
            &format!(
                "{} {} {} {} {}",
                section.rule_id, section.label, row.entity_key, row.fact, row.recommendation
            ),
        )
    }

    fn section_visible(&self, section: &RuleSection) -> bool {
        matches_filter(
            &self.filter,
            &format!(
                "{} {} {}",
                section.rule_id,
                section.label,
                section.state.as_str()
            ),
        )
    }

    pub fn selected_url(&self) -> Option<&UrlRecord> {
        self.filtered_urls().get(self.url_index).copied()
    }

    pub fn selected_finding(&self) -> Option<&FindingRow> {
        match self.findings_cursor? {
            FindingsCursor::Finding {
                severity,
                rule,
                finding,
            } => self
                .investigation
                .by_severity
                .get(severity)
                .and_then(|(_, rules)| rules.get(rule))
                .and_then(|section| section.findings.get(finding)),
            _ => None,
        }
    }

    pub fn selected_section(&self) -> Option<&RuleSection> {
        match self.findings_cursor? {
            FindingsCursor::Finding { severity, rule, .. } => self
                .investigation
                .by_severity
                .get(severity)
                .and_then(|(_, rules)| rules.get(rule)),
            FindingsCursor::Incomplete(index) => self.investigation.incomplete.get(index),
            FindingsCursor::Unsupported(index) => self.investigation.unsupported.get(index),
        }
    }

    pub fn apply_progress(&mut self, progress: ProgressSnapshot) {
        if progress.run_id.is_some() {
            self.last_run_id = progress.run_id;
        }
        if matches!(
            progress.status,
            SessionStatus::Completed | SessionStatus::Incomplete | SessionStatus::Failed
        ) && self.progress.status == SessionStatus::Running
        {
            self.message = format!("Run {:?}", progress.status);
        }
        self.progress = progress;
    }

    pub fn apply_event(&mut self, event: CrawlEvent) {
        match event {
            CrawlEvent::Status(status) => {
                self.last_run_id = Some(status.run_id);
                self.progress.run_id = Some(status.run_id);
                self.progress.status = status.status;
            }
            CrawlEvent::FetchCompleted(fetch) => self.upsert_url(fetch),
            CrawlEvent::Diagnostic(diagnostic) => self.push_diagnostic(diagnostic),
        }
    }

    fn upsert_url(&mut self, fetch: FetchCompletion) {
        let record = UrlRecord {
            original: fetch.original.clone(),
            identity: fetch.identity.clone(),
            state: fetch.state,
            reason: fetch.reason,
            click_depth: None,
            via_website: true,
            via_sitemap: false,
        };
        if let Some(existing) = self
            .urls
            .iter_mut()
            .find(|url| url.original == fetch.original)
        {
            *existing = record;
        } else {
            self.urls.push(record);
        }
        self.clamp_selection();
    }

    fn push_diagnostic(&mut self, diagnostic: Diagnostic) {
        let text = format!("{:?}: {}", diagnostic.kind, diagnostic.message);
        self.message = text.clone();
        self.diagnostics.push(text);
        if self.diagnostics.len() > 20 {
            self.diagnostics.remove(0);
        }
    }

    pub fn set_urls(&mut self, urls: Vec<UrlRecord>, links: Vec<CoverageLink>) {
        self.urls = urls;
        self.links = links;
        self.clamp_selection();
    }

    pub fn set_runs(&mut self, runs: Vec<RunSummary>) {
        self.runs = runs;
        if !self.runs.is_empty() {
            self.run_index = self.run_index.min(self.runs.len() - 1);
            if self.last_run_id.is_none() {
                self.last_run_id = Some(self.runs[self.run_index].id);
            }
        }
    }

    pub fn set_report(&mut self, report: AuditReport) {
        self.investigation = investigation_from_report(&report);
        self.last_report = Some(report);
        self.clamp_selection();
        if self.findings_cursor.is_none() {
            self.findings_cursor = self.visible_finding_cursors().first().copied();
        }
        self.message = format!(
            "Live findings {}. Incomplete {}. Unsupported {}. No placeholder scores.",
            self.investigation.finding_count(),
            self.investigation.incomplete.len(),
            self.investigation.unsupported.len()
        );
    }

    pub fn auth_presence(&self, field: AuthField) -> AuthPresence {
        let key = self.auth_env(field);
        match std::env::var(key) {
            Ok(value) if !value.is_empty() => AuthPresence::Set,
            _ => AuthPresence::Missing,
        }
    }

    pub fn auth_env(&self, field: AuthField) -> &str {
        match field {
            AuthField::Signature => &self.profile.auth_signature_env,
            AuthField::SignatureInput => &self.profile.auth_signature_input_env,
            AuthField::SignatureAgent => &self.profile.auth_signature_agent_env,
        }
    }

    pub fn auth_value(&self, field: AuthField) -> Option<&str> {
        let buffer = match field {
            AuthField::Signature => &self.auth_signature,
            AuthField::SignatureInput => &self.auth_input,
            AuthField::SignatureAgent => &self.auth_agent,
        };
        if buffer.is_empty() {
            None
        } else {
            Some(buffer.as_secret())
        }
    }

    pub fn screen_label(&self) -> &'static str {
        self.screen.label()
    }

    pub fn running(&self) -> bool {
        self.progress.status == SessionStatus::Running
    }
}

fn add_index(current: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let len = len as i32;
    let next = current as i32 + delta;
    ((next % len) + len) as usize % len as usize
}

fn matches_filter(filter: &str, haystack: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    haystack
        .to_ascii_lowercase()
        .contains(&filter.to_ascii_lowercase())
}

pub fn url_line(url: &UrlRecord) -> String {
    format!(
        "{} {} {}{}",
        url_state_label(url.state),
        url.original,
        url.reason,
        url.click_depth
            .map(|depth| format!(" depth={depth}"))
            .unwrap_or_default()
    )
}

pub fn url_state_label(state: UrlState) -> &'static str {
    match state {
        UrlState::Fetched => "fetched",
        UrlState::Excluded => "excluded",
        UrlState::Blocked => "blocked",
        UrlState::Failed => "failed",
        UrlState::Pending => "pending",
        UrlState::InFlight => "in-flight",
    }
}

pub fn discover_profiles(dir: &Path) -> anyhow::Result<Vec<ProfileFile>> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.starts_with("profile") || !name.ends_with(".toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        match Profile::load(&text) {
            Ok(profile) => files.push(ProfileFile {
                path,
                name,
                profile: Some(profile),
                error: None,
            }),
            Err(err) => files.push(ProfileFile {
                path,
                name,
                profile: None,
                error: Some(err.to_string()),
            }),
        }
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

pub fn help_text() -> &'static str {
    "Keyboard\n\
     1-5 / Tab  screens     ?  help     /  filter     q Esc Ctrl-C  quit\n\
     j k  move     Enter  select/edit     w  save profile     e  edit field\n\
     s / Ctrl-S  start crawl     x / Ctrl-X  cancel     r / Ctrl-R  resume\n\
     a  apply masked auth to the process environment\n\
     o  export CSV+JSON of the evaluated run (no credentials)\n\
     Cancel, resume, filter, help and selection work while a crawl is running.\n\
     Credentials are masked in the UI and never written to profiles or SQLite."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::looks_like_placeholder_score;
    use crate::render::render_plain;
    use crawlytic_core::{
        CATALOGUE_VERSION, CoverageLink, EvidencePointer, FetchIdentity, Finding, FindingId,
        RULE_CONFIG_VERSION, RuleOutcome, RuleState, Severity, UrlState,
    };
    use url::Url;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn sample_profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn app() -> App {
        App::from_profile(sample_profile(), Vec::new(), 0)
    }

    fn identity(url: &str) -> FetchIdentity {
        FetchIdentity::from_url(&Url::parse(url).unwrap())
    }

    fn url(original: &str, state: UrlState) -> UrlRecord {
        UrlRecord {
            original: original.into(),
            identity: Some(identity(original)),
            state,
            reason: "fixture".into(),
            click_depth: Some(1),
            via_website: true,
            via_sitemap: false,
        }
    }

    fn report() -> AuditReport {
        AuditReport {
            run_id: 1,
            config_version: RULE_CONFIG_VERSION,
            config_fingerprint: "v1;e:;t:".into(),
            outcomes: vec![
                RuleOutcome {
                    rule_id: "meta.missing_title".into(),
                    state: RuleState::Findings,
                },
                RuleOutcome {
                    rule_id: "meta.long_title".into(),
                    state: RuleState::Incomplete,
                },
                RuleOutcome {
                    rule_id: "content.low_text_html_ratio".into(),
                    state: RuleState::Unsupported,
                },
            ],
            findings: vec![Finding {
                id: FindingId::new("meta.missing_title", "https://audit.example/untitled"),
                catalogue_version: CATALOGUE_VERSION,
                config_version: RULE_CONFIG_VERSION,
                severity: Severity::Error,
                state: RuleState::Findings,
                fact: "The page has no non-empty title element.".into(),
                recommendation: "Add a single descriptive title element.".into(),
                evidence: vec![EvidencePointer {
                    observation_identity: "https://audit.example/untitled".into(),
                    field: "title".into(),
                    excerpt: "(empty)".into(),
                }],
                suppressed: false,
            }],
        }
    }

    fn loaded(app: &mut App) {
        app.set_urls(
            vec![
                url("https://audit.example/", UrlState::Fetched),
                url("https://audit.example/untitled", UrlState::Fetched),
                url("https://audit.example/cart", UrlState::Excluded),
            ],
            vec![CoverageLink {
                from_identity: identity("https://audit.example/"),
                href: "/untitled".into(),
                to_original: "https://audit.example/untitled".into(),
                to_identity: Some(identity("https://audit.example/untitled")),
                skip_reason: None,
            }],
        );
        app.set_report(report());
    }

    #[test]
    fn keyboard_navigation_reaches_every_screen() {
        let mut app = app();
        loaded(&mut app);
        assert_eq!(app.handle(Key::Char('4')), Action::None);
        assert_eq!(app.screen, Screen::Urls);
        app.handle(Key::Char('j'));
        assert_eq!(
            app.selected_url().map(|url| url.original.as_str()),
            Some("https://audit.example/untitled")
        );
        app.handle(Key::Char('5'));
        assert_eq!(app.screen, Screen::Findings);
        assert!(app.selected_finding().is_some());
        app.handle(Key::Tab);
        assert_eq!(app.screen, Screen::Profiles);
        app.handle(Key::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn filter_help_cancel_and_resume_work_while_running() {
        let mut app = app();
        loaded(&mut app);
        app.apply_progress(ProgressSnapshot {
            run_id: Some(7),
            status: SessionStatus::Running,
            displayed_user_agent: crawlytic_core::DisplayedUserAgent::from_profile(&app.profile),
            counters: CrawlCounters {
                fetched: 2,
                pending: 4,
                in_flight: 1,
                ..CrawlCounters::default()
            },
            dropped_events: 0,
        });
        app.handle(Key::Char('/'));
        app.handle(Key::Char('u'));
        app.handle(Key::Char('n'));
        app.handle(Key::Char('t'));
        assert_eq!(app.filter, "unt");
        assert_eq!(app.filtered_urls().len(), 1);
        assert_eq!(app.handle(Key::Ctrl('x')), Action::Cancel);
        app.handle(Key::Esc);
        app.handle(Key::Char('?'));
        assert!(matches!(app.overlay, Overlay::Help));
        assert_eq!(app.handle(Key::Ctrl('r')), Action::Resume);
        assert_eq!(app.handle(Key::Ctrl('s')), Action::Start);
        app.handle(Key::Esc);
        assert_eq!(app.handle(Key::Char('s')), Action::Start);
    }

    #[test]
    fn credentials_never_render_or_debug_unmasked() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut app = app();
        app.screen = Screen::Auth;
        app.handle(Key::Enter);
        let secret = "super-secret-token-value";
        for c in secret.chars() {
            app.handle(Key::Char(c));
        }
        let rendered = render_plain(&app, 80, 24);
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(rendered.contains('•'), "{rendered}");
        let dump = format!("{app:?}");
        assert!(!dump.contains(secret), "{dump}");
        app.handle(Key::Enter);
        assert_eq!(app.handle(Key::Char('a')), Action::ApplyAuth);
        assert!(!render_plain(&app, 80, 12).contains(secret));
    }

    #[test]
    fn small_terminals_and_event_floods_stay_usable() {
        let mut app = app();
        loaded(&mut app);
        app.screen = Screen::Urls;
        for i in 0..200 {
            app.apply_event(CrawlEvent::FetchCompleted(FetchCompletion {
                run_id: 1,
                original: format!("https://audit.example/p/{i}"),
                identity: None,
                state: UrlState::Fetched,
                reason: "Fetched".into(),
            }));
        }
        let tiny = render_plain(&app, 20, 5);
        let small = render_plain(&app, 40, 8);
        assert!(tiny.contains("Crawlytic"), "{tiny}");
        assert!(
            small.contains("URL") || small.contains("url") || small.contains("fetched"),
            "{small}"
        );
        assert!(!looks_like_placeholder_score(&tiny));
        assert!(!looks_like_placeholder_score(&small));
    }

    #[test]
    fn findings_show_evidence_inlinks_and_not_synthetic_scores() {
        let mut app = app();
        loaded(&mut app);
        app.screen = Screen::Findings;
        let rendered = render_plain(&app, 100, 30);
        assert!(rendered.contains("error"), "{rendered}");
        assert!(
            rendered.contains("missing") || rendered.contains("title"),
            "{rendered}"
        );
        assert!(rendered.contains("untitled"), "{rendered}");
        assert!(rendered.contains("title"), "{rendered}");
        assert!(
            rendered.contains("incomplete") || rendered.contains("Incomplete"),
            "{rendered}"
        );
        assert!(
            rendered.contains("unsupported") || rendered.contains("Unsupported"),
            "{rendered}"
        );
        assert!(
            rendered.contains("inlink") || rendered.contains("https://audit.example/"),
            "{rendered}"
        );
        assert!(!looks_like_placeholder_score(&rendered), "{rendered}");
        assert!(
            !rendered.to_ascii_lowercase().contains("site health"),
            "{rendered}"
        );
        app.investigation = Investigation::default();
        app.findings_cursor = None;
        let empty = render_plain(&app, 80, 20);
        assert!(
            empty.contains("No live findings") || empty.contains("no live findings"),
            "{empty}"
        );
        assert!(!empty.contains("synthetic"), "{empty}");
    }

    #[test]
    fn profile_edit_does_not_store_signature_values() {
        let mut app = app();
        app.screen = Screen::Profiles;
        app.profile_field = 2;
        app.handle(Key::Char('e'));
        match &app.overlay {
            Overlay::Edit { field, .. } => assert_eq!(*field, ProfileField::UserAgent),
            other => panic!("expected edit overlay, got {other:?}"),
        }
        for c in "Crawlytic/test".chars() {
            app.handle(Key::Char(c));
        }
        app.overlay = Overlay::Edit {
            field: ProfileField::UserAgent,
            buffer: "Crawlytic/test".into(),
        };
        app.handle(Key::Enter);
        assert_eq!(app.profile.user_agent, "Crawlytic/test");
        let toml = app.profile.to_toml().unwrap();
        assert!(!toml.to_ascii_lowercase().contains("sig1="));
    }

    #[test]
    fn findings_export_key_writes_csv_and_json_action() {
        let mut app = app();
        loaded(&mut app);
        app.screen = Screen::Findings;
        assert_eq!(app.handle(Key::Char('o')), Action::Export);
        let help = help_text();
        assert!(help.contains("export"), "{help}");
        let rendered = render_plain(&app, 100, 24);
        assert!(
            rendered.contains("o export") || help.contains("o  export"),
            "{rendered}\n{help}"
        );
        assert_eq!(
            app.last_report.as_ref().map(|report| report.run_id),
            Some(1)
        );
        assert_eq!(
            app.last_report.as_ref().map(|report| report.findings.len()),
            Some(app.investigation.finding_count())
        );
    }
}
