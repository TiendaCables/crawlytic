use anyhow::{Context, Result, ensure};
use reqwest::header::HeaderValue;
use serde::Deserialize;
use url::Url;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRole {
    OwnBot,
    Comparison,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    HomepageInternalLinks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlDelay {
    Minimum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IgnoredParameterMode {
    Skip,
    Strip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleCadence {
    Weekly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Versioned crawl profile. Secret values are referenced by environment name only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub role: ProfileRole,
    pub start_url: Url,
    pub max_pages: usize,
    pub observed_pages_baseline: usize,
    pub user_agent: String,
    pub discovery_mode: DiscoveryMode,
    pub crawl_delay: CrawlDelay,
    pub javascript_rendering: bool,
    pub bypass_robots: bool,
    pub bypass_meta: bool,
    pub password_authentication: bool,
    pub web_bot_auth_required: bool,
    pub allow_subfolders: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub ignored_parameter_mode: IgnoredParameterMode,
    pub parameter_names_case_sensitive: bool,
    pub skip_parameters: Vec<String>,
    pub schedule_cadence: ScheduleCadence,
    pub schedule_weekday: Weekday,
    #[serde(default)]
    pub schedule_time: Option<String>,
    #[serde(default)]
    pub schedule_timezone: Option<String>,
    pub completion_email: bool,
    pub auth_signature_env: String,
    pub auth_signature_input_env: String,
    pub auth_signature_agent_env: String,
    pub ignored_parameters_captured: usize,
    pub ignored_parameters_source_count: usize,
    pub exclude_paths_complete: bool,
    pub lists_complete: bool,
    #[serde(default)]
    pub limits_are_catalogue_size: bool,
}

impl Profile {
    pub fn load(text: &str) -> Result<Self> {
        let mut p: Self = toml::from_str(text).context("Invalid profile TOML")?;
        p.schedule_time = blank_to_none(p.schedule_time.take());
        p.schedule_timezone = blank_to_none(p.schedule_timezone.take());
        p.validate()?;
        Ok(p)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "Unsupported profile schema_version {}",
            self.schema_version
        );
        ensure!(
            self.start_url.scheme() == "https" && self.start_url.host_str().is_some(),
            "An HTTPS storefront URL is required"
        );
        ensure!(
            self.start_url.username().is_empty() && self.start_url.password().is_none(),
            "URL credentials are not supported"
        );
        ensure!(self.max_pages > 0, "Page limit must be positive");
        ensure!(
            !self.limits_are_catalogue_size,
            "Page cap and observed baseline are not catalogue size"
        );
        HeaderValue::from_str(&self.user_agent)
            .map_err(|_| anyhow::anyhow!("Invalid user agent"))?;
        if self.role == ProfileRole::OwnBot {
            ensure!(
                !self.user_agent.contains("SiteAuditBot"),
                "Own-bot profiles must identify independently"
            );
        }
        for name in [
            &self.auth_signature_env,
            &self.auth_signature_input_env,
            &self.auth_signature_agent_env,
        ] {
            ensure!(
                is_env_name(name),
                "Auth fields must be environment variable names, not secret values"
            );
        }
        validate_path_patterns("exclude_paths", &self.exclude_paths)?;
        validate_path_patterns("allow_subfolders", &self.allow_subfolders)?;
        validate_unique("skip_parameters", &self.skip_parameters)?;
        ensure!(
            self.ignored_parameters_captured == self.skip_parameters.len(),
            "ignored_parameters_captured must match skip_parameters length"
        );
        ensure!(
            self.ignored_parameters_source_count >= self.ignored_parameters_captured,
            "ignored_parameters_source_count cannot be below the captured list"
        );
        if self.lists_complete {
            ensure!(
                self.exclude_paths_complete
                    && self.ignored_parameters_captured == self.ignored_parameters_source_count,
                "lists_complete requires the full parameter list and complete path exclusions"
            );
        }
        Ok(())
    }

    pub fn exclusion(&self, url: &Url) -> Option<&'static str> {
        if url.origin() != self.start_url.origin() {
            return Some("Outside configured origin");
        }
        if let Some(reason) = allow_subfolder_reason(&self.allow_subfolders, url.path()) {
            return Some(reason);
        }
        if let Some(reason) = exclude_path_reason(&self.exclude_paths, url.path()) {
            return Some(reason);
        }
        if self.ignored_parameter_mode == IgnoredParameterMode::Skip
            && self.has_ignored_parameter(url)
        {
            return Some("Ignored parameter");
        }
        None
    }

    /// Skip mode refuses the URL. Strip mode is explicit and rewrites the query instead.
    pub fn apply_ignored_parameters(&self, url: &Url) -> Result<Url, &'static str> {
        match self.ignored_parameter_mode {
            IgnoredParameterMode::Skip => {
                if self.has_ignored_parameter(url) {
                    Err("Ignored parameter")
                } else {
                    Ok(url.clone())
                }
            }
            IgnoredParameterMode::Strip => Ok(self.strip_ignored_parameters(url)),
        }
    }

    fn has_ignored_parameter(&self, url: &Url) -> bool {
        url.query_pairs().any(|(key, _)| {
            self.skip_parameters
                .iter()
                .any(|name| self.param_eq(name, &key))
        })
    }

    fn param_eq(&self, configured: &str, key: &str) -> bool {
        if self.parameter_names_case_sensitive {
            configured == key
        } else {
            configured.eq_ignore_ascii_case(key)
        }
    }

    fn strip_ignored_parameters(&self, url: &Url) -> Url {
        let mut url = url.clone();
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(key, _)| {
                !self
                    .skip_parameters
                    .iter()
                    .any(|name| self.param_eq(name, key))
            })
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        if kept.is_empty() {
            url.set_query(None);
        } else {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in &kept {
                serializer.append_pair(key, value);
            }
            let query = serializer.finish();
            url.set_query(Some(&query));
        }
        url
    }

    pub fn summary(&self) -> String {
        let role = match self.role {
            ProfileRole::OwnBot => "own-bot",
            ProfileRole::Comparison => "comparison baseline; do not impersonate Semrush",
        };
        let lists = if self.lists_complete {
            "complete"
        } else {
            "incomplete; do not claim Semrush scope parity"
        };
        let param_mode = match self.ignored_parameter_mode {
            IgnoredParameterMode::Skip => "skip URLs that carry them",
            IgnoredParameterMode::Strip => "strip parameters then fetch",
        };
        let schedule_when = match (&self.schedule_time, &self.schedule_timezone) {
            (None, None) => "time/timezone unspecified; no scheduler".to_owned(),
            (time, timezone) => format!(
                "time {} / timezone {}",
                time.as_deref().unwrap_or("unspecified"),
                timezone.as_deref().unwrap_or("unspecified")
            ),
        };
        format!(
            "Store: {}\nRole: {role} | User-Agent: {}\nPage cap: {} (not catalogue size) | Observed baseline: {} (historical, not an invariant)\nDiscovery: homepage internal links | JavaScript rendering: {} | Crawl delay: minimum\nRobots bypass: {} | Meta bypass: {} | Web Bot Auth: {} | Password auth: {}\nSchedule intent: weekly {} ({schedule_when})\nExcluded paths: {} ({lists}) | Ignored parameters: {} of {} ({param_mode})\nSecrets: environment references only ({}, {}, {})",
            self.start_url,
            self.user_agent,
            self.max_pages,
            self.observed_pages_baseline,
            off_on(self.javascript_rendering),
            off_on(self.bypass_robots),
            off_on(self.bypass_meta),
            if self.web_bot_auth_required {
                "required"
            } else {
                "off"
            },
            off_on(self.password_authentication),
            weekday_name(self.schedule_weekday),
            self.exclude_paths.len(),
            self.ignored_parameters_captured,
            self.ignored_parameters_source_count,
            self.auth_signature_env,
            self.auth_signature_input_env,
            self.auth_signature_agent_env,
        )
    }
}

fn off_on(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn weekday_name(day: Weekday) -> &'static str {
    match day {
        Weekday::Monday => "Monday",
        Weekday::Tuesday => "Tuesday",
        Weekday::Wednesday => "Wednesday",
        Weekday::Thursday => "Thursday",
        Weekday::Friday => "Friday",
        Weekday::Saturday => "Saturday",
        Weekday::Sunday => "Sunday",
    }
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('A'..='Z') | Some('_'))
        && chars.all(|c| matches!(c, 'A'..='Z' | '0'..='9' | '_'))
}

fn validate_path_patterns(field: &str, patterns: &[String]) -> Result<()> {
    validate_unique(field, patterns)?;
    for pattern in patterns {
        ensure!(
            !pattern.is_empty() && pattern.starts_with('/'),
            "{field} entries must be non-empty paths starting with /"
        );
    }
    Ok(())
}

fn validate_unique(field: &str, values: &[String]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        ensure!(seen.insert(value), "Duplicate {field} entry {value}");
    }
    Ok(())
}

fn allow_subfolder_reason(allows: &[String], path: &str) -> Option<&'static str> {
    if allows.is_empty() {
        return None;
    }
    if allows.iter().any(|pattern| path_matches(pattern, path)) {
        None
    } else {
        Some("Not in allowed subfolders")
    }
}

fn exclude_path_reason(patterns: &[String], path: &str) -> Option<&'static str> {
    for pattern in patterns {
        if pattern.ends_with('/') {
            if folder_matches(pattern, path) {
                return Some("Excluded subfolder");
            }
        } else if path.starts_with(pattern.as_str()) {
            return Some("Excluded path prefix");
        }
    }
    None
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.ends_with('/') {
        folder_matches(pattern, path)
    } else {
        path.starts_with(pattern)
    }
}

fn folder_matches(pattern: &str, path: &str) -> bool {
    let folder = pattern.trim_end_matches('/');
    path == folder || path.starts_with(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEMRUSH_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25 (compatible; SiteAuditBot/0.97; +http://www.semrush.com/bot.html)";

    fn url(path: &str) -> Url {
        Url::parse(&format!("https://www.tiendacables.com{path}")).unwrap()
    }

    fn load_scope(
        exclude_paths: &str,
        skip_parameters: &str,
        mode: &str,
        captured: usize,
        extra: &str,
    ) -> Profile {
        load_configured("[]", exclude_paths, skip_parameters, mode, captured, extra)
    }

    fn load_configured(
        allow_subfolders: &str,
        exclude_paths: &str,
        skip_parameters: &str,
        mode: &str,
        captured: usize,
        extra: &str,
    ) -> Profile {
        Profile::load(&format!(
            r#"
schema_version = 1
role = "own_bot"
start_url = "https://www.tiendacables.com/"
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
allow_subfolders = {allow_subfolders}
exclude_paths = {exclude_paths}
ignored_parameter_mode = "{mode}"
parameter_names_case_sensitive = true
skip_parameters = {skip_parameters}
schedule_cadence = "weekly"
schedule_weekday = "monday"
completion_email = false
auth_signature_env = "CRAWL_SIGNATURE"
auth_signature_input_env = "CRAWL_SIGNATURE_INPUT"
auth_signature_agent_env = "CRAWL_SIGNATURE_AGENT"
ignored_parameters_captured = {captured}
ignored_parameters_source_count = 27
exclude_paths_complete = false
lists_complete = false
{extra}
"#
        ))
        .unwrap()
    }

    #[test]
    fn path_prefix_is_not_subfolder_matching() {
        let p = load_scope(r#"["/shoes", "/boots/"]"#, "[]", "skip", 0, "");
        assert_eq!(
            p.exclusion(&url("/shoes-men")),
            Some("Excluded path prefix"),
            "/shoes is a string prefix and matches /shoes-men"
        );
        assert_eq!(p.exclusion(&url("/shoes")), Some("Excluded path prefix"));
        assert_eq!(
            p.exclusion(&url("/boots-men")),
            None,
            "/boots/ is a subfolder and must not match /boots-men"
        );
        assert_eq!(
            p.exclusion(&url("/boots/red")),
            Some("Excluded subfolder"),
            "/boots/ excludes pages in that folder"
        );
        assert_eq!(
            p.exclusion(&url("/boots")),
            Some("Excluded subfolder"),
            "/boots/ also excludes the folder path itself"
        );
        assert_eq!(p.exclusion(&url("/boots/")), Some("Excluded subfolder"));
    }

    #[test]
    fn captured_tagged_path_uses_subfolder_semantics() {
        let p = load_scope(r#"["/en/blogs/noticias/tagged/"]"#, "[]", "skip", 0, "");
        assert_eq!(
            p.exclusion(&url("/en/blogs/noticias/tagged/oferta")),
            Some("Excluded subfolder")
        );
        assert_eq!(
            p.exclusion(&url("/en/blogs/noticias/tagged-archive")),
            None,
            "trailing slash must not become a string prefix"
        );
    }

    #[test]
    fn skip_does_not_strip_ignored_parameters() {
        let p = load_scope("[]", r#"["variant"]"#, "skip", 1, "");
        let with_variant = url("/products/x?variant=1&page=2");
        assert_eq!(p.exclusion(&with_variant), Some("Ignored parameter"));
        assert_eq!(
            p.apply_ignored_parameters(&with_variant),
            Err("Ignored parameter")
        );
        assert_eq!(
            p.exclusion(&url("/products/x?page=2")),
            None,
            "skipping is not a substitute for fetching the stripped URL"
        );
    }

    #[test]
    fn strip_mode_is_explicit_and_distinct() {
        let p = load_scope("[]", r#"["variant"]"#, "strip", 1, "");
        let with_variant = url("/products/x?variant=1&page=2");
        assert_eq!(
            p.exclusion(&with_variant),
            None,
            "strip mode must not reuse skip exclusions"
        );
        let fetched = p.apply_ignored_parameters(&with_variant).unwrap();
        assert_eq!(
            fetched.as_str(),
            "https://www.tiendacables.com/products/x?page=2"
        );
        assert_ne!(p.ignored_parameter_mode, IgnoredParameterMode::Skip);
    }

    #[test]
    fn ignored_parameter_names_are_case_sensitive() {
        let p = load_scope("[]", r#"["variant"]"#, "skip", 1, "");
        assert_eq!(
            p.exclusion(&url("/products/x?Variant=1")),
            None,
            "names are case-sensitive unless configured otherwise"
        );
        assert_eq!(
            p.exclusion(&url("/products/x?variant=1")),
            Some("Ignored parameter")
        );
        assert_eq!(p.exclusion(&url("/products/x?options[prefix]=1")), None);
        let with_option = load_scope("[]", r#"["options[prefix]"]"#, "skip", 1, "");
        assert_eq!(
            with_option.exclusion(&url("/products/x?options[prefix]=1")),
            Some("Ignored parameter")
        );
    }

    #[test]
    fn empty_allow_subfolders_does_not_restrict_origin() {
        let p = load_scope("[]", "[]", "skip", 0, "");
        assert!(p.allow_subfolders.is_empty());
        assert_eq!(p.exclusion(&url("/products/x")), None);
        let limited = load_configured(r#"["/collections/"]"#, "[]", "[]", "skip", 0, "");
        assert_eq!(
            limited.exclusion(&url("/products/x")),
            Some("Not in allowed subfolders")
        );
        assert_eq!(limited.exclusion(&url("/collections/cables")), None);
    }

    #[test]
    fn captured_limits_are_not_catalogue_size() {
        let own = Profile::load(include_str!("../../../profile.example.toml")).unwrap();
        assert_eq!(own.max_pages, 20_000);
        assert_eq!(own.observed_pages_baseline, 3_725);
        assert!(!own.limits_are_catalogue_size);
        assert_ne!(own.max_pages, own.observed_pages_baseline);
        assert!(own.summary().contains("not catalogue size"));
        assert!(own.summary().contains("historical, not an invariant"));
        let err = Profile::load(
            include_str!("../../../profile.example.toml")
                .to_owned()
                .replace(
                    "lists_complete = false",
                    "lists_complete = false\nlimits_are_catalogue_size = true",
                )
                .as_str(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not catalogue size"), "{err}");
    }

    #[test]
    fn weekly_monday_intent_has_no_invented_schedule() {
        let own = Profile::load(include_str!("../../../profile.example.toml")).unwrap();
        assert_eq!(own.schedule_cadence, ScheduleCadence::Weekly);
        assert_eq!(own.schedule_weekday, Weekday::Monday);
        assert_eq!(own.schedule_time, None);
        assert_eq!(own.schedule_timezone, None);
        assert!(
            own.summary()
                .contains("time/timezone unspecified; no scheduler")
        );
    }

    #[test]
    fn own_bot_and_comparison_profiles_are_preserved() {
        let own = Profile::load(include_str!("../../../profile.example.toml")).unwrap();
        let comparison = Profile::load(include_str!("../../../profile.comparison.toml")).unwrap();
        assert_eq!(own.role, ProfileRole::OwnBot);
        assert_eq!(comparison.role, ProfileRole::Comparison);
        assert_eq!(own.user_agent, "Crawlytic/0.1 (self-hosted SEO audit)");
        assert!(!own.user_agent.contains("SiteAuditBot"));
        assert_eq!(comparison.user_agent, SEMRUSH_UA);
        assert!(!comparison.javascript_rendering);
        assert!(!own.javascript_rendering);
        assert!(!own.bypass_robots);
        assert!(!comparison.bypass_robots);
        assert!(own.web_bot_auth_required);
        assert_eq!(own.ignored_parameter_mode, IgnoredParameterMode::Skip);
        assert_eq!(
            comparison.ignored_parameter_mode,
            IgnoredParameterMode::Skip
        );
        assert_eq!(own.ignored_parameters_captured, 12);
        assert_eq!(own.ignored_parameters_source_count, 27);
        assert!(!own.lists_complete);
        assert!(!own.exclude_paths_complete);
        assert!(!comparison.lists_complete);
        assert_eq!(own.discovery_mode, DiscoveryMode::HomepageInternalLinks);
        assert_eq!(own.crawl_delay, CrawlDelay::Minimum);
        assert!(comparison.summary().contains("do not impersonate Semrush"));
    }

    #[test]
    fn incomplete_lists_cannot_be_marked_complete() {
        let err = Profile::load(
            include_str!("../../../profile.example.toml")
                .to_owned()
                .replace("lists_complete = false", "lists_complete = true")
                .as_str(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("lists_complete"), "{err}");
    }

    #[test]
    fn profiles_store_secret_references_not_values() {
        for text in [
            include_str!("../../../profile.example.toml"),
            include_str!("../../../profile.comparison.toml"),
        ] {
            let profile = Profile::load(text).unwrap();
            assert_eq!(profile.auth_signature_env, "CRAWL_SIGNATURE");
            assert_eq!(profile.auth_signature_input_env, "CRAWL_SIGNATURE_INPUT");
            assert_eq!(profile.auth_signature_agent_env, "CRAWL_SIGNATURE_AGENT");
            assert!(!text.contains("sig1="));
            assert!(!text.contains("CRAWL_SIGNATURE="));
        }
    }

    #[test]
    fn scope_and_parameters_are_explicit() {
        let p = Profile::load(include_str!("../../../profile.example.toml")).unwrap();
        assert!(
            p.exclusion(&Url::parse("https://evil.example/").unwrap())
                .is_some()
        );
        assert!(
            p.exclusion(&Url::parse("https://www.tiendacables.com/products/x?variant=1").unwrap())
                .is_some()
        );
        assert!(
            p.exclusion(&Url::parse("https://www.tiendacables.com/collections/x?page=2").unwrap())
                .is_none()
        );
        assert!(
            p.exclusion(&Url::parse("https://www.tiendacables.com/search?q=x").unwrap())
                .is_some()
        );
    }
}
