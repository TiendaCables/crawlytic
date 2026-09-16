mod catalogue;
mod profile;

pub use catalogue::{
    CATALOGUE_VERSION, CapturedCurrent, CoarseUnit, FIXTURE_CONTRACT_VERSION, FixtureKind,
    HISTORICAL_BASELINE_DATE, InventoryUnit, NewIssuesExample, Rule, RuleState, RuleStatus,
    Severity, Stage, StateInput, checker_supported, current_findings, expected_fixture_state,
    new_issues_examples, resolve_state, rule_by_id, rules,
};
pub use profile::{
    CrawlDelay, DiscoveryMode, IgnoredParameterMode, Profile, ProfileRole, SCHEMA_VERSION,
    ScheduleCadence, Weekday,
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    Client,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

// Intentionally neither Debug nor Serialize: never put credentials in snapshots or logs.
pub struct WebBotAuth {
    headers: HeaderMap,
}

impl WebBotAuth {
    pub fn new(signature: &str, input: &str, agent: &str) -> Result<Self> {
        ensure!(
            !agent.trim().is_empty(),
            "Web Bot Auth fields must not be empty"
        );
        let agent = Self::signature_agent_header(agent);
        let mut headers = HeaderMap::new();
        for (name, text) in [
            ("signature", signature),
            ("signature-input", input),
            ("signature-agent", agent.as_str()),
        ] {
            ensure!(
                !text.trim().is_empty(),
                "Web Bot Auth fields must not be empty"
            );
            let mut value = HeaderValue::from_str(text)
                .map_err(|_| anyhow::anyhow!("Invalid Web Bot Auth header value"))?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        Ok(Self { headers })
    }

    fn signature_agent_header(agent: &str) -> String {
        let agent = agent.trim();
        if agent.starts_with('"') && agent.ends_with('"') && agent.len() >= 2 {
            agent.to_owned()
        } else {
            format!("\"{agent}\"")
        }
    }

    pub fn from_env() -> Result<Self> {
        let read = |key| std::env::var(key).map_err(|_| anyhow::anyhow!("Missing {key}"));
        Self::new(
            &read("CRAWL_SIGNATURE")?,
            &read("CRAWL_SIGNATURE_INPUT")?,
            &read("CRAWL_SIGNATURE_AGENT")?,
        )
    }
}

fn dotenv_error(err: dotenvy::Error) -> anyhow::Error {
    match err {
        dotenvy::Error::LineParse(_, line) => {
            anyhow::anyhow!("Invalid .env file at line {line}")
        }
        dotenvy::Error::Io(e) => anyhow::Error::new(e).context("Cannot read .env file"),
        _ => anyhow::anyhow!("Invalid .env file"),
    }
}

/// Parse a dotenv file without applying it. Outer quotes are stripped;
/// escaped embedded quotes are preserved.
pub fn parse_env_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let iter = dotenvy::from_path_iter(path).map_err(dotenv_error)?;
    let mut out = BTreeMap::new();
    for item in iter {
        let (key, value) = item.map_err(dotenv_error)?;
        out.insert(key, value);
    }
    Ok(out)
}

/// Load key/value pairs from `path` into the process environment.
/// Existing variables win over file values. A missing file is not an error.
pub fn load_env_file(path: &Path) -> Result<()> {
    match dotenvy::from_path(path) {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(dotenv_error(e)),
    }
}

/// Load `.env` from the current directory if present. Does not override
/// variables already set in the environment. Invalid files error without
/// echoing secret values.
pub fn load_dotenv() -> Result<()> {
    match dotenvy::dotenv() {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(dotenv_error(e)),
    }
}

#[derive(Debug)]
pub struct Probe {
    pub status: u16,
    pub content_type: String,
    pub bytes_sampled: usize,
}

/// A bounded signed HTTP probe. Redirects are refused, including to other hosts.
/// A 200 HTML response is reachability evidence, not proof Shopify accepted auth.
pub async fn preflight(profile: &Profile, auth: &WebBotAuth) -> Result<Probe> {
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(20))
        .user_agent(&profile.user_agent)
        .build()
        .context("Cannot create HTTP client")?;
    let mut response = client
        .get(profile.start_url.clone())
        .headers(auth.headers.clone())
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Connection failed: check DNS, TLS and network access"))?;
    let status = response.status();
    if status.is_redirection() {
        bail!("Redirect received; configure the final HTTPS host. Auth was not forwarded.");
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        bail!(
            "Access denied. Check signature, expiry and domain; other access controls may also apply."
        );
    }
    if status.as_u16() == 429 {
        bail!("Rate limited. Check signature and retry later at a lower rate.");
    }
    ensure!(
        status.is_success(),
        "Storefront returned HTTP {}",
        status.as_u16()
    );
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    ensure!(
        content_type.contains("text/html"),
        "Expected an HTML storefront response"
    );
    let mut sample = Vec::new();
    while sample.len() < 65536 {
        let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("Failed reading response"))?
        else {
            break;
        };
        let take = chunk.len().min(65536 - sample.len());
        sample.extend_from_slice(&chunk[..take]);
    }
    let lower = String::from_utf8_lossy(&sample).to_lowercase();
    ensure!(
        !lower.contains("cf-chl-") && !lower.contains("<title>just a moment"),
        "Possible challenge page; storefront access is not verified"
    );
    Ok(Probe {
        status: status.as_u16(),
        content_type,
        bytes_sampled: sample.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_are_sensitive_and_injection_is_rejected() {
        let auth = WebBotAuth::new("sig1=:example:", "sig1=()", "https://shopify.com").unwrap();
        assert!(auth.headers.values().all(HeaderValue::is_sensitive));
        assert_eq!(
            auth.headers
                .get("signature-agent")
                .unwrap()
                .to_str()
                .unwrap(),
            "\"https://shopify.com\""
        );
        let quoted =
            WebBotAuth::new("sig1=:example:", "sig1=()", "\"https://example.com/bot\"").unwrap();
        assert_eq!(
            quoted
                .headers
                .get("signature-agent")
                .unwrap()
                .to_str()
                .unwrap(),
            "\"https://example.com/bot\""
        );
        assert!(WebBotAuth::new("bad\r\nInjected: yes", "input", "agent").is_err());
        assert!(WebBotAuth::new("", "input", "agent").is_err());
        assert!(WebBotAuth::new("sig", "input", "   ").is_err());
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write_temp_env(contents: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "crawlytic-core-env-{}-{}.env",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn take_var(key: &str) -> Option<String> {
        let value = std::env::var(key).ok();
        unsafe { std::env::remove_var(key) };
        value
    }

    fn restore_var(key: &str, value: Option<String>) {
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn env_file_preserves_embedded_quotes() {
        let path = write_temp_env(
            r#"CRAWL_SIGNATURE="sig with \"embedded\" quotes"
CRAWL_SIGNATURE_INPUT="sig1=(\"@authority\" \"@path\");keyid=\"abc\""
"#,
        );
        let vars = parse_env_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(vars["CRAWL_SIGNATURE"], r#"sig with "embedded" quotes"#);
        assert_eq!(
            vars["CRAWL_SIGNATURE_INPUT"],
            r#"sig1=("@authority" "@path");keyid="abc""#
        );
    }

    #[test]
    fn environment_overrides_file_values() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = "CRAWLYTIC_CORE_TEST_ENV_OVERRIDE";
        let previous = take_var(key);
        unsafe { std::env::set_var(key, "from-environment") };
        let path = write_temp_env("CRAWLYTIC_CORE_TEST_ENV_OVERRIDE=from-file\n");
        let result = load_env_file(&path);
        let loaded = std::env::var(key).ok();
        restore_var(key, previous);
        let _ = std::fs::remove_file(&path);
        result.unwrap();
        assert_eq!(loaded.as_deref(), Some("from-environment"));
    }

    #[test]
    fn missing_and_invalid_values_produce_redacted_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            "CRAWL_SIGNATURE",
            "CRAWL_SIGNATURE_INPUT",
            "CRAWL_SIGNATURE_AGENT",
        ];
        let previous: Vec<_> = keys.iter().map(|k| (*k, take_var(k))).collect();
        let missing = match WebBotAuth::from_env() {
            Ok(_) => panic!("expected missing credentials"),
            Err(e) => e.to_string(),
        };
        for (key, value) in previous {
            restore_var(key, value);
        }
        assert_eq!(missing, "Missing CRAWL_SIGNATURE");

        let secret = "super-secret-token-value";
        let invalid = match WebBotAuth::new(&format!("{secret}\r\nInjected: 1"), "input", "agent") {
            Ok(_) => panic!("expected invalid header value"),
            Err(e) => e.to_string(),
        };
        assert!(!invalid.contains(secret), "{invalid}");
        assert!(!invalid.contains("Injected"), "{invalid}");

        let path = write_temp_env(&format!("CRAWL_SIGNATURE=\"{secret}\nunterminated\n"));
        let parse_err = parse_env_file(&path).unwrap_err().to_string();
        let _ = std::fs::remove_file(&path);
        assert!(!parse_err.contains(secret), "{parse_err}");
    }
}
