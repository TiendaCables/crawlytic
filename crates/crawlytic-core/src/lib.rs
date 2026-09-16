mod auth;
mod catalogue;
mod crawl;
mod profile;
mod robots;
mod scope;
mod transport;

pub use auth::{
    CREDENTIAL_REPLACEMENT_PLAN, CRYPTO_VERIFICATION_LIMITATION, SignatureMetadata, WebBotAuth,
};
pub use catalogue::{
    CATALOGUE_VERSION, CapturedCurrent, CoarseUnit, FIXTURE_CONTRACT_VERSION, FixtureKind,
    HISTORICAL_BASELINE_DATE, InventoryUnit, NewIssuesExample, Rule, RuleState, RuleStatus,
    Severity, Stage, StateInput, checker_supported, current_findings, expected_fixture_state,
    new_issues_examples, resolve_state, rule_by_id, rules,
};
pub use crawl::{CancelHandle, CrawlLimits, CrawlReport, Crawler, UrlRecord, UrlState};
pub use profile::{
    CrawlDelay, DiscoveryMode, IgnoredParameterMode, Profile, ProfileRole, SCHEMA_VERSION,
    ScheduleCadence, Weekday,
};
pub use robots::{
    AllowReason, BlockKind, BlockedEvidence, RobotsCache, RobotsFetchState, RobotsFile,
    RobotsRunMetadata, UrlAccess, evaluate_url, product_token,
};
pub use scope::{
    ClassifiedUrl, Coverage, CoverageLink, CoverageUrl, FetchIdentity, SKIP_MALFORMED,
    SKIP_UNSUPPORTED_SCHEME, classify_absolute, classify_href,
};
pub use transport::{AccessError, FetchRecord, Probe, ResourceKind, SignedTransport, preflight};

use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(missing.starts_with("Missing CRAWL_SIGNATURE"), "{missing}");
        assert!(missing.contains(CREDENTIAL_REPLACEMENT_PLAN), "{missing}");

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
