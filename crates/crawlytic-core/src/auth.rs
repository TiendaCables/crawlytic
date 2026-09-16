use crate::profile::Profile;
use anyhow::{Result, bail, ensure};
use reqwest::header::{HeaderMap, HeaderValue};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CREDENTIAL_REPLACEMENT_PLAN: &str = "Replace CRAWL_SIGNATURE and CRAWL_SIGNATURE_INPUT in the launch-directory .env or the process environment. Do not store secrets in profiles, fixtures, issues or exports. Signature-Agent remains the Shopify sf-string.";

pub const CRYPTO_VERIFICATION_LIMITATION: &str = "A 200 response with Web Bot Auth headers attached is access evidence, not proof of cryptographic verification.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureMetadata {
    pub created_unix: Option<u64>,
    pub expires_unix: Option<u64>,
}

// Intentionally neither Debug nor Serialize: never put credentials in snapshots or logs.
#[derive(Clone)]
pub struct WebBotAuth {
    headers: HeaderMap,
    metadata: SignatureMetadata,
}

impl WebBotAuth {
    pub fn new(signature: &str, input: &str, agent: &str) -> Result<Self> {
        ensure!(
            !agent.trim().is_empty(),
            "Web Bot Auth fields must not be empty"
        );
        let agent = Self::signature_agent_header(agent);
        validate_signature(signature)?;
        let metadata = parse_signature_input(input)?;
        if let Some(expires) = metadata.expires_unix {
            let now = unix_now();
            if expires <= now {
                bail!(
                    "Web Bot Auth credentials have expired according to Signature-Input metadata. {CREDENTIAL_REPLACEMENT_PLAN}"
                );
            }
        }
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
        Ok(Self { headers, metadata })
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
        Self::from_env_keys(
            "CRAWL_SIGNATURE",
            "CRAWL_SIGNATURE_INPUT",
            "CRAWL_SIGNATURE_AGENT",
        )
    }

    pub fn from_profile(profile: &Profile) -> Result<Self> {
        Self::from_env_keys(
            &profile.auth_signature_env,
            &profile.auth_signature_input_env,
            &profile.auth_signature_agent_env,
        )
    }

    fn from_env_keys(signature: &str, input: &str, agent: &str) -> Result<Self> {
        let read = |key: &str| {
            std::env::var(key)
                .map_err(|_| anyhow::anyhow!("Missing {key}. {CREDENTIAL_REPLACEMENT_PLAN}"))
        };
        Self::new(&read(signature)?, &read(input)?, &read(agent)?)
    }

    pub fn metadata(&self) -> SignatureMetadata {
        self.metadata
    }

    pub fn replacement_plan() -> &'static str {
        CREDENTIAL_REPLACEMENT_PLAN
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn expired_now(&self) -> bool {
        self.metadata
            .expires_unix
            .is_some_and(|expires| expires <= unix_now())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_sf_key(label: &str) -> bool {
    let mut chars = label.chars();
    matches!(
        chars.next(),
        Some('a'..='z') | Some('A'..='Z') | Some('0'..='9') | Some('*') | Some('_')
    ) && chars.all(|c| {
        matches!(
            c,
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '*'
        )
    })
}

fn validate_signature(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty(),
        "Web Bot Auth fields must not be empty"
    );
    for item in value.split(',') {
        let item = item.trim();
        let Some((label, rest)) = item.split_once('=') else {
            bail!("Invalid Signature formatting");
        };
        ensure!(is_sf_key(label), "Invalid Signature formatting");
        ensure!(
            rest.starts_with(':') && rest.ends_with(':') && rest.len() >= 2,
            "Invalid Signature formatting"
        );
        let bytes = &rest[1..rest.len() - 1];
        ensure!(
            bytes
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')),
            "Invalid Signature formatting"
        );
    }
    Ok(())
}

fn parse_unix_param(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()),
        "Invalid Signature-Input formatting"
    );
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid Signature-Input formatting"))
}

fn parse_signature_input(input: &str) -> Result<SignatureMetadata> {
    ensure!(
        !input.trim().is_empty(),
        "Web Bot Auth fields must not be empty"
    );
    let Some(eq) = input.find('=') else {
        bail!("Invalid Signature-Input formatting");
    };
    let label = &input[..eq];
    ensure!(
        is_sf_key(label.trim()),
        "Invalid Signature-Input formatting"
    );
    let rest = input[eq + 1..].trim_start();
    ensure!(rest.starts_with('('), "Invalid Signature-Input formatting");
    let Some(close) = rest.find(')') else {
        bail!("Invalid Signature-Input formatting");
    };
    let mut created_unix = None;
    let mut expires_unix = None;
    for param in rest[close + 1..].split(';') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        if let Some(value) = param.strip_prefix("created=") {
            created_unix = Some(parse_unix_param(value)?);
        } else if let Some(value) = param.strip_prefix("expires=") {
            expires_unix = Some(parse_unix_param(value)?);
        }
    }
    Ok(SignatureMetadata {
        created_unix,
        expires_unix,
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

    #[test]
    fn exact_header_values_are_preserved() {
        let signature = "sig1=:abc+DEF/12=_:";
        let input =
            r#"sig1=("@authority" "@path");created=2000000000;keyid="abc";tag="web-bot-auth""#;
        let auth = WebBotAuth::new(signature, input, "\"https://shopify.com\"").unwrap();
        assert_eq!(
            auth.headers.get("signature").unwrap().to_str().unwrap(),
            signature
        );
        assert_eq!(
            auth.headers
                .get("signature-input")
                .unwrap()
                .to_str()
                .unwrap(),
            input
        );
        assert_eq!(auth.metadata.created_unix, Some(2_000_000_000));
        assert_eq!(auth.metadata.expires_unix, None);
    }

    #[test]
    fn malformed_signature_fields_fail_before_use() {
        assert!(WebBotAuth::new("not-a-signature", "sig1=()", "https://shopify.com").is_err());
        assert!(WebBotAuth::new("sig1=:abc:", "no-list", "https://shopify.com").is_err());
        assert!(
            WebBotAuth::new("sig1=:abc:", "sig1=();expires=nope", "https://shopify.com").is_err()
        );
    }

    #[test]
    fn expired_metadata_fails_with_replacement_plan() {
        let err = match WebBotAuth::new(
            "sig1=:abc:",
            "sig1=();created=1;expires=1",
            "https://shopify.com",
        ) {
            Ok(_) => panic!("expected expired credentials"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("expired"), "{err}");
        assert!(err.contains(CREDENTIAL_REPLACEMENT_PLAN), "{err}");
        assert!(!err.contains("sig1=:abc:"), "{err}");
    }
}
