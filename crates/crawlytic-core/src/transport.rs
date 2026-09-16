use crate::auth::{CRYPTO_VERIFICATION_LIMITATION, WebBotAuth};
use crate::profile::Profile;
use crate::robots::{RobotsFile, RobotsRunMetadata, UrlAccess};
use anyhow::{Context, Result};
use reqwest::{
    Client, StatusCode,
    header::{LOCATION, RETRY_AFTER},
    redirect::Policy,
};
use std::fmt::{Display, Formatter};
use std::time::Duration;
use url::Url;

const MAX_REDIRECTS: usize = 5;
const MAX_RETRIES: usize = 1;
const SAMPLE_LIMIT: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Page,
    Robots,
    Sitemap,
    SameOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRecord {
    pub requested_url: Url,
    pub destination_url: Url,
    pub status: u16,
    pub content_type: String,
    pub bytes_sampled: usize,
    pub resource_kind: ResourceKind,
    pub credentials_attached: bool,
}

#[derive(Debug)]
pub struct Probe {
    pub status: u16,
    pub content_type: String,
    pub bytes_sampled: usize,
    pub samples: Vec<FetchRecord>,
    pub evidence_note: &'static str,
    pub robots: RobotsRunMetadata,
    pub start_url_access: UrlAccess,
}

#[derive(Debug)]
pub struct AccessError {
    observation: String,
    suspected_cause: Option<String>,
    blocking: bool,
}

impl AccessError {
    pub fn observation(&self) -> &str {
        &self.observation
    }

    pub fn suspected_cause(&self) -> Option<&str> {
        self.suspected_cause.as_deref()
    }

    fn with_cause(observation: impl Into<String>, cause: impl Into<String>) -> Self {
        Self {
            observation: observation.into(),
            suspected_cause: Some(cause.into()),
            blocking: false,
        }
    }

    fn blocking(observation: impl Into<String>, cause: impl Into<String>) -> Self {
        Self {
            observation: observation.into(),
            suspected_cause: Some(cause.into()),
            blocking: true,
        }
    }

    pub(crate) fn blocking_status(&self) -> bool {
        self.blocking
    }
}

impl Display for AccessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Observation: {}", self.observation)?;
        if let Some(cause) = &self.suspected_cause {
            write!(f, "\nSuspected cause: {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AccessError {}

pub struct SignedTransport {
    client: Client,
    auth: WebBotAuth,
    approved: Url,
}

impl SignedTransport {
    pub fn new(profile: &Profile, auth: &WebBotAuth) -> Result<Self> {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(20))
            .user_agent(&profile.user_agent)
            .https_only(true)
            .build()
            .context("Cannot create HTTP client")?;
        Ok(Self::new_with_client(
            client,
            profile.start_url.clone(),
            auth,
        ))
    }

    pub(crate) fn new_with_client(client: Client, approved: Url, auth: &WebBotAuth) -> Self {
        Self {
            client,
            auth: auth.clone(),
            approved,
        }
    }

    pub async fn fetch(
        &self,
        url: &Url,
        kind: ResourceKind,
    ) -> std::result::Result<FetchRecord, AccessError> {
        self.fetch_with_body(url, kind)
            .await
            .map(|(record, _)| record)
    }

    pub(crate) async fn fetch_with_body(
        &self,
        url: &Url,
        kind: ResourceKind,
    ) -> std::result::Result<(FetchRecord, Vec<u8>), AccessError> {
        if self.auth.expired_now() {
            return Err(AccessError::with_cause(
                "Web Bot Auth credentials are missing, malformed, or expired before the request was sent.",
                format!(
                    "Unsigned fallback is disabled. {}",
                    WebBotAuth::replacement_plan()
                ),
            ));
        }
        let mut current = url.clone();
        self.authorize(&current)?;
        let mut redirects = 0;
        loop {
            let response = self.send_signed(&current).await?;
            let status = response.status();
            if status.is_redirection() {
                let next = self.redirect_target(&current, &response)?;
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    return Err(AccessError::with_cause(
                        format!(
                            "HTTP {} from {current} exceeded the redirect limit",
                            status.as_u16()
                        ),
                        "Redirect loop or chain stopped. Credentials were not forwarded beyond the last approved HTTPS origin request.",
                    ));
                }
                self.authorize(&next)?;
                current = next;
                continue;
            }
            diagnose_status(&current, status, response.headers().get(RETRY_AFTER))?;
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let sample = read_sample(response).await?;
            if kind == ResourceKind::Page {
                ensure_html_page(&current, status, &content_type, &sample)?;
            } else if kind != ResourceKind::Robots
                && !status.is_success()
                && status != StatusCode::NOT_FOUND
            {
                return Err(AccessError::with_cause(
                    format!("HTTP {} from {current} for {:?}", status.as_u16(), kind),
                    "The origin returned a non-success status. This observation is not a signature verdict.",
                ));
            }
            return Ok((
                FetchRecord {
                    requested_url: url.clone(),
                    destination_url: current,
                    status: status.as_u16(),
                    content_type,
                    bytes_sampled: sample.len(),
                    resource_kind: kind,
                    credentials_attached: true,
                },
                sample,
            ));
        }
    }

    pub async fn sample_access(
        &self,
        profile: &Profile,
    ) -> std::result::Result<Probe, AccessError> {
        let robots_url = origin_path(&profile.start_url, "/robots.txt");
        let (robots_record, file) = match self
            .fetch_with_body(&robots_url, ResourceKind::Robots)
            .await
        {
            Ok((record, body)) => {
                let file = RobotsFile::from_fetch(&record, &body);
                (Some(record), file)
            }
            Err(err) if err.blocking_status() => return Err(err),
            Err(err) => (None, RobotsFile::unavailable(err.observation())),
        };
        let start_url_access = file.decide(profile, &profile.start_url);
        let robots = file.metadata(profile, &profile.start_url);
        let mut samples = Vec::new();
        if let UrlAccess::Allowed { .. } = &start_url_access {
            samples.push(self.fetch(&profile.start_url, ResourceKind::Page).await?);
        }
        if let Some(record) = robots_record {
            samples.push(record);
        }
        let sitemap_url = origin_path(&profile.start_url, "/sitemap.xml");
        if matches!(
            file.decide(profile, &sitemap_url),
            UrlAccess::Allowed { .. }
        ) {
            match self.fetch(&sitemap_url, ResourceKind::Sitemap).await {
                Ok(record) => samples.push(record),
                Err(err) if err.blocking_status() => return Err(err),
                Err(_) => {}
            }
        }
        let page = samples
            .iter()
            .find(|s| s.resource_kind == ResourceKind::Page);
        Ok(Probe {
            status: page.map(|s| s.status).unwrap_or(0),
            content_type: page.map(|s| s.content_type.clone()).unwrap_or_default(),
            bytes_sampled: page.map(|s| s.bytes_sampled).unwrap_or(0),
            samples,
            evidence_note: CRYPTO_VERIFICATION_LIMITATION,
            robots,
            start_url_access,
        })
    }

    fn authorize(&self, url: &Url) -> std::result::Result<(), AccessError> {
        if url.scheme() != "https" {
            return Err(AccessError::with_cause(
                format!("Refused {url}"),
                "HTTPS to HTTP downgrades and plain HTTP are not used for Web Bot Auth. Credentials were not forwarded.",
            ));
        }
        if url.origin() != self.approved.origin() {
            return Err(AccessError::with_cause(
                format!("Refused {url}"),
                "Web Bot Auth headers are attached only to the approved HTTPS origin. Credentials were not forwarded to another host or port.",
            ));
        }
        Ok(())
    }

    async fn send_signed(&self, url: &Url) -> std::result::Result<reqwest::Response, AccessError> {
        for attempt in 0..=MAX_RETRIES {
            match self
                .client
                .get(url.clone())
                .headers(self.auth.headers().clone())
                .send()
                .await
            {
                Ok(response) => return Ok(response),
                Err(_) if attempt < MAX_RETRIES => {}
                Err(_) => break,
            }
        }
        Err(AccessError::with_cause(
            format!("Connection failed to {url}"),
            "Check DNS, TLS and network access. This is not evidence that Shopify accepted or rejected the signature.",
        ))
    }

    fn redirect_target(
        &self,
        from: &Url,
        response: &reqwest::Response,
    ) -> std::result::Result<Url, AccessError> {
        let status = response.status().as_u16();
        let Some(location) = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
        else {
            return Err(AccessError::with_cause(
                format!("HTTP {status} from {from} without a usable Location header"),
                "The redirect could not be followed. Credentials were not forwarded.",
            ));
        };
        let next = from.join(location).map_err(|_| {
            AccessError::with_cause(
                format!("HTTP {status} from {from} with an unusable Location header"),
                "The redirect could not be followed. Credentials were not forwarded.",
            )
        })?;
        if next.scheme() != "https" {
            return Err(AccessError::with_cause(
                format!("HTTP {status} from {from} to {next}"),
                "HTTPS to HTTP downgrade refused. Credentials were not forwarded.",
            ));
        }
        if next.origin() != self.approved.origin() {
            return Err(AccessError::with_cause(
                format!("HTTP {status} from {from} to {next}"),
                "Cross-origin redirect refused. Credentials were not forwarded to another origin.",
            ));
        }
        Ok(next)
    }
}

/// Bounded signed sample of the start URL plus same-origin robots and sitemap.
/// A successful page fetch is reachability evidence, not cryptographic proof.
pub async fn preflight(profile: &Profile, auth: &WebBotAuth) -> Result<Probe> {
    SignedTransport::new(profile, auth)?
        .sample_access(profile)
        .await
        .map_err(|err| anyhow::anyhow!("{err}"))
}

fn origin_path(start: &Url, path: &str) -> Url {
    let mut url = start.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn diagnose_status(
    url: &Url,
    status: StatusCode,
    retry_after: Option<&reqwest::header::HeaderValue>,
) -> std::result::Result<(), AccessError> {
    match status.as_u16() {
        401 => Err(AccessError::blocking(
            format!(
                "HTTP 401 from {url} after attaching Signature, Signature-Input and Signature-Agent to the approved HTTPS origin"
            ),
            "Shopify may have rejected the signature, the credentials may be expired or bound to another host, or another access control may apply. A 401 is not proof of the specific cause.",
        )),
        403 => Err(AccessError::blocking(
            format!(
                "HTTP 403 from {url} after attaching Signature, Signature-Input and Signature-Agent to the approved HTTPS origin"
            ),
            "The origin refused access. This may be an invalid signature, a WAF or bot challenge, or another control. A 403 is not proof of the specific cause.",
        )),
        429 => {
            let retry = retry_after
                .and_then(|value| value.to_str().ok())
                .map(|value| format!(" Retry-After={value}."))
                .unwrap_or_default();
            Err(AccessError::blocking(
                format!("HTTP 429 from {url}.{retry}"),
                "The origin asked for a slower rate. Rate limiting may be independent of signature validity.",
            ))
        }
        _ => Ok(()),
    }
}

async fn read_sample(mut response: reqwest::Response) -> std::result::Result<Vec<u8>, AccessError> {
    let mut sample = Vec::new();
    while sample.len() < SAMPLE_LIMIT {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(SAMPLE_LIMIT - sample.len());
                sample.extend_from_slice(&chunk[..take]);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(AccessError::with_cause(
                    "Failed reading response",
                    "The body could not be sampled. This is not a signature verdict.",
                ));
            }
        }
    }
    Ok(sample)
}

fn ensure_html_page(
    url: &Url,
    status: StatusCode,
    content_type: &str,
    sample: &[u8],
) -> std::result::Result<(), AccessError> {
    if !status.is_success() {
        return Err(AccessError::with_cause(
            format!("HTTP {} from {url}", status.as_u16()),
            "The storefront returned a non-success status. This observation is not proof of signature acceptance or rejection.",
        ));
    }
    if !content_type.contains("text/html") {
        return Err(AccessError::with_cause(
            format!(
                "HTTP {} from {url} with content-type {content_type}",
                status.as_u16()
            ),
            "Expected an HTML storefront response. A non-HTML 200 is not treated as page access evidence.",
        ));
    }
    let lower = String::from_utf8_lossy(sample).to_lowercase();
    if lower.contains("cf-chl-") || lower.contains("<title>just a moment") {
        return Err(AccessError::with_cause(
            format!(
                "HTTP {} from {url} looked like a challenge page",
                status.as_u16()
            ),
            "Possible challenge page; storefront access is not verified. This heuristic cannot detect every block page.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CREDENTIAL_REPLACEMENT_PLAN;
    use std::collections::{HashMap, VecDeque};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Once};
    use std::thread;
    use std::time::Duration as StdDuration;

    const SIGNATURE: &str = "sig1=:TESTSIGNATUREVALUE:";
    const SIGNATURE_INPUT: &str =
        r#"sig1=("@authority" "@path");created=2000000000;keyid="test";tag="web-bot-auth""#;
    const AGENT: &str = "\"https://shopify.com\"";

    #[derive(Clone)]
    enum Planned {
        Hangup,
        Respond {
            status: u16,
            location: Option<String>,
            content_type: String,
            body: String,
            retry_after: Option<String>,
        },
    }

    #[derive(Clone)]
    struct Recorded {
        scheme: &'static str,
        host: String,
        path: String,
        headers: HashMap<String, String>,
    }

    struct TestOrigin {
        scheme: &'static str,
        addr: SocketAddr,
        recorded: Arc<Mutex<Vec<Recorded>>>,
        plans: Arc<Mutex<HashMap<String, VecDeque<Planned>>>>,
        _server: thread::JoinHandle<()>,
    }

    impl TestOrigin {
        fn http() -> Self {
            Self::start("http", None)
        }

        fn https() -> Self {
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            Self::start("https", Some(tls_config(&cert)))
        }

        fn start(scheme: &'static str, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
            let listener =
                TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
            listener.set_nonblocking(false).unwrap();
            let addr = listener.local_addr().unwrap();
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let plans = Arc::new(Mutex::new(HashMap::new()));
            let rec = recorded.clone();
            let plan_map = plans.clone();
            let server = thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(StdDuration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(StdDuration::from_secs(2)));
                    handle_conn(scheme, stream, tls.clone(), &rec, &plan_map);
                }
            });
            Self {
                scheme,
                addr,
                recorded,
                plans,
                _server: server,
            }
        }

        fn url(&self) -> Url {
            Url::parse(&format!(
                "{}://127.0.0.1:{}/",
                self.scheme,
                self.addr.port()
            ))
            .unwrap()
        }

        fn on(&self, path: &str, status: u16, content_type: &str, body: &str) {
            self.push(
                path,
                Planned::Respond {
                    status,
                    location: None,
                    content_type: content_type.into(),
                    body: body.into(),
                    retry_after: None,
                },
            );
        }

        fn redirect(&self, path: &str, location: &str) {
            self.push(
                path,
                Planned::Respond {
                    status: 302,
                    location: Some(location.into()),
                    content_type: "text/plain".into(),
                    body: String::new(),
                    retry_after: None,
                },
            );
        }

        fn hangup_then(&self, path: &str, status: u16, content_type: &str, body: &str) {
            self.push(path, Planned::Hangup);
            self.on(path, status, content_type, body);
        }

        fn status_retry_after(&self, path: &str, status: u16, retry_after: &str) {
            self.push(
                path,
                Planned::Respond {
                    status,
                    location: None,
                    content_type: "text/plain".into(),
                    body: String::new(),
                    retry_after: Some(retry_after.into()),
                },
            );
        }

        fn push(&self, path: &str, planned: Planned) {
            self.plans
                .lock()
                .unwrap()
                .entry(path.to_owned())
                .or_default()
                .push_back(planned);
        }

        fn recorded(&self) -> Vec<Recorded> {
            self.recorded.lock().unwrap().clone()
        }
    }

    fn tls_config(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> Arc<rustls::ServerConfig> {
        static PROVIDER: Once = Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
        let cert_der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    fn handle_conn(
        scheme: &'static str,
        stream: TcpStream,
        tls: Option<Arc<rustls::ServerConfig>>,
        recorded: &Arc<Mutex<Vec<Recorded>>>,
        plans: &Arc<Mutex<HashMap<String, VecDeque<Planned>>>>,
    ) {
        if let Some(config) = tls {
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, stream);
            serve(scheme, &mut stream, recorded, plans);
        } else {
            let mut stream = stream;
            serve(scheme, &mut stream, recorded, plans);
        }
    }

    fn serve(
        scheme: &'static str,
        stream: &mut impl ReadWrite,
        recorded: &Arc<Mutex<Vec<Recorded>>>,
        plans: &Arc<Mutex<HashMap<String, VecDeque<Planned>>>>,
    ) {
        let Ok(req) = read_request(scheme, stream) else {
            return;
        };
        let planned = {
            let mut plans = plans.lock().unwrap();
            plans
                .get_mut(&req.path)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Planned::Respond {
                    status: 404,
                    location: None,
                    content_type: "text/plain".into(),
                    body: "missing".into(),
                    retry_after: None,
                })
        };
        recorded.lock().unwrap().push(req);
        match planned {
            Planned::Hangup => {}
            Planned::Respond {
                status,
                location,
                content_type,
                body,
                retry_after,
            } => {
                let reason = match status {
                    200 => "OK",
                    302 => "Found",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    429 => "Too Many Requests",
                    _ => "Status",
                };
                let mut out = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(location) = location {
                    out.push_str(&format!("Location: {location}\r\n"));
                }
                if let Some(retry_after) = retry_after {
                    out.push_str(&format!("Retry-After: {retry_after}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(&body);
                let _ = stream.write_all(out.as_bytes());
                let _ = stream.flush();
            }
        }
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    fn read_request(scheme: &'static str, stream: &mut impl Read) -> std::io::Result<Recorded> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64_000 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines = text.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_owned();
        let mut headers = HashMap::new();
        let mut host = String::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_ascii_lowercase();
                let value = value.trim().to_owned();
                if name == "host" {
                    host = value.clone();
                }
                headers.insert(name, value);
            }
        }
        Ok(Recorded {
            scheme,
            host,
            path,
            headers,
        })
    }

    fn auth() -> WebBotAuth {
        WebBotAuth::new(SIGNATURE, SIGNATURE_INPUT, AGENT).unwrap()
    }

    fn client() -> Client {
        Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    fn transport(origin: &TestOrigin) -> SignedTransport {
        SignedTransport::new_with_client(client(), origin.url(), &auth())
    }

    fn profile_for(origin: &TestOrigin) -> Profile {
        static N: AtomicU64 = AtomicU64::new(0);
        let _ = N.fetch_add(1, Ordering::Relaxed);
        Profile::load(&format!(
            r#"
schema_version = 1
role = "own_bot"
start_url = "{}"
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
allow_subfolders = []
exclude_paths = []
ignored_parameter_mode = "skip"
parameter_names_case_sensitive = true
skip_parameters = []
schedule_cadence = "weekly"
schedule_weekday = "monday"
completion_email = false
auth_signature_env = "CRAWL_SIGNATURE"
auth_signature_input_env = "CRAWL_SIGNATURE_INPUT"
auth_signature_agent_env = "CRAWL_SIGNATURE_AGENT"
ignored_parameters_captured = 0
ignored_parameters_source_count = 27
exclude_paths_complete = false
lists_complete = false
"#,
            origin.url()
        ))
        .unwrap()
    }

    fn assert_signed(req: &Recorded) {
        assert_eq!(
            req.headers.get("signature").map(String::as_str),
            Some(SIGNATURE)
        );
        assert_eq!(
            req.headers.get("signature-input").map(String::as_str),
            Some(SIGNATURE_INPUT)
        );
        assert_eq!(
            req.headers.get("signature-agent").map(String::as_str),
            Some(AGENT)
        );
    }

    #[tokio::test]
    async fn signed_headers_reach_only_approved_https_destinations() {
        let approved = TestOrigin::https();
        let other = TestOrigin::https();
        let http = TestOrigin::http();
        approved.on("/", 200, "text/html", "<html>ok</html>");
        approved.on(
            "/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nAllow: /\n",
        );
        approved.on("/sitemap.xml", 200, "application/xml", "<urlset></urlset>");
        approved.on("/asset.css", 200, "text/css", "body{}");

        let t = transport(&approved);
        let page = t.fetch(&approved.url(), ResourceKind::Page).await.unwrap();
        assert_eq!(page.status, 200);
        assert!(page.credentials_attached);
        let robots = t
            .fetch(
                &origin_path(&approved.url(), "/robots.txt"),
                ResourceKind::Robots,
            )
            .await
            .unwrap();
        assert_eq!(robots.status, 200);
        let sitemap = t
            .fetch(
                &origin_path(&approved.url(), "/sitemap.xml"),
                ResourceKind::Sitemap,
            )
            .await
            .unwrap();
        assert_eq!(sitemap.status, 200);
        let asset = t
            .fetch(
                &origin_path(&approved.url(), "/asset.css"),
                ResourceKind::SameOrigin,
            )
            .await
            .unwrap();
        assert_eq!(asset.status, 200);

        let http_err = t.fetch(&http.url(), ResourceKind::Page).await.unwrap_err();
        assert!(http_err.observation().contains("Refused"), "{http_err}");
        assert!(
            http_err
                .suspected_cause()
                .unwrap()
                .contains("not forwarded")
        );

        let other_err = t.fetch(&other.url(), ResourceKind::Page).await.unwrap_err();
        assert!(other_err.observation().contains("Refused"), "{other_err}");

        assert!(http.recorded().is_empty());
        assert!(other.recorded().is_empty());
        let got = approved.recorded();
        assert_eq!(got.len(), 4);
        for req in &got {
            assert_eq!(req.scheme, "https");
            assert_signed(req);
        }
        let paths: Vec<_> = got.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/", "/robots.txt", "/sitemap.xml", "/asset.css"]);
    }

    #[tokio::test]
    async fn same_origin_https_redirect_keeps_headers_and_cross_origin_is_refused() {
        let approved = TestOrigin::https();
        let other = TestOrigin::https();
        let http = TestOrigin::http();
        approved.redirect("/same", "/dest");
        approved.on("/dest", 200, "text/html", "<html>dest</html>");
        approved.redirect("/away", other.url().as_str());
        approved.redirect("/down", http.url().as_str());

        let t = transport(&approved);
        let ok = t
            .fetch(&origin_path(&approved.url(), "/same"), ResourceKind::Page)
            .await
            .unwrap();
        assert_eq!(ok.destination_url.path(), "/dest");
        assert!(ok.credentials_attached);

        let away = t
            .fetch(&origin_path(&approved.url(), "/away"), ResourceKind::Page)
            .await
            .unwrap_err();
        assert!(away.observation().contains("HTTP 302"), "{away}");
        assert!(away.suspected_cause().unwrap().contains("not forwarded"));
        assert!(other.recorded().is_empty());

        let down = t
            .fetch(&origin_path(&approved.url(), "/down"), ResourceKind::Page)
            .await
            .unwrap_err();
        assert!(
            down.suspected_cause().unwrap().contains("downgrade"),
            "{down}"
        );
        assert!(http.recorded().is_empty());

        let rec = approved.recorded();
        assert_eq!(rec.len(), 4);
        for req in &rec {
            assert_signed(req);
        }
        assert_eq!(
            rec.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            ["/same", "/dest", "/away", "/down"]
        );
    }

    #[tokio::test]
    async fn retry_resends_exact_headers_to_the_same_destination() {
        let origin = TestOrigin::https();
        origin.hangup_then("/", 200, "text/html", "<html>retried</html>");
        let record = transport(&origin)
            .fetch(&origin.url(), ResourceKind::Page)
            .await
            .unwrap();
        assert_eq!(record.status, 200);
        let rec = origin.recorded();
        assert_eq!(rec.len(), 2);
        assert_eq!(rec[0].path, "/");
        assert_eq!(rec[1].path, "/");
        assert_eq!(rec[0].host, rec[1].host);
        for req in &rec {
            assert_eq!(req.scheme, "https");
            assert_signed(req);
        }
    }

    #[tokio::test]
    async fn missing_or_malformed_credentials_fail_before_sending() {
        let origin = TestOrigin::https();
        origin.on("/", 200, "text/html", "<html>no</html>");
        assert!(WebBotAuth::new("", SIGNATURE_INPUT, AGENT).is_err());
        assert!(WebBotAuth::new(SIGNATURE, "bad", AGENT).is_err());
        assert!(origin.recorded().is_empty());
    }

    #[tokio::test]
    async fn status_diagnostics_separate_observation_from_cause_and_redact_secrets() {
        let origin = TestOrigin::https();
        origin.on("/401", 401, "text/plain", "nope");
        origin.on("/403", 403, "text/plain", "nope");
        origin.status_retry_after("/429", 429, "12");
        let t = transport(&origin);
        let e401 = t
            .fetch(&origin_path(&origin.url(), "/401"), ResourceKind::Page)
            .await
            .unwrap_err();
        let e403 = t
            .fetch(&origin_path(&origin.url(), "/403"), ResourceKind::Page)
            .await
            .unwrap_err();
        let e429 = t
            .fetch(&origin_path(&origin.url(), "/429"), ResourceKind::Page)
            .await
            .unwrap_err();
        for err in [&e401, &e403, &e429] {
            let text = err.to_string();
            assert!(text.contains("Observation:"), "{text}");
            assert!(text.contains("Suspected cause:"), "{text}");
            assert!(!text.contains(SIGNATURE), "{text}");
            assert!(!text.contains("TESTSIGNATUREVALUE"), "{text}");
            assert!(!text.contains("keyid="), "{text}");
            assert!(!format!("{err:?}").contains("TESTSIGNATUREVALUE"));
        }
        assert!(e401.observation().contains("HTTP 401"));
        assert!(e403.observation().contains("HTTP 403"));
        assert!(e429.observation().contains("HTTP 429"));
        assert!(e429.observation().contains("Retry-After=12"));
        assert!(e429.suspected_cause().unwrap().contains("independent"));
        assert!(e401.suspected_cause().unwrap().contains("not proof"));
        for req in origin.recorded() {
            assert_signed(&req);
        }
    }

    #[tokio::test]
    async fn preflight_records_access_evidence_without_claiming_crypto_proof() {
        let origin = TestOrigin::https();
        origin.on("/", 200, "text/html", "<html>store</html>");
        origin.on(
            "/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nDisallow:\n",
        );
        origin.on("/sitemap.xml", 404, "text/plain", "missing");
        let profile = profile_for(&origin);
        let probe = transport(&origin).sample_access(&profile).await.unwrap();
        assert_eq!(probe.status, 200);
        assert_eq!(probe.samples.len(), 3);
        assert_eq!(probe.samples[0].resource_kind, ResourceKind::Page);
        assert_eq!(probe.samples[1].resource_kind, ResourceKind::Robots);
        assert_eq!(probe.samples[2].resource_kind, ResourceKind::Sitemap);
        assert_eq!(probe.samples[2].status, 404);
        assert_eq!(probe.evidence_note, CRYPTO_VERIFICATION_LIMITATION);
        assert!(!probe.evidence_note.to_lowercase().contains("verified"));
        assert!(
            probe
                .evidence_note
                .contains("not proof of cryptographic verification")
        );
        assert!(!format!("{probe:?}").contains("TESTSIGNATUREVALUE"));
        assert!(CREDENTIAL_REPLACEMENT_PLAN.contains("Do not store secrets"));
        assert!(!probe.robots.bypass_robots);
        assert!(matches!(probe.start_url_access, UrlAccess::Allowed { .. }));
        for req in origin.recorded() {
            assert_signed(&req);
        }
    }

    #[tokio::test]
    async fn robots_denial_does_not_fetch_the_page_or_look_like_a_broken_page() {
        let origin = TestOrigin::https();
        origin.on("/", 200, "text/html", "<html>secret</html>");
        origin.on(
            "/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nDisallow: /\n",
        );
        origin.on("/sitemap.xml", 200, "application/xml", "<urlset></urlset>");
        let profile = profile_for(&origin);
        let probe = transport(&origin).sample_access(&profile).await.unwrap();
        assert!(matches!(
            probe.start_url_access,
            UrlAccess::Blocked(ref evidence)
                if evidence.kind == crate::robots::BlockKind::RobotsTxt
                    && evidence.note.contains("not a broken page")
        ));
        assert_eq!(probe.status, 0);
        assert!(
            !probe
                .samples
                .iter()
                .any(|s| s.resource_kind == ResourceKind::Page)
        );
        assert!(
            probe
                .samples
                .iter()
                .any(|s| s.resource_kind == ResourceKind::Robots)
        );
        let paths: Vec<_> = origin.recorded().iter().map(|r| r.path.clone()).collect();
        assert!(paths.contains(&"/robots.txt".into()), "{paths:?}");
        assert!(
            !paths.iter().any(|p| p == "/"),
            "page must not be fetched: {paths:?}"
        );
        assert!(!paths.iter().any(|p| p == "/sitemap.xml"), "{paths:?}");
        for req in origin.recorded() {
            assert_signed(&req);
        }
    }

    #[tokio::test]
    async fn owner_robots_bypass_is_retained_and_still_signs() {
        let origin = TestOrigin::https();
        origin.on("/", 200, "text/html", "<html>override</html>");
        origin.on(
            "/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nDisallow: /\n",
        );
        origin.on("/sitemap.xml", 404, "text/plain", "missing");
        let mut profile = profile_for(&origin);
        profile.bypass_robots = true;
        let probe = transport(&origin).sample_access(&profile).await.unwrap();
        assert!(probe.robots.bypass_robots);
        assert!(!probe.robots.bypass_meta);
        assert!(matches!(
            probe.start_url_access,
            UrlAccess::Allowed {
                reason: crate::robots::AllowReason::OwnerAuditBypass { .. }
            }
        ));
        assert_eq!(probe.status, 200);
        assert!(
            probe
                .samples
                .iter()
                .any(|s| s.resource_kind == ResourceKind::Page)
        );
        for req in origin.recorded() {
            assert_signed(&req);
        }
    }

    #[tokio::test]
    async fn unavailable_robots_allows_fetch_without_calling_it_a_denial() {
        let origin = TestOrigin::https();
        origin.on("/", 200, "text/html", "<html>up</html>");
        origin.on("/robots.txt", 500, "text/plain", "nope");
        origin.on("/sitemap.xml", 200, "application/xml", "<urlset></urlset>");
        let profile = profile_for(&origin);
        let probe = transport(&origin).sample_access(&profile).await.unwrap();
        assert!(matches!(
            probe.start_url_access,
            UrlAccess::Allowed {
                reason: crate::robots::AllowReason::RobotsUnavailable
            }
        ));
        assert_eq!(probe.status, 200);
        assert!(matches!(
            probe.robots.fetch,
            crate::robots::RobotsFetchState::Unavailable { .. }
        ));
    }

    #[tokio::test]
    #[ignore = "contacts the live storefront; credentials stay on the execution machine"]
    async fn live_tiendacables_small_sample_is_not_crypto_proof() {
        crate::load_dotenv().unwrap();
        let profile = Profile::load(include_str!("../../../profile.example.toml")).unwrap();
        let auth = WebBotAuth::from_profile(&profile).expect("live sample needs local credentials");
        let probe = SignedTransport::new(&profile, &auth)
            .unwrap()
            .sample_access(&profile)
            .await
            .unwrap();
        assert_eq!(probe.evidence_note, CRYPTO_VERIFICATION_LIMITATION);
        assert_eq!(probe.status, 200);
        assert!(
            probe
                .samples
                .iter()
                .all(|sample| sample.credentials_attached)
        );
        assert!(!format!("{probe:?}").contains("sig1="));
        assert!(!format!("{probe:?}").contains("TESTSIGNATUREVALUE"));
    }
}
