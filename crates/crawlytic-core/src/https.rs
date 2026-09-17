//! HTTPS host probes and TLS certificate inspections.
//!
//! Host probes never attach Web Bot Auth headers. Certificate inspection uses
//! rustls with webpki roots; verification is not disabled. The presented
//! certificate is recorded even when verification fails.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, StreamOwned};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use x509_parser::prelude::*;

/// rustls + Mozilla webpki roots. Verification stays enabled.
pub const TLS_VERIFIER: &str = "rustls-webpki";
/// Static mixed content is read from HTML img/script/style hrefs.
pub const MIXED_CONTENT_STATIC_COVERAGE: &str = "static-html";
/// JavaScript-injected mixed content is not observed without rendering.
pub const MIXED_CONTENT_DYNAMIC_COVERAGE: &str = "incomplete-without-rendering";
/// Crawlytic warning window, not a Semrush formula.
pub const DEFAULT_DAYS_BEFORE_EXPIRY: u32 = 14;
/// Per-address TCP connect budget so a blackholed AAAA record cannot freeze a run.
pub const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostProbeKind {
    HttpHomepage,
    HttpsWww,
    HttpsApex,
}

impl HostProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpHomepage => "http_homepage",
            Self::HttpsWww => "https_www",
            Self::HttpsApex => "https_apex",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "http_homepage" => Some(Self::HttpHomepage),
            "https_www" => Some(Self::HttpsWww),
            "https_apex" => Some(Self::HttpsApex),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbe {
    pub kind: HostProbeKind,
    pub requested_url: String,
    pub destination_url: Option<String>,
    pub status: Option<u16>,
    pub redirect_chain: Vec<crate::extract::RedirectHop>,
    pub canonicals: Vec<String>,
    pub failed_reason: Option<String>,
    pub credentials_attached: bool,
}

impl HostProbe {
    pub fn redirected_to_https(&self) -> bool {
        let hop_upgrade = self
            .redirect_chain
            .iter()
            .any(|hop| hop.from.starts_with("http://") && hop.to.starts_with("https://"));
        let dest_upgrade = self.requested_url.starts_with("http://")
            && self
                .destination_url
                .as_deref()
                .is_some_and(|url| url.starts_with("https://"));
        hop_upgrade || dest_upgrade
    }

    pub fn canonical_https(&self) -> bool {
        self.canonicals
            .iter()
            .any(|value| value.trim().starts_with("https://"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInspection {
    pub host: String,
    pub port: u16,
    pub inspected: bool,
    pub verified: bool,
    pub hostname_ok: bool,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
    pub names: Vec<String>,
    pub error: Option<String>,
    pub credentials_attached: bool,
}

pub fn production_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Inspect `host:port` with Mozilla webpki roots. Never disables verification.
pub fn inspect_tls(host: &str, port: u16) -> TlsInspection {
    inspect_tls_with_roots(host, port, host, production_roots())
}

pub(crate) fn inspect_tls_with_roots(
    connect_host: &str,
    port: u16,
    server_name: &str,
    roots: RootCertStore,
) -> TlsInspection {
    ensure_crypto_provider();
    let mut inspection = TlsInspection {
        host: server_name.to_owned(),
        port,
        inspected: false,
        verified: false,
        hostname_ok: false,
        not_before_unix: None,
        not_after_unix: None,
        names: Vec::new(),
        error: None,
        credentials_attached: false,
    };
    let Ok(name) = ServerName::try_from(server_name.to_owned()) else {
        inspection.error = Some(format!("Unusable TLS server name {server_name}"));
        return inspection;
    };
    let inner = match rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build() {
        Ok(inner) => inner,
        Err(err) => {
            inspection.error = Some(format!("TLS verifier could not be built: {err}"));
            return inspection;
        }
    };
    let recorder = Arc::new(RecordingVerifier {
        inner,
        presented: Mutex::new(None),
    });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let Ok(client) = ClientConnection::new(Arc::new(config), name) else {
        inspection.error = Some(format!("TLS client could not be created for {server_name}"));
        return inspection;
    };
    let addr = format!("{connect_host}:{port}");
    let stream = match connect_tls_stream(connect_host, port) {
        Ok(stream) => stream,
        Err(err) => {
            inspection.error = Some(format!("Connection failed to {addr}: {err}"));
            return inspection;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));
    let mut tls = StreamOwned::new(client, stream);
    let handshake = tls
        .write_all(b"HEAD / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .and_then(|_| tls.flush());
    let mut presented = recorder
        .presented
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    if let Some(cert) = presented.take() {
        fill_from_cert(&mut inspection, &cert);
    } else if let Err(err) = handshake {
        inspection.error = Some(format!("TLS handshake failed to {addr}: {err}"));
    } else {
        inspection.error = Some(format!("TLS handshake produced no certificate from {addr}"));
    }
    inspection
}

fn fill_from_cert(inspection: &mut TlsInspection, cert: &PresentedCert) {
    inspection.inspected = true;
    inspection.verified = cert.verified;
    inspection.hostname_ok = cert.hostname_ok;
    inspection.error = cert.error.clone();
    if let Ok((_, parsed)) = X509Certificate::from_der(&cert.der) {
        inspection.not_before_unix = Some(parsed.validity().not_before.timestamp());
        inspection.not_after_unix = Some(parsed.validity().not_after.timestamp());
        inspection.names = certificate_names(&parsed);
        if !inspection.hostname_ok {
            inspection.hostname_ok = names_include_host(&inspection.names, &inspection.host);
        }
    }
}

fn certificate_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut names = Vec::new();
    for cn in cert.subject().iter_common_name() {
        if let Ok(value) = cn.as_str() {
            push_name(&mut names, value);
        }
    }
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            if let GeneralName::DNSName(value) = name {
                push_name(&mut names, value);
            }
        }
    }
    names
}

fn push_name(names: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if !names
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(value))
    {
        names.push(value.to_owned());
    }
}

pub(crate) fn names_include_host(names: &[String], host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    names.iter().any(|name| {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if name == host {
            return true;
        }
        let Some(rest) = name.strip_prefix("*.") else {
            return false;
        };
        let Some(label) = host.strip_suffix(rest) else {
            return false;
        };
        let label = label.strip_suffix('.').unwrap_or(label);
        !label.is_empty() && !label.contains('.')
    })
}

fn connect_tls_stream(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut last = None;
    let mut resolved = false;
    for addr in (host, port).to_socket_addrs()? {
        resolved = true;
        match TcpStream::connect_timeout(&addr, TLS_CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            if resolved {
                format!("No usable address for {host}:{port}")
            } else {
                format!("DNS lookup failed for {host}:{port}")
            },
        )
    }))
}

fn ensure_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Debug)]
struct PresentedCert {
    der: Vec<u8>,
    verified: bool,
    hostname_ok: bool,
    error: Option<String>,
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    presented: Mutex<Option<PresentedCert>>,
}

impl RecordingVerifier {
    fn record(
        &self,
        end_entity: &CertificateDer<'_>,
        result: &Result<ServerCertVerified, TlsError>,
    ) {
        let (verified, hostname_ok, error) = match result {
            Ok(_) => (true, true, None),
            Err(err) => {
                let hostname_ok = !matches!(
                    err,
                    TlsError::InvalidCertificate(
                        CertificateError::NotValidForName
                            | CertificateError::NotValidForNameContext { .. }
                    )
                );
                (false, hostname_ok, Some(err.to_string()))
            }
        };
        if let Ok(mut slot) = self.presented.lock() {
            *slot = Some(PresentedCert {
                der: end_entity.as_ref().to_vec(),
                verified,
                hostname_ok,
                error,
            });
        }
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        self.record(end_entity, &result);
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn apex_and_www(host: &str) -> Option<(String, String)> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if let Some(apex) = host.strip_prefix("www.") {
        if apex.is_empty() || apex.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        Some((apex.to_owned(), host.to_owned()))
    } else {
        Some((host.to_owned(), format!("www.{host}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::ServerConfig;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::thread;

    fn ca() -> (CertificateParams, KeyPair, RootCertStore) {
        ensure_crypto_provider();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["test-ca".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        (params, key, roots)
    }

    fn leaf(
        ca_params: &CertificateParams,
        ca_key: &KeyPair,
        sans: Vec<String>,
        not_after_year: i32,
    ) -> (Vec<u8>, KeyPair) {
        let issuer = Issuer::from_params(ca_params, ca_key);
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(sans).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        let cert = params.signed_by(&key, &issuer).unwrap();
        (cert.der().as_ref().to_vec(), key)
    }

    fn serve(cert_der: Vec<u8>, key: KeyPair) -> SocketAddr {
        ensure_crypto_provider();
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(conn, stream);
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        addr
    }

    #[test]
    fn expired_and_mismatched_certificates_are_inspected_with_verification_on() {
        let (ca_params, ca_key, roots) = ca();
        let (expired_der, expired_key) = leaf(&ca_params, &ca_key, vec!["localhost".into()], 2021);
        let expired_addr = serve(expired_der, expired_key);
        let expired =
            inspect_tls_with_roots("127.0.0.1", expired_addr.port(), "localhost", roots.clone());
        assert!(expired.inspected, "{expired:?}");
        assert!(!expired.verified, "{expired:?}");
        assert!(
            expired.not_after_unix.unwrap() < 1_700_000_000,
            "{expired:?}"
        );
        assert!(
            expired
                .error
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("expir")
                || expired.not_after_unix.unwrap()
                    < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
            "{expired:?}"
        );
        assert!(!expired.credentials_attached);
        assert_eq!(TLS_VERIFIER, "rustls-webpki");

        let (mismatch_der, mismatch_key) =
            leaf(&ca_params, &ca_key, vec!["other.example".into()], 4096);
        let mismatch_addr = serve(mismatch_der, mismatch_key);
        let mismatch = inspect_tls_with_roots(
            "127.0.0.1",
            mismatch_addr.port(),
            "localhost",
            roots.clone(),
        );
        assert!(mismatch.inspected, "{mismatch:?}");
        assert!(!mismatch.verified, "{mismatch:?}");
        assert!(!mismatch.hostname_ok, "{mismatch:?}");
        assert!(
            mismatch.names.iter().any(|name| name == "other.example"),
            "{mismatch:?}"
        );

        let (ok_der, ok_key) = leaf(&ca_params, &ca_key, vec!["localhost".into()], 4096);
        let ok_addr = serve(ok_der, ok_key);
        let ok = inspect_tls_with_roots("127.0.0.1", ok_addr.port(), "localhost", roots);
        assert!(ok.inspected, "{ok:?}");
        assert!(ok.verified, "{ok:?}");
        assert!(ok.hostname_ok, "{ok:?}");
        assert!(ok.names.iter().any(|name| name == "localhost"), "{ok:?}");
        assert!(!format!("{ok:?}").contains("CRAWL_SIGNATURE"));
        assert!(!format!("{ok:?}").contains("sig1="));
    }

    #[test]
    fn production_roots_are_webpki_and_not_empty() {
        assert!(!production_roots().is_empty());
        assert_eq!(
            MIXED_CONTENT_DYNAMIC_COVERAGE,
            "incomplete-without-rendering"
        );
        assert_eq!(MIXED_CONTENT_STATIC_COVERAGE, "static-html");
    }

    #[test]
    fn wildcard_names_match_one_label() {
        assert!(names_include_host(
            &["*.audit.example".into()],
            "www.audit.example"
        ));
        assert!(!names_include_host(
            &["*.audit.example".into()],
            "audit.example"
        ));
        assert!(!names_include_host(
            &["*.audit.example".into()],
            "a.b.audit.example"
        ));
    }

    #[test]
    fn redirect_and_canonical_are_distinct_observations() {
        let redirect = HostProbe {
            kind: HostProbeKind::HttpHomepage,
            requested_url: "http://audit.example/".into(),
            destination_url: Some("https://audit.example/".into()),
            status: Some(200),
            redirect_chain: vec![crate::extract::RedirectHop {
                from: "http://audit.example/".into(),
                to: "https://audit.example/".into(),
                status: 301,
            }],
            canonicals: vec!["https://audit.example/".into()],
            failed_reason: None,
            credentials_attached: false,
        };
        assert!(redirect.redirected_to_https());
        let canonical_only = HostProbe {
            kind: HostProbeKind::HttpHomepage,
            requested_url: "http://audit.example/".into(),
            destination_url: Some("http://audit.example/".into()),
            status: Some(200),
            redirect_chain: Vec::new(),
            canonicals: vec!["https://audit.example/".into()],
            failed_reason: None,
            credentials_attached: false,
        };
        assert!(!canonical_only.redirected_to_https());
        assert!(canonical_only.canonical_https());
    }

    #[test]
    fn unreachable_address_does_not_block_indefinitely() {
        let started = std::time::Instant::now();
        let inspection = inspect_tls("192.0.2.1", 443);
        assert!(
            started.elapsed() < TLS_CONNECT_TIMEOUT + Duration::from_secs(3),
            "connect took {:?}",
            started.elapsed()
        );
        assert!(!inspection.inspected, "{inspection:?}");
        assert!(inspection.error.is_some(), "{inspection:?}");
        assert!(!inspection.credentials_attached);
    }
}
