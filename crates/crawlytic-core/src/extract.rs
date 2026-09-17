//! Versioned page, link and resource observations.
//!
//! Audit rules share this evidence and must not refetch pages. The schema has
//! no severity, recommendation or UI fields. Truncated, challenge, error and
//! non-HTML bodies are extracted when possible but never marked complete.

use url::Url;

pub const EXTRACTION_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationFlags {
    pub truncated: bool,
    pub challenge: bool,
    pub error_status: bool,
    pub non_html: bool,
    pub encoding_fallback: bool,
}

impl ObservationFlags {
    pub fn is_complete(self) -> bool {
        !self.truncated
            && !self.challenge
            && !self.error_status
            && !self.non_html
            && !self.encoding_fallback
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOwner {
    SameHost,
    OtherHost,
    Opaque,
}

impl HostOwner {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameHost => "same_host",
            Self::OtherHost => "other_host",
            Self::Opaque => "opaque",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "same_host" => Some(Self::SameHost),
            "other_host" => Some(Self::OtherHost),
            "opaque" => Some(Self::Opaque),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedKind {
    Image,
    Script,
    Style,
}

impl EmbeddedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Script => "script",
            Self::Style => "style",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "image" => Some(Self::Image),
            "script" => Some(Self::Script),
            "style" => Some(Self::Style),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heading {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hreflang {
    pub lang: String,
    pub href: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectHop {
    pub from: String,
    pub to: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageObservation {
    pub schema_version: u32,
    pub flags: ObservationFlags,
    pub status: u16,
    pub content_type: String,
    pub duration_ms: Option<u64>,
    pub raw_bytes: u64,
    pub decoded_bytes: u64,
    pub encoding: String,
    pub charset_declared: bool,
    pub doctype: Option<String>,
    pub html_lang: Option<String>,
    pub titles: Vec<String>,
    pub descriptions: Vec<String>,
    pub headings: Vec<Heading>,
    pub robots_meta: Vec<String>,
    pub robots_headers: Vec<String>,
    pub canonicals: Vec<String>,
    pub hreflangs: Vec<Hreflang>,
    pub viewport: Option<String>,
    pub has_frames: bool,
    pub has_plugin_markup: bool,
    pub meta_refresh: Vec<String>,
    pub text: String,
}

impl PageObservation {
    pub fn is_complete(&self) -> bool {
        self.flags.is_complete()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkObservation {
    pub source: String,
    pub href: String,
    pub destination: Option<String>,
    pub anchor: String,
    pub rel: String,
    pub element: String,
    pub host_owner: HostOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceObservation {
    pub referring: String,
    pub kind: EmbeddedKind,
    pub href: String,
    pub destination: Option<String>,
    pub alt: Option<String>,
    pub host_owner: HostOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedObservations {
    pub schema_version: u32,
    pub identity: String,
    pub page: PageObservation,
    pub links: Vec<LinkObservation>,
    pub resources: Vec<ResourceObservation>,
    pub redirect_chain: Vec<RedirectHop>,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractInput<'a> {
    pub destination_url: &'a Url,
    pub status: u16,
    pub content_type: &'a str,
    pub headers: &'a [ExtractHeader<'a>],
    pub body: &'a [u8],
    pub truncated: bool,
    pub duration_ms: Option<u64>,
}

pub fn extract(input: &ExtractInput<'_>) -> ExtractedObservations {
    let identity = input.destination_url.as_str().to_owned();
    let (decoded, encoding, encoding_fallback) = decode_body(input.content_type, input.body);
    let decoded_bytes = decoded.len() as u64;
    let challenge = looks_like_challenge(&decoded);
    let error_status = input.status >= 400;
    let non_html = !is_html(input.content_type, &decoded);
    let flags = ObservationFlags {
        truncated: input.truncated,
        challenge,
        error_status,
        non_html,
        encoding_fallback,
    };
    let robots_headers = header_values(input.headers, "x-robots-tag");
    let mut canonicals = Vec::new();
    let mut hreflangs = Vec::new();
    for value in header_values(input.headers, "link") {
        parse_http_link(&value, &mut canonicals, &mut hreflangs);
    }

    let mut page = PageObservation {
        schema_version: EXTRACTION_SCHEMA_VERSION,
        flags,
        status: input.status,
        content_type: input.content_type.to_owned(),
        duration_ms: input.duration_ms,
        raw_bytes: input.body.len() as u64,
        decoded_bytes,
        encoding,
        charset_declared: charset_declared(input.content_type, input.body),
        doctype: None,
        html_lang: None,
        titles: Vec::new(),
        descriptions: Vec::new(),
        headings: Vec::new(),
        robots_meta: Vec::new(),
        robots_headers,
        canonicals,
        hreflangs,
        viewport: None,
        has_frames: false,
        has_plugin_markup: false,
        meta_refresh: Vec::new(),
        text: String::new(),
    };

    let mut links = Vec::new();
    let mut resources = Vec::new();
    if !non_html {
        parse_html(
            &decoded,
            input.destination_url,
            &identity,
            &mut page,
            &mut links,
            &mut resources,
        );
    }

    ExtractedObservations {
        schema_version: EXTRACTION_SCHEMA_VERSION,
        identity,
        page,
        links,
        resources,
        redirect_chain: Vec::new(),
    }
}

fn is_html(content_type: &str, decoded: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if let Some((media, _)) = ct.split_once(';') {
        let media = media.trim();
        if media == "text/html" || media == "application/xhtml+xml" {
            return true;
        }
        if !media.is_empty() {
            return false;
        }
    } else if !ct.trim().is_empty() {
        let media = ct.trim();
        if media == "text/html" || media == "application/xhtml+xml" {
            return true;
        }
        return false;
    }
    let lower = decoded.to_ascii_lowercase();
    lower.contains("<html") || lower.contains("<!doctype")
}

fn looks_like_challenge(decoded: &str) -> bool {
    let lower = decoded.to_ascii_lowercase();
    lower.contains("cf-chl-") || lower.contains("<title>just a moment")
}

fn header_values(headers: &[ExtractHeader<'_>], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn charset_declared(content_type: &str, body: &[u8]) -> bool {
    charset_from_content_type(content_type).is_some() || sniff_meta_charset(body).is_some()
}

fn charset_from_content_type(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    lower.split(';').skip(1).find_map(|part| {
        let part = part.trim();
        part.strip_prefix("charset=").map(|value| {
            value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_ascii_lowercase()
        })
    })
}

fn decode_body(content_type: &str, body: &[u8]) -> (String, String, bool) {
    let (bytes, bom) = if body.starts_with(&[0xef, 0xbb, 0xbf]) {
        (&body[3..], true)
    } else {
        (body, false)
    };
    let mut declared = charset_from_content_type(content_type);
    if declared.is_none() {
        declared = sniff_meta_charset(bytes);
    }
    if bom {
        declared = Some("utf-8".into());
    }
    let charset = declared.unwrap_or_else(|| "utf-8".into());
    match charset.as_str() {
        "utf-8" | "utf8" => match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_owned(), "utf-8".into(), false),
            Err(_) => (decode_windows_1252(bytes), "windows-1252".into(), true),
        },
        "iso-8859-1" | "latin1" | "latin-1" | "windows-1252" | "cp1252" => {
            (decode_windows_1252(bytes), charset, false)
        }
        _ => match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_owned(), charset, false),
            Err(_) => (decode_windows_1252(bytes), "windows-1252".into(), true),
        },
    }
}

fn sniff_meta_charset(bytes: &[u8]) -> Option<String> {
    let prefix = &bytes[..bytes.len().min(1024)];
    let ascii = String::from_utf8_lossy(prefix).to_ascii_lowercase();
    if let Some(idx) = ascii.find("charset=") {
        let rest = &ascii[idx + 8..];
        let rest = rest.trim_start_matches(['"', '\'', ' ']);
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            .unwrap_or(rest.len());
        let value = rest[..end].trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

fn decode_windows_1252(bytes: &[u8]) -> String {
    bytes.iter().copied().map(windows_1252_char).collect()
}

fn windows_1252_char(b: u8) -> char {
    match b {
        0x80 => '\u{20AC}',
        0x82 => '\u{201A}',
        0x83 => '\u{0192}',
        0x84 => '\u{201E}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02C6}',
        0x89 => '\u{2030}',
        0x8A => '\u{0160}',
        0x8B => '\u{2039}',
        0x8C => '\u{0152}',
        0x8E => '\u{017D}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201C}',
        0x94 => '\u{201D}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02DC}',
        0x99 => '\u{2122}',
        0x9A => '\u{0161}',
        0x9B => '\u{203A}',
        0x9C => '\u{0153}',
        0x9E => '\u{017E}',
        0x9F => '\u{0178}',
        0x81 | 0x8D | 0x8F | 0x90 | 0x9D => '\u{FFFD}',
        _ => char::from(b),
    }
}

fn parse_http_link(value: &str, canonicals: &mut Vec<String>, hreflangs: &mut Vec<Hreflang>) {
    for part in split_link_parts(value) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some(url_end) = part.find('>') else {
            continue;
        };
        if !part.starts_with('<') {
            continue;
        }
        let href = part[1..url_end].trim().to_owned();
        let params = part[url_end + 1..].to_ascii_lowercase();
        let rel = link_param(&params, "rel").unwrap_or_default();
        let rel_tokens: Vec<&str> = rel.split_whitespace().collect();
        if rel_tokens.contains(&"canonical") {
            canonicals.push(href.clone());
        }
        if let Some(lang) = link_param(&params, "hreflang")
            && rel_tokens.contains(&"alternate")
        {
            hreflangs.push(Hreflang { lang, href });
        }
    }
}

fn split_link_parts(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in value.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ',' if !quoted => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn link_param(params: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let bytes = params.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if params[i..].starts_with(&needle) {
            let mut j = i + needle.len();
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                let start = j;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                return Some(params[start..j].trim().to_owned());
            }
            let start = j;
            while j < bytes.len() && bytes[j] != b';' && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            return Some(params[start..j].trim().to_owned());
        }
        i += 1;
    }
    None
}

fn parse_html(
    html: &str,
    document_url: &Url,
    identity: &str,
    page: &mut PageObservation,
    links: &mut Vec<LinkObservation>,
    resources: &mut Vec<ResourceObservation>,
) {
    let bytes = html.as_bytes();
    let mut i = 0;
    let mut base_href = None;
    let mut text = String::new();
    while i < bytes.len() {
        if bytes[i] != b'<' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'<' {
                i += 1;
            }
            push_text(&mut text, &html[start..i]);
            continue;
        }
        if starts_with_ignore_ascii(bytes, i, b"<!--") {
            i += 4;
            while i < bytes.len() && !starts_with_ignore_ascii(bytes, i, b"-->") {
                i += 1;
            }
            i = i.saturating_add(3);
            continue;
        }
        if starts_with_ignore_ascii(bytes, i, b"<!doctype") {
            if let Some((end, inner)) = read_tag(bytes, i) {
                let declared = inner
                    .trim_start_matches([
                        '!', 'D', 'd', 'O', 'o', 'C', 'c', 'T', 't', 'Y', 'y', 'P', 'p', 'E', 'e',
                    ])
                    .trim()
                    .trim_end_matches('/')
                    .trim();
                if page.doctype.is_none() {
                    page.doctype = Some(normalize_space(declared));
                }
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"script") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                if let Some(src) = attr(&attrs, "src") {
                    push_resource(
                        resources,
                        identity,
                        document_url,
                        base_href.as_deref(),
                        EmbeddedKind::Script,
                        &src,
                        None,
                    );
                }
                i = skip_element_from(bytes, end, b"script");
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"style") {
            i = skip_element(bytes, i, b"style");
            continue;
        }
        if tag_opens(bytes, i, b"noscript") {
            i = skip_element(bytes, i, b"noscript");
            continue;
        }
        if tag_opens(bytes, i, b"html") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                if page.html_lang.is_none()
                    && let Some(lang) = attr(&attrs, "lang")
                {
                    page.html_lang = Some(lang);
                }
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"base") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                if base_href.is_none()
                    && let Some(href) = attr(&attrs, "href")
                {
                    base_href = Some(href);
                }
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"title") {
            if let Some((end, _)) = read_tag(bytes, i) {
                let (inner, next) = read_until_close(bytes, end, b"title");
                let value = normalize_space(&decode_entities(&strip_tags(&inner)));
                if !value.is_empty() {
                    page.titles.push(value);
                } else {
                    page.titles.push(String::new());
                }
                i = next;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"meta") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                apply_meta(page, &attrs);
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"link") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                apply_link_tag(
                    page,
                    resources,
                    identity,
                    document_url,
                    base_href.as_deref(),
                    &attrs,
                );
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"a") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                let (inner, next) = read_until_close(bytes, end, b"a");
                if let Some(href) = attr(&attrs, "href") {
                    let anchor = accessible_name(&inner);
                    let rel = attr(&attrs, "rel").unwrap_or_default();
                    push_link(
                        links,
                        identity,
                        document_url,
                        base_href.as_deref(),
                        &href,
                        &anchor,
                        &rel,
                        "a",
                    );
                }
                push_text(&mut text, &strip_tags(&inner));
                i = next;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"area") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                if let Some(href) = attr(&attrs, "href") {
                    let anchor = attr(&attrs, "alt").unwrap_or_default();
                    let rel = attr(&attrs, "rel").unwrap_or_default();
                    push_link(
                        links,
                        identity,
                        document_url,
                        base_href.as_deref(),
                        &href,
                        &anchor,
                        &rel,
                        "area",
                    );
                }
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"frameset") || tag_opens(bytes, i, b"frame") {
            page.has_frames = true;
            if let Some((end, _)) = read_tag(bytes, i) {
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"embed")
            || tag_opens(bytes, i, b"object")
            || tag_opens(bytes, i, b"applet")
        {
            page.has_plugin_markup = true;
            if let Some((end, _)) = read_tag(bytes, i) {
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if tag_opens(bytes, i, b"img") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                if let Some(src) = attr(&attrs, "src") {
                    push_resource(
                        resources,
                        identity,
                        document_url,
                        base_href.as_deref(),
                        EmbeddedKind::Image,
                        &src,
                        attr(&attrs, "alt"),
                    );
                }
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        if let Some(level) = heading_level(bytes, i) {
            if let Some((end, _)) = read_tag(bytes, i) {
                let name = [b'h', b'0' + level];
                let (inner, next) = read_until_close(bytes, end, &name);
                let value = normalize_space(&decode_entities(&strip_tags(&inner)));
                page.headings.push(Heading {
                    level,
                    text: value.clone(),
                });
                push_text(&mut text, &value);
                i = next;
            } else {
                i += 1;
            }
            continue;
        }
        if let Some((end, _)) = read_tag(bytes, i) {
            i = end;
        } else {
            i += 1;
        }
    }
    page.text = normalize_space(&decode_entities(&text));
}

fn apply_meta(page: &mut PageObservation, attrs: &str) {
    if attr(attrs, "charset")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        page.charset_declared = true;
    }
    let name = attr(attrs, "name")
        .or_else(|| attr(attrs, "http-equiv"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let content = attr(attrs, "content").unwrap_or_default();
    match name.as_str() {
        "description" => page
            .descriptions
            .push(normalize_space(&decode_entities(&content))),
        "robots" | "googlebot" => {
            if !content.trim().is_empty() {
                page.robots_meta.push(content.trim().to_owned());
            }
        }
        "viewport" if page.viewport.is_none() => {
            page.viewport = Some(content.trim().to_owned());
        }
        "content-type" if charset_from_content_type(&content).is_some() => {
            page.charset_declared = true;
        }
        "refresh" if !content.trim().is_empty() => {
            page.meta_refresh.push(content.trim().to_owned());
        }
        _ => {}
    }
}

fn apply_link_tag(
    page: &mut PageObservation,
    resources: &mut Vec<ResourceObservation>,
    identity: &str,
    document_url: &Url,
    base_href: Option<&str>,
    attrs: &str,
) {
    let rel = attr(attrs, "rel").unwrap_or_default().to_ascii_lowercase();
    let href = attr(attrs, "href").unwrap_or_default();
    let tokens: Vec<&str> = rel.split_whitespace().collect();
    if tokens.contains(&"canonical") && !href.is_empty() {
        page.canonicals.push(href.clone());
    }
    if tokens.contains(&"alternate")
        && let Some(lang) = attr(attrs, "hreflang")
        && !href.is_empty()
    {
        page.hreflangs.push(Hreflang {
            lang,
            href: href.clone(),
        });
    }
    if tokens.contains(&"stylesheet") && !href.is_empty() {
        push_resource(
            resources,
            identity,
            document_url,
            base_href,
            EmbeddedKind::Style,
            &href,
            None,
        );
    }
}

fn heading_level(bytes: &[u8], i: usize) -> Option<u8> {
    if !tag_opens(bytes, i, b"h1")
        && !tag_opens(bytes, i, b"h2")
        && !tag_opens(bytes, i, b"h3")
        && !tag_opens(bytes, i, b"h4")
        && !tag_opens(bytes, i, b"h5")
        && !tag_opens(bytes, i, b"h6")
    {
        return None;
    }
    let mut j = i + 1;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if j + 1 < bytes.len() && (bytes[j] == b'h' || bytes[j] == b'H') {
        let level = bytes[j + 1];
        if (b'1'..=b'6').contains(&level) {
            return Some(level - b'0');
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn push_link(
    links: &mut Vec<LinkObservation>,
    identity: &str,
    document_url: &Url,
    base_href: Option<&str>,
    href: &str,
    anchor: &str,
    rel: &str,
    element: &str,
) {
    let (destination, host_owner) = resolve_owner(document_url, base_href, href);
    links.push(LinkObservation {
        source: identity.to_owned(),
        href: href.to_owned(),
        destination,
        anchor: normalize_space(anchor),
        rel: rel.trim().to_owned(),
        element: element.to_owned(),
        host_owner,
    });
}

fn push_resource(
    resources: &mut Vec<ResourceObservation>,
    identity: &str,
    document_url: &Url,
    base_href: Option<&str>,
    kind: EmbeddedKind,
    href: &str,
    alt: Option<String>,
) {
    let (destination, host_owner) = resolve_owner(document_url, base_href, href);
    resources.push(ResourceObservation {
        referring: identity.to_owned(),
        kind,
        href: href.to_owned(),
        destination,
        alt,
        host_owner,
    });
}

fn resolve_owner(
    document_url: &Url,
    base_href: Option<&str>,
    href: &str,
) -> (Option<String>, HostOwner) {
    let href = href.trim();
    if href.is_empty() {
        return (None, HostOwner::Opaque);
    }
    let base = match base_href.map(str::trim).filter(|value| !value.is_empty()) {
        Some(base_href) => document_url
            .join(base_href)
            .unwrap_or_else(|_| document_url.clone()),
        None => document_url.clone(),
    };
    let Ok(resolved) = base.join(href) else {
        return (None, HostOwner::Opaque);
    };
    if !matches!(resolved.scheme(), "http" | "https") {
        return (Some(resolved.to_string()), HostOwner::Opaque);
    }
    let owner = if resolved.host_str() == document_url.host_str()
        && resolved.port_or_known_default() == document_url.port_or_known_default()
    {
        HostOwner::SameHost
    } else {
        HostOwner::OtherHost
    };
    (Some(resolved.to_string()), owner)
}

fn push_text(out: &mut String, chunk: &str) {
    if !chunk.is_empty() {
        out.push(' ');
        out.push_str(chunk);
    }
}

fn strip_tags(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut i = 0;
    let mut out = String::new();
    while i < bytes.len() {
        if bytes[i] == b'<'
            && let Some((end, _)) = read_tag(bytes, i)
        {
            i = end;
            out.push(' ');
            continue;
        }
        let start = i;
        i += 1;
        while i < bytes.len() && bytes[i] != b'<' {
            i += 1;
        }
        out.push_str(&html[start..i]);
    }
    out
}

fn normalize_space(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        if let Some(end) = rest.find(';') {
            let entity = &rest[1..end];
            if let Some(ch) = entity_char(entity) {
                out.push(ch);
                rest = &rest[end + 1..];
                continue;
            }
        }
        out.push('&');
        rest = &rest[1..];
    }
    out.push_str(rest);
    out
}

fn entity_char(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{00A0}'),
        _ if let Some(num) = entity.strip_prefix('#') => {
            let value = if let Some(hex) = num.strip_prefix(['x', 'X']) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                num.parse().ok()
            };
            value.and_then(char::from_u32)
        }
        _ => None,
    }
}

fn starts_with_ignore_ascii(bytes: &[u8], i: usize, needle: &[u8]) -> bool {
    let Some(slice) = bytes.get(i..i + needle.len()) else {
        return false;
    };
    slice.eq_ignore_ascii_case(needle)
}

fn tag_opens(bytes: &[u8], i: usize, name: &[u8]) -> bool {
    if !starts_with_ignore_ascii(bytes, i, b"<") {
        return false;
    }
    let mut j = i + 1;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'/' {
        return false;
    }
    if let Some(colon) = bytes.get(j..).and_then(|rest| {
        rest.iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-' || **b == b'_' || **b == b':')
            .position(|b| *b == b':')
    }) {
        let local = j + colon + 1;
        if starts_with_ignore_ascii(bytes, local, name) {
            let after = local + name.len();
            return after == bytes.len()
                || matches!(bytes[after], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>');
        }
    }
    if !starts_with_ignore_ascii(bytes, j, name) {
        return false;
    }
    let after = j + name.len();
    after == bytes.len() || matches!(bytes[after], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>')
}

fn accessible_name(inner: &str) -> String {
    let text = normalize_space(&decode_entities(&strip_tags(inner)));
    if !text.is_empty() {
        return text;
    }
    let bytes = inner.as_bytes();
    let mut i = 0;
    let mut alts = Vec::new();
    while i < bytes.len() {
        if tag_opens(bytes, i, b"img")
            && let Some((end, attrs)) = read_tag(bytes, i)
        {
            if let Some(alt) = attr(&attrs, "alt") {
                let alt = normalize_space(&decode_entities(&alt));
                if !alt.is_empty() {
                    alts.push(alt);
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    alts.join(" ")
}

fn skip_element(bytes: &[u8], start: usize, name: &[u8]) -> usize {
    let Some((end, _)) = read_tag(bytes, start) else {
        return start + 1;
    };
    skip_element_from(bytes, end, name)
}

fn skip_element_from(bytes: &[u8], start: usize, name: &[u8]) -> usize {
    let mut i = start;
    let close = {
        let mut v = b"</".to_vec();
        v.extend_from_slice(name);
        v
    };
    while i < bytes.len() {
        if starts_with_ignore_ascii(bytes, i, &close) {
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            return i.saturating_add(1);
        }
        i += 1;
    }
    bytes.len()
}

fn read_tag(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    if start >= bytes.len() || bytes[start] != b'<' {
        return None;
    }
    let mut i = start + 1;
    let mut quote = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'>' {
            let attrs = String::from_utf8_lossy(&bytes[start + 1..i]).into_owned();
            return Some((i + 1, attrs));
        }
        i += 1;
    }
    Some((
        bytes.len(),
        String::from_utf8_lossy(&bytes[start + 1..]).into_owned(),
    ))
}

fn attr(tag_inner: &str, name: &str) -> Option<String> {
    let bytes = tag_inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'-' | b'_' | b':'))
        {
            i += 1;
        }
        let attr_name = tag_inner[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let vstart = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                let value = tag_inner[vstart..i].to_owned();
                if i < bytes.len() {
                    i += 1;
                }
                value
            } else {
                let vstart = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/' {
                    i += 1;
                }
                tag_inner[vstart..i].to_owned()
            }
        } else {
            String::new()
        };
        if attr_name == name {
            return Some(decode_entities(&value));
        }
    }
    None
}

fn read_until_close(bytes: &[u8], start: usize, name: &[u8]) -> (String, usize) {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'<' && starts_with_ignore_ascii(bytes, i, b"</") {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if let Some(colon) = bytes.get(j..).and_then(|rest| {
                rest.iter()
                    .take_while(|b| {
                        b.is_ascii_alphanumeric() || **b == b'-' || **b == b'_' || **b == b':'
                    })
                    .position(|b| *b == b':')
            }) {
                j += colon + 1;
            }
            if starts_with_ignore_ascii(bytes, j, name) {
                let text = String::from_utf8_lossy(&bytes[start..i]).into_owned();
                while i < bytes.len() && bytes[i] != b'>' {
                    i += 1;
                }
                return (text, i.saturating_add(1));
            }
        }
        i += 1;
    }
    (
        String::from_utf8_lossy(&bytes[start..]).into_owned(),
        bytes.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url() -> Url {
        Url::parse("https://www.tiendacables.com/es/cables").unwrap()
    }

    fn extract_html(html: &str) -> ExtractedObservations {
        extract_html_status(200, "text/html", html.as_bytes(), false)
    }

    fn extract_html_status(
        status: u16,
        content_type: &str,
        body: &[u8],
        truncated: bool,
    ) -> ExtractedObservations {
        let destination = url();
        extract(&ExtractInput {
            destination_url: &destination,
            status,
            content_type,
            headers: &[],
            body,
            truncated,
            duration_ms: Some(12),
        })
    }

    #[test]
    fn missing_and_multiple_tags_are_retained() {
        let missing = extract_html("<html><body><p>Hi</p></body></html>");
        assert!(missing.page.titles.is_empty());
        assert!(missing.page.descriptions.is_empty());
        assert!(missing.page.canonicals.is_empty());
        assert!(!missing.page.charset_declared);
        assert!(!missing.page.has_frames);
        assert!(!missing.page.has_plugin_markup);
        assert!(missing.page.is_complete());

        let empty_title = extract_html("<html><head><title></title></head><body></body></html>");
        assert_eq!(empty_title.page.titles, [""]);
        assert!(!empty_title.page.titles.is_empty());

        let multiple = extract_html(
            r#"<!DOCTYPE html>
            <html lang="es">
              <head>
                <title>First</title>
                <title>Second</title>
                <meta name="description" content="One">
                <meta name="description" content="Two">
                <link rel="canonical" href="/a">
                <link rel="canonical" href="/b">
                <meta name="viewport" content="width=device-width">
                <meta name="robots" content="noindex">
              </head>
              <body>
                <h1>Main</h1>
                <h1>Also</h1>
                <h2>Sub</h2>
              </body>
            </html>"#,
        );
        assert_eq!(multiple.page.titles, ["First", "Second"]);
        assert_eq!(multiple.page.descriptions, ["One", "Two"]);
        assert_eq!(multiple.page.canonicals, ["/a", "/b"]);
        assert_eq!(multiple.page.html_lang.as_deref(), Some("es"));
        assert_eq!(multiple.page.doctype.as_deref(), Some("html"));
        assert_eq!(
            multiple.page.viewport.as_deref(),
            Some("width=device-width")
        );
        assert_eq!(multiple.page.robots_meta, ["noindex"]);
        assert_eq!(
            multiple.page.headings,
            vec![
                Heading {
                    level: 1,
                    text: "Main".into()
                },
                Heading {
                    level: 1,
                    text: "Also".into()
                },
                Heading {
                    level: 2,
                    text: "Sub".into()
                }
            ]
        );
        assert_eq!(multiple.page.duration_ms, Some(12));
        assert_eq!(multiple.schema_version, EXTRACTION_SCHEMA_VERSION);
    }

    #[test]
    fn malformed_html_still_extracts_what_it_can() {
        let obs = extract_html(
            r#"<html><title>Unclosed<title>Second</title>
            <h1>Broken <span>heading</h1>
            <a href='/ok'>Go</a>
            <img src='/logo.png' alt='Logo'"#,
        );
        assert!(
            obs.page
                .titles
                .iter()
                .any(|title| title.contains("Unclosed"))
        );
        assert!(
            obs.page
                .headings
                .iter()
                .any(|heading| heading.text.contains("Broken"))
        );
        assert_eq!(obs.links[0].href, "/ok");
        assert_eq!(obs.resources[0].href, "/logo.png");
        assert!(obs.page.is_complete());
    }

    #[test]
    fn non_html_responses_are_not_complete_seo_observations() {
        let json =
            extract_html_status(200, "application/json", br#"{"title":"not a page"}"#, false);
        assert!(json.page.flags.non_html);
        assert!(!json.page.is_complete());
        assert!(json.page.titles.is_empty());
        assert!(json.links.is_empty());
    }

    #[test]
    fn encoding_fallback_and_declared_latin1() {
        let mut latin1 = b"<!DOCTYPE html><html><title>caf".to_vec();
        latin1.push(0xe9);
        latin1.extend_from_slice(b"</title></html>");
        let declared = extract_html_status(200, "text/html; charset=iso-8859-1", &latin1, false);
        assert_eq!(declared.page.titles, ["caf\u{e9}"]);
        assert!(!declared.page.flags.encoding_fallback);
        assert_eq!(declared.page.encoding, "iso-8859-1");
        assert!(declared.page.decoded_bytes > 0);
        assert_eq!(declared.page.raw_bytes, latin1.len() as u64);

        let fallback = extract_html_status(200, "text/html; charset=utf-8", &latin1, false);
        assert!(fallback.page.flags.encoding_fallback);
        assert!(!fallback.page.is_complete());
        assert_eq!(fallback.page.titles, ["caf\u{e9}"]);
        assert_eq!(fallback.page.encoding, "windows-1252");
    }

    #[test]
    fn truncated_challenge_and_error_bodies_are_not_complete() {
        let truncated = extract_html_status(200, "text/html", b"<html><head><title>Partial", true);
        assert!(truncated.page.flags.truncated);
        assert!(!truncated.page.is_complete());
        assert_eq!(truncated.page.titles, ["Partial"]);

        let challenge = extract_html(
            r#"<html><title>Just a moment...</title><div class="cf-chl-widget"></div></html>"#,
        );
        assert!(challenge.page.flags.challenge);
        assert!(!challenge.page.is_complete());
        assert_eq!(challenge.page.titles, ["Just a moment..."]);

        let error = extract_html_status(
            500,
            "text/html",
            b"<html><title>Oops</title><h1>Error</h1></html>",
            false,
        );
        assert!(error.page.flags.error_status);
        assert!(!error.page.is_complete());
        assert_eq!(error.page.status, 500);
        assert_eq!(error.page.titles, ["Oops"]);
    }

    #[test]
    fn links_keep_source_destination_context_and_host_ownership() {
        let obs = extract_html(
            r#"<html><head><base href="/es/"></head>
            <body>
              <a href="cables" rel="nofollow">Copper <b>cables</b></a>
              <a href="https://cdn.example.com/out">Away</a>
              <a href="mailto:info@tiendacables.com">Mail</a>
              <area href="/map" alt="Map" rel="noopener">
            </body></html>"#,
        );
        let internal = obs.links.iter().find(|link| link.href == "cables").unwrap();
        assert_eq!(internal.source, url().as_str());
        assert_eq!(
            internal.destination.as_deref(),
            Some("https://www.tiendacables.com/es/cables")
        );
        assert_eq!(internal.anchor, "Copper cables");
        assert_eq!(internal.rel, "nofollow");
        assert_eq!(internal.element, "a");
        assert_eq!(internal.host_owner, HostOwner::SameHost);

        let external = obs
            .links
            .iter()
            .find(|link| link.href.starts_with("https://cdn.example.com"))
            .unwrap();
        assert_eq!(external.host_owner, HostOwner::OtherHost);

        let mail = obs
            .links
            .iter()
            .find(|link| link.href.starts_with("mailto:"))
            .unwrap();
        assert_eq!(mail.host_owner, HostOwner::Opaque);

        let area = obs
            .links
            .iter()
            .find(|link| link.element == "area")
            .unwrap();
        assert_eq!(area.anchor, "Map");
        assert_eq!(area.host_owner, HostOwner::SameHost);
    }

    #[test]
    fn image_only_anchors_use_img_alt_as_accessible_name() {
        let obs = extract_html(
            r#"<html><body>
              <a href="/named"><img src="/a.png" alt="Buy cables"></a>
              <a href="/empty"><img src="/b.png"></a>
              <a href="/text"><img src="/c.png" alt="ignored"> Visible </a>
            </body></html>"#,
        );
        let named = obs.links.iter().find(|link| link.href == "/named").unwrap();
        assert_eq!(named.anchor, "Buy cables");
        let empty = obs.links.iter().find(|link| link.href == "/empty").unwrap();
        assert_eq!(empty.anchor, "");
        let text = obs.links.iter().find(|link| link.href == "/text").unwrap();
        assert_eq!(text.anchor, "Visible");
    }

    #[test]
    fn meta_refresh_is_extracted_from_http_equiv() {
        let obs = extract_html(
            r#"<html><head><meta http-equiv="refresh" content="0;url=/next"></head><body></body></html>"#,
        );
        assert_eq!(obs.page.meta_refresh, ["0;url=/next"]);
        let none = extract_html("<html><head></head><body></body></html>");
        assert!(none.page.meta_refresh.is_empty());
        assert!(none.redirect_chain.is_empty());
    }

    #[test]
    fn resources_record_kind_alt_and_host_ownership() {
        let obs = extract_html(
            r#"<html><head>
              <link rel="stylesheet" href="https://cdn.example.com/app.css">
              <script src="/app.js"></script>
            </head>
            <body>
              <img src="/logo.png" alt="Logo">
              <img src="https://cdn.example.com/hero.jpg">
            </body></html>"#,
        );
        let css = obs
            .resources
            .iter()
            .find(|item| item.kind == EmbeddedKind::Style)
            .unwrap();
        assert_eq!(css.host_owner, HostOwner::OtherHost);
        let script = obs
            .resources
            .iter()
            .find(|item| item.kind == EmbeddedKind::Script)
            .unwrap();
        assert_eq!(script.host_owner, HostOwner::SameHost);
        let logo = obs
            .resources
            .iter()
            .find(|item| item.href == "/logo.png")
            .unwrap();
        assert_eq!(logo.alt.as_deref(), Some("Logo"));
        assert_eq!(logo.host_owner, HostOwner::SameHost);
        let hero = obs
            .resources
            .iter()
            .find(|item| item.href.contains("hero.jpg"))
            .unwrap();
        assert_eq!(hero.host_owner, HostOwner::OtherHost);
        assert_eq!(hero.referring, url().as_str());
    }

    #[test]
    fn robots_canonical_and_hreflang_include_http_headers() {
        let destination = url();
        let headers = [
            ExtractHeader {
                name: "X-Robots-Tag",
                value: "noindex, nofollow",
            },
            ExtractHeader {
                name: "Link",
                value: r#"<https://www.tiendacables.com/en>; rel="alternate"; hreflang="en", <https://www.tiendacables.com/es/cables>; rel="canonical""#,
            },
        ];
        let obs = extract(&ExtractInput {
            destination_url: &destination,
            status: 200,
            content_type: "text/html",
            headers: &headers,
            body: br#"<html><head>
                <link rel="alternate" hreflang="es" href="/es/cables">
                <meta name="robots" content="max-snippet:20">
              </head></html>"#,
            truncated: false,
            duration_ms: None,
        });
        assert_eq!(obs.page.robots_headers, ["noindex, nofollow"]);
        assert_eq!(obs.page.robots_meta, ["max-snippet:20"]);
        assert!(
            obs.page
                .canonicals
                .iter()
                .any(|value| value == "https://www.tiendacables.com/es/cables")
        );
        assert!(
            obs.page
                .hreflangs
                .iter()
                .any(|item| item.lang == "en" && item.href.contains("/en"))
        );
        assert!(
            obs.page
                .hreflangs
                .iter()
                .any(|item| item.lang == "es" && item.href == "/es/cables")
        );
    }

    #[test]
    fn charset_frames_and_plugins_are_observed() {
        let meta =
            extract_html("<html><head><meta charset=\"utf-8\"><title>A</title></head></html>");
        assert!(meta.page.charset_declared);
        let http_equiv = extract_html(
            "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head></html>",
        );
        assert!(http_equiv.page.charset_declared);
        let header = extract_html_status(200, "text/html; charset=utf-8", b"<html></html>", false);
        assert!(header.page.charset_declared);

        let frames = extract_html("<frameset><frame src=\"/a\"></frameset>");
        assert!(frames.page.has_frames);
        let iframe = extract_html("<html><body><iframe src=\"/a\"></iframe></body></html>");
        assert!(!iframe.page.has_frames);

        let plugin = extract_html("<html><body><embed src=\"flash.swf\"></body></html>");
        assert!(plugin.page.has_plugin_markup);
        let object = extract_html("<html><body><object data=\"a.swf\"></object></body></html>");
        assert!(object.page.has_plugin_markup);
    }

    #[test]
    fn extraction_schema_is_independent_of_severity_and_ui() {
        let dump = format!("{:?}", extract_html("<html><title>A</title></html>"));
        let lower = dump.to_ascii_lowercase();
        assert!(!lower.contains("severity"));
        assert!(!lower.contains("ratatui"));
        assert!(!lower.contains("warning"));
        assert!(!lower.contains("finding"));
        assert_eq!(EXTRACTION_SCHEMA_VERSION, 3);
    }
}
