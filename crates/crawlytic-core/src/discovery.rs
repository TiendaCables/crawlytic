//! Navigational HTML links and independent sitemap inventory.
//!
//! `<a href>` extraction is raw HTML only (JavaScript is off). Sitemaps are
//! discovery evidence: they never create a navigation edge or assign click
//! depth. Gzip and nested indexes are bounded; cycles, parse errors and
//! inaccessible files are recorded. Cross-origin sitemap locations are not
//! fetched and never receive credentials.

use flate2::read::GzDecoder;
use std::io::Read;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NavigationalLinks {
    pub base_href: Option<String>,
    pub hrefs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSitemap {
    Urlset(Vec<String>),
    Index(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitemapDecodeError {
    Oversized,
    InvalidGzip,
}

pub fn extract_navigational_links(html: &str) -> NavigationalLinks {
    let mut base_href = None;
    let mut hrefs = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
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
        if tag_opens(bytes, i, b"script") {
            i = skip_element(bytes, i, b"script");
            continue;
        }
        if tag_opens(bytes, i, b"style") {
            i = skip_element(bytes, i, b"style");
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
        if tag_opens(bytes, i, b"a") {
            if let Some((end, attrs)) = read_tag(bytes, i) {
                if let Some(href) = attr(&attrs, "href") {
                    hrefs.push(href);
                }
                i = end;
            } else {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    NavigationalLinks { base_href, hrefs }
}

pub fn decode_sitemap_body(
    bytes: &[u8],
    max_uncompressed: usize,
) -> Result<Vec<u8>, SitemapDecodeError> {
    if bytes.len() >= 2 && bytes[..2] == GZIP_MAGIC {
        let mut decoder = GzDecoder::new(bytes);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match decoder.read(&mut buf) {
                Ok(0) => return Ok(out),
                Ok(n) => {
                    if out.len().saturating_add(n) > max_uncompressed {
                        return Err(SitemapDecodeError::Oversized);
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                Err(_) => return Err(SitemapDecodeError::InvalidGzip),
            }
        }
    }
    if bytes.len() > max_uncompressed {
        return Err(SitemapDecodeError::Oversized);
    }
    Ok(bytes.to_vec())
}

pub fn parse_sitemap_xml(xml: &str) -> Result<ParsedSitemap, String> {
    let trimmed = xml.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err("Empty sitemap document".to_owned());
    }
    let kind = root_kind(trimmed).ok_or_else(|| "Not a sitemap urlset or index".to_owned())?;
    let locs = extract_locs(trimmed);
    match kind {
        RootKind::Index => Ok(ParsedSitemap::Index(locs)),
        RootKind::Urlset => Ok(ParsedSitemap::Urlset(locs)),
    }
}

#[derive(Clone, Copy)]
enum RootKind {
    Urlset,
    Index,
}

fn root_kind(xml: &str) -> Option<RootKind> {
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
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
        if starts_with_ignore_ascii(bytes, i, b"<?") {
            i += 2;
            while i < bytes.len() && !starts_with_ignore_ascii(bytes, i, b"?>") {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        if starts_with_ignore_ascii(bytes, i, b"<!doctype") {
            i += 1;
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            i = i.saturating_add(1);
            continue;
        }
        if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 1;
            continue;
        }
        if tag_opens(bytes, i, b"sitemapindex") {
            return Some(RootKind::Index);
        }
        if tag_opens(bytes, i, b"urlset") {
            return Some(RootKind::Urlset);
        }
        i += 1;
    }
    None
}

fn extract_locs(xml: &str) -> Vec<String> {
    let bytes = xml.as_bytes();
    let mut locs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<'
            && tag_opens(bytes, i, b"loc")
            && let Some((end, _)) = read_tag(bytes, i)
        {
            let (text, next) = read_until_close(bytes, end, b"loc");
            let loc = decode_xml_text(&text).trim().to_owned();
            if !loc.is_empty() {
                locs.push(loc);
            }
            i = next;
            continue;
        }
        i += 1;
    }
    locs
}

fn decode_xml_text(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
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

fn skip_element(bytes: &[u8], start: usize, name: &[u8]) -> usize {
    let Some((end, _)) = read_tag(bytes, start) else {
        return start + 1;
    };
    let mut i = end;
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
    None
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
            return Some(value);
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
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    #[test]
    fn extracts_base_and_anchor_hrefs_but_not_script_markup() {
        let html = r#"<html><head><BASE href="/en/"><base href="/ignored/"></head>
            <body>
              <a href="/a">A</a>
              <a HREF='b'>B</a>
              <a>nohref</a>
              <script>document.write('<a href="/js">x</a>');</script>
              <style>a[href="/css"]{}</style>
              <!-- <a href="/comment">no</a> -->
            </body></html>"#;
        let links = extract_navigational_links(html);
        assert_eq!(links.base_href.as_deref(), Some("/en/"));
        assert_eq!(links.hrefs, vec!["/a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn sitemap_urlset_and_index_are_distinct() {
        let urlset = parse_sitemap_xml(
            r#"<?xml version="1.0"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <url><loc>https://www.tiendacables.com/a</loc></url>
              <url><loc>https://www.tiendacables.com/b</loc></url>
            </urlset>"#,
        )
        .unwrap();
        assert_eq!(
            urlset,
            ParsedSitemap::Urlset(vec![
                "https://www.tiendacables.com/a".into(),
                "https://www.tiendacables.com/b".into()
            ])
        );
        let index = parse_sitemap_xml(
            r#"<sitemapindex>
              <sitemap><loc>https://www.tiendacables.com/sitemap-a.xml</loc></sitemap>
            </sitemapindex>"#,
        )
        .unwrap();
        assert_eq!(
            index,
            ParsedSitemap::Index(vec!["https://www.tiendacables.com/sitemap-a.xml".into()])
        );
        assert!(parse_sitemap_xml("<html>nope</html>").is_err());
    }

    #[test]
    fn gzip_sitemaps_decode_until_the_size_cap() {
        let xml = b"<urlset><url><loc>https://www.tiendacables.com/a</loc></url></urlset>";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml).unwrap();
        let gz = encoder.finish().unwrap();
        let decoded = decode_sitemap_body(&gz, 1024).unwrap();
        assert_eq!(
            parse_sitemap_xml(std::str::from_utf8(&decoded).unwrap()).unwrap(),
            ParsedSitemap::Urlset(vec!["https://www.tiendacables.com/a".into()])
        );
        assert_eq!(
            decode_sitemap_body(&gz, 8),
            Err(SitemapDecodeError::Oversized)
        );
        assert_eq!(
            decode_sitemap_body(xml, 8),
            Err(SitemapDecodeError::Oversized)
        );
    }
}
