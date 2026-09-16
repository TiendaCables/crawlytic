# Crawlytic

A self-hosted technical SEO auditor with a Ratatui interface.

## Run

Install a current stable Rust toolchain. From this directory:

```sh
cargo run -p crawlytic
```

The interface starts without credentials. Copy `.env.example` to `.env` and fill in
Shopify-generated `CRAWL_SIGNATURE`, `CRAWL_SIGNATURE_INPUT`, and `CRAWL_SIGNATURE_AGENT`.
`.env` is loaded at launch. Quoted values keep embedded quotes after the outer quotes
are stripped; exported environment variables override file values. Missing or invalid
credentials produce errors that do not echo secret material. Avoid putting literal
credentials in shell history.

Press `p` for a bounded signed sample (start URL, `/robots.txt`, `/sitemap.xml`),
`q`/Escape/Ctrl-C to quit. Network work runs off the UI thread. No requests occur
automatically. Signature, Signature-Input and Signature-Agent are attached only to
the profile's HTTPS origin. Same-origin HTTPS redirects keep the headers; other
origins and HTTP downgrades are refused and never receive credentials. Missing,
malformed or expired credentials fail before a request is sent. There is no unsigned
fallback. `CRAWL_SIGNATURE_AGENT` is sent as the `Signature-Agent` header. Shopify
requires an sf-string, so a URI without quotes is wrapped as `"https://shopify.com"`.
`expires` in Signature-Input is treated as local expiry metadata; replace values in
`.env` or the process environment, never in profiles.

Copy `profile.example.toml` to `profile.local.toml` and launch with
`cargo run -p crawlytic -- profile.local.toml` to customize the own-bot profile.
`profile.comparison.toml` records the captured Semrush SiteAuditBot user-agent and
the same owner-supplied scope lists for comparison only; do not use it to impersonate
Semrush. Wrap `.env` values in single quotes so embedded double quotes survive.

Captured lists are complete: 27 ignored parameter names and 21 excluded paths.
URLs that carry a listed parameter are skipped entirely; `ignored_parameter_mode = "strip"` is a
separate explicit behaviour. Path entries without a trailing slash are string
prefixes (`/shoes` matches `/shoes-men`); a trailing slash is that folder only.
Discovered hrefs keep the original link text, a fragment-stripped fetch identity, and an exact skip
reason. Scheme, host and default port are normalized; distinct paths, query values, duplicate
parameters and pagination are not collapsed. A canonical is never treated as proof two URLs are the
same. Excluded and external targets remain in coverage and link relationships and are not fetched.
Website mode starts at the homepage and follows raw HTML `<a href>` links (JavaScript off).
Sitemaps are independent inventory: they never create a navigation edge or assign click depth.
`discovery_mode` may be `homepage_internal_links`, `sitemap`, or `combined`. Cross-origin sitemap
locations are recorded and never receive credentials.

## Boundaries

- `crawlytic-core`: profile, URL identity/scope, robots policy, Web Bot Auth transport, bounded crawl, homepage/sitemap discovery, SQLite run persistence, versioned page/link/resource extraction, and typed start/cancel/resume commands with coalesced progress events; no terminal dependency.
- `crawlytic`: Ratatui rendering, key input and background-task coordination.
- Future interfaces can use the core without depending on Ratatui. The displayed user agent is the HTTP User-Agent string, not a browser viewport.

Implemented: versioned TOML profiles (own-bot and comparison), prefix vs subfolder
exclusions, skip-vs-strip query policy, URL identity (relative links, HTML base href,
fragment-stripped fetch keys, scheme/host/port normalization), coverage of skipped URLs
without fetching them, Web Bot Auth transport with origin-locked
headers, same-origin HTTPS redirects, one connection retry, Signature-Input expiry
metadata, 401/403/429 diagnostics that separate observation from suspected cause,
HTTP/TLS fixtures for header destinations, robots access policy as a separate layer
(user-agent groups, wildcards, encodings, failed fetches, sitemap declarations),
bounded signed sample of page/robots/sitemap, responsive terminal status, versioned
rule catalogue v1 (97 transcribed checks plus limited AMP remainder, fixture contract,
six result states), bounded async crawl (frontier, worker pool, per-origin pace for
`crawl_delay = minimum`, independent URL/queue/response-size caps, 429/503 Retry-After
backoff with a retry budget, cancellation that classifies outstanding URLs),
homepage-link discovery and independent sitemap inventory (indexes, gzip, size/depth/cycle
bounds, cross-origin locations refused without forwarding credentials),
SQLite persistence for runs, sanitized profile snapshots, URL states, fetch evidence,
links, resource references, sitemap membership and idempotent findings. Versioned page,
link and resource observations (schema v1) extracted from fetched bodies so later rules
share evidence without refetching: titles, descriptions, headings, robots meta/headers,
canonicals, hreflang/lang, viewport, doctype, encoding, text, anchors/rel and
images/scripts/styles, plus status, timings, content type, raw versus decoded sizes and
completeness. Truncated, challenge, error and non-HTML bodies cannot be marked complete.
The extraction schema has no severity or UI fields. Typed crawl
commands (start, cancel, resume) and coalesced progress events (run status, counters,
fetch completion, diagnostics) so a headless client can drive a run; the discrete event
queue is bounded and a slow consumer drops events instead of growing memory. Counters
are unique URL records by persisted state and must reconcile with storage. Durable truth
stays in SQLite; events are a live view. The displayed user agent is not a viewport. Checkers
are not shipped; live evaluation is `unsupported` until owner issues land. Current 14
September 2026 findings are stored separately from the historical "new issues" column.
No-count rows are not failures. Duplicate fetch identities are scheduled once. Every URL
ends fetched, excluded, blocked, failed or pending with a reason. A cancelled run is not
complete. Authentication failures do not continue unsigned. Sitemap-only URLs do not get
click depth 0. A kill/restart resumes without refetching completed observations; in-flight
URLs are retried. Stored settings keep environment references only and never Signature or
Signature-Input values. Disk-full and migration failures are visible and leave the run
incomplete. Raw HTML retention is off by default and quota-bounded when enabled. An
uncommitted writer batch (default 32 statements) can be lost on crash.

Not implemented: rule checkers, cross-run finding history,
scheduling, credential editing/storage, mobile rendering or JS.
The page cap (20,000) and historical 3,725-page observation are not catalogue size.
Weekly Monday is recorded without a time, timezone, or scheduler.
A successful sample is not evidence that Shopify verified the signature, and the
simple challenge heuristic cannot detect every block page. Default TiendaCables
profiles keep robots and meta bypass off even with signed requests. Robots denial is
blocked evidence, not a broken page. Meta noindex is a distinct block kind and is not
evaluated in this slice. Crawl-delay is recorded and is not access policy. Missing or
unreachable robots.txt allows crawling and is not treated as a denial.
`page` is a distinct fetch identity and is skipped only because the TiendaCables profile
lists it as an ignored parameter. Path slash variants and query order stay distinct.

## Next milestones

1. Shortest-path depth from the homepage graph; sitemaps stay separate evidence.
2. Rule checkers over stored observations (titles, links, canonicals); then the broader Semrush catalogue.
3. Cross-run history, scheduled headless runs and exports. A web UI can follow independently.

Recorded TiendaCables settings: www.tiendacables.com; 20,000 page cap; 3,725-page
historical observation (not an invariant); homepage-link discovery; JS off; crawl
delay minimum (no numeric rate); weekly Monday intent; robots/meta bypass off;
Web Bot Auth required; 27 ignored parameters and 21 excluded paths captured.

## Verification

Automated (does not contact the storefront):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

Terminal smoke test on Arch Linux (interactive; `q` / Esc / Ctrl-C to quit).
The TUI starts without sending requests. Press `p` only when you intend a live probe.

```sh
cargo run -p crawlytic
```

Controlled HTTP/TLS fixtures in `cargo test` assert which destination receives each
Web Bot Auth header, including same-origin redirects, refused cross-origin and HTTP
downgrades, retries, 401/403/429 diagnostics and secret redaction. Robots fixtures
cover user-agent selection, conflicting rules, encodings, failed fetches, signed
requests with bypass off, and an explicit owner-audit override retained in run
metadata. Crawl fixtures cover duplicate identities, independent URL/queue/body caps,
429/503 backoff, unsigned-fallback refusal, robots blocks, cancellation, homepage-link
discovery, sitemap inventory (including gzip, cycles, oversized/parse/inaccessible files)
and refused cross-origin sitemap locations. Engine fixtures cover a headless start/observe
client, cancel/resume commands, counter reconciliation with persisted URL states, and a
bounded event queue that drops when the consumer lags. Persistence fixtures cover kill/restart resume
without duplicate findings, in-flight retry, secret-free stored settings, writer batching,
optional HTML quotas, and visible disk-full/migration failures that leave partial runs
incomplete. Extraction fixtures cover missing/multiple tags, malformed HTML, non-HTML
responses, encoding fallback, link/resource host ownership, and truncated/challenge/error
bodies that stay incomplete. They do not contact the storefront.

A user-reported or local `p` sample is operator evidence only. It is not recorded in
this repository, is not covered by the default `cargo test` run, and is not proof that
Shopify accepted the signature or that a crawl is ready. Optional
`cargo test -p crawlytic-core live_tiendacables -- --ignored` contacts the live origin
when credentials are already in the execution environment. Do not commit `.env`,
`profile.local.toml`, SQLite files, or probe transcripts.

References: https://ratatui.rs/ and
https://help.shopify.com/en/manual/promoting-marketing/seo/crawling-your-store
