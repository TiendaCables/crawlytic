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
credentials in shell history. The Auth screen can also accept masked values into the
process environment; they are never rendered unmasked, logged, or written to profiles
or SQLite.

Keyboard: `1`–`5` or Tab cycle Profiles, Auth, Run, URL inventory and Findings; `/`
filters; `j`/`k` move; `s` / Ctrl-S start a crawl; `x` / Ctrl-X cancel; `r` / Ctrl-R
resume; `a` apply masked auth; `e`/`w` edit and write the selected profile; `o` export
the evaluated run as CSV+JSON; `?` help; `q`/Escape/Ctrl-C quit. Cancel, resume, filter, help and selection stay available while
a crawl is running. Network work runs off the UI thread. No requests occur automatically.
The terminal is restored on errors, panic and exit. Signature, Signature-Input and
Signature-Agent are attached only to the profile's HTTPS origin. Same-origin HTTPS
redirects keep the headers; other origins and HTTP downgrades are refused and never
receive credentials. Missing, malformed or expired credentials fail before a request is
sent. There is no unsigned fallback. `CRAWL_SIGNATURE_AGENT` is sent as the
`Signature-Agent` header. Shopify requires an sf-string, so a URI without quotes is
wrapped as `"https://shopify.com"`.
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

- `crawlytic-core`: profile, URL identity/scope, robots policy, Web Bot Auth transport, bounded crawl, homepage/sitemap discovery, SQLite run persistence, versioned page/link/resource extraction, evidence-based rule execution and finding lifecycle, HTML metadata, link/URL-shape, canonical/indexability, crawl-depth/orphan, resource, hreflang/lang, duplicate-content and structured-data checkers, typed start/cancel/resume commands with coalesced progress events, run listing for resume, CSV/JSON audit export, and a read-only generic CSV baseline importer; no terminal dependency.
- `crawlytic`: Ratatui rendering, key input, profile/auth screens, run/URL/finding investigation and background-task coordination.
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
link and resource observations (schema v4) extracted from fetched bodies so later rules
share evidence without refetching: titles, descriptions, headings, robots meta/headers,
canonicals, hreflang/lang, viewport, doctype, encoding, declared charset, frames,
legacy plugin markup, meta refresh, JSON-LD blocks, Microdata/RDFa type inventory, redirect hops, text (nav/header/footer/aside chrome omitted),
anchors/rel (image-only anchors use img alt) and
images/scripts/styles, plus status, timings, content type, raw versus decoded sizes and
completeness. Truncated, challenge, error and non-HTML bodies cannot be marked complete.
The extraction schema has no severity or UI fields. Typed crawl
commands (start, cancel, resume) and coalesced progress events (run status, counters,
fetch completion, diagnostics) so a headless client can drive a run; the discrete event
queue is bounded and a slow consumer drops events instead of growing memory. Counters
are unique URL records by persisted state and must reconcile with storage. Durable truth
stays in SQLite; events are a live view. The displayed user agent is not a viewport. A versioned
rule engine evaluates registered checkers against stored observations with no recrawl. Findings
use a stable rule-plus-entity identity and keep fact, recommendation and severity separate.
Missing prerequisites resolve to `incomplete` or `unsupported`, never `passed`. Scoped
suppressions require a reason, are auditable, and do not delete evidence. HTML metadata checkers evaluate stored observations for titles, descriptions, headings,
viewport, charset, doctype, oversized HTML, frames and plugin markup. Missing versus
intentionally empty titles and descriptions stay distinct. Duplicate groups carry
canonical and indexability context and are compared by affected URL set. Threshold
recommendations quote `max_title_chars`, `min_title_chars` and `max_html_bytes`
(Crawlytic heuristics, not Semrush formulas). The 14 September 2026 5-page duplicate-description
and 73-page long-title totals remain historical catalogue metadata; they are not live URL lists.
Link, anchor, redirect and URL-shape checkers evaluate stored observations: broken internal/external
links, HTTP 4xx/5xx, malformed hrefs, meta refresh, redirect chains/loops, temporary/permanent
redirects, on-page link count, query-parameter count, path underscores, page URLs longer than 200
characters, long link URLs, internal/external nofollow, missing and generic anchors, and resources
used as page links. Findings include the referring page, original anchor and target status.
External HTTP 403 is an access limitation, not a confirmed broken target. Resource-as-page-link
classification uses the fetched Content-Type, never the file extension alone; Semrush parity is not
claimed. Heuristic defaults (`max_on_page_links=2500`, `max_query_params=4`, `max_link_chars=2048`,
`max_redirects=1`, generic-anchor stop-list) are Crawlytic values, not Semrush formulas. The >200
character page-URL threshold is the inventory baseline. Unfetched link targets stay `incomplete`,
never `passed`. Crawl-depth checkers build a directed homepage `<a href>` graph: shortest-path
click depth with a reproducible path, unique referring pages, one-inbound pages, and sitemap
URLs with no observed internal inbound link. Canonicals, assets and sitemap membership never
create a navigation edge. Incomplete crawls label sitemap orphan *candidates* rather than
definite site-wide orphans. `max_clicks` defaults to 3 (inventory baseline, not a Semrush
formula). Hreflang checkers evaluate stored observations for BCP 47/`x-default` syntax, per-source
language conflicts, target status, missing return links, missing self-references, and
canonical/noindex inconsistency. Failed relationships attach source and target evidence.
Missing hreflang on a single-language page with `html lang` is not an error; both lang and
hreflang absent is a warning. Content-language disagreement is a Crawlytic stopword heuristic
with confidence (`min_language_hits`, `min_language_confidence`), not a parser or Semrush
formula. Cross-host locale targets are fetched once over unsigned HTTPS (or a separately
authorized transport) and do not consume `max_pages` or receive Web Bot Auth headers; same-host
unfetched targets stay `incomplete`. Duplicate-content checkers hash chrome-stripped main text after
trim-and-collapse-whitespace and recurring 5-gram boilerplate removal (`boilerplate_min_pages=3`).
Exact groups use a 64-bit FNV-1a fingerprint. Near-duplicates use 64-bit simhash with 4×16-bit LSH
bands so comparisons stay bounded at a 20k URL cap (`near_duplicate_max_hamming=3`, `min_main_tokens=12`).
Reports include group method, fingerprint/hamming evidence and canonical/indexability context.
Product variants that keep distinct main copy are not grouped. Truncated, non-HTML, challenge, error
and robots-blocked responses never enter normal groups. Thresholds are Crawlytic heuristics, not
Semrush formulas; near-duplicate grouping is transitive and uncertain. Structured-data checkers parse
JSON-LD only (validator v1: Product, Offer, BreadcrumbList, Organization). Syntax, vocabulary and
search-feature findings stay separate and point at item type, path and field. Microdata and RDFa are
inventoried and reported as uncovered rather than passed. Local validation does not determine Google
rich-result eligibility or actual search appearance. Other inventory checkers are not shipped;
unregistered catalogue rules stay `unsupported`. Current 14
September 2026 findings are stored separately from the historical "new issues" column.
No-count rows are not failures. Evaluated runs export CSV and JSON with stable finding
identities, severity, unit, URL, evidence, status and run coverage. Formula-leading cells
are neutralized for spreadsheet import. Counts match the Findings screen. Credentials are
refused. A generic CSV mapper reads `source_check` and `entity_url` (optional referrer,
unit, severity, observed_at, source_report, current_count, historical_delta) and keeps
unmapped columns. Aggregate rows stay distinct from affected-entity rows; current counts
are not historical deltas. The Semrush XLSX adapter is blocked until a real workbook is
supplied; sheet and column names are not assumed. Source files are never modified.
Duplicate fetch identities are scheduled once. Every URL
ends fetched, excluded, blocked, failed or pending with a reason. A cancelled run is not
complete. Authentication failures do not continue unsigned. Sitemap-only URLs do not get
click depth 0. A kill/restart resumes without refetching completed observations; in-flight
URLs are retried. Stored settings keep environment references only and never Signature or
Signature-Input values. Disk-full and migration failures are visible and leave the run
incomplete. Raw HTML retention is off by default and quota-bounded when enabled. An
uncommitted writer batch (default 32 statements) can be lost on crash.

Not implemented: remaining inventory checkers beyond the shipped HTML/link/indexability/navigation/resource/hreflang/duplicate-content/structured-data set, cross-run finding history,
scheduling, a credential vault (masked process-environment setup only), mobile rendering or JS.
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

1. Remaining inventory checkers over stored observations; then the broader Semrush catalogue.
2. Cross-run history and scheduled headless runs. A web UI can follow independently.

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
The TUI starts without sending requests. Press `s` only when you intend a live crawl.
Deterministic TUI fixtures cover keyboard navigation, filtering during a running session,
masked credentials, small terminals, event floods, grouped findings with evidence/inlinks,
incomplete/unsupported checks without placeholder scores, and CSV/JSON export from the
Findings screen.

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
incomplete. Rule-execution fixtures cover stable finding identities, incomplete/unsupported
prerequisites that never pass, fact/recommendation/severity separation, stored-observation
reruns without a recrawl, and auditable suppressions that keep evidence. Extraction fixtures cover missing/multiple tags, malformed HTML, non-HTML
responses, encoding fallback, declared charset, frames versus iframe, plugin markup,
link/resource host ownership, meta refresh, image-only accessible names, and truncated/challenge/error
bodies that stay incomplete. HTML metadata fixtures cover missing versus empty titles
and descriptions, duplicate groups with canonical/indexability context, quoted
thresholds, headings, viewport width, doctype, oversized HTML, and URL-set comparison
against the historical 5/73 totals without fabricating storefront URLs. Link/URL-shape
fixtures cover referring page plus original anchor plus target status, external 403 as an
access limitation, content-type-based resources-as-page-links without Semrush parity, the
>200 character baseline, quoted heuristic thresholds, and incomplete evidence when a
target was not fetched. Crawl-depth fixtures cover diamond/cycle/disconnected shortest paths,
canonical/asset/sitemap edges that never count as inbound, a reproducible homepage path in
depth findings, and coverage-qualified sitemap orphan candidates. Hreflang fixtures cover multi-locale
and `x-default` clusters, absent return links, inaccessible targets, invalid BCP 47 tags, source
conflicts, `html lang` without hreflang on a single-language page, content-language heuristic
confidence, and unsigned cross-host locale fetches that never attach credentials. Structured-data fixtures cover JSON-LD arrays and `@graph`, multiple offers, malformed JSON, missing required properties, Microdata/RDFa inventory that does not pass, unsupported types, and recommendations that do not promise Google rich results or appearance. Export fixtures cover quotes, Unicode,
formula injection, stable finding identities, coverage reconciliation, secret refusal, and
read-only CSV import that separates aggregate counts from entity rows and historical deltas.
The Semrush workbook adapter stays blocked without inspecting unsupplied XLSX bytes. They do not contact the storefront.

A user-reported or local crawl is operator evidence only. It is not recorded in
this repository, is not covered by the default `cargo test` run, and is not proof that
Shopify accepted the signature or that a crawl is ready. Optional
`cargo test -p crawlytic-core live_tiendacables -- --ignored` contacts the live origin
when credentials are already in the execution environment. Do not commit `.env`,
`profile.local.toml`, SQLite files, or probe transcripts.

References: https://ratatui.rs/ and
https://help.shopify.com/en/manual/promoting-marketing/seo/crawling-your-store
