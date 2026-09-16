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

Press `p` for a signed HTTPS probe, `q`/Escape/Ctrl-C to quit. Network work runs off
the UI thread. No requests occur automatically. Redirects are deliberately refused
in this slice; configure the final host. Auth errors never trigger unsigned fallback.
`CRAWL_SIGNATURE_AGENT` is sent as the `Signature-Agent` header. Shopify requires an
sf-string, so a URI without quotes is wrapped as `"https://shopify.com"`.

Copy `profile.example.toml` to `profile.local.toml` and launch with
`cargo run -p crawlytic -- profile.local.toml` to customize the own-bot profile.
`profile.comparison.toml` records the captured Semrush SiteAuditBot user-agent and
the same owner-supplied scope lists for comparison only; do not use it to impersonate
Semrush. Wrap `.env` values in single quotes so embedded double quotes survive.

Captured lists are complete: 27 ignored parameter names and 21 excluded paths.
URLs that carry a listed parameter are skipped entirely; `ignored_parameter_mode = "strip"` is a
separate explicit behaviour. Path entries without a trailing slash are string
prefixes (`/shoes` matches `/shoes-men`); a trailing slash is that folder only.

## Boundaries

- `crawlytic-core`: profile, URL scope and Web Bot Auth transport; no terminal dependency.
- `crawlytic`: Ratatui rendering, key input and background-task coordination.
- Future interfaces can use the core without depending on Ratatui.

Implemented: versioned TOML profiles (own-bot and comparison), prefix vs subfolder
exclusions, skip-vs-strip query policy, credential validation, sensitive headers,
bounded HTML preflight, responsive terminal status.

Not implemented: crawl queue, robots evaluation, sitemap ingestion, audit rules,
SQLite history, scheduling, credential editing/storage, mobile rendering or JS.
The page cap (20,000) and historical 3,725-page observation are not catalogue size.
Weekly Monday is recorded without a time, timezone, or scheduler.
The explicit connection probe only requests the configured start URL.
A successful probe is not evidence that Shopify verified the signature, and the
simple challenge heuristic cannot detect every block page.

## Next milestones

1. Auth transport integration tests against controlled fixtures; signed requests on
   the selected origin only, including redirect handling and expiry diagnostics.
2. Bounded queue, robots, backoff, cancellation, discovery and per-URL reasons.
   Preserve skipped links for coverage without fetching excluded URLs.
3. SQLite runs and homepage-based link depth; sitemaps as separate discovery evidence.
4. Metadata/link/canonical checks with evidence; then the broader Semrush catalogue.
5. History, scheduled headless runs and exports. A web UI can follow independently.

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

A user-reported successful `p` probe is operator evidence only. It is not recorded in
this repository, is not covered by `cargo test`, and is not proof that Shopify accepted
the signature or that a crawl is ready. Do not commit `.env`, `profile.local.toml`,
SQLite files, or probe transcripts.

References: https://ratatui.rs/ and
https://help.shopify.com/en/manual/promoting-marketing/seo/crawling-your-store
