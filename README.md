# Crawl TUI — working title

An initial Ratatui shell for a self-hosted technical SEO auditor. The name is provisional.

## Run

Install a current stable Rust toolchain. From this directory:

```sh
cargo run -p audit-tui
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
`cargo run -p audit-tui -- profile.local.toml` to customize the profile.
The example exclusions and parameters are only the visible portion of screenshots.
The prototype identifies itself; it does not impersonate Semrush's mobile bot.

## Boundaries

- `audit-core`: profile, URL scope and Web Bot Auth transport; no terminal dependency.
- `audit-tui`: Ratatui rendering, key input and background-task coordination.
- Future interfaces can use the core without depending on Ratatui.

Implemented: TOML loading, explicit exclusion semantics, credential validation,
sensitive headers, bounded HTML preflight, responsive terminal status.

Not implemented: crawl queue, robots evaluation, sitemap ingestion, audit rules,
SQLite history, scheduling, credential editing/storage, mobile rendering or JS.
The page budget and exclusion configuration are for the forthcoming crawler;
the explicit connection probe only requests the configured start URL.
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

Current Semrush baseline: www.tiendacables.com; 3,725 crawled pages in screenshots;
20,000 configured ceiling; homepage-link discovery; JS off; weekly Mondays;
robots bypass off; Web Bot Auth required; 27 ignored parameters (partial list provided).

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
cargo run -p audit-tui
```

A user-reported successful `p` probe is operator evidence only. It is not recorded in
this repository, is not covered by `cargo test`, and is not proof that Shopify accepted
the signature or that a crawl is ready. Do not commit `.env`, `profile.local.toml`,
SQLite files, or probe transcripts.

References: https://ratatui.rs/ and
https://help.shopify.com/en/manual/promoting-marketing/seo/crawling-your-store
