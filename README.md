# Crawlytic

Self-hosted technical SEO auditor. Crawl your own origin, persist evidence in
SQLite, and inspect findings in a terminal UI or from a headless `audit` run.

Built by [TiendaCables](https://github.com/TiendaCables). MIT licensed.
Crates stay unpublished (`publish = false`); install from this repository.

- [What it is](#what-it-is)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Terminal UI](#terminal-ui)
- [Configuration](#configuration)
- [Auth and crawl safety](#auth-and-crawl-safety)
- [Workspace](#workspace)
- [Status](#status)
- [Develop](#develop)
- [License](#license)

## What it is

Crawlytic is an operator-run auditor for a site you control. It is not a SaaS
product, not a crates.io package, and not a Semrush Site Audit replacement.

It will:

- Discover URLs from the homepage, a sitemap, or both
- Fetch pages over HTTPS with [Web Bot Auth](https://help.shopify.com/en/manual/promoting-marketing/seo/crawling-your-store) when the profile requires it
- Store runs, URL states, and findings in SQLite
- Evaluate a versioned rule catalogue against stored observations (no recrawl)
- Export CSV + JSON, compare runs, and print systemd/cron guidance

It will not:

- Render JavaScript or emulate a browser
- Send email or completion notifications
- Queue overlapping crawls (a second process exits instead)
- Attach credentials to HTTP, other origins, or unsigned fallbacks
- Claim Google rich-result eligibility or search appearance

The binary talks to the network only when you start a crawl. Opening the UI
does not fetch anything.

## Install

Needs a stable Rust toolchain **1.89+** (edition 2024). From a clone:

```sh
cargo install --path crates/crawlytic --locked
```

Or from git:

```sh
cargo install --git https://github.com/TiendaCables/crawlytic.git --locked crawlytic
```

`crawlytic` is then on `PATH`. There is no distro package and no `cargo publish`.

From a checkout, without installing:

```sh
cargo run -p crawlytic
```

## Quick start

1. Copy the examples (never commit the copies):

   ```sh
   cp .env.example .env
   cp profile.example.toml profile.local.toml
   ```

2. Put Shopify-generated Web Bot Auth values in `.env`. Wrap values in single
   quotes so embedded double quotes survive:

   ```sh
   CRAWL_SIGNATURE='...'
   CRAWL_SIGNATURE_INPUT='...'
   CRAWL_SIGNATURE_AGENT='"https://shopify.com"'
   ```

   Quoted file values keep inner quotes after the outer quotes are stripped.
   Exported environment variables override `.env`. `.env` is loaded at launch.

3. Edit `profile.local.toml`: `start_url`, `max_pages`, `discovery_mode`,
   exclusions, and ignored parameters. Secrets stay in the environment; the
   profile only names the variables.

4. Run the UI, or audit headlessly:

   ```sh
   crawlytic profile.local.toml
   crawlytic audit --profile profile.local.toml --json
   ```

The SQLite store defaults to `./crawlytic.sqlite` (`--store` or
`CRAWLYTIC_STORE`). Opening an older store applies schema migrations and keeps
existing runs. Back up before upgrading the binary.

## Commands

| Command | What it does |
|---|---|
| `crawlytic [profile.toml]` | Interactive Ratatui UI |
| `crawlytic audit --profile PATH [--json] [--resume]` | Crawl, evaluate, export CSV+JSON |
| `crawlytic schedule print --profile PATH` | Print systemd oneshot+timer and a `MAILTO=""` crontab. Does not install units or enable timers. |
| `crawlytic coverage` | Secret-free supported/deferred rule coverage JSON (also a CI artifact) |
| `crawlytic backup --out PATH` | Consistent SQLite snapshot. Destination must not already exist. |
| `crawlytic retention print` | Show raw-HTML retention settings |
| `crawlytic retention set --max-html-bytes N [--retain-raw-html]` | Quota-bounded HTML retention (off by default) |
| `crawlytic help` | CLI help |

Audit options: `--store`, `--export-dir`, `--lock`, `--resume`. Overlap uses a
store lock (exit 3), not a queue. Resume a crashed crawl with `audit --resume`.

Exit codes: **0** ok, **1** usage, **2** auth/expiry, **3** overlap, **4** crawl,
**5** export.

`schedule print` is guidance only. Both `schedule_time` (HH:MM) and
`schedule_timezone` (IANA) must be set on the profile before a schedule is
considered enabled. Timer restart is `Restart=no` with `Persistent=true` for
missed weekly fires.

### Restore on a new machine

Prefer `crawlytic backup` over copying a live WAL file (`*.sqlite-wal`):

```sh
crawlytic backup --store crawlytic.sqlite --out crawlytic.sqlite.bak
# copy crawlytic.sqlite.bak, profile.local.toml, and .env to the new host
cp crawlytic.sqlite.bak crawlytic.sqlite
crawlytic audit --profile profile.local.toml --store crawlytic.sqlite --json
```

## Terminal UI

Screens: **1** Profiles, **2** Auth, **3** Run, **4** URL inventory, **5**
Findings, **6** Compare, **7** History. Tab / Shift-Tab cycle them.

| Key | Action |
|---|---|
| `1`–`7` / Tab | Screens |
| `j` / `k` | Move |
| `/` | Filter |
| `s` / Ctrl-S | Start crawl |
| `x` / Ctrl-X | Cancel |
| `r` / Ctrl-R | Resume |
| `a` | Apply masked auth to the process environment |
| `e` / `w` | Edit / write the selected profile |
| `o` | Export the evaluated run as CSV+JSON |
| `?` | Help |
| `q` / Esc / Ctrl-C | Quit |

Cancel, resume, filter, help, and selection stay available while a crawl runs.
Network work is off the UI thread. The terminal is restored on error, panic,
and exit. Credentials are masked in the UI and never written to profiles or
SQLite.

## Configuration

### Profile

`profile.example.toml` is the own-bot profile (copy to `profile.local.toml`).
`profile.comparison.toml` records a captured Semrush SiteAuditBot user-agent
and the same owner-supplied scope lists for **comparison only**. Do not use it
to impersonate Semrush.

Useful fields:

| Field | Notes |
|---|---|
| `start_url` | HTTPS origin to crawl |
| `max_pages` | Crawl ceiling, not catalogue size |
| `discovery_mode` | `homepage_internal_links`, `sitemap`, or `combined` |
| `user_agent` | HTTP User-Agent string (not a viewport) |
| `exclude_paths` | No trailing slash: string prefix (`/shoes` matches `/shoes-men`). Trailing slash: that folder only. |
| `ignored_parameter_mode` | Default `skip` drops the whole URL if a listed parameter is present. `strip` is a separate explicit mode. |
| `web_bot_auth_required` | No unsigned fallback when true |
| `schedule_time` / `schedule_timezone` | Both required before `schedule print` is enabled |

Sitemaps are independent inventory: they never create a navigation edge or
assign click depth. Cross-origin sitemap locations are recorded and never
receive credentials. Website mode starts at the homepage and follows raw HTML
`<a href>` (JavaScript off).

URL identity keeps distinct paths, query values, duplicate parameters, and
pagination. Scheme, host, and default port are normalized. A canonical is
never treated as proof two URLs are the same. Excluded and external targets
stay in coverage and link relationships; they are not fetched.

### Store and retention

Raw HTML retention is off by default and quota-bounded when enabled:

```sh
crawlytic retention print --store crawlytic.sqlite
crawlytic retention set --store crawlytic.sqlite --max-html-bytes 10485760 --retain-raw-html
```

Do not commit `.env`, `profile.local.toml`, SQLite files, or probe transcripts.

## Auth and crawl safety

Web Bot Auth headers (`Signature`, `Signature-Input`, `Signature-Agent`) attach
only to the profile's HTTPS origin. Same-origin HTTPS redirects keep the
headers. Other origins and HTTP downgrades are refused and never receive
credentials.

Missing, malformed, or expired credentials fail **before** a request is sent.
There is no unsigned fallback. `expires` in Signature-Input is local expiry
metadata; replace values in `.env` or the process environment, never in
profiles.

`CRAWL_SIGNATURE_AGENT` is sent as `Signature-Agent`. Shopify requires an
sf-string, so a URI without quotes is wrapped as `"https://shopify.com"`.

The Auth screen can accept masked values into the process environment. They
are never rendered unmasked, logged, or written to profiles or SQLite. Missing
or invalid credentials produce errors that do not echo secret material. Avoid
putting literal credentials in shell history.

A successful sample is not evidence that Shopify verified the signature. The
simple challenge heuristic cannot detect every block page.

## Workspace

| Crate | Role |
|---|---|
| `crawlytic-core` | Profile, scope, robots, transport, crawl, SQLite, extraction, rules, export, compare, headless audit, schedule plans. No terminal dependency. |
| `crawlytic` | Ratatui UI, key input, and the `audit` / `schedule print` / `coverage` / `backup` / `retention` CLI |

Future interfaces can use core without depending on Ratatui.

Shipped checkers cover HTML metadata, links/URL-shape, canonicals and
indexability, crawl depth and orphans, resources, hreflang/lang, duplicate
content, JSON-LD structured data, and HTTPS/certificates. Unregistered
catalogue rules stay `unsupported`, never `passed`. Missing prerequisites
resolve to `incomplete` or `unsupported`.

Findings use a stable rule-plus-entity identity. Fact, recommendation, and
severity stay separate. Scoped suppressions require a reason, are auditable,
and do not delete evidence.

## Status

Implemented: versioned TOML profiles, origin-locked Web Bot Auth, bounded
async crawl with cancel/resume, SQLite persistence, rule evaluation over
stored observations, CSV/JSON export, run comparison and history, headless
audit with overlap locking, local weekly schedule *plans*.

Not implemented: remaining inventory checkers, a credential vault, mobile or
JS rendering, email, Semrush Site Audit replacement. The Semrush XLSX adapter
stays blocked until a real workbook is supplied.

Known limits:

- Default page cap is 20,000. Historical snapshot counts in example profiles
  are observations, not invariants.
- Heuristic thresholds (`max_title_chars`, `max_clicks`, near-duplicate
  Hamming distance, certificate `days_before_expiry`, …) are Crawlytic values,
  not Semrush formulas.
- Robots denial is blocked evidence, not a broken page. Missing or unreachable
  `robots.txt` allows crawling.
- Default TiendaCables profiles keep robots and meta bypass off even with
  signed requests.
- Timezone names are checked against local zoneinfo when present; systemd/cron
  still resolve the name at fire time.
- An uncommitted writer batch (default 32 statements) can be lost on crash.

Next:

1. Remaining inventory checkers over stored observations, then the broader catalogue.
2. A web UI can follow independently.

`crawlytic coverage` is the live supported/deferred list.

## Develop

Automated checks do not contact the storefront. GitHub Actions on `main` and
pull requests runs the same commands and uploads `rule-coverage.json`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
cargo run -p crawlytic -- coverage
```

`cargo test` includes HTTP/TLS, robots, crawl, engine, persistence, rules,
extraction, export, and TUI fixtures. Press `s` in the UI only when you intend
a live crawl.

A user-reported or local crawl is operator evidence only. It is not recorded
in this repository and is not proof that Shopify accepted the signature.

Optional live probe (credentials already in the environment):

```sh
cargo test -p crawlytic-core live_tiendacables -- --ignored
```

Do **not** `cargo publish` these crates from a personal crates.io account.
`publish = false` is intentional. If a later issue enables registry
publication, use a TiendaCables GitHub identity (or a dedicated company user),
add the org team as crate owners, and keep personal crates.io credentials off
this repository.

## License

[MIT](LICENSE) © 2026 TiendaCables.

References: [Ratatui](https://ratatui.rs/) ·
[Shopify: crawling your store](https://help.shopify.com/en/manual/promoting-marketing/seo/crawling-your-store)
