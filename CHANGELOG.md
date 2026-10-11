# Changelog

## v2.0.0 — 2026-10-11
A full rewrite of the engine while keeping the SecretOpt1c DNA (active + passive recon, BHEH swagger).
The original v1.0 bash tool is preserved under [`legacy/`](legacy/).

### Added
- **New detection engine** — `secrethub.json` schema v2: **132 high-fidelity regex modules across 86
  providers** matching real secret *values* (AWS, GCP, Azure, GitHub, GitLab, Stripe, Slack, Twilio,
  SendGrid, OpenAI, Anthropic, Groq, Figma, Supabase, PlanetScale, Doppler, Vault, Cloudinary, npm,
  PyPI, DigitalOcean, Shopify, JWT, private keys, DB URIs, and many more), each with **severity,
  entropy floor, confidence, keywords** and an optional **live-validation** recipe.
- **Wide generic catch-all** — detects `encryptionKey`, `secretKey`, `apiKey`, `client_secret`,
  `*_SECRET`, and `.env` / `export` assignments with entropy gating, so custom/unbranded keys are caught.
- **Live validation** (`--validate`) — verifies candidate keys against provider read-only APIs and tags
  them `VALID / invalid / error`. Turns "found a string" into "found a live key".
- **Built-in crawler** — active page + `<script>` crawl following **JavaScript and `.js.map` source
  maps**; pluggable passive sources `--sources crawl,wayback,gau,katana`; optional `gobuster` brute
  with live progress.
- **Robust fetching** — threaded, real-browser `User-Agent` (`--ua` to override), `Accept: */*`, and
  **automatic Brotli/gzip decoding** so WAF/CDN-compressed JS bundles are scanned correctly.
- **False-positive filtering with local context** — drops placeholders (`YOUR_API_KEY`, `example`,
  `{{env}}`…) using a window around each match, so findings survive minified single-line bundles.
- **Branded reporting** — rich terminal table in BHEH green, plus **`report.html`** (filter/search,
  severity tiles, VALID badges), **`secrets.json`** (pipelines/CI), and **`secrets.csv`** (back-compat).
- **Run modes** — interactive menu, full CLI, `--usage` examples screen, `--list-rules` / `--explain`,
  `--selftest`, `--scan-file -` (pipe your own `curl`), and `--redact` to mask values when sharing.
- Docker image, `pyproject.toml` (`pipx install .`), graceful no-`rich` fallback.

### Changed
- Core moved from Bash to Python; `SecretOpt1c.sh` is now a thin launcher (back-compatible entrypoint).
- `secrethub.json` keyword list retained as a low-signal `mentions` layer (`--mentions`).
- Secret values are shown **in full by default** (it's your finding); use `--redact` to mask.

### Preserved
- The complete v1.0 bash workflow and its keyword `secrethub.json` live in [`legacy/`](legacy/).
