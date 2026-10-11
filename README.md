# BHEH's SecretOpt1c

<p align="center">
<a href="https://www.blackhatethicalhacking.com"><img src="https://blackhatethicalhacking.com/assets/images/Logo_Complete.png" width="300px" alt="BHEH"></a>
</p>

<p align="center">

**Unleashing secrets, for a successful attack with pinpoint accuracy**

SecretOpt1c is written by Chris "SaintDruG" Abou-Chabké from Black Hat Ethical Hacking and is designed for Red Teams and Bug Bounty Hunters!
</p>

<p align="center">
<img src="https://img.shields.io/badge/version-2.0.0-4cd964?style=flat-square">
<img src="https://img.shields.io/badge/engine-132%20modules%20%C2%B7%2086%20providers-4cd964?style=flat-square">
<img src="https://img.shields.io/badge/python-3.8%2B-4cd964?style=flat-square">
<img src="https://img.shields.io/badge/recon-active%20%2B%20passive-4cd964?style=flat-square">
<img src="https://img.shields.io/badge/platform-Kali%20%C2%B7%20Ubuntu%20%C2%B7%20macOS-4cd964?style=flat-square">
<img src="https://img.shields.io/badge/for-authorized%20testing%20only-ff5d5d?style=flat-square">
</p>

---

## What's new in v2.0

v1.0 harvested URLs and `grep`'d them for secret **keywords**. **v2.0 keeps all of that DNA** — active **+** passive recon, zero-config, the BHEH terminal swagger — and turns it into a real **secret-exposure engine** with live validation and branded reporting.

| | v1.0 (classic) | **v2.0** |
|---|---|---|
| **Matching** | keyword list via `grep` | **132 high-fidelity regex modules across 86 providers** for real secret *values* (AWS, GitHub, GitLab, Stripe, Slack, GCP, OpenAI, Anthropic, Groq, Figma, Supabase, PlanetScale, Doppler, Vault, Cloudinary, DB URIs, private keys…) + **Shannon-entropy** scoring |
| **Generic catch-all** | — | wide **`encryptionKey` / `*_SECRET` / `.env`** assignment detection with entropy gating |
| **Validation** | — | **LIVE validation** — verifies candidate keys against provider APIs → `VALID / invalid` |
| **Harvesting** | gobuster + waybackurls | **built-in crawler** following **JS + `.js.map` source maps**, plus pluggable `crawl,wayback,gau,katana` (+ optional gobuster brute) |
| **Fetching** | `curl` loop | **threaded**, real-browser UA, `Accept: */*`, **auto-decodes Brotli/gzip** (so WAF/CDN-compressed bundles still scan) |
| **Noise control** | — | **false-positive filtering** (placeholders, `YOUR_API_KEY`, `{{env}}`) with **local-context** matching that survives minified one-line bundles |
| **Output** | `secrets.csv` | branded **terminal table** + **`report.html`** + **`secrets.json`** + `secrets.csv` |
| **UX** | interactive prompts | **interactive menu** + full **CLI** + **`--usage`** screen + **`--scan-file`** (pipe your own `curl`) |

> It is also, our little S3cr3t...

![giphy](https://user-images.githubusercontent.com/13942386/220763198-c2a91923-c21d-4ede-851d-ce8aa983708a.gif)

---

# Description

SecretOpt1c is designed for Red Team, Pentesters, and Bug Bounty Hunters. It is a very powerful and versatile tool that helps uncover sensitive information on websites using ACTIVE and PASSIVE Techniques for Superior Accuracy! It has a built-in powerful regex pattern matching engine — written based on a lot of research and included as the `secrethub.json` file, to accurately identify secrets hidden within a website's pages (JavaScript bundles, source maps, config, `.env`, and more). It uses **both active and passive recon**, follows JavaScript and `.js.map` source maps, harvests and de-duplicates URLs, fetches all the content, analyzes it against the patterns, and saves only the secrets found, with the snippet and the exact URL + full path where each one lives.

> **v2.0** rebuilds the engine around high-fidelity **regex + entropy** detection, adds **live secret validation**, a built-in **crawler**, concurrent fetching that **auto-decodes Brotli/gzip**, and branded **HTML/JSON/CSV** reports, while keeping the original v1.0 bash workflow fully intact (see below).

---

# Features

### v2.0 engine

- **132 detection modules across 86 providers** — self-describing regex rules in `secrethub.json`, each with provider, severity, confidence, keywords, optional entropy floor, and optional live validator.
- **Shannon-entropy scoring** — kills low-entropy noise, keeps real high-entropy secrets.
- **Wide generic catch-all** — detects `encryptionKey`, `secretKey`, `apiKey`, `client_secret`, `*_SECRET`, and `.env` / `export` assignments that provider-specific rules would miss.
- **Live validation (`--validate`)** — verifies candidate keys against provider APIs and flags them `VALID` / `invalid` (read-only endpoints only).
- **Built-in crawler** — follows pages, `<script src>`, and **`.js.map` source maps**; pluggable sources `crawl,wayback,gau,katana`; optional `gobuster` active brute with live progress.
- **Robust fetching** — threaded, real-browser `User-Agent` (override with `--ua`), `Accept: */*`, and **automatic Brotli/gzip decoding** so WAF/CDN-compressed JS bundles are scanned correctly (not skipped as garbage).
- **False-positive filtering** — drops placeholders (`YOUR_API_KEY`, `example`, `{{env}}`…) using **local context around each match**, so findings survive minified single-line bundles.
- **Branded reporting** — a live terminal table **plus** `report.html` (filter/search, severity tiles, VALID badges), `secrets.json`, and `secrets.csv`.
- **Flexible run modes** — interactive menu, full CLI, `--usage` examples screen, `--list-rules` / `--explain`, `--selftest`, `--scan-file -` (pipe your own `curl`), and `--redact` to mask values when sharing a report.

### v1.0 (classic) — still included

<details>
<summary><b>Original bash workflow — step by step (click to expand)</b></summary>

- **Input:** prompts the user for the URL and the path to the wordlist.
- **Wordlist existence check:** verifies the wordlist file exists; if not, errors out and exits.
- **Directory creation:** creates a `$domain` directory to store results.
- **Gobuster:** runs `gobuster dir` to discover directories and files, with:
  - `-u $url` — target URL
  - `-w $wordlist` — path to the wordlist
  - `-x .js,.php,.yml,.env,.txt,.xml,.html,.config` — extensions to test
  - `-e` — enable extension testing
  - `-s 200,204,301,302,307,401,403` — status codes considered successful
  - `--random-agent` — random user agent per request
  - `-o $domain/gobuster.txt` — save output
- **Waybackurls:** runs right after Gobuster using the same extensions, piped through `httpx`, then both results are combined and sorted into one big discovery.
- **Progress bar:** displays a cool progress bar as it analyses secrets.
- **URL extraction:** extracts discovered URLs with `grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*"`, sorts unique into `discovered_urls.txt` (keeps 200 and 301, adding the redirected URL).
- **Loop through URLs:** loops each discovered URL and `curl`s the content into per-host files.
- **Secrets discovery:** searches the fetched content against the regex patterns in `secrethub.json` (processed with `jq`), printing each URL + full path before each secret so you know exactly where it was found.

</details>

---

# Usage

```bash
# Interactive menu (pick a target, sources, validation, verbose)
./SecretOpt1c.sh                 # or:  python3 secretopt1c.py

# Scan a domain (active crawl + passive wayback by default)
python3 secretopt1c.py -d example.com

# Scan one file / URL directly (great for a specific JS bundle)
python3 secretopt1c.py -d https://example.com/main.abc123.js

# Verbose live crawl + live validation
python3 secretopt1c.py -d example.com -v --validate

# Choose harvest sources
python3 secretopt1c.py -d example.com --sources crawl,wayback,gau,katana

# Active brute with a wordlist (gobuster, live progress)
python3 secretopt1c.py -d example.com -w /path/to/wordlist.txt

# Pipe your own curl straight into the engine
curl -s --compressed https://example.com/app.js | python3 secretopt1c.py --scan-file -

# Scan a local file
python3 secretopt1c.py --scan-file ./bundle.js

# List all 132 modules / explain one
python3 secretopt1c.py --list-rules
python3 secretopt1c.py --explain stripe-secret-key

# Prove the engine on synthetic secrets
python3 secretopt1c.py --selftest

# Mask values when sharing a report · custom UA · output dir
python3 secretopt1c.py -d example.com --redact --ua 'curl/8.4' -o ~/scans/example
```

Run `python3 secretopt1c.py --usage` for the on-screen examples, or `-h` for the full flag list.

---

# The detection engine — `secrethub.json`

Each rule is self-describing. Add your own by appending to the `rules` array:

```json
{
  "id": "stripe-secret-key",
  "name": "Stripe Secret Key",
  "provider": "Stripe",
  "severity": "critical",
  "regex": "\\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\\b",
  "entropy": 0,
  "keywords": ["stripe", "sk_live"],
  "validate": { "method": "GET", "url": "https://api.stripe.com/v1/account",
                "auth": "bearer:{{match}}", "valid_if_status": [200] }
}
```

- `regex` — matches the **value**; `group` picks which capture holds the secret.
- `entropy` — minimum Shannon entropy to accept (kills low-entropy noise).
- `severity` — `critical | high | medium | low | info`.
- `validate` — optional live check. `auth`: `bearer:` · `token:` · `header:NAME:` · `basic:` with `{{match}}` templating. Only read-only endpoints are used.
- `false_positives` — global regexes that drop placeholders/examples.
- `mentions` — the v1.0 keyword list, kept as an opt-in low-signal layer (`--mentions`).

---

# Output

Every scan writes to `./<host>/` (or `-o <dir>`):

- **`report.html`** — branded, filterable report (severity tiles, VALID badges, search).
- **`secrets.json`** — structured findings for pipelines / CI.
- **`secrets.csv`** — classic CSV (v1.0 compatible).

---

# Requirements

### v2.0 (Python)

```bash
pip install -r requirements.txt        # requests · rich · brotli
```

Optional, auto-used if installed (for extra passive/active sources): `waybackurls`, `gau`, `katana`, `gobuster`.

### v1.0 (classic bash) — optional, for the original workflow

- **figlet & lolcat:** `pip install lolcat` & `apt-get install figlet`
- **pv** (Pipe Viewer, progress bar): `sudo apt-get install pv`
- **Gobuster:** `sudo apt-get install gobuster`
- **Waybackurls:** `go install github.com/tomnomnom/waybackurls@latest`
- **Wordlists:** e.g. [SecLists](https://github.com/danielmiessler/SecLists) and [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)
- **SecretHub.json:** the custom regex pattern-matching engine, included in this repo.

---

# Installation

```bash
git clone https://github.com/blackhatethicalhacking/SecretOpt1c.git
cd SecretOpt1c
pip install -r requirements.txt
chmod +x SecretOpt1c.sh
./SecretOpt1c.sh
```

- The script opens an interactive menu (or pass `-d <target>` to scan directly).
- You can optionally provide a wordlist for the `gobuster` active brute.

---

# Screenshots


**Banner & Menu**

<img width="1908" height="1071" alt="Screenshot 2026-10-11 at 3 45 22 PM" src="https://github.com/user-attachments/assets/05a279d0-167c-48fa-9101-6786202a6e71" />

**Usage**

<img width="1908" height="1071" alt="Screenshot 2026-10-11 at 3 45 32 PM" src="https://github.com/user-attachments/assets/541589da-6ce3-470f-9794-e0365285f01c" />

**HTML report (`report.html`)**

<img width="1908" height="924" alt="Screenshot 2026-10-11 at 3 47 17 PM" src="https://github.com/user-attachments/assets/d1bd5ec1-bc73-40cd-96f9-f7d196abe25f" />

**Detection modules (`--list-rules`)**

<img width="1908" height="1071" alt="Screenshot 2026-10-11 at 3 45 48 PM" src="https://github.com/user-attachments/assets/f95cc1bc-28a3-4d18-843c-53955ab6df2e" />

---

# Compatibility: 

This tool has been tested on Kali Linux, Ubuntu and MacOS.

# Disclaimer

This tool is provided for educational and research purpose only. The author of this project are no way responsible for any misuse of this tool. 
We use it to test under NDA agreements with clients and their consents for pentesting purposes and we never encourage to misuse or take responsibility for any damage caused !

<h2 align="center">
  <a href="https://store.blackhatethicalhacking.com/" target="_blank">BHEH Official Merch</a>
</h2>

<p align="center">
Introducing our Merch Store, designed for the Offensive Security community. Explore a curated collection of apparel and drinkware, perfect for both professionals and enthusiasts. Our selection includes premium t-shirts, hoodies, and mugs, each featuring bold hacking-themed slogans and graphics that embody the spirit of red teaming and offensive security. 
Hack with style and showcase your dedication to hacker culture with gear that’s as dynamic and resilient as you are. 😊
</p>

<p align="center">

<img src="https://github.com/blackhatethicalhacking/blackhatethicalhacking/blob/main/Merch_Promo.gif" width="540px" height="540">
  </p>
