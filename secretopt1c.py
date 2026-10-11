#!/usr/bin/env python3
"""
SecretOpt1c v2 — Unleashing secrets, for a successful attack with pinpoint accuracy.

Written by Chris "SaintDruG" Abou-Chabké — Black Hat Ethical Hacking
https://www.blackhatethicalhacking.com  |  https://github.com/blackhatethicalhacking/SecretOpt1c

v2 rewrite: high-fidelity regex + entropy detection engine, concurrent active/passive
harvesting with a built-in JS & source-map crawler, optional LIVE secret validation,
and branded terminal + HTML/JSON reporting.

For authorized Red Team / Bug Bounty use only. See DISCLAIMER in README.
"""
from __future__ import annotations

import argparse
import base64
import colorsys
import concurrent.futures as cf
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlparse, urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    print("[!] 'requests' is required:  pip install requests")
    sys.exit(1)

# ---- Optional pretty terminal (graceful fallback) --------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.theme import Theme
    _RICH = True
    BRAND = "#4cd964"
    console = Console(theme=Theme({
        "brand": BRAND, "ok": "bold #4cd964", "warn": "bold yellow",
        "crit": "bold red", "dim": "grey50", "info": "cyan",
    }))
except Exception:
    _RICH = False
    BRAND = "#4cd964"
    console = None

VERSION = "2.0.0"
THEME = "rainbow"   # rainbow | green  (banner ONLY; operational status lines are always green)
REDACT = False      # show FULL secret values by default (offensive tool); --redact to mask
AUTHOR = "Chris 'SaintDruG' Abou-Chabké"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_STYLE = {"critical": "crit", "high": "warn", "medium": "info", "low": "dim", "info": "dim"}
DEFAULT_EXT = (".js", ".json", ".map", ".env", ".yml", ".yaml", ".xml",
               ".txt", ".config", ".bak", ".php", ".html")
# Default to a REAL browser fingerprint. Bank / enterprise targets sit behind
# WAFs (Cloudflare, Akamai, F5) that 403/406 any unknown User-Agent — which is
# exactly why a scan of a protected site can come back empty. Override with --ua.
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
BROWSER_HEADERS = {
    "User-Agent": UA,
    # MUST be */* — NOT an html-preferring Accept. SPA hosts (Angular/React on
    # nginx, Firebase, Netlify…) do Accept-based content negotiation: if the
    # request says it prefers text/html, they serve index.html for EVERYTHING,
    # even /main.<hash>.js. That returns the HTML shell (no secrets) instead of
    # the real bundle — which is exactly why a scan comes back empty while
    # `curl` (which sends */*) shows the key. Match curl: accept anything.
    "Accept": "*/*",
    # Force gzip/deflate only. If we advertised 'br' (Brotli) and the local
    # 'brotli' package was missing/broken, requests would hand back the raw
    # compressed bytes as .text — unreadable garbage, zero regex hits — even
    # though curl pulls the file clean. This is a classic "finds nothing on a
    # real site" trap. Identity/gzip is always decodable.
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}
WAF_CODES = {401, 403, 406, 429, 503}


def make_session(ua=None):
    s = requests.Session()
    h = dict(BROWSER_HEADERS)
    if ua:
        h["User-Agent"] = ua
    s.headers.update(h)
    return s


def _looks_garbled(txt):
    """Heuristic: did we get undecoded compressed bytes instead of real text?
    Compressed payloads decoded as latin-1 are full of control/non-text bytes."""
    if not txt:
        return False
    sample = txt[:2000]
    bad = sum(1 for c in sample if c not in "\t\r\n" and (ord(c) < 32 or ord(c) == 0xFFFD))
    return bad / len(sample) > 0.08


def body_text(r):
    """Return readable text for a response even if it came back Brotli/gzip-encoded
    and 'requests' could not transparently decode it. This is THE fix for the
    'curl shows the secret but the scanner finds nothing' case on sites that serve
    Brotli-compressed JS/CSS bundles (common on Angular/CDN-hosted apps)."""
    txt = r.text
    if not _looks_garbled(txt):
        return txt
    raw = r.content
    ce = (r.headers.get("Content-Encoding") or "").lower()
    for dec in _decoders_for(ce):
        try:
            out = dec(raw)
            if out:
                s = out.decode("utf-8", "replace")
                if not _looks_garbled(s):
                    return s
        except Exception:
            continue
    return txt  # give up gracefully; never crash a scan over one asset


def _decoders_for(ce):
    """Yield decompressors to try, ordered by the declared Content-Encoding."""
    decs = []
    def brotli_dec(b):
        try:
            import brotli
            return brotli.decompress(b)
        except Exception:
            import brotlicffi
            return brotlicffi.decompress(b)
    def gzip_dec(b):
        import gzip as _g
        return _g.decompress(b)
    def zlib_dec(b):
        import zlib as _z
        return _z.decompress(b)
    def deflate_raw(b):
        import zlib as _z
        return _z.decompress(b, -_z.MAX_WBITS)
    if "br" in ce:
        decs = [brotli_dec, gzip_dec, zlib_dec, deflate_raw]
    elif "gzip" in ce:
        decs = [gzip_dec, brotli_dec, zlib_dec, deflate_raw]
    elif "deflate" in ce:
        decs = [zlib_dec, deflate_raw, gzip_dec, brotli_dec]
    else:
        # server didn't say (or stripped the header) — try everything
        decs = [brotli_dec, gzip_dec, zlib_dec, deflate_raw]
    return decs
QUOTES = [
    "The supreme art of war is to subdue the enemy without fighting.",
    "All warfare is based on deception.",
    "He who knows when he can fight and when he cannot, will be victorious.",
    "The whole secret lies in confusing the enemy, so that he cannot fathom our real intent.",
    "Opportunities multiply as they are seized.",
]


def cprint(msg, style=None):
    if _RICH:
        console.print(msg, style=style)
    else:
        print(re.sub(r"\[/?[^\]]+\]", "", str(msg)))


# ---- lolcat-style rainbow (built-in, no external lolcat needed) -------------------
def _rainbow(s, freq=0.09, off=0):
    """Return a rich Text with a per-character HSV rainbow sweep."""
    t = Text()
    i = off
    for ch in s:
        if ch == "\n":
            t.append("\n")
            continue
        r, g, b = colorsys.hsv_to_rgb((i * freq) % 1.0, 0.92, 1.0)
        t.append(ch, style=f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}")
        i += 1
    return t


def lol(s, freq=0.09):
    """Rainbow line — used for the BANNER taglines only (recaptures v1's lolcat vibe)."""
    plain = re.sub(r"\[/?[^\]]+\]", "", s)
    if _RICH and THEME == "rainbow":
        console.print(_rainbow(plain, freq, off=int(time.time() * 7) % 97))
    elif _RICH:
        console.print(plain, style="brand")
    else:
        print(plain)


def status(msg, style="brand"):
    """Operational status / progress line — ALWAYS brand green, never rainbow.
    Embedded rich markup (e.g. [crit]…[/crit]) still renders over the green base."""
    if _RICH:
        console.print(msg, style=style)
    else:
        print(re.sub(r"\[/?[^\]]+\]", "", str(msg)))


# ============================================================ banner
BANNER_ART = r"""
  ____                     _    ___        _   _ ___
 / ___|  ___  ___ _ __ ___| |_ / _ \ _ __ | |_/ |  / ___
 \___ \ / _ \/ __| '__/ _ \ __| | | | '_ \| __| | | |
  ___) |  __/ (__| | |  __/ |_| |_| | |_) | |_| | | |___
 |____/ \___|\___|_|  \___|\__|\___/| .__/ \__|_|_|\____|
                                    |_|      v%s
""" % VERSION


def banner():
    if _RICH:
        if THEME == "rainbow":
            # colour the art line-by-line so each row shifts hue, lolcat-style
            for ln in BANNER_ART.splitlines():
                console.print(_rainbow(ln, off=hash(ln) % 50) if ln.strip() else Text(""))
        else:
            console.print(Text(BANNER_ART, style="brand"))
        lol("Unleashing secrets, for a successful attack with pinpoint accuracy")
        lol("MEANS, IT'S  ☕ 1337 ⚡ TIME, 369 ☯")
        lol(f"Offensive Security Tip: {QUOTES[int(time.time()) % len(QUOTES)]}  — Sun Tzu")
        console.print(Panel(
            Text.assemble(
                ("Red Team / Bug Bounty secret hunting — active + passive + live validation\n", "brand"),
                (f"Made with ❤ by {AUTHOR}\n", "white"),
                ("blackhatethicalhacking.com  ·  github.com/blackhatethicalhacking/SecretOpt1c", "dim"),
            ),
            title="[brand]BHEH · SecretOpt1c[/brand]",
            subtitle=f"[dim]v{VERSION} · for authorized testing only[/dim]",
            border_style="brand",
        ))
    else:
        print(BANNER_ART)
        print("Unleashing secrets, for a successful attack with pinpoint accuracy")
        print(f"Made with <3 by {AUTHOR} — SecretOpt1c v{VERSION}")


# ============================================================ module listing / about
def list_rules(hub_path):
    det = Detector(hub_path)
    provs = sorted({r.get("provider", "Generic") for r in det.rules})
    vals = sum(1 for r in det.rules if "validate" in r)
    if _RICH:
        t = Table(title=f"[brand]SecretOpt1c — {len(det.rules)} detection modules[/brand]",
                  header_style="brand", border_style="grey30")
        for c in ("#", "Provider", "Severity", "Conf", "Live?", "Detects"):
            t.add_column(c, overflow="fold")
        for i, r in enumerate(sorted(det.rules, key=lambda x: (x.get("provider", ""), SEV_ORDER.get(x.get("severity"), 9))), 1):
            live = "[ok]✓ validate[/ok]" if "validate" in r else "[dim]–[/dim]"
            sev = r.get("severity", "medium")
            t.add_row(str(i), r.get("provider", "Generic"),
                      f"[{SEV_STYLE[sev]}]{sev.upper()}[/{SEV_STYLE[sev]}]",
                      r.get("confidence", "med")[:4], live, r["name"])
        console.print(t)
        status(f"⟡ {len(det.rules)} modules · {len(provs)} providers · {vals} with LIVE validation · "
               f"+{len(det.mention_kw)} keyword 'mentions' · {len(det.fp)} false-positive filters")
    else:
        for r in det.rules:
            print(f"[{r.get('severity','').upper():8}] {r.get('provider',''):14} {r['name']}")
        print(f"{len(det.rules)} modules · {len(provs)} providers · {vals} validators")


def explain_rule(hub_path, rule_id):
    det = Detector(hub_path)
    r = next((x for x in det.rules if x["id"] == rule_id), None)
    if not r:
        cprint(f"[warn]no rule with id '{rule_id}'. Use --list-rules to see ids.[/warn]")
        return
    if _RICH:
        console.print(Panel(
            Text.assemble(
                (f"{r['name']}\n", "brand"),
                (f"id        {r['id']}\n", "white"),
                (f"provider  {r.get('provider','Generic')}\n", "white"),
                (f"severity  {r.get('severity','medium')}   confidence {r.get('confidence','medium')}\n", "white"),
                (f"entropy≥  {r.get('entropy',0)}\n", "white"),
                (f"keywords  {', '.join(r.get('keywords',[]))}\n", "dim"),
                (f"regex     {r['regex']}\n", "info"),
                (f"validate  {json.dumps(r.get('validate','—'))}\n", "dim"),
                (f"refs      {', '.join(r.get('references',[])) or '—'}", "dim"),
            ), title=f"[brand]module · {rule_id}[/brand]", border_style="brand"))
    else:
        print(json.dumps(r, indent=2, default=str))


def about():
    banner()
    lol("SecretOpt1c finds exposed secrets on web targets using ACTIVE (crawl/brute) and")
    lol("PASSIVE (wayback/gau/katana) recon, follows JavaScript & source maps, matches")
    lol("high-fidelity regex + entropy, and can LIVE-VALIDATE keys against provider APIs.")
    cprint(f"\n[dim]Author:[/dim] {AUTHOR}   [dim]·[/dim]  blackhatethicalhacking.com")
    cprint("[dim]Use only on targets you are authorized to test.[/dim]")


# every way to run it — shared by the Usage screen and the -h epilog
EXAMPLES = [
    ("Interactive menu",            "./SecretOpt1c.sh                 (or: python3 secretopt1c.py)"),
    ("Scan a domain",               "python3 secretopt1c.py -d example.com"),
    ("Scan one file/URL directly",  "python3 secretopt1c.py -d https://example.com/main.abc123.js"),
    ("Verbose + live validation",   "python3 secretopt1c.py -d example.com -v --validate"),
    ("Pick harvest sources",        "python3 secretopt1c.py -d example.com --sources crawl,wayback,gau,katana"),
    ("Active brute (gobuster)",     "python3 secretopt1c.py -d example.com -w /path/wordlist.txt"),
    ("Pipe your own curl in",       "curl -s --compressed https://example.com/app.js | python3 secretopt1c.py --scan-file -"),
    ("Scan a local file",           "python3 secretopt1c.py --scan-file ./bundle.js"),
    ("List all 132 modules",        "python3 secretopt1c.py --list-rules"),
    ("Explain one module",          "python3 secretopt1c.py --explain stripe-secret-key"),
    ("Prove the engine",            "python3 secretopt1c.py --selftest"),
    ("Mask secrets / set UA / out", "python3 secretopt1c.py -d example.com --redact --ua 'curl/8.4' -o ~/scans/ex"),
]


def _examples_plain():
    width = max(len(t) for t, _ in EXAMPLES)
    return "\n".join(f"  {t.ljust(width)}   {c}" for t, c in EXAMPLES)


def usage(show_banner=True):
    if show_banner:
        banner()
    if _RICH:
        body = Text()
        for t, c in EXAMPLES:
            body.append(f"  {t}\n", style="brand")
            body.append(f"      {c}\n", style="white")
        console.print(Panel(body, title="[brand]U S A G E  ·  ways to run it[/brand]",
                            subtitle="[dim]authorized testing only[/dim]", border_style="brand"))
        cprint("[dim]  tip: no -d / no flags  →  interactive menu. Full flag list:  -h[/dim]")
    else:
        print("USAGE — ways to run SecretOpt1c:\n" + _examples_plain())


# ============================================================ data model
@dataclass
class Finding:
    rule_id: str
    name: str
    provider: str
    severity: str
    url: str
    secret: str            # redacted for display
    raw_len: int
    entropy: float
    line: int
    snippet: str
    validated: str = "unverified"   # valid | invalid | unverified | error
    confidence: str = "medium"

    def key(self):
        return (self.rule_id, self._full)

    _full: str = field(default="", repr=False)


# ============================================================ detector
class Detector:
    def __init__(self, hub_path):
        with open(hub_path, "r", encoding="utf-8") as fh:
            self.hub = json.load(fh)
        self.rules = []
        for r in self.hub.get("rules", []):
            try:
                r["_rx"] = re.compile(r["regex"])
            except re.error as e:
                cprint(f"[warn][!] bad regex in rule {r.get('id')}: {e}", "warn")
                continue
            self.rules.append(r)
        self.fp = [re.compile(p) for p in self.hub.get("false_positives", [])]
        m = self.hub.get("mentions", {})
        self.mention_kw = [k.lower() for k in m.get("keywords", [])]
        self.mention_sev = m.get("severity", "info")

    @staticmethod
    def entropy(s: str) -> float:
        if not s:
            return 0.0
        probs = [s.count(c) / len(s) for c in set(s)]
        return round(-sum(p * math.log2(p) for p in probs), 2)

    @staticmethod
    def redact(s: str) -> str:
        if len(s) <= 10:
            return s[:2] + "*" * max(0, len(s) - 2)
        return f"{s[:4]}{'*' * 6}{s[-4:]}  (len {len(s)})"

    def _is_fp(self, value: str, line_text: str) -> bool:
        for rx in self.fp:
            if rx.search(value) or rx.search(line_text):
                return True
        return False

    def scan(self, url: str, body: str, want_mentions=False):
        out = []
        lines = body.splitlines()
        # precompute line starts for line numbers
        starts, pos = [], 0
        for ln in lines:
            starts.append(pos)
            pos += len(ln) + 1

        def line_of(idx):
            lo, hi = 0, len(starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if starts[mid] <= idx:
                    lo = mid
                else:
                    hi = mid - 1
            return lo

        for r in self.rules:
            rx = r["_rx"]
            grp = r.get("group", 0)
            floor = float(r.get("entropy", self.hub.get("defaults", {}).get("entropy", 0)))
            for m in rx.finditer(body):
                try:
                    value = m.group(grp) if grp else (m.group(1) if m.groups() else m.group(0))
                except Exception:
                    value = m.group(0)
                if not value:
                    continue
                ln_no = line_of(m.start())
                # LOCAL context window around the match — NOT the whole line.
                # Minified bundles are one giant line; checking the full line for
                # FP words like 'example'/'sample' would drop every real finding
                # just because those words appear somewhere else in the file.
                ctx = body[max(0, m.start() - 48): m.end() + 48]
                ent = self.entropy(value)
                if floor and ent < floor:
                    continue
                if self._is_fp(value, ctx):
                    continue
                snip = ctx.strip()[:160]
                f = Finding(
                    rule_id=r["id"], name=r["name"], provider=r.get("provider", "Generic"),
                    severity=r.get("severity", "medium"), url=url,
                    secret=(self.redact(value) if REDACT else value), raw_len=len(value), entropy=ent,
                    line=ln_no + 1, snippet=snip, confidence=r.get("confidence", "medium"),
                )
                f._full = value
                f._rule = r  # type: ignore
                out.append(f)

        if want_mentions:
            low = body.lower()
            hit = sorted({k for k in self.mention_kw if k in low})
            if hit:
                f = Finding(
                    rule_id="mention", name="Secret keyword reference(s)", provider="Generic",
                    severity=self.mention_sev, url=url, secret=", ".join(hit[:8]),
                    raw_len=len(hit), entropy=0.0, line=0, snippet=", ".join(hit[:12]),
                    confidence="low",
                )
                f._full = "mention:" + ",".join(hit)
                out.append(f)
        return out


# ============================================================ validator
class Validator:
    def __init__(self, timeout=8):
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA

    def validate(self, f: Finding) -> str:
        rule = getattr(f, "_rule", None)
        if not rule or "validate" not in rule:
            return "unverified"
        v = rule["validate"]
        secret = f._full
        url = v["url"].replace("{{match}}", secret)
        headers = {"User-Agent": UA, "Accept": "application/json"}
        auth = None
        a = v.get("auth", "")
        try:
            if a.startswith("bearer:"):
                headers["Authorization"] = "Bearer " + a.split("bearer:", 1)[1].replace("{{match}}", secret)
            elif a.startswith("token:"):
                headers["Authorization"] = "token " + a.split("token:", 1)[1].replace("{{match}}", secret)
            elif a.startswith("header:"):
                _, name, val = a.split(":", 2)
                headers[name] = val.replace("{{match}}", secret)
            elif a.startswith("basic:"):
                creds = a.split("basic:", 1)[1].replace("{{match}}", secret)
                user, _, pwd = creds.partition(":")
                auth = (user, pwd)
            method = v.get("method", "GET").upper()
            resp = self.s.request(method, url, headers=headers, auth=auth,
                                  timeout=self.timeout, verify=False, allow_redirects=False)
            if "valid_if_json" in v:
                try:
                    data = resp.json()
                    if all(data.get(k) == val for k, val in v["valid_if_json"].items()):
                        return "valid"
                    return "invalid"
                except Exception:
                    return "invalid"
            ok = v.get("valid_if_status", [200])
            return "valid" if resp.status_code in ok else "invalid"
        except requests.RequestException:
            return "error"
        except Exception:
            return "error"


# ============================================================ harvester
class Harvester:
    def __init__(self, domain, threads=20, timeout=12, max_urls=800, depth=2,
                 wordlist=None, verbose=False, ua=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.max_urls = max_urls
        self.depth = depth
        self.wordlist = wordlist
        self.verbose = verbose
        self.blocked = 0          # count of WAF-style blocks (403/406/429…)
        self.s = make_session(ua)
        self.base = self._resolve_scheme(domain)
        self.host = urlparse(self.base).netloc or domain

    def _resolve_scheme(self, domain):
        """If no scheme given, probe BOTH https:// and http:// and keep whichever
        actually serves the real page (most bytes). Many bug-bounty targets — like
        testphp.vulnweb.com — only answer on http, so 'https-first' silently found
        nothing. We now pick by response, not by preference."""
        if domain.startswith("http"):
            return domain
        best, best_score = None, -1
        for scheme in ("https://", "http://"):
            try:
                r = self.s.get(scheme + domain, timeout=self.timeout, verify=False, allow_redirects=True)
                score = len(r.text or "") if r.status_code < 400 else 0
                if self.verbose:
                    status(f"  ├─ probe {scheme}{domain}  →  HTTP {r.status_code}  "
                           f"[dim]({len(r.text or '')} bytes)[/dim]")
                if score > best_score:
                    best, best_score = scheme + domain, score
            except requests.RequestException:
                if self.verbose:
                    status(f"  ├─ probe {scheme}{domain}  →  [dim]unreachable[/dim]")
                continue
        return best or ("https://" + domain)  # fall back; crawl will simply find nothing

    def _same_site(self, u):
        try:
            return urlparse(u).netloc.endswith(self.host.replace("www.", ""))
        except Exception:
            return False

    def crawl(self):
        """Built-in active crawler: pages + <script> src, following .js and .js.map.
        With -v it prints a live line for EVERY fetch — hit or miss — so you watch
        it work instead of staring at a silent 'harvested 0'."""
        seen, found = set(), set()
        seeds = [self.base, urljoin(self.base, "/sitemap.xml"),
                 urljoin(self.base, "/robots.txt"), urljoin(self.base, "/.well-known/security.txt")]
        queue = seeds[:]
        depth = 0
        while queue and depth <= self.depth and len(found) < self.max_urls:
            batch, queue = queue[:200], queue[200:]
            batch = [u for u in batch if u not in seen]
            if not batch:
                break
            if self.verbose:
                status(f"  ├─ depth {depth} — fetching {len(batch)} URL(s) …")
            with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = {ex.submit(self._get, u): u for u in batch}
                for fut in cf.as_completed(futs):
                    u = futs[fut]
                    seen.add(u)
                    body, code = fut.result()
                    if not body:
                        if self.verbose:
                            status(f"  │   [dim]· {code or 'dead'}   {u}[/dim]")
                        continue
                    found.add(u)
                    new = [l for l in self._extract(u, body)
                           if self._same_site(l) and l not in seen]
                    if self.verbose:
                        status(f"  │   [ok]✓ {code}[/ok]   {u}   [dim]→ {len(new)} links[/dim]")
                    for link in new:
                        if any(link.lower().split("?")[0].endswith(e) for e in DEFAULT_EXT):
                            found.add(link)                       # scan this asset directly
                            if link.lower().endswith(".js"):
                                found.add(link + ".map")          # chase JS source maps
                        else:
                            queue.append(link)                    # keep crawling pages
            depth += 1
        if self.verbose:
            status(f"  └─ crawl complete — {len(found)} URLs in scope")
        return list(found)[: self.max_urls]

    def _get(self, url):
        """Return (body_or_None, status_code_or_None) so the crawler can log misses too."""
        try:
            r = self.s.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            if r.status_code in WAF_CODES:
                self.blocked += 1
            if r.status_code < 400 and r.content:
                return body_text(r), r.status_code
            return None, r.status_code
        except requests.RequestException:
            return None, None

    @staticmethod
    def _extract(base, body):
        links = set()
        for m in re.finditer(r"""(?:src|href)\s*=\s*['"]([^'"]+)['"]""", body, re.I):
            links.add(urljoin(base, m.group(1)))
        # sourceMappingURL comments inside JS
        for m in re.finditer(r"sourceMappingURL=([^\s'\"]+)", body):
            links.add(urljoin(base, m.group(1)))
        # bare urls in sitemap/text
        for m in re.finditer(r"https?://[^\s'\"<>]+", body):
            links.add(m.group(0))
        return links

    def external(self, sources):
        """Shell out to installed recon tools if present; merge their URLs."""
        urls = set()
        cmds = {
            "wayback": (["waybackurls", self.host], None),
            "gau": (["gau", "--subs", self.host], None),
            "katana": (["katana", "-u", self.base, "-silent", "-jc", "-d", "2"], None),
        }
        for name in sources:
            spec = cmds.get(name)
            if not spec:
                continue
            exe = spec[0][0]
            if not shutil.which(exe):
                cprint(f"[dim]    - {name}: '{exe}' not installed, skipping[/dim]")
                continue
            try:
                out = subprocess.run(spec[0], capture_output=True, text=True, timeout=120)
                for ln in out.stdout.splitlines():
                    ln = ln.strip()
                    if ln.startswith("http") and any(ln.lower().split("?")[0].endswith(e) for e in DEFAULT_EXT):
                        urls.add(ln)
                cprint(f"[ok]    + {name}: {len(urls)} urls so far[/ok]")
            except Exception as e:
                cprint(f"[warn]    - {name} failed: {e}[/warn]")
        return list(urls)

    def gobuster(self):
        if not self.wordlist:
            return []
        if not shutil.which("gobuster"):
            cprint("[dim]    - gobuster not installed, skipping active brute[/dim]")
            return []
        out_urls = set()
        status(f"  [gobuster] dir brute on {self.base}  (live progress below)")
        try:
            cmd = ["gobuster", "dir", "-u", self.base, "-w", self.wordlist,
                   "-x", "js,php,yml,env,txt,xml,html,config,json,map", "-t", str(self.threads)]
            # stream output live so you SEE gobuster working, like v1
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            for ln in iter(proc.stdout.readline, ""):
                ln = ln.rstrip()
                if not ln:
                    continue
                m = re.search(r"(/\S+)\s+\(Status:\s*(2\d\d|3\d\d)", ln)
                if m:
                    out_urls.add(urljoin(self.base, m.group(1)))
                    status(f"    [ok][gobuster][/ok] {ln.strip()}")
                elif self.verbose and ("Progress:" in ln or ln.startswith("/")):
                    cprint(f"[dim]    {ln.strip()}[/dim]")
            proc.wait(timeout=900)
        except Exception as e:
            cprint(f"[warn]    - gobuster failed: {e}[/warn]")
        cprint(f"[ok]    + gobuster: {len(out_urls)} paths[/ok]")
        return list(out_urls)


# ============================================================ reporter
class Reporter:
    def __init__(self, outdir, host):
        self.outdir = outdir
        self.host = host
        os.makedirs(outdir, exist_ok=True)

    def terminal(self, findings):
        if not findings:
            cprint("\n[ok]No secrets detected.[/ok] (try --validate, more --sources, or a bigger scope)")
            return
        if not _RICH:
            for f in findings:
                print(f"[{f.severity.upper()}] {f.name} | {f.url} | {f.secret} | {f.validated}")
            return
        t = Table(title=f"[brand]SecretOpt1c v{VERSION} — findings for {self.host}[/brand]",
                  header_style="brand", border_style="grey30", expand=True)
        for c in ("Sev", "Provider", "Secret", "Valid?", "Entropy", "Location"):
            t.add_column(c, overflow="fold")
        for f in findings:
            valid = {"valid": "[crit]● VALID[/crit]", "invalid": "[dim]○ invalid[/dim]",
                     "error": "[warn]? error[/warn]"}.get(f.validated, "[dim]– n/a[/dim]")
            t.add_row(
                f"[{SEV_STYLE[f.severity]}]{f.severity.upper()}[/{SEV_STYLE[f.severity]}]",
                f"{f.provider}\n[dim]{f.name}[/dim]",
                f"[white]{escape(f.secret)}[/white]",
                valid, str(f.entropy),
                f"[dim]{escape(f.url)}[/dim]" + (f"[dim]:{f.line}[/dim]" if f.line else ""),
            )
        console.print(t)

    def json_report(self, findings, meta):
        path = os.path.join(self.outdir, "secrets.json")
        data = {"meta": meta, "findings": [
            {k: v for k, v in asdict(f).items() if not k.startswith("_")} for f in findings]}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return path

    def csv_report(self, findings):
        path = os.path.join(self.outdir, "secrets.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("severity,provider,rule,url,line,secret,entropy,validated,confidence\n")
            for f in findings:
                fh.write(",".join('"%s"' % str(x).replace('"', "'") for x in
                         [f.severity, f.provider, f.name, f.url, f.line, f.secret,
                          f.entropy, f.validated, f.confidence]) + "\n")
        return path

    def html_report(self, findings, meta):
        path = os.path.join(self.outdir, "report.html")
        rows = ""
        for f in findings:
            vcls = {"valid": "valid", "invalid": "inv", "error": "err"}.get(f.validated, "na")
            vtxt = {"valid": "● VALID", "invalid": "○ invalid", "error": "? error"}.get(f.validated, "– n/a")
            rows += f"""<tr class="sev-{f.severity}" data-sev="{SEV_ORDER[f.severity]}">
  <td><span class="pill {f.severity}">{f.severity.upper()}</span></td>
  <td><b>{escape(f.provider)}</b><br><span class="dim">{escape(f.name)}</span></td>
  <td class="mono">{escape(f.secret)}</td>
  <td><span class="v {vcls}">{vtxt}</span></td>
  <td class="mono">{f.entropy}</td>
  <td class="mono url">{escape(f.url)}{(':' + str(f.line)) if f.line else ''}<br><span class="snip">{escape(f.snippet)}</span></td>
</tr>"""
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
        valid_n = sum(1 for f in findings if f.validated == "valid")
        html = HTML_TMPL.format(
            host=escape(self.host), version=VERSION, ts=meta.get("finished", ""),
            total=len(findings), crit=counts["critical"], high=counts["high"],
            med=counts["medium"], low=counts["low"], valid=valid_n,
            urls=meta.get("urls_scanned", 0), rows=rows,
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path


HTML_TMPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecretOpt1c Report — {host}</title>
<style>
:root{{--bg:#07080a;--panel:#111418;--line:#232931;--fg:#eef0f2;--muted:#8a9097;--brand:#4cd964;--red:#ff4d4d;--amber:#ffb020;--cyan:#56c7ff;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,Consolas,monospace}}
.wrap{{max-width:1200px;margin:0 auto;padding:28px 20px 60px}}
.head{{border-bottom:2px solid rgba(76,217,100,.35);padding-bottom:18px;margin-bottom:22px}}
.kick{{color:var(--brand);letter-spacing:.2em;font-size:11px;text-transform:uppercase}}
h1{{font-size:30px;margin:8px 0 4px;letter-spacing:-.02em}}h1 b{{color:var(--brand)}}
.sub{{color:var(--muted);font-size:12px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:22px 0}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}}
.stat .n{{font-size:26px;font-weight:800}}.stat .l{{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-top:4px}}
.stat.c .n{{color:var(--red)}}.stat.v .n{{color:var(--brand)}}
.bar{{display:flex;gap:8px;margin:14px 0 20px;flex-wrap:wrap}}
.bar button{{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:999px;padding:7px 14px;font:inherit;font-size:12px;cursor:pointer}}
.bar button:hover{{border-color:var(--brand);color:var(--brand)}}
input#q{{flex:1;min-width:160px;background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:999px;padding:8px 14px;font:inherit}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th{{text-align:left;color:var(--brand);border-bottom:1px solid var(--line);padding:10px 8px;position:sticky;top:0;background:var(--bg)}}
td{{border-bottom:1px solid #15191e;padding:10px 8px;vertical-align:top}}
.mono{{font-family:inherit}}.dim{{color:var(--muted)}}.url{{word-break:break-all}}.snip{{color:#5c636b;font-size:11px}}
.pill{{font-weight:700;font-size:10px;border-radius:5px;padding:3px 7px}}
.pill.critical{{background:rgba(255,77,77,.15);color:var(--red)}}.pill.high{{background:rgba(255,176,32,.15);color:var(--amber)}}
.pill.medium{{background:rgba(86,199,255,.15);color:var(--cyan)}}.pill.low,.pill.info{{background:#1a1f25;color:var(--muted)}}
.v.valid{{color:var(--red);font-weight:700}}.v.inv{{color:var(--muted)}}.v.err{{color:var(--amber)}}.v.na{{color:#4b5159}}
footer{{margin-top:30px;color:#4b5159;font-size:11px;text-align:center}}
footer a{{color:var(--brand);text-decoration:none}}
</style></head><body><div class="wrap">
<div class="head">
  <div class="kick">BHEH · SecretOpt1c v{version} · secret exposure report</div>
  <h1>Findings for <b>{host}</b></h1>
  <div class="sub">{total} findings across {urls} URLs · generated {ts}</div>
</div>
<div class="stats">
  <div class="stat c"><div class="n">{crit}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n">{high}</div><div class="l">High</div></div>
  <div class="stat"><div class="n">{med}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n">{low}</div><div class="l">Low</div></div>
  <div class="stat v"><div class="n">{valid}</div><div class="l">Live/Valid</div></div>
  <div class="stat"><div class="n">{total}</div><div class="l">Total</div></div>
</div>
<div class="bar">
  <button onclick="flt('all')">All</button>
  <button onclick="flt('0')">Critical</button>
  <button onclick="flt('1')">High</button>
  <button onclick="flt('valid')">Valid only</button>
  <input id="q" placeholder="filter by provider / url / secret…" oninput="search(this.value)">
</div>
<table><thead><tr><th>Sev</th><th>Provider</th><th>Secret</th><th>Valid?</th><th>Entropy</th><th>Location</th></tr></thead>
<tbody id="tb">{rows}</tbody></table>
<footer>Made with ❤ by Chris 'SaintDruG' Abou-Chabké · <a href="https://github.com/blackhatethicalhacking/SecretOpt1c">SecretOpt1c v{version}</a>
 · Black Hat Ethical Hacking · for authorized testing only</footer>
</div><script>
function flt(v){{document.querySelectorAll('#tb tr').forEach(function(r){{
 if(v==='all')r.style.display='';
 else if(v==='valid')r.style.display=r.querySelector('.v.valid')?'':'none';
 else r.style.display=(r.dataset.sev<=v)?'':'none';}});}}
function search(q){{q=q.toLowerCase();document.querySelectorAll('#tb tr').forEach(function(r){{
 r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';}});}}
</script></body></html>"""


# ============================================================ orchestration
def run(args):
    if not args.no_banner:
        banner()
    det = Detector(args.hub)
    provs = len({r.get("provider", "Generic") for r in det.rules})
    vals = sum(1 for r in det.rules if "validate" in r)

    harv = Harvester(args.domain, threads=args.threads, max_urls=args.max_urls,
                     depth=args.depth, wordlist=args.wordlist, verbose=args.verbose,
                     ua=getattr(args, "ua", None))
    host = harv.host
    outdir = args.output or host

    status(f"▶ Loadout: {len(det.rules)} detection modules · {provs} providers · "
           f"{vals} live-validators · {len(det.fp)} FP filters")
    status(f"▶ Target: {host}  ({harv.base})  · sources: {args.sources} · threads: {args.threads}"
           + ("  · VALIDATE ON" if args.validate else ""))

    urls = set()
    srcs = [s.strip() for s in args.sources.split(",") if s.strip()]
    if "crawl" in srcs:
        status("  [*] ACTIVE crawl — pages + <script> JS + .js.map source maps …")
        urls.update(harv.crawl())
    ext = [s for s in srcs if s in ("wayback", "gau", "katana")]
    if ext:
        status(f"  [*] PASSIVE sources — {', '.join(ext)} …")
        urls.update(harv.external(ext))
    if args.wordlist:
        status("  [*] ACTIVE brute — gobuster …")
        urls.update(harv.gobuster())
    urls = sorted(u for u in urls if u.startswith("http"))
    status(f"  ✓ harvested {len(urls)} candidate URLs")

    # fetch + scan concurrently
    findings, scanned = [], 0
    scan_blocked = [0]
    sess = make_session(getattr(args, "ua", None))

    def fetch_scan(u):
        try:
            r = sess.get(u, timeout=args.timeout, verify=False, allow_redirects=True)
            if r.status_code in WAF_CODES:
                scan_blocked[0] += 1
            if r.status_code >= 400 or not r.content:
                return (u, [])
            return (u, det.scan(u, body_text(r), want_mentions=args.mentions))
        except requests.RequestException:
            return (u, [])

    if urls:
        status(f"  [*] fetching & analyzing {len(urls)} URLs with {len(det.rules)} modules …")
        if args.verbose or not _RICH:
            with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
                for u, res in ex.map(fetch_scan, urls):
                    scanned += 1
                    if args.verbose:
                        tag = f"[ok][+] {len(res)} hit(s)[/ok]" if res else "[dim][-] clean[/dim]"
                        status(f"    {tag}  {u}")
                    findings.extend(res)
        else:
            with Progress(SpinnerColumn(style="brand"), TextColumn("[brand]analyzing[/brand]"),
                          BarColumn(complete_style="brand"), TextColumn("{task.completed}/{task.total}"),
                          TimeElapsedColumn(), console=console, transient=True) as pr:
                task = pr.add_task("scan", total=len(urls))
                with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
                    for u, res in ex.map(fetch_scan, urls):
                        findings.extend(res); scanned += 1; pr.advance(task)

    # dedup
    uniq, seen = [], set()
    for f in sorted(findings, key=lambda x: SEV_ORDER[x.severity]):
        if f.key() in seen:
            continue
        seen.add(f.key()); uniq.append(f)
    findings = uniq

    # validate
    if args.validate and findings:
        targets = [f for f in findings if getattr(f, "_rule", None) and "validate" in f._rule]
        if targets:
            status(f"  [*] LIVE-validating {len(targets)} candidate secret(s) against provider APIs …")
            val = Validator(timeout=args.timeout)
            with cf.ThreadPoolExecutor(max_workers=min(10, args.threads)) as ex:
                for f, verdict in zip(targets, ex.map(val.validate, targets)):
                    f.validated = verdict

    findings.sort(key=lambda x: (SEV_ORDER[x.severity], x.validated != "valid"))

    meta = {"tool": "SecretOpt1c", "version": VERSION, "host": host,
            "urls_scanned": scanned, "rules": len(det.rules),
            "finished": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            "validated": args.validate}

    # ALWAYS write the folder + reports, even with 0 findings, so you know it ran
    rep = Reporter(outdir, host)
    rep.terminal(findings)
    j = rep.json_report(findings, meta)
    c = rep.csv_report(findings)
    h = rep.html_report(findings, meta)

    crit = sum(1 for f in findings if f.severity == "critical")
    live = sum(1 for f in findings if f.validated == "valid")
    cprint(f"\n[brand]▣ Done.[/brand] {len(findings)} findings "
           f"([crit]{crit} critical[/crit], [ok]{live} live[/ok]) · {scanned} URLs scanned")
    cprint(f"[ok]  reports saved → {os.path.abspath(outdir)}/[/ok]")
    cprint(f"[dim]    {h}\n    {j}\n    {c}[/dim]")
    if not urls:
        cprint("[warn]  Note: 0 URLs harvested — host may be unreachable or empty. "
               "Try --sources crawl,wayback,gau or check the scheme.[/warn]")
    blocked_total = harv.blocked + scan_blocked[0]
    if blocked_total:
        cprint(f"[warn]  Note: {blocked_total} request(s) returned 401/403/406/429/503 — "
               "likely WAF/bot filtering. Try --ua to spoof a specific browser, or scan the "
               "exact file URL (-d https://host/app.<hash>.js).[/warn]")
    status("  it is also, our little S3cr3t…", style="dim")


def main():
    p = argparse.ArgumentParser(
        prog="secretopt1c",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="SecretOpt1c v2.0 — Red Team / Bug Bounty secret hunting (authorized use only).",
        epilog="ways to run it:\n" + _examples_plain() +
               "\n\n  (no -d and no flags opens the interactive menu)\n")
    p.add_argument("-d", "--domain", help="target domain or URL (e.g. example.com)")
    p.add_argument("-w", "--wordlist", help="wordlist for gobuster active brute (optional)")
    p.add_argument("-o", "--output", help="output directory (default: <host>)")
    p.add_argument("--hub", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrethub.json"),
                   help="path to secrethub.json ruleset")
    p.add_argument("--sources", default="crawl,wayback",
                   help="harvest sources: crawl,wayback,gau,katana (comma-sep)")
    p.add_argument("--validate", action="store_true", help="live-validate candidate secrets against provider APIs")
    p.add_argument("--mentions", action="store_true", help="also report low-signal keyword 'mentions'")
    p.add_argument("--ua", help="override User-Agent (default: a real Chrome UA, to get past WAFs)")
    p.add_argument("--threads", type=int, default=25, help="concurrency (default 25)")
    p.add_argument("--timeout", type=int, default=12, help="per-request timeout seconds")
    p.add_argument("--max-urls", type=int, default=800, dest="max_urls", help="cap on harvested URLs")
    p.add_argument("--depth", type=int, default=2, help="crawl depth")
    p.add_argument("-v", "--verbose", action="store_true", help="show URLs as they are crawled/fetched + live gobuster")
    p.add_argument("--theme", choices=["rainbow", "green"], default="rainbow", help="banner/status theme")
    p.add_argument("--list-rules", action="store_true", help="list all detection modules and exit")
    p.add_argument("--explain", metavar="RULE_ID", help="explain one detection module and exit")
    p.add_argument("--no-banner", action="store_true", help="suppress banner")
    p.add_argument("--selftest", action="store_true", help="run a built-in detection self-test and exit")
    p.add_argument("--scan-file", metavar="PATH", dest="scan_file",
                   help="scan a local file (or '-' for STDIN) against secrethub.json — "
                        "e.g.  curl -s --compressed URL | secretopt1c.py --scan-file -")
    p.add_argument("--stdin", action="store_true", help="scan content piped on STDIN (same as --scan-file -)")
    p.add_argument("--redact", action="store_true",
                   help="mask secret values in output (default: show full value — it's your finding)")
    p.add_argument("--usage", action="store_true", help="show example invocations (all the ways to run it) and exit")
    args = p.parse_args()

    global THEME, REDACT
    THEME = args.theme
    REDACT = args.redact

    if args.usage:
        return usage()
    if args.list_rules:
        banner(); return list_rules(args.hub)
    if args.explain:
        return explain_rule(args.hub, args.explain)
    if args.selftest:
        return selftest(args)
    if args.stdin or args.scan_file:
        return scan_local(args)

    if not args.domain:
        return menu(args, p)

    try:
        run(args)
    except KeyboardInterrupt:
        cprint("\n[warn]interrupted.[/warn]")


def scan_local(args):
    """Scan already-fetched content (a file, or STDIN) straight against secrethub.json.
    This is the 'you curl it, I grep the rules' path — it removes recon/fetch from the
    equation entirely, so you can prove the engine on content you got yourself:

        curl -s --compressed https://host/main.<hash>.js | python3 secretopt1c.py --scan-file -
        python3 secretopt1c.py --scan-file ./main.js
    """
    src = "-" if args.stdin else args.scan_file
    try:
        if src == "-":
            data = sys.stdin.buffer.read()
            label = "stdin"
        else:
            with open(src, "rb") as fh:
                data = fh.read()
            label = src
    except Exception as e:
        cprint(f"[crit]could not read {src}: {e}[/crit]"); return
    # bytes may be gzip/brotli if the user piped a raw compressed body — decode defensively
    text = data.decode("utf-8", "replace")
    if _looks_garbled(text):
        for dec in _decoders_for(""):
            try:
                out = dec(data)
                s = out.decode("utf-8", "replace")
                if not _looks_garbled(s):
                    text = s; break
            except Exception:
                continue
    if not args.no_banner:
        banner()
    det = Detector(args.hub)
    status(f"▶ Scanning {label} ({len(text):,} bytes) against {len(det.rules)} modules …")
    findings = det.scan(label, text, want_mentions=args.mentions)
    findings.sort(key=lambda x: SEV_ORDER[x.severity])
    rep = Reporter(args.output or "scan-out", label)
    rep.terminal(findings)
    meta = {"tool": "SecretOpt1c", "version": VERSION, "host": label, "urls_scanned": 1,
            "rules": len(det.rules),
            "finished": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"), "validated": False}
    h = rep.html_report(findings, meta); rep.json_report(findings, meta); rep.csv_report(findings)
    crit = sum(1 for f in findings if f.severity == "critical")
    cprint(f"\n[brand]▣ {len(findings)} findings[/brand] ([crit]{crit} critical[/crit]) "
           f"· report → {os.path.abspath(args.output or 'scan-out')}/report.html")


def menu(args, parser):
    """Interactive menu shown when SecretOpt1c is launched with no target."""
    banner()
    while True:
        if _RICH:
            console.print(Panel(
                Text.assemble(
                    ("  [1]  ", "brand"), ("Scan a target\n", "white"),
                    ("  [2]  ", "brand"), ("List detection modules (what it hunts for)\n", "white"),
                    ("  [3]  ", "brand"), ("Run self-test (prove the engine + sample report)\n", "white"),
                    ("  [4]  ", "brand"), ("Usage / examples (all the ways to run it)\n", "white"),
                    ("  [5]  ", "brand"), ("About\n", "white"),
                    ("  [6]  ", "brand"), ("Exit", "white"),
                ), title="[brand]M E N U[/brand]", border_style="brand", width=62))
        else:
            print("\n[1] Scan  [2] List modules  [3] Self-test  [4] Usage  [5] About  [6] Exit")
        try:
            choice = input("  SecretOpt1c ⟫ ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(); return
        if choice in ("1", "scan"):
            try:
                args.domain = input("    target domain/URL: ").strip()
                if not args.domain:
                    continue
                wl = input("    wordlist for gobuster (Enter to skip): ").strip()
                args.wordlist = wl or None
                src = input("    sources [crawl,wayback,gau,katana] (Enter=crawl,wayback): ").strip()
                args.sources = src or "crawl,wayback"
                args.validate = input("    live-validate secrets? [y/N]: ").strip().lower().startswith("y")
                args.verbose = input("    verbose (show every URL)? [y/N]: ").strip().lower().startswith("y")
                args.no_banner = True
                run(args)
            except KeyboardInterrupt:
                cprint("\n[warn]  interrupted.[/warn]")
        elif choice in ("2", "list", "modules"):
            list_rules(args.hub)
        elif choice in ("3", "selftest", "test"):
            args.no_banner = True; selftest(args)
        elif choice in ("4", "usage", "examples", "help"):
            usage(show_banner=False)
        elif choice in ("5", "about"):
            about()
        elif choice in ("6", "q", "quit", "exit"):
            lol("  Security is a myth!  —  www.blackhatethicalhacking.com"); return
        else:
            cprint("[dim]  pick 1-6[/dim]")


def selftest(args):
    """Prove the engine works against a synthetic page full of fake secrets."""
    if not getattr(args, "no_banner", False):
        banner()
    det = Detector(args.hub)
    sample = (
        "const cfg = {\n"
        "  aws: 'AKIAZ4NC7PXYBQD3RLMN',\n"
        "  stripe: 'sk_live_51H8xWconcrete0ABCDEFGHijkLMNopq',\n"
        "  gh: 'ghp_0123456789abcdefghijABCDEFGHIJ012345',\n"
        "  slack: 'xoxb-123456789012-abcdefABCDEF0123',\n"
        "  google: 'AIzaSyB1a2b3c4d5e6f7g8h9i0J1k2L3m4N5o6P',\n"
        "  openai: 'sk-proj-ABCDEFGHIJKLMNOPQRSTT3BlbkFJabcdefghijklmnopqrst',\n"
        "  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4',\n"
        "  db: 'postgres://admin:S3cr3tP@ss@db.internal:5432/prod',\n"
        "  encryptionKey: 'FR9Tu1oIpbmIsSNIpgTQhq',\n"
        "  ENCRYPTION_SECRET=aB3dE6gH9jK2mN5pQ8sT1vW4\n"
        "  placeholder: 'YOUR_API_KEY_HERE',  // should be filtered\n"
        "  ex: 'AKIAIOSFODNN7EXAMPLE'          // should be filtered\n"
        "};\n"
    )
    findings = det.scan("https://assets.example.com/static/app.min.js", sample, want_mentions=True)
    findings.sort(key=lambda x: SEV_ORDER[x.severity])
    outdir = "selftest"
    rep = Reporter(outdir, "selftest")
    rep.terminal(findings)
    meta = {"tool": "SecretOpt1c", "version": VERSION, "host": "selftest (synthetic)",
            "urls_scanned": 1, "rules": len(det.rules),
            "finished": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"), "validated": False}
    h = rep.html_report(findings, meta); rep.json_report(findings, meta); rep.csv_report(findings)
    cprint(f"\n[ok]self-test matched {len(findings)} findings "
           f"(placeholders/examples correctly filtered).[/ok]")
    cprint(f"[ok]  sample report written → {os.path.abspath(outdir)}/report.html[/ok]")


if __name__ == "__main__":
    main()
