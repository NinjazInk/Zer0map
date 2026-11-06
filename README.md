# Zer0map

An interactive, Metasploit-style reconnaissance framework for authorized security testing.

> **For authorized testing and educational purposes only.** Always obtain permission before
> scanning targets you do not own.

## Install & run

```bash
pip install -r requirements.txt
python zer0map.py
```

Non-interactive use (scripting / CI):

```bash
python zer0map.py -x "use headers; set URL https://example.com; run; export headers.md"
python zer0map.py -r commands.rc   # one command per line
```

## Commands

| Command | Description |
|---|---|
| `help` / `?` | List commands and modules |
| `modules` / `show modules` | Table of modules |
| `use <module>` / `back` | Load / unload a module |
| `show options` / `options` | Current module's options |
| `set <OPTION> <value>` / `unset <OPTION>` | Set / reset an option |
| `info` | Module details and options |
| `run` / `exploit` | Execute the module |
| `scan <domain>` | Full sweep: enumerate subdomains, then audit every live host (sugar for `use scan; set DOMAIN <domain>; run`) |
| `export <file.json\|file.md>` | Save the last run's results |
| `banner`, `clear`, `exit` / `quit` | |

Tab-completion covers commands, module names, option names, and option values (booleans,
choices, file paths). History is saved to `~/.zer0map_history`. Ctrl+C cancels a running
module without leaving the shell; Ctrl+D exits.

## Modules

| Module | Purpose | Key options |
|---|---|---|
| `subdomains` | Passive enumeration (crt.sh, CertSpotter, HackerTarget) + DNS brute-force, with CDN-aware wildcard filtering, SERVFAIL retries, DNS-error tracking and dangling-CNAME flagging | `DOMAIN`, `METHOD`, `SOURCES`, `WORDLIST`, `THREADS`, `NAMESERVERS` |
| `takeover` | Flags dangling CNAMEs that may allow subdomain takeover across ~15 hosting providers (GitHub Pages, Heroku, S3, Azure, Shopify, Netlify, …); reuses the last `subdomains` run or enumerates passively | `DOMAIN`, `INPUT`, `THREADS`, `TIMEOUT` |
| `headers` | PASS/WARN/FAIL table over the 9 core headers plus a severity-ranked findings list (cookies, CORS reflection, HTTP→HTTPS redirect, TLS errors, COOP/COEP/CORP, deep CSP). Scores /100 and grades A–F. Detects bot-protection challenge pages | `URL`, `PATHS`, `FOLLOW_REDIRECTS`, `CORS`, `CHECK_REDIRECT`, `TIMEOUT`, `VERIFY_SSL`, `VERBOSE` |
| `techfp` | Fingerprints server/language/framework/CMS/JS/CDN from headers, cookies, HTML and known paths; flags exposed `.env`, `.git`, `web.config`, ELMAH, server-status, Swagger | `URL`, `DEPTH`, `TIMEOUT`, `VERIFY_SSL`, `THREADS` |
| `portscan` | Threaded TCP connect scan, service mapping, banner grabbing (incl. HTTP/TLS probes) | `TARGET`, `PORTS`, `THREADS`, `TIMEOUT` |
| `whois` | Raw WHOIS via IANA referral chain, DNS records, SPF/DKIM/DMARC email posture | `DOMAIN` |
| `scan` | Enumerates subdomains, then audits every live host (takeover + header grade) in parallel, sorted worst-first | `DOMAIN`, `BRUTE`, `SOURCES`, `WORDLIST`, `THREADS`, `HTTP_THREADS`, `TIMEOUT`, `LIMIT`, `CORS`, `CHECK_TAKEOVER`, `PATHS`, `NAMESERVERS` |

`PORTS` accepts `top100`, `top1000`, `all`, ranges (`1-1024`), lists (`80,443,8080`) or a mix.
`top100` is a curated list of commonly exposed services; `top1000` is that list plus well-known
high ports, padded with the lowest ports up to 1000.

### subdomains / takeover notes

`METHOD` is `all` (default), `passive`, or `bruteforce`. `SOURCES` is a comma-separated subset of
`crtsh,certspotter,hackertarget`. A source that fails or is rate-limited is logged and skipped,
never fatal. The Source column lists every source a name came from. `NAMESERVERS` overrides the
system resolver (e.g. `1.1.1.1,8.8.8.8`).

Wildcard DNS is detected by resolving random labels; brute-force hits matching the wildcard are
dropped, and when the wildcard answer is a shared CDN IP the HTTP response fingerprint is compared
before discarding. Names seen passively that no longer resolve are summarized separately, and DNS
timeouts / SERVFAILs are shown per name rather than silently dropped.

`takeover` findings are leads that must be confirmed manually — providers change their error pages
and some resources cannot be re-registered.

### scan

`scan example.com` enumerates subdomains (passively by default; add `set BRUTE true` for the
wordlist), then audits every host that resolves in parallel: it runs the takeover check and the
header audit (HTTPS, falling back to HTTP) and prints one table sorted worst-first (takeover
candidates, then lowest grades), followed by the takeover list and a summary. `LIMIT` caps how
many hosts are audited, `HTTP_THREADS` controls audit concurrency, and `PATHS` adds extra paths
to check on each host. The whole result is exportable with `export`.

### headers scoring

Score starts at 100 and loses 25 per high, 12 per medium, 5 per low finding (info findings are
free). Grades: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 40, else **F**. Set `VERBOSE true` to
show informational findings and raw header values; set `PATHS /,/api,/admin` to audit several
paths in one run.

## Writing a module

Drop a file in `modules/`; any `BaseModule` subclass is registered automatically.

```python
from core.base_module import BaseModule

class Module(BaseModule):
    name = "example"
    description = "One-line description"

    def __init__(self):
        super().__init__()
        self.add_option("TARGET", None, True, "Target host")
        self.add_option("THREADS", 10, False, "Concurrency", type="int", minimum=1)

    def run(self) -> dict:
        target = self.get("TARGET")
        ...            # print with core.output helpers; check self.cancelled in loops
        return {...}   # JSON-serializable; becomes self.results and is used by `export`
```

Raise `core.utils.ReconError` for user-facing errors. The shell prints them without a traceback.
