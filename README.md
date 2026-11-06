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
| `export <file.json\|file.md>` | Save the last run's results |
| `banner`, `clear`, `exit` / `quit` | |

Tab-completion covers commands, module names, option names, and option values (booleans,
choices, file paths). History is saved to `~/.zer0map_history`. Ctrl+C cancels a running
module without leaving the shell; Ctrl+D exits.

## Modules

| Module | Purpose | Key options |
|---|---|---|
| `subdomains` | DNS brute-force + crt.sh Certificate Transparency, with wildcard-DNS filtering and dangling-CNAME flagging | `DOMAIN`, `WORDLIST`, `THREADS`, `METHOD` |
| `headers` | Grades 9 security headers PASS/WARN/FAIL, scores X/9 with an A-F grade, gives recommendations | `URL`, `FOLLOW_REDIRECTS`, `TIMEOUT`, `VERIFY_SSL` |
| `techfp` | Fingerprints server/language/framework/CMS/JS/CDN from headers, cookies, HTML and known paths; flags exposed `.env`, `.git`, `web.config`, ELMAH, server-status, Swagger | `URL`, `DEPTH`, `TIMEOUT`, `VERIFY_SSL`, `THREADS` |
| `portscan` | Threaded TCP connect scan, service mapping, banner grabbing (incl. HTTP/TLS probes) | `TARGET`, `PORTS`, `THREADS`, `TIMEOUT` |
| `whois` | Raw WHOIS via IANA referral chain, DNS records, SPF/DKIM/DMARC email posture | `DOMAIN` |

`PORTS` accepts `top100`, `top1000`, `all`, ranges (`1-1024`), lists (`80,443,8080`) or a mix.
`top100` is a curated list of commonly exposed services; `top1000` is that list plus well-known
high ports, padded with the lowest ports up to 1000.

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
