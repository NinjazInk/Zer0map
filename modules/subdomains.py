"""subdomains: DNS brute-force + Certificate Transparency (crt.sh) subdomain enumeration."""
from __future__ import annotations

import json
import random
import string
import time
from pathlib import Path

from rich.text import Text

from core.base_module import BaseModule
from core.output import (
    add_row,
    console,
    make_table,
    print_error,
    print_good,
    print_info,
    print_section,
    print_warn,
)
from core.utils import (
    DOMAIN_RE,
    RateLimiter,
    ReconError,
    http_request,
    make_resolver,
    normalize_domain,
    resolve_host,
    run_concurrent,
)

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"
CRTSH_URL = "https://crt.sh/"
# crt.sh is a free community service that aggressively throttles: keep >=5s between calls
CRTSH_LIMITER = RateLimiter(5.0)


class Module(BaseModule):
    name = "subdomains"
    description = "Enumerate subdomains via DNS brute-force and Certificate Transparency (crt.sh)"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("DOMAIN", None, True, "Target domain (e.g. example.com)")
        self.add_option(
            "WORDLIST", None, False, "Subdomain wordlist path (default: built-in, ~100 names)", type="path"
        )
        self.add_option("THREADS", 10, False, "Concurrent DNS lookups", type="int", minimum=1)
        self.add_option(
            "METHOD", "all", False, "bruteforce, crtsh, or all", type="choice",
            choices=["bruteforce", "crtsh", "all"],
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _load_wordlist(path: str | None) -> list[str]:
        source = Path(path) if path else DEFAULT_WORDLIST
        try:
            lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            raise ReconError(f"Cannot read wordlist {source}: {exc.strerror}") from None
        words, seen = [], set()
        for line in lines:
            word = line.strip().lower().strip(".")
            if word and not word.startswith("#") and word not in seen:
                seen.add(word)
                words.append(word)
        if not words:
            raise ReconError(f"Wordlist {source} is empty")
        return words

    def _detect_wildcard(self, domain: str, resolver) -> set[str]:
        """Resolve a random label; if it answers, the zone has wildcard DNS."""
        ips: set[str] = set()
        for _ in range(2):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            try:
                res = resolve_host(f"{label}.{domain}", resolver)
            except ReconError:
                continue
            if res:
                ips.update(res["a"] + res["aaaa"])
        return ips

    def _query_crtsh(self, domain: str) -> list[dict]:
        params = {"q": f"%.{domain}", "output": "json"}
        last_error = "no response"
        for attempt in range(1, 4):
            if self.cancelled:
                return []
            CRTSH_LIMITER.wait()
            try:
                resp = http_request("GET", CRTSH_URL, params=params, timeout=45)
            except ReconError as exc:
                last_error = str(exc)
            else:
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except (json.JSONDecodeError, ValueError):
                        last_error = "crt.sh returned a non-JSON response"
                    else:
                        if isinstance(data, list):
                            return data
                        last_error = "unexpected JSON structure from crt.sh"
                elif resp.status_code in (429, 502, 503, 504):
                    last_error = f"crt.sh is throttling/unavailable (HTTP {resp.status_code})"
                else:
                    raise ReconError(f"crt.sh returned HTTP {resp.status_code}")
            if attempt < 3:
                backoff = 5 * attempt
                print_warn(f"crt.sh attempt {attempt} failed: {last_error}; retrying in {backoff}s")
                time.sleep(backoff)
        raise ReconError(f"crt.sh query failed after 3 attempts: {last_error}")

    @staticmethod
    def _extract_names(entries: list[dict], domain: str) -> set[str]:
        names: set[str] = set()
        for entry in entries:
            values = f"{entry.get('name_value', '')}\n{entry.get('common_name', '')}"
            for raw in values.splitlines():
                name = raw.strip().lower().rstrip(".")
                while name.startswith("*."):
                    name = name[2:]
                if not name or "@" in name or name == domain:
                    continue
                if name.endswith("." + domain) and DOMAIN_RE.match(name):
                    names.add(name)
        return names

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        domain = normalize_domain(self.get("DOMAIN"))
        method = self.get("METHOD")
        threads = self.get("THREADS")
        resolver = make_resolver(timeout=2.0, lifetime=4.0)
        found: dict[str, dict] = {}
        errors: list[str] = []
        crt_unresolved: list[str] = []
        start = time.monotonic()

        def record(name: str, res: dict, source: str) -> None:
            entry = found.setdefault(name, {"a": [], "aaaa": [], "cname": None, "sources": set()})
            entry["a"] = sorted(set(entry["a"]) | set(res["a"]))
            entry["aaaa"] = sorted(set(entry["aaaa"]) | set(res["aaaa"]))
            entry["cname"] = entry["cname"] or res["cname"]
            entry["sources"].add(source)

        print_info(f"Target: {domain}  |  method: {method}  |  threads: {threads}")

        with console.status("[info]Checking for wildcard DNS...[/info]"):
            wildcard_ips = self._detect_wildcard(domain, resolver)
        if wildcard_ips:
            print_warn(
                f"Wildcard DNS detected ({', '.join(sorted(wildcard_ips))}); "
                "brute-force hits pointing only at these IPs will be discarded"
            )

        # ---------------- DNS brute-force
        if method in ("bruteforce", "all"):
            words = self._load_wordlist(self.get("WORDLIST"))
            print_info(f"Brute-forcing {len(words)} candidate names")
            hits = run_concurrent(
                lambda w: resolve_host(f"{w}.{domain}", resolver),
                words, threads, "DNS brute-force", self.stop_event,
            )
            kept = 0
            for word, res in hits:
                ips = set(res["a"] + res["aaaa"])
                if wildcard_ips and ips and ips <= wildcard_ips:
                    continue
                record(f"{word}.{domain}", res, "bruteforce")
                kept += 1
            print_good(f"Brute-force found {kept} subdomain(s)")

        # ---------------- Certificate Transparency
        if method in ("crtsh", "all") and not self.cancelled:
            try:
                with console.status("[info]Querying crt.sh Certificate Transparency logs...[/info]"):
                    entries = self._query_crtsh(domain)
                names = self._extract_names(entries, domain)
                print_info(f"crt.sh returned {len(entries)} certificate(s), {len(names)} unique name(s)")
                if names:
                    hits = run_concurrent(
                        lambda n: resolve_host(n, resolver),
                        sorted(names), threads, "Validating crt.sh names", self.stop_event,
                    )
                    resolved = {n for n, _ in hits}
                    for name, res in hits:
                        record(name, res, "crt.sh")
                    crt_unresolved = sorted(names - resolved)
                    print_good(
                        f"crt.sh: {len(resolved)} name(s) resolve, "
                        f"{len(crt_unresolved)} no longer resolve"
                    )
            except ReconError as exc:
                errors.append(str(exc))
                print_error(str(exc))

        # ---------------- output
        rows = []
        for name in sorted(found, key=lambda n: (n.count("."), n)):
            e = found[name]
            source = "both" if len(e["sources"]) > 1 else next(iter(e["sources"]))
            rows.append(
                {
                    "subdomain": name,
                    "ipv4": e["a"],
                    "ipv6": e["aaaa"],
                    "cname": e["cname"],
                    "source": source,
                    "dangling_cname": bool(e["cname"] and not e["a"] and not e["aaaa"]),
                }
            )

        print_section("Subdomains")
        if rows:
            table = make_table(None, ["Subdomain", "IP Address(es)", "Source"])
            for r in rows:
                ip_cell = Text("\n".join(r["ipv4"] + r["ipv6"]))
                if r["cname"]:
                    if ip_cell.plain:
                        ip_cell.append("\n")
                    ip_cell.append(f"CNAME {r['cname']}", style="muted")
                if r["dangling_cname"]:
                    ip_cell.append("\n(CNAME target doesn't resolve: check for takeover)", style="warning")
                src_style = {"both": "pass", "crt.sh": "info", "bruteforce": "accent"}[r["source"]]
                add_row(table, r["subdomain"], ip_cell, Text(r["source"], style=src_style))
            console.print(table)
        else:
            print_warn("No subdomains found")

        unique_ips = sorted({ip for r in rows for ip in r["ipv4"] + r["ipv6"]})
        by_source = {
            "bruteforce": sum(r["source"] == "bruteforce" for r in rows),
            "crt.sh": sum(r["source"] == "crt.sh" for r in rows),
            "both": sum(r["source"] == "both" for r in rows),
        }
        dangling = [r["subdomain"] for r in rows if r["dangling_cname"]]

        print_section("Summary")
        print_good(f"Total subdomains found: {len(rows)}")
        print_info(
            f"By source: bruteforce only = {by_source['bruteforce']}, "
            f"crt.sh only = {by_source['crt.sh']}, both = {by_source['both']}"
        )
        print_info(f"Unique IPs discovered: {len(unique_ips)}")
        if dangling:
            print_warn(f"{len(dangling)} dangling CNAME(s): {', '.join(dangling)}")
        print_info(f"Completed in {time.monotonic() - start:.1f}s")

        return {
            "domain": domain,
            "method": method,
            "wildcard_ips": sorted(wildcard_ips),
            "summary": {
                "total": len(rows),
                "bruteforce_only": by_source["bruteforce"],
                "crtsh_only": by_source["crt.sh"],
                "both": by_source["both"],
                "unique_ips": len(unique_ips),
            },
            "subdomains": rows,
            "unique_ips": unique_ips,
            "crtsh_unresolved": crt_unresolved,
            "errors": errors,
        }
