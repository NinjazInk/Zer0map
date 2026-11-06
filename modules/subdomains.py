"""subdomains: passive enumeration (crt.sh, CertSpotter, HackerTarget) + DNS brute-force.

Passive sources ask third parties that have already seen the names (Certificate Transparency
logs, passive-DNS datasets); they never touch the target. Brute-force guesses names from a
wordlist and asks DNS, which does hit the target's authoritative nameservers.

Wildcard DNS (``*.example.com`` resolving to something) makes every guess look valid, so we
detect it first by resolving random labels. When the wildcard answer is a CDN IP shared by real
hosts, we additionally compare the HTTP response fingerprint before discarding a brute-force hit.

The orchestration lives in the module-level ``enumerate_subdomains`` so other modules (e.g. the
``scan`` workflow) can reuse it without going through the shell.
"""
from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path

from rich.text import Text

from core.base_module import BaseModule
from core.output import (
    add_row,
    console,
    make_table,
    print_good,
    print_info,
    print_section,
    print_warn,
)
from core.utils import (
    PASSIVE_SOURCES,
    ReconError,
    http_fingerprint,
    make_resolver,
    normalize_domain,
    resolve_full,
    run_concurrent,
)

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"


class WildcardSignature:
    """Captures how a zone answers for names that shouldn't exist, so brute-force hits that
    merely match the wildcard can be discarded."""

    def __init__(self) -> None:
        self.ips: set[str] = set()
        self.cnames: set[str] = set()
        self.fingerprints: set[tuple[int, int]] = set()

    @property
    def active(self) -> bool:
        return bool(self.ips or self.cnames or self.fingerprints)

    def matches(self, res: dict) -> bool:
        """True when the result is certainly just the wildcard answer."""
        if res["cnames"] and set(res["cnames"]) & self.cnames:
            return True
        if res["a"] or res["aaaa"]:
            ips = set(res["a"] + res["aaaa"])
            if self.ips and not self.fingerprints and ips <= self.ips:
                return True
        return False

    def maybe_wildcard(self, res: dict) -> bool:
        """True when IPs match a CDN wildcard but an HTTP check is needed to be sure."""
        if not self.fingerprints or not self.ips:
            return False
        ips = set(res["a"] + res["aaaa"])
        return bool(ips) and ips <= self.ips

    def matches_http(self, fp: tuple[int, int], tolerance: float = 0.05) -> bool:
        status, length = fp
        for fp_status, fp_len in self.fingerprints:
            if status != fp_status:
                continue
            if fp_len == 0 and length == 0:
                return True
            if fp_len > 0 and abs(length - fp_len) / fp_len <= tolerance:
                return True
        return False


def load_wordlist(path: str | None) -> list[str]:
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


def detect_wildcard(domain: str, resolver, stop_event: threading.Event) -> WildcardSignature:
    sig = WildcardSignature()
    alive_names: list[str] = []
    for _ in range(3):
        if stop_event.is_set():
            break
        label = "zm-" + secrets.token_hex(8)
        name = f"{label}.{domain}"
        res = resolve_full(name, resolver)
        sig.ips.update(res["a"] + res["aaaa"])
        sig.cnames.update(res["cnames"])
        if res["alive"]:
            alive_names.append(name)
    # Only fingerprint when the wildcard points at bare IPs (likely a CDN), not a CNAME
    if alive_names and not sig.cnames:
        for name in alive_names:
            if stop_event.is_set():
                break
            fp = http_fingerprint(name)
            if fp:
                sig.fingerprints.add(fp)
    return sig


def enumerate_subdomains(
    domain: str,
    *,
    method: str = "all",
    sources: list[str] | None = None,
    wordlist: str | None = None,
    threads: int = 10,
    nameservers: list[str] | None = None,
    stop_event: threading.Event | None = None,
    resolver=None,
) -> tuple[dict, dict]:
    """Enumerate subdomains, printing progress and tables. Returns (result, resolutions).

    ``result`` is the JSON-serializable summary. ``resolutions`` maps each resolving name to its
    full resolve_full() dict (with a ``name`` key), so callers like ``scan`` can reuse the DNS
    work without re-resolving.
    """
    stop_event = stop_event or threading.Event()
    sources = sources if sources is not None else (list(PASSIVE_SOURCES) if method in ("passive", "all") else [])
    resolver = resolver or make_resolver(timeout=2.0, lifetime=4.0, nameservers=nameservers)

    found: dict[str, dict] = {}          # name -> {sources:set, res:dict|None}
    errors: list[str] = []
    start = time.monotonic()

    def mark(name: str, source: str) -> None:
        found.setdefault(name, {"sources": set(), "res": None})["sources"].add(source)

    def set_res(name: str, res: dict) -> None:
        found.setdefault(name, {"sources": set(), "res": None})["res"] = res

    print_info(f"Target: {domain}  |  method: {method}  |  threads: {threads}"
               + (f"  |  sources: {', '.join(sources)}" if sources else ""))

    # ---------------- passive sources
    if method in ("passive", "all"):
        for name in sources:
            if stop_event.is_set():
                break
            fn = PASSIVE_SOURCES[name]
            try:
                with console.status(f"[info]Querying {name}...[/info]"):
                    hits = fn(domain)
            except ReconError as exc:
                msg = f"{name}: {exc}"
                errors.append(msg)
                print_warn(msg)
                continue
            for h in hits:
                mark(h, name)
            print_good(f"{name}: {len(hits)} name(s)")

    # ---------------- brute-force
    wildcard = WildcardSignature()
    if method in ("bruteforce", "all") and not stop_event.is_set():
        with console.status("[info]Checking for wildcard DNS...[/info]"):
            wildcard = detect_wildcard(domain, resolver, stop_event)
        if wildcard.active:
            parts = sorted(wildcard.ips) + sorted(wildcard.cnames)
            if wildcard.fingerprints:
                parts.append(f"http-fingerprints:{len(wildcard.fingerprints)}")
            print_warn(f"Wildcard DNS detected -> {', '.join(parts)}; matching brute-force hits discarded")

        words = load_wordlist(wordlist)
        print_info(f"Brute-forcing {len(words)} candidate names")
        hits = run_concurrent(
            lambda w: resolve_full(f"{w}.{domain}", resolver),
            words, threads, "DNS brute-force", stop_event,
        )
        maybe: list[tuple[str, dict]] = []
        kept = 0
        for word, res in hits:
            if not res["alive"]:
                continue
            name = f"{word}.{domain}"
            if wildcard.matches(res):
                continue
            if wildcard.maybe_wildcard(res):
                maybe.append((name, res))
                continue
            mark(name, "bruteforce")
            set_res(name, res)
            kept += 1
        if maybe:
            print_info(f"HTTP-confirming {len(maybe)} candidate(s) on CDN IPs...")
            for name, res in maybe:
                if stop_event.is_set():
                    break
                fp = http_fingerprint(name)
                if fp and wildcard.matches_http(fp):
                    continue
                mark(name, "bruteforce")
                set_res(name, res)
                kept += 1
        print_good(f"Brute-force found {kept} subdomain(s)")

    # ---------------- resolve passive names not already resolved
    todo = [n for n, e in found.items() if e["res"] is None]
    if todo and not stop_event.is_set():
        hits = run_concurrent(
            lambda n: resolve_full(n, resolver),
            todo, threads, "Resolving passive results", stop_event,
        )
        for name, res in hits:
            set_res(name, res)

    # ---------------- build rows + resolutions
    rows, unresolved, resolutions = [], [], {}
    for name in sorted(found, key=lambda n: (n.count("."), n)):
        e = found[name]
        res = e["res"] or {"a": [], "aaaa": [], "cname": None, "cnames": [],
                           "dangling": False, "error": None, "alive": False}
        srcs = sorted(e["sources"])
        if not res["alive"] and not res["error"]:
            unresolved.append(name)
            continue
        resolutions[name] = {**res, "name": name, "sources": srcs}
        rows.append({
            "subdomain": name,
            "ipv4": res["a"],
            "ipv6": res["aaaa"],
            "cname": res["cname"],
            "sources": srcs,
            "source": ", ".join(srcs),
            "dangling_cname": res["dangling"],
            "dns_error": res["error"],
        })

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
            if r["dns_error"]:
                if ip_cell.plain:
                    ip_cell.append("\n")
                ip_cell.append(f"(DNS error: {r['dns_error']})", style="warning")
            multi = len(r["sources"]) > 1
            add_row(table, r["subdomain"], ip_cell,
                    Text(r["source"], style="pass" if multi else "info"))
        console.print(table)
    else:
        print_warn("No resolving subdomains found")

    unique_ips = sorted({ip for r in rows for ip in r["ipv4"] + r["ipv6"]})
    dangling = [r["subdomain"] for r in rows if r["dangling_cname"]]
    dns_errors = [r["subdomain"] for r in rows if r["dns_error"]]
    per_source = {s: sum(s in r["sources"] for r in rows) for s in set(sources) | {"bruteforce"}}

    print_section("Summary")
    print_good(f"Total resolving subdomains: {len(rows)}")
    print_info("By source: " + ", ".join(f"{s} = {per_source[s]}" for s in sorted(per_source)))
    print_info(f"Unique IPs discovered: {len(unique_ips)}")
    if unresolved:
        print_info(f"{len(unresolved)} name(s) seen passively no longer resolve")
    if dangling:
        print_warn(f"{len(dangling)} dangling CNAME(s): {', '.join(dangling)}")
    if dns_errors:
        print_warn(f"{len(dns_errors)} name(s) had DNS errors: {', '.join(dns_errors)}")
    print_info(f"Completed in {time.monotonic() - start:.1f}s")

    result = {
        "domain": domain,
        "method": method,
        "sources": sources,
        "wildcard": {
            "ips": sorted(wildcard.ips),
            "cnames": sorted(wildcard.cnames),
            "fingerprints": len(wildcard.fingerprints),
        },
        "summary": {
            "total": len(rows),
            "by_source": per_source,
            "unique_ips": len(unique_ips),
            "unresolved": len(unresolved),
            "dangling": len(dangling),
        },
        "subdomains": rows,
        "unique_ips": unique_ips,
        "unresolved": unresolved,
        "errors": errors,
    }
    return result, resolutions


class Module(BaseModule):
    name = "subdomains"
    description = "Enumerate subdomains via passive sources (crt.sh, CertSpotter, HackerTarget) and DNS brute-force"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("DOMAIN", None, True, "Target domain (e.g. example.com)")
        self.add_option(
            "METHOD", "all", False, "bruteforce, passive, or all", type="choice",
            choices=["bruteforce", "passive", "all"],
        )
        self.add_option(
            "SOURCES", "crtsh,certspotter,hackertarget", False,
            f"Comma-separated passive sources ({', '.join(PASSIVE_SOURCES)})",
        )
        self.add_option(
            "WORDLIST", None, False, "Brute-force wordlist path (default: built-in, ~100 names)", type="path"
        )
        self.add_option("THREADS", 10, False, "Concurrent DNS lookups", type="int", minimum=1)
        self.add_option("NAMESERVERS", None, False, "Comma-separated resolver IPs (default: system)")

    def parse_sources(self) -> list[str]:
        raw = (self.get("SOURCES") or "").strip()
        if not raw:
            return list(PASSIVE_SOURCES)
        chosen = [s.strip().lower() for s in raw.split(",") if s.strip()]
        bad = [s for s in chosen if s not in PASSIVE_SOURCES]
        if bad:
            raise ReconError(f"Unknown source(s): {', '.join(bad)}. Choices: {', '.join(PASSIVE_SOURCES)}")
        return chosen

    def parse_nameservers(self) -> list[str] | None:
        raw = (self.get("NAMESERVERS") or "").strip()
        return [s.strip() for s in raw.split(",") if s.strip()] or None

    def run(self) -> dict:
        domain = normalize_domain(self.get("DOMAIN"))
        method = self.get("METHOD")
        result, _ = enumerate_subdomains(
            domain,
            method=method,
            sources=self.parse_sources() if method in ("passive", "all") else [],
            wordlist=self.get("WORDLIST"),
            threads=self.get("THREADS"),
            nameservers=self.parse_nameservers(),
            stop_event=self.stop_event,
        )
        return result
