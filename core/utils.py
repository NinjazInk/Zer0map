"""Shared helpers: input normalization, HTTP, DNS, rate limiting and concurrency."""
from __future__ import annotations

import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests
import urllib3
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from core.output import console

VERSION = "1.0"
USER_AGENT = f"Mozilla/5.0 (compatible; Zer0map/{VERSION}; +authorized-security-testing)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)


class ReconError(Exception):
    """A user-facing error: printed cleanly by the shell without a traceback."""


# ----------------------------------------------------------------------------- normalization
def normalize_domain(value: str) -> str:
    """Accept 'example.com', 'https://example.com/path', 'Example.COM.' -> 'example.com'."""
    raw = (value or "").strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/")[0].split(":")[0].strip(".").lower()
    try:
        raw = raw.encode("idna").decode("ascii")
    except UnicodeError:
        raise ReconError(f"Invalid domain: {value!r}") from None
    if not DOMAIN_RE.match(raw):
        raise ReconError(f"Invalid domain: {value!r}")
    return raw


def normalize_url(value: str) -> str:
    raw = (value or "").strip()
    if not re.match(r"^https?://", raw, re.I):
        if "://" in raw:
            raise ReconError("Only http:// and https:// URLs are supported")
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ReconError(f"Invalid URL: {value!r}")
    return raw


# ----------------------------------------------------------------------------- HTTP
_thread_local = threading.local()


def get_session() -> requests.Session:
    """One requests.Session per thread (Session objects aren't guaranteed thread-safe)."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        _thread_local.session = session
    return session


def http_request(
    method: str,
    url: str,
    *,
    timeout: float = 10,
    allow_redirects: bool = True,
    verify: bool = True,
    **kwargs: Any,
) -> requests.Response:
    """Perform an HTTP request, converting every network failure into a ReconError."""
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        return get_session().request(
            method, url, timeout=timeout, allow_redirects=allow_redirects, verify=verify, **kwargs
        )
    except requests.exceptions.SSLError as exc:
        raise ReconError(
            f"SSL/TLS error for {url}: {_short(exc)} (set VERIFY_SSL false to skip verification)"
        ) from None
    except requests.exceptions.ConnectTimeout:
        raise ReconError(f"Connection to {url} timed out after {timeout}s") from None
    except requests.exceptions.ReadTimeout:
        raise ReconError(f"{url} did not respond within {timeout}s") from None
    except requests.exceptions.TooManyRedirects:
        raise ReconError(f"Too many redirects for {url}") from None
    except requests.exceptions.InvalidURL:
        raise ReconError(f"Invalid URL: {url}") from None
    except requests.exceptions.ConnectionError as exc:
        msg = _short(exc)
        if "Name or service not known" in msg or "getaddrinfo" in msg or "NameResolution" in msg:
            raise ReconError(f"DNS resolution failed for {urlparse(url).hostname}") from None
        if "refused" in msg.lower():
            raise ReconError(f"Connection refused by {urlparse(url).netloc}") from None
        raise ReconError(f"Connection error for {url}: {msg}") from None
    except requests.exceptions.RequestException as exc:
        raise ReconError(f"HTTP request failed for {url}: {_short(exc)}") from None


def _short(exc: BaseException, limit: int = 160) -> str:
    text = str(exc)
    # urllib3 wraps errors deeply; keep the innermost reason
    m = re.search(r"\(Caused by \w+\((.*)\)\)$", text)
    if m:
        text = m.group(1)
    return text if len(text) <= limit else text[: limit - 3] + "..."


class RateLimiter:
    """Ensures at least `interval` seconds between calls to wait() (thread-safe)."""

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            delay = self._last + self.interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()


# ----------------------------------------------------------------------------- DNS
def make_resolver(
    timeout: float = 3.0, lifetime: float = 5.0, nameservers: list[str] | None = None
) -> dns.resolver.Resolver:
    try:
        resolver = dns.resolver.Resolver(configure=True)
    except (dns.resolver.NoResolverConfiguration, OSError):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    if nameservers:
        resolver.nameservers = list(nameservers)
    if not resolver.nameservers:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def dns_query(
    name: str, rdtype: str, resolver: dns.resolver.Resolver
) -> tuple[list[str], int | None, str | None]:
    """Return (records, ttl, canonical_name). Empty list when the record doesn't exist.

    Raises ReconError only for resolver-level failures (timeouts / no nameservers),
    so callers can tell "doesn't exist" apart from "couldn't ask".
    """
    try:
        answer = resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN):
        return [], None, None
    except dns.resolver.NoNameservers:
        return [], None, None  # SERVFAIL / refused from all nameservers: treat as absent
    except dns.exception.Timeout:
        raise ReconError(f"DNS timeout resolving {name} ({rdtype})") from None
    except dns.exception.DNSException as exc:
        raise ReconError(f"DNS error resolving {name} ({rdtype}): {exc}") from None
    records = []
    for rr in answer:
        if rdtype == "TXT":
            records.append(b"".join(rr.strings).decode("utf-8", "replace"))
        else:
            records.append(rr.to_text().rstrip(".") if rdtype in ("CNAME", "NS", "PTR") else rr.to_text())
    canonical = str(answer.canonical_name).rstrip(".")
    return records, answer.rrset.ttl if answer.rrset else None, canonical


def resolve_host(name: str, resolver: dns.resolver.Resolver) -> dict | None:
    """Resolve A/AAAA (and CNAME). Returns None if the name doesn't resolve at all."""
    a, _, canon_a = dns_query(name, "A", resolver)
    aaaa, _, canon_aaaa = dns_query(name, "AAAA", resolver)
    cname = None
    for canon in (canon_a, canon_aaaa):
        if canon and canon.lower() != name.lower():
            cname = canon
            break
    if not a and not aaaa:
        records, _, _ = dns_query(name, "CNAME", resolver)
        if records:
            cname = records[0]
    if not a and not aaaa and not cname:
        return None
    return {"a": sorted(a), "aaaa": sorted(aaaa), "cname": cname}


# Resolver-level failure codes returned all nameservers answered SERVFAIL
SERVFAIL_RETRIES = 2


def resolve_full(name: str, resolver: dns.resolver.Resolver, retries: int = SERVFAIL_RETRIES) -> dict:
    """Resolve A/AAAA/CNAME for a name, returning a rich result that always has the same shape.

    Unlike resolve_host this never returns None and never raises for an ordinary lookup: it
    reports transient resolver failures in the ``error`` field and flags dangling CNAMEs (a
    CNAME whose chain ends in NXDOMAIN: a subdomain-takeover signal).

    Returns {a, aaaa, cname (str|None), cnames (list), dangling (bool), error (str|None),
    alive (bool)}.
    """
    out = {"a": [], "aaaa": [], "cname": None, "cnames": [], "dangling": False,
           "error": None, "alive": False}

    def _resolve_with_retry(rtype: str):
        last: Exception | None = None
        for attempt in range(1 + retries):
            try:
                return resolver.resolve(name, rtype)
            except dns.resolver.NoNameservers as exc:  # SERVFAIL from every nameserver
                last = exc
                if attempt < retries:
                    time.sleep(0.5 * (attempt + 1))
        raise last  # type: ignore[misc]

    cnames: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answer = _resolve_with_retry(rtype)
        except dns.resolver.NXDOMAIN:
            out["dangling"] = _collect_cname(name, resolver, cnames)
            break
        except dns.resolver.NoNameservers:
            out["error"] = "SERVFAIL (server failure) after retries"
            break
        except dns.exception.Timeout:
            out["error"] = out["error"] or "DNS timeout"
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            out["error"] = out["error"] or f"{type(exc).__name__}"
            continue
        for rrset in answer.response.answer:
            for rdata in rrset:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    target = rdata.target.to_text().rstrip(".")
                    if target not in cnames:
                        cnames.append(target)
                elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    if rrset.rdtype == dns.rdatatype.A:
                        out["a"].append(rdata.address)
                    else:
                        out["aaaa"].append(rdata.address)

    if not out["a"] and not out["aaaa"] and not cnames and not out["error"]:
        # No A/AAAA and not NXDOMAIN: the name may still be a bare CNAME (NoAnswer path)
        _collect_cname(name, resolver, cnames)

    out["a"] = sorted(set(out["a"]))
    out["aaaa"] = sorted(set(out["aaaa"]))
    out["cnames"] = cnames
    out["cname"] = cnames[0] if cnames else None
    out["alive"] = bool(out["a"] or out["aaaa"] or cnames)
    return out


def _collect_cname(name: str, resolver: dns.resolver.Resolver, cnames: list[str]) -> bool:
    """Append any CNAME target for ``name`` to ``cnames``. Returns True if one was found."""
    try:
        answer = resolver.resolve(name, "CNAME")
    except dns.exception.DNSException:
        return False
    found = False
    for rdata in answer:
        target = rdata.target.to_text().rstrip(".")
        if target not in cnames:
            cnames.append(target)
        found = True
    return found


def http_fingerprint(host: str, timeout: float = 5.0) -> tuple[int, int] | None:
    """Fetch a host over HTTPS then HTTP and return (status_code, content_length), or None."""
    for scheme in ("https", "http"):
        try:
            resp = http_request("GET", f"{scheme}://{host}/", timeout=timeout,
                                 allow_redirects=True, verify=False)
            return (resp.status_code, len(resp.content))
        except ReconError:
            continue
    return None


# ----------------------------------------------------------------------------- passive sources
def _clean_name(raw: str, domain: str) -> str | None:
    """Normalize a candidate hostname; return it only if it is under ``domain``."""
    name = raw.strip().lower().rstrip(".")
    while name.startswith("*."):
        name = name[2:]
    if not name or " " in name or "@" in name:
        return None
    if name == domain or name.endswith("." + domain):
        return name if DOMAIN_RE.match(name) else None
    return None


def passive_crtsh(domain: str, timeout: float = 45) -> set[str]:
    """Certificate Transparency search via crt.sh (``%`` is a SQL wildcard)."""
    import json as _json

    resp = http_request("GET", "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                        timeout=timeout)
    if resp.status_code in (429, 502, 503, 504):
        raise ReconError(f"crt.sh unavailable (HTTP {resp.status_code})")
    if resp.status_code != 200:
        raise ReconError(f"crt.sh returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except (_json.JSONDecodeError, ValueError):
        raise ReconError("crt.sh returned a non-JSON response") from None
    if not isinstance(data, list):
        raise ReconError("unexpected JSON structure from crt.sh")
    names: set[str] = set()
    for entry in data:
        for field in ("name_value", "common_name"):
            for raw in str(entry.get(field, "")).splitlines():
                if (n := _clean_name(raw, domain)):
                    names.add(n)
    return names


def passive_certspotter(domain: str, timeout: float = 20) -> set[str]:
    """CertSpotter CT-log aggregator (free tier is rate limited)."""
    resp = http_request(
        "GET", "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=timeout,
    )
    if resp.status_code == 429:
        raise ReconError("certspotter rate limit exceeded (HTTP 429)")
    if resp.status_code != 200:
        raise ReconError(f"certspotter returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except (ValueError,):
        raise ReconError("certspotter returned a non-JSON response") from None
    names: set[str] = set()
    for issuance in data if isinstance(data, list) else []:
        for raw in issuance.get("dns_names", []):
            if (n := _clean_name(raw, domain)):
                names.add(n)
    return names


def passive_hackertarget(domain: str, timeout: float = 20) -> set[str]:
    """HackerTarget passive-DNS dataset. Returns CSV lines 'host,ip'."""
    resp = http_request("GET", "https://api.hackertarget.com/hostsearch/",
                        params={"q": domain}, timeout=timeout)
    if resp.status_code != 200:
        raise ReconError(f"hackertarget returned HTTP {resp.status_code}")
    text = resp.text
    if "API count exceeded" in text or text.startswith("error"):
        raise ReconError(text.strip()[:120] or "hackertarget error")
    names: set[str] = set()
    for line in text.splitlines():
        if (n := _clean_name(line.split(",", 1)[0], domain)):
            names.add(n)
    return names


PASSIVE_SOURCES: dict[str, Callable[[str], set[str]]] = {
    "crtsh": passive_crtsh,
    "certspotter": passive_certspotter,
    "hackertarget": passive_hackertarget,
}


def resolve_target(host: str) -> list[tuple[int, str]]:
    """Resolve a hostname/IP for socket use -> [(family, address)]. Raises ReconError."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ReconError(f"Could not resolve {host}: {exc.strerror}") from None
    seen, out = set(), []
    # Prefer IPv4 when available
    for family, _, _, _, sockaddr in sorted(infos, key=lambda i: i[0] != socket.AF_INET):
        if sockaddr[0] not in seen:
            seen.add(sockaddr[0])
            out.append((family, sockaddr[0]))
    return out


# ----------------------------------------------------------------------------- concurrency
def run_concurrent(
    func: Callable[[Any], Any],
    items: Iterable[Any],
    threads: int,
    description: str,
    stop_event: threading.Event,
) -> list[tuple[Any, Any]]:
    """Run func over items in a thread pool with a progress bar.

    Returns [(item, result)] for results that are not None. On Ctrl+C the stop event
    is set, pending work is cancelled and KeyboardInterrupt propagates to the shell.
    """
    items = list(items)
    results: list[tuple[Any, Any]] = []
    errors: list[str] = []

    def wrapped(item: Any) -> Any:
        if stop_event.is_set():
            return None
        try:
            return func(item)
        except ReconError as exc:
            errors.append(str(exc))
            return None
        except Exception as exc:  # never let one worker kill the scan
            errors.append(f"{item}: {exc}")
            return None

    executor = ThreadPoolExecutor(max_workers=max(1, int(threads)))
    progress = Progress(
        SpinnerColumn(style="info"),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    try:
        with progress:
            task = progress.add_task(description, total=len(items))
            futures = {executor.submit(wrapped, item): item for item in items}
            for fut in as_completed(futures):
                progress.advance(task)
                result = fut.result()
                if result is not None:
                    results.append((futures[fut], result))
    except KeyboardInterrupt:
        stop_event.set()
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    if errors:
        from core.output import print_warn

        print_warn(f"{len(errors)} lookup(s) failed (e.g. {errors[0]})")
    return results
