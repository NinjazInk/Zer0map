"""takeover: dangling-CNAME (subdomain takeover) detection.

A subdomain takeover happens when ``shop.example.com`` is a CNAME to a hosted service
(``example.myshopify.com``, an S3 bucket, ``example.github.io`` ...) but the resource on that
service was deleted. Anyone who then claims the same resource name serves content on
``shop.example.com`` - phishing, cookie theft for the parent domain, and so on.

Two signals are used: the CNAME target no longer resolves (NXDOMAIN), or the service answers
with its "nothing configured here" page. Findings are leads that must be confirmed manually:
providers change their error pages and some resources can't be re-registered. The community
list at github.com/EdOverflow/can-i-take-over-xyz tracks what's currently exploitable.
"""
from __future__ import annotations

import re
import time

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
    status_text,
)
from core.utils import (
    PASSIVE_SOURCES,
    ReconError,
    http_request,
    make_resolver,
    normalize_domain,
    resolve_full,
    run_concurrent,
)

# Each service: CNAME target patterns, and body text a fresh/unclaimed resource returns.
SERVICES: list[dict] = [
    {"service": "GitHub Pages", "cname": [r"\.github\.io$"],
     "fingerprint": ["There isn't a GitHub Pages site here"]},
    {"service": "Heroku", "cname": [r"\.herokuapp\.com$", r"\.herokudns\.com$", r"\.herokussl\.com$"],
     "fingerprint": ["No such app", "no-such-app.html"]},
    {"service": "AWS S3", "cname": [r"\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$", r"\.s3-website[.-]"],
     "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "AWS Elastic Beanstalk", "cname": [r"\.elasticbeanstalk\.com$"], "fingerprint": []},
    {"service": "Microsoft Azure",
     "cname": [r"\.azurewebsites\.net$", r"\.cloudapp\.net$", r"\.cloudapp\.azure\.com$",
               r"\.trafficmanager\.net$", r"\.blob\.core\.windows\.net$", r"\.azureedge\.net$"],
     "fingerprint": []},
    {"service": "Shopify", "cname": [r"\.myshopify\.com$"],
     "fingerprint": ["Sorry, this shop is currently unavailable"]},
    {"service": "Fastly", "cname": [r"\.fastly\.net$"], "fingerprint": ["Fastly error: unknown domain"]},
    {"service": "Netlify", "cname": [r"\.netlify\.(app|com)$"], "fingerprint": ["Not Found - Request ID"]},
    {"service": "Pantheon", "cname": [r"\.pantheonsite\.io$"], "fingerprint": ["404 error unknown site"]},
    {"service": "Zendesk", "cname": [r"\.zendesk\.com$"], "fingerprint": ["Help Center Closed"]},
    {"service": "Surge.sh", "cname": [r"\.surge\.sh$"], "fingerprint": ["project not found"]},
    {"service": "Bitbucket", "cname": [r"\.bitbucket\.io$"], "fingerprint": ["Repository not found"]},
    {"service": "Tumblr", "cname": [r"\.tumblr\.com$"],
     "fingerprint": ["Whatever you were looking for doesn't currently exist at this address"]},
    {"service": "Ghost", "cname": [r"\.ghost\.io$"],
     "fingerprint": ["The thing you were looking for is no longer here"]},
    {"service": "Read the Docs", "cname": [r"\.readthedocs\.io$"],
     "fingerprint": ["unknown to Read the Docs"]},
]


def match_service(cnames: list[str]) -> dict | None:
    for target in cnames:
        for svc in SERVICES:
            if any(re.search(p, target, re.I) for p in svc["cname"]):
                return svc
    return None


def _fetch_body(name: str, timeout: float) -> str | None:
    """Fetch the subdomain itself (HTTP first: a dangling host's TLS cert usually won't match)."""
    for scheme in ("http", "https"):
        try:
            resp = http_request("GET", f"{scheme}://{name}/", timeout=timeout,
                                 allow_redirects=True, verify=False)
            return resp.text[:200_000]
        except ReconError:
            continue
    return None


def check_takeover(res: dict, timeout: float = 10.0) -> dict | None:
    """Return a takeover finding for a resolution dict (needs name, cnames, dangling), or None."""
    if not res.get("cnames"):
        return None
    svc = match_service(res["cnames"])
    evidence: list[str] = []
    if res.get("dangling"):
        evidence.append(f"CNAME target {res['cnames'][-1]} does not resolve (NXDOMAIN)")
    if svc and svc["fingerprint"] and not res.get("dangling"):
        body = _fetch_body(res["name"], timeout)
        if body:
            low = body.lower()
            for fp in svc["fingerprint"]:
                if fp.lower() in low:
                    evidence.append(f"response contains {svc['service']} error text: {fp!r}")
                    break
    if not evidence:
        return None
    return {
        "subdomain": res["name"],
        "cnames": res["cnames"],
        "service": svc["service"] if svc else None,
        "confidence": "likely" if svc else "possible",
        "evidence": evidence,
    }


class Module(BaseModule):
    name = "takeover"
    description = "Detect dangling CNAMEs that may allow subdomain takeover (~15 providers)"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("DOMAIN", None, True, "Target domain (e.g. example.com)")
        self.add_option("THREADS", 10, False, "Concurrent checks", type="int", minimum=1)
        self.add_option("TIMEOUT", 10.0, False, "Per-request timeout (seconds)", type="float", minimum=1)
        self.add_option(
            "INPUT", "last", False,
            "'last' reuses the previous subdomains run if available, else enumerates passively",
            type="choice", choices=["last", "passive"],
        )

    # ------------------------------------------------------------------ candidate names
    def _names_from_last(self, domain: str) -> list[str] | None:
        inst = getattr(self.shell, "instances", {}).get("subdomains") if self.shell else None
        res = getattr(inst, "results", None) if inst else None
        if not res or res.get("domain") != domain:
            return None
        names = [r["subdomain"] for r in res.get("subdomains", [])]
        return names or None

    def _names_passive(self, domain: str) -> list[str]:
        names: set[str] = set()
        for src in PASSIVE_SOURCES:
            if self.cancelled:
                break
            try:
                with console.status(f"[info]Querying {src}...[/info]"):
                    names |= PASSIVE_SOURCES[src](domain)
            except ReconError as exc:
                print_warn(f"{src}: {exc}")
        return sorted(names)

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        domain = normalize_domain(self.get("DOMAIN"))
        threads = self.get("THREADS")
        resolver = make_resolver(timeout=2.0, lifetime=4.0)
        start = time.monotonic()

        names = None
        if self.get("INPUT") == "last":
            names = self._names_from_last(domain)
            if names:
                print_info(f"Reusing {len(names)} name(s) from the last subdomains run")
        if names is None:
            print_info("Enumerating subdomains passively...")
            names = self._names_passive(domain)
        names = [n for n in names if n == domain or n.endswith("." + domain)]
        print_info(f"Checking {len(names)} name(s) for dangling CNAMEs")

        if not names:
            print_warn("No candidate names to check")
            return {"domain": domain, "input": self.get("INPUT"), "checked": 0, "findings": []}

        resolved = run_concurrent(
            lambda n: resolve_full(n, resolver),
            names, threads, "Resolving CNAMEs", self.stop_event,
        )
        candidates = [(n, r) for n, r in resolved if r["cnames"]]
        for name, res in candidates:
            res["name"] = name

        findings = []
        if candidates:
            hits = run_concurrent(
                lambda item: check_takeover(item[1], self.get("TIMEOUT")),
                candidates, threads, "Checking takeover signatures", self.stop_event,
            )
            findings = [f for _, f in hits]

        order = {"likely": 0, "possible": 1}
        findings.sort(key=lambda f: (order[f["confidence"]], f["subdomain"]))

        print_section("Subdomain Takeover")
        if findings:
            table = make_table(None, ["Subdomain", "CNAME chain", "Service", "Confidence",
                                      ("Evidence", {"overflow": "fold", "max_width": 50})])
            for f in findings:
                conf = "FAIL" if f["confidence"] == "likely" else "WARN"
                add_row(table, f["subdomain"], " -> ".join(f["cnames"]),
                        f["service"] or "unknown", status_text(conf), "; ".join(f["evidence"]))
            console.print(table)
            print_warn("These are leads only. Verify manually before reporting "
                       "(providers change error pages; some resources can't be re-registered).")
        else:
            print_good("No dangling CNAMEs found among the checked names")

        print_section("Summary")
        print_info(f"Checked {len(names)} name(s), {len(candidates)} with CNAMEs")
        print_good(f"Possible takeovers: {len(findings)} "
                   f"({sum(f['confidence'] == 'likely' for f in findings)} likely)")
        print_info(f"Completed in {time.monotonic() - start:.1f}s")

        return {
            "domain": domain,
            "input": self.get("INPUT"),
            "checked": len(names),
            "with_cnames": len(candidates),
            "findings": findings,
        }
