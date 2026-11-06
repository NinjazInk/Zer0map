"""scan: full attack-surface sweep - enumerate subdomains, then audit every live host.

Forgotten hosts (old staging sites, abandoned marketing pages) are where weak configuration and
takeover-able CNAMEs tend to live, so auditing only the main site misses most of the interesting
findings. For every host that resolves this runs the dangling-CNAME (takeover) check and the
security-header audit, and prints one table sorted worst-first.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

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
from core.utils import PASSIVE_SOURCES, ReconError, normalize_domain, run_concurrent
from modules.headers import analyze as analyze_headers
from modules.subdomains import enumerate_subdomains
from modules.takeover import check_takeover


class Module(BaseModule):
    name = "scan"
    description = "Enumerate subdomains, then audit every live host (headers + takeover), worst first"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("DOMAIN", None, True, "Target domain (e.g. example.com)")
        self.add_option("BRUTE", False, False, "Also brute-force subdomains from the wordlist", type="bool")
        self.add_option(
            "SOURCES", "crtsh,certspotter,hackertarget", False,
            f"Comma-separated passive sources ({', '.join(PASSIVE_SOURCES)})",
        )
        self.add_option("WORDLIST", None, False, "Brute-force wordlist path (with BRUTE)", type="path")
        self.add_option("THREADS", 50, False, "Concurrent DNS lookups (enumeration)", type="int", minimum=1)
        self.add_option("HTTP_THREADS", 10, False, "Hosts audited in parallel", type="int", minimum=1)
        self.add_option("TIMEOUT", 10.0, False, "Per-request timeout (seconds)", type="float", minimum=1)
        self.add_option("LIMIT", 0, False, "Audit at most this many hosts (0 = no limit)", type="int", minimum=0)
        self.add_option("CORS", True, False, "Run the CORS probe on each host", type="bool")
        self.add_option("CHECK_TAKEOVER", True, False, "Check dangling CNAMEs for takeover", type="bool")
        self.add_option("PATHS", None, False, "Comma-separated paths to also check per host")
        self.add_option("NAMESERVERS", None, False, "Comma-separated resolver IPs (default: system)")

    # ------------------------------------------------------------------ option parsing
    def _sources(self) -> list[str]:
        raw = (self.get("SOURCES") or "").strip()
        if not raw:
            return list(PASSIVE_SOURCES)
        chosen = [s.strip().lower() for s in raw.split(",") if s.strip()]
        bad = [s for s in chosen if s not in PASSIVE_SOURCES]
        if bad:
            raise ReconError(f"Unknown source(s): {', '.join(bad)}. Choices: {', '.join(PASSIVE_SOURCES)}")
        return chosen

    def _nameservers(self) -> list[str] | None:
        raw = (self.get("NAMESERVERS") or "").strip()
        return [s.strip() for s in raw.split(",") if s.strip()] or None

    def _paths(self) -> list[str]:
        raw = (self.get("PATHS") or "").strip()
        out = []
        for p in raw.split(","):
            p = p.strip()
            if p:
                out.append(p if p.startswith("/") else "/" + p)
        return out

    # ------------------------------------------------------------------ per-host audit
    def _audit_host(self, res: dict) -> dict:
        name = res["name"]
        timeout = self.get("TIMEOUT")
        host = {"name": name, "report": None, "takeover": None, "error": None, "path_reports": []}
        try:
            if self.get("CHECK_TAKEOVER") and res.get("cnames"):
                host["takeover"] = check_takeover(res, timeout)
        except Exception as exc:  # never let one host kill the sweep
            host["error"] = f"takeover check failed: {exc}"

        if not (res["a"] or res["aaaa"]):
            if res.get("error"):
                detail = f"DNS error: {res['error']}"
            elif res.get("cnames"):
                detail = "no address (CNAME target does not resolve)"
            else:
                detail = "no address"
            host["error"] = host["error"] or detail
            return host

        base = None
        last_exc = None
        for scheme in ("https", "http"):
            try:
                host["report"] = analyze_headers(
                    f"{scheme}://{name}", timeout=timeout, follow_redirects=True,
                    cors=self.get("CORS"), check_redirect=False, verify=True,
                )
                base = f"{scheme}://{name}"
                break
            except ReconError as exc:
                last_exc = exc
        if host["report"] is None:
            host["error"] = f"no HTTP(S) response ({last_exc})"
            return host

        for path in self._paths():
            if self.cancelled:
                break
            try:
                pr = analyze_headers(base.rstrip("/") + path, timeout=timeout,
                                     follow_redirects=True, cors=False, check_redirect=False, verify=True)
                host["path_reports"].append(pr)
            except ReconError:
                continue
        return host

    @staticmethod
    def _counts(report: dict | None) -> dict:
        out = {"high": 0, "medium": 0, "low": 0}
        if report:
            for f in report["findings"]:
                if f["severity"] in out:
                    out[f["severity"]] += 1
        return out

    @staticmethod
    def _top_issue(report: dict | None) -> str:
        if not report:
            return ""
        for f in report["findings"]:
            if f["severity"] in ("high", "medium"):
                return f["title"]
        return ""

    def _sort_key(self, host: dict):
        report = host["report"]
        blocked = bool(report and report["blocked_by"])
        score = report["score"] if report and report["score"] is not None else 0
        return (host["takeover"] is None, blocked, report is None, score, host["name"])

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        domain = normalize_domain(self.get("DOMAIN"))
        method = "all" if self.get("BRUTE") else "passive"
        start = time.monotonic()

        print_section("Enumeration")
        sub, resolutions = enumerate_subdomains(
            domain, method=method, sources=self._sources(), wordlist=self.get("WORDLIST"),
            threads=self.get("THREADS"), nameservers=self._nameservers(), stop_event=self.stop_event,
        )

        live = [resolutions[n] for n in sorted(resolutions)]
        limit = self.get("LIMIT")
        if limit and len(live) > limit:
            print_info(f"Limiting audit to {limit} of {len(live)} live host(s)")
            live = live[:limit]

        print_section("Host Audit")
        if not live:
            print_warn("No live hosts to audit")
            return {"domain": domain, "subdomains": sub, "hosts": [], "takeovers": []}

        print_info(f"Auditing {len(live)} live host(s) with {self.get('HTTP_THREADS')} threads")
        audited = run_concurrent(
            self._audit_host, live, self.get("HTTP_THREADS"), "Auditing hosts", self.stop_event,
        )
        hosts = [h for _, h in audited]
        hosts.sort(key=self._sort_key)

        # ---------------- results table
        width = max((len(h["name"]) for h in hosts), default=4)
        table = make_table(None, [("Host", {"no_wrap": True}), "HTTP", "Grade",
                                   ("High", {"justify": "right"}), ("Med", {"justify": "right"}),
                                   ("Low", {"justify": "right"}),
                                   ("Top issue", {"overflow": "fold", "max_width": 40})])
        rows_out = []
        for h in hosts:
            report = h["report"]
            counts = self._counts(report)
            if report and report["blocked_by"]:
                add_row(table, h["name"], str(report["status_code"]),
                        Text("BLOCKED", style="critical"), "", "", "",
                        Text(f"bot protection ({report['blocked_by']})", style="warning"))
                grade, score, status = None, None, report["status_code"]
                top = f"bot protection ({report['blocked_by']})"
            elif report:
                grade = report["grade"]
                gstyle = {"A": "pass", "B": "pass", "C": "warning", "D": "warning", "F": "critical"}[grade]
                top = self._top_issue(report)
                status, score = report["status_code"], report["score"]
                add_row(table, h["name"], str(status), Text(grade, style=gstyle),
                        Text(str(counts["high"]), style="critical" if counts["high"] else ""),
                        str(counts["medium"]), str(counts["low"]), top or "-")
            else:
                grade, score, status = None, None, None
                top = h["error"] or ""
                add_row(table, h["name"], Text("-", style="muted"), Text("-", style="muted"),
                        "", "", "", Text(top, style="muted"))
            rows_out.append({
                "name": h["name"], "status": status, "grade": grade, "score": score,
                "counts": counts, "top_issue": top, "error": h["error"],
                "blocked_by": report["blocked_by"] if report else None,
                "takeover": h["takeover"],
                "findings": report["findings"] if report else [],
                "paths": [{"url": pr["final_url"], "grade": pr["grade"], "score": pr["score"],
                           "blocked_by": pr["blocked_by"]} for pr in h["path_reports"]],
            })
        console.print(table)

        # ---------------- takeovers
        takeovers = [h["takeover"] for h in hosts if h["takeover"]]
        if takeovers:
            print_section("Possible Subdomain Takeovers")
            print_warn(f"{len(takeovers)} candidate(s) - verify manually before reporting")
            ttable = make_table(None, ["Subdomain", "CNAME chain", "Service", "Confidence",
                                       ("Evidence", {"overflow": "fold", "max_width": 44})])
            for t in takeovers:
                conf = "FAIL" if t["confidence"] == "likely" else "WARN"
                add_row(ttable, t["subdomain"], " -> ".join(t["cnames"]), t["service"] or "unknown",
                        status_text(conf), "; ".join(t["evidence"]))
            console.print(ttable)

        # ---------------- per-path findings
        path_hosts = [h for h in hosts if h["path_reports"]]
        if path_hosts:
            print_section("Per-path Findings")
            for h in path_hosts:
                for pr in h["path_reports"]:
                    if pr["blocked_by"]:
                        console.print(Text(f"  {pr['final_url']}: BLOCKED ({pr['blocked_by']})", style="warning"))
                    else:
                        gstyle = {"A": "pass", "B": "pass", "C": "warning",
                                  "D": "warning", "F": "critical"}[pr["grade"]]
                        line = Text(f"  {pr['final_url']}: ")
                        line.append(pr["grade"], style=gstyle)
                        line.append(f"  ({pr['score']}/100)", style="muted")
                        console.print(line)

        # ---------------- summary
        graded = [h for h in hosts if h["report"] and not h["report"]["blocked_by"]]
        answered = [h for h in hosts if h["report"]]
        weak = sum(1 for h in graded if h["report"]["grade"] in ("D", "F"))
        print_section("Summary")
        print_good(f"{len(hosts)} live host(s), {len(answered)} answered HTTP(S)")
        print_info(f"{weak} graded D or F  |  {len(takeovers)} possible takeover(s)")
        print_info(f"Completed in {time.monotonic() - start:.1f}s")

        return {
            "domain": domain,
            "subdomain_summary": sub["summary"],
            "hosts": rows_out,
            "takeovers": takeovers,
            "summary": {
                "live_hosts": len(hosts),
                "answered_http": len(answered),
                "graded_d_or_f": weak,
                "takeovers": len(takeovers),
            },
        }
