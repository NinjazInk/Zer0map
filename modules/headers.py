"""headers: HTTP security header analyzer."""
from __future__ import annotations

import re

from rich.text import Text

from core.base_module import BaseModule
from core.output import (
    add_row,
    console,
    make_table,
    print_info,
    print_section,
    print_warn,
    status_text,
)
from core.utils import http_request, normalize_url

ONE_YEAR = 31536000
SAFE_REFERRER = {"no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin"}
WEAK_REFERRER = {"no-referrer-when-downgrade", "origin", "origin-when-cross-origin"}
GENERIC_SERVERS = {
    "nginx", "apache", "cloudflare", "microsoft-iis", "iis", "gws", "akamaighost", "envoy",
    "caddy", "litespeed", "openresty", "server", "webserver", "amazons3", "gse", "vercel",
    "netlify", "github.com", "awselb", "istio-envoy", "kestrel", "h2o", "lighttpd",
}


def _directives(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


class Module(BaseModule):
    name = "headers"
    description = "Analyze HTTP security headers and grade the configuration (A-F)"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("URL", None, True, "Full URL to analyze (e.g. https://example.com)")
        self.add_option("FOLLOW_REDIRECTS", True, False, "Follow redirects (true/false)", type="bool")
        self.add_option("TIMEOUT", 10.0, False, "Request timeout in seconds", type="float", minimum=1)
        self.add_option("VERIFY_SSL", True, False, "Verify TLS certificates (true/false)", type="bool")

    # Each check returns (status, explanation, recommendation-or-None)
    def _hsts(self, v: str | None, https: bool):
        rec = ("Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' so browsers "
               "always use HTTPS and can't be downgraded/stripped.")
        if v is None:
            if not https:
                return "FAIL", "Missing (site served over plain HTTP)", "Serve the site over HTTPS, then " + rec[0].lower() + rec[1:]
            return "FAIL", "Missing: connections can be downgraded to HTTP", rec
        m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
        age = int(m.group(1)) if m else None
        subs = "includesubdomains" in v.lower()
        if age is None:
            return "FAIL", "Present but max-age is missing/invalid", rec
        if age < ONE_YEAR:
            return "WARN", f"max-age={age} is below 1 year ({ONE_YEAR})", rec
        if not subs:
            return "WARN", f"max-age={age} but includeSubDomains is missing", rec
        note = " (preload)" if "preload" in v.lower() else ""
        return "PASS", f"max-age={age}; includeSubDomains{note}", None

    def _csp(self, v: str | None, report_only: str | None):
        rec = ("Define a Content-Security-Policy with a restrictive default-src/script-src "
               "(e.g. \"default-src 'self'; object-src 'none'; frame-ancestors 'self'\") and use "
               "nonces or hashes instead of 'unsafe-inline'/'unsafe-eval' to mitigate XSS.")
        if v is None:
            if report_only:
                return "WARN", "Only Content-Security-Policy-Report-Only is set (not enforced)", rec
            return "FAIL", "Missing: no XSS / injection mitigation policy", rec
        d = _directives(v)
        scripts = d.get("script-src", d.get("default-src"))
        issues = []
        if scripts is None:
            issues.append("no default-src/script-src (scripts unrestricted)")
        else:
            if any(s in ("*", "http:", "https:", "data:") for s in scripts):
                issues.append("overly permissive script source (*, http:, https: or data:)")
            has_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'" for s in scripts)
            if "'unsafe-inline'" in scripts and not has_nonce:
                issues.append("'unsafe-inline' scripts allowed")
            if "'unsafe-eval'" in scripts:
                issues.append("'unsafe-eval' allowed")
        if "*" in d.get("default-src", []):
            issues.append("default-src *")
        if issues:
            return "WARN", "; ".join(dict.fromkeys(issues)), rec
        return "PASS", f"Present ({len(d)} directives)", None

    def _xfo(self, v: str | None, csp: str | None):
        rec = ("Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or CSP 'frame-ancestors' to "
               "prevent clickjacking.")
        if v is None:
            if csp and "frame-ancestors" in _directives(csp):
                return "PASS", "Missing, but CSP frame-ancestors provides equivalent protection", None
            return "FAIL", "Missing: page can be framed (clickjacking risk)", rec
        val = v.strip().upper()
        if val in ("DENY", "SAMEORIGIN"):
            return "PASS", val, None
        if val.startswith("ALLOW-FROM"):
            return "WARN", "ALLOW-FROM is obsolete and ignored by modern browsers", rec
        return "WARN", f"Invalid value '{v}'", rec

    def _xcto(self, v: str | None):
        rec = "Set 'X-Content-Type-Options: nosniff' to stop browsers MIME-sniffing responses into executable types."
        if v is None:
            return "FAIL", "Missing (MIME-sniffing risk)", rec
        if v.strip().lower() == "nosniff":
            return "PASS", "nosniff", None
        return "WARN", f"Unexpected value '{v}'", rec

    def _referrer(self, v: str | None):
        rec = ("Set 'Referrer-Policy: strict-origin-when-cross-origin' (or no-referrer) so full URLs, "
               "which may contain tokens, aren't leaked to third parties.")
        if v is None:
            return "WARN", "Missing (relies on browser default)", rec
        # Multiple comma-separated values: the last one the browser understands wins
        policies = [p.strip().lower() for p in v.split(",") if p.strip()]
        policy = policies[-1] if policies else ""
        if policy == "unsafe-url":
            return "FAIL", "unsafe-url leaks full URLs (including over HTTP)", rec
        if policy in SAFE_REFERRER:
            return "PASS", policy, None
        if policy in WEAK_REFERRER:
            return "WARN", f"{policy} leaks more than necessary", rec
        return "WARN", f"Unrecognized policy '{v}'", rec

    def _permissions(self, v: str | None, feature_policy: str | None):
        rec = ("Set a Permissions-Policy (e.g. 'camera=(), microphone=(), geolocation=()') to restrict "
               "powerful browser features to what the site actually uses.")
        if v is None:
            if feature_policy:
                return "WARN", "Only the deprecated Feature-Policy header is set", rec
            return "WARN", "Missing: browser feature access unrestricted", rec
        return "PASS", f"Present ({len([p for p in v.split(',') if p.strip()])} features)", None

    def _xxss(self, v: str | None):
        rec = ("Remove X-XSS-Protection (or set it to '0'). The legacy XSS auditor is removed from "
               "modern browsers and '1; mode=block' could be abused for XS-leaks; rely on CSP.")
        if v is None:
            return "PASS", "Not set (correct; deprecated header)", None
        if v.strip().startswith("0"):
            return "PASS", "Explicitly disabled (0)", None
        return "WARN", f"Set to '{v}': deprecated, use CSP instead", rec

    def _server(self, v: str | None):
        rec = ("Remove version details from the Server header (e.g. nginx 'server_tokens off;', "
               "Apache 'ServerTokens Prod') to avoid aiding targeted exploits.")
        if v is None or not v.strip():
            return "PASS", "Not disclosed", None
        if re.search(r"\d", v) or "(" in v:
            return "WARN", f"Discloses version/platform: {v}", rec
        if v.strip().lower() in GENERIC_SERVERS or len(v.split()) == 1:
            return "PASS", f"Generic value: {v}", None
        return "WARN", f"Discloses software: {v}", rec

    def _powered_by(self, v: str | None):
        rec = ("Remove X-Powered-By (e.g. PHP 'expose_php = Off', Express 'app.disable(\"x-powered-by\")') "
               "to avoid disclosing the backend stack.")
        if v is None:
            return "PASS", "Not disclosed", None
        return "WARN", f"Discloses backend: {v}", rec

    def run(self) -> dict:
        url = normalize_url(self.get("URL"))
        timeout = self.get("TIMEOUT")
        with console.status(f"[info]Requesting {url}...[/info]"):
            resp = http_request(
                "GET", url, timeout=timeout, allow_redirects=self.get("FOLLOW_REDIRECTS"),
                verify=self.get("VERIFY_SSL"), stream=True,
            )
            resp.close()  # headers are all we need
        h = resp.headers
        final_url = resp.url
        https = final_url.lower().startswith("https://")

        chain = [f"{r.status_code} {r.url}" for r in resp.history]
        print_info(f"Final URL: {final_url}  (HTTP {resp.status_code})")
        if chain:
            print_info("Redirects: " + "  ->  ".join(chain))
        if resp.status_code >= 400:
            print_warn(f"Server answered HTTP {resp.status_code}; error pages often lack the headers "
                       "the real application sends, so results may not be representative")

        checks = [
            ("Strict-Transport-Security", h.get("Strict-Transport-Security"), self._hsts(h.get("Strict-Transport-Security"), https)),
            ("Content-Security-Policy", h.get("Content-Security-Policy"), self._csp(h.get("Content-Security-Policy"), h.get("Content-Security-Policy-Report-Only"))),
            ("X-Frame-Options", h.get("X-Frame-Options"), self._xfo(h.get("X-Frame-Options"), h.get("Content-Security-Policy"))),
            ("X-Content-Type-Options", h.get("X-Content-Type-Options"), self._xcto(h.get("X-Content-Type-Options"))),
            ("Referrer-Policy", h.get("Referrer-Policy"), self._referrer(h.get("Referrer-Policy"))),
            ("Permissions-Policy", h.get("Permissions-Policy"), self._permissions(h.get("Permissions-Policy"), h.get("Feature-Policy"))),
            ("X-XSS-Protection", h.get("X-XSS-Protection"), self._xxss(h.get("X-XSS-Protection"))),
            ("Server", h.get("Server"), self._server(h.get("Server"))),
            ("X-Powered-By", h.get("X-Powered-By"), self._powered_by(h.get("X-Powered-By"))),
        ]

        print_section("Security Headers")
        table = make_table(None, [("Header", {"no_wrap": True}), "Status", "Details", ("Value", {"overflow": "fold", "max_width": 50})])
        results = []
        for header, value, (status, detail, rec) in checks:
            shown = value if value is None or len(value) <= 120 else value[:117] + "..."
            add_row(table, header, status_text(status), detail,
                    Text(shown, style="muted") if shown else Text("-", style="muted"))
            results.append({"header": header, "status": status, "detail": detail,
                            "value": value, "recommendation": rec})
        console.print(table)

        passed = sum(r["status"] == "PASS" for r in results)
        warned = sum(r["status"] == "WARN" for r in results)
        grade = "A" if passed == 9 else "B" if passed >= 7 else "C" if passed >= 5 else "D" if passed >= 3 else "F"
        grade_style = {"A": "pass", "B": "pass", "C": "warning", "D": "warning", "F": "critical"}[grade]

        print_section("Score")
        score = Text()
        score.append(f"{passed}/9", style="heading")
        score.append(" headers properly configured   Grade: ")
        score.append(grade, style=f"{grade_style} bold")
        score.append(f"   ({warned} warning(s), {9 - passed - warned} failure(s))", style="muted")
        console.print(score)

        recs = [r for r in results if r["recommendation"]]
        if recs:
            print_section("Recommendations")
            for r in recs:
                line = Text()
                line.append(f"[{r['status']}] ", style=status_text(r["status"]).style)
                line.append(r["header"], style="heading")
                line.append(f": {r['recommendation']}")
                console.print(line)

        return {
            "url": url,
            "final_url": final_url,
            "status_code": resp.status_code,
            "redirects": chain,
            "score": f"{passed}/9",
            "grade": grade,
            "headers": results,
            "raw_headers": dict(h),
        }
