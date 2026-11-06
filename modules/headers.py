"""headers: HTTP security header analyzer.

Produces two views of a URL: a quick PASS/WARN/FAIL table over the nine core headers, and a
severity-ranked findings list (with a "why it matters" and a fix for each) that also covers
cookies, CORS, the HTTP->HTTPS redirect, TLS errors and cross-origin policies. Scores out of
100 and grades A-F. Bot-protection challenge pages are detected and skipped, since grading a
firewall's block page would be meaningless.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from rich.text import Text

from core.base_module import BaseModule
from core.output import add_row, console, make_table, print_info, print_section, print_warn
from core.utils import ReconError, http_request, normalize_url

SEVERITY_WEIGHT = {"high": 25, "medium": 12, "low": 5, "info": 0}
SEVERITY_ORDER = ["high", "medium", "low", "info"]
SEVERITY_STYLE = {"high": "critical", "medium": "warning", "low": "info", "info": "muted"}

CORE_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    "X-XSS-Protection", "Server", "X-Powered-By",
]

CHALLENGE_SIGNATURES = [
    (r"cf-mitigated.*challenge", "Cloudflare"),
    (r"<title>\s*just a moment", "Cloudflare"),
    (r"cdn-cgi/challenge-platform", "Cloudflare"),
    (r"_cf_chl_opt", "Cloudflare"),
    (r"<title>\s*attention required.*cloudflare", "Cloudflare"),
    (r"managed challenge", "Cloudflare"),
    (r"akamai bot manager", "Akamai"),
    (r"access denied.*reference\s*#", "Akamai"),
    (r"<title>\s*ddos-guard", "DDoS-Guard"),
    (r"sucuri website firewall", "Sucuri"),
    (r"you have been blocked", "WAF"),
    (r"<title>\s*access denied", "WAF"),
]


def finding(header, severity, title, why, fix="", value=None) -> dict:
    return {"header": header, "severity": severity, "title": title, "why": why,
            "fix": fix, "value": value}


def get_set_cookies(resp) -> list[str]:
    """Every raw Set-Cookie header (requests folds duplicates into one otherwise)."""
    raw = getattr(resp, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None and hasattr(headers, "getlist"):
        values = headers.getlist("Set-Cookie")
        if values:
            return list(values)
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() not in directives:  # duplicates after the first are ignored
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


KNOWN_CSP_DIRECTIVES = {
    "default-src", "script-src", "style-src", "img-src", "connect-src", "font-src", "object-src",
    "media-src", "frame-src", "child-src", "worker-src", "frame-ancestors", "form-action",
    "base-uri", "manifest-src", "navigate-to", "report-uri", "report-to", "sandbox",
    "require-trusted-types-for", "trusted-types", "upgrade-insecure-requests",
    "block-all-mixed-content", "plugin-types", "prefetch-src", "script-src-elem", "style-src-elem",
}


def split_multi_csp(raw: str) -> list[str]:
    """Split comma-joined CSP headers (requests joins multiple with ', ') back into policies."""
    parts = re.split(r",\s*", raw)
    policies = [parts[0]]
    for part in parts[1:]:
        first = part.strip().split()[0].lower() if part.strip() else ""
        if first in KNOWN_CSP_DIRECTIVES:
            policies.append(part)
        else:
            policies[-1] += ", " + part
    return policies


def extract_meta_csp(body: str) -> str | None:
    for q in ('"', "'"):
        for pattern in (
            rf'<meta\s[^>]*http-equiv\s*=\s*{q}Content-Security-Policy{q}\s[^>]*content\s*=\s*{q}([^{q}]+){q}',
            rf'<meta\s[^>]*content\s*=\s*{q}([^{q}]+){q}\s[^>]*http-equiv\s*=\s*{q}Content-Security-Policy{q}',
        ):
            m = re.search(pattern, body, re.I | re.S)
            if m:
                return m.group(1)
    return None


# --------------------------------------------------------------------------- individual checks

def check_hsts(h, is_https) -> list[dict]:
    v = h.get("Strict-Transport-Security")
    if not is_https:
        return [finding("Strict-Transport-Security", "high", "Site served over plain HTTP",
                        "Without TLS, anyone on the network path can read and modify traffic. HSTS is "
                        "ignored over HTTP, so it can't help until HTTPS is in place.",
                        "Serve the site over HTTPS, redirect HTTP to HTTPS, then add HSTS.")]
    if not v:
        return [finding("Strict-Transport-Security", "medium", "HSTS missing",
                        "A user typing the bare domain makes a first request over HTTP that an attacker "
                        "can intercept and downgrade (SSL stripping).",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    out = []
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age == 0:
        out.append(finding("Strict-Transport-Security", "medium", "HSTS max-age is 0 or missing",
                           "max-age=0 tells browsers to forget the HSTS policy, disabling it.",
                           "Set max-age to at least 31536000 (1 year).", v))
    elif max_age < 31536000:
        out.append(finding("Strict-Transport-Security", "low", f"HSTS max-age is short ({max_age}s)",
                           "Short lifetimes let the policy expire between visits, reopening the "
                           "downgrade window.", "Use max-age of at least 31536000 (1 year).", v))
    if "includesubdomains" not in v.lower():
        out.append(finding("Strict-Transport-Security", "low", "HSTS lacks includeSubDomains",
                           "Subdomains aren't covered, so an HTTP subdomain can set cookies for the "
                           "parent domain.", "Add includeSubDomains once all subdomains support HTTPS.", v))
    if "preload" not in v.lower():
        out.append(finding("Strict-Transport-Security", "info", "HSTS not preload-ready",
                           "Preloading ships the policy inside browsers so even the first visit is "
                           "protected.", "Consider 'preload' and submitting to hstspreload.org.", v))
    return out


def check_csp(h, meta_csp=None) -> list[dict]:
    v = h.get("Content-Security-Policy")
    ro = h.get("Content-Security-Policy-Report-Only")
    from_meta = False
    if not v and meta_csp:
        v, from_meta = meta_csp, True
    if not v:
        if ro:
            return [finding("Content-Security-Policy", "medium", "CSP is report-only",
                            "Report-Only logs violations but blocks nothing, so it gives no XSS "
                            "protection yet.", "Promote it to Content-Security-Policy once reports are "
                            "clean.", ro)]
        return [finding("Content-Security-Policy", "medium", "CSP missing",
                        "CSP is the main browser-side defence against XSS: without it any injected "
                        "<script> runs.",
                        "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; "
                        "frame-ancestors 'self'")]
    out = []
    if from_meta:
        out.append(finding("Content-Security-Policy", "info", "CSP set via <meta> tag",
                           "A <meta> CSP can't use frame-ancestors/report-uri/sandbox and applies only "
                           "after the parser reaches it.", "Send CSP as an HTTP response header.", v[:200]))
    policies = split_multi_csp(v)
    if len(policies) > 1:
        out.append(finding("Content-Security-Policy", "info",
                           f"Multiple CSP policies detected ({len(policies)})",
                           "Browsers apply all policies (intersection); only the first is analyzed here.",
                           "Consolidate into a single Content-Security-Policy header.", v[:200]))
    d = parse_csp(policies[0])
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        out.append(finding("Content-Security-Policy", "high", "CSP has no script-src or default-src",
                           "With neither directive scripts may load from anywhere; the policy doesn't "
                           "mitigate XSS.", "Add default-src 'self' (or a strict script-src).", v))
    else:
        has_nonce_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
        strict_dynamic = "'strict-dynamic'" in script
        if "'unsafe-inline'" in script and not (has_nonce_hash or strict_dynamic):
            out.append(finding("Content-Security-Policy", "high", "script-src allows 'unsafe-inline'",
                               "Inline scripts and event handlers are allowed, which is exactly what most "
                               "XSS payloads use, so this largely defeats CSP.",
                               "Use nonces or hashes and drop 'unsafe-inline'.", v))
        if "'unsafe-eval'" in script:
            out.append(finding("Content-Security-Policy", "medium", "script-src allows 'unsafe-eval'",
                               "eval()/new Function() let attacker-controlled strings become code.",
                               "Refactor away from eval and remove 'unsafe-eval'.", v))
        wild = [t for t in script if t in ("*", "http:", "https:", "data:") or t.startswith("*.")]
        if wild and not strict_dynamic:
            out.append(finding("Content-Security-Policy", "high",
                               f"script-src allows broad sources ({' '.join(wild)})",
                               "Any host (or data: URIs) can serve scripts, so an attacker just hosts the "
                               "payload elsewhere.", "List specific origins, or use nonces + "
                               "'strict-dynamic'.", v))
    if "object-src" not in d and "default-src" not in d:
        out.append(finding("Content-Security-Policy", "low", "CSP missing object-src",
                           "Plugins (<object>/<embed>) can be abused to run script.",
                           "Add object-src 'none'.", v))
    if "base-uri" not in d:
        out.append(finding("Content-Security-Policy", "low", "CSP missing base-uri",
                           "An injected <base href> can redirect every relative script URL to an "
                           "attacker's server; base-uri does not fall back to default-src.",
                           "Add base-uri 'self' (or 'none').", v))
    if "frame-ancestors" not in d:
        out.append(finding("Content-Security-Policy", "info", "CSP missing frame-ancestors",
                           "frame-ancestors is the modern clickjacking control and does not fall back to "
                           "default-src.", "Add frame-ancestors 'self' (or 'none').", v))
    return out


def check_xfo(h, meta_csp=None) -> list[dict]:
    raw_csp = h.get("Content-Security-Policy") or meta_csp or ""
    csp = parse_csp(split_multi_csp(raw_csp)[0]) if raw_csp else {}
    v = h.get("X-Frame-Options")
    if not v:
        if "frame-ancestors" in csp:
            return []
        return [finding("X-Frame-Options", "medium", "Clickjacking protection missing",
                        "Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can load "
                        "this page in an invisible iframe and trick users into clicking it.",
                        "X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.")]
    val = v.strip().upper()
    if val.startswith("ALLOW-FROM"):
        return [finding("X-Frame-Options", "medium", "X-Frame-Options uses ALLOW-FROM",
                        "ALLOW-FROM is unsupported by modern browsers, which then ignore the header.",
                        "Use CSP frame-ancestors <origin> instead.", v)]
    if val not in ("DENY", "SAMEORIGIN"):
        return [finding("X-Frame-Options", "medium", "X-Frame-Options has an invalid value",
                        "Browsers ignore unrecognised values, leaving the page frameable.",
                        "Use DENY or SAMEORIGIN.", v)]
    return []


def check_xcto(h) -> list[dict]:
    v = h.get("X-Content-Type-Options")
    if not v or v.strip().lower() != "nosniff":
        return [finding("X-Content-Type-Options", "low",
                        "X-Content-Type-Options not 'nosniff'" if v else "X-Content-Type-Options missing",
                        "Browsers may MIME-sniff a response and execute an uploaded text/image file as "
                        "script or HTML.", "X-Content-Type-Options: nosniff", v)]
    return []


def check_referrer(h) -> list[dict]:
    v = h.get("Referrer-Policy")
    if not v:
        return [finding("Referrer-Policy", "low", "Referrer-Policy missing",
                        "Browsers default to strict-origin-when-cross-origin today, but setting it "
                        "explicitly avoids leaking full URLs (which may carry tokens) on older clients.",
                        "Referrer-Policy: strict-origin-when-cross-origin")]
    policy = [p.strip().lower() for p in v.split(",") if p.strip()][-1]
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return [finding("Referrer-Policy", "medium", f"Referrer-Policy '{policy}' leaks full URLs",
                        "Full URLs, including paths and query strings, are sent to third-party sites.",
                        "Use strict-origin-when-cross-origin or no-referrer.", v)]
    return []


def check_permissions_policy(h) -> list[dict]:
    if not h.get("Permissions-Policy") and not h.get("Feature-Policy"):
        return [finding("Permissions-Policy", "info", "Permissions-Policy missing",
                        "Lets you switch off powerful features (camera, geolocation, payment) for the "
                        "page and its iframes, limiting what injected or third-party code can use.",
                        "Permissions-Policy: camera=(), microphone=(), geolocation=()")]
    return []


def check_xss_protection(h) -> list[dict]:
    v = h.get("X-XSS-Protection")
    if v and v.strip().startswith("1"):
        return [finding("X-XSS-Protection", "info", "Legacy X-XSS-Protection enabled",
                        "The old XSS auditor was removed from browsers and itself introduced "
                        "information-leak bugs. Modern guidance is to disable it and rely on CSP.",
                        "X-XSS-Protection: 0 (or remove it).", v)]
    return []


def check_disclosure(h) -> list[dict]:
    out = []
    server = h.get("Server")
    if server and re.search(r"\d", server):
        out.append(finding("Server", "low", "Server header discloses version",
                           "Exact versions let attackers match the host against known CVEs without "
                           "probing.", "Strip the version (e.g. nginx: server_tokens off).", server))
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        if (v := h.get(name)):
            out.append(finding(name, "low", f"{name} discloses technology",
                               "Advertises the framework/runtime (and often its version), making "
                               "targeted attacks easier.", f"Remove the {name} header.", v))
    return out


def _cookie_attrs(raw: str) -> dict[str, str]:
    return {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
            for a in raw.split(";")[1:]}


def check_cookies(set_cookies, is_https) -> list[dict]:
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = _cookie_attrs(raw)
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not attrs.get("samesite"):
            missing.append("SameSite")
        if missing:
            sev = "medium" if ("Secure" in missing or "HttpOnly" in missing) else "low"
            out.append(finding("Set-Cookie", sev, f"Cookie '{name}' missing {', '.join(missing)}",
                               "Secure keeps it off plain HTTP; HttpOnly hides it from JavaScript (so XSS "
                               "can't steal it); SameSite limits cross-site sending (CSRF).",
                               "Set Secure; HttpOnly; SameSite=Lax on session cookies.", raw[:200]))
        if attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
            out.append(finding("Set-Cookie", "low", f"Cookie '{name}' has SameSite=None without Secure",
                               "Browsers reject SameSite=None cookies that aren't Secure.",
                               "Add Secure.", raw[:200]))
    return out


def check_host_cookie_prefix(set_cookies, is_https) -> list[dict]:
    if not is_https:
        return []
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        if not name.startswith("__Host-"):
            continue
        attrs = _cookie_attrs(raw)
        problems = []
        if "secure" not in attrs:
            problems.append("Secure")
        if attrs.get("path", "").strip() != "/":
            problems.append("Path=/")
        if "domain" in attrs:
            problems.append("no Domain")
        if problems:
            out.append(finding("Set-Cookie", "medium",
                               f"__Host- cookie '{name}' violates prefix rules ({', '.join(problems)})",
                               "__Host- cookies must have Secure, Path=/ and no Domain; browsers silently "
                               "drop ones that break these rules.",
                               f"Set: {name}=...; Secure; Path=/  (no Domain attribute).", raw[:200]))
    return out


def _missing_cross_origin(h, header, name, why) -> list[dict]:
    if not h.get(header):
        fixes = {"Cross-Origin-Opener-Policy": "Cross-Origin-Opener-Policy: same-origin",
                 "Cross-Origin-Embedder-Policy": "Cross-Origin-Embedder-Policy: require-corp",
                 "Cross-Origin-Resource-Policy": "Cross-Origin-Resource-Policy: same-origin"}
        return [finding(header, "info", f"{name} missing", why, fixes[header])]
    return []


def check_cross_origin(h) -> list[dict]:
    out = []
    out += _missing_cross_origin(h, "Cross-Origin-Opener-Policy", "COOP",
                                 "Without COOP, windows opened from this site share a browsing context "
                                 "group, which can leak information via side channels (e.g. Spectre).")
    out += _missing_cross_origin(h, "Cross-Origin-Embedder-Policy", "COEP",
                                 "Without COEP, cross-origin resources load without explicit opt-in and "
                                 "the page can't use SharedArrayBuffer or high-resolution timers.")
    out += _missing_cross_origin(h, "Cross-Origin-Resource-Policy", "CORP",
                                 "Without CORP, other sites can embed this resource in img/script/iframe "
                                 "tags, leaking data to cross-origin pages.")
    return out


def check_cors(url, timeout, verify) -> list[dict]:
    probe = "https://zer0map-cors-probe.example"
    try:
        r = http_request("GET", url, headers={"Origin": probe}, timeout=timeout,
                         allow_redirects=True, verify=verify)
    except ReconError:
        return []
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao == probe:
        return [finding("Access-Control-Allow-Origin", "high" if acac else "medium",
                        "CORS reflects arbitrary Origin" + (" with credentials" if acac else ""),
                        "The server echoes any Origin, so any website can read responses from this "
                        "endpoint" + (" using the victim's cookies." if acac else "."),
                        "Validate Origin against an explicit allowlist.", acao)]
    if acao == "null":
        return [finding("Access-Control-Allow-Origin", "medium", "CORS allows the 'null' origin",
                        "Sandboxed iframes and file:// pages send Origin: null, so attackers obtain it "
                        "trivially.", "Never allow 'null'.", acao)]
    if acao == "*":
        return [finding("Access-Control-Allow-Origin", "info", "CORS allows any origin (*)",
                        "Fine for truly public data; make sure nothing sensitive is exposed without "
                        "auth.", "", acao)]
    return []


def check_https_redirect(url, timeout, verify, max_hops=5) -> list[dict]:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return []
    current = f"http://{parsed.netloc}/"
    hops: list[str] = []
    for _ in range(max_hops):
        try:
            r = http_request("GET", current, timeout=timeout, allow_redirects=False, verify=verify)
        except ReconError:
            return []  # port 80 closed/filtered: nothing served in plaintext
        location = r.headers.get("Location")
        if not (300 <= r.status_code < 400 and location):
            break
        nxt = urljoin(current, location)
        hops.append(nxt)
        if urlparse(nxt).scheme == "https":
            break
        current = nxt
    chain = " -> ".join([f"http://{parsed.netloc}/"] + hops)
    if not hops:
        return [finding("Redirect", "medium", "HTTP does not redirect to HTTPS",
                        "The site answers over plain HTTP without redirecting, so users who type the bare "
                        "domain or follow an old http:// link stay unencrypted.",
                        "Return a 301 from http:// to the same URL on https://.", chain)]
    final = urlparse(hops[-1])
    if final.scheme != "https":
        return [finding("Redirect", "medium", "HTTP redirect never reaches HTTPS",
                        f"After {len(hops)} redirect(s) the browser is still on plain HTTP.",
                        "Redirect http:// directly to https://.", chain)]
    if len(hops) > 1:
        return [finding("Redirect", "low", "HTTP reaches HTTPS only via extra plain-HTTP hops",
                        "Every plain-HTTP hop is a chance for a network attacker to rewrite the redirect "
                        "and keep the user on HTTP.", "Make the first response a redirect to https://.",
                        chain)]
    if final.hostname != host:
        return [finding("Redirect", "low", "First redirect goes to HTTPS on a different host",
                        f"http://{host} jumps straight to {final.hostname}, so the browser never sees an "
                        f"HTTPS response from {host} and can't learn its HSTS policy.",
                        f"Redirect to https://{host}/ first.", chain)]
    return []


def detect_challenge(resp) -> str | None:
    try:
        body = resp.text[:50_000].lower()
    except Exception:
        body = ""
    if resp.status_code in (403, 503):
        for pattern, provider in CHALLENGE_SIGNATURES:
            if re.search(pattern, body, re.I | re.S):
                return provider
    cf = resp.headers.get("cf-mitigated", "")
    if "challenge" in cf.lower():
        return "Cloudflare"
    if resp.status_code == 503 and "ddos-guard" in resp.headers.get("Server", "").lower():
        return "DDoS-Guard"
    return None


def grade_for(score: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= threshold:
            return letter
    return "F"


def run_checks(resp, meta_csp) -> list[dict]:
    h = resp.headers
    is_https = urlparse(resp.url).scheme == "https"
    cookies = get_set_cookies(resp)
    findings: list[dict] = []
    findings += check_hsts(h, is_https)
    findings += check_csp(h, meta_csp)
    findings += check_xfo(h, meta_csp)
    findings += check_xcto(h)
    findings += check_referrer(h)
    findings += check_permissions_policy(h)
    findings += check_xss_protection(h)
    findings += check_disclosure(h)
    findings += check_cookies(cookies, is_https)
    findings += check_host_cookie_prefix(cookies, is_https)
    findings += check_cross_origin(h)
    return findings


def analyze(url: str, *, timeout: float = 10.0, follow_redirects: bool = True,
            cors: bool = True, check_redirect: bool = True, verify: bool = True) -> dict:
    """Fetch a URL and return a report dict: url, final_url, status_code, blocked_by,
    findings (severity-sorted), score, grade, raw_headers. Raises ReconError if the URL can't
    be fetched (other than a recoverable TLS error, which becomes a high finding)."""
    tls_finding = None
    try:
        resp = http_request("GET", url, timeout=timeout, allow_redirects=follow_redirects, verify=verify)
    except ReconError as exc:
        if verify and "SSL/TLS error" in str(exc):
            tls_finding = finding("TLS", "high", "TLS certificate error",
                                  f"The TLS handshake failed: {str(exc)[:160]}. Often an expired, "
                                  "self-signed or misconfigured certificate.",
                                  "Install a valid certificate from a trusted CA.")
            resp = http_request("GET", url, timeout=timeout, allow_redirects=follow_redirects, verify=False)
            verify = False
        else:
            raise

    challenge = detect_challenge(resp)
    if challenge:
        return {"url": url, "final_url": resp.url, "status_code": resp.status_code,
                "blocked_by": challenge, "findings": [], "score": None, "grade": None,
                "raw_headers": dict(resp.headers)}

    meta_csp = extract_meta_csp(resp.text[:200_000]) if resp.text else None
    findings = run_checks(resp, meta_csp)
    if tls_finding:
        findings.insert(0, tls_finding)
    if cors:
        findings += check_cors(resp.url, timeout, verify)
    if check_redirect and urlparse(resp.url).scheme == "https":
        findings += check_https_redirect(resp.url, timeout, verify)
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))

    score = max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
    return {"url": url, "final_url": resp.url, "status_code": resp.status_code,
            "blocked_by": None, "findings": findings, "score": score, "grade": grade_for(score),
            "meta_csp": meta_csp, "raw_headers": dict(resp.headers)}


class Module(BaseModule):
    name = "headers"
    description = "Analyze HTTP security headers: PASS/WARN/FAIL table, severity findings, A-F score"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("URL", None, True, "Full URL to analyze (e.g. https://example.com)")
        self.add_option("PATHS", None, False, "Comma-separated paths to also check (e.g. /,/api,/admin)")
        self.add_option("FOLLOW_REDIRECTS", True, False, "Follow redirects (true/false)", type="bool")
        self.add_option("CORS", True, False, "Run the CORS origin-reflection probe", type="bool")
        self.add_option("CHECK_REDIRECT", True, False, "Check HTTP->HTTPS redirect", type="bool")
        self.add_option("TIMEOUT", 10.0, False, "Request timeout in seconds", type="float", minimum=1)
        self.add_option("VERIFY_SSL", True, False, "Verify TLS certificates (true/false)", type="bool")
        self.add_option("VERBOSE", False, False, "Show info findings and raw values", type="bool")

    # ------------------------------------------------------------------ analysis
    def _analyze(self, url: str) -> dict:
        return analyze(url, timeout=self.get("TIMEOUT"),
                       follow_redirects=self.get("FOLLOW_REDIRECTS"),
                       cors=self.get("CORS"), check_redirect=self.get("CHECK_REDIRECT"),
                       verify=self.get("VERIFY_SSL"))

    # ------------------------------------------------------------------ rendering
    def _render(self, report: dict) -> None:
        verbose = self.get("VERBOSE")
        print_info(f"Final URL: {report['final_url']}  (HTTP {report['status_code']})")
        if report["blocked_by"]:
            print_warn(f"BLOCKED by {report['blocked_by']} bot protection. The response is a challenge "
                       "page, not the real site, so header grades would be meaningless. Try from an "
                       "allowed IP or skip this host.")
            return

        findings = report["findings"]
        by_header: dict[str, list[dict]] = {}
        for f in findings:
            by_header.setdefault(f["header"], []).append(f)

        # Per-header PASS/WARN/FAIL overview of the nine core headers
        print_section("Security Headers")
        overview = make_table(None, [("Header", {"no_wrap": True}), "Status", "Details",
                                     ("Value", {"overflow": "fold", "max_width": 44})])
        for header in CORE_HEADERS:
            hits = by_header.get(header, [])
            worst = min((SEVERITY_ORDER.index(f["severity"]) for f in hits), default=99)
            if worst <= SEVERITY_ORDER.index("medium"):
                status, style = "FAIL", "critical"
            elif worst in (SEVERITY_ORDER.index("low"), SEVERITY_ORDER.index("info")):
                status, style = "WARN", "warning"
            else:
                status, style = "PASS", "pass"
            detail = hits[0]["title"] if hits else "OK"
            value = report["raw_headers"].get(header)
            shown = (value[:120] + "...") if value and len(value) > 120 else value
            add_row(overview, Text(header), Text(status, style=style), detail,
                    Text(shown or "-", style="muted"))
        console.print(overview)

        # Severity-ranked findings
        shown_findings = [f for f in findings if verbose or f["severity"] != "info"]
        if shown_findings:
            print_section("Findings")
            ftable = make_table(None, ["Severity", "Finding",
                                       ("Why it matters", {"overflow": "fold", "max_width": 44}),
                                       ("Fix", {"overflow": "fold", "max_width": 40})])
            for f in shown_findings:
                add_row(ftable, Text(f["severity"].upper(), style=SEVERITY_STYLE[f["severity"]]),
                        f["title"], f["why"], f["fix"] or "-")
            console.print(ftable)

        counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
        print_section("Score")
        gstyle = {"A": "pass", "B": "pass", "C": "warning", "D": "warning", "F": "critical"}[report["grade"]]
        line = Text()
        line.append(f"{report['score']}/100", style="heading")
        line.append("   Grade: ")
        line.append(report["grade"], style=f"{gstyle} bold")
        line.append(f"   (high={counts['high']}, medium={counts['medium']}, "
                    f"low={counts['low']}, info={counts['info']})", style="muted")
        console.print(line)
        hidden = counts["info"] if not verbose else 0
        if hidden:
            print_info(f"{hidden} informational note(s) hidden; set VERBOSE true to show")

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        base = normalize_url(self.get("URL"))
        raw_paths = (self.get("PATHS") or "").strip()
        if raw_paths:
            parsed = urlparse(base)
            root = f"{parsed.scheme}://{parsed.netloc}"
            targets = []
            for p in raw_paths.split(","):
                p = p.strip()
                if not p:
                    continue
                targets.append(root + (p if p.startswith("/") else "/" + p))
        else:
            targets = [base]

        reports = []
        for i, url in enumerate(targets):
            if self.cancelled:
                break
            if i:
                console.rule(style="muted")
            try:
                report = self._analyze(url)
            except ReconError as exc:
                print_warn(f"{url}: {exc}")
                continue
            self._render(report)
            reports.append(report)

        if not reports:
            raise ReconError("No target returned a usable response")

        if len(reports) == 1:
            return reports[0]
        return {"base_url": base, "paths": reports,
                "summary": {"checked": len(reports),
                            "graded": sum(r["grade"] is not None for r in reports)}}
