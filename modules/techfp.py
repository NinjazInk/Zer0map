"""techfp: web technology fingerprinter (headers, cookies, HTML, known paths)."""
from __future__ import annotations

import random
import re
import string
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment
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
from core.utils import ReconError, http_request, normalize_url, run_concurrent

CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# cookie name (lowercase, prefix match when ending in '*') -> (category, technology)
COOKIE_SIGNATURES = {
    "phpsessid": ("Language", "PHP"),
    "jsessionid": ("Language", "Java (Servlet container)"),
    "asp.net_sessionid": ("Framework", "ASP.NET"),
    "aspsessionid*": ("Framework", "Classic ASP"),
    ".aspxauth": ("Framework", "ASP.NET (Forms Auth)"),
    "__requestverificationtoken": ("Framework", "ASP.NET MVC"),
    "csrftoken": ("Framework", "Django"),
    "sessionid": ("Framework", "Django"),
    "_rails_session": ("Framework", "Ruby on Rails"),
    "*_session_rails": ("Framework", "Ruby on Rails"),
    "laravel_session": ("Framework", "Laravel"),
    "xsrf-token": ("Framework", "Laravel / Angular (XSRF-TOKEN)"),
    "connect.sid": ("Framework", "Node.js / Express"),
    "wp_*": ("CMS", "WordPress"),
    "wordpress_*": ("CMS", "WordPress"),
    "ci_session": ("Framework", "CodeIgniter"),
    "cakephp": ("Framework", "CakePHP"),
    "symfony": ("Framework", "Symfony"),
    "frontend": ("CMS", "Magento"),
    "mage-*": ("CMS", "Magento"),
    "_shopify_*": ("CMS", "Shopify"),
    "__cf_bm": ("CDN", "Cloudflare"),
    "cf_clearance": ("CDN", "Cloudflare"),
    "awsalb*": ("CDN", "AWS Elastic Load Balancer"),
    "bigipserver*": ("Server", "F5 BIG-IP"),
    "ts01*": ("Server", "F5 BIG-IP ASM"),
    "_flask*": ("Framework", "Flask"),
    "session": ("Framework", "Generic session cookie (Flask/others)"),
    "grafana_session": ("Framework", "Grafana"),
}

# header name -> category used when the header itself reveals technology
CDN_HEADERS = [
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-amz-cf-pop", "Amazon CloudFront"),
    ("x-akamai-transformed", "Akamai"),
    ("x-akamai-request-id", "Akamai"),
    ("x-fastly-request-id", "Fastly"),
    ("x-vercel-id", "Vercel"),
    ("x-nf-request-id", "Netlify"),
    ("x-azure-ref", "Azure Front Door"),
    ("x-msedge-ref", "Azure CDN"),
    ("x-github-request-id", "GitHub Pages"),
    ("x-sucuri-id", "Sucuri WAF"),
    ("x-cdn", "Generic CDN ({value})"),
    ("x-iinfo", "Imperva Incapsula"),
    ("fly-request-id", "Fly.io"),
    ("x-goog-generation", "Google Cloud Storage"),
    ("x-amz-request-id", "Amazon S3"),
]

SERVER_PATTERNS = [
    (r"nginx(?:/([\d.]+))?", "Server", "nginx"),
    (r"openresty(?:/([\d.]+))?", "Server", "OpenResty"),
    (r"apache(?:/([\d.]+))?", "Server", "Apache HTTP Server"),
    (r"microsoft-iis(?:/([\d.]+))?", "Server", "Microsoft IIS"),
    (r"litespeed", "Server", "LiteSpeed"),
    (r"caddy", "Server", "Caddy"),
    (r"lighttpd(?:/([\d.]+))?", "Server", "lighttpd"),
    (r"gunicorn(?:/([\d.]+))?", "Server", "Gunicorn (Python)"),
    (r"uvicorn", "Server", "Uvicorn (Python)"),
    (r"werkzeug(?:/([\d.]+))?", "Server", "Werkzeug (Python/Flask)"),
    (r"kestrel", "Server", "Kestrel (.NET)"),
    (r"jetty(?:\(([\d.]+))?", "Server", "Jetty (Java)"),
    (r"tomcat|coyote", "Server", "Apache Tomcat"),
    (r"envoy", "Server", "Envoy"),
    (r"cloudflare", "CDN", "Cloudflare"),
    (r"akamaighost", "CDN", "Akamai"),
    (r"amazons3", "CDN", "Amazon S3"),
    (r"awselb", "CDN", "AWS Elastic Load Balancer"),
    (r"gws|gse", "Server", "Google Web Server"),
    (r"vercel", "CDN", "Vercel"),
    (r"netlify", "CDN", "Netlify"),
    (r"github\.com", "CDN", "GitHub Pages"),
    (r"cowboy", "Server", "Cowboy (Erlang/Elixir)"),
    (r"(?:^|\s)php/([\d.]+)", "Language", "PHP"),
    (r"openssl/([\d.a-z]+)", "Server", "OpenSSL"),
    (r"ubuntu|debian|centos|red hat|win32|win64|unix", "Server", "OS hint"),
]

POWERED_BY_PATTERNS = [
    (r"php(?:/([\d.]+))?", "Language", "PHP"),
    (r"asp\.net", "Framework", "ASP.NET"),
    (r"express", "Framework", "Node.js / Express"),
    (r"next\.js(?:\s*([\d.]+))?", "Framework", "Next.js"),
    (r"nuxt", "Framework", "Nuxt.js"),
    (r"servlet(?:/([\d.]+))?", "Language", "Java Servlet"),
    (r"jsp(?:/([\d.]+))?", "Language", "Java (JSP)"),
    (r"plesk", "Server", "Plesk"),
    (r"wp engine", "CMS", "WordPress (WP Engine)"),
    (r"craft cms", "CMS", "Craft CMS"),
    (r"shopify", "CMS", "Shopify"),
]

# (regex on HTML, category, technology, confidence, evidence)
HTML_SIGNATURES = [
    (r"/wp-content/", "CMS", "WordPress", "High", "/wp-content/ asset paths"),
    (r"/wp-includes/", "CMS", "WordPress", "High", "/wp-includes/ asset paths"),
    (r"/sites/default/files/", "CMS", "Drupal", "High", "/sites/default/files/ paths"),
    (r"drupal-settings-json|Drupal\.settings", "CMS", "Drupal", "High", "Drupal settings object"),
    (r"/media/jui/|/media/system/js/", "CMS", "Joomla", "High", "/media/jui/ asset paths"),
    (r"cdn\.shopify\.com|Shopify\.theme", "CMS", "Shopify", "High", "Shopify CDN/theme object"),
    (r"static\.wixstatic\.com|wix-bolt", "CMS", "Wix", "High", "Wix static assets"),
    (r"squarespace\.com|static1\.squarespace", "CMS", "Squarespace", "High", "Squarespace assets"),
    (r"/skin/frontend/|Mage\.Cookies|/static/version\d+/frontend/", "CMS", "Magento", "High", "Magento asset paths"),
    (r"ghost-(?:url|portal)|content=\"Ghost", "CMS", "Ghost", "Medium", "Ghost markers"),
    (r"/_next/static/|__NEXT_DATA__", "Framework", "Next.js", "High", "/_next/ assets or __NEXT_DATA__"),
    (r"/_nuxt/|/__nuxt/|window\.__NUXT__", "Framework", "Nuxt.js", "High", "/_nuxt/ assets or __NUXT__"),
    (r"___gatsby|/page-data/", "Framework", "Gatsby", "High", "___gatsby root"),
    (r"data-reactroot|data-reactid|__REACT_DEVTOOLS|react-dom(?:\.production)?(?:\.min)?\.js", "JS Libraries", "React", "Medium", "React markers"),
    (r"ng-version=\"([\d.]+)\"", "JS Libraries", "Angular", "High", "ng-version attribute"),
    (r"\bng-app\b|angular(?:\.min)?\.js", "JS Libraries", "AngularJS (1.x)", "Medium", "ng-app / angular.js"),
    (r"data-v-[0-9a-f]{8}|__VUE__|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js", "JS Libraries", "Vue.js", "Medium", "Vue markers"),
    (r"svelte-[a-z0-9]{6}|__sveltekit", "JS Libraries", "Svelte", "Medium", "Svelte class hashes"),
    (r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js", "JS Libraries", "jQuery", "High", "jquery script"),
    (r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)", "JS Libraries", "Bootstrap", "Medium", "bootstrap asset"),
    (r"tailwind", "JS Libraries", "Tailwind CSS", "Low", "tailwind reference"),
    (r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+", "JS Libraries", "Google Tag Manager", "High", "GTM container"),
    (r"google-analytics\.com/|gtag\(|G-[A-Z0-9]{8,}", "JS Libraries", "Google Analytics", "Medium", "GA script"),
    (r"cdnjs\.cloudflare\.com", "CDN", "cdnjs", "Medium", "cdnjs-hosted assets"),
    (r"cdn\.jsdelivr\.net", "CDN", "jsDelivr", "Medium", "jsDelivr-hosted assets"),
    (r"unpkg\.com", "CDN", "unpkg", "Medium", "unpkg-hosted assets"),
    (r"recaptcha/api\.js", "JS Libraries", "Google reCAPTCHA", "High", "reCAPTCHA script"),
    (r"js\.stripe\.com", "JS Libraries", "Stripe.js", "High", "Stripe script"),
]

VERSION_LIBS = [
    # (category, technology, regex capturing version in script src / inline script)
    ("JS Libraries", "jQuery", r"jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js|jquery(?:\.min)?\.js\?ver=(\d+\.\d+(?:\.\d+)?)|jQuery v(\d+\.\d+\.\d+)"),
    ("JS Libraries", "React", r"react(?:-dom)?@(\d+\.\d+\.\d+)|React v(\d+\.\d+\.\d+)"),
    ("JS Libraries", "Vue.js", r"vue@(\d+\.\d+\.\d+)|Vue\.js v(\d+\.\d+\.\d+)"),
    ("JS Libraries", "AngularJS (1.x)", r"angular(?:js)?/(1\.\d+\.\d+)/|AngularJS v(1\.\d+\.\d+)"),
    ("JS Libraries", "Bootstrap", r"bootstrap@(\d+\.\d+\.\d+)|bootstrap/(\d+\.\d+\.\d+)/|Bootstrap v(\d+\.\d+\.\d+)"),
]

BODY_CLASS_SIGNATURES = [
    (r"\bwp-(?:custom-logo|embed-responsive)\b|\bpage-template\b|\bwordpress\b", "CMS", "WordPress"),
    (r"\bpath-frontpage\b|\bpage-node-|\bnode-type-", "CMS", "Drupal"),
    (r"\bjoomla\b|\bsite-grid\b|\bcom_content\b", "CMS", "Joomla"),
    (r"\bcms-index-index\b|\bcatalog-product-view\b", "CMS", "Magento"),
]

COMMENT_SIGNATURES = [
    (r"yoast", "CMS", "WordPress (Yoast SEO plugin)"),
    (r"wp super cache|w3 total cache|wp rocket|litespeed cache", "CMS", "WordPress (cache plugin)"),
    (r"drupal", "CMS", "Drupal"),
    (r"joomla", "CMS", "Joomla"),
    (r"shopify", "CMS", "Shopify"),
    (r"squarespace", "CMS", "Squarespace"),
    (r"generated by (.+?)(?:\s|$)", "Framework", "Generator comment"),
]

INTERESTING_ROBOTS = re.compile(
    r"admin|backup|bak|private|secret|internal|config|\.git|\.env|dev|staging|test|old|tmp|"
    r"api|login|dashboard|db|sql|upload|cgi-bin|phpmyadmin|console|debug|swagger|graphql",
    re.I,
)

ENV_LINE = re.compile(r"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M)


class Module(BaseModule):
    name = "techfp"
    description = "Fingerprint the web technology stack (server, language, framework, CMS, JS, CDN)"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("URL", None, True, "Target URL (e.g. https://example.com)")
        self.add_option("DEPTH", "full", False, "basic (headers only) or full (headers + HTML + paths)",
                        type="choice", choices=["basic", "full"])
        self.add_option("TIMEOUT", 10.0, False, "Request timeout in seconds", type="float", minimum=1)
        self.add_option("VERIFY_SSL", True, False, "Verify TLS certificates (true/false)", type="bool")
        self.add_option("THREADS", 5, False, "Concurrent path probes (full depth)", type="int", minimum=1)

    # ------------------------------------------------------------------ bookkeeping
    def _reset(self) -> None:
        self.detections: dict[tuple[str, str], dict] = {}
        self.findings: list[dict] = []

    def detect(self, category: str, tech: str, confidence: str, evidence: str, version: str | None = None) -> None:
        key = (category, tech.lower())
        entry = self.detections.get(key)
        if entry is None:
            self.detections[key] = {"category": category, "technology": tech, "version": version,
                                    "confidence": confidence, "evidence": [evidence]}
            return
        if CONF_RANK[confidence] > CONF_RANK[entry["confidence"]]:
            entry["confidence"] = confidence
        if version and not entry["version"]:
            entry["version"] = version
        if evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)

    def finding(self, severity: str, title: str, evidence: str) -> None:
        if not any(f["title"] == title for f in self.findings):
            self.findings.append({"severity": severity, "title": title, "evidence": evidence})

    # ------------------------------------------------------------------ analysis
    def _analyze_headers(self, resp) -> None:
        responses = list(resp.history) + [resp]
        for r in responses:
            h = r.headers
            server = h.get("Server")
            if server:
                for pattern, cat, tech in SERVER_PATTERNS:
                    m = re.search(pattern, server, re.I)
                    if m:
                        version = next((g for g in m.groups() if g), None) if m.groups() else None
                        if tech == "OS hint":
                            self.detect("Server", f"OS: {m.group(0)}", "Medium", f"Server: {server}")
                        else:
                            self.detect(cat, tech, "High", f"Server: {server}", version)
                if re.search(r"\d", server):
                    self.finding("LOW", "Server header discloses version", f"Server: {server}")
            powered = h.get("X-Powered-By")
            if powered:
                matched = False
                for pattern, cat, tech in POWERED_BY_PATTERNS:
                    m = re.search(pattern, powered, re.I)
                    if m:
                        matched = True
                        version = next((g for g in m.groups() if g), None) if m.groups() else None
                        self.detect(cat, tech, "High", f"X-Powered-By: {powered}", version)
                if not matched:
                    self.detect("Framework", powered, "Medium", f"X-Powered-By: {powered}")
                self.finding("LOW", "X-Powered-By discloses backend technology", f"X-Powered-By: {powered}")
            for name, cat, tech in (("X-AspNet-Version", "Framework", "ASP.NET"),
                                    ("X-AspNetMvc-Version", "Framework", "ASP.NET MVC")):
                if h.get(name):
                    self.detect(cat, tech, "High", f"{name}: {h[name]}", h[name])
                    self.finding("LOW", f"{name} header discloses framework version", f"{name}: {h[name]}")
            gen = h.get("X-Generator")
            if gen:
                vm = re.search(r"(\d+(?:\.\d+)+)", gen)
                name = re.sub(r"\s*v?\d[\d.]*.*$", "", gen).strip() or gen
                self.detect("CMS", name, "High", f"X-Generator: {gen}", vm.group(1) if vm else None)
            if h.get("X-Drupal-Cache") or h.get("X-Drupal-Dynamic-Cache"):
                self.detect("CMS", "Drupal", "High", "X-Drupal-Cache header")
            if h.get("X-Shopify-Stage") or h.get("X-ShopId"):
                self.detect("CMS", "Shopify", "High", "Shopify headers")
            if "wp-json" in h.get("Link", ""):
                self.detect("CMS", "WordPress", "High", "Link: </wp-json/> REST API header")
            if h.get("X-Varnish"):
                self.detect("CDN", "Varnish cache", "High", "X-Varnish header")
            via = h.get("Via")
            if via:
                if "varnish" in via.lower():
                    self.detect("CDN", "Varnish cache", "High", f"Via: {via}")
                elif "cloudfront" in via.lower():
                    self.detect("CDN", "Amazon CloudFront", "High", f"Via: {via}")
                else:
                    self.detect("CDN", f"Proxy ({via.split(',')[0].strip()})", "Low", f"Via: {via}")
            served_by = h.get("X-Served-By", "")
            if served_by.startswith("cache-"):
                self.detect("CDN", "Fastly", "High", f"X-Served-By: {served_by}")
            for header, tech in CDN_HEADERS:
                if header in h:
                    self.detect("CDN", tech.format(value=h[header]), "High", f"{header} header")

        # Cookies from every response in the redirect chain
        cookie_names = set()
        for r in responses:
            for c in r.cookies:
                cookie_names.add(c.name)
            raw = r.headers.get("Set-Cookie", "")
            cookie_names.update(m.group(1) for m in re.finditer(r"(?:^|,\s*)([^=;,\s]+)=", raw))
        for cname in sorted(cookie_names):
            low = cname.lower()
            for sig, (cat, tech) in COOKIE_SIGNATURES.items():
                if (sig.endswith("*") and low.startswith(sig[:-1])) or \
                   (sig.startswith("*") and low.endswith(sig[1:])) or low == sig:
                    conf = "Low" if sig in ("session", "sessionid") else "High"
                    self.detect(cat, tech, conf, f"Cookie: {cname}")
                    break

    def _analyze_html(self, html: str) -> None:
        soup = BeautifulSoup(html, "html.parser")

        for meta in soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)}):
            content = (meta.get("content") or "").strip()
            if content:
                m = re.match(r"(.+?)\s+v?(\d+(?:\.\d+)*)", content)
                tech, version = (m.group(1), m.group(2)) if m else (content, None)
                self.detect("CMS", tech, "High", f'<meta name="generator" content="{content}">', version)
                if version:
                    self.finding("LOW", "Generator meta tag discloses CMS version", content)

        for pattern, cat, tech, conf, evidence in HTML_SIGNATURES:
            m = re.search(pattern, html, re.I)
            if m:
                version = next((g for g in m.groups() if g), None) if m.groups() else None
                self.detect(cat, tech, conf, evidence, version)

        # Versioned libraries from script srcs and inline banners
        sources = " ".join(s.get("src", "") for s in soup.find_all("script")) + " " + \
                  " ".join(l.get("href", "") for l in soup.find_all("link"))
        haystack = sources + " " + " ".join((s.string or "")[:5000] for s in soup.find_all("script") if not s.get("src"))
        for cat, tech, pattern in VERSION_LIBS:
            m = re.search(pattern, haystack, re.I)
            if m:
                version = next((g for g in m.groups() if g), None)
                self.detect(cat, tech, "High", f"versioned reference ({m.group(0)[:60]})", version)

        body = soup.find("body")
        classes = " ".join(body.get("class", [])) if body else ""
        for pattern, cat, tech in BODY_CLASS_SIGNATURES:
            if classes and re.search(pattern, classes, re.I):
                self.detect(cat, tech, "Medium", f'body class="{classes[:60]}"')

        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            for pattern, cat, tech in COMMENT_SIGNATURES:
                m = re.search(pattern, text, re.I)
                if m:
                    if tech == "Generator comment":
                        self.detect(cat, m.group(1).strip()[:40], "Low", f"<!-- {text[:60]} -->")
                    else:
                        self.detect(cat, tech, "Medium", f"HTML comment: {text[:60]}")

    # ------------------------------------------------------------------ path probing
    def _fetch(self, url: str, method: str = "GET"):
        return http_request(method, url, timeout=self.get("TIMEOUT"), allow_redirects=False,
                            verify=self.get("VERIFY_SSL"))

    def _probe(self, item):
        path, base = item
        url = urljoin(base, path)
        try:
            resp = self._fetch(url, "HEAD")
            if resp.status_code in (405, 501):  # HEAD not supported
                resp = self._fetch(url, "GET")
        except ReconError:
            return None
        if resp.status_code not in (200, 301, 302, 307, 308):
            return None
        body = ""
        if resp.status_code == 200:
            try:
                get = self._fetch(url, "GET")
                body = get.text[:200_000] if get.status_code == 200 else ""
            except ReconError:
                body = ""
        return {"status": resp.status_code, "location": resp.headers.get("Location"), "body": body,
                "length": len(body), "content_type": resp.headers.get("Content-Type", "")}

    def _probe_paths(self, base: str) -> list[dict]:
        # Soft-404 baseline: many sites answer 200 for any path
        rand = "".join(random.choices(string.ascii_lowercase, k=12))
        baseline = self._probe((f"/zer0map-{rand}.html", base))
        soft404 = bool(baseline and baseline["status"] == 200)
        if soft404:
            print_warn("Server returns 200 for non-existent paths (soft 404); relying on content checks")

        paths = ["/robots.txt", "/wp-login.php", "/administrator/", "/user/login", "/elmah.axd",
                 "/web.config", "/server-status", "/.env", "/graphql", "/api/swagger.json",
                 "/swagger-ui.html", "/.git/HEAD"]
        hits = {item[0]: res for item, res in run_concurrent(
            self._probe, [(p, base) for p in paths], self.get("THREADS"),
            "Probing known paths", self.stop_event)}
        found = []

        def note(path: str, tech: str, cat: str, conf: str, detail: str) -> None:
            found.append({"path": path, "status": hits[path]["status"], "detail": detail})
            self.detect(cat, tech, conf, f"{path} ({detail})")

        for path in [p for p in paths if p in hits]:
            res = hits[path]
            body, status = res["body"], res["status"]
            redirect = status in (301, 302, 307, 308)
            loc = res["location"] or ""
            # A redirect to a generic page or a soft-404 200 with no matching content is weak evidence
            weak = redirect or soft404
            if path == "/robots.txt":
                if status == 200 and re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", body):
                    disallowed = re.findall(r"(?im)^\s*disallow\s*:\s*(\S+)", body)
                    interesting = sorted({d for d in disallowed if INTERESTING_ROBOTS.search(d)})
                    detail = f"{len(disallowed)} Disallow rule(s)"
                    if interesting:
                        detail += "; interesting: " + ", ".join(interesting[:10])
                    found.append({"path": path, "status": status, "detail": detail,
                                  "disallowed": disallowed, "interesting": interesting})
                    self.detect("Interesting Paths", "/robots.txt", "High", detail)
                    if "/wp-admin/" in disallowed:
                        self.detect("CMS", "WordPress", "High", "robots.txt disallows /wp-admin/")
            elif path == "/wp-login.php":
                if status == 200 and re.search(r"user_login|wp-submit|wp-login", body):
                    note(path, "WordPress", "CMS", "High", "WordPress login page")
                elif not weak:
                    note(path, "WordPress", "CMS", "Low", f"HTTP {status}")
            elif path == "/administrator/":
                if status == 200 and re.search(r"joomla", body, re.I):
                    note(path, "Joomla", "CMS", "High", "Joomla administrator login")
                elif status == 200 and not weak:
                    note(path, "Joomla", "CMS", "Low", "HTTP 200 (unconfirmed)")
            elif path == "/user/login":
                if status == 200 and re.search(r"drupal|user-login-form", body, re.I):
                    note(path, "Drupal", "CMS", "High", "Drupal login form")
            elif path == "/elmah.axd":
                if status == 200 and re.search(r"error log for|elmah", body, re.I):
                    note(path, "ASP.NET (ELMAH)", "Framework", "High", "ELMAH error log accessible")
                    self.finding("CRITICAL", "ELMAH error log publicly accessible (stack traces, cookies, requests)", path)
            elif path == "/web.config":
                if status == 200 and "<configuration" in body.lower():
                    note(path, "IIS / ASP.NET", "Server", "High", "web.config is downloadable")
                    self.finding("CRITICAL", "web.config is publicly downloadable (may contain secrets/connection strings)", path)
            elif path == "/server-status":
                if status == 200 and "apache server status" in body.lower():
                    note(path, "Apache HTTP Server", "Server", "High", "mod_status page accessible")
                    self.finding("HIGH", "Apache server-status is publicly accessible (live requests, client IPs)", path)
            elif path == "/.env":
                lines = ENV_LINE.findall(body) if status == 200 else []
                if len(lines) >= 2 and "<html" not in body[:500].lower():
                    found.append({"path": path, "status": status, "detail": f"{len(lines)} KEY=VALUE lines"})
                    self.detect("Interesting Paths", "/.env", "High", "environment file exposed")
                    self.finding("CRITICAL", "Exposed .env file (credentials / API keys likely leaked)",
                                 f"{path}: {len(lines)} variable assignments")
            elif path == "/.git/HEAD":
                if status == 200 and body.startswith("ref:"):
                    found.append({"path": path, "status": status, "detail": body.strip()[:60]})
                    self.detect("Interesting Paths", "/.git/", "High", "Git repository exposed")
                    self.finding("CRITICAL", "Exposed .git directory (source code can be reconstructed)", path)
            elif path == "/graphql":
                if re.search(r"graphql|\"errors\"\s*:|must provide query", body, re.I) or \
                   (status == 200 and "application/json" in res["content_type"] and not soft404):
                    note(path, "GraphQL", "Interesting Paths", "High", "GraphQL endpoint")
                    self.finding("INFO", "GraphQL endpoint found (test for introspection / authZ)", path)
                elif redirect and "graphql" in loc.lower():
                    note(path, "GraphQL", "Interesting Paths", "Medium", f"redirects to {loc}")
            elif path in ("/api/swagger.json", "/swagger-ui.html"):
                if re.search(r"\"swagger\"\s*:|\"openapi\"\s*:|swagger-ui", body, re.I):
                    note(path, "Swagger / OpenAPI docs", "Interesting Paths", "High", "API documentation exposed")
                    self.finding("MEDIUM", "API documentation publicly exposed (full endpoint map)", path)
        return found

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        self._reset()
        url = normalize_url(self.get("URL"))
        depth = self.get("DEPTH")
        with console.status(f"[info]Fetching {url}...[/info]"):
            resp = http_request("GET", url, timeout=self.get("TIMEOUT"), verify=self.get("VERIFY_SSL"))
        print_info(f"Final URL: {resp.url}  (HTTP {resp.status_code}, {len(resp.content)} bytes)")

        self._analyze_headers(resp)
        paths: list[dict] = []
        if depth == "full":
            ctype = resp.headers.get("Content-Type", "")
            if "html" in ctype or resp.text.lstrip()[:1] == "<":
                self._analyze_html(resp.text)
            else:
                print_warn(f"Response is not HTML ({ctype or 'unknown type'}); skipping HTML analysis")
            parsed = urlparse(resp.url)
            paths = self._probe_paths(f"{parsed.scheme}://{parsed.netloc}/")

        order = ["Server", "Language", "Framework", "CMS", "JS Libraries", "CDN", "Interesting Paths"]
        detections = sorted(
            self.detections.values(),
            key=lambda d: (order.index(d["category"]) if d["category"] in order else 99,
                           -CONF_RANK[d["confidence"]], d["technology"].lower()),
        )

        print_section("Technology Fingerprint")
        if detections:
            table = make_table(None, ["Category", "Detected Technology", "Confidence",
                                      ("Evidence", {"overflow": "fold", "max_width": 60})])
            conf_style = {"High": "pass", "Medium": "warning", "Low": "muted"}
            for d in detections:
                tech = d["technology"] + (f" {d['version']}" if d["version"] else "")
                add_row(table, d["category"], tech, Text(d["confidence"], style=conf_style[d["confidence"]]),
                        "; ".join(d["evidence"][:3]))
            console.print(table)
        else:
            print_warn("No technologies identified")

        if self.findings:
            self.findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
            print_section("Security Findings")
            ftable = make_table(None, ["Severity", "Finding", "Evidence"])
            for f in self.findings:
                add_row(ftable, status_text(f["severity"]), f["title"], f["evidence"])
            console.print(ftable)
        else:
            print_good("No information disclosures or misconfigurations found")

        return {
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "depth": depth,
            "technologies": [
                {**d, "evidence": "; ".join(d["evidence"])} for d in detections
            ],
            "paths": [{k: v for k, v in p.items() if k != "disallowed"} for p in paths],
            "findings": self.findings,
        }
