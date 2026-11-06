"""whois: raw WHOIS lookup (IANA referral chain) + DNS records + email security posture."""
from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

from rich.text import Text

from core.base_module import BaseModule
from core.output import (
    add_row,
    console,
    make_table,
    print_critical,
    print_error,
    print_good,
    print_info,
    print_section,
    print_warn,
    status_text,
)
from core.utils import ReconError, dns_query, make_resolver, normalize_domain

IANA = "whois.iana.org"
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim",
    "smtp", "email", "mandrill", "mxvault", "zoho", "protonmail", "protonmail2", "fm1", "fm2",
    "fm3", "cm", "mailjet", "sendgrid", "amazonses", "everlytic", "sig1", "key1", "mailgun", "pm",
]

FIELD_PATTERNS = {
    "registrar": [r"^\s*Registrar:\s*(.+)$", r"^\s*registrar:\s*(.+)$", r"^\s*Registrar Name:\s*(.+)$",
                  r"^\s*Sponsoring Registrar:\s*(.+)$"],
    "creation_date": [r"^\s*Creation Date:\s*(.+)$", r"^\s*created:\s*(.+)$", r"^\s*Registered on:\s*(.+)$",
                      r"^\s*Registration Time:\s*(.+)$", r"^\s*Domain Registration Date:\s*(.+)$",
                      r"^\s*Registered:\s*(.+)$"],
    "expiry_date": [r"^\s*Registry Expiry Date:\s*(.+)$", r"^\s*Registrar Registration Expiration Date:\s*(.+)$",
                    r"^\s*Expiration Date:\s*(.+)$", r"^\s*Expiry Date:\s*(.+)$", r"^\s*paid-till:\s*(.+)$",
                    r"^\s*expires:\s*(.+)$", r"^\s*Expiration Time:\s*(.+)$", r"^\s*Domain Expiration Date:\s*(.+)$"],
    "updated_date": [r"^\s*Updated Date:\s*(.+)$", r"^\s*last-modified:\s*(.+)$", r"^\s*changed:\s*(.+)$"],
    "registrant_org": [r"^\s*Registrant Organi[sz]ation:\s*(.+)$", r"^\s*org:\s*(.+)$",
                       r"^\s*Registrant:\s*(.+)$"],
    "registrant_country": [r"^\s*Registrant Country:\s*(.+)$"],
    "dnssec": [r"^\s*DNSSEC:\s*(.+)$"],
}
MULTI_PATTERNS = {
    "name_servers": [r"^\s*Name Server:\s*(\S+)", r"^\s*nserver:\s*(\S+)", r"^\s*Nameservers?:\s*(\S+)"],
    "status": [r"^\s*Domain Status:\s*(\S+)", r"^\s*status:\s*(.+)$"],
}
REDACTED = re.compile(r"redacted|privacy|withheld|data protected|not disclosed|gdpr|proxy|whoisguard", re.I)


def whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((query + "\r\n").encode("utf-8"))
            chunks, total = [], 0
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if total > 1_000_000:
                    break
    except socket.timeout:
        raise ReconError(f"WHOIS server {server} timed out") from None
    except socket.gaierror:
        raise ReconError(f"Could not resolve WHOIS server {server}") from None
    except OSError as exc:
        raise ReconError(f"WHOIS query to {server} failed: {exc.strerror or exc}") from None
    return b"".join(chunks).decode("utf-8", "replace")


def _format_query(server: str, domain: str) -> str:
    if server == "whois.denic.de":
        return f"-T dn,ace {domain}"
    if server == "whois.jprs.jp":
        return f"{domain}/e"
    if server in ("whois.verisign-grs.com", "whois.crsnic.net"):
        return f"domain {domain}"
    return domain


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.strip().split(" (")[0]
    raw = re.sub(r"\s+UTC$|Z$", "", raw).replace("T", " ").split(".")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d", "%d/%m/%Y",
                "%Y/%m/%d", "%Y-%m-%d %H:%M", "%d-%m-%Y", "%b %d %Y", "%Y%m%d"):
        for candidate in (raw.strip(), raw[:19].strip(), raw[:10].strip()):
            try:
                return datetime.strptime(candidate, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
    return None


def parse_whois(texts: list[str]) -> dict:
    """Parse fields, preferring the first text (most specific server) and falling back."""
    out: dict = {}
    for field, patterns in FIELD_PATTERNS.items():
        for text in texts:
            for p in patterns:
                m = re.search(p, text, re.I | re.M)
                if m and m.group(1).strip():
                    out[field] = m.group(1).strip()
                    break
            if field in out:
                break
    for field, patterns in MULTI_PATTERNS.items():
        values: list[str] = []
        for text in texts:
            for p in patterns:
                for m in re.finditer(p, text, re.I | re.M):
                    v = m.group(1).strip().rstrip(".")
                    v = v.lower() if field == "name_servers" else v.split()[0]
                    if v and v not in values:
                        values.append(v)
        out[field] = values
    return out


class Module(BaseModule):
    name = "whois"
    description = "WHOIS registration data, DNS records and email security posture (SPF/DKIM/DMARC)"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("DOMAIN", None, True, "Target domain (e.g. example.com)")

    # ------------------------------------------------------------------ WHOIS
    def _whois(self, domain: str) -> dict:
        tld = domain.rsplit(".", 1)[-1]
        iana = whois_query(IANA, tld)
        m = re.search(r"^\s*(?:whois|refer):\s*(\S+)", iana, re.I | re.M)
        if not m:
            raise ReconError(f"IANA has no WHOIS server for .{tld}")
        servers = [m.group(1).strip()]
        registry_text = whois_query(servers[0], _format_query(servers[0], domain))
        texts = [registry_text]
        ref = re.search(r"^\s*Registrar WHOIS Server:\s*(\S+)", registry_text, re.I | re.M)
        if ref:
            registrar_server = re.sub(r"^\w+://", "", ref.group(1).strip()).strip("/")
            if registrar_server and registrar_server.lower() != servers[0].lower():
                try:
                    texts.insert(0, whois_query(registrar_server, domain))
                    servers.append(registrar_server)
                except ReconError as exc:
                    print_warn(f"Registrar WHOIS lookup failed ({exc}); using registry data only")
        if re.search(r"no match|not found|no data found|no entries found|status:\s*free|available for registration",
                     registry_text[:2000], re.I):
            raise ReconError(f"WHOIS: {domain} does not appear to be registered")
        parsed = parse_whois(texts)
        parsed["servers"] = servers
        return parsed

    # ------------------------------------------------------------------ email posture
    @staticmethod
    def _spf(txt_records: list[str]) -> dict:
        spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
        if not spf:
            return {"status": "MISSING", "record": None,
                    "detail": "No SPF record: anyone can send mail claiming to be this domain"}
        if len(spf) > 1:
            return {"status": "MISCONFIGURED", "record": " || ".join(spf),
                    "detail": "Multiple SPF records (RFC 7208 permerror: SPF fails entirely)"}
        record = spf[0]
        lookups = len(re.findall(r"\b(?:include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", record, re.I))
        m = re.search(r"([+?~-]?)all\b", record, re.I)
        qualifier = (m.group(1) or "+") if m else None
        if qualifier == "+":
            status, detail = "MISCONFIGURED", "'+all' allows any server to send (SPF is useless)"
        elif qualifier == "?":
            status, detail = "MISCONFIGURED", "'?all' (neutral) provides no protection"
        elif qualifier == "~":
            status, detail = "PRESENT", "'~all' softfail (acceptable with DMARC enforcement; '-all' is stricter)"
        elif qualifier == "-":
            status, detail = "PRESENT", "'-all' hard fail (strict)"
        elif "redirect=" in record.lower():
            status, detail = "PRESENT", "Policy delegated via redirect="
        else:
            status, detail = "MISCONFIGURED", "No 'all' mechanism: unlisted senders aren't rejected"
        if lookups > 10:
            status, detail = "MISCONFIGURED", detail + f"; {lookups} DNS-lookup mechanisms (limit is 10)"
        return {"status": status, "record": record, "detail": detail, "all_qualifier": qualifier}

    @staticmethod
    def _dmarc(records: list[str]) -> dict:
        dmarc = [r for r in records if r.lower().replace(" ", "").startswith("v=dmarc1")]
        if not dmarc:
            return {"status": "MISSING", "record": None, "policy": None,
                    "detail": "No DMARC record: spoofed mail isn't rejected and you get no reports"}
        if len(dmarc) > 1:
            return {"status": "MISCONFIGURED", "record": " || ".join(dmarc), "policy": None,
                    "detail": "Multiple DMARC records (receivers will ignore DMARC)"}
        record = dmarc[0]
        tags = {}
        for part in record.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        policy = tags.get("p", "").lower()
        pct = tags.get("pct", "100")
        notes = []
        if "rua" not in tags:
            notes.append("no rua= aggregate reporting")
        if policy == "reject":
            status, detail = "PRESENT", "p=reject (spoofed mail is rejected)"
        elif policy == "quarantine":
            status, detail = "PRESENT", "p=quarantine (spoofed mail goes to spam)"
        elif policy == "none":
            status, detail = "MISCONFIGURED", "p=none: monitoring only, spoofed mail is still delivered"
        else:
            status, detail = "MISCONFIGURED", f"Invalid or missing policy (p={policy or '?'})"
        if pct != "100" and policy in ("reject", "quarantine"):
            status = "MISCONFIGURED"
            notes.append(f"pct={pct}: policy only applied to {pct}% of mail")
        if tags.get("sp", "").lower() == "none" and policy in ("reject", "quarantine"):
            notes.append("sp=none leaves subdomains unprotected")
        if notes:
            detail += " (" + "; ".join(notes) + ")"
        return {"status": status, "record": record, "policy": policy or None, "detail": detail, "tags": tags}

    def _dkim(self, domain: str, resolver) -> list[dict]:
        found = []
        for sel in DKIM_SELECTORS:
            if self.cancelled:
                break
            name = f"{sel}._domainkey.{domain}"
            try:
                txt, _, _ = dns_query(name, "TXT", resolver)
                if not txt:
                    cname, _, _ = dns_query(name, "CNAME", resolver)
                    if cname:
                        found.append({"selector": sel, "record": f"CNAME -> {cname[0]}"})
                    continue
            except ReconError:
                continue
            for t in txt:
                if "p=" in t or "k=" in t or "v=dkim1" in t.lower():
                    revoked = re.search(r"\bp=\s*(;|$)", t) is not None
                    found.append({"selector": sel, "record": (t[:70] + "...") if len(t) > 70 else t,
                                  "revoked": revoked})
                    break
        return found

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        domain = normalize_domain(self.get("DOMAIN"))
        resolver = make_resolver(timeout=3.0, lifetime=6.0)
        result: dict = {"domain": domain, "whois": None, "dns_records": [], "email_security": {}, "errors": []}

        # ---------------- WHOIS
        print_section("WHOIS")
        try:
            with console.status(f"[info]Querying WHOIS (via {IANA})...[/info]"):
                info = self._whois(domain)
            result["whois"] = info
            table = make_table(None, ["Field", ("Value", {"overflow": "fold"})])
            org = info.get("registrant_org")
            if org and REDACTED.search(org):
                org_cell = Text(f"{org} (redacted / privacy-protected)", style="muted")
            else:
                org_cell = Text(org or "Not disclosed", style="" if org else "muted")
            expiry = _parse_date(info.get("expiry_date"))
            expiry_cell = Text(info.get("expiry_date") or "Unknown")
            if expiry:
                days = (expiry - datetime.now(timezone.utc)).days
                info["days_until_expiry"] = days
                style = "critical" if days < 30 else "warning" if days < 90 else "pass"
                expiry_cell.append(f"  ({days} days left)", style=style)
            created = _parse_date(info.get("creation_date"))
            created_cell = Text(info.get("creation_date") or "Unknown")
            if created:
                age = (datetime.now(timezone.utc) - created).days
                info["domain_age_days"] = age
                created_cell.append(f"  ({age // 365}y {age % 365}d old)", style="muted")
                if age < 90:
                    created_cell.append("  newly registered", style="warning")
            add_row(table, "WHOIS servers", " -> ".join([IANA] + info["servers"]))
            add_row(table, "Registrar", info.get("registrar") or "Unknown")
            add_row(table, "Creation date", created_cell)
            add_row(table, "Expiry date", expiry_cell)
            if info.get("updated_date"):
                add_row(table, "Updated date", info["updated_date"])
            add_row(table, "Registrant org", org_cell)
            if info.get("registrant_country"):
                add_row(table, "Registrant country", info["registrant_country"])
            add_row(table, "Name servers", "\n".join(info["name_servers"]) or "-")
            add_row(table, "Status", "\n".join(info["status"]) or "-")
            if info.get("dnssec"):
                add_row(table, "DNSSEC", status_text("PASS") if "signed" in info["dnssec"].lower()
                        and "unsigned" not in info["dnssec"].lower() else Text(info["dnssec"], style="warning"))
            console.print(table)
        except ReconError as exc:
            result["errors"].append(str(exc))
            print_error(str(exc))

        if self.cancelled:
            return result

        # ---------------- DNS records
        print_section("DNS Records")
        records: dict[str, list[str]] = {}
        dns_table = make_table(None, ["Type", ("Value", {"overflow": "fold"}), ("TTL", {"justify": "right"})])
        with console.status("[info]Querying DNS records...[/info]"):
            for rtype in RECORD_TYPES:
                try:
                    values, ttl, _ = dns_query(domain, rtype, resolver)
                except ReconError as exc:
                    result["errors"].append(str(exc))
                    values, ttl = [], None
                records[rtype] = values
                for v in sorted(values):
                    result["dns_records"].append({"type": rtype, "value": v, "ttl": ttl})
                    add_row(dns_table, Text(rtype, style="info"), v, ttl if ttl is not None else "-")
        if result["dns_records"]:
            console.print(dns_table)
        else:
            print_warn("No DNS records returned")
        missing = [t for t in ("A", "MX", "NS", "TXT") if not records.get(t)]
        if missing:
            print_info(f"No records of type: {', '.join(missing)}")

        # ---------------- Email security
        print_section("Email Security")
        if not records.get("NS") and not records.get("SOA"):
            print_warn(f"{domain} has no NS/SOA records (unregistered, not a zone apex, or DNS is "
                       "unreachable); email posture cannot be assessed")
            result["email_security"] = {"posture": "UNKNOWN"}
            return result
        try:
            dmarc_txt, _, _ = dns_query(f"_dmarc.{domain}", "TXT", resolver)
        except ReconError as exc:
            dmarc_txt = []
            result["errors"].append(str(exc))
        spf = self._spf(records.get("TXT", []))
        dmarc = self._dmarc(dmarc_txt)
        with console.status("[info]Probing common DKIM selectors...[/info]"):
            dkim = self._dkim(domain, resolver)
        dkim_status = "PRESENT" if dkim else "WARN"
        dkim_detail = (f"Found selector(s): {', '.join(d['selector'] for d in dkim)}" if dkim else
                       f"None of {len(DKIM_SELECTORS)} common selectors found (custom selectors may exist)")

        email_table = make_table(None, ["Check", "Status", "Details", ("Record", {"overflow": "fold", "max_width": 60})])
        add_row(email_table, "SPF", status_text(spf["status"]), spf["detail"], Text(spf["record"] or "-", style="muted"))
        add_row(email_table, "DMARC", status_text(dmarc["status"]), dmarc["detail"], Text(dmarc["record"] or "-", style="muted"))
        add_row(email_table, "DKIM", status_text(dkim_status), dkim_detail,
                Text("\n".join(f"{d['selector']}: {d['record']}" for d in dkim) or "-", style="muted"))
        console.print(email_table)

        has_mx = bool(records.get("MX"))
        spf_ok = spf["status"] == "PRESENT"
        dmarc_enforced = dmarc["status"] == "PRESENT"
        if spf_ok and dmarc_enforced:
            posture = "PROTECTED"
            print_good(f"Email posture: SPF + DMARC enforced (p={dmarc['policy']}). Spoofing is mitigated.")
        elif spf["status"] == "MISSING" and dmarc["status"] == "MISSING":
            posture = "VULNERABLE"
            print_critical("Email posture: no SPF and no DMARC. The domain can be trivially spoofed.")
        else:
            posture = "PARTIAL"
            problems = []
            if not spf_ok:
                problems.append(f"SPF {spf['status'].lower()}")
            if not dmarc_enforced:
                problems.append(f"DMARC {dmarc['status'].lower()}" + (" (p=none)" if dmarc.get("policy") == "none" else ""))
            print_warn(f"Email posture: partially protected ({', '.join(problems)}). Spoofing may succeed.")
        if not has_mx:
            print_info("No MX records: if the domain never sends mail, publish 'v=spf1 -all' and "
                       "'v=DMARC1; p=reject' to prevent it being spoofed.")

        result["email_security"] = {"posture": posture, "has_mx": has_mx, "spf": spf, "dmarc": dmarc,
                                    "dkim": {"status": dkim_status, "selectors": dkim}}
        return result
