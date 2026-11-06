"""portscan: threaded TCP connect scanner with banner grabbing."""
from __future__ import annotations

import errno
import re
import socket
import ssl
import threading
import time

from rich.text import Text

from core.base_module import BaseModule, OptionError
from core.output import add_row, console, make_table, print_good, print_info, print_section, print_warn
from core.utils import USER_AGENT, ReconError, resolve_target, run_concurrent

SERVICES = {
    7: "Echo", 20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    79: "Finger", 80: "HTTP", 81: "HTTP-Alt", 88: "Kerberos", 106: "POP3PW", 110: "POP3",
    111: "RPCbind", 113: "Ident", 119: "NNTP", 135: "MSRPC", 139: "NetBIOS-SSN", 143: "IMAP",
    179: "BGP", 199: "SMUX", 389: "LDAP", 427: "SLP", 443: "HTTPS", 444: "SNPP", 445: "SMB",
    465: "SMTPS", 513: "rlogin", 514: "rsh", 515: "LPD", 543: "klogin", 544: "kshell",
    548: "AFP", 554: "RTSP", 587: "SMTP-Submission", 631: "IPP", 636: "LDAPS", 873: "rsync",
    902: "VMware", 990: "FTPS", 993: "IMAPS", 995: "POP3S", 1025: "MS-RPC", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2121: "FTP-Alt", 2181: "ZooKeeper", 2375: "Docker",
    2376: "Docker-TLS", 3000: "HTTP-Dev", 3128: "Squid", 3268: "LDAP-GC", 3306: "MySQL",
    3389: "RDP", 4443: "HTTPS-Alt", 4848: "GlassFish", 5000: "HTTP-Dev/UPnP", 5060: "SIP",
    5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP", 5800: "VNC-HTTP", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM-HTTPS", 6000: "X11", 6379: "Redis", 6443: "Kubernetes-API",
    7001: "WebLogic", 7070: "RealServer", 8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP13",
    8080: "HTTP-Alt", 8081: "HTTP-Alt", 8088: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt/PHP-FPM", 9090: "HTTP-Alt/Prometheus", 9100: "JetDirect", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 9418: "Git", 9999: "HTTP-Alt", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB", 49152: "MS-RPC-Dynamic",
    5044: "Logstash", 8086: "InfluxDB", 15672: "RabbitMQ-Mgmt", 50000: "SAP/Jenkins-Agent",
    6667: "IRC", 1900: "UPnP", 2222: "SSH-Alt", 3690: "SVN", 5222: "XMPP", 5555: "ADB",
    8161: "ActiveMQ", 8500: "Consul", 8889: "HTTP-Alt", 10250: "Kubelet", 2380: "etcd", 2379: "etcd",
}

# Curated list of the 100 ports most commonly found open on internet-facing and internal hosts
TOP_100 = [
    7, 21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143, 179, 199, 389,
    427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 873, 990, 993,
    995, 1025, 1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2121, 2181, 2375, 2376, 3000,
    3128, 3268, 3306, 3389, 4443, 4848, 5000, 5060, 5432, 5601, 5672, 5800, 5900, 5985, 5986,
    6000, 6379, 6443, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9090,
    9100, 9200, 9300, 9418, 9999, 10000, 11211, 27017, 49152, 902, 1194, 2222, 5222, 6667,
    8086, 8500, 10250,
]
assert len(TOP_100) == 100 and len(set(TOP_100)) == 100

_EXTRA_COMMON = [
    1900, 2379, 2380, 3690, 5044, 5555, 8161, 8889, 15672, 27018, 50000, 1099, 1434, 1830,
    2000, 2001, 2100, 2483, 2484, 3001, 3260, 3333, 3851, 4000, 4369, 4444, 4567, 4711, 4712,
    4786, 4899, 5001, 5005, 5009, 5050, 5051, 5357, 5431, 5555, 5601, 5631, 5666, 5671, 5938,
    6001, 6080, 6082, 6346, 6347, 6514, 6588, 6660, 6664, 6665, 6666, 6668, 6669, 6697, 7000,
    7002, 7077, 7443, 7474, 7547, 7777, 7778, 8001, 8002, 8010, 8020, 8042, 8060, 8069, 8083,
    8084, 8085, 8087, 8089, 8090, 8091, 8095, 8098, 8099, 8123, 8139, 8172, 8180, 8181, 8200,
    8222, 8280, 8281, 8300, 8333, 8400, 8401, 8402, 8444, 8445, 8480, 8530, 8531, 8545, 8649,
    8686, 8800, 8834, 8880, 8899, 8983, 9001, 9002, 9003, 9009, 9042, 9043, 9050, 9051, 9060,
    9080, 9091, 9092, 9093, 9094, 9095, 9097, 9098, 9099, 9160, 9191, 9443, 9444, 9500, 9600,
    9800, 9876, 9898, 9943, 9944, 9981, 9990, 9998, 10001, 10050, 10051, 10255, 10443, 11000,
    12000, 12345, 13000, 16010, 16992, 16993, 18080, 18081, 19000, 20000, 25565, 28017, 30000,
    31337, 32400, 32768, 33060, 37777, 44818, 47001, 49153, 49154, 49155, 49156, 49157, 50070,
    50075, 54321, 55555, 60000, 61613, 61616, 62078,
]


def _build_top_1000() -> list[int]:
    """TOP_100 + well-known high ports, padded with the lowest privileged ports up to 1000."""
    ports = list(dict.fromkeys(TOP_100 + sorted(set(_EXTRA_COMMON))))
    candidate = 1
    while len(ports) < 1000:
        if candidate not in ports:
            ports.append(candidate)
        candidate += 1
    return sorted(ports[:1000])


TOP_1000 = _build_top_1000()

HTTP_PORTS = {80, 81, 591, 3000, 5000, 7001, 7070, 8000, 8008, 8080, 8081, 8088, 8086, 8500,
              8888, 8889, 9000, 9090, 9200, 10000, 2375, 4848, 5601, 15672, 10250}
TLS_PORTS = {443, 444, 4443, 6443, 8443, 9443, 2376, 5986, 10443}
TLS_WRAPPED = {465: "SMTPS", 636: "LDAPS", 990: "FTPS", 993: "IMAPS", 995: "POP3S"}


def parse_ports(spec: str) -> list[int]:
    spec = str(spec).strip().lower()
    if spec == "top100":
        return sorted(TOP_100)
    if spec == "top1000":
        return TOP_1000
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if part in ("top100", "top1000"):
            ports.update(parse_ports(part))
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        try:
            if m:
                lo, hi = int(m.group(1)), int(m.group(2))
                if lo > hi:
                    lo, hi = hi, lo
                if lo < 1 or hi > 65535:
                    raise ValueError
                ports.update(range(lo, hi + 1))
            else:
                p = int(part)
                if not 1 <= p <= 65535:
                    raise ValueError
                ports.add(p)
        except ValueError:
            raise OptionError(f"Invalid port specification '{part}' (ports must be 1-65535)") from None
    if not ports:
        raise OptionError("No ports specified")
    return sorted(ports)


def _clean(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    text = re.sub(r"[^\x20-\x7e]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _summarize_http(data: bytes) -> str:
    text = data.decode("latin-1", "replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    status = lines[0].strip() if lines else ""
    server = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("server:")), "")
    return f"{status} | Server: {server}" if server else status


class Module(BaseModule):
    name = "portscan"
    description = "Threaded TCP connect port scanner with service mapping and banner grabbing"

    def __init__(self) -> None:
        super().__init__()
        self.add_option("TARGET", None, True, "IP address or hostname")
        self.add_option("PORTS", "top100", False, "top100, top1000, all, 1-1024, or 80,443,8080")
        self.add_option("THREADS", 50, False, "Concurrent connections", type="int", minimum=1)
        self.add_option("TIMEOUT", 1.5, False, "Per-port connect timeout (seconds)", type="float", minimum=0.1)

    def set_option(self, name, raw):
        value = super().set_option(name, raw)
        if name.upper() == "PORTS":
            parse_ports(value)  # validate early
        return value

    # ------------------------------------------------------------------ scanning
    def _connect(self, port: int) -> socket.socket | None | str:
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            err = sock.connect_ex((self.ip, port))
        except (socket.timeout, OSError):
            sock.close()
            return "filtered"
        if err == 0:
            return sock
        sock.close()
        return "closed" if err == errno.ECONNREFUSED else "filtered"

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        read_timeout = min(2.0, max(0.5, self.timeout))
        try:
            if port in TLS_PORTS:
                return self._tls_http_banner(sock, port, read_timeout)
            if port in TLS_WRAPPED:
                return self._tls_passive_banner(sock, read_timeout)
            sock.settimeout(read_timeout)
            if port in HTTP_PORTS:
                return self._http_banner(sock)
            try:
                data = sock.recv(1024)  # server-speaks-first protocols (SSH, FTP, SMTP, ...)
            except socket.timeout:
                data = b""
            if data:
                return _clean(data)
            # Nothing volunteered: nudge with an HTTP request (catches HTTP on odd ports)
            return self._http_banner(sock)
        except (OSError, ssl.SSLError):
            return ""
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _http_banner(self, sock: socket.socket) -> str:
        req = f"HEAD / HTTP/1.0\r\nHost: {self.host}\r\nUser-Agent: {USER_AGENT}\r\n\r\n"
        sock.sendall(req.encode())
        data = sock.recv(2048)
        if data.startswith(b"HTTP/"):
            return _summarize_http(data)
        return _clean(data)

    @staticmethod
    def _tls_context() -> ssl.SSLContext:
        # Banner grabbing only: certificate validation is intentionally not performed here
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _tls_http_banner(self, sock, port, read_timeout) -> str:
        sock.settimeout(read_timeout + 1)
        server_name = self.host if not re.fullmatch(r"[\d.:]+", self.host) else None
        with self._tls_context().wrap_socket(sock, server_hostname=server_name) as tls:
            version = tls.version() or "TLS"
            banner = self._http_banner(tls)
            return f"[{version}] {banner}".strip()

    def _tls_passive_banner(self, sock, read_timeout) -> str:
        sock.settimeout(read_timeout + 1)
        with self._tls_context().wrap_socket(sock) as tls:
            try:
                data = tls.recv(1024)
            except socket.timeout:
                data = b""
            return f"[{tls.version()}] {_clean(data)}".strip()

    def _scan(self, port: int):
        if self.cancelled:
            return None
        result = self._connect(port)
        with self._lock:
            self.counts[result if isinstance(result, str) else "open"] += 1
        if isinstance(result, str):
            return None
        banner = self._grab_banner(result, port)
        return banner

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        self.host = str(self.get("TARGET")).strip()
        if "://" in self.host:
            from urllib.parse import urlparse
            self.host = urlparse(self.host).hostname or self.host
        ports = parse_ports(self.get("PORTS"))
        self.timeout = float(self.get("TIMEOUT"))
        threads = min(int(self.get("THREADS")), len(ports))
        addrs = resolve_target(self.host)
        self.family, self.ip = addrs[0]
        self.counts = {"open": 0, "closed": 0, "filtered": 0}
        self._lock = threading.Lock()

        print_info(f"Target: {self.host} ({self.ip})  |  {len(ports)} port(s)  |  "
                   f"threads: {threads}  |  timeout: {self.timeout}s")
        if len(ports) > 10000:
            print_warn("Full-range scans can take a long time; press Ctrl+C to cancel")

        start = time.monotonic()
        hits = run_concurrent(self._scan, ports, threads, f"Scanning {self.ip}", self.stop_event)
        duration = time.monotonic() - start

        open_ports = []
        for port, banner in sorted(hits):
            service = SERVICES.get(port, "unknown")
            if port in TLS_WRAPPED and service == "unknown":
                service = TLS_WRAPPED[port]
            banner = banner[:80] + ("..." if len(banner) > 80 else "")
            open_ports.append({"port": port, "state": "open", "service": service, "banner": banner})

        print_section(f"Open Ports on {self.host}")
        if open_ports:
            table = make_table(None, [("Port", {"justify": "right"}), "State", "Service",
                                      ("Banner", {"overflow": "fold", "max_width": 80})])
            for p in open_ports:
                add_row(table, f"{p['port']}/tcp", Text("open", style="pass"), p["service"],
                        Text(p["banner"] or "-", style="" if p["banner"] else "muted"))
            console.print(table)
        else:
            print_warn("No open ports found")

        # Open ports with empty banners were still counted as open
        open_count = len(open_ports)
        print_section("Summary")
        print_good(f"Open: {open_count}")
        print_info(f"Closed: {self.counts['closed']}  |  Filtered (no response): {self.counts['filtered']}")
        print_info(f"Scan duration: {duration:.2f}s")

        risky = [p for p in open_ports if p["port"] in (23, 445, 2375, 3389, 5900, 6379, 9200, 11211, 27017, 10250)]
        for p in risky:
            print_warn(f"Port {p['port']} ({p['service']}) is commonly targeted; verify it should be exposed")

        return {
            "target": self.host,
            "ip": self.ip,
            "ports_scanned": len(ports),
            "summary": {"open": open_count, "closed": self.counts["closed"],
                        "filtered": self.counts["filtered"], "duration_seconds": round(duration, 2)},
            "open_ports": open_ports,
        }
