#!/usr/bin/env python3
"""
info_disclosure_helper.py — Information Disclosure Testing Helper

Usage:
    python3 info_disclosure_helper.py git-check https://target.com
    python3 info_disclosure_helper.py backup-wordlist
    python3 info_disclosure_helper.py headers https://target.com
    python3 info_disclosure_helper.py js-secrets ./downloaded/
    python3 info_disclosure_helper.py s3-guess target
    python3 info_disclosure_helper.py dorks target.com
    python3 info_disclosure_helper.py actuator https://target.com
"""
import sys, os, re, subprocess, urllib.request, urllib.error

GIT_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD", "/.git/index", "/.git/packed-refs",
    "/.svn/entries", "/.hg/hgrc", "/.bzr/README",
]

BACKUP_EXTENSIONS = [
    ".bak",".backup",".old",".orig",".copy",".tmp",".swp",".save",
    ".1",".2","~",".zip",".tar.gz",".tar",".gz",".rar",
]

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.json", "/settings.py", "/settings.php",
    "/wp-config.php", "/web.config", "/app.config",
    "/.htpasswd", "/.htaccess",
    "/composer.json", "/package.json", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml",
    "/database.sql", "/backup.sql", "/dump.sql", "/db.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup.zip", "/site.zip", "/www.zip",
]

ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/configprops",
    "/actuator/beans", "/actuator/mappings", "/actuator/heapdump",
    "/actuator/threaddump", "/actuator/loggers", "/actuator/health",
    "/actuator/info", "/actuator/metrics",
]

LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
    "Via", "X-Debug-Token", "X-CF-App-Instance", "X-Drupal-Cache",
    "X-Varnish", "X-Cache", "X-Runtime", "X-Version",
]

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}', 'API Key'),
    (r'[Ss][Ee][Cc][Rr][Ee][Tt]\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}', 'Secret'),
    (r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*["\'][^"\']{8,}', 'Password'),
    (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Key'),
    (r'ghp_[A-Za-z0-9]{36}', 'GitHub Token'),
    (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', 'SendGrid Key'),
    (r'https?://[^"\']*:[^"\'@]*@[^"\']*', 'URL with credentials'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', 'JWT Token'),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),
]

S3_PATTERNS = lambda base: [
    base, f"{base}-dev", f"{base}-prod", f"{base}-staging",
    f"{base}-backup", f"{base}-assets", f"{base}-uploads",
    f"{base}-static", f"{base}-media", f"{base}-logs",
    f"{base}-data", f"{base}-files", f"{base}-exports",
]

def fetch(url, timeout=5):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2000).decode("utf-8","ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}

def git_check(base_url):
    base_url = base_url.rstrip("/")
    print(f"\n[+] Git/VCS Exposure Check: {base_url}\n")
    for path in GIT_PATHS:
        status, body, _ = fetch(base_url + path)
        if status == 200:
            preview = body[:80].replace("\n"," ")
            print(f"  [!!!] FOUND {path}  ({status}) → {preview}")
        else:
            print(f"  [ ]  {path}  ({status})")
    print()
    print(f"  If /.git/HEAD found, dump with:")
    print(f"  git-dumper {base_url}/.git/ ./output-repo/\n")

def backup_wordlist():
    targets = ["index","login","config","database","admin","backup","db",
               "users","settings","api","app","main","core","init"]
    print("\n[+] Backup File Wordlist:\n")
    for t in targets:
        for ext in BACKUP_EXTENSIONS:
            print(f"{t}{ext}")
        print(f"{t}.php.bak")
        for ext in [".zip",".tar.gz"]:
            print(f"{t}{ext}")
    print()
    print("  ffuf scan:")
    print("  ffuf -u https://TARGET/FUZZ -w <above list> -mc 200 -fc 404\n")

def headers_check(url):
    print(f"\n[+] Response Headers Analysis: {url}\n")
    status, _, headers = fetch(url)
    print(f"  Status: {status}\n")
    for h in LEAKY_HEADERS:
        val = headers.get(h, headers.get(h.lower(), None))
        if val:
            print(f"  [!] {h}: {val}")
    print()
    print("  Also check all sensitive files:")
    for path in SENSITIVE_FILES[:10]:
        s, body, _ = fetch(url.rstrip("/") + path)
        if s == 200:
            print(f"  [!!!] EXPOSED: {path}")
    print()

def js_secrets(directory):
    print(f"\n[+] Scanning JS files for secrets in: {directory}\n")
    found = 0
    for root, _, files in os.walk(directory):
        for fname in files:
            if fname.endswith(".js") or fname.endswith(".map"):
                fpath = os.path.join(root, fname)
                try:
                    content = open(fpath).read()
                except:
                    continue
                for pattern, label in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for m in matches:
                        print(f"  [!] {label} in {fpath}")
                        print(f"      {m[:120]}")
                        found += 1
    if found == 0:
        print("  No secrets found (or directory empty)")
    print(f"\n  Total findings: {found}\n")

def s3_guess(brand):
    print(f"\n[+] S3 Bucket Guesses for '{brand}':\n")
    for bucket in S3_PATTERNS(brand):
        print(f"  aws s3 ls s3://{bucket} --no-sign-request")
        print(f"  curl -s https://{bucket}.s3.amazonaws.com/ | grep -q ListBucketResult && echo 'OPEN: {bucket}'")
    print()

def dorks(domain):
    print(f"\n[+] Google Dorks for {domain}:\n")
    dork_list = [
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:{domain} "api_key" OR "password" OR "secret"',
        f'site:{domain} inurl:backup OR inurl:admin OR inurl:config',
        f'site:{domain} ext:log OR ext:sql OR ext:bak',
        f'site:{domain} "phpinfo()"',
        f'site:github.com "{domain}" "api_key" OR "password"',
        f'site:pastebin.com "{domain}"',
    ]
    for d in dork_list:
        print(f'  https://www.google.com/search?q={urllib.request.quote(d)}')
    print()

def actuator_check(base_url):
    base_url = base_url.rstrip("/")
    print(f"\n[+] Spring Actuator Endpoint Check: {base_url}\n")
    for path in ACTUATOR_PATHS:
        status, body, _ = fetch(base_url + path)
        if status == 200:
            preview = body[:100].replace("\n"," ")
            print(f"  [!!!] EXPOSED {path} ({status}) → {preview[:80]}")
        else:
            print(f"  [ ]  {path} ({status})")
    print()
    print("  If /actuator/env exposed → look for credentials in output")
    print("  If /actuator/heapdump exposed → download and analyze with Eclipse MAT\n")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "git-check":
        git_check(args[1] if len(args)>1 else "https://target.com")
    elif cmd == "backup-wordlist":
        backup_wordlist()
    elif cmd == "headers":
        headers_check(args[1] if len(args)>1 else "https://target.com")
    elif cmd == "js-secrets":
        js_secrets(args[1] if len(args)>1 else ".")
    elif cmd == "s3-guess":
        s3_guess(args[1] if len(args)>1 else "target")
    elif cmd == "dorks":
        dorks(args[1] if len(args)>1 else "target.com")
    elif cmd == "actuator":
        actuator_check(args[1] if len(args)>1 else "https://target.com")
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
