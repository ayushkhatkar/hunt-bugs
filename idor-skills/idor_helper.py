#!/usr/bin/env python3
"""
idor_helper.py — IDOR/BOLA Testing Helper

Usage:
    python3 idor_helper.py fuzz https://target.com/api/users/FUZZ/profile TOKEN 1 10000
    python3 idor_helper.py decode-uuid 550e8400-e29b-11d4-a716-446655440000
    python3 idor_helper.py params
    python3 idor_helper.py accounts
"""
import sys, base64, json, uuid, datetime

COMMON_ID_PARAMS = [
    "id","user_id","uid","account_id","profile_id","order_id","invoice_id",
    "doc_id","file_id","message_id","thread_id","customer_id","org_id",
    "team_id","group_id","session_id","record_id","item_id","product_id",
    "report_id","ticket_id","case_id","employee_id","contact_id","address_id",
]

def fuzz_command(url, token, start, end):
    print(f"\n[+] IDOR ffuf command:\n")
    print(f'ffuf -u "{url}" \\')
    print(f'     -w <(seq {start} {end}) \\')
    print(f'     -H "Authorization: Bearer {token}" \\')
    print(f'     -mc 200 \\')
    print(f'     -fc 404,403 \\')
    print(f'     -t 30 \\')
    print(f'     -o idor_results.json -of json\n')

def decode_uuid(u):
    try:
        obj = uuid.UUID(u)
        print(f"\n[+] UUID Analysis: {u}")
        print(f"  Version : {obj.version}")
        if obj.version == 1:
            ts = (obj.time - 0x01b21dd213814000) / 1e7
            dt = datetime.datetime.fromtimestamp(ts)
            print(f"  Timestamp : {dt} (predictable — UUID v1!)")
            print(f"  Node (MAC): {hex(obj.node)}")
            print(f"  [!] UUID v1 is time-based and predictable!")
        else:
            print(f"  [~] UUID v{obj.version} — not time-based, harder to predict")
        print()
    except ValueError as e:
        print(f"[!] Invalid UUID: {e}")

def show_params():
    print("\n[+] Common ID parameter names to test:\n")
    for p in COMMON_ID_PARAMS:
        print(f"  {p}")
    print()

def show_accounts():
    print("\n[+] IDOR Testing Setup:\n")
    print("  1. Create Account A (attacker)  → note your user_id from any response")
    print("  2. Create Account B (victim)    → note their user_id")
    print("  3. Log in as Account A")
    print("  4. Try accessing Account B's resources with Account A's token")
    print()
    print("  Quick checks:")
    print("  - Try ID=1 (often admin)")
    print("  - Try ID=0 and ID=-1")
    print("  - Try your_id ± 1")
    print("  - Try very large ID (overflow)")
    print()

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)
    cmd = args[0]
    if cmd == "fuzz":
        url = args[1] if len(args) > 1 else "https://target.com/api/users/FUZZ"
        token = args[2] if len(args) > 2 else "YOUR-TOKEN"
        start = args[3] if len(args) > 3 else "1"
        end = args[4] if len(args) > 4 else "10000"
        fuzz_command(url, token, start, end)
    elif cmd == "decode-uuid":
        u = args[1] if len(args) > 1 else "550e8400-e29b-11d4-a716-446655440000"
        decode_uuid(u)
    elif cmd == "params":
        show_params()
    elif cmd == "accounts":
        show_accounts()
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
