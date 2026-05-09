# IDOR/BOLA Quick Reference Cheatsheet

## ID Types and Where to Find Them

| ID Type | Example | Where Found |
|---------|---------|-------------|
| Numeric sequential | 1337, 1338 | URL path, query param, body |
| UUID v1 (time-based) | 550e8400-e29b-11d4-... | API responses |
| UUID v4 (random) | f47ac10b-58cc-4372-... | API responses |
| Base64 encoded | dXNlcl8xMzM3 | Cookie, header, body |
| Hashed (MD5/SHA1) | 5f4dcc3b5aa765... | URL, body |
| Custom slug | user-john-doe | URL path |

## Decode Common ID Formats

```bash
# Base64
echo "dXNlcl8xMzM3" | base64 -d    # → user_1337

# JWT (middle part = payload)
echo "PAYLOAD" | base64 -d

# URL encoded
python3 -c "import urllib.parse; print(urllib.parse.unquote('user%5F1337'))"
```

## HTTP Headers That May Contain User Context

```
Authorization: Bearer TOKEN
Cookie: session=...; user_id=1337
X-User-ID: 1337
X-Account-ID: 5001
X-Client-ID: abc123
```

## Two-Account Testing Matrix

| Test | Account A (attacker) | Account B (victim) | Expected | Test Result |
|------|--------------------|--------------------|----------|-------------|
| Read profile | A's token | B's ID | 403/404 | |
| Update profile | A's token | B's ID | 403 | |
| Delete resource | A's token | B's ID | 403 | |
| Download file | A's token | B's file ID | 403 | |
| View order | A's token | B's order ID | 403 | |

## GraphQL IDOR Patterns

```graphql
# Enumerate via batch query
query {
  u1: user(id: "1") { id email }
  u2: user(id: "2") { id email }
  u3: user(id: "3") { id email }
}

# Access sensitive nested objects
query {
  order(id: "5001") {
    id
    user { email phone address }
    payment { cardNumber cardExpiry }
  }
}
```

## IDOR in API Pagination

```
GET /api/users?page=1&per_page=100     # get all users?
GET /api/logs?start=0&limit=99999      # all audit logs?
GET /api/admin/users?include_deleted=true
```

## Common Vulnerable Endpoints by Function

| Function | Endpoint Pattern |
|---------|----------------|
| Profile | `/users/{id}`, `/account/{id}/settings` |
| Documents | `/files/{id}`, `/documents/{id}/download` |
| Orders | `/orders/{id}`, `/invoices/{id}` |
| Messages | `/messages/{id}`, `/threads/{id}` |
| Admin | `/admin/users/{id}`, `/manage/accounts/{id}` |
| Export | `/export?user={id}`, `/reports/{id}/csv` |
