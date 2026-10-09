# Posture Management Findings - OWASP Mapping

This document maps the 168 Posture Management findings to OWASP API Security Top 10 (2023) categories and shows which traffic patterns trigger them.

## Summary by OWASP Category

| OWASP Category | # Findings | Attack Function |
|----------------|-----------|-----------------|
| API2:2023 - Broken Authentication | 41 | `posture_api2()` |
| API3:2023 - Broken Object Property Level Authorization | 87 | `posture_api3()` |
| API4:2023 - Unrestricted Resource Consumption | 11 | `posture_api4()` |
| API5:2023 - Broken Function Level Authorization | 13 | `posture_api5()` |
| API6:2023 - Unrestricted Access to Sensitive Business Flows | 4 | `posture_api6()` |
| API8:2023 - Security Misconfiguration | 89 | `posture_api8()` |
| API9:2023 - Improper Inventory Management | 3 | `posture_api9()` |
| API10:2023 - Unsafe Consumption of APIs | 2 | `posture_api10()` |

**Note:** API1 (BOLA) and API7 (SSRF) are exploitation-focused and don't have posture-detection equivalents in this dataset.

---

## API2:2023 - Broken Authentication (41 findings)

### Traffic Patterns Generated:
1. **Expired JWT tokens** - Send JWTs with `exp` claim in the past
2. **Unsigned JWT tokens** - Send JWTs with `alg: none`
3. **Long-lived JWT tokens** - Send JWTs with 100-year expiration
4. **Basic Authentication** - Send `Authorization: Basic ...` headers
5. **Credentials in URLs** - Send tokens/passwords in query params and path params
6. **Credential Spraying** - Same email, multiple passwords
7. **Credential Stuffing** - Common username:password combinations
8. **Auth Bypass attempts** - Special headers like `X-Original-URL`, `X-Forwarded-For`

### Key Findings Triggered:
- API Accepts Expired JWT Token
- API Accepts Unsigned JWT Tokens in Authentication Mechanism
- API Accepts JWT Token With Excessively Long Lifespan
- Host Allows Basic Authentication Method
- API Exposes Authentication Details in Path/Query Parameters
- API Permits Credentials Spraying
- API Permits Credentials Stuffing
- API Vulnerable to Authentication Bypass

---

## API3:2023 - Broken Object Property Level Authorization (87 findings)

### Traffic Patterns Generated:
1. **Unauthenticated requests** - Try accessing endpoints without tokens
2. **Malformed requests** - Send broken JSON, invalid types to trigger stack traces
3. **Error triggering** - Invalid IDs, missing parameters to expose error details
4. **Cross-user access** - Try accessing user2's data with user1's token
5. **Old API versions** - Request `/api/v1/...` endpoints
6. **Sensitive field requests** - Look for SSN, credit cards, passwords in responses

### Traffic Patterns Generated:
- Requests without `Authorization` header
- Malformed JSON: `{"broken": json`
- Invalid type conversions: string where number expected
- SQL injection to trigger errors: `id=1' OR '1'='1`
- Very large numbers: `999999999999`
- Cross-user resource access attempts

### Key Findings Triggered:
- API Exposes Sensitive Data Without Authentication
- API Responds with Internal Server Error Stack Trace
- API Returns Sensitive Data in Error Message
- API Exposes Forbidden Data
- API Exposes Excessive Data In An Older Version
- API Exposes Sensitive Data Using a Shared Authorization

---

## API4:2023 - Unrestricted Resource Consumption (11 findings)

### Traffic Patterns Generated:
1. **SQL Injection patterns** - Common SQLi payloads in query/path/body
2. **Mass email/SMS** - Attempt to send bulk messages via contact forms
3. **HTTP downgrade** - Try HTTP when HTTPS is available

### SQL Injection Payloads:
```
' OR '1'='1
1' UNION SELECT NULL,NULL,NULL--
admin'--
1' AND 1=1--
'; DROP TABLE users--
```

Sent in:
- Query parameters: `?id=<payload>`
- Path parameters: `/orders/<payload>`
- POST body: `{"title": "<payload>"}`

### Key Findings Triggered:
- An API Contains a Direct DB Access
- An Unauthenticated API Contains a Direct DB Access
- Internet-Facing API Allows Sending Phishing Emails
- Application-Load-Balancers Listening on Insecure Port

---

## API5:2023 - Broken Function Level Authorization (13 findings)

### Traffic Patterns Generated:
1. **Unauthenticated POST/PUT/DELETE** - Modifications without auth token
2. **Cross-user modifications** - Modify user2's resources with user1's token
3. **Unauthenticated GraphQL mutations** - POST mutations without auth

### Examples:
```bash
# POST without auth
POST /community/api/v2/community/posts
{"title": "Test", "content": "No auth"}

# PUT without auth  
PUT /identity/api/v2/user/dashboard
{"name": "Attacker"}

# DELETE without auth
DELETE /community/api/v2/community/posts/1

# GraphQL mutation without auth
POST /graphql
{"query": "mutation { updateUser(id: 1, name: \"Attacker\") { id } }"}
```

### Key Findings Triggered:
- API Allows Unauthenticated Modification
- GraphQL API Allows Unauthenticated Modification
- API Allows Modification Using a Shared Authorization

---

## API6:2023 - Unrestricted Access to Sensitive Business Flows (4 findings)

### Traffic Patterns Generated:
Business-logic focused SQL injection:
```sql
' OR 1=1 LIMIT 1000--                                    # Bulk extraction
' UNION SELECT username,password,1 FROM users--          # Credential theft
' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- # Schema discovery
```

### Key Findings Triggered:
- An API Contains a Direct DB Access
- An Unauthenticated Internet-facing API Contains a Direct DB Access

---

## API8:2023 - Security Misconfiguration (89 findings)

### Traffic Patterns Generated:
1. **GraphQL Introspection** - `__schema` queries (authenticated and unauthenticated)
2. **CORS testing** - Various `Origin` headers including `evil.com`, `null`, `*`
3. **Sensitive data in URLs** - Passwords, emails, credit cards in query/path params
4. **Server fingerprinting** - Check for `Server`, `X-Powered-By` headers
5. **Internal FQDN detection** - Look for `.internal`, `.local`, `10.x`, `192.168.x` in responses

### GraphQL Introspection Query:
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name }
      }
    }
  }
}
```

### CORS Test Origins:
```
https://evil.com
http://attacker.com  
null
https://api.example.com.evil.com
```

### Key Findings Triggered:
- API Supports GraphQL Introspection Queries
- GraphQL Endpoint Allows Unauthenticated Introspection Query
- CORS Misconfiguration Enables Unauthorized Access
- API Receives Sensitive Data in Query/Path Params
- Broad Technical Information Exposed on X-Powered-By Header
- API Server Exposes Internal FQDN Name

---

## API9:2023 - Improper Inventory Management (3 findings)

### Traffic Patterns Generated:
1. **Old API versions** - Try `v1`, `v0`, `beta`, `alpha` endpoints
2. **API documentation** - Check for Swagger/OpenAPI docs

### Endpoints Checked:
```
/identity/api/v1/user/dashboard
/workshop/api/v0/shop/orders
/api/docs
/swagger.json
/openapi.json
/api-docs
/redoc
```

### Key Findings Triggered:
- API Exposes Excessive Data In An Older Version
- API Documentation Leakage

---

## API10:2023 - Unsafe Consumption of APIs (2 findings)

### Traffic Patterns Generated:
1. **OAuth Implicit Flow** - Request with `response_type=token`
2. **OAuth ROPC Flow** - POST with `grant_type=password`

### OAuth Implicit Flow:
```http
GET /identity/api/auth/oauth/authorize?
    response_type=token&
    client_id=crapi-client&
    redirect_uri=http://localhost/callback
```

### OAuth ROPC Flow:
```http
POST /identity/api/auth/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user@test.com&password=pass123&client_id=crapi-client
```

### Key Findings Triggered:
- Deprecated OAuth Flow Exposes Authorization Server To Phishing Attacks
- Detected OAuth ROPC Flow Presents Account Takeover Risk

---

## Usage Examples

### Run all posture attacks:
```bash
python crapihacker.py --url https://crapi.example.com --attack posture-all
```

### Run specific OWASP category:
```bash
python crapihacker.py --url https://crapi.example.com --attack posture-api2
```

### Combine exploitation + posture:
```bash
python crapihacker.py --url https://crapi.example.com --attack api1,api2,posture-api2,posture-api3
```

### List all available attacks:
```bash
python crapihacker.py --list
```

---

## Infrastructure-Only Findings (Cannot Generate via Traffic)

Some posture findings are infrastructure-based and require cloud API access or network scanning:

- Azure/AWS resource misconfigurations (50+ findings)
- F5 BIG-IP configurations
- Load balancer settings
- API Management gateway configurations
- Network topology (direct internet access, missing WAF)

These require separate cloud API enumeration scripts, not HTTP traffic generation.

---

## Detection Window

For optimal posture detection, send this traffic over **5-30 minutes** to simulate realistic attack patterns. Instant bulk requests may be rate-limited or appear as testing rather than genuine attacks.

Consider:
- Small delays between requests (`time.sleep(0.1)`)
- Randomized parameter values
- Multiple user sessions
- Varied attack timing
