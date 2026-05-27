# crAPI OWASP Attack Simulator

Python script that runs all [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) attacks against a [crAPI](https://github.com/OWASP/crAPI) instance.

## Requirements

- Python 3.8+
- A running crAPI instance

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install requests
```

## Usage

```bash
# Run all attacks
.venv/bin/python crapi_owasp.py --url http://localhost:8888 --attack all

# Run a single attack
.venv/bin/python crapi_owasp.py --url http://localhost:8888 --attack api7

# Run multiple attacks
.venv/bin/python crapi_owasp.py --url http://localhost:8888 --attack api1,api3,api5

# List available attacks
.venv/bin/python crapi_owasp.py --list

# Clear saved session (create fresh test users on next run)
.venv/bin/python crapi_owasp.py --reset
```

## Attacks

| ID    | OWASP Category                              | What it tests |
|-------|---------------------------------------------|---------------|
| api1  | Broken Object Level Authorization (BOLA)   | Mechanic report & order enumeration by ID |
| api2  | Broken Authentication                       | JWT `none` algorithm, OTP brute force, weak passwords |
| api3  | Broken Object Property Level Authorization | Mass assignment, excessive data exposure |
| api4  | Unrestricted Resource Consumption           | Rate limiting, unbounded pagination |
| api5  | Broken Function Level Authorization (BFLA) | Admin endpoint access as regular user |
| api6  | Unrestricted Access to Sensitive Business Flows | Coupon reuse, negative quantity orders |
| api7  | Server Side Request Forgery (SSRF)          | Internal URL injection via mechanic API field |
| api8  | Security Misconfiguration                   | Swagger exposure, CORS, default credentials, stack traces |
| api9  | Improper Inventory Management               | Legacy `/v1/` endpoints, undocumented endpoints |
| api10 | Unsafe Consumption of APIs                  | SQLi / SSTI via third-party mechanic API |

## Output

- `[VULNERABLE]` — attack succeeded
- `[NOT VULN]`   — control in place
- `[INFO]`       — informational finding

## Session persistence

On first run the script registers two test accounts (attacker + victim) and saves them to `.crapi_session.json`. Subsequent runs reuse the same identities so attacker-owned data (vehicles, orders, reports) accumulates across sessions. Run `--reset` to start fresh.

> **Note:** `.crapi_session.json` contains credentials — do not commit it.
