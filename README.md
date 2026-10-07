# crAPI OWASP Attack Simulator

Python script that runs all [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) attacks against a [crAPI](https://github.com/OWASP/crAPI) instance.

## Requirements

- Python 3.8+
- A running crAPI instance

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install requests PyJWT cryptography
```

**Note:** `PyJWT` and `cryptography` are optional but enable RS256 JWT forgery tests in API2.

## Usage

```bash
# Run all attacks
python crapihacker.py --url http://localhost:8888 --attack all

# Run against remote instance
python crapihacker.py --url https://crapi.aws.doedens.net --attack all

# Run a single attack
python crapihacker.py --url http://localhost:8888 --attack api7

# Run multiple attacks
python crapihacker.py --url http://localhost:8888 --attack api1,api3,api7,injection

# List available attacks
python crapihacker.py --list

# Clear saved session (create fresh test users on next run)
python crapihacker.py --reset
```

**Performance:** Requests timeout after 30 seconds (suitable for remote/slow instances). The script shows verbose progress output for each attack phase.

## Attacks

| ID         | OWASP Category                              | What it tests |
|------------|---------------------------------------------|---------------|
| api1       | Broken Object Level Authorization (BOLA)   | Vehicle location access, mechanic report enumeration by ID |
| api2       | Broken Authentication                       | Expired/forged RS256 JWT, JWT `none` algorithm, OTP brute force, weak passwords |
| api3       | Broken Object Property Level Authorization | Mass assignment (role escalation), excessive data exposure in dashboard/posts |
| api4       | Unrestricted Resource Consumption           | Rate limiting on random vehicle lookups, login brute force (100 attempts) |
| api5       | Broken Function Level Authorization (BFLA) | Admin endpoint access with regular user token, unexpected field injection |
| api6       | Unrestricted Access to Sensitive Business Flows | Coupon reuse, negative quantity orders (credit injection) |
| api7       | Server Side Request Forgery (SSRF)          | Internal localhost:8000, AWS metadata, file:// via mechanic_api field |
| api8       | Security Misconfiguration                   | Exposed API docs, CORS with evil.com, default creds, stack traces, weak JWT secret |
| api9       | Improper Inventory Management               | Legacy `/v1/` endpoints, non-production routes still accessible |
| api10      | Unsafe Consumption of APIs                  | SQLi / XSS / SSTI injection via third-party mechanic API |
| injection  | General Injection Attacks                   | JWT alg:none, SQLi in comments, XSS in comments, path traversal |
| log4j      | CVE-2021-44228 Log4Shell                    | JNDI LDAP/RMI payloads in User-Agent header (RCE) |

## Output

- 🟢 `[VULNERABLE]` — attack succeeded, vulnerability confirmed
- 🔴 `[NOT VULN]`   — control in place, attack blocked
- 🟡 `[INFO]`       — informational finding or test progress
- 🔴 `[ERROR]`      — network error or unexpected failure

The script shows verbose progress output for each attack phase, making it easy to follow during demos.

## Session persistence

On first run the script registers two test accounts (attacker + victim) and saves them to `.crapi_session.json`. Subsequent runs reuse the same identities so attacker-owned data (vehicles, orders, reports) accumulates across sessions. Run `--reset` to start fresh.

> **Note:** `.crapi_session.json` contains credentials — do not commit it.
