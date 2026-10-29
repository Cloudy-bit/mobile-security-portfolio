
# Mobile API Security Testing Framework

A defensive Python starter framework for reviewing mobile-app API endpoint definitions and optionally checking a small set of HTTP response headers. It is designed for authorized test environments and does not attempt authentication bypass, fuzzing, brute force, or data modification.

## What it does
- Reads endpoint definitions from a JSON file.
- Offline mode checks URL shape, HTTP vs HTTPS, credentials embedded in URLs, and sensitive-looking query parameter names (values are redacted/not reported).
- Optionally performs only explicitly listed `GET` or `HEAD` requests.
- In active mode, observes a small allowlist of response headers and checks for HSTS and `X-Content-Type-Options`.
- Does not read or store response bodies; does not print cookies or authentication headers.
- Produces JSON and Markdown reports with rule IDs and recommendations.

## Safety and scope
Use active mode only against systems you own or have written authorization to test. The active mode is intentionally limited: no POST/PUT/PATCH/DELETE, no custom authentication, no fuzzing, no brute-force, no login attempts, and no intentional redirect following. This is not a full penetration-testing suite. A URL keyword or missing header is not proof of an exploitable vulnerability. Use test data and a staging/lab API whenever possible.

## Requirements
- Python 3.10+
- pytest for tests
- No third-party runtime dependency is required.

## Windows installation (PowerShell)
```powershell
cd mobile-api-security-testing-framework
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
```

## Configure endpoints
Edit `samples/endpoints.json`. Replace example hostnames with endpoints from your own app or authorized lab. Supported methods are `GET` and `HEAD` only.

Example:
```json
[
  {
    "url": "https://api.your-lab.test/v1/profile",
    "method": "GET",
    "label": "profile endpoint"
  }
]
```

Do not put real tokens, passwords, API keys, or personal data into the endpoint file. Prefer a test environment.

## Run offline URL review (recommended first)
```powershell
.\.venv\Scripts\python.exe -m mobile_api_audit samples/endpoints.json --output reports
```

## Run limited active checks
Only after confirming written authorization:
```powershell
.\.venv\Scripts\python.exe -m mobile_api_audit samples/endpoints.json --active --output reports --delay 1
```
The sample domains use `example.test`, so replace them before active testing. The command will not perform useful checks against the sample host.

## Tests
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Outputs
- `reports/mobile_api_audit.json`
- `reports/mobile_api_audit.md`

## Architecture
```text
JSON endpoint list
   -> schema + method validation
   -> offline URL heuristics
   -> optional limited GET/HEAD request
   -> response-header checks
   -> severity-sorted findings
   -> JSON + Markdown reports
```

## Rule catalog
| Rule | Severity | Meaning |
|---|---|---|
| MAP001 | HIGH | URL is invalid or not absolute HTTP(S) |
| MAP002 | HIGH | Credentials embedded in URL |
| MAP003 | HIGH | Plain HTTP target (unless explicitly suppressed) |
| MAP004 | HIGH | Query parameter name resembles a secret; value is not echoed |
| MAP005 | INFO | Path contains a sensitive-function keyword; heuristic only |
| MAP101 | LOW | HSTS not observed on supplied HTTPS response |
| MAP102 | INFO | `X-Content-Type-Options` not observed |
| MAP103 | INFO | Server returned a 5xx status |

## Technologies
- **Python** for portable automation and rule logic.
- **urllib** for optional, restricted HTTP requests without an extra dependency.
- **JSON** for endpoint input and machine-readable reports.
- **Markdown** for human-readable results.
- **pytest** for regression tests.

## Important limitations
- No endpoint discovery, OpenAPI parsing, authentication handling, API schema validation, IDOR testing, rate-limit testing, business-logic testing, or full TLS assessment.
- Does not validate whether an endpoint is accessible to an attacker.
- Response bodies are intentionally not read.
- Test coverage is a starter baseline; expand it before relying on this in professional engagements.
