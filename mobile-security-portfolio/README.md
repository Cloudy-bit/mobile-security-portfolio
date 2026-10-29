# Ashish Vasava — Mobile & Application Security Portfolio

A collection of four Python-based defensive security tools for static Android configuration review and safe, authorized API assessment. Each project includes source code, tests, sample inputs, and a project-specific README.

## Projects

### [Android Security Analysis Lab](./android-security-analysis-lab/README.md)

Static APK/manifest-focused analysis, permission review, optional Androguard support, and JSON/Markdown reports. Tests: 4 passed.

### [Android Component & Deep-Link Security Auditor](./android-component-deeplink-auditor/README.md)

Reviews exported components, intent filters, deep-link schemes/hosts/paths, and autoVerify settings. Flags review items, not proof of exploitability. Tests: 4 passed.

### [Mobile API Security Testing Framework](./mobile-api-security-testing-framework/README.md)

Offline endpoint-definition checks plus limited authorized GET/HEAD response-header checks; no fuzzing or response-body collection, and report values are redacted. Tests: 5 passed.

### [Android Network & TLS Security Analyzer](./android-network-tls-security-analyzer/README.md)

Static review of plain-XML manifest/network-security configuration for cleartext policy, trust anchors, debug overrides, and pin-set configuration. Not a live TLS tester. Tests: 5 passed.

## Validation

The project test suites were run from the packaged source archives on 29 October 2026:

| Project | Tests |
|---|---:|
| Android Security Analysis Lab | 4 passed |
| Android Component & Deep-Link Security Auditor | 4 passed |
| Mobile API Security Testing Framework | 5 passed |
| Android Network & TLS Security Analyzer | 5 passed |
| **Total** | **18 passed** |

## Safety and scope

- Use these tools only with APKs, applications, and API endpoints you own or have explicit permission to assess.
- Static configuration findings are indicators for review, not automatic proof of a vulnerability.
- The API framework limits active checks to GET/HEAD and response headers; it does not fuzz, brute-force, or read response bodies.
- The Network & TLS Analyzer parses plain XML configuration. It does not perform live TLS handshakes or runtime certificate-pinning tests.

## Quick start (Windows PowerShell)

Open the folder for the tool you want to run, then follow that project's README. Typical setup is:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
```

Some projects offer an optional `apk` extra; check the individual README for the exact install command and CLI usage.

## Repository contents

- `android-security-analysis-lab/`
- `android-component-deeplink-auditor/`
- `mobile-api-security-testing-framework/`
- `android-network-tls-security-analyzer/`

## Not included

The separately mentioned malware-analysis lab was not provided for review, and the proposed Mobile Security Findings & Reporting Platform has not been built as part of this bundle. Neither is represented as a completed project here.
