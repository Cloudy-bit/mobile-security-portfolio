# Android Network & TLS Security Analyzer

A Python CLI for static review of Android manifest network settings and available plain-XML Network Security Configuration resources. It never executes the APK and does not connect to the network.

## Checks
- `android:usesCleartextTraffic` application attribute.
- `android:networkSecurityConfig` resource reference.
- Plain XML base/domain config cleartext policies.
- User-installed CA trust anchors and debug override references.
- Empty or unparsable pin sets.
- JSON and Markdown reporting with rule IDs, severity, details, and recommendations.

## Important limitations
Many real APKs contain compiled binary XML and compiled resources. This version deliberately reports when it cannot parse them; it does not claim to decode every production APK. It does not perform a live TLS handshake, validate server certificates, inventory cipher suites, or test pinning at runtime. Static indicators are not proof of exploitability or proof that the app is secure. Only assess apps you own or are authorized to test.

## Requirements
Python 3.10+ and pytest for tests. No runtime third-party dependency.

## Windows setup (PowerShell)
```powershell
cd android-network-tls-security-analyzer
py -3 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install --upgrade pip
.\\.venv\\Scripts\\python.exe -m pip install -e ".[test]"
```

## Run
```powershell
.\\.venv\\Scripts\\python.exe -m network_tls_analyzer "C:\\path\\to\\authorized-app.apk" --output reports
```
Reports are written to `reports/<apk>_network_tls_report.json` and `.md`.

## Tests
```powershell
.\\.venv\\Scripts\\python.exe -m pytest -q
```

## Rule catalog
| Rule | Severity | Indicator |
|---|---|---|
| NTSA001 | INFO | Unexpected configuration root |
| NTSA002 | HIGH | Base config explicitly permits cleartext |
| NTSA003 | INFO | Base cleartext policy is not explicit |
| NTSA004 | MEDIUM | Domain config explicitly permits cleartext |
| NTSA005 | MEDIUM | User-installed CA trust is configured |
| NTSA006 | INFO | Debug override trust anchor is referenced |
| NTSA007 | MEDIUM | Pin-set has no parsed pins |
| NTSA008 | HIGH | Manifest explicitly enables cleartext |
| NTSA009 | INFO | Manifest cleartext policy is not explicit |
| NTSA010 | INFO | Network security config resource is referenced |
| NTSA011 | INFO | Referenced resource was not found in plain XML form |

## Architecture
```text
APK ZIP -> AndroidManifest.xml -> extract app network attributes
                         \\-> locate common res/xml config paths
                              -> parse plain XML config
                              -> rule engine
                              -> JSON + Markdown reports
```

## Technologies
- Python for portable static analysis.
- zipfile to read APK contents without running them.
- ElementTree for XML parsing.
- pytest for repeatable tests.
- JSON/Markdown for machine-readable and human-readable results.
