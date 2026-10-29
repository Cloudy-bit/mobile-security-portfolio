
# Android Security Analysis Lab

A defensive Python command-line tool for **static Android APK manifest review**. It reads an APK as a ZIP container and inspects `AndroidManifest.xml`. It never executes the APK.

## Checks included
- Package and version metadata
- Declared permissions, with contextual notes for selected sensitive permissions
- `debuggable`, `allowBackup`, and `usesCleartextTraffic`
- Detection of a Network Security Configuration reference (the referenced XML is not yet parsed)
- Activities, activity aliases, services, receivers, and providers
- Explicitly exported components and components with intent filters but no explicit exported value
- JSON and Markdown report generation

## Important limitations
This is a manifest-focused first version, not a full mobile security audit. A permission is not automatically a vulnerability; exported components may be intentional and protected elsewhere. The tool does not analyze decompiled code, runtime behavior, cryptography, embedded secrets, backend APIs, or all Network Security Configuration rules. Findings are review indicators, not proof of exploitability.

Only assess apps you own or have permission to test. Do not upload confidential APKs to third-party services without authorization.

## Requirements
- Python 3.10+
- Optional Androguard parser for binary Android XML
- pytest for automated tests

## Setup (Windows PowerShell)
```powershell
cd android-security-analysis-lab
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[apk,test]"
```
If activation is blocked:
```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[apk,test]"
```

## Run against an authorized APK
```powershell
android-security-lab "C:\path\to\your-app.apk" --output reports
```
Or:
```powershell
python -m android_security_lab "C:\path\to\your-app.apk" --output reports
```
Reports are written to:
- `reports/<apk-name>_security_report.json`
- `reports/<apk-name>_security_report.md`

For JSON output in the terminal:
```powershell
python -m android_security_lab "C:\path\to\your-app.apk" --json-only
```

## Run tests
```powershell
python -m pytest -q
```
Tests generate synthetic APK-shaped ZIP data with a plain XML manifest; this fixture is not a real app scan.

## Architecture
```text
APK -> ZIP reader -> AndroidManifest.xml
                      |
         +------------+-------------+
         |                          |
    plain XML                 binary Android XML
  Python XML parser          optional Androguard
         |                          |
         +------------+-------------+
                      |
             normalized metadata
                      |
                rule engine
                      |
              JSON + Markdown
```

## Why these technologies?
- **Python:** automation, parsing, rules, reports, and testability.
- **zipfile:** APKs are ZIP containers; this reads files without running the app.
- **ElementTree:** standard-library XML parsing.
- **Androguard (optional):** decode binary Android XML used in most production APKs.
- **pytest:** repeatable checks for parser and rule behavior.
- **JSON:** structured output for future integrations.
- **Markdown:** readable report suitable for GitHub.

## Rules
| Rule | Severity | Indicator |
|---|---|---|
| ASL001 | HIGH / INFO | Debuggable true / not explicit |
| ASL002 | MEDIUM | Backup enabled |
| ASL003 | HIGH / INFO | Cleartext allowed / not explicit |
| ASL004 | INFO | Network Security Configuration reference |
| ASL005 | MEDIUM / LOW | Explicitly exported component |
| ASL006 | INFO | Intent-filter without explicit exported value |
| ASL007 | INFO | Selected sensitive permission |

Severity is a triage hint, not a verified exploitability rating.

## Possible next upgrades
- Parse `network_security_config.xml`
- Add configurable rules and suppression justifications
- Export SARIF
- Build a report-import web UI
- Integration tests against a deliberately vulnerable sample app built for this project
