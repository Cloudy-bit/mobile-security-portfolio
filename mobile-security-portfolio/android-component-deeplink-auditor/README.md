
# Android Component & Deep-Link Security Auditor

A defensive Python CLI that statically reviews an Android APK's manifest for component exposure and browsable HTTP(S) deep-link configuration. It **never executes the APK or sends intents**.

## Features
- Lists activities, activity aliases, services, receivers, and providers.
- Extracts `android:exported`, component/application permission declarations, and intent-filter actions/categories.
- Identifies VIEW + BROWSABLE HTTP(S) deep-link declarations, including parsed scheme/host/path/pathPrefix/pathPattern/port and `autoVerify`.
- Applies review rules and generates JSON and Markdown reports.
- Includes tests using a synthetic manifest fixture.

## Limitations
An exported component or deep link is not automatically a vulnerability. This tool does not execute apps, test runtime behavior, resolve all resource references, confirm Digital Asset Links or App Links verification, or fully implement Android's URI matching rules. Severity indicates review priority only. Only analyze apps you own or are authorized to assess.

## Requirements
- Python 3.10+
- Optional Androguard to decode binary Android XML manifests (common in production APKs)
- pytest for tests

## Windows setup (PowerShell)
```powershell
cd android-component-deeplink-auditor
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[apk,test]"
```
Using the venv Python directly avoids PowerShell activation-policy issues.

## Run
```powershell
.\.venv\Scripts\python.exe -m component_auditor "C:\path\to\authorized-app.apk" --output reports
```
Creates:
- `reports/<apk-name>_component_deeplink_report.json`
- `reports/<apk-name>_component_deeplink_report.md`

Print JSON to terminal:
```powershell
.\.venv\Scripts\python.exe -m component_auditor "C:\path\to\authorized-app.apk" --json-only
```

## Test
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Architecture
```text
APK (ZIP)
  -> AndroidManifest.xml
  -> plain XML parser OR optional Androguard for binary XML
  -> normalized components + intent filters + data declarations
  -> rule engine (CDSA001-CDSA007)
  -> JSON report + Markdown report
```

## Technologies and why
- **Python:** simple, testable automation and report generation.
- **zipfile:** APK is a ZIP container; manifest can be read without running the app.
- **ElementTree:** parses decoded XML using Python's standard library.
- **Androguard:** optional decoder for binary Android XML.
- **pytest:** repeatable unit tests.
- **JSON:** machine-readable findings.
- **Markdown:** readable audit report suitable for code review and GitHub.

## Rules
| Rule | Severity | Indicator |
|---|---|---|
| CDSA001 | MEDIUM/LOW | Exported component has no explicit component/application permission |
| CDSA002 | INFO | Exported component declares a permission; protection level not evaluated |
| CDSA003 | INFO | Intent filter exists but exported value is not explicit |
| CDSA004 | INFO | HTTP(S) browsable filter on component marked non-exported |
| CDSA005 | MEDIUM | HTTP(S) browsable filter lacks a host in parsed data |
| CDSA006 | MEDIUM | Browsable web filter does not show HTTPS in parsed data |
| CDSA007 | INFO | Browsable web deep link needs route/authorization validation |

These rules identify review areas, not confirmed exploitability. Android can combine multiple `<data>` elements according to platform matching semantics, so always verify the actual manifest and behavior.

## Future improvements
- Parse merged manifests and resource references
- Add a rule suppression/justification file
- Export SARIF
- Add an authorized runtime test module for a dedicated lab app
- Add a report dashboard
