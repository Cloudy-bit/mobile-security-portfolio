
from __future__ import annotations
import json
import zipfile
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def _attr(element: ET.Element | None, name: str, default: str | None = None) -> str | None:
    return element.attrib.get(f"{ANDROID_NS}{name}", default) if element is not None else default

def _bool(value: str | None) -> bool | None:
    if value is None: return None
    if value.strip().lower() in {"true", "1"}: return True
    if value.strip().lower() in {"false", "0"}: return False
    return None

def parse_manifest_xml(data: bytes) -> dict[str, Any]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("Manifest is binary or invalid XML. Install the optional Androguard parser: python -m pip install -e '.[apk]'.") from exc
    if root.tag != "manifest":
        raise ValueError("XML root is not <manifest>.")
    permissions = sorted({
        name for node in root
        if node.tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
        if (name := _attr(node, "name"))
    })
    app = next((node for node in root if node.tag == "application"), None)
    app_data = {
        "debuggable": _bool(_attr(app, "debuggable")),
        "allow_backup": _bool(_attr(app, "allowBackup")),
        "uses_cleartext_traffic": _bool(_attr(app, "usesCleartextTraffic")),
        "network_security_config": _attr(app, "networkSecurityConfig"),
    }
    components = []
    if app is not None:
        for node in app:
            if node.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                continue
            name = _attr(node, "name")
            if name:
                components.append({
                    "type": node.tag,
                    "name": name,
                    "exported": _bool(_attr(node, "exported")),
                    "has_intent_filter": any(child.tag == "intent-filter" for child in node),
                    "permission": _attr(node, "permission"),
                })
    return {
        "package": root.attrib.get("package", "unknown"),
        "version_name": _attr(root, "versionName"),
        "version_code": _attr(root, "versionCode"),
        "permissions": permissions,
        "application": app_data,
        "components": components,
    }

def _get_manifest(apk: Path) -> tuple[bytes, str]:
    try:
        with zipfile.ZipFile(apk) as archive:
            data = archive.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ValueError("Not a valid APK/ZIP containing AndroidManifest.xml.") from exc
    if data.lstrip().startswith((b"<?xml", b"<manifest")):
        return data, "plain-xml"
    try:
        from androguard.core.apk import APK
    except ImportError as exc:
        raise ValueError("This APK uses binary Android XML. Install optional parser with `python -m pip install -e '.[apk]'`. APKs are never executed.") from exc
    parsed = APK(str(apk)).get_android_manifest_xml()
    if parsed is None:
        raise ValueError("Androguard could not decode AndroidManifest.xml.")
    return ET.tostring(parsed, encoding="utf-8"), "androguard"

def _finding(rule_id: str, severity: str, title: str, detail: str, recommendation: str) -> dict[str, str]:
    return {"rule_id": rule_id, "severity": severity, "title": title, "detail": detail, "recommendation": recommendation}

SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE",
}

def evaluate_findings(metadata: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    app = metadata.get("application", {})
    if app.get("debuggable") is True:
        findings.append(_finding("ASL001", "HIGH", "Debuggable application", 'Manifest sets android:debuggable="true".', "Disable debugging in release builds and verify the final artifact."))
    elif app.get("debuggable") is None:
        findings.append(_finding("ASL001", "INFO", "Debuggable setting not explicit", "No readable explicit debuggable value was found.", "Confirm the effective release build configuration."))
    if app.get("allow_backup") is True:
        findings.append(_finding("ASL002", "MEDIUM", "Application backup is enabled", "Manifest sets android:allowBackup=\"true\"; actual exposure depends on platform and app configuration.", "Review backup requirements and configure data-extraction rules where appropriate."))
    if app.get("uses_cleartext_traffic") is True:
        findings.append(_finding("ASL003", "HIGH", "Cleartext traffic is allowed", 'Manifest sets android:usesCleartextTraffic="true".', "Prefer HTTPS and disable cleartext traffic unless a documented exception is required."))
    elif app.get("uses_cleartext_traffic") is None:
        findings.append(_finding("ASL003", "INFO", "Cleartext setting not explicit", "No explicit usesCleartextTraffic value was found.", "Determine the effective policy for the target SDK and inspect network security configuration."))
    if app.get("network_security_config"):
        findings.append(_finding("ASL004", "INFO", "Network Security Configuration referenced", f"Manifest references {app['network_security_config']}; resource contents are not parsed by this version.", "Review trust anchors, cleartext exceptions, and debug-only overrides."))
    for component in metadata.get("components", []):
        if component.get("exported") is True:
            sev = "MEDIUM" if component["type"] in {"provider", "service", "receiver"} else "LOW"
            permission = component.get("permission")
            detail = f"{component['type']} {component['name']} is explicitly exported."
            detail += f" Component permission: {permission}." if permission else " No component-level permission is declared in this manifest entry."
            findings.append(_finding("ASL005", sev, "Exported component requires review", detail, "Verify intended exposure, enforce authorization, validate inputs, and test only in an authorized environment."))
        elif component.get("exported") is None and component.get("has_intent_filter"):
            findings.append(_finding("ASL006", "INFO", "Component export behavior needs review", f"{component['type']} {component['name']} has an intent-filter but no explicit exported value.", "Check behavior against the target SDK and Android platform rules."))
    for permission in metadata.get("permissions", []):
        if permission in SENSITIVE_PERMISSIONS:
            findings.append(_finding("ASL007", "INFO", "Sensitive permission declared", f"Manifest requests {permission}; this alone does not prove misuse.", "Confirm necessity and document the user-facing purpose."))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda x: (order.get(x["severity"], 99), x["rule_id"]))

def analyze_apk(apk_path: str | Path) -> dict[str, Any]:
    path = Path(apk_path)
    if not path.is_file():
        raise ValueError(f"APK file does not exist: {path}")
    data, parser = _get_manifest(path)
    metadata = parse_manifest_xml(data)
    findings = evaluate_findings(metadata)
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return {
        "tool": "Android Security Analysis Lab", "tool_version": "1.0.0",
        "input_file": path.name, "manifest_parser": parser,
        "analysis_type": "static manifest configuration review", "execution_performed": False,
        "metadata": metadata, "findings": findings,
        "summary": {"finding_count": len(findings), "by_severity": {s: sum(f["severity"] == s for f in findings) for s in severities}},
        "limitations": [
            "Manifest-focused static review only; not a full security audit.",
            "Permissions and exported components are review indicators, not proof of vulnerabilities.",
            "Network security resources, code paths, runtime behavior, and backend APIs are not fully analyzed.",
            "Only analyze apps you own or are authorized to assess."
        ]
    }

def write_reports(result: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    stem = Path(result["input_file"]).stem
    json_path = out / f"{stem}_security_report.json"
    md_path = out / f"{stem}_security_report.md"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        f"# Android Security Analysis Report: {result['input_file']}", "",
        f"- **Tool:** {result['tool']} {result['tool_version']}",
        f"- **Analysis:** {result['analysis_type']}", f"- **Parser:** {result['manifest_parser']}",
        "- **APK executed:** No", "", "## Summary", "",
        f"Total findings: **{result['summary']['finding_count']}**", ""
    ]
    lines.extend(f"- {s}: {n}" for s, n in result["summary"]["by_severity"].items())
    md = result["metadata"]
    lines += ["", "## Metadata", "", f"- Package: `{md.get('package', 'unknown')}`",
              f"- Version: `{md.get('version_name') or 'not declared'}`",
              f"- Permissions: {len(md.get('permissions', []))}", f"- Components: {len(md.get('components', []))}",
              "", "## Findings", ""]
    if not result["findings"]:
        lines.append("No findings were produced by these rules. This does not mean the app is secure.")
    for f in result["findings"]:
        lines += [f"### [{f['severity']}] {f['rule_id']} — {f['title']}", "", f["detail"], "", f"**Recommendation:** {f['recommendation']}", ""]
    lines += ["## Limitations", ""] + [f"- {x}" for x in result["limitations"]]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path
