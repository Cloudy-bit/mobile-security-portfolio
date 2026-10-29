
from __future__ import annotations
import json
import zipfile
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
AUTO = "{http://schemas.android.com/apk/res-auto}"

def attr(node: ET.Element | None, name: str, default: str | None = None) -> str | None:
    return node.attrib.get(f"{ANDROID}{name}", default) if node is not None else default

def bool_attr(value: str | None) -> bool | None:
    if value is None: return None
    value = value.lower().strip()
    if value in {"true", "1"}: return True
    if value in {"false", "0"}: return False
    return None

def _resource_value(value: str | None) -> str | None:
    if value is None: return None
    return value

def parse_manifest(xml_bytes: bytes) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError("Manifest is binary or invalid XML. Install the optional Androguard parser: python -m pip install -e '.[apk]'.") from exc
    if root.tag != "manifest":
        raise ValueError("Manifest XML root must be <manifest>.")
    app = next((n for n in root if n.tag == "application"), None)
    app_permission = attr(app, "permission")
    components = []
    deep_links = []
    tag_types = {"activity", "activity-alias", "service", "receiver", "provider"}
    if app is not None:
        for node in app:
            if node.tag not in tag_types:
                continue
            name = attr(node, "name")
            if not name:
                continue
            filters = []
            for intent in [c for c in node if c.tag == "intent-filter"]:
                actions = [attr(a, "name") for a in intent if a.tag == "action" and attr(a, "name")]
                categories = [attr(c, "name") for c in intent if c.tag == "category" and attr(c, "name")]
                data_nodes = [d for d in intent if d.tag == "data"]
                data_items = []
                for data in data_nodes:
                    item = {key: attr(data, key) for key in
                            ["scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType"]}
                    data_items.append({k: v for k, v in item.items() if v is not None})
                is_web_link = (
                    "android.intent.action.VIEW" in actions
                    and "android.intent.category.BROWSABLE" in categories
                    and any(d.get("scheme") in {"http", "https"} for d in data_items)
                )
                filter_data = {
                    "actions": actions,
                    "categories": categories,
                    "data": data_items,
                    "is_browsable_web_deep_link": is_web_link,
                }
                filters.append(filter_data)
                if is_web_link:
                    for data in data_items:
                        if data.get("scheme") in {"http", "https"}:
                            deep_links.append({
                                "component": name,
                                "component_type": node.tag,
                                "scheme": data.get("scheme"),
                                "host": data.get("host"),
                                "port": data.get("port"),
                                "path": data.get("path"),
                                "path_prefix": data.get("pathPrefix"),
                                "path_pattern": data.get("pathPattern"),
                                "auto_verify": bool_attr(attr(intent, "autoVerify")) is True,
                                "exported": bool_attr(attr(node, "exported")),
                                "permission": attr(node, "permission") or app_permission,
                            })
            components.append({
                "type": node.tag,
                "name": name,
                "exported": bool_attr(attr(node, "exported")),
                "permission": attr(node, "permission") or app_permission,
                "component_permission_explicit": bool_attr(attr(node, "permission")) is not None or bool_attr(app_permission) is not None,
                "intent_filters": filters,
                "intent_filter_count": len(filters),
            })
    return {
        "package": root.attrib.get("package", "unknown"),
        "target_sdk": next((attr(n, "targetSdkVersion") for n in root if n.tag == "uses-sdk"), None),
        "application_permission": app_permission,
        "components": components,
        "deep_links": deep_links,
    }

def read_manifest(apk_path: Path) -> tuple[bytes, str]:
    try:
        with zipfile.ZipFile(apk_path) as zf:
            data = zf.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ValueError("Input is not an APK/ZIP with AndroidManifest.xml.") from exc
    if data.lstrip().startswith((b"<?xml", b"<manifest")):
        return data, "plain-xml"
    try:
        from androguard.core.apk import APK
    except ImportError as exc:
        raise ValueError("Binary AndroidManifest.xml detected. Install optional parser with `python -m pip install -e '.[apk]'`. The APK will not be executed.") from exc
    root = APK(str(apk_path)).get_android_manifest_xml()
    if root is None:
        raise ValueError("Androguard could not decode the manifest.")
    return ET.tostring(root, encoding="utf-8"), "androguard"

def finding(rule_id: str, severity: str, title: str, detail: str, recommendation: str) -> dict[str, str]:
    return {"rule_id": rule_id, "severity": severity, "title": title, "detail": detail, "recommendation": recommendation}

def analyze_components(metadata: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    for comp in metadata["components"]:
        name, typ = comp["name"], comp["type"]
        if comp["exported"] is True:
            sev = "MEDIUM" if typ in {"provider", "service", "receiver"} else "LOW"
            if not comp["component_permission_explicit"]:
                findings.append(finding(
                    "CDSA001", sev, "Exported component has no explicit component/application permission",
                    f"{typ} {name} is exported and this manifest does not declare an app-level or component-level permission. Exported does not automatically mean vulnerable.",
                    "Confirm external access is intended; enforce authorization inside the component and validate incoming intents or URI data."
                ))
            else:
                findings.append(finding(
                    "CDSA002", "INFO", "Exported component declares a permission",
                    f"{typ} {name} is exported and a permission is declared. The tool does not evaluate the permission's protection level.",
                    "Verify the permission's protection level and ensure access controls match the component's intended audience."
                ))
        elif comp["exported"] is None and comp["intent_filter_count"]:
            findings.append(finding(
                "CDSA003", "INFO", "Component has intent filters but no explicit exported value",
                f"{typ} {name} has {comp['intent_filter_count']} intent filter(s), but android:exported is not explicit.",
                "Check effective exported behavior against target SDK and platform requirements; explicitly declare exported where required."
            ))
        for idx, intent in enumerate(comp["intent_filters"], start=1):
            if intent["is_browsable_web_deep_link"]:
                if comp["exported"] is False:
                    findings.append(finding(
                        "CDSA004", "INFO", "Web deep-link filter on non-exported component",
                        f"{typ} {name} has a VIEW + BROWSABLE HTTP(S) filter, but exported is false in the manifest.",
                        "Verify that this configuration matches intended app-link behavior and test only with an authorized app build."
                    ))
                elif not any(d.get("host") for d in intent["data"]):
                    findings.append(finding(
                        "CDSA005", "MEDIUM", "HTTP(S) deep link has no explicit host",
                        f"{typ} {name} has a browsable HTTP(S) intent filter without a host value in the same data declaration.",
                        "Constrain accepted hosts and paths; validate all deep-link parameters before use."
                    ))
                elif not any(d.get("scheme") == "https" for d in intent["data"]):
                    findings.append(finding(
                        "CDSA006", "MEDIUM", "Browsable deep link has no HTTPS scheme in the filter",
                        f"{typ} {name} has a browsable web-link filter but the parsed data entries do not include HTTPS.",
                        "Prefer HTTPS-only links where possible and validate routing behavior."
                    ))
                else:
                    findings.append(finding(
                        "CDSA007", "INFO", "Browsable web deep link requires route validation",
                        f"{typ} {name} accepts browsable web links. This is an entry point, not proof of a vulnerability.",
                        "Validate host/path matching, authentication state, authorization, parameter handling, and safe navigation."
                    ))
    return findings

def analyze_apk(apk_path: str | Path) -> dict[str, Any]:
    path = Path(apk_path)
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    xml, parser = read_manifest(path)
    metadata = parse_manifest(xml)
    findings = analyze_components(metadata)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 99), f["rule_id"], f["title"]))
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return {
        "tool": "Android Component & Deep-Link Security Auditor",
        "version": "1.0.0",
        "input_file": path.name,
        "parser": parser,
        "analysis_type": "static manifest component and deep-link review",
        "execution_performed": False,
        "metadata": metadata,
        "findings": findings,
        "summary": {
            "component_count": len(metadata["components"]),
            "deep_link_count": len(metadata["deep_links"]),
            "finding_count": len(findings),
            "by_severity": {s: sum(f["severity"] == s for f in findings) for s in severities},
        },
        "limitations": [
            "Static manifest review only; the tool does not execute the app or send intents.",
            "An exported component or deep link is not automatically a vulnerability.",
            "This version does not resolve resource references, Android App Links verification state, or all manifest-merging/platform behavior.",
            "Intent-filter data elements can combine across declarations under Android matching rules; this report lists parsed declarations and is not a complete URI matcher.",
            "Only analyze applications you own or are authorized to assess."
        ]
    }

def write_reports(result: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    stem = Path(result["input_file"]).stem
    json_path = out / f"{stem}_component_deeplink_report.json"
    md_path = out / f"{stem}_component_deeplink_report.md"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    md = [
        f"# Component & Deep-Link Audit: {result['input_file']}", "",
        f"- **Tool:** {result['tool']} {result['version']}",
        f"- **Parser:** {result['parser']}",
        "- **APK executed:** No",
        f"- **Analysis:** {result['analysis_type']}", "",
        "## Summary", "",
        f"- Components: {result['summary']['component_count']}",
        f"- Web deep-link declarations: {result['summary']['deep_link_count']}",
        f"- Findings: {result['summary']['finding_count']}", ""
    ]
    md.extend(f"- {s}: {n}" for s, n in result["summary"]["by_severity"].items())
    md += ["", "## Components", ""]
    if not result["metadata"]["components"]:
        md.append("No supported components were parsed.")
    for c in result["metadata"]["components"]:
        md += [f"### {c['type']}: `{c['name']}`", "",
               f"- Exported: `{c['exported']}`",
               f"- Permission: `{c['permission'] or 'none declared'}`",
               f"- Intent filters: {c['intent_filter_count']}", ""]
        for i, f in enumerate(c["intent_filters"], 1):
            md += [f"**Intent filter {i}**", f"- Actions: {', '.join(f['actions']) or 'none'}",
                   f"- Categories: {', '.join(f['categories']) or 'none'}",
                   f"- Data: `{json.dumps(f['data'], ensure_ascii=False)}`",
                   f"- Browsable HTTP(S) deep link: `{f['is_browsable_web_deep_link']}`", ""]
    md += ["## Deep Links", ""]
    if not result["metadata"]["deep_links"]:
        md.append("No VIEW + BROWSABLE HTTP(S) deep-link declaration was identified.")
    for d in result["metadata"]["deep_links"]:
        md.append(f"- `{d['component']}` — scheme `{d['scheme']}`, host `{d['host'] or 'not declared'}`, path `{d['path'] or d['path_prefix'] or d['path_pattern'] or 'not declared'}`, autoVerify `{d['auto_verify']}`")
    md += ["", "## Findings", ""]
    if not result["findings"]:
        md.append("No findings from these rules. This does not establish that the app is secure.")
    for f in result["findings"]:
        md += [f"### [{f['severity']}] {f['rule_id']} — {f['title']}", "", f["detail"], "", f"**Recommendation:** {f['recommendation']}", ""]
    md += ["## Limitations", ""] + [f"- {x}" for x in result["limitations"]]
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    return json_path, md_path
