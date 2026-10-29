
from __future__ import annotations
import json, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
NETWORK_SECURITY_NS = "{http://schemas.android.com/apk/res/android}"

def a(node, name, default=None):
    return node.attrib.get(f"{ANDROID}{name}", node.attrib.get(name, default)) if node is not None else default

def as_bool(value):
    if value is None: return None
    v = value.strip().lower()
    if v in {"true", "1"}: return True
    if v in {"false", "0"}: return False
    return None

def extract_zip_file(apk: Path, filename: str) -> bytes | None:
    try:
        with zipfile.ZipFile(apk) as z:
            try: return z.read(filename)
            except KeyError: return None
    except zipfile.BadZipFile as e:
        raise ValueError("Input is not a valid APK/ZIP file.") from e

def parse_xml(data: bytes, label: str):
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"{label} is binary XML or invalid XML. This version parses plain XML fixtures only. For binary APK manifests, use aapt2 or Androguard to decode the file first.") from e

def analyze_network_config(xml: bytes, source_name="network_security_config.xml") -> list[dict]:
    root = parse_xml(xml, source_name)
    findings = []
    if root.tag not in {"network-security-config", "domain-config", "base-config", "debug-overrides"}:
        findings.append({"rule_id":"NTSA001","severity":"INFO","title":"Unrecognized network security config root",
                         "detail":f"Root element is {root.tag!r}.","recommendation":"Confirm this is the intended Android Network Security Configuration file."})
        return findings
    for elem in root.iter():
        if elem.tag == "base-config":
            clear = as_bool(a(elem, "cleartextTrafficPermitted"))
            if clear is True:
                findings.append({"rule_id":"NTSA002","severity":"HIGH","title":"Cleartext traffic explicitly permitted by base-config",
                                 "detail":"The base-config explicitly allows cleartext traffic. This may permit HTTP connections depending on platform and app behavior.",
                                 "recommendation":"Disable cleartext traffic unless a documented requirement exists; prefer HTTPS for all production endpoints."})
            if clear is None:
                findings.append({"rule_id":"NTSA003","severity":"INFO","title":"Base cleartext policy not explicit",
                                 "detail":"No explicit boolean cleartextTrafficPermitted value was parsed on this base-config.",
                                 "recommendation":"Document the intended policy and set an explicit value appropriate for the app's supported Android versions."})
        elif elem.tag == "domain-config":
            clear = as_bool(a(elem, "cleartextTrafficPermitted"))
            domains = [((d.text or "").strip()) for d in elem if d.tag == "domain" and (d.text or "").strip()]
            if clear is True:
                findings.append({"rule_id":"NTSA004","severity":"MEDIUM","title":"Cleartext traffic permitted for domain-config",
                                 "detail":f"Domain configuration permits cleartext for: {', '.join(domains) if domains else '(domain not parsed)'}.",
                                 "recommendation":"Remove the cleartext exception or restrict it to a justified development-only configuration."})
        elif elem.tag == "trust-anchors":
            certs = [c for c in elem if c.tag == "certificates"]
            if any(a(c, "src") == "user" for c in certs):
                findings.append({"rule_id":"NTSA005","severity":"MEDIUM","title":"User-installed certificates trusted",
                                 "detail":"A trust anchor references src=\"user\". This can be intentional for enterprise or debugging use, but expands trust to user-installed CAs.",
                                 "recommendation":"Confirm this is required. Prefer system trust anchors in production unless user CA trust is a documented requirement."})
            if any(a(c, "src") == "debug-overrides" for c in certs):
                findings.append({"rule_id":"NTSA006","severity":"INFO","title":"Debug override trust anchor referenced",
                                 "detail":"A trust anchor references debug-overrides. The practical effect depends on build type and platform behavior.",
                                 "recommendation":"Verify debug trust settings are not unintentionally enabled in release builds."})
        elif elem.tag == "pin-set":
            pins = [p for p in elem if p.tag == "pin" and (p.text or "").strip()]
            if not pins:
                findings.append({"rule_id":"NTSA007","severity":"MEDIUM","title":"Pin set contains no parsed pins",
                                 "detail":"A pin-set element exists but no non-empty pin value was parsed.",
                                 "recommendation":"Validate the pin-set syntax and ensure any pinning design includes a carefully managed backup pin and rotation plan."})
    return findings

def analyze_apk(apk_file: str | Path) -> dict:
    apk = Path(apk_file)
    if not apk.is_file(): raise ValueError(f"File not found: {apk}")
    manifest_bytes = extract_zip_file(apk, "AndroidManifest.xml")
    if manifest_bytes is None: raise ValueError("AndroidManifest.xml not found in APK.")
    manifest = parse_xml(manifest_bytes, "AndroidManifest.xml")
    app = next((n for n in manifest if n.tag == "application"), None)
    uses_sdk = next((n for n in manifest if n.tag == "uses-sdk"), None)
    app_cleartext = as_bool(a(app, "usesCleartextTraffic"))
    target_sdk = a(uses_sdk, "targetSdkVersion")
    network_ref = a(app, "networkSecurityConfig")
    findings = []
    if app_cleartext is True:
        findings.append({"rule_id":"NTSA008","severity":"HIGH","title":"Application manifest permits cleartext traffic",
                         "detail":"android:usesCleartextTraffic is explicitly true in the application manifest.",
                         "recommendation":"Set the policy to false for production unless cleartext is required and appropriately constrained."})
    elif app_cleartext is None:
        findings.append({"rule_id":"NTSA009","severity":"INFO","title":"Application cleartext policy not explicit",
                         "detail":"The manifest does not contain a parsable explicit usesCleartextTraffic value. Effective behavior can depend on target SDK, platform version, and network security config.",
                         "recommendation":"Review effective policy on supported Android versions and explicitly document the production requirement."})
    if network_ref:
        resource_name = network_ref.split("/")[-1]
        findings.append({"rule_id":"NTSA010","severity":"INFO","title":"Network security configuration referenced",
                         "detail":f"Manifest references {network_ref}. The analyzer will try common APK resource paths for {resource_name}.xml.",
                         "recommendation":"Inspect the resolved resource and confirm release builds use the intended configuration."})
        candidate_paths = [f"res/xml/{resource_name}.xml", f"res/xml-v24/{resource_name}.xml"]
        found = None
        for candidate in candidate_paths:
            data = extract_zip_file(apk, candidate)
            if data is not None:
                found = (candidate, data); break
        if found:
            findings.extend(analyze_network_config(found[1], found[0]))
        else:
            findings.append({"rule_id":"NTSA011","severity":"INFO","title":"Referenced network config not parsed",
                             "detail":"No plain-XML network security config was found at the common paths. Compiled Android resources may be binary or stored differently.",
                             "recommendation":"Decode resources with Android build tools or Androguard, then review the effective network security configuration."})
    findings.sort(key=lambda f: ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(f["severity"],99), f["rule_id"]))
    return {
        "tool":"Android Network & TLS Security Analyzer", "version":"1.0.0",
        "input_file":apk.name, "analysis_type":"static manifest and available plain-XML network security config review",
        "execution_performed":False,
        "metadata":{"package":manifest.attrib.get("package","unknown"),"target_sdk":target_sdk,
                    "uses_cleartext_traffic":app_cleartext,"network_security_config":network_ref},
        "findings":findings,
        "summary":{"finding_count":len(findings),
                   "by_severity":{s:sum(f["severity"]==s for f in findings) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}},
        "limitations":[
            "The APK is never executed and no network connection is made.",
            "This version parses plain XML manifest/config fixtures; production APKs commonly use compiled binary Android XML/resources.",
            "It does not conduct a live TLS handshake, certificate validation test, cipher-suite review, or certificate-pinning bypass.",
            "Missing manifest attributes do not prove a secure or insecure effective policy; target SDK and platform behavior matter.",
            "Only analyze APKs you own or are authorized to assess."
        ]
    }

def write_reports(result: dict, output_dir: str | Path):
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True)
    stem=Path(result["input_file"]).stem
    jp=out/f"{stem}_network_tls_report.json"; mp=out/f"{stem}_network_tls_report.md"
    jp.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    m=["# Android Network & TLS Security Report","",f"- **Input:** {result['input_file']}",
       f"- **Package:** {result['metadata']['package']}",
       f"- **Target SDK:** {result['metadata']['target_sdk'] or 'not parsed'}",
       f"- **APK executed:** No","", "## Manifest metadata","",
       f"- `usesCleartextTraffic`: `{result['metadata']['uses_cleartext_traffic']}`",
       f"- `networkSecurityConfig`: `{result['metadata']['network_security_config'] or 'not declared'}`","",
       "## Summary","",f"- Findings: {result['summary']['finding_count']}"]
    m += [f"- {s}: {n}" for s,n in result["summary"]["by_severity"].items()]
    m += ["","## Findings",""]
    if not result["findings"]: m.append("No findings from the configured rules. This does not establish that the app is secure.")
    for f in result["findings"]:
        m += [f"### [{f['severity']}] {f['rule_id']} — {f['title']}","",f["detail"],"",f"**Recommendation:** {f['recommendation']}",""]
    m += ["## Limitations",""] + [f"- {x}" for x in result["limitations"]]
    mp.write_text("\n".join(m)+"\n",encoding="utf-8")
    return jp,mp
