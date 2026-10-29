
import zipfile
from pathlib import Path
import pytest
from android_security_lab.analyzer import analyze_apk, parse_manifest_xml, evaluate_findings

MANIFEST = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test" android:versionName="1.2" android:versionCode="12">
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter></activity>
    <service android:name=".SyncService" android:exported="false"/>
  </application>
</manifest>'''

def test_parse_manifest():
    metadata = parse_manifest_xml(MANIFEST)
    assert metadata["package"] == "com.example.test"
    assert "android.permission.CAMERA" in metadata["permissions"]
    assert metadata["application"]["debuggable"] is True
    assert metadata["components"][0]["name"] == ".MainActivity"

def test_rules_find_indicators():
    findings = evaluate_findings(parse_manifest_xml(MANIFEST))
    ids = {f["rule_id"] for f in findings}
    assert {"ASL001", "ASL002", "ASL003", "ASL005", "ASL007"} <= ids

def test_analyze_fixture(tmp_path: Path):
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    result = analyze_apk(apk)
    assert result["manifest_parser"] == "plain-xml"
    assert result["execution_performed"] is False
    assert result["summary"]["finding_count"] > 0

def test_bad_xml_raises():
    with pytest.raises(ValueError, match="Manifest is binary or invalid XML"):
        parse_manifest_xml(b"not xml")
