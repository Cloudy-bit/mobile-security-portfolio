
import zipfile
from pathlib import Path
import pytest
from component_auditor.analyzer import parse_manifest, analyze_apk, analyze_components

MANIFEST = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.links">
 <uses-sdk android:targetSdkVersion="33"/>
 <application>
  <activity android:name=".PublicLinkActivity" android:exported="true">
   <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="example.test" android:pathPrefix="/open"/>
   </intent-filter>
  </activity>
  <service android:name=".OpenService" android:exported="true"/>
  <receiver android:name=".LocalReceiver" android:exported="false"/>
 </application>
</manifest>'''

def test_extract_components_and_deeplinks():
    metadata = parse_manifest(MANIFEST)
    assert len(metadata["components"]) == 3
    assert len(metadata["deep_links"]) == 1
    link = metadata["deep_links"][0]
    assert link["scheme"] == "https"
    assert link["host"] == "example.test"
    assert link["path_prefix"] == "/open"
    assert link["auto_verify"] is True

def test_exported_entry_points_flagged_as_review_indicators():
    findings = analyze_components(parse_manifest(MANIFEST))
    ids = {f["rule_id"] for f in findings}
    assert "CDSA001" in ids
    assert "CDSA007" in ids
    assert all("not automatically" in f["detail"].lower() or f["rule_id"] != "CDSA001" for f in findings)

def test_analyze_apk_fixture(tmp_path: Path):
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", MANIFEST)
    result = analyze_apk(apk)
    assert result["execution_performed"] is False
    assert result["summary"]["component_count"] == 3
    assert result["summary"]["deep_link_count"] == 1
    assert result["summary"]["finding_count"] > 0

def test_bad_xml():
    with pytest.raises(ValueError, match="binary or invalid XML"):
        parse_manifest(b"not xml")
