import zipfile
from pathlib import Path
import pytest
from network_tls_analyzer.analyzer import analyze_apk, analyze_network_config

ANDROID = "http://schemas.android.com/apk/res/android"

def make_apk(path: Path, manifest: bytes, config: bytes | None = None):
    with zipfile.ZipFile(path,"w") as z:
        z.writestr("AndroidManifest.xml",manifest)
        if config is not None:
            z.writestr("res/xml/network_security_config.xml",config)

def test_manifest_cleartext_and_network_reference(tmp_path):
    manifest = ('<manifest xmlns:android="' + ANDROID + '" package="com.example.lab">'
      '<uses-sdk android:targetSdkVersion="33"/>'
      '<application android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network_security_config"/>'
      '</manifest>').encode()
    config=b'<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'
    apk=tmp_path/"lab.apk"; make_apk(apk,manifest,config)
    report=analyze_apk(apk)
    ids={f["rule_id"] for f in report["findings"]}
    assert "NTSA008" in ids and "NTSA010" in ids and "NTSA002" in ids
    assert report["execution_performed"] is False

def test_user_ca_is_reported_as_review_item():
    config=b'<network-security-config><base-config><trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors></base-config></network-security-config>'
    ids={f["rule_id"] for f in analyze_network_config(config)}
    assert "NTSA005" in ids

def test_domain_cleartext_policy():
    config=b'<network-security-config><domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">example.test</domain></domain-config></network-security-config>'
    findings=analyze_network_config(config)
    assert any(f["rule_id"]=="NTSA004" and "example.test" in f["detail"] for f in findings)

def test_invalid_xml_is_reported():
    with pytest.raises(ValueError,match="binary XML or invalid XML"):
        analyze_network_config(b"not xml")

def test_missing_manifest_fails_cleanly(tmp_path):
    apk=tmp_path/"empty.apk"
    with zipfile.ZipFile(apk,"w") as z: z.writestr("classes.dex",b"")
    with pytest.raises(ValueError,match="AndroidManifest.xml not found"):
        analyze_apk(apk)
