
import json
from pathlib import Path
import pytest
from mobile_api_audit.checks import check_url, check_response
from mobile_api_audit.runner import load_endpoints, run_audit, write_reports

def test_http_and_sensitive_path_flags():
    findings = check_url("http://localhost:8080/v1/profile")
    ids = {f["rule_id"] for f in findings}
    assert "MAP003" in ids
    assert "MAP005" in ids

def test_secret_value_not_in_finding():
    findings = check_url("https://example.test/api?access_token=very-secret-value")
    assert any(f["rule_id"] == "MAP004" for f in findings)
    assert all("very-secret-value" not in str(f) for f in findings)

def test_response_header_checks():
    findings = check_response("https://example.test/api", 200, {"Content-Type": "application/json"})
    assert {f["rule_id"] for f in findings} == {"MAP101", "MAP102"}

def test_loader_rejects_unsafe_methods(tmp_path: Path):
    p = tmp_path / "endpoints.json"
    p.write_text(json.dumps([{"url": "https://example.test", "method": "POST"}]))
    with pytest.raises(ValueError, match="only GET and HEAD"):
        load_endpoints(p)

def test_offline_audit_and_reports(tmp_path: Path):
    endpoints = [{"url": "https://api.example.test/v1/orders", "method": "GET"}]
    report = run_audit(endpoints, active=False)
    assert report["summary"]["request_count"] == 0
    assert report["results"][0]["request_performed"] is False
    jp, mp = write_reports(report, tmp_path/"reports")
    assert jp.exists() and mp.exists()
    assert "Mobile API Security Audit" in mp.read_text()
