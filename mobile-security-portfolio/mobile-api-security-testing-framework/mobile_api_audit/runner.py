
from __future__ import annotations
import json, time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from .checks import check_url, check_response, redact_url

def load_endpoints(path: str | Path) -> list[dict]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Endpoints file must contain a JSON array.")
    endpoints = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            raise ValueError(f"Endpoint entry {i} must be an object with a string 'url'.")
        method = str(item.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError(f"Endpoint entry {i}: only GET and HEAD are supported in this safe version.")
        endpoints.append({"url": item["url"], "method": method, "label": str(item.get("label", ""))})
    return endpoints

def run_audit(endpoints: list[dict], active: bool = False, allow_http: bool = False,
              timeout: float = 5.0, delay: float = 0.5) -> dict:
    all_findings = []
    results = []
    for endpoint in endpoints:
        url = endpoint["url"]
        findings = check_url(url, allow_http=allow_http)
        result = {"url": redact_url(url), "method": endpoint.get("method", "GET"), "label": endpoint.get("label", ""),
                  "request_performed": False, "status": None, "response_headers": {}, "findings": findings, "error": None}
        if active and not any(f["rule_id"] == "MAP001" for f in findings):
            # Deliberately restricted to GET/HEAD, no custom auth, no request body, and no redirect following.
            request = Request(url, method=endpoint.get("method", "GET"), headers={"User-Agent": "MobileAPISecurityAudit/1.0"})
            try:
                with urlopen(request, timeout=timeout) as response:
                    result["request_performed"] = True
                    result["status"] = response.status
                    # Header values are limited to ordinary security metadata; cookies and auth headers are excluded.
                    allowed = {"strict-transport-security", "x-content-type-options", "content-type",
                               "content-security-policy", "cache-control", "server"}
                    result["response_headers"] = {k: v for k, v in response.headers.items() if k.lower() in allowed}
                    result["findings"].extend(check_response(url, response.status, result["response_headers"]))
            except HTTPError as exc:
                result["request_performed"] = True
                result["status"] = exc.code
                allowed = {"strict-transport-security", "x-content-type-options", "content-type",
                           "content-security-policy", "cache-control", "server"}
                result["response_headers"] = {k: v for k, v in exc.headers.items() if k.lower() in allowed} if exc.headers else {}
                result["findings"].extend(check_response(url, exc.code, result["response_headers"]))
                result["error"] = f"HTTP response error: {exc.code}"
            except (URLError, TimeoutError, ValueError) as exc:
                result["request_performed"] = True
                result["error"] = f"Request failed: {type(exc).__name__}"
            if delay > 0:
                time.sleep(delay)
        all_findings.extend(result["findings"])
        results.append(result)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: (severity_order.get(f["severity"], 99), f["rule_id"], f["endpoint"]))
    return {
        "tool": "Mobile API Security Testing Framework",
        "version": "1.0.0",
        "mode": "active-safe-GET/HEAD" if active else "offline URL review",
        "results": results,
        "findings": all_findings,
        "summary": {
            "endpoint_count": len(results),
            "request_count": sum(bool(r["request_performed"]) for r in results),
            "finding_count": len(all_findings),
            "by_severity": {s: sum(f["severity"] == s for f in all_findings) for s in severity_order},
        },
        "limitations": [
            "This is a starter assessment framework, not a full API penetration tester.",
            "Offline checks use URL shape and keywords; they cannot confirm authorization or exploitability.",
            "Active mode sends only GET/HEAD requests to explicitly listed URLs; it does not brute-force, fuzz, log in, modify data, or follow redirects intentionally.",
            "Only run active checks against systems you own or have written authorization to test.",
            "Response bodies are not read or stored. Authentication headers, cookies, and query values are not printed in reports.",
            "TLS certificate validation uses Python's standard HTTPS client; this tool does not conduct a full TLS configuration audit.",
        ],
    }

def write_reports(report: dict, output_dir: str | Path) -> tuple[Path, Path]:
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    jp, mp = out/"mobile_api_audit.json", out/"mobile_api_audit.md"
    jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Mobile API Security Audit", "",
        f"- **Tool:** {report['tool']} {report['version']}",
        f"- **Mode:** {report['mode']}",
        f"- **Endpoints:** {report['summary']['endpoint_count']}",
        f"- **Requests performed:** {report['summary']['request_count']}",
        f"- **Findings:** {report['summary']['finding_count']}", "",
        "## Severity summary", ""
    ]
    lines.extend(f"- {sev}: {count}" for sev, count in report["summary"]["by_severity"].items())
    lines += ["", "## Endpoint results", ""]
    for result in report["results"]:
        lines += [f"### `{result['method']} {result['url']}`", "",
                  f"- Request performed: `{result['request_performed']}`",
                  f"- HTTP status: `{result['status'] if result['status'] is not None else 'not checked'}`"]
        if result["error"]: lines.append(f"- Error: {result['error']}")
        lines.append("")
        for f in result["findings"]:
            lines += [f"**[{f['severity']}] {f['rule_id']} — {f['title']}**",
                      f"- Detail: {f['detail']}", f"- Recommendation: {f['recommendation']}", ""]
        if not result["findings"]: lines += ["No findings from the configured checks.", ""]
    lines += ["## Limitations", ""] + [f"- {x}" for x in report["limitations"]]
    mp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return jp, mp
