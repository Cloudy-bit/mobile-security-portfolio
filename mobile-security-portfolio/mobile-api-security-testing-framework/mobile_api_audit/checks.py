
from __future__ import annotations
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from .models import Finding

SENSITIVE_WORDS = ("admin", "user", "account", "profile", "order", "payment", "invoice", "document", "upload", "download", "role", "permission")
SECRET_MARKERS = ("password=", "token=", "api_key=", "apikey=", "secret=", "access_token=", "authorization=")

def redact_url(url: str) -> str:
    """Remove URL user-info and redact all query values before reporting."""
    try:
        p = urlparse(url)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        query_pairs = parse_qsl(p.query, keep_blank_values=True)
        safe_query = urlencode([(k, "[REDACTED]" if v else "") for k, v in query_pairs])
        return urlunparse((p.scheme, host, p.path, p.params, safe_query, ""))
    except (ValueError, TypeError):
        return "[invalid URL]"

def _finding(rule, severity, title, endpoint, detail, recommendation, evidence=""):
    return Finding(rule, severity, title, redact_url(endpoint), detail, recommendation, evidence).to_dict()

def check_url(url: str, allow_http: bool = False) -> list[dict]:
    findings = []
    p = urlparse(url)
    if p.scheme not in {"http", "https"} or not p.netloc:
        return [_finding("MAP001", "HIGH", "Invalid or unsupported URL", url,
                         "The supplied URL is not an absolute HTTP(S) URL.",
                         "Provide an absolute URL to a system you own or are authorized to test.")]
    if p.username or p.password:
        findings.append(_finding("MAP002", "HIGH", "Credentials embedded in URL", url,
                                 "The URL contains user-info credentials.",
                                 "Remove credentials from URLs; use a supported authentication header or secure credential store."))
    if p.scheme == "http" and not allow_http:
        findings.append(_finding("MAP003", "HIGH", "Plain HTTP target", url,
                                 "The URL uses HTTP rather than HTTPS. This is a transport configuration concern, not proof that sensitive data is exposed.",
                                 "Prefer HTTPS for authentication and sensitive traffic; use HTTP only in a controlled local lab."))
    if p.query and any(marker in p.query.lower() for marker in SECRET_MARKERS):
        findings.append(_finding("MAP004", "HIGH", "Possible secret in query string", url,
                                 "A query parameter name resembles a credential or token field; the value is not echoed in this report.",
                                 "Avoid putting secrets in URLs because URLs can appear in logs, browser history, and monitoring systems.",
                                 evidence="Sensitive-looking query parameter name detected; value redacted."))
    path_lower = p.path.lower()
    if any(word in path_lower for word in SENSITIVE_WORDS):
        findings.append(_finding("MAP005", "INFO", "Potentially sensitive endpoint path", url,
                                 "The path contains a keyword often associated with account or privileged functionality. This is only a heuristic.",
                                 "Review authentication, object-level authorization, input validation, and data minimization for this endpoint."))
    return findings

def check_response(url: str, status: int, headers: dict[str, str], body: str = "") -> list[dict]:
    """Passive checks of a response already obtained by an authorized caller."""
    findings = []
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
        findings.append(_finding("MAP101", "LOW", "HSTS header not observed",
                                 url, "The supplied HTTPS response headers do not include Strict-Transport-Security.",
                                 "Consider HSTS after confirming HTTPS is consistently supported across the domain and subdomains."))
    if "x-content-type-options" not in h:
        findings.append(_finding("MAP102", "INFO", "X-Content-Type-Options header not observed",
                                 url, "The supplied response headers do not include X-Content-Type-Options.",
                                 "Consider `X-Content-Type-Options: nosniff` where appropriate for the service."))
    if status >= 500:
        findings.append(_finding("MAP103", "INFO", "Server error response",
                                 url, f"The supplied response status is {status}. No exploitability is inferred.",
                                 "Review server logs and error handling; avoid exposing internal details in client responses."))
    # Do not inspect, persist, or echo response body content; it may contain sensitive data.
    return findings
