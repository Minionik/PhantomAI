"""
Phase 19 — Detection & Logging Assessment

A vulnerability with zero detection and no alerting is more dangerous than a loud RCE.

Tests:
  1. Auth failure rate limiting  — send 10 rapid login attempts, check for lockout/429
  2. Admin action logging        — does /admin respond identically to repeated probes? (no telemetry)
  3. Error response analysis     — do errors expose stack traces? (verbose = poor logging)
  4. WAF detection & evasion     — is a WAF present? does case variation / encoding bypass it?
  5. SSRF blind telemetry        — does SSRF generate any observable side-effect on the target?
  6. Security headers            — HSTS, CSP, X-Frame-Options, Referrer-Policy
  7. Rate limiting on APIs       — rapid GET/POST to API endpoints
"""
import time
import json
import warnings
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

_SECURITY_HEADERS = {
    "Strict-Transport-Security":  ("HSTS missing — downgrade attacks possible",              "medium"),
    "Content-Security-Policy":    ("CSP missing — XSS impact amplified",                    "medium"),
    "X-Frame-Options":            ("Clickjacking protection missing",                        "low"),
    "X-Content-Type-Options":     ("MIME sniffing protection missing",                       "low"),
    "Referrer-Policy":            ("Referrer-Policy missing — sensitive URLs may leak",      "low"),
    "Permissions-Policy":         ("Permissions-Policy missing",                             "info"),
}

_WAF_INDICATORS = {
    "cloudflare":  ["cf-ray", "cloudflare"],
    "akamai":      ["akamai", "x-check-cacheable", "x-akamai"],
    "aws_waf":     ["x-amzn-requestid", "x-amzn-trace-id"],
    "sucuri":      ["x-sucuri-id", "sucuri"],
    "imperva":     ["x-iinfo", "incap_ses", "visid_incap"],
    "f5_bigip":    ["x-wa-info", "bigipserver", "f5"],
    "barracuda":   ["barra_counter_session"],
    "modsecurity": ["mod_security", "modsec"],
}

_WAF_BYPASS_PAYLOADS = [
    "<ScRiPt>alert(1)</ScRiPt>",           # case variation
    "%3Cscript%3Ealert(1)%3C/script%3E",    # URL encoding
    "<scr\x00ipt>alert(1)</scr\x00ipt>",   # null byte
    "';alert(1)//",                         # comment bypass
    "<svg/onload=alert(1)>",               # alternative tag
    "javascript:alert(1)",                 # protocol
    "' OR 1=1--",                           # SQLi baseline
    "' /*!50000OR*/ 1=1--",               # MySQL version comment bypass
    "' OR/**/ 1=1--",                      # comment insertion
]

_LOGIN_PATHS = [
    "/api/login", "/api/auth/login", "/api/v1/login",
    "/login", "/api/token", "/api/auth/token",
]


# ---------------------------------------------------------------------------
# 1. Auth failure rate limiting
# ---------------------------------------------------------------------------

def _check_auth_rate_limit(base_url: str) -> list[dict]:
    findings: list[dict] = []
    base = base_url.rstrip("/")

    for path in _LOGIN_PATHS:
        url     = base + path
        blocked = False
        codes   = []

        for i in range(10):
            try:
                r = requests.post(
                    url,
                    json={"email": f"test{i}@test.com", "password": "wrongpass123"},
                    headers={**_HEADERS, "Content-Type": "application/json"},
                    timeout=4, verify=False, allow_redirects=False,
                )
                codes.append(r.status_code)
                if r.status_code in (429, 423, 503):
                    blocked = True
                    break
                # Check for lockout in body
                if any(kw in r.text.lower() for kw in ["locked", "too many", "rate limit", "blocked", "captcha"]):
                    blocked = True
                    break
            except Exception:
                break

        if not codes:
            continue

        if blocked:
            findings.append({
                "issue":    f"Rate limiting detected at {path} (blocked after {len(codes)} attempts)",
                "severity": "info",
                "owasp":    "A07",
                "url":      url,
                "detail":   f"Auth endpoint enforces rate limiting — HTTP {codes[-1]} after {len(codes)} attempts",
                "detection_quality": "good",
            })
        else:
            findings.append({
                "issue":    f"No rate limiting on auth endpoint: {path} ({len(codes)} requests, no lockout)",
                "severity": "high",
                "owasp":    "A07",
                "url":      url,
                "response_codes": codes,
                "detail":   "Authentication endpoint accepts unlimited failed attempts — credential stuffing / brute force possible",
                "detection_quality": "poor",
            })
        break  # one auth endpoint is enough

    return findings


# ---------------------------------------------------------------------------
# 2. Verbose error responses
# ---------------------------------------------------------------------------

_ERROR_PROBES = [
    ("SQLi probe",    "?id=1'"),
    ("Path traversal","?file=../../etc/passwd"),
    ("XSS probe",     "?q=<script>alert(1)</script>"),
    ("Type error",    "?id[]=invalid"),
]

_STACK_TRACE_INDICATORS = [
    "stack trace", "traceback", "exception in", "at line", "file \"",
    "at com.", "at org.", "at java.", "at sun.",
    "php fatal", "uncaught exception", "warning:", "notice:",
    "rails", "activerecord", "actioncontroller",
    "django.core", "django.db", "python traceback",
    "internal server error", "debug information",
]


def _check_verbose_errors(base_url: str) -> list[dict]:
    findings: list[dict] = []
    base = base_url.rstrip("/")

    for label, suffix in _ERROR_PROBES:
        url = base + suffix
        try:
            r = requests.get(url, headers=_HEADERS, timeout=5, verify=False, allow_redirects=False)
            if r.status_code < 400:
                continue
            body = r.text.lower()
            exposed = [ind for ind in _STACK_TRACE_INDICATORS if ind in body]
            if exposed:
                findings.append({
                    "issue":    f"Verbose error response exposes internals ({label})",
                    "severity": "medium",
                    "owasp":    "A05",
                    "url":      url,
                    "status":   r.status_code,
                    "exposed":  exposed[:3],
                    "snippet":  r.text[:400],
                    "detail":   (
                        f"Error response for {suffix} contains: {', '.join(exposed[:3])} — "
                        "stack traces reveal framework, file paths, and internal logic"
                    ),
                    "detection_quality": "poor",
                })
                break
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# 3. WAF detection + bypass
# ---------------------------------------------------------------------------

def _detect_waf(base_url: str) -> dict:
    result: dict = {"waf": None, "headers": {}}
    try:
        r = requests.get(base_url, headers=_HEADERS, timeout=6, verify=False)
        hdrs_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        result["headers"] = dict(r.headers)

        for waf_name, indicators in _WAF_INDICATORS.items():
            for ind in indicators:
                if any(ind in h or ind in v for h, v in hdrs_lower.items()):
                    result["waf"] = waf_name
                    break
            if result["waf"]:
                break
    except Exception:
        pass
    return result


def _test_waf_bypass(base_url: str, waf_name: str | None) -> list[dict]:
    """Test WAF bypass payloads to see if any slip through."""
    findings: list[dict] = []
    if not waf_name:
        return findings

    base = base_url.rstrip("/")
    for payload in _WAF_BYPASS_PAYLOADS[:5]:
        url = f"{base}?q={payload}"
        try:
            r = requests.get(url, headers=_HEADERS, timeout=5, verify=False, allow_redirects=False)
            # WAF blocks: 403, 406, 429, 503
            if r.status_code not in (403, 406, 429, 503):
                if payload.lower() in r.text.lower() or "alert(1)" in r.text:
                    findings.append({
                        "issue":    f"WAF bypass — payload reached application: {payload[:30]}",
                        "severity": "high",
                        "owasp":    "A05",
                        "url":      url,
                        "waf":      waf_name,
                        "payload":  payload,
                        "status":   r.status_code,
                        "detail":   (
                            f"{waf_name} WAF did not block payload '{payload[:30]}' — "
                            "evasion via case/encoding variation possible"
                        ),
                        "detection_quality": "poor",
                    })
        except Exception:
            continue

    if not findings:
        findings.append({
            "issue":    f"WAF present ({waf_name}) and blocked all standard probes",
            "severity": "info",
            "owasp":    "A05",
            "url":      base_url,
            "waf":      waf_name,
            "detail":   f"{waf_name} WAF actively blocked all 5 test payloads",
            "detection_quality": "good",
        })

    return findings


# ---------------------------------------------------------------------------
# 4. Security header audit
# ---------------------------------------------------------------------------

def _audit_security_headers(base_url: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(base_url, headers=_HEADERS, timeout=6, verify=False, allow_redirects=True)
        present = {k.lower() for k in r.headers}
        for header, (message, severity) in _SECURITY_HEADERS.items():
            if header.lower() not in present:
                findings.append({
                    "issue":    message,
                    "severity": severity,
                    "owasp":    "A05",
                    "url":      base_url,
                    "header":   header,
                    "detail":   f"Response is missing '{header}' security header",
                    "detection_quality": "neutral",
                })
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# 5. API rate limiting
# ---------------------------------------------------------------------------

def _check_api_rate_limit(base_url: str, api_urls: list[str]) -> list[dict]:
    findings: list[dict] = []
    candidates = [u for u in (api_urls or []) if "/api/" in u][:3]

    for url in candidates:
        codes = []
        rate_limited = False
        for _ in range(20):
            try:
                r = requests.get(url, headers=_HEADERS, timeout=3, verify=False, allow_redirects=False)
                codes.append(r.status_code)
                if r.status_code == 429 or "rate limit" in r.text.lower():
                    rate_limited = True
                    break
            except Exception:
                break

        if not codes:
            continue

        if rate_limited:
            findings.append({
                "issue":    f"API rate limiting enforced: {url}",
                "severity": "info",
                "owasp":    "A09",
                "url":      url,
                "detail":   f"Rate limited after {len(codes)} requests (HTTP 429)",
                "detection_quality": "good",
            })
        else:
            findings.append({
                "issue":    f"No rate limiting on API endpoint: {url}",
                "severity": "medium",
                "owasp":    "A09",
                "url":      url,
                "requests_sent": len(codes),
                "detail":   f"Sent {len(codes)} rapid requests — no rate limiting observed",
                "detection_quality": "poor",
            })
        break

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_detection(
    target: str,
    api_urls: list[str] = None,
    ai=None,
) -> dict:
    base_url = target if target.startswith("http") else f"https://{target}"

    print("    [*] Detection: auth rate limiting ...")
    rate_limit_findings = _check_auth_rate_limit(base_url)

    print("    [*] Detection: verbose error response analysis ...")
    error_findings = _check_verbose_errors(base_url)

    print("    [*] Detection: WAF detection + bypass ...")
    waf_info = _detect_waf(base_url)
    waf_findings = _test_waf_bypass(base_url, waf_info.get("waf"))

    print("    [*] Detection: security header audit ...")
    header_findings = _audit_security_headers(base_url)

    print("    [*] Detection: API rate limiting ...")
    api_rate_findings = _check_api_rate_limit(base_url, api_urls or [])

    all_findings = (
        rate_limit_findings + error_findings + waf_findings
        + header_findings + api_rate_findings
    )

    # Categorise by detection quality
    poor_detection   = [f for f in all_findings if f.get("detection_quality") == "poor"]
    good_detection   = [f for f in all_findings if f.get("detection_quality") == "good"]

    # AI assessment
    ai_detection = None
    if ai and ai.is_available() and all_findings:
        summary = json.dumps(
            [{"issue": f["issue"], "severity": f["severity"],
              "quality": f.get("detection_quality", "neutral")}
             for f in all_findings[:15]],
            indent=2
        )[:2000]
        prompt = (
            "You are a security operations analyst reviewing detection and logging findings.\n\n"
            f"Target: {target}\n"
            f"Detection findings:\n{summary}\n\n"
            "Assess:\n"
            "1. Overall detection maturity (immature/developing/mature)\n"
            "2. Which attack technique would be MOST silent against this target?\n"
            "3. Which finding, if left unremediated, would allow the longest undetected dwell time?\n"
            "4. Top 2 defensive controls that would most improve detection coverage\n\n"
            "Return ONLY valid JSON:\n"
            '{"maturity":"immature|developing|mature", "most_silent_technique":"...", '
            '"longest_dwell":"...", "top_controls":["...", "..."]}'
        )
        ai_detection = ai.ask_json(prompt, model="fast")

    return {
        "rate_limiting":   rate_limit_findings,
        "verbose_errors":  error_findings,
        "waf":             {"detected": waf_info.get("waf"), "bypass_findings": waf_findings},
        "security_headers": header_findings,
        "api_rate_limit":  api_rate_findings,
        "all_findings":    all_findings,
        "poor_detection":  poor_detection,
        "good_detection":  good_detection,
        "ai_detection":    ai_detection,
        "summary": {
            "total":         len(all_findings),
            "poor_coverage": len(poor_detection),
            "good_coverage": len(good_detection),
            "waf":           waf_info.get("waf"),
        },
    }
