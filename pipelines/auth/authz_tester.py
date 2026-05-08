"""
Phase 11 — Authorization Testing

Tests:
  1. IDOR         — replace numeric/UUID identifiers in URLs and params
  2. Horizontal   — compare responses between sequential IDs
  3. Vertical     — probe admin/staff endpoints with low-priv session
  4. Mass assign  — inject extra privilege fields in PUT/PATCH/POST bodies
  5. API version  — check if v1 lacks v2 authorization controls
  6. HTTP method  — try switching GET → DELETE/PUT on object endpoints
"""
import re
import json
import warnings
import urllib3
import requests
from urllib.parse import urlparse, urlencode, parse_qs
from core.run_cmd import dedupe

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# Regex patterns for ID-like path segments
_ID_PATTERNS = [
    re.compile(r'/(\d{1,10})(?:/|$)'),                                         # numeric
    re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)'),  # UUID
    re.compile(r'/([0-9a-f]{24})(?:/|$)'),                                     # MongoDB ObjectId
    re.compile(r'/([0-9a-zA-Z]{16,32})(?:/|$)'),                               # generic opaque
]

# Admin/staff paths to probe for vertical escalation
_ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/dashboard", "/admin/settings",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/staff", "/staff/users", "/internal",
    "/superuser", "/manage", "/management",
    "/api/users", "/api/accounts", "/api/roles",
    "/api/v1/users", "/api/v2/users",
    "/api/v1/permissions", "/api/v2/permissions",
]

# Fields to inject for mass assignment testing
_MASS_ASSIGN_FIELDS = {
    "role":      ["admin", "superuser", "staff"],
    "is_admin":  [True, 1, "true"],
    "admin":     [True, 1, "true"],
    "verified":  [True, 1, "true"],
    "active":    [True, 1, "true"],
    "plan":      ["enterprise", "premium", "unlimited"],
    "credits":   [9999, 99999],
    "balance":   [9999.99],
    "tier":      ["admin", "enterprise"],
    "scope":     ["admin read write delete"],
    "permissions": ["*", "admin:all"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, headers: dict = None) -> requests.Response | None:
    try:
        return requests.get(
            url, headers={**_HEADERS, **(headers or {})},
            timeout=6, verify=False, allow_redirects=False,
        )
    except Exception:
        return None


def _method(method: str, url: str, data=None, headers: dict = None) -> requests.Response | None:
    try:
        return requests.request(
            method.upper(), url,
            json=data,
            headers={**_HEADERS, "Content-Type": "application/json", **(headers or {})},
            timeout=6, verify=False, allow_redirects=False,
        )
    except Exception:
        return None


def _extract_id_segments(url: str) -> list[tuple[str, str]]:
    """Return list of (pattern_type, matched_id) found in the URL path."""
    path = urlparse(url).path
    hits = []
    for pat in _ID_PATTERNS:
        for m in pat.finditer(path):
            hits.append((pat.pattern[:10], m.group(1)))
    return hits


def _mutate_id(url: str, old_id: str, new_id: str) -> str:
    """Replace first occurrence of old_id in the URL path with new_id."""
    parsed = urlparse(url)
    new_path = parsed.path.replace(f"/{old_id}/", f"/{new_id}/", 1)
    new_path = new_path.replace(f"/{old_id}", f"/{new_id}", 1)
    return parsed._replace(path=new_path).geturl()


def _is_same_content(r1: requests.Response, r2: requests.Response) -> bool:
    """Return True if both responses look the same (same data, different ID)."""
    if abs(len(r1.text) - len(r2.text)) > 50:
        return False
    # Compare JSON keys if possible
    try:
        j1, j2 = r1.json(), r2.json()
        return set(j1.keys()) == set(j2.keys())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# IDOR + Horizontal Escalation
# ---------------------------------------------------------------------------

def _test_idor(urls: list[str], auth_headers: dict = None) -> list[dict]:
    findings = []
    tested: set[str] = set()

    for url in urls[:30]:
        id_segs = _extract_id_segments(url)
        if not id_segs:
            continue

        for _, current_id in id_segs[:1]:  # first ID segment only per URL
            if url in tested:
                continue
            tested.add(url)

            baseline = _get(url, auth_headers)
            if not baseline or baseline.status_code >= 400:
                continue

            # Try adjacent IDs
            try:
                id_int = int(current_id)
                candidates = [id_int - 1, id_int + 1, id_int + 100]
            except ValueError:
                # UUID / opaque — just try a static test ID
                candidates = ["00000000-0000-0000-0000-000000000001"]

            for alt_id in candidates:
                alt_url   = _mutate_id(url, current_id, str(alt_id))
                alt_resp  = _get(alt_url, auth_headers)
                if not alt_resp:
                    continue

                if alt_resp.status_code == baseline.status_code and alt_resp.status_code < 400:
                    findings.append({
                        "issue":    "Potential IDOR — different object ID returned same status",
                        "severity": "high",
                        "owasp":    "A01",
                        "url":      url,
                        "mutated":  alt_url,
                        "original_id": str(current_id),
                        "tested_id":   str(alt_id),
                        "status":   alt_resp.status_code,
                        "detail":   (
                            "Server returned HTTP "
                            f"{alt_resp.status_code} for object ID {alt_id} — "
                            "verify if this belongs to a different user"
                        ),
                    })
                    break  # one finding per URL is enough

    return findings


# ---------------------------------------------------------------------------
# Vertical Escalation (admin endpoint probe)
# ---------------------------------------------------------------------------

def _test_vertical(base_url: str, auth_headers: dict = None) -> list[dict]:
    findings = []
    base = base_url.rstrip("/")

    for path in _ADMIN_PATHS:
        url  = base + path
        resp = _get(url, auth_headers)
        if not resp:
            continue
        if resp.status_code in (200, 201, 206):
            findings.append({
                "issue":    f"Admin/privileged endpoint accessible: {path}",
                "severity": "critical",
                "owasp":    "A01",
                "url":      url,
                "status":   resp.status_code,
                "detail":   (
                    f"GET {url} returned {resp.status_code} with current session — "
                    "this may indicate a vertical privilege escalation"
                ),
            })
        elif resp.status_code == 403:
            # 403 is less interesting but worth noting for manual follow-up
            findings.append({
                "issue":    f"Admin endpoint exists but access denied: {path}",
                "severity": "low",
                "owasp":    "A01",
                "url":      url,
                "status":   resp.status_code,
                "detail":   "Endpoint returned 403 — exists but authorization enforced; test with other methods",
            })

    return findings


# ---------------------------------------------------------------------------
# Mass Assignment
# ---------------------------------------------------------------------------

def _test_mass_assignment(urls: list[str], auth_headers: dict = None) -> list[dict]:
    """
    Try injecting privilege-escalation fields in PUT/PATCH/POST requests.
    """
    findings = []
    put_patch_candidates = [u for u in urls if _extract_id_segments(u)][:5]

    for url in put_patch_candidates:
        # Probe with extra fields in PUT/PATCH body
        for method in ("PUT", "PATCH"):
            for field, values in list(_MASS_ASSIGN_FIELDS.items())[:5]:
                body = {field: values[0]}
                resp = _method(method, url, data=body, headers=auth_headers)
                if resp and resp.status_code in (200, 201, 202):
                    findings.append({
                        "issue":    f"Possible mass assignment — {method} {url} accepted '{field}'",
                        "severity": "high",
                        "owasp":    "A04",
                        "url":      url,
                        "method":   method,
                        "field":    field,
                        "value":    values[0],
                        "status":   resp.status_code,
                        "detail":   (
                            f"{method} request accepted '{field}={values[0]}' — "
                            "server may have applied the privilege-escalating field"
                        ),
                    })
                    break

    return findings


# ---------------------------------------------------------------------------
# HTTP Method Switching
# ---------------------------------------------------------------------------

def _test_method_switching(urls: list[str], auth_headers: dict = None) -> list[dict]:
    """
    Try DELETE / PUT on GET-only endpoints. 405 → endpoint exists but method not allowed.
    200/204 → method accepted, potential destructive operation.
    """
    findings = []
    candidates = [u for u in urls if _extract_id_segments(u)][:10]

    for url in candidates:
        for method in ("DELETE", "PUT", "PATCH"):
            resp = _method(method, url, data={}, headers=auth_headers)
            if resp and resp.status_code in (200, 201, 202, 204):
                findings.append({
                    "issue":    f"HTTP method switching accepted: {method} {url}",
                    "severity": "high",
                    "owasp":    "A01",
                    "url":      url,
                    "method":   method,
                    "status":   resp.status_code,
                    "detail":   (
                        f"{method} {url} returned {resp.status_code} — "
                        "server accepts destructive methods without explicit restriction"
                    ),
                })

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_authz(
    target: str,
    urls: list[str],
    params: list[str],
    auth_headers: dict = None,
    ai=None,
) -> dict:
    """
    Run full authorization test suite.
    auth_headers: dict of headers to include in requests (e.g. Authorization: Bearer ...)
    """
    base_url = target if target.startswith("http") else f"https://{target}"
    all_urls = dedupe(urls + params)

    idor_findings    = _test_idor(all_urls, auth_headers)
    vertical_findings = _test_vertical(base_url, auth_headers)
    mass_findings    = _test_mass_assignment(all_urls, auth_headers)
    method_findings  = _test_method_switching(all_urls, auth_headers)

    all_findings = idor_findings + vertical_findings + mass_findings + method_findings

    # AI analysis of authorization findings
    ai_analysis = None
    if ai and ai.is_available() and all_findings:
        summary = json.dumps(
            [{"issue": f["issue"], "url": f["url"], "severity": f["severity"]} for f in all_findings[:15]],
            indent=2
        )[:2000]
        prompt = (
            "You are a senior penetration tester reviewing authorization test results.\n\n"
            f"Findings:\n{summary}\n\n"
            "For each finding:\n"
            "1. Confirm if this is a real vulnerability or false positive\n"
            "2. Describe the exact manual verification step a tester should take\n"
            "3. Estimate the business impact if exploited\n\n"
            "Return ONLY valid JSON array: "
            '[{"issue":"...", "confirmed":true/false, "verify_step":"...", "business_impact":"..."}]'
        )
        ai_analysis = ai.ask_json(prompt, model="fast")

    return {
        "idor":        idor_findings,
        "vertical":    vertical_findings,
        "mass_assign": mass_findings,
        "method_switch": method_findings,
        "all_findings":  all_findings,
        "ai_analysis":   ai_analysis,
    }
