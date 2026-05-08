"""
Phase 13 — Environment Pivoting

Modern applications are interconnected systems, not isolated apps.

Tests:
  1. Cloud metadata SSRF    — AWS IMDSv1/v2, GCP, Azure, Oracle, Alibaba
  2. Internal routing abuse  — known internal service URLs via SSRF
  3. CI/CD path discovery    — exposed pipeline config files
  4. Container escape paths  — Docker socket, proc filesystem, cgroup indicators
  5. Kubernetes trust abuse  — service account tokens, API server, kubelet
  6. Environment / secret    — .env, config files, exposed secrets in responses
"""
import os
import json
import warnings
import urllib3
import requests
from urllib.parse import urlparse
from core.run_cmd import run_cmd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# ---------------------------------------------------------------------------
# Cloud metadata endpoints
# ---------------------------------------------------------------------------

_CLOUD_METADATA = [
    # AWS IMDSv1 (no header required)
    ("AWS IMDSv1 — instance identity",   "http://169.254.169.254/latest/meta-data/",              ["ami-id", "instance-id", "local-ipv4"]),
    ("AWS IMDSv1 — IAM credentials",     "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["RoleArn", "AccessKeyId", "SecretAccessKey", "Token"]),
    ("AWS IMDSv1 — user-data",           "http://169.254.169.254/latest/user-data",               ["password", "secret", "key", "#!/"]),
    # GCP metadata
    ("GCP metadata — project info",      "http://metadata.google.internal/computeMetadata/v1/project/", ["projectId", "project-id"]),
    ("GCP metadata — service accounts",  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", ["default", "email"]),
    # Azure IMDS
    ("Azure IMDS — instance",            "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["subscriptionId", "resourceGroupName", "vmId"]),
    ("Azure IMDS — identity token",      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", ["access_token"]),
    # Oracle Cloud
    ("Oracle Cloud IMDS",                "http://169.254.169.254/opc/v2/instance/",               ["id", "compartmentId"]),
    # Alibaba Cloud
    ("Alibaba Cloud IMDS",               "http://100.100.100.200/latest/meta-data/",              ["instance-id"]),
    # Generic localhost probes
    ("Localhost — admin panel",          "http://127.0.0.1/admin",                                ["admin", "dashboard", "login"]),
    ("Localhost — status/health",        "http://localhost/status",                                ["status", "ok", "healthy"]),
]

# SSRF delivery params to try
_SSRF_PARAMS = ["url", "uri", "src", "redirect", "next", "return", "callback", "fetch", "path", "dest", "host", "endpoint"]


# ---------------------------------------------------------------------------
# CI/CD path discovery
# ---------------------------------------------------------------------------

_CICD_PATHS = [
    # Git
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.gitignore", "/.gitmodules",
    # GitHub Actions
    "/.github/workflows/main.yml", "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml", "/.github/workflows/release.yml",
    # GitLab CI
    "/.gitlab-ci.yml",
    # Jenkins
    "/Jenkinsfile", "/jenkins/Jenkinsfile",
    # CircleCI
    "/.circleci/config.yml",
    # Travis CI
    "/.travis.yml",
    # Azure DevOps
    "/azure-pipelines.yml",
    # Bitbucket
    "/bitbucket-pipelines.yml",
    # Docker
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.dockerignore",
    # Kubernetes
    "/k8s/", "/kubernetes/", "/helm/",
    "/kustomization.yaml", "/kustomization.yml",
    # Terraform / Ansible
    "/terraform/", "/ansible/", "/playbook.yml",
    # Environment files
    "/.env", "/.env.production", "/.env.local", "/.env.staging",
    "/config.yml", "/config.yaml", "/config.json",
    "/secrets.yml", "/secrets.yaml",
    "/application.properties", "/application.yml",
    "/appsettings.json", "/web.config",
    # Backup files
    "/backup.sql", "/db.sql", "/dump.sql",
    "/backup.zip", "/backup.tar.gz",
    "/.htpasswd", "/.htaccess",
]

_CICD_KEYWORDS = [
    "password", "secret", "token", "key", "api_key", "aws_", "gcp_",
    "azure_", "database_url", "db_pass", "private", "credential",
    "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
]


# ---------------------------------------------------------------------------
# Container / K8s indicators
# ---------------------------------------------------------------------------

_CONTAINER_PATHS = [
    # Docker socket (if app can reach host filesystem via SSRF → file://)
    "/var/run/docker.sock",
    # K8s service account token
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    # /proc indicators inside container
    "/proc/1/cgroup",
    "/proc/self/cgroup",
    "/proc/net/tcp",
]

_K8S_ENDPOINTS = [
    "https://kubernetes.default.svc/api",
    "https://kubernetes.default.svc/api/v1/namespaces",
    "https://kubernetes.default.svc/api/v1/secrets",
    # Kubelet (usually :10250)
    "https://{host}:10250/pods",
    "https://{host}:10250/runningpods/",
    # Etcd (usually :2379)
    "http://{host}:2379/v2/keys",
    "http://{host}:2379/v3/kv/range",
    # Dashboard
    "http://{host}:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
]

_DOCKER_ENDPOINTS = [
    "http://{host}:2375/version",
    "http://{host}:2375/containers/json",
    "http://{host}:2375/images/json",
    "http://{host}:2376/version",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, extra_headers: dict = None, timeout: int = 5) -> requests.Response | None:
    try:
        hdrs = {**_HEADERS, **(extra_headers or {})}
        return requests.get(url, headers=hdrs, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def _ssrf_deliver(target_url: str, metadata_url: str, ssrf_params: list[str]) -> dict | None:
    """Try each SSRF param to deliver the metadata_url to the target."""
    for param in ssrf_params:
        probe_url = f"{target_url}?{param}={metadata_url}"
        r = _get(probe_url)
        if r and r.status_code == 200:
            return {"delivery_param": param, "probe_url": probe_url, "response": r.text[:500]}
    return None


# ---------------------------------------------------------------------------
# Phase 13 modules
# ---------------------------------------------------------------------------

def _cloud_metadata_probe(target_url: str, ssrf_params: list[str]) -> list[dict]:
    """Direct + SSRF-assisted cloud metadata probing."""
    findings: list[dict] = []

    for label, metadata_url, indicators in _CLOUD_METADATA:
        # 1. Direct request (app server → metadata service directly)
        r = _get(metadata_url, extra_headers={"Metadata": "true", "Metadata-Flavor": "Google"})
        if r and r.status_code == 200:
            body = r.text
            hit_indicators = [ind for ind in indicators if ind.lower() in body.lower()]
            if hit_indicators:
                findings.append({
                    "issue":    f"Cloud metadata accessible directly: {label}",
                    "severity": "critical",
                    "owasp":    "A10",
                    "url":      metadata_url,
                    "indicators": hit_indicators,
                    "snippet":  body[:300],
                    "detail":   "Direct access from scanner — target likely has SSRF or is inside the cloud network",
                })
                continue

        # 2. SSRF delivery via target application parameters
        if ssrf_params and target_url:
            result = _ssrf_deliver(target_url, metadata_url, ssrf_params[:6])
            if result:
                body = result["response"]
                hit_indicators = [ind for ind in indicators if ind.lower() in body.lower()]
                if hit_indicators:
                    findings.append({
                        "issue":    f"SSRF → Cloud metadata: {label}",
                        "severity": "critical",
                        "owasp":    "A10",
                        "url":      result["probe_url"],
                        "delivery_param": result["delivery_param"],
                        "indicators": hit_indicators,
                        "snippet":  body[:300],
                        "detail":   f"Target application fetched cloud metadata via '{result['delivery_param']}' parameter",
                    })

    return findings


def _cicd_discovery(base_url: str) -> list[dict]:
    """Probe for exposed CI/CD config, secret files, and environment files."""
    findings: list[dict] = []
    base = base_url.rstrip("/")

    for path in _CICD_PATHS:
        url  = base + path
        r    = _get(url)
        if not r or r.status_code not in (200, 206):
            continue

        body = r.text
        ct   = r.headers.get("Content-Type", "")

        # Skip HTML pages (these are usually login redirects, not actual config files)
        if "text/html" in ct and "<html" in body.lower() and len(body) > 2000:
            continue

        # Check for sensitive keywords
        found_keywords = [kw for kw in _CICD_KEYWORDS if kw.lower() in body.lower()]
        severity = "critical" if found_keywords else "medium"

        findings.append({
            "issue":    f"{'Sensitive data in' if found_keywords else 'Exposed'} config/pipeline file: {path}",
            "severity": severity,
            "owasp":    "A05",
            "url":      url,
            "status":   r.status_code,
            "sensitive_keywords": found_keywords,
            "snippet":  body[:400],
            "detail":   (
                f"File {path} is publicly accessible"
                + (f" and contains sensitive keywords: {', '.join(found_keywords)}" if found_keywords else "")
            ),
        })

    return findings


def _container_k8s_probe(base_url: str) -> list[dict]:
    """
    Probe for Kubernetes API server, Docker daemon, and container escape indicators.
    """
    findings: list[dict] = []
    parsed = urlparse(base_url)
    host   = parsed.hostname or parsed.netloc.split(":")[0]

    # K8s API server — try default service DNS name + target IP
    k8s_targets = ["kubernetes.default.svc", host]
    for k8s_host in k8s_targets:
        for template in _K8S_ENDPOINTS[:5]:
            url = template.replace("{host}", k8s_host)
            r   = _get(url, timeout=4)
            if r and r.status_code in (200, 401, 403):
                sensitive = r.status_code == 200 and any(
                    kw in r.text for kw in ["apiVersion", "namespaces", "secrets", "pods"]
                )
                findings.append({
                    "issue":    f"Kubernetes API endpoint {'accessible' if sensitive else 'exists'}: {url}",
                    "severity": "critical" if sensitive else "high",
                    "owasp":    "A05",
                    "url":      url,
                    "status":   r.status_code,
                    "detail":   (
                        f"K8s API at {url} returned HTTP {r.status_code}"
                        + (" — authenticated data returned" if sensitive else " — authentication required but endpoint exposed")
                    ),
                    "snippet":  r.text[:300] if sensitive else "",
                })

    # Docker daemon (unauthenticated :2375)
    for template in _DOCKER_ENDPOINTS:
        url = template.replace("{host}", host)
        r   = _get(url, timeout=3)
        if r and r.status_code == 200 and ("Version" in r.text or "Containers" in r.text):
            findings.append({
                "issue":    f"Unauthenticated Docker daemon: {url}",
                "severity": "critical",
                "owasp":    "A05",
                "url":      url,
                "status":   200,
                "detail":   "Docker API is exposed without authentication — full container control possible",
                "snippet":  r.text[:300],
            })

    # Container escape indicators — try via SSRF file:// protocol if applicable
    for container_path in _CONTAINER_PATHS[:4]:
        probe = f"{base_url.rstrip('/')}?file=file://{container_path}"
        r = _get(probe)
        if r and any(kw in r.text for kw in ["docker", "kubepods", "eyJ", "kube-system", "containerd"]):
            findings.append({
                "issue":    f"Container escape indicator — path accessible via SSRF: {container_path}",
                "severity": "critical",
                "owasp":    "A10",
                "url":      probe,
                "detail":   f"Target responded with container internals from {container_path}",
                "snippet":  r.text[:300],
            })

    return findings


def _env_secret_probe(base_url: str) -> list[dict]:
    """
    Probe for .env and config files not caught by cicd_discovery (extra paths).
    Also test for exposed debug endpoints that print environment variables.
    """
    findings: list[dict] = []
    base = base_url.rstrip("/")

    debug_paths = [
        "/debug", "/debug/vars", "/debug/pprof", "/_debug",
        "/actuator", "/actuator/env", "/actuator/configprops",
        "/actuator/mappings", "/actuator/beans",
        "/__debug__", "/server-status", "/server-info",
        "/metrics", "/health", "/info",
        "/phpinfo.php", "/info.php", "/php-info.php",
        "/_profiler", "/_profiler/latest/exception",
        "/api/debug", "/api/config",
        "/console", "/rails/info/properties",
        "/_ah/admin",  # GAE
    ]

    sensitive_debug_kws = [
        "secret", "password", "api_key", "aws_", "database_url",
        "RAILS_ENV", "APP_ENV", "NODE_ENV", "DEBUG", "private",
    ]

    for path in debug_paths:
        url = base + path
        r   = _get(url)
        if not r or r.status_code not in (200, 206):
            continue
        ct = r.headers.get("Content-Type", "").lower()
        # Only flag if it looks like data, not a login page
        if "text/html" in ct and r.text.count("<") > 20:
            if "springboot" not in r.text.lower() and "actuator" not in url:
                continue
        found_kws = [kw for kw in sensitive_debug_kws if kw.lower() in r.text.lower()]
        severity  = "critical" if found_kws else "medium"
        findings.append({
            "issue":    f"Debug/diagnostic endpoint exposed: {path}",
            "severity": severity,
            "owasp":    "A05",
            "url":      url,
            "status":   r.status_code,
            "sensitive_keywords": found_kws,
            "snippet":  r.text[:400],
            "detail":   (
                f"Endpoint {path} accessible"
                + (f" with sensitive data: {', '.join(found_kws)}" if found_kws else "")
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_pivot(
    target: str,
    urls: list[str],
    params: list[str],
    ai=None,
) -> dict:
    base_url = target if target.startswith("http") else f"https://{target}"

    # Collect SSRF-capable params from discovered URLs
    from urllib.parse import parse_qs
    ssrf_params: list[str] = []
    for url in (params or [])[:50]:
        for p in parse_qs(urlparse(url).query).keys():
            if p.lower() in _SSRF_PARAMS and p not in ssrf_params:
                ssrf_params.append(p)

    print("    [*] Pivot: cloud metadata probes ...")
    cloud_findings = _cloud_metadata_probe(base_url, ssrf_params)

    print("    [*] Pivot: CI/CD + secret file discovery ...")
    cicd_findings  = _cicd_discovery(base_url)

    print("    [*] Pivot: container / Kubernetes probes ...")
    k8s_findings   = _container_k8s_probe(base_url)

    print("    [*] Pivot: debug endpoint + env var exposure ...")
    env_findings   = _env_secret_probe(base_url)

    all_findings = cloud_findings + cicd_findings + k8s_findings + env_findings

    # AI synthesis — what does this environment look like?
    ai_assessment = None
    if ai and ai.is_available() and all_findings:
        findings_text = json.dumps(
            [{"issue": f["issue"], "severity": f["severity"], "url": f.get("url","")}
             for f in all_findings[:20]],
            indent=2
        )[:2500]

        prompt = (
            "You are a senior red-team operator reviewing environment pivoting findings.\n\n"
            f"Target: {target}\n"
            f"Pivoting findings:\n{findings_text}\n\n"
            "Assess:\n"
            "1. What is the likely deployment environment? (cloud provider, container platform, serverless)\n"
            "2. What is the most dangerous pivot path from these findings?\n"
            "3. What additional manual steps should the tester take to confirm cloud/container compromise?\n"
            "4. Are any of these findings false positives?\n\n"
            "Return ONLY valid JSON:\n"
            '{"environment": "...", "most_dangerous_path": "...", '
            '"manual_steps": ["..."], "false_positives": ["url_or_issue_that_is_FP"]}'
        )
        ai_assessment = ai.ask_json(prompt, model="deep")

    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    high     = sum(1 for f in all_findings if f.get("severity") == "high")

    return {
        "cloud":        cloud_findings,
        "cicd":         cicd_findings,
        "container_k8s": k8s_findings,
        "env_debug":    env_findings,
        "all_findings": all_findings,
        "ai_assessment": ai_assessment,
        "summary": {
            "total":    len(all_findings),
            "critical": critical,
            "high":     high,
        },
    }
