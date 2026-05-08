import os
import json
import tempfile
import warnings
import urllib3
import requests
from urllib.parse import urlparse, parse_qs
from core.run_cmd import run_cmd, dedupe

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_WORDLIST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"))
WORDLIST_PATH = os.path.join(_WORDLIST_DIR, "dirs.txt")

_DIR_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    WORDLIST_PATH,
]

_PARAM_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/seclists/Discovery/Web-Content/common-query-parameter-names.txt",
    os.path.join(_WORDLIST_DIR, "params.txt"),
]

# Swagger / OpenAPI discovery paths
_SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/api-docs.json", "/api-docs/swagger.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/docs/swagger.json", "/swagger/v1/swagger.json",
    "/swagger/index.html", "/swagger-ui.html",
    "/redoc", "/api/redoc",
    "/.well-known/openapi",
]

# GraphQL endpoints to probe
_GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/graphiql",
    "/v1/graphql", "/v2/graphql", "/query",
    "/api/query", "/gql", "/api/gql",
]

# Internal / DevOps service fingerprints: (path, port, service_name)
_INTERNAL_SERVICES = [
    (":8080",  "/",             "Jenkins / Tomcat"),
    (":8080",  "/jenkins",      "Jenkins"),
    (":3000",  "/api/health",   "Grafana"),
    (":3000",  "/login",        "Grafana"),
    (":5601",  "/app/kibana",   "Kibana"),
    (":9200",  "/",             "Elasticsearch"),
    (":9200",  "/_cat/indices", "Elasticsearch"),
    (":2375",  "/version",      "Docker daemon (unauthenticated)"),
    (":2376",  "/version",      "Docker daemon TLS"),
    (":9090",  "/metrics",      "Prometheus"),
    (":9090",  "/graph",        "Prometheus"),
    (":6379",  "/",             "Redis"),
    (":5432",  "/",             "PostgreSQL"),
    (":27017", "/",             "MongoDB"),
    (":4848",  "/common/index", "GlassFish Admin"),
    (":8161",  "/admin",        "ActiveMQ Admin"),
    (":15672", "/",             "RabbitMQ Management"),
    (":8888",  "/",             "Jupyter Notebook"),
    (":8500",  "/ui/",          "Consul UI"),
    (":8200",  "/ui/",          "Vault UI"),
]

_GRAPHQL_INTROSPECTION = """{"query":"{\n  __schema {\n    types { name }\n  }\n}"}"""
_GRAPHQL_INTROSPECTION_FULL = (
    '{"query":"fragment FullType on __Type { kind name description fields(includeDeprecated:true)'
    '{ name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason}'
    ' inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated:true)'
    '{ name description isDeprecated deprecationReason } possibleTypes { ...TypeRef }}'
    'fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue}'
    'fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType'
    '{ kind name ofType { kind name ofType { kind name ofType { kind name }}}}}}}'
    'query IntrospectionQuery { __schema { queryType { name } mutationType { name }'
    ' subscriptionType { name } types { ...FullType } directives { name description locations args'
    ' { ...InputValue }}}}"}'
)


def _best_wordlist(paths: list[str]) -> str:
    for p in paths:
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            return p
    return paths[-1]


def _feroxbuster_scan(target_url: str, wordlist: str) -> list[str]:
    lines = run_cmd(
        f"feroxbuster --url {target_url} -w {wordlist} "
        "-x php,asp,aspx,jsp,json,bak,zip,txt,conf,xml,sql "
        "-q --no-state --silent "
        "-s 200,204,301,302,307,401,403",
        timeout=180,
    )
    urls: list[str] = []
    for line in lines:
        parts = line.strip().split()
        for part in reversed(parts):
            if part.startswith("http"):
                urls.append(part)
                break
    return dedupe(urls)


def _ffuf_dir_scan(target: str, wordlist: str) -> list[str]:
    lines = run_cmd(
        f"ffuf -u https://{target}/FUZZ -w {wordlist} "
        "-mc 200,204,301,302,307,401,403 -c -t 40 -s",
        timeout=120,
    )
    return lines[:300]


def _param_discovery(target_urls: list[str], wordlist: str) -> list[str]:
    discovered: list[str] = []
    candidates = [u for u in target_urls if "?" not in u][:5]
    if not candidates:
        return []
    for url in candidates:
        lines = run_cmd(
            f"ffuf -u {url}?FUZZ=phantomai_probe -w {wordlist} "
            "-mc 200,204,301,302,307,400,401,403 "
            "-fs 0 -s -t 30",
            timeout=90,
        )
        for line in lines:
            param = line.strip().split()[0] if line.strip() else ""
            if param and "phantomai" not in param.lower():
                discovered.append(f"{url}?{param}=")
    return dedupe(discovered)


def _swagger_discovery(base_url: str) -> list[dict]:
    found: list[dict] = []
    for path in _SWAGGER_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = requests.get(
                url, timeout=5, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (security-scanner)"},
                allow_redirects=True,
            )
            if r.status_code not in (200, 206):
                continue
            ct = r.headers.get("Content-Type", "").lower()
            body = r.text
            # Confirm it's actually an API spec
            if (
                ("swagger" in body.lower() or "openapi" in body.lower())
                or ("application/json" in ct and ("paths" in body or "info" in body))
                or path.endswith((".html",)) and "swagger" in body.lower()
            ):
                entry: dict = {"url": url, "path": path, "status": r.status_code}
                try:
                    spec = r.json()
                    entry["title"]    = spec.get("info", {}).get("title", "")
                    entry["version"]  = spec.get("info", {}).get("version", "")
                    entry["paths"]    = list((spec.get("paths") or {}).keys())[:20]
                    entry["spec_version"] = spec.get("openapi") or spec.get("swagger") or ""
                except Exception:
                    entry["raw_snippet"] = body[:300]
                found.append(entry)
        except Exception:
            continue
    return found


def _graphql_probe(base_url: str) -> list[dict]:
    found: list[dict] = []
    for path in _GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        for payload, label in [
            (_GRAPHQL_INTROSPECTION, "simple"),
            ('{"query":"{__typename}"}', "typename"),
        ]:
            try:
                r = requests.post(
                    url, data=payload, timeout=6, verify=False,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (security-scanner)",
                    },
                )
                if r.status_code not in (200, 400):
                    continue
                body = r.text
                if "__schema" in body or "__typename" in body or '"data"' in body:
                    entry: dict = {"url": url, "path": path, "probe": label}
                    introspection_allowed = "__schema" in body and '"types"' in body
                    entry["introspection_enabled"] = introspection_allowed
                    if introspection_allowed:
                        try:
                            data = r.json()
                            types = (data.get("data", {}).get("__schema", {})
                                     .get("types", []))
                            user_types = [t["name"] for t in types
                                          if t.get("name") and not t["name"].startswith("__")]
                            entry["types_count"] = len(user_types)
                            entry["sample_types"] = user_types[:10]
                        except Exception:
                            pass
                    found.append(entry)
                    break
            except Exception:
                continue
        if found and found[-1].get("path") == path:
            continue  # already found endpoint, skip remaining probes

    return found


def _internal_service_scan(host: str) -> list[dict]:
    found: list[dict] = []
    scheme = "https" if host.startswith("https://") else "http"
    # Strip scheme/path to get bare hostname
    bare = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    seen_ports: set = set()
    for port_str, path, service in _INTERNAL_SERVICES:
        port = port_str.lstrip(":")
        if port in seen_ports:
            continue

        url = f"{scheme}://{bare}{port_str}{path}"
        try:
            r = requests.get(
                url, timeout=3, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (security-scanner)"},
                allow_redirects=False,
            )
            if r.status_code < 500:
                found.append({
                    "url":     url,
                    "service": service,
                    "status":  r.status_code,
                    "server":  r.headers.get("Server", ""),
                })
                seen_ports.add(port)
        except Exception:
            continue

    return found


def run_enum(target: str, urls: list, stack: dict = None, ai=None) -> dict:
    results = {}

    dir_wordlist   = _best_wordlist(_DIR_WORDLIST_PATHS)
    param_wordlist = _best_wordlist(_PARAM_WORDLIST_PATHS)

    # ── AI-enhanced wordlist ──────────────────────────────────────────────────
    extra_paths: list[str] = []
    if ai and ai.is_available() and stack:
        from core.tech_fingerprint import stack_summary
        summary = stack_summary(stack)
        if summary and summary != "unknown":
            prompt = (
                f"Target web application uses: {summary}\n"
                "List 20 directory/file paths likely to exist on this stack that a pentester should check. "
                "Examples: config files, admin panels, debug endpoints, backup files, framework-specific paths. "
                "Return ONLY a newline-separated list of paths (no leading slash, no commentary)."
            )
            ai_response = ai.ask(prompt, model="fast")
            if ai_response:
                extra_paths = [p.strip().lstrip("/") for p in ai_response.splitlines() if p.strip()]

    fuzz_wordlist = dir_wordlist
    if extra_paths:
        try:
            with open(dir_wordlist, "r") as base:
                base_content = base.read()
            merged = base_content.rstrip() + "\n" + "\n".join(extra_paths)
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write(merged)
            tmp.close()
            fuzz_wordlist = tmp.name
        except Exception:
            pass

    # ── Directory / Content Discovery ─────────────────────────────────────────
    base_url = f"https://{target}" if not target.startswith("http") else target

    fuzz_out = _feroxbuster_scan(base_url, fuzz_wordlist)
    if not fuzz_out:
        fuzz_out = _ffuf_dir_scan(target, fuzz_wordlist)
    results["fuzz"] = fuzz_out[:300]

    if extra_paths and fuzz_wordlist != dir_wordlist:
        try:
            os.unlink(fuzz_wordlist)
        except Exception:
            pass

    # ── Parameter Extraction from known URLs ──────────────────────────────────
    param_urls:  list[str] = []
    param_names: set[str]  = set()
    for url in urls[:150]:
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query)
        if qs:
            param_urls.append(url)
            param_names.update(qs.keys())

    results["params"]      = dedupe(param_urls)
    results["param_names"] = list(param_names)

    # ── Hidden Parameter Discovery ────────────────────────────────────────────
    discovered_params = _param_discovery(urls[:20], param_wordlist)
    if discovered_params:
        results["discovered_params"] = discovered_params
        results["params"] = dedupe(results["params"] + discovered_params)

    # ── Swagger / OpenAPI Discovery ───────────────────────────────────────────
    swagger_hits = _swagger_discovery(base_url)
    results["swagger"] = swagger_hits
    if swagger_hits:
        # Pull all API paths discovered from specs into the URL pool
        for spec in swagger_hits:
            for p in spec.get("paths", []):
                full = base_url.rstrip("/") + p
                if full not in results["params"]:
                    param_urls.append(full)

    # ── GraphQL Introspection ─────────────────────────────────────────────────
    graphql_hits = _graphql_probe(base_url)
    results["graphql"] = graphql_hits

    # ── Internal / DevOps Service Scan ────────────────────────────────────────
    internal_hits = _internal_service_scan(base_url)
    results["internal_services"] = internal_hits

    return results
