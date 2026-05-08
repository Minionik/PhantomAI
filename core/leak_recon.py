import os
import json
import requests
from core.run_cmd import run_cmd

_URLSCAN_API = "https://urlscan.io/api/v1/search/"
_GITHUB_API  = "https://api.github.com/search/code"

_GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" credential',
    '"{domain}" private_key',
    'site:{domain} filetype:env',
    'site:{domain} filetype:sql',
]


def _urlscan_lookup(domain: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(
            _URLSCAN_API,
            params={"q": f"domain:{domain}", "size": 20},
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        data = r.json()
        for result in data.get("results", []):
            page = result.get("page", {})
            task = result.get("task", {})
            findings.append({
                "url":       page.get("url", ""),
                "ip":        page.get("ip", ""),
                "country":   page.get("country", ""),
                "server":    page.get("server", ""),
                "scan_date": task.get("time", ""),
            })
    except Exception:
        pass
    return findings


def _github_dork_search(domain: str, token: str | None) -> list[dict]:
    findings: list[dict] = []
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Without a token GitHub allows ~10 unauthenticated requests/min; limit dorks
    dorks = _GITHUB_DORKS[:3] if not token else _GITHUB_DORKS

    for dork_tmpl in dorks:
        query = dork_tmpl.format(domain=domain)
        try:
            r = requests.get(
                _GITHUB_API,
                params={"q": query, "per_page": 5},
                headers=headers,
                timeout=10,
            )
            if r.status_code == 403:
                break  # rate-limited
            data = r.json()
            for item in data.get("items", []):
                findings.append({
                    "dork":    query,
                    "repo":    item.get("repository", {}).get("full_name", ""),
                    "file":    item.get("path", ""),
                    "url":     item.get("html_url", ""),
                    "score":   item.get("score", 0),
                })
        except Exception:
            continue

    return findings


def _trufflehog_scan(target_url: str) -> list[dict]:
    findings: list[dict] = []
    # Scan public GitHub repos mentioning the domain — or the target URL directly
    lines = run_cmd(
        f"trufflehog git --json --only-verified {target_url}",
        timeout=60,
    )
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append({
                "detector": obj.get("DetectorName", ""),
                "raw":      obj.get("Raw", "")[:200],
                "source":   obj.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                "verified": obj.get("Verified", False),
            })
        except Exception:
            continue
    return findings


def _securitytrails_lookup(domain: str, api_key: str) -> dict:
    result: dict = {"subdomains": [], "associated_domains": []}
    try:
        headers = {"APIKEY": api_key, "Accept": "application/json"}
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers=headers,
            params={"children_only": "false"},
            timeout=10,
        )
        data = r.json()
        subs = data.get("subdomains", [])
        result["subdomains"] = [f"{s}.{domain}" for s in subs[:100]]
    except Exception:
        pass
    return result


def leak_recon(domain: str) -> dict:
    github_token      = os.getenv("GITHUB_TOKEN")
    securitytrails_key = os.getenv("SECURITYTRAILS_API_KEY")

    result: dict = {
        "urlscan":         [],
        "github_leaks":    [],
        "trufflehog":      [],
        "securitytrails":  {},
        "summary":         [],
    }

    result["urlscan"] = _urlscan_lookup(domain)

    result["github_leaks"] = _github_dork_search(domain, github_token)

    if securitytrails_key:
        result["securitytrails"] = _securitytrails_lookup(domain, securitytrails_key)

    # Summarise notable findings
    summary = result["summary"]
    if result["urlscan"]:
        summary.append(f"URLScan: {len(result['urlscan'])} historical scans found")

    leak_count = len([g for g in result["github_leaks"] if g.get("score", 0) > 0])
    if leak_count:
        summary.append(f"GitHub: {leak_count} potential leak(s) across "
                       f"{len(set(g['repo'] for g in result['github_leaks']))} repo(s)")

    if result["trufflehog"]:
        verified = sum(1 for t in result["trufflehog"] if t.get("verified"))
        summary.append(f"TruffleHog: {len(result['trufflehog'])} secret(s) found "
                       f"({verified} verified)")

    if result["securitytrails"].get("subdomains"):
        summary.append(f"SecurityTrails: {len(result['securitytrails']['subdomains'])} "
                       f"historical subdomain(s)")

    return result
