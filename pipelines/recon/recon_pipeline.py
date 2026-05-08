import os
import re
import math
import json
import socket
import tempfile
import warnings
import urllib3
import requests
from collections import Counter
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.run_cmd import run_cmd, dedupe
from core.dns_recon import dns_records
from core.leak_recon import leak_recon

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# Paths checked in order for DNS brute-force wordlist
_DNS_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    os.path.join(os.path.dirname(__file__), "../../wordlists/dns_common.txt"),
]

# ===========================================================================
# JS analysis helpers
# ===========================================================================

_JS_SKIP_KEYWORDS = {
    "jquery", "bootstrap", "vendor", "polyfill", "lodash", "underscore",
    "react", "angular", "vue", "backbone", "modernizr", "moment", "axios",
    "webpack", "chunk", "runtime", "manifest", ".min.",
}
_JS_PRIORITY_KEYWORDS = [
    "config", "env", "setting", "secret", "key", "auth", "token",
    "api", "admin", "user", "account", "payment", "credential",
    "app", "main", "index", "init", "service",
]
_SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                                                              "AWS Access Key ID"),
    (r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',          "AWS Secret Key"),
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',         "API Key"),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',                  "Hardcoded Password"),
    (r'(?i)(?:secret|token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',      "Secret / Token"),
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',                             "PEM Private Key"),
    (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',                    "JWT Token"),
    (r'(?i)(?:mongodb|postgres|mysql|redis)\+?://\S+:\S+@\S+',                        "DB Connection String"),
    (r'(?i)(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}',                                "Stripe Key"),
    (r'(?i)gh[pousr]_[A-Za-z0-9]{36}',                                                "GitHub Token"),
    (r'(?i)xox[baprs]-[A-Za-z0-9\-]{10,}',                                            "Slack Token"),
    (r'(?i)AIza[0-9A-Za-z_\-]{35}',                                                   "Google API Key"),
    (r'(?i)SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',                             "SendGrid Key"),
    (r'(?i)(?:authorization|auth)\s*[=:]\s*["\'](?:basic|bearer)\s+([A-Za-z0-9+/=]{20,})["\']',
     "Hardcoded Auth Header"),
]


def _shannon_entropy(s: str) -> float:
    if len(s) < 20:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _high_entropy_strings(content: str) -> list[str]:
    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{20,100})["\']', content)
    hits = [s for s in candidates if _shannon_entropy(s) > 4.5 and not s.startswith("http")]
    return list(dict.fromkeys(hits))[:10]


def _find_js_urls(urls: list[str]) -> list[str]:
    js_raw = [u for u in urls if re.search(r'\.js(\?|$)', u)]
    filtered = [u for u in js_raw if not any(kw in u.rsplit("/", 1)[-1].lower() for kw in _JS_SKIP_KEYWORDS)]

    def _score(url: str) -> int:
        name = url.rsplit("/", 1)[-1].lower()
        for i, kw in enumerate(_JS_PRIORITY_KEYWORDS):
            if kw in name:
                return i
        return len(_JS_PRIORITY_KEYWORDS)

    filtered.sort(key=_score)
    return dedupe(filtered)[:20]


def _analyze_js_file(url: str, ai=None) -> dict | None:
    try:
        r = requests.get(url, timeout=10, verify=False, headers=_HEADERS)
        if r.status_code != 200 or len(r.content) > 500_000:
            return None
    except Exception:
        return None

    content  = r.text
    filename = url.rsplit("/", 1)[-1].split("?")[0]

    secrets = []
    for pattern, label in _SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            value   = (m.group(1) if m.lastindex else m.group(0))[:80]
            context = content[max(0, m.start() - 40): m.end() + 40].strip()
            secrets.append({"type": label, "snippet": value, "context": context})

    endpoints: list[str] = []
    for pat in [
        r'''(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:get|post))\s*\(\s*[`'"](/[^`'"]{3,60})[`'"]''',
        r'''(?:url|endpoint|path|route)\s*[=:]\s*[`'"](/[a-zA-Z0-9/_\-\.]{3,60})[`'"]''',
        r'''[`'"](/api/[^\s`'"<>]{3,60})[`'"]''',
    ]:
        endpoints.extend(re.findall(pat, content))
    endpoints = list(dict.fromkeys(endpoints))[:20]

    entropy_hits = _high_entropy_strings(content)
    is_priority  = any(kw in filename.lower() for kw in _JS_PRIORITY_KEYWORDS)
    needs_ai     = bool(secrets or entropy_hits or is_priority)

    ai_result = None
    if ai and ai.is_available() and needs_ai:
        prompt = (
            f"JavaScript file: {filename}\nURL: {url}\n\n"
            f"Content (first 3000 chars):\n{content[:3000]}\n\n"
            "Security analysis — look for:\n"
            "1. Hardcoded secrets / credentials (API keys, passwords, tokens)\n"
            "2. Encoded / obfuscated values: base64, hex, simple XOR — try to decode\n"
            "3. Sensitive API endpoints and internal service URLs\n"
            "4. Config leaks: DB hostnames, internal service names, env variable hints\n"
            "5. Auth flows that reveal weaknesses or attack entry points\n\n"
            "Return ONLY valid JSON:\n"
            '{"secrets":[{"type":"...","value":"...","risk":"high/medium/low","decoded_if_encoded":"..."}],'
            '"endpoints":["..."],'
            '"sensitive_configs":[{"key":"...","value":"..."}],'
            '"encoded_values":[{"raw":"...","encoding":"base64/hex/other","decoded":"..."}],'
            '"summary":"...","risk_level":"high/medium/low/info"}'
        )
        ai_result = ai.ask_json(prompt, model="deep")

    if not secrets and not endpoints and not entropy_hits and not ai_result:
        return None

    return {
        "url":          url,
        "filename":     filename,
        "secrets":      secrets,
        "endpoints":    endpoints,
        "entropy_hits": entropy_hits,
        "ai_analysis":  ai_result,
        "risk_level":   "high" if secrets else ("medium" if entropy_hits else "low"),
    }


# ===========================================================================
# OSINT & Entity Mapping
# ===========================================================================

def _asn_discovery(target: str) -> dict:
    """Find ASN, organisation, and owned IP prefixes via BGPView API (free, no key)."""
    result: dict = {"asn": None, "org": None, "country": None, "ip": None, "prefixes": []}
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
    except Exception:
        return result

    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}",
                         headers=_HEADERS, timeout=10, verify=False)
        if r.status_code == 200:
            prefixes = r.json().get("data", {}).get("prefixes", [])
            if prefixes:
                asn_data         = prefixes[0].get("asn", {})
                result["asn"]    = asn_data.get("asn")
                result["org"]    = asn_data.get("description")
                result["country"] = asn_data.get("country_code")
    except Exception:
        pass

    if result["asn"]:
        try:
            r2 = requests.get(f"https://api.bgpview.io/asn/{result['asn']}/prefixes",
                              headers=_HEADERS, timeout=10, verify=False)
            if r2.status_code == 200:
                result["prefixes"] = [
                    p.get("prefix") for p in
                    r2.json().get("data", {}).get("ipv4_prefixes", [])
                    if p.get("prefix")
                ][:20]
        except Exception:
            pass

    # amass intel can also surface related IP ranges
    amass_out = run_cmd(f"amass intel -d {target} -whois -silent", timeout=60)
    result["related_ips"] = [
        l.strip() for l in amass_out
        if re.match(r'^\d+\.\d+\.\d+\.\d+(/\d+)?$', l.strip())
    ][:10]

    return result


def _reverse_whois(target: str) -> list[str]:
    """
    Find sibling domains owned by the same entity.
    Uses Whoxy API if WHOXY_API_KEY is set; falls back to amass intel.
    """
    related: list[str] = []
    api_key = os.getenv("WHOXY_API_KEY", "").strip()

    if api_key:
        keyword = target.split(".")[0]
        try:
            r = requests.get(
                f"https://api.whoxy.com/?key={api_key}&reverse=whois"
                f"&name={keyword}&mode=domains",
                headers=_HEADERS, timeout=15, verify=False,
            )
            if r.status_code == 200:
                for entry in r.json().get("search_result", []):
                    d = entry.get("domain_name", "")
                    if d and d != target:
                        related.append(d)
        except Exception:
            pass

    if not related:
        # Free fallback: amass intel finds related domains via cert transparency + WHOIS
        amass_out = run_cmd(f"amass intel -d {target} -whois -silent", timeout=90)
        for line in amass_out:
            line = line.strip()
            if "." in line and " " not in line and not line.startswith("["):
                related.append(line)

    return dedupe(related)[:50]


def _cloud_asset_scan(target: str) -> dict:
    """
    Brute-force public cloud storage (S3, Azure Blobs, GCP buckets) using cloud_enum.
    Uses the target's second-level domain as the keyword.
    """
    parts   = target.rstrip(".").split(".")
    keyword = parts[-2] if len(parts) >= 2 else parts[0]

    assets: dict = {"s3": [], "azure": [], "gcp": [], "raw": []}
    for cmd in [
        f"cloud_enum -k {keyword} --disable-brute",
        f"python3 /opt/cloud_enum/cloud_enum.py -k {keyword} --disable-brute",
        f"cloud-enum -k {keyword} --disable-brute",
    ]:
        lines = run_cmd(cmd, timeout=120)
        if lines:
            assets["raw"] = lines
            for line in lines:
                lo = line.lower()
                if "s3.amazonaws.com" in lo or "s3://" in lo:
                    assets["s3"].append(line.strip())
                elif "blob.core.windows.net" in lo or "azurewebsites" in lo:
                    assets["azure"].append(line.strip())
                elif "storage.googleapis.com" in lo or "appspot.com" in lo:
                    assets["gcp"].append(line.strip())
            break

    return assets


# ===========================================================================
# Passive subdomain sources (parallel, no tools required)
# ===========================================================================

def _passive_crtsh(domain: str) -> list[str]:
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         headers=_HEADERS, timeout=30, verify=False)
        if r.status_code != 200:
            return []
        subs: set[str] = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        return list(subs)
    except Exception:
        return []


def _passive_hackertarget(domain: str) -> list[str]:
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         headers=_HEADERS, timeout=20, verify=False)
        if r.status_code != 200 or r.text.startswith("error"):
            return []
        subs = []
        for line in r.text.splitlines():
            host = line.split(",")[0].strip()
            if host.endswith(f".{domain}") or host == domain:
                subs.append(host)
        return subs
    except Exception:
        return []


def _passive_alienvault(domain: str) -> list[str]:
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=_HEADERS, timeout=20, verify=False)
        if r.status_code != 200:
            return []
        subs: set[str] = set()
        for record in r.json().get("passive_dns", []):
            host = record.get("hostname", "")
            if host.endswith(f".{domain}") or host == domain:
                subs.add(host)
        return list(subs)
    except Exception:
        return []


def _passive_wayback_subs(domain: str) -> list[str]:
    try:
        r = requests.get(
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=500",
            headers=_HEADERS, timeout=30, verify=False)
        if r.status_code != 200:
            return []
        subs: set[str] = set()
        for entry in r.json()[1:]:
            host = urlparse(entry[0]).netloc.split(":")[0]
            if host.endswith(f".{domain}") or host == domain:
                subs.add(host)
        return list(subs)
    except Exception:
        return []


def _run_passive_sources(domain: str) -> tuple[list[str], dict[str, int]]:
    sources = {
        "crt.sh":       _passive_crtsh,
        "HackerTarget": _passive_hackertarget,
        "AlienVault":   _passive_alienvault,
        "Wayback":      _passive_wayback_subs,
    }
    combined: list[str] = []
    counts:   dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(fn, domain): name for name, fn in sources.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result       = future.result()
                counts[name] = len(result)
                combined.extend(result)
            except Exception:
                counts[name] = 0
    return combined, counts


# ===========================================================================
# Permutation & brute-force
# ===========================================================================

def _get_dns_wordlist() -> str | None:
    for path in _DNS_WORDLIST_PATHS:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return None


def _alterx_permute(subs: list[str]) -> list[str]:
    """Generate subdomain mutations (e.g. dev-api, api2, api-prod) using alterx."""
    if not subs:
        return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(subs[:500]))
        tmp_path = tmp.name
    lines = run_cmd(f"alterx -l {tmp_path} -silent", timeout=120)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    return lines


def _shuffledns_bruteforce(domain: str) -> list[str]:
    """High-volume DNS brute-force using shuffledns."""
    wordlist = _get_dns_wordlist()
    if not wordlist:
        return []
    return run_cmd(f"shuffledns -d {domain} -w {wordlist} -silent", timeout=300)


# ===========================================================================
# DNS resolution — puredns (wildcard-aware) with dnsx fallback
# ===========================================================================

def _puredns_resolve(subs: list[str]) -> list[str]:
    """Resolve subdomains with wildcard detection via puredns."""
    if not subs:
        return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(subs))
        tmp_path = tmp.name
    lines = run_cmd(f"puredns resolve {tmp_path} -q", timeout=180)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    return dedupe([l.strip() for l in lines if l.strip()])


def _dnsx_resolve(subs: list[str]) -> list[str]:
    if not subs:
        return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(subs))
        tmp_path = tmp.name
    lines = run_cmd(f"dnsx -l {tmp_path} -silent", timeout=120)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    return dedupe(lines)


# ===========================================================================
# HTTP footprinting — extended ports, tech detection, JSON output
# ===========================================================================

def _httpx_scan(hosts: list[str]) -> tuple[list[str], list[dict]]:
    """
    Probe hosts on common web ports, extract title, tech stack, status codes.
    Returns (live_urls, web_data_list).
    """
    if not hosts:
        return [], []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(hosts))
        tmp_path = tmp.name

    lines = run_cmd(
        f"httpx -l {tmp_path} "
        "-p 80,443,8080,8443,9000,9443 "
        "-title -tech-detect -status-code -follow-redirects "
        "-json -silent",
        timeout=180,
    )
    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    live_urls: list[str] = []
    web_data:  list[dict] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            url   = entry.get("url", "")
            if not url:
                continue
            live_urls.append(url)
            web_data.append({
                "url":       url,
                "status":    entry.get("status-code", entry.get("status_code")),
                "title":     entry.get("title", ""),
                "tech":      entry.get("tech", entry.get("technologies", [])),
                "ip":        entry.get("host", entry.get("ip", "")),
                "webserver": entry.get("webserver", ""),
            })
        except (json.JSONDecodeError, ValueError):
            if line.startswith("http"):
                live_urls.append(line)

    # Graceful fallback: plain httpx if JSON mode returned nothing
    if not live_urls and hosts:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(hosts))
            tmp_path2 = tmp.name
        plain = run_cmd(f"httpx -silent -l {tmp_path2}", timeout=120)
        try:
            os.unlink(tmp_path2)
        except Exception:
            pass
        live_urls = dedupe(plain)

    return dedupe(live_urls), web_data


def _gowitness_screenshots(hosts: list[str]) -> str | None:
    """Capture screenshots of live hosts with gowitness for visual recon."""
    if not hosts:
        return None
    out_dir = tempfile.mkdtemp(prefix="phantomai_screenshots_")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(hosts[:50]))
        tmp_path = tmp.name

    for cmd in [
        f"gowitness scan file --file {tmp_path} --screenshot-path {out_dir}",
        f"gowitness file -f {tmp_path} --screenshot-path {out_dir}",
    ]:
        run_cmd(cmd, timeout=180)
        if any(f.endswith(".png") for f in os.listdir(out_dir)):
            break

    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    count = len([f for f in os.listdir(out_dir) if f.endswith(".png")])
    if count:
        return out_dir
    try:
        os.rmdir(out_dir)
    except Exception:
        pass
    return None


# ===========================================================================
# Port scanning — naabu (fast discovery) + nmap -sV -sC (deep fingerprint)
# ===========================================================================

def _extract_ips(web_data: list[dict]) -> list[str]:
    seen: set[str] = set()
    ips: list[str] = []
    for entry in web_data:
        ip = entry.get("ip", "")
        if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def _full_port_scan(targets: list[str]) -> dict[str, list[str]]:
    """
    Stage 1: naabu — fast top-1000 TCP port sweep.
    Stage 2: nmap -sV -sC — service version + script scan on open ports.
    Fallback: nmap -F if naabu is not installed.
    Returns {host: ["22/tcp openssh 8.9", "443/tcp https nginx", ...]}
    """
    if not targets:
        return {}

    capped = targets[:10]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(capped))
        targets_file = tmp.name

    open_ports: dict[str, list[int]] = {}

    # Stage 1: naabu fast sweep
    naabu_lines = run_cmd(
        f"naabu -l {targets_file} -top-ports 1000 -rate 1000 -silent",
        timeout=180,
    )
    for line in naabu_lines:
        if ":" in line:
            host, _, port = line.rpartition(":")
            try:
                open_ports.setdefault(host.strip(), []).append(int(port.strip()))
            except ValueError:
                pass

    # Fallback to nmap -F if naabu not installed
    if not open_ports:
        for t in capped[:5]:
            for line in run_cmd(f"nmap -T4 -F --open -oG - {t}", timeout=120):
                for port, proto, _ in re.findall(r'(\d+)/open/(tcp|udp)//(\w+)', line):
                    open_ports.setdefault(t, []).append(int(port))

    try:
        os.unlink(targets_file)
    except Exception:
        pass

    if not open_ports:
        return {}

    # Stage 2: nmap -sV -sC on discovered ports
    final: dict[str, list[str]] = {}
    for host, ports in list(open_ports.items())[:5]:
        port_str = ",".join(str(p) for p in sorted(set(ports))[:30])
        svc_lines = run_cmd(
            f"nmap -sV -sC -p {port_str} -T4 --open -oG - {host}",
            timeout=180,
        )
        services: list[str] = []
        for line in svc_lines:
            for port, proto, svc in re.findall(r'(\d+)/open/(tcp|udp)//([^\s/]+)', line):
                services.append(f"{port}/{proto} {svc}")
        final[host] = services if services else [f"{p}/tcp" for p in ports]

    return final


# ===========================================================================
# Site crawling
# ===========================================================================

def _crawl_target(target: str) -> list[str]:
    base_url = target if target.startswith("http") else f"https://{target}"

    lines = run_cmd(f"katana -u {base_url} -silent -d 3 -jc -kf all", timeout=180)
    if lines:
        return [l for l in lines if l.startswith("http")]

    lines = run_cmd(f"gospider -s {base_url} -c 10 -d 3 -q", timeout=180)
    if lines:
        urls = []
        for l in lines:
            parts = l.split("] ")
            url   = parts[-1].strip() if parts else l.strip()
            if url.startswith("http"):
                urls.append(url)
        return urls

    lines = run_cmd(f"hakrawler -url {base_url} -depth 3", timeout=120)
    return [l for l in lines if l.startswith("http")]


# ===========================================================================
# Shodan lookup (optional — SHODAN_API_KEY env var)
# ===========================================================================

def _shodan_lookup(target: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    result: dict = {"services": [], "vulns": [], "ports": [], "tags": [], "error": None}
    if not api_key:
        return result
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        result["error"] = "DNS resolution failed"
        return result
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10,
            headers=_HEADERS,
        )
        if r.status_code == 404:
            result["error"] = "not in Shodan index"
            return result
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result
        data = r.json()
        result["ports"]  = data.get("ports", [])
        result["tags"]   = data.get("tags", [])
        result["vulns"]  = list(data.get("vulns", {}).keys())
        for service in data.get("data", []):
            result["services"].append({
                "port":     service.get("port"),
                "proto":    service.get("transport"),
                "product":  service.get("product", ""),
                "version":  service.get("version", ""),
                "cpe":      service.get("cpe", []),
                "banner":   service.get("data", "")[:200],
            })
    except Exception as e:
        result["error"] = str(e)
    return result


# ===========================================================================
# Main recon pipeline
# ===========================================================================

def run_recon(target: str, ai=None) -> dict:
    results: dict = {}

    # ── Phase 1a: OSINT & Entity Mapping (parallel) ──────────────────────────
    print("    [*] OSINT: ASN, WHOIS, cloud assets, DNS records, leaks, Shodan ...")

    # Extract base domain for DNS/leak recon (strip subdomains)
    parts = target.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else target

    with ThreadPoolExecutor(max_workers=6) as pool:
        asn_f    = pool.submit(_asn_discovery,   target)
        whois_f  = pool.submit(_reverse_whois,   target)
        cloud_f  = pool.submit(_cloud_asset_scan, target)
        dns_f    = pool.submit(dns_records,       base_domain)
        leak_f   = pool.submit(leak_recon,        base_domain)
        shodan_f = pool.submit(_shodan_lookup,    target)

        asn_info        = asn_f.result()
        related_domains = whois_f.result()
        cloud_assets    = cloud_f.result()
        dns_data        = dns_f.result()
        leak_data       = leak_f.result()
        shodan_data     = shodan_f.result()

    results["asn_info"]        = asn_info
    results["related_domains"] = related_domains
    results["cloud_assets"]    = cloud_assets
    results["dns_records"]     = dns_data
    results["leak_recon"]      = leak_data
    results["shodan"]          = shodan_data

    if asn_info.get("asn"):
        print(f"    [+] ASN: AS{asn_info['asn']} ({asn_info.get('org','?')}) "
              f"— {len(asn_info.get('prefixes', []))} IP prefix(es)")
    if related_domains:
        print(f"    [+] Reverse WHOIS: {len(related_domains)} related domain(s)")
    total_cloud = sum(len(v) for k, v in cloud_assets.items() if k != "raw")
    if total_cloud:
        print(f"    [+] Cloud assets: {total_cloud} bucket(s)/blob(s) found "
              f"(S3:{len(cloud_assets['s3'])} Azure:{len(cloud_assets['azure'])} "
              f"GCP:{len(cloud_assets['gcp'])})")

    dns_issues = dns_data.get("security_issues", [])
    if dns_issues:
        critical = [i for i in dns_issues if i.get("risk") == "critical"]
        high     = [i for i in dns_issues if i.get("risk") == "high"]
        print(f"    [+] DNS records: {len(dns_data.get('ns',[]))} NS, "
              f"{len(dns_data.get('mx',[]))} MX | "
              f"{len(dns_issues)} security issue(s) "
              f"({len(critical)} critical, {len(high)} high)")
        if dns_data.get("zone_transfer"):
            print(f"    [!] ZONE TRANSFER ALLOWED — {len(dns_data['zone_transfer'])} record(s) exposed!")

    if leak_data.get("summary"):
        for line in leak_data["summary"]:
            print(f"    [+] {line}")

    if shodan_data.get("ports"):
        vuln_count = len(shodan_data.get("vulns", []))
        print(f"    [+] Shodan: {len(shodan_data['ports'])} port(s) indexed"
              + (f", {vuln_count} CVE(s)" if vuln_count else ""))

    # ── Phase 1b: Subdomain Enumeration ──────────────────────────────────────
    print("    [*] Passive sources: crt.sh, HackerTarget, AlienVault, Wayback ...")
    passive_subs, passive_counts = _run_passive_sources(target)
    count_str = " | ".join(f"{n}:{c}" for n, c in passive_counts.items())
    print(f"    [+] Passive — {count_str}")

    print("    [*] Active: subfinder -all, assetfinder, amass ...")
    subfinder   = run_cmd(f"subfinder -d {target} -all -silent",      timeout=120)
    assetfinder = run_cmd(f"assetfinder {target}",                     timeout=60)
    amass       = run_cmd(f"amass enum -passive -d {target}",          timeout=180)
    base_subs   = dedupe(passive_subs + subfinder + assetfinder + amass)

    # Permutation + brute-force in parallel
    print("    [*] Permutation (alterx) & brute-force (shuffledns) ...")
    with ThreadPoolExecutor(max_workers=2) as pool:
        alterx_f    = pool.submit(_alterx_permute,        base_subs)
        shuffledns_f = pool.submit(_shuffledns_bruteforce, target)
        permuted = alterx_f.result()
        bruted   = shuffledns_f.result()

    all_subs = dedupe(base_subs + permuted + bruted)
    print(f"    [+] Total unique candidates: {len(all_subs)} "
          f"(base:{len(base_subs)} permuted:{len(permuted)} bruted:{len(bruted)})")

    # ── Phase 1c: DNS Resolution — puredns → dnsx → raw ──────────────────────
    dns_valid = all_subs
    if all_subs:
        resolved = _puredns_resolve(all_subs)
        if resolved:
            dns_valid = resolved
            print(f"    [+] puredns: {len(all_subs)} → {len(dns_valid)} DNS-valid (wildcard-filtered)")
        else:
            resolved = _dnsx_resolve(all_subs)
            if resolved:
                dns_valid = resolved
                print(f"    [+] dnsx: {len(all_subs)} → {len(dns_valid)} DNS-valid")
            else:
                print(f"    [!] No DNS resolver found — using all {len(all_subs)} candidates")

    results["subdomains"] = dns_valid

    # ── Phase 1d: HTTP Footprinting ──────────────────────────────────────────
    print("    [*] HTTP footprinting: extended ports + tech detection ...")
    live_hosts, web_data = _httpx_scan(dns_valid)
    results["live_hosts"] = live_hosts
    results["web_data"]   = web_data

    # Screenshots (non-blocking — skip if gowitness is slow/missing)
    screenshots_dir = _gowitness_screenshots(live_hosts)
    if screenshots_dir:
        results["screenshots_dir"] = screenshots_dir
        png_count = len([f for f in os.listdir(screenshots_dir) if f.endswith(".png")])
        print(f"    [+] Screenshots: {png_count} saved → {screenshots_dir}")

    # ── Phase 1e: Port Scanning — naabu + nmap -sV -sC ───────────────────────
    print("    [*] Port scanning: naabu (fast) + nmap -sV -sC (deep) ...")
    ips     = _extract_ips(web_data)
    targets = ips if ips else [
        urlparse(h).netloc.split(":")[0] for h in live_hosts[:10] if h
    ]
    port_results = _full_port_scan(targets)
    results["port_scan"] = port_results

    if port_results:
        port_summary = " | ".join(
            f"{h}: {', '.join(p[:4])}" for h, p in list(port_results.items())[:3]
        )
        print(f"    [+] Ports — {port_summary}")

    # ── Phase 1f: Site Crawling + URL Gathering (parallel) ───────────────────
    print("    [*] Crawling & URL gathering (parallel) ...")
    with ThreadPoolExecutor(max_workers=2) as pool:
        crawl_f  = pool.submit(_crawl_target, target)
        gau_f    = pool.submit(run_cmd, f"gau {target}", 120)
        wb_f     = pool.submit(run_cmd, f"waybackurls {target}", 120)
        crawled_urls = crawl_f.result()
        gau_urls     = gau_f.result()
        wb_urls      = wb_f.result()

    results["crawled_urls"] = dedupe(crawled_urls)
    print(f"    [+] Crawled {len(results['crawled_urls'])} URLs")

    raw_urls = dedupe(gau_urls + wb_urls + crawled_urls)

    # ── Phase 1g: JS File Discovery & Analysis ───────────────────────────────
    print("    [*] Discovering JavaScript files ...")
    js_urls     = _find_js_urls(raw_urls)
    js_findings: list[dict] = []

    if js_urls:
        print(f"    [*] Analysing {len(js_urls)} JS files for secrets, config leaks & endpoints ...")
        for js_url in js_urls:
            finding = _analyze_js_file(js_url, ai=ai)
            if finding:
                js_findings.append(finding)
        high = sum(1 for f in js_findings if f.get("risk_level") == "high")
        print(f"    [+] JS: {len(js_findings)} interesting files ({high} high-risk)")

        # Feed JS-discovered endpoints back into the URL pool
        for finding in js_findings:
            for ep in finding.get("endpoints", []):
                if ep.startswith("/"):
                    raw_urls.append(f"https://{target}{ep}")
            ai_eps = (finding.get("ai_analysis") or {}).get("endpoints", [])
            for ep in ai_eps:
                if isinstance(ep, str) and ep.startswith("/"):
                    raw_urls.append(f"https://{target}{ep}")

    results["js_findings"] = js_findings

    # ── Phase 1h: AI URL Prioritisation ──────────────────────────────────────
    if ai and ai.is_available() and len(raw_urls) > 20:
        url_text = "\n".join(raw_urls)
        prompt = (
            f"Target domain: {target}\n"
            f"Discovered URLs ({len(raw_urls)} total, first 2000 chars):\n"
            f"{url_text[:2000]}\n\n"
            "Return the top 50 most interesting attack-surface URLs. "
            "Prioritise: URLs with query parameters, admin/panel paths, API endpoints, "
            "file upload paths, authentication paths, backup/config files. "
            "Return ONLY a newline-separated list of URLs, no commentary."
        )
        ai_response = ai.ask(prompt, model="fast")
        if ai_response:
            prioritised = [u.strip() for u in ai_response.splitlines()
                           if u.strip().startswith("http")]
            if len(prioritised) >= 10:
                raw_urls = prioritised

    results["urls"] = dedupe(raw_urls)[:200]
    return results
