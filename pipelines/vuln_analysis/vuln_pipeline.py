import json
import os
import tempfile
from core.run_cmd import run_cmd_str
from core.owasp_mapper import map_finding

# Common authentication/management paths for A07 coverage
_AUTH_PATHS = [
    "login", "signin", "sign-in", "signup", "register", "logout",
    "auth", "authenticate", "oauth", "oauth2", "sso", "2fa", "mfa",
    "admin/login", "user/login", "account/login", "accounts/login",
    "api/login", "api/auth", "api/token", "api/v1/auth", "api/v1/login",
    "api/v1/token", "api/v2/auth", "api/v2/login",
    "wp-login.php", "wp-admin",
    "admin", "administrator", "dashboard", "panel", "portal",
    "forgot-password", "reset-password", "change-password",
    "verify", "confirm", "activate", "unlock",
    "session", "sessions", "token", "tokens",
    "user/register", "account/register", "accounts/register",
]


def run_vuln(target: str, urls: list, stack: dict = None, ai=None) -> dict:
    results = {}
    test_urls = urls[:5] if urls else []

    # --- A01/A03/A05/A06: Nuclei ---
    print("    [*] Running nuclei...")
    nuclei_out = run_cmd_str(
        f"nuclei -u {target} -severity medium,high,critical -silent",
        timeout=300,
    )
    results["nuclei"] = nuclei_out[:4000]

    # --- A03: XSS via Dalfox (top 5 URLs) ---
    dalfox_results = []
    if test_urls:
        print(f"    [*] Running dalfox on {len(test_urls)} URLs...")
        for url in test_urls:
            out = run_cmd_str(f"dalfox url \"{url}\" --silence", timeout=60)
            if out.strip():
                dalfox_results.append(out[:500])
    results["dalfox"] = "\n---\n".join(dalfox_results)

    # --- A03: SQLi via SQLMap (top 5 URLs) ---
    sqlmap_results = []
    if test_urls:
        print(f"    [*] Running sqlmap on {len(test_urls)} URLs...")
        for url in test_urls:
            out = run_cmd_str(f"sqlmap -u \"{url}\" --batch --level=2 --risk=2", timeout=120)
            if out.strip():
                sqlmap_results.append(out[:500])
    results["sqlmap"] = "\n---\n".join(sqlmap_results)

    # --- A02: Cryptographic Failures via sslyze ---
    print("    [*] Running sslyze (TLS/SSL check)...")
    ssl_out = run_cmd_str(f"sslyze --regular {target}", timeout=60)
    results["sslyze"] = ssl_out[:2000]

    # --- A10: SSRF probe ---
    print("    [*] Probing for SSRF...")
    ssrf_findings = []
    ssrf_payloads = [
        f"http://{target}/?url=http://169.254.169.254/latest/meta-data/",
        f"http://{target}/?redirect=http://localhost/",
        f"http://{target}/?next=http://127.0.0.1:80/",
        f"http://{target}/?file=http://169.254.169.254/",
    ]
    for probe_url in ssrf_payloads:
        out = run_cmd_str(f"curl -sk --max-time 5 \"{probe_url}\"", timeout=10)
        if any(kw in out.lower() for kw in ["ami-id", "instance-id", "metadata", "root:x:", "localhost"]):
            ssrf_findings.append({"url": probe_url, "response_snippet": out[:200]})
    results["ssrf"] = ssrf_findings

    # --- A07: Auth endpoint discovery via ffuf ---
    # Write auth paths to a temp wordlist — avoids the broken -w - (stdin) approach
    print("    [*] Fuzzing auth endpoints...")
    auth_wl = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(_AUTH_PATHS))
            auth_wl = tmp.name
        auth_fuzz = run_cmd_str(
            f"ffuf -u http://{target}/FUZZ -w {auth_wl} -mc 200,301,302,403 -c -t 20 -s",
            timeout=30,
        )
        results["auth_endpoints"] = auth_fuzz[:500]
    except Exception:
        results["auth_endpoints"] = ""
    finally:
        if auth_wl:
            try:
                os.unlink(auth_wl)
            except Exception:
                pass

    # --- AI False Positive Triage ---
    triaged = []
    if ai and ai.is_available():
        raw_for_ai = {
            "nuclei":         results["nuclei"][:1500],
            "dalfox":         results["dalfox"][:800],
            "sqlmap":         results["sqlmap"][:800],
            "sslyze":         results["sslyze"][:800],
            "ssrf":           results["ssrf"],
            "auth_endpoints": results["auth_endpoints"][:300],
        }
        triage_prompt = (
            "You are a senior penetration tester triaging automated scanner output.\n\n"
            f"Scanner findings (JSON):\n{json.dumps(raw_for_ai, indent=2)[:3000]}\n\n"
            "For each REAL, confirmed or highly likely finding:\n"
            "- Remove false positives and generic/informational noise\n"
            "- Return a JSON array where each item has:\n"
            '  { "tool": str, "finding": str, "owasp": "A01" through "A10", '
            '"severity": "critical"|"high"|"medium"|"low", '
            '"confidence": "high"|"medium"|"low", "evidence": str }\n'
            "If no real findings, return an empty array [].\n"
            "Return ONLY valid JSON, no explanation."
        )
        ai_result = ai.ask_json(triage_prompt, model="fast")
        if isinstance(ai_result, list):
            triaged = ai_result
        else:
            triaged = _fallback_triage(results)
    else:
        triaged = _fallback_triage(results)

    results["triaged"] = triaged
    return results


def _fallback_triage(results: dict) -> list:
    findings = []
    if results.get("nuclei", "").strip():
        for line in results["nuclei"].splitlines()[:10]:
            if line.strip():
                findings.append({
                    "tool": "nuclei",
                    "finding": line.strip(),
                    "owasp": map_finding(line),
                    "severity": _guess_severity(line),
                    "confidence": "medium",
                    "evidence": line.strip(),
                })
    for hit in results.get("ssrf", []):
        findings.append({
            "tool": "ssrf-probe",
            "finding": f"Potential SSRF at {hit['url']}",
            "owasp": "A10",
            "severity": "high",
            "confidence": "high",
            "evidence": hit.get("response_snippet", ""),
        })
    return findings


def _guess_severity(text: str) -> str:
    t = text.lower()
    if "critical" in t:
        return "critical"
    if "high" in t:
        return "high"
    if "medium" in t:
        return "medium"
    return "low"
