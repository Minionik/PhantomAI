import re
import json
import warnings
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_SSO_PROVIDERS = {
    "okta":       ["okta.com", "okta-hosted", ".okta."],
    "auth0":      ["auth0.com", ".auth0.com"],
    "azure_ad":   ["login.microsoftonline.com", "login.microsoft.com", "sts.windows.net"],
    "cognito":    ["cognito-idp", "amazoncognito.com"],
    "keycloak":   ["keycloak", "/realms/", "/auth/realms/"],
    "pingidentity": ["pingidentity.com", "ping-", "pinglabs"],
    "onelogin":   ["onelogin.com"],
    "jumpcloud":  ["jumpcloud.com"],
}

_OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/api/.well-known/openid-configuration",
]


def _cors_analysis(base_url: str, headers: dict) -> dict:
    result = {
        "acao": headers.get("Access-Control-Allow-Origin", ""),
        "acac": headers.get("Access-Control-Allow-Credentials", ""),
        "issues": [],
    }

    # Probe with a foreign origin
    try:
        probe = requests.get(
            base_url,
            timeout=6,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (security-scanner)",
                "Origin": "https://evil.example.com",
            },
        )
        acao = probe.headers.get("Access-Control-Allow-Origin", "")
        acac = probe.headers.get("Access-Control-Allow-Credentials", "").lower()
        result["acao"] = acao
        result["acac"] = acac

        if acao == "*":
            result["issues"].append({
                "issue":    "CORS wildcard (Access-Control-Allow-Origin: *)",
                "severity": "medium",
                "detail":   "Any origin can read responses; credentials cannot be sent with wildcard",
            })
        elif acao == "https://evil.example.com":
            if acac == "true":
                result["issues"].append({
                    "issue":    "CORS origin reflection + credentials allowed",
                    "severity": "high",
                    "detail":   "Server reflects arbitrary Origin and sets Allow-Credentials: true — "
                                "cross-origin authenticated requests are possible",
                })
            else:
                result["issues"].append({
                    "issue":    "CORS origin reflection (no credentials)",
                    "severity": "low",
                    "detail":   "Server reflects arbitrary Origin header; no credentials flag set",
                })
    except Exception:
        pass

    return result


def _cookie_security(resp_headers: dict) -> list[dict]:
    issues: list[dict] = []
    raw = resp_headers.get("Set-Cookie", "") or resp_headers.get("set-cookie", "")
    if not raw:
        return issues

    cookies = raw if isinstance(raw, list) else [raw]
    for cookie in cookies:
        c = cookie.lower()
        name = cookie.split("=")[0].strip()
        if "httponly" not in c:
            issues.append({
                "issue":    f"Cookie '{name}' missing HttpOnly flag",
                "severity": "medium",
                "detail":   "Cookie accessible via JavaScript — XSS can steal it",
            })
        if "secure" not in c:
            issues.append({
                "issue":    f"Cookie '{name}' missing Secure flag",
                "severity": "medium",
                "detail":   "Cookie transmitted over HTTP — MITM can intercept it",
            })
        if "samesite" not in c:
            issues.append({
                "issue":    f"Cookie '{name}' missing SameSite attribute",
                "severity": "low",
                "detail":   "No SameSite policy — CSRF may be possible via cross-site requests",
            })

    return issues


def _sso_fingerprint(target: str, base_url: str, resp_text: str, resp_headers: dict) -> dict:
    result: dict = {"provider": None, "oidc_endpoint": None, "issues": []}

    # Check response body + headers + location for SSO provider hints
    combined = (resp_text[:2000] + str(resp_headers)).lower()
    for provider, patterns in _SSO_PROVIDERS.items():
        for pat in patterns:
            if pat.lower() in combined:
                result["provider"] = provider
                break
        if result["provider"]:
            break

    # Try OIDC discovery endpoints on the target itself
    for path in _OIDC_PATHS:
        try:
            r = requests.get(
                f"{base_url.rstrip('/')}{path}",
                timeout=5,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (security-scanner)"},
                allow_redirects=True,
            )
            if r.status_code == 200 and "issuer" in r.text:
                result["oidc_endpoint"] = f"{base_url.rstrip('/')}{path}"
                try:
                    oidc_data = r.json()
                    issuer = oidc_data.get("issuer", "")
                    for provider, patterns in _SSO_PROVIDERS.items():
                        for pat in patterns:
                            if pat.lower() in issuer.lower():
                                result["provider"] = result["provider"] or provider
                                break
                except Exception:
                    pass
                break
        except Exception:
            continue

    return result


def fingerprint(target: str, ai=None) -> dict:
    url = target if target.startswith("http") else f"https://{target}"
    stack = {
        "framework":  None,
        "cms":        None,
        "waf":        None,
        "server":     None,
        "language":   None,
        "raw_headers": {},
        "cors":       {},
        "cookies":    [],
        "sso":        {},
        "security_headers": {},
    }

    resp_text = ""
    try:
        resp = requests.get(
            url, timeout=8, verify=False, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (security-scanner)"},
        )
        headers   = dict(resp.headers)
        resp_text = resp.text
        stack["raw_headers"] = headers
        html_snippet = resp_text[:600]

        # ── Rule-based header analysis ──────────────────────────────────────
        server = headers.get("Server", headers.get("server", ""))
        stack["server"] = server if server else None

        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered:
            if "php" in powered.lower():
                stack["language"] = "PHP"
            elif "asp.net" in powered.lower():
                stack["language"] = "ASP.NET"
            elif "express" in powered.lower():
                stack["framework"] = "Express.js"

        cookies = headers.get("Set-Cookie", "")
        if "laravel_session" in str(cookies).lower():
            stack["framework"] = "Laravel"
        elif "django" in str(cookies).lower() or "csrftoken" in str(cookies):
            stack["framework"] = "Django"
        elif "phpsessid" in str(cookies).lower():
            stack["language"] = stack["language"] or "PHP"

        # WAF detection
        waf_headers = {
            "cf-ray":          "Cloudflare",
            "x-sucuri-id":     "Sucuri",
            "x-fw-hash":       "Wordfence",
            "x-protected-by":  "ModSecurity",
        }
        for h, waf in waf_headers.items():
            if h in {k.lower() for k in headers}:
                stack["waf"] = waf
                break
        if not stack["waf"] and "cloudflare" in server.lower():
            stack["waf"] = "Cloudflare"

        # HTML-based detection
        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            html_snippet, re.I,
        )
        if gen_match:
            gen = gen_match.group(1)
            if "wordpress" in gen.lower():
                stack["cms"] = "WordPress"
            elif "drupal" in gen.lower():
                stack["cms"] = "Drupal"
            elif "joomla" in gen.lower():
                stack["cms"] = "Joomla"

        # ── Security header audit ────────────────────────────────────────────
        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy":   "CSP",
            "X-Frame-Options":           "Clickjacking protection",
            "X-Content-Type-Options":    "MIME sniffing protection",
            "Referrer-Policy":           "Referrer policy",
            "Permissions-Policy":        "Permissions policy",
        }
        audit: dict = {}
        for hdr, label in sec_headers.items():
            val = headers.get(hdr) or headers.get(hdr.lower())
            audit[hdr] = val if val else "MISSING"
        stack["security_headers"] = audit

        # ── CORS analysis ────────────────────────────────────────────────────
        stack["cors"] = _cors_analysis(url, headers)

        # ── Cookie security ──────────────────────────────────────────────────
        stack["cookies"] = _cookie_security(headers)

        # ── SSO/OAuth fingerprinting ─────────────────────────────────────────
        stack["sso"] = _sso_fingerprint(target, url, resp_text, headers)

        # ── AI-enhanced fingerprinting ───────────────────────────────────────
        if ai and ai.is_available():
            header_summary = json.dumps(
                {k: v for k, v in headers.items()
                 if k.lower() in {"server", "x-powered-by", "set-cookie",
                                  "x-generator", "via", "x-aspnet-version",
                                  "x-runtime", "x-frame-options"}},
                indent=2,
            )
            prompt = (
                f"HTTP response headers:\n{header_summary}\n\n"
                f"HTML snippet (first 500 chars):\n{html_snippet[:500]}\n\n"
                "Identify the web framework, CMS, WAF, server, and programming language. "
                "Return ONLY valid JSON with keys: framework, cms, waf, server, language. "
                "Use null if unknown."
            )
            ai_result = ai.ask_json(prompt, model="fast")
            if isinstance(ai_result, dict):
                for key in ("framework", "cms", "waf", "server", "language"):
                    if ai_result.get(key) and not stack.get(key):
                        stack[key] = ai_result[key]

    except requests.exceptions.SSLError:
        try:
            url_http = f"http://{target}"
            resp = requests.get(
                url_http, timeout=8, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (security-scanner)"},
            )
            stack["raw_headers"] = dict(resp.headers)
        except Exception:
            pass
    except Exception:
        pass

    return stack


def stack_summary(stack: dict) -> str:
    parts = []
    for key in ("framework", "cms", "server", "language", "waf"):
        if stack.get(key):
            parts.append(f"{key}={stack[key]}")
    return ", ".join(parts) if parts else "unknown"
