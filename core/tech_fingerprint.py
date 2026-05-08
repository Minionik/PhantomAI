import re
import json
import requests


def fingerprint(target: str, ai=None) -> dict:
    """
    Probe target for tech stack indicators from HTTP headers and HTML.
    Returns dict with keys: framework, cms, waf, server, language, raw_headers.
    """
    url = target if target.startswith("http") else f"https://{target}"
    stack = {
        "framework": None,
        "cms": None,
        "waf": None,
        "server": None,
        "language": None,
        "raw_headers": {},
    }

    try:
        resp = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (security-scanner)"})
        headers = dict(resp.headers)
        stack["raw_headers"] = headers
        html_snippet = resp.text[:600]

        # --- Rule-based header analysis ---
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
        if "laravel_session" in cookies.lower():
            stack["framework"] = "Laravel"
        elif "django" in cookies.lower() or "csrftoken" in cookies:
            stack["framework"] = "Django"
        elif "phpsessid" in cookies.lower():
            stack["language"] = stack["language"] or "PHP"

        # WAF detection from headers
        waf_headers = {
            "cf-ray": "Cloudflare",
            "x-sucuri-id": "Sucuri",
            "x-fw-hash": "Wordfence",
            "x-protected-by": "ModSecurity",
            "server": None,
        }
        for h, waf in waf_headers.items():
            val = headers.get(h, "").lower()
            if h == "server" and "cloudflare" in val:
                stack["waf"] = "Cloudflare"
            elif waf and h in {k.lower() for k in headers}:
                stack["waf"] = waf

        # HTML-based detection
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html_snippet, re.I)
        if gen_match:
            gen = gen_match.group(1)
            if "wordpress" in gen.lower():
                stack["cms"] = "WordPress"
            elif "drupal" in gen.lower():
                stack["cms"] = "Drupal"
            elif "joomla" in gen.lower():
                stack["cms"] = "Joomla"

        # --- AI-enhanced fingerprinting ---
        if ai and ai.is_available():
            header_summary = json.dumps({k: v for k, v in headers.items()
                                         if k.lower() in {"server", "x-powered-by", "set-cookie",
                                                          "x-generator", "via", "x-aspnet-version",
                                                          "x-runtime", "x-frame-options"}}, indent=2)
            prompt = (
                f"HTTP response headers:\n{header_summary}\n\n"
                f"HTML snippet (first 500 chars):\n{html_snippet[:500]}\n\n"
                "Identify the web framework, CMS, WAF, server, and programming language. "
                'Return ONLY valid JSON with keys: framework, cms, waf, server, language. '
                "Use null if unknown."
            )
            ai_result = ai.ask_json(prompt, model="fast")
            if isinstance(ai_result, dict):
                for key in ("framework", "cms", "waf", "server", "language"):
                    if ai_result.get(key) and not stack.get(key):
                        stack[key] = ai_result[key]

    except requests.exceptions.SSLError:
        # retry over HTTP
        try:
            url_http = f"http://{target}"
            resp = requests.get(url_http, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (security-scanner)"})
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
