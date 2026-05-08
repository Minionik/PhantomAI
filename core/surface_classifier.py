"""
Phase 10 — Attack Surface Classification

Classifies all collected recon/enum/vuln data into four attack surfaces:
  auth    — Authentication Surface
  authz   — Authorization Surface
  trust   — Internal Trust Surface
  logic   — Business Logic Surface

For each surface: which endpoints/params hit it, hypotheses to test, priority score.
"""
import re
import json

# ---------------------------------------------------------------------------
# Surface definitions
# ---------------------------------------------------------------------------

SURFACES = {
    "auth": {
        "name": "Authentication Surface",
        "url_keywords": [
            "login", "signin", "sign-in", "logout", "signup", "register",
            "oauth", "oauth2", "sso", "saml", "2fa", "mfa", "totp", "webauthn",
            "password", "passwd", "reset", "forgot", "recover", "token",
            "session", "auth", "authenticate", "invite", "magic-link",
            "verify", "confirm", "activate",
        ],
        "param_keywords": ["token", "password", "passwd", "pwd", "code", "otp", "session", "state", "nonce"],
        "hypotheses": [
            "Weak or predictable token generation",
            "OAuth state parameter missing / not validated (CSRF on OAuth flow)",
            "JWT algorithm confusion (none / HS256 with RS256 public key)",
            "Missing or bypassable MFA enforcement",
            "Password reset link reuse / long expiry",
            "Session fixation — session ID not rotated on login",
            "Invite token enumeration / reuse",
            "SSO issuer confusion / cross-tenant token acceptance",
        ],
        "owasp": "A07",
    },
    "authz": {
        "name": "Authorization Surface",
        "url_keywords": [
            "api", "admin", "user", "account", "profile", "order", "invoice",
            "ticket", "message", "file", "document", "report", "record",
            "id", "uuid", "guid", "object", "resource", "item",
        ],
        "param_keywords": ["id", "user_id", "account_id", "order_id", "uid", "oid", "pid", "rid", "gid", "tid"],
        "hypotheses": [
            "IDOR — replace numeric or UUID object identifiers",
            "Horizontal privilege escalation — access another user's resources",
            "Vertical privilege escalation — reach admin/staff functionality",
            "Mass assignment — inject extra fields into PUT/PATCH body",
            "Hidden admin functions exposed via undocumented API paths",
            "Role bypass via HTTP method switching (GET vs POST vs DELETE)",
            "API versioning gap — v1 lacks v2 authorization checks",
        ],
        "owasp": "A01",
    },
    "trust": {
        "name": "Internal Trust Surface",
        "url_keywords": [
            "proxy", "gateway", "internal", "callback", "webhook", "forward",
            "redirect", "next", "return", "url", "uri", "src", "dest",
            "endpoint", "host", "fetch", "load", "import",
        ],
        "param_keywords": [
            "url", "uri", "src", "source", "dest", "destination", "redirect",
            "next", "return", "return_url", "back", "forward", "callback",
            "host", "endpoint", "fetch", "include", "path",
        ],
        "hypotheses": [
            "SSRF — cloud metadata access (AWS 169.254.169.254 / GCP / Azure)",
            "SSRF — internal service discovery (Redis, Elasticsearch, Prometheus)",
            "Reverse proxy trust bypass via X-Forwarded-For / X-Real-IP injection",
            "Internal-only route exposure through misconfigured gateway",
            "localhost / 127.0.0.1 access via SSRF",
            "Service mesh trust abuse — spoof internal service-to-service calls",
            "Open redirect chained with OAuth to steal tokens",
        ],
        "owasp": "A10",
    },
    "logic": {
        "name": "Business Logic Surface",
        "url_keywords": [
            "payment", "checkout", "order", "purchase", "cart", "billing",
            "subscription", "plan", "upgrade", "downgrade", "coupon", "promo",
            "discount", "refund", "cancel", "approve", "reject", "confirm",
            "onboard", "invite", "transfer", "withdraw", "deposit",
            "workflow", "step", "wizard", "process",
        ],
        "param_keywords": [
            "amount", "price", "total", "quantity", "qty", "count",
            "coupon", "promo", "code", "discount", "plan", "tier",
            "role", "status", "state", "step", "phase",
        ],
        "hypotheses": [
            "Race condition on payment / reservation (double-spend)",
            "Negative quantity / price manipulation",
            "Coupon / promo code unlimited reuse or stacking",
            "Workflow state desync — skip required approval steps",
            "Payment bypass — manipulate total before charge",
            "Privilege chaining — free → paid feature unlock via state mutation",
            "Subscription plan downgrade after accessing premium features",
            "Invitation abuse — self-invite to elevate role",
        ],
        "owasp": "A04",
    },
}


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def classify_surfaces(
    urls: list[str],
    params: list[str],
    findings: list[dict],
    swagger_specs: list[dict] = None,
    graphql_endpoints: list[dict] = None,
    internal_services: list[dict] = None,
    ai=None,
) -> dict:
    """
    Returns a dict keyed by surface ID with:
      matched_urls, matched_params, hypotheses, priority (0-100), owasp
    """
    swagger_specs      = swagger_specs      or []
    graphql_endpoints  = graphql_endpoints  or []
    internal_services  = internal_services  or []

    classification: dict = {}

    for surface_id, surface in SURFACES.items():
        matched_urls:   list[str] = []
        matched_params: list[str] = []

        url_kws   = surface["url_keywords"]
        param_kws = surface["param_keywords"]

        for url in urls:
            url_lower = url.lower()
            if any(kw in url_lower for kw in url_kws):
                matched_urls.append(url)

        # Pull API paths from Swagger specs
        for spec in swagger_specs:
            for path in spec.get("paths", []):
                path_lower = path.lower()
                if any(kw in path_lower for kw in url_kws):
                    full = spec.get("url", "").rsplit("/", 1)[0] + path
                    if full not in matched_urls:
                        matched_urls.append(full)

        for param in params:
            param_lower = param.lower().split("?")[-1].split("=")[0]
            if any(kw in param_lower for kw in param_kws):
                matched_params.append(param)

        # Score: base on matches + finding overlap
        score = min(len(matched_urls) * 3 + len(matched_params) * 5, 60)

        # Boost from confirmed findings
        for f in findings:
            f_text = (f.get("finding", "") + " " + f.get("owasp", "")).lower()
            if surface["owasp"].lower() in f_text:
                score = min(score + 15, 100)
            if any(kw in f_text for kw in url_kws):
                score = min(score + 5, 100)

        # Boost trust surface if internal services found
        if surface_id == "trust" and (internal_services or graphql_endpoints):
            score = min(score + 20, 100)

        # Boost authz if GraphQL found (introspection = hidden objects)
        if surface_id == "authz" and graphql_endpoints:
            score = min(score + 15, 100)

        classification[surface_id] = {
            "name":           surface["name"],
            "owasp":          surface["owasp"],
            "matched_urls":   matched_urls[:20],
            "matched_params": matched_params[:20],
            "hypotheses":     surface["hypotheses"],
            "priority":       score,
        }

    # Sort by priority descending
    classification = dict(
        sorted(classification.items(), key=lambda kv: kv[1]["priority"], reverse=True)
    )

    # AI enrichment — generate target-specific hypotheses
    if ai and ai.is_available():
        top_surfaces = list(classification.items())[:3]
        surface_summary = "\n".join(
            f"- {v['name']} (priority {v['priority']}): "
            f"{len(v['matched_urls'])} URL(s), {len(v['matched_params'])} param(s)"
            for _, v in top_surfaces
        )
        finding_text = json.dumps(
            [{"finding": f.get("finding"), "owasp": f.get("owasp"), "severity": f.get("severity")}
             for f in findings[:10]],
            indent=2
        )[:1500]

        prompt = (
            "You are a senior penetration tester classifying an attack surface.\n\n"
            f"Top surfaces identified:\n{surface_summary}\n\n"
            f"Confirmed findings so far:\n{finding_text}\n\n"
            "For each surface, suggest 2-3 additional target-specific test hypotheses "
            "that a human tester should manually verify. Focus on what automation CANNOT test.\n"
            "Return ONLY valid JSON: "
            '{"auth": ["hypothesis..."], "authz": [...], "trust": [...], "logic": [...]}'
        )
        ai_result = ai.ask_json(prompt, model="fast")
        if isinstance(ai_result, dict):
            for sid, extra in ai_result.items():
                if sid in classification and isinstance(extra, list):
                    classification[sid]["ai_hypotheses"] = extra

    return classification
