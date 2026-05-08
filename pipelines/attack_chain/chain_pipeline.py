"""
Phase 12 & 20 — Attack Chain Analysis

Single vulnerabilities are overrated. Real compromise comes from chaining.
Phase 12: initial chain detection from recon/vuln/exploit/pivot findings.
Phase 20: advanced cross-phase chaining — combines ALL phases (14-19) findings
          into multi-step compromise narratives with business impact scoring.

This module:
  1. Takes all findings from every phase
  2. Applies rule-based chain detection for known multi-step patterns
  3. Uses AI Sonnet to reason about novel chains the rules miss
  4. Phase 20 advanced chains: validated proof + persistence + detection gap analysis
  5. Scores each chain by exploitability × impact × stealth
"""
import json

# ---------------------------------------------------------------------------
# Known chain patterns (rule-based, no AI required)
# ---------------------------------------------------------------------------

# Format: {"id": str, "name": str, "requires": [keyword_list], "severity": str, "description": str}
_CHAIN_RULES = [
    {
        "id":       "open_redirect_oauth",
        "name":     "Open Redirect → OAuth Token Theft",
        "requires": [["redirect", "open redirect"], ["oauth", "sso", "token", "auth"]],
        "severity": "critical",
        "chain":    ["Discover open redirect endpoint", "Register OAuth app with redirect_uri pointing to vulnerable redirect", "Send victim to OAuth flow — token delivered to attacker"],
        "owasp":    ["A01", "A07"],
    },
    {
        "id":       "ssrf_metadata_rce",
        "name":     "SSRF → Cloud Metadata → RCE",
        "requires": [["ssrf", "169.254.169.254", "metadata"], ["aws", "gcp", "azure", "iam", "credential"]],
        "severity": "critical",
        "chain":    ["Exploit SSRF to reach cloud metadata service", "Extract IAM role credentials (access key + secret)", "Use credentials to escalate via cloud API (S3, EC2, Lambda)"],
        "owasp":    ["A10", "A05"],
    },
    {
        "id":       "jwt_idor_admin",
        "name":     "Weak JWT → IDOR → Admin Access",
        "requires": [["jwt", "weak secret", "alg=none", "algorithm confusion"], ["idor", "object", "id", "access control"]],
        "severity": "critical",
        "chain":    ["Forge JWT with known weak secret or alg=none", "Access another user's object via IDOR", "Escalate to admin role by mutating JWT claims"],
        "owasp":    ["A07", "A01"],
    },
    {
        "id":       "xss_csrf_account_takeover",
        "name":     "Stored XSS → CSRF → Account Takeover",
        "requires": [["xss", "cross-site scripting", "stored xss"], ["csrf", "token", "password", "email change"]],
        "severity": "high",
        "chain":    ["Inject stored XSS payload", "Payload executes CSRF against password/email change endpoint", "Attacker takes over account without victim interaction"],
        "owasp":    ["A03", "A01"],
    },
    {
        "id":       "sqli_auth_bypass",
        "name":     "SQLi → Auth Bypass → Data Exfil",
        "requires": [["sqli", "sql injection", "sql syntax", "mysql error"], ["login", "auth", "bypass"]],
        "severity": "critical",
        "chain":    ["Identify SQLi in login or search parameter", "Bypass authentication with ' OR 1=1-- payload", "Dump user table or sensitive data via UNION injection"],
        "owasp":    ["A03", "A07"],
    },
    {
        "id":       "mass_assign_priv_chain",
        "name":     "Mass Assignment → Privilege Escalation → Lateral Movement",
        "requires": [["mass assignment", "mass assign", "parameter pollution"], ["role", "admin", "privilege", "permission"]],
        "severity": "high",
        "chain":    ["Identify mass assignment vulnerability in registration/profile endpoint", "Inject role=admin or is_admin=true in request body", "Use elevated session to access admin APIs or other users' data"],
        "owasp":    ["A04", "A01"],
    },
    {
        "id":       "lfi_rce",
        "name":     "LFI → Log Poisoning → RCE",
        "requires": [["lfi", "local file inclusion", "path traversal", "etc/passwd"]],
        "severity": "critical",
        "chain":    ["Confirm LFI via /etc/passwd read", "Poison access/error log by injecting PHP payload in User-Agent", "Include log file via LFI to achieve RCE"],
        "owasp":    ["A03", "A05"],
    },
    {
        "id":       "exposed_api_idor",
        "name":     "Unauthenticated API + IDOR → Data Breach",
        "requires": [["swagger", "openapi", "api-docs", "graphql", "introspection"], ["idor", "object", "id", "user"]],
        "severity": "high",
        "chain":    ["Find undocumented/exposed API spec (Swagger, GraphQL introspection)", "Map all object endpoints from the spec", "Enumerate objects via sequential/predictable IDs"],
        "owasp":    ["A01", "A05"],
    },
    {
        "id":       "internal_service_ssrf_pivot",
        "name":     "Internal Service Exposure → SSRF Pivot → Data Access",
        "requires": [["jenkins", "grafana", "kibana", "elasticsearch", "docker", "prometheus", "internal"], ["ssrf", "proxy", "redirect"]],
        "severity": "critical",
        "chain":    ["Discover exposed internal service (Jenkins/Elasticsearch/Docker daemon)", "Use SSRF vulnerability to reach internal service from application tier", "Execute commands or read data from internal service without authentication"],
        "owasp":    ["A10", "A05"],
    },
    {
        "id":       "subdomain_takeover_phishing",
        "name":     "Subdomain Takeover → Phishing / Cookie Theft",
        "requires": [["subdomain", "cname", "takeover", "dangling"]],
        "severity": "high",
        "chain":    ["Identify dangling CNAME record pointing to unclaimed cloud service", "Claim the cloud resource (S3 bucket, Heroku app, etc.)", "Host phishing page or cookie-stealing script on the subdomain"],
        "owasp":    ["A05", "A07"],
    },
    {
        "id":       "zone_transfer_map",
        "name":     "Zone Transfer → Full Infrastructure Map → Targeted Attack",
        "requires": [["zone transfer", "axfr", "zone transfer allowed"]],
        "severity": "high",
        "chain":    ["Exploit zone transfer to dump all DNS records", "Map complete internal infrastructure (dev, staging, internal services)", "Target identified staging/dev systems (often lack production hardening)"],
        "owasp":    ["A05"],
    },
]


def _text_from_findings(findings: list[dict]) -> str:
    """Flatten all findings into one searchable text blob."""
    parts = []
    for f in findings:
        for v in f.values():
            if isinstance(v, str):
                parts.append(v.lower())
    return " ".join(parts)


def _detect_rule_chains(all_findings: list[dict]) -> list[dict]:
    """Apply rule-based chain detection against the full findings corpus."""
    text = _text_from_findings(all_findings)
    matched: list[dict] = []

    for rule in _CHAIN_RULES:
        required = rule["requires"]
        hit = all(
            any(kw in text for kw in keyword_group)
            for keyword_group in required
        )
        if hit:
            matched.append({
                "chain_id":   rule["id"],
                "name":       rule["name"],
                "severity":   rule["severity"],
                "chain":      rule["chain"],
                "owasp":      rule["owasp"],
                "source":     "rule-based",
                "confidence": "medium",
            })

    return matched


def _score_chain(chain: dict) -> int:
    """Score a chain 0–100 based on severity × confidence × stealth."""
    sev_score    = {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(chain.get("severity", "medium"), 20)
    conf_score   = {"high": 30, "medium": 20, "low": 10}.get(chain.get("confidence", "medium"), 20)
    steps_score  = min(len(chain.get("chain", [])) * 10, 30)
    # Phase 20 stealth bonus — chains that bypass detection are more dangerous
    stealth_bonus = 10 if chain.get("detection_bypass") else 0
    validated_bonus = 10 if chain.get("validated") else 0
    return sev_score + conf_score + steps_score + stealth_bonus + validated_bonus


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_chain_analysis(
    target: str,
    all_findings: list[dict],
    surface_classification: dict = None,
    jwt_findings: dict = None,
    authz_findings: dict = None,
    pivot_findings: dict = None,
    ai=None,
) -> dict:
    """
    Aggregate all findings and produce a list of attack chains, scored by exploitability.
    """
    # Flatten every input source into a single findings list for rule matching
    extended = list(all_findings)

    for source, data in [
        ("jwt",   jwt_findings   or {}),
        ("authz", authz_findings or {}),
        ("pivot", pivot_findings or {}),
    ]:
        for key, val in data.items():
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and item.get("issue"):
                        extended.append({
                            "finding":  item.get("issue", ""),
                            "severity": item.get("severity", "medium"),
                            "evidence": str(item),
                            "owasp":    item.get("owasp", "A01"),
                        })
            elif isinstance(val, dict) and val.get("issue"):
                extended.append({
                    "finding":  val.get("issue", ""),
                    "severity": val.get("severity", "medium"),
                    "evidence": str(val),
                    "owasp":    val.get("owasp", "A01"),
                })

    # Step 1: rule-based chains
    chains = _detect_rule_chains(extended)

    # Step 2: AI-driven chain discovery (Sonnet — needs reasoning depth)
    ai_chains: list[dict] = []
    if ai and ai.is_available() and extended:
        surface_text = ""
        if surface_classification:
            top = list(surface_classification.items())[:4]
            surface_text = "Attack Surfaces:\n" + "\n".join(
                f"  {v['name']} (priority {v['priority']}): "
                + ", ".join(v.get("hypotheses", [])[:3])
                for _, v in top
            )

        findings_json = json.dumps(
            [{"finding": f.get("finding",""), "severity": f.get("severity",""), "owasp": f.get("owasp","")}
             for f in extended[:25]],
            indent=2
        )[:3000]

        prompt = (
            "You are an elite penetration tester specialising in attack chain analysis.\n\n"
            f"Target: {target}\n\n"
            f"{surface_text}\n\n"
            f"Individual findings:\n{findings_json}\n\n"
            "Your task: identify multi-step attack chains that combine two or more "
            "findings into a higher-impact exploit path. Think like an adversary.\n\n"
            "For each chain:\n"
            '- "name": short descriptive name\n'
            '- "severity": critical/high/medium\n'
            '- "chain": ordered list of steps (3-5 steps)\n'
            '- "start": the entry-point finding\n'
            '- "end": the business impact (what the attacker achieves)\n'
            '- "owasp": list of OWASP 2025 categories involved\n'
            '- "confidence": high/medium/low\n'
            '- "manual_notes": what a tester needs to verify manually\n\n'
            "Focus on CRITICAL chains first. If findings are too sparse, say so.\n"
            "Return ONLY valid JSON array (empty [] if no chains found)."
        )
        result = ai.ask_json(prompt, model="deep")
        if isinstance(result, list):
            for chain in result:
                chain["source"] = "ai"
            ai_chains = result

    # Merge + dedupe by name
    seen_names: set[str] = {c["name"] for c in chains}
    for c in ai_chains:
        if c.get("name") not in seen_names:
            chains.append(c)
            seen_names.add(c.get("name", ""))

    # Score and sort
    for c in chains:
        c["score"] = _score_chain(c)
    chains.sort(key=lambda c: c["score"], reverse=True)

    return {
        "chains":       chains,
        "total":        len(chains),
        "critical":     sum(1 for c in chains if c.get("severity") == "critical"),
        "high":         sum(1 for c in chains if c.get("severity") == "high"),
        "top_chain":    chains[0] if chains else None,
    }


# ---------------------------------------------------------------------------
# Phase 20 — Advanced Cross-Phase Chain Analysis
# ---------------------------------------------------------------------------

def run_advanced_chains(
    target: str,
    base_chains: list[dict],
    validated_findings: list[dict] = None,
    escalation_findings: list[dict] = None,
    lateral_findings: list[dict] = None,
    persistence_findings: list[dict] = None,
    detection_gaps: list[dict] = None,
    ai=None,
) -> dict:
    """
    Phase 20: synthesise ALL phase findings into complete attack narratives.

    Upgrades base_chains with:
      - validation status (proof captured in Phase 15)
      - escalation paths (Phase 16)
      - lateral movement legs (Phase 17)
      - persistence opportunities (Phase 18)
      - detection gaps (Phase 19 poor_coverage findings)

    Returns final scored chain list with full operator narrative.
    """
    # Mark chains where we have validated proof
    validated_issues = {
        f.get("proof", {}).get("impact", "") or f.get("finding", "")
        for f in (validated_findings or [])
    }
    poor_detection = {f.get("issue", "") for f in (detection_gaps or [])}

    enriched: list[dict] = []
    for chain in base_chains:
        c = dict(chain)
        chain_text = " ".join(c.get("chain", [])).lower() + c.get("name", "").lower()

        # Was this chain validated?
        c["validated"] = any(
            any(kw in chain_text for kw in v_issue.lower().split()[:3])
            for v_issue in validated_issues if v_issue
        )

        # Does this chain benefit from a detection gap?
        c["detection_bypass"] = any(
            any(kw in chain_text for kw in gap.lower().split()[:3])
            for gap in poor_detection if gap
        )

        # Persistence opportunity
        persist_overlap = any(
            any(kw in chain_text for kw in f.get("issue", "").lower().split()[:3])
            for f in (persistence_findings or [])
            if f.get("severity") in ("critical", "high")
        )
        if persist_overlap:
            c.setdefault("persistence_note", "Persistence opportunity identified — see Phase 18 findings")

        # Re-score with new bonuses
        c["score"] = _score_chain(c)
        enriched.append(c)

    enriched.sort(key=lambda c: c["score"], reverse=True)

    # AI: full attack narrative for top 3 chains
    ai_narratives = None
    if ai and ai.is_available() and enriched:
        top3 = enriched[:3]
        escalation_text = ""
        if escalation_findings:
            top_esc = [f.get("issue", "") for f in escalation_findings[:3]]
            escalation_text = f"\nEscalation paths available: {'; '.join(top_esc)}"

        lateral_text = ""
        if lateral_findings:
            top_lat = [f.get("issue", "") for f in lateral_findings[:3]]
            lateral_text = f"\nLateral movement paths: {'; '.join(top_lat)}"

        chains_json = json.dumps(
            [{"name": c.get("name"), "severity": c.get("severity"),
              "steps": c.get("chain", []), "validated": c.get("validated"),
              "detection_bypass": c.get("detection_bypass")}
             for c in top3],
            indent=2
        )[:2500]

        prompt = (
            "You are writing the final compromise narrative for a penetration test report.\n\n"
            f"Target: {target}\n"
            f"Top attack chains:\n{chains_json}\n"
            f"{escalation_text}\n"
            f"{lateral_text}\n\n"
            "For each chain write a complete attack narrative that:\n"
            "1. Describes the full compromise path from initial access to final objective\n"
            "2. States exactly what a real attacker achieves\n"
            "3. Estimates time-to-compromise for a skilled attacker\n"
            "4. Rates detection likelihood (silent/noisy/very noisy)\n"
            "5. States the single most effective defensive control\n\n"
            "Write for a CISO audience — no jargon, focus on business risk.\n\n"
            "Return ONLY valid JSON array (3 items):\n"
            '[{"chain":"...", "narrative":"...", "attacker_objective":"...", '
            '"time_to_compromise":"...", "detection":"silent|noisy|very noisy", '
            '"key_control":"..."}]'
        )
        ai_narratives = ai.ask_json(prompt, model="deep")

    return {
        "chains":         enriched,
        "total":          len(enriched),
        "critical":       sum(1 for c in enriched if c.get("severity") == "critical"),
        "validated":      sum(1 for c in enriched if c.get("validated")),
        "silent_chains":  sum(1 for c in enriched if c.get("detection_bypass")),
        "top_chain":      enriched[0] if enriched else None,
        "ai_narratives":  ai_narratives,
    }
