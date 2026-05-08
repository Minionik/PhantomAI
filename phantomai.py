import argparse
import os
import warnings
import urllib3
from dotenv import load_dotenv

# Suppress InsecureRequestWarning globally — PhantomAI intentionally sends
# requests to targets with self-signed / invalid certificates (pentest context).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from core.ai_engine import AIEngine
from pipelines.phase0_init import run_phase0
from pipelines.recon.recon_pipeline import run_recon
from pipelines.enumeration.enum_pipeline import run_enum
from pipelines.vuln_analysis.vuln_pipeline import run_vuln
from pipelines.exploitation.exploit_pipeline import run_exploit
from pipelines.post_exploitation.post_pipeline import run_post
from pipelines.auth.jwt_tester import find_and_test_jwts
from pipelines.auth.authz_tester import run_authz
from pipelines.attack_chain.chain_pipeline import run_chain_analysis, run_advanced_chains
from pipelines.pivot.pivot_pipeline import run_pivot
from pipelines.escalation.escalation_pipeline import run_escalation
from pipelines.lateral.lateral_pipeline import run_lateral
from pipelines.persistence.persistence_pipeline import run_persistence
from pipelines.detection.detection_pipeline import run_detection
from pipelines.exploitation.impact_validator import run_impact_validation
from core.surface_classifier import classify_surfaces
from core.exploit_prioritizer import build_exploit_queue
from reports.html_reporter import generate_report, print_terminal_summary

load_dotenv()

_BANNER = r"""
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ██╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║███████║██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
  AI-Powered Penetration Testing Framework  |  OWASP 2025  |  v3.0
"""


def main():
    print(_BANNER)

    parser = argparse.ArgumentParser(
        prog="phantomai",
        description="PhantomAI — AI-powered OWASP 2025 penetration testing framework",
    )
    parser.add_argument("--no-ai",  action="store_true", help="Disable AI features (no API key needed)")
    parser.add_argument("--output", default=".",          help="Directory to save HTML report (default: current dir)")
    parser.add_argument("--target",                       help="Target domain/IP (skips interactive prompt)")
    args = parser.parse_args()

    ai = AIEngine() if not args.no_ai else None
    ai_enabled = ai is not None and ai.is_available()

    if args.no_ai:
        print("[*] AI disabled — running in standard mode")
    elif not ai_enabled:
        print("[!] AI unavailable — set AI_TIER and credentials in .env")
        print("    Free tier : install Ollama (https://ollama.com) → AI_TIER=free")
        print("    Paid tier : set ANTHROPIC_API_KEY           → AI_TIER=basic or pro")
    else:
        print(f"[+] AI tier: {ai.tier_label()}")

    # ── Phase 0: Validation + Tech Fingerprinting ────────────────────────────
    print("\n[*] Phase 0: Target Validation & Fingerprinting")
    phase0 = run_phase0(ai=ai, target_arg=args.target)

    if not phase0["reachable"]:
        print("[-] Target not reachable. Aborting.")
        return

    target = phase0["target"]
    stack  = phase0.get("stack", {})

    if stack:
        from core.tech_fingerprint import stack_summary
        print(f"[+] Stack detected: {stack_summary(stack)}")
        if stack.get("cors", {}).get("issues"):
            for issue in stack["cors"]["issues"]:
                print(f"    [!] CORS: {issue['issue']} ({issue['severity']})")
        if stack.get("sso", {}).get("provider"):
            print(f"    [+] SSO provider: {stack['sso']['provider']}"
                  + (f" — OIDC: {stack['sso']['oidc_endpoint']}" if stack["sso"].get("oidc_endpoint") else ""))
        cookie_issues = stack.get("cookies", [])
        if cookie_issues:
            print(f"    [!] Cookie issues: {len(cookie_issues)} (missing HttpOnly/Secure/SameSite)")

    # ── Phase 1: Recon ───────────────────────────────────────────────────────
    print("\n[*] Phase 1: Reconnaissance")
    recon       = run_recon(target, ai=ai)
    js_findings = recon.get("js_findings", [])
    port_scan   = recon.get("port_scan", {})
    asn_info    = recon.get("asn_info", {})
    cloud       = recon.get("cloud_assets", {})
    dns_data    = recon.get("dns_records", {})
    leak_data   = recon.get("leak_recon", {})
    shodan_data = recon.get("shodan", {})
    print(f"    Subdomains : {len(recon.get('subdomains', []))} | "
          f"Live hosts : {len(recon.get('live_hosts', []))} | "
          f"URLs : {len(recon.get('urls', []))}")
    if asn_info.get("asn"):
        print(f"    ASN        : AS{asn_info['asn']} — {asn_info.get('org','?')} "
              f"({len(asn_info.get('prefixes',[]))} prefix(es))")
    total_cloud = sum(len(v) for k, v in cloud.items() if k != "raw")
    if total_cloud:
        print(f"    Cloud      : {total_cloud} asset(s) — "
              f"S3:{len(cloud.get('s3',[]))} Azure:{len(cloud.get('azure',[]))} "
              f"GCP:{len(cloud.get('gcp',[]))}")
    if port_scan:
        print(f"    Ports      : " + " | ".join(
            f"{h}→[{', '.join(p[:3])}{'…' if len(p)>3 else ''}]"
            for h, p in list(port_scan.items())[:3]
        ))
    if js_findings:
        high = sum(1 for f in js_findings if f.get("risk_level") == "high")
        print(f"    JS files   : {len(js_findings)} analysed ({high} high-risk)")
    if dns_data.get("security_issues"):
        issues  = dns_data["security_issues"]
        critical = sum(1 for i in issues if i.get("risk") == "critical")
        high_dns = sum(1 for i in issues if i.get("risk") == "high")
        print(f"    DNS issues : {len(issues)} "
              f"({critical} critical, {high_dns} high) — "
              f"SPF:{'✓' if dns_data.get('spf') else '✗'}  "
              f"DMARC:{'✓' if dns_data.get('dmarc') else '✗'}  "
              f"DKIM:{'✓' if dns_data.get('dkim') else '✗'}")
    if leak_data.get("summary"):
        for line in leak_data["summary"]:
            print(f"    Leaks      : {line}")
    if shodan_data.get("ports"):
        vuln_count = len(shodan_data.get("vulns", []))
        print(f"    Shodan     : {len(shodan_data['ports'])} port(s)"
              + (f", {vuln_count} CVE(s): {', '.join(shodan_data['vulns'][:3])}" if vuln_count else ""))

    # ── Phase 2: Enumeration ─────────────────────────────────────────────────
    print("\n[*] Phase 2: Enumeration")
    enum = run_enum(target, recon.get("urls", []), stack=stack, ai=ai)
    print(f"    Fuzz hits : {len(enum.get('fuzz', []))} | "
          f"Params found : {len(enum.get('params', []))}")
    if enum.get("swagger"):
        paths_total = sum(len(s.get("paths", [])) for s in enum["swagger"])
        print(f"    Swagger/OpenAPI : {len(enum['swagger'])} spec(s) found "
              f"({paths_total} API path(s) discovered)")
    if enum.get("graphql"):
        introspection_on = sum(1 for g in enum["graphql"] if g.get("introspection_enabled"))
        print(f"    GraphQL : {len(enum['graphql'])} endpoint(s) found "
              f"({introspection_on} with introspection enabled)")
    if enum.get("internal_services"):
        svc_names = [s["service"] for s in enum["internal_services"][:4]]
        print(f"    Internal services : {len(enum['internal_services'])} exposed — "
              + ", ".join(svc_names))

    # ── Phase 3: Vulnerability Analysis ─────────────────────────────────────
    print("\n[*] Phase 3: Vulnerability Analysis")
    vuln    = run_vuln(target, recon.get("urls", []), stack=stack, ai=ai)
    triaged = vuln.get("triaged", [])
    print(f"    Triaged findings : {len(triaged)}")

    # ── Phase 4: Exploitation ────────────────────────────────────────────────
    print("\n[*] Phase 4: Exploitation")
    exploit = run_exploit(target, enum.get("params", []), stack=stack, ai=ai)
    print(f"    Exploitation results : {len(exploit.get('results', {}))}")

    # ── Phase 10: Attack Surface Classification ──────────────────────────────
    print("\n[*] Phase 10: Attack Surface Classification")
    all_urls   = recon.get("urls", []) + enum.get("fuzz", [])
    all_params = enum.get("params", [])
    surfaces   = classify_surfaces(
        urls=all_urls,
        params=all_params,
        findings=triaged,
        swagger_specs=enum.get("swagger", []),
        graphql_endpoints=enum.get("graphql", []),
        internal_services=enum.get("internal_services", []),
        ai=ai,
    )
    for sid, surf in list(surfaces.items())[:4]:
        ai_hints = len(surf.get("ai_hypotheses", []))
        print(f"    {surf['name']:35s} priority={surf['priority']:3d} | "
              f"{len(surf['matched_urls'])} URL(s) | "
              f"{len(surf['hypotheses']) + ai_hints} hypotheses")

    # ── Phase 11: Manual Attack Mapping ─────────────────────────────────────
    print("\n[*] Phase 11: Manual Attack Mapping")

    print("    [*] JWT / OAuth analysis ...")
    jwt_results = find_and_test_jwts(all_urls[:50])
    if jwt_results.get("tokens_found"):
        issues = {k: v for k, v in jwt_results.get("findings", {}).items()
                  if any(k2 not in ("token_info",) for k2 in v)}
        print(f"    JWT tokens found: {len(jwt_results['tokens_found'])} | "
              f"Vulnerabilities: {sum(len(v) for v in jwt_results.get('findings', {}).values())}")
    else:
        print("    JWT: no tokens found in responses")

    print("    [*] Authorization testing (IDOR, vertical escalation, mass assignment) ...")
    authz_results = run_authz(target, all_urls, all_params, ai=ai)
    authz_all     = authz_results.get("all_findings", [])
    authz_critical = sum(1 for f in authz_all if f.get("severity") == "critical")
    authz_high     = sum(1 for f in authz_all if f.get("severity") == "high")
    print(f"    Authorization: {len(authz_all)} finding(s) "
          f"({authz_critical} critical, {authz_high} high) — "
          f"IDOR:{len(authz_results.get('idor',[]))} "
          f"Vertical:{len(authz_results.get('vertical',[]))} "
          f"MassAssign:{len(authz_results.get('mass_assign',[]))}")

    # ── Phase 13: Environment Pivoting ───────────────────────────────────────
    print("\n[*] Phase 13: Environment Pivoting")
    pivot_results = run_pivot(target, all_urls, all_params, ai=ai)
    pivot_summary = pivot_results.get("summary", {})
    print(f"    Pivot findings : {pivot_summary.get('total', 0)} "
          f"({pivot_summary.get('critical', 0)} critical, {pivot_summary.get('high', 0)} high)")
    if pivot_results.get("cicd"):
        sensitive_cicd = [f for f in pivot_results["cicd"] if f.get("sensitive_keywords")]
        print(f"    CI/CD files    : {len(pivot_results['cicd'])} exposed "
              f"({len(sensitive_cicd)} with secrets)")
    if pivot_results.get("container_k8s"):
        print(f"    Container/K8s  : {len(pivot_results['container_k8s'])} finding(s)")
    if pivot_results.get("cloud"):
        print(f"    Cloud metadata : {len(pivot_results['cloud'])} accessible")
    if pivot_results.get("ai_assessment", {}) and isinstance(pivot_results.get("ai_assessment"), dict):
        env = pivot_results["ai_assessment"].get("environment", "")
        if env:
            print(f"    Environment    : {env}")

    # ── Phase 12: Attack Chain Analysis ─────────────────────────────────────
    print("\n[*] Phase 12: Attack Chain Analysis")
    all_flat_findings = triaged + authz_all + pivot_results.get("all_findings", [])
    chain_results = run_chain_analysis(
        target=target,
        all_findings=all_flat_findings,
        surface_classification=surfaces,
        jwt_findings=jwt_results.get("findings", {}),
        authz_findings=authz_results,
        pivot_findings=pivot_results,
        ai=ai,
    )
    print(f"    Chains identified : {chain_results['total']} "
          f"({chain_results['critical']} critical, {chain_results['high']} high)")
    if chain_results.get("top_chain"):
        top = chain_results["top_chain"]
        print(f"    Top chain       : {top.get('name','?')} "
              f"[{top.get('severity','?').upper()}] (score {top.get('score',0)})")
        for i, step in enumerate(top.get("chain", [])[:3], 1):
            print(f"      {i}. {step}")

    # ── Phase 14: Exploitation Strategy ─────────────────────────────────────
    print("\n[*] Phase 14: Exploitation Strategy")
    exploit_queue = build_exploit_queue(
        all_findings=all_flat_findings,
        surfaces=surfaces,
        chain_results=chain_results,
        ai=ai,
    )
    print(f"    Ranked targets : {exploit_queue['total']} findings prioritised "
          f"({exploit_queue['critical_count']} critical, {exploit_queue['high_count']} high)")
    if exploit_queue.get("surface_focus"):
        sf = exploit_queue["surface_focus"]
        print(f"    Surface focus  : {sf['surface']} (priority {sf['priority']})")
    if exploit_queue.get("top_targets"):
        t = exploit_queue["top_targets"][0]
        print(f"    #1 target      : [{t['severity'].upper()}] {t['finding'][:60]}")
        print(f"      Approach     : {t['approach'][:80]}")
    if exploit_queue.get("ai_strategy") and isinstance(exploit_queue["ai_strategy"], list):
        for item in exploit_queue["ai_strategy"][:2]:
            decision = item.get("decision", "?").upper()
            print(f"    AI → {decision:6s}  : {item.get('finding','?')[:55]}")

    # ── Phase 15: Impact Validation ─────────────────────────────────────────
    print("\n[*] Phase 15: Impact Validation")
    # Collect SSRF-capable params
    from urllib.parse import parse_qs as _parse_qs
    ssrf_params_list = []
    for u in all_params[:50]:
        for p in _parse_qs(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(u).query).keys():
            if p.lower() in ["url","uri","src","redirect","next","return","callback","fetch","dest","host"]:
                if p not in ssrf_params_list:
                    ssrf_params_list.append(p)

    impact_results = run_impact_validation(
        exploit_queue=exploit_queue.get("queue", []),
        jwt_findings=jwt_results.get("findings", {}),
        pivot_findings=pivot_results,
        ssrf_params=ssrf_params_list,
        ai=ai,
    )
    print(f"    Validated findings : {impact_results['total_proven']} / "
          f"{len(exploit_queue.get('queue', [])[:15])} tested (proof of impact captured)")
    for v in impact_results.get("validated", [])[:3]:
        proof = v.get("proof", {})
        print(f"    ✓ PROVEN : {proof.get('impact','?')[:70]}")

    # ── Phase 16: Privilege Escalation ──────────────────────────────────────
    print("\n[*] Phase 16: Privilege Escalation")
    escalation_results = run_escalation(
        target=target,
        pivot_data=pivot_results,
        ai=ai,
    )
    esc_sum = escalation_results.get("summary", {})
    print(f"    Escalation findings : {esc_sum.get('total',0)} "
          f"({esc_sum.get('critical',0)} critical, {esc_sum.get('high',0)} high)")
    if escalation_results.get("ai_path") and isinstance(escalation_results["ai_path"], dict):
        access = escalation_results["ai_path"].get("access_level", "")
        if access:
            print(f"    Access achieved : {access}")

    # ── Phase 17: Lateral Movement ───────────────────────────────────────────
    print("\n[*] Phase 17: Lateral Movement")
    lateral_results = run_lateral(
        target=target,
        live_hosts=recon.get("live_hosts", []),
        ssrf_params=ssrf_params_list,
        cicd_findings=pivot_results.get("cicd", []),
        js_findings=js_findings,
        ai=ai,
    )
    lat_sum = lateral_results.get("summary", {})
    print(f"    Lateral findings : {lat_sum.get('total',0)} "
          f"({lat_sum.get('critical',0)} critical)")
    if lateral_results.get("ci_creds"):
        print(f"    CI/CD secrets   : {len(lateral_results['ci_creds'])} extracted")
    if lateral_results.get("ssrf_pivots"):
        print(f"    SSRF pivots     : {len(lateral_results['ssrf_pivots'])} internal services reached")
    if lateral_results.get("api_pivots"):
        print(f"    API key pivots  : {len(lateral_results['api_pivots'])} valid keys confirmed")

    # ── Phase 18: Persistence Analysis ──────────────────────────────────────
    print("\n[*] Phase 18: Persistence Analysis")
    persistence_results = run_persistence(
        target=target,
        jwt_findings=jwt_results.get("findings", {}),
        ai=ai,
    )
    pers_sum = persistence_results.get("summary", {})
    print(f"    Persistence findings : {pers_sum.get('total',0)} "
          f"({pers_sum.get('critical',0)} critical, {pers_sum.get('high',0)} high)")
    if persistence_results.get("default_creds"):
        print(f"    [!!] Default credentials accepted: "
              f"{persistence_results['default_creds'][0].get('username','?')}/"
              f"{persistence_results['default_creds'][0].get('password','?')}")
    if persistence_results.get("webhooks"):
        reg = [w for w in persistence_results["webhooks"] if w.get("severity") == "high"]
        if reg:
            print(f"    Webhook registration : {len(reg)} endpoint(s) accept attacker URL")

    # ── Phase 19: Detection & Logging Assessment ─────────────────────────────
    print("\n[*] Phase 19: Detection & Logging Assessment")
    detection_results = run_detection(
        target=target,
        api_urls=all_urls[:50],
        ai=ai,
    )
    det_sum = detection_results.get("summary", {})
    waf_name = det_sum.get("waf", "none detected")
    print(f"    WAF              : {waf_name}")
    print(f"    Poor coverage    : {det_sum.get('poor_coverage',0)} gap(s) "
          f"| Good coverage : {det_sum.get('good_coverage',0)}")
    if detection_results.get("ai_detection") and isinstance(detection_results["ai_detection"], dict):
        maturity = detection_results["ai_detection"].get("maturity", "")
        silent   = detection_results["ai_detection"].get("most_silent_technique", "")
        if maturity:
            print(f"    Detection maturity : {maturity}")
        if silent:
            print(f"    Most silent attack : {silent[:70]}")

    # ── Phase 20: Advanced Attack Chaining ───────────────────────────────────
    print("\n[*] Phase 20: Advanced Attack Chain Synthesis")
    advanced_chains = run_advanced_chains(
        target=target,
        base_chains=chain_results.get("chains", []),
        validated_findings=impact_results.get("validated", []),
        escalation_findings=escalation_results.get("all_findings", []),
        lateral_findings=lateral_results.get("all_findings", []),
        persistence_findings=persistence_results.get("all_findings", []),
        detection_gaps=detection_results.get("poor_detection", []),
        ai=ai,
    )
    print(f"    Final chains : {advanced_chains['total']} "
          f"({advanced_chains['critical']} critical | "
          f"{advanced_chains['validated']} validated | "
          f"{advanced_chains['silent_chains']} detection-evading)")
    if advanced_chains.get("top_chain"):
        top = advanced_chains["top_chain"]
        print(f"    Top chain    : {top.get('name','?')} [score {top.get('score',0)}]"
              + (" ✓PROVEN" if top.get("validated") else "")
              + (" 🔇SILENT" if top.get("detection_bypass") else ""))
    if advanced_chains.get("ai_narratives") and isinstance(advanced_chains["ai_narratives"], list):
        for narr in advanced_chains["ai_narratives"][:1]:
            print(f"    Narrative    : {narr.get('narrative','')[:100]}...")

    # ── Phase 5: Report Generation ───────────────────────────────────────────
    print("\n[*] Phase 5: Report Generation")
    post = run_post(
        target=target,
        stack=stack,
        triaged_findings=triaged,
        exploit_results=exploit.get("results", {}),
        js_findings=js_findings,
        authz_findings=authz_all,
        pivot_findings=pivot_results.get("all_findings", []),
        chain_results=chain_results,
        surfaces=surfaces,
        ai=ai,
    )

    all_findings = post.get("findings", [])
    if not all_findings:
        for f in triaged:
            all_findings.append({
                "title":          f.get("finding", "Unknown"),
                "severity":       f.get("severity", "medium"),
                "owasp_category": f.get("owasp", "A05"),
                "cwe_id":         "",
                "description":    f.get("finding", ""),
                "evidence":       f.get("evidence", ""),
                "remediation":    "Review and remediate according to OWASP guidelines.",
                "references":     "https://owasp.org/www-project-top-ten/",
            })

    report_data = {
        "target":            target,
        "stack":             stack,
        "executive_summary": post.get("executive_summary", ""),
        "findings":          all_findings,
        "recon": {
            "subdomains":       recon.get("subdomains", []),
            "live_hosts":       recon.get("live_hosts", []),
            "urls":             recon.get("urls", []),
            "dns_records":      recon.get("dns_records", {}),
            "dns_issues":       (recon.get("dns_records") or {}).get("security_issues", []),
            "leak_recon":       recon.get("leak_recon", {}),
            "shodan":           recon.get("shodan", {}),
            "cloud_assets":     recon.get("cloud_assets", {}),
            "asn_info":         recon.get("asn_info", {}),
        },
        "enumeration": {
            "swagger":           enum.get("swagger", []),
            "graphql":           enum.get("graphql", []),
            "internal_services": enum.get("internal_services", []),
        },
        "surfaces":       surfaces,
        "attack_chains":  chain_results.get("chains", []),
        "pivot":          pivot_results,
        "jwt":            jwt_results,
        "authz":          authz_results,
    }

    print_terminal_summary(report_data)

    report_path = generate_report(report_data, output_dir=args.output)
    print(f"[+] HTML report saved: {report_path}\n")


if __name__ == "__main__":
    main()
