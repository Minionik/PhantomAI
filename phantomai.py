import argparse
import os
import warnings
import urllib3
from dotenv import load_dotenv

# Suppress InsecureRequestWarning globally — PhantomAI intentionally sends
# requests to targets with self-signed / invalid certificates (pentest context).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from core.ai_engine import AIEngine
from pipelines.phase0_init import run_phase0
from pipelines.recon.recon_pipeline import run_recon
from pipelines.enumeration.enum_pipeline import run_enum
from pipelines.vuln_analysis.vuln_pipeline import run_vuln
from pipelines.exploitation.exploit_pipeline import run_exploit
from pipelines.post_exploitation.post_pipeline import run_post
from reports.html_reporter import generate_report, print_terminal_summary

load_dotenv()

_BANNER = r"""
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ██╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║███████║██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
  AI-Powered Penetration Testing Framework  |  OWASP 2025  |  v1.0
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

    # Phase 0: Validation + Tech Fingerprinting
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

    # Phase 1: Recon
    print("\n[*] Phase 1: Reconnaissance")
    recon = run_recon(target, ai=ai)
    print(f"    Subdomains : {len(recon.get('subdomains', []))} | "
          f"Live hosts : {len(recon.get('live_hosts', []))} | "
          f"URLs : {len(recon.get('urls', []))}")

    # Phase 2: Enumeration
    print("\n[*] Phase 2: Enumeration")
    enum = run_enum(target, recon.get("urls", []), stack=stack, ai=ai)
    print(f"    Fuzz hits : {len(enum.get('fuzz', []))} | "
          f"Params found : {len(enum.get('params', []))}")

    # Phase 3: Vulnerability Analysis
    print("\n[*] Phase 3: Vulnerability Analysis")
    vuln    = run_vuln(target, recon.get("urls", []), stack=stack, ai=ai)
    triaged = vuln.get("triaged", [])
    print(f"    Triaged findings : {len(triaged)}")

    # Phase 4: Exploitation
    print("\n[*] Phase 4: Exploitation")
    exploit = run_exploit(target, enum.get("params", []), stack=stack, ai=ai)
    print(f"    Exploitation results : {len(exploit.get('results', {}))}")

    # Phase 5: Post-Exploitation + Report
    print("\n[*] Phase 5: Report Generation")
    post = run_post(
        target=target,
        stack=stack,
        triaged_findings=triaged,
        exploit_results=exploit.get("results", {}),
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
            "subdomains": recon.get("subdomains", []),
            "live_hosts":  recon.get("live_hosts", []),
            "urls":        recon.get("urls", []),
        },
    }

    print_terminal_summary(report_data)

    report_path = generate_report(report_data, output_dir=args.output)
    print(f"[+] HTML report saved: {report_path}\n")


if __name__ == "__main__":
    main()
