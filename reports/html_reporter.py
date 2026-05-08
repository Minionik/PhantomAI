import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = os.path.dirname(__file__)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#16a34a",
    "info":     "#6b7280",
}


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _overall_risk(counts: dict) -> str:
    if counts.get("critical", 0) > 0:
        return "CRITICAL"
    if counts.get("high", 0) > 0:
        return "HIGH"
    if counts.get("medium", 0) > 0:
        return "MEDIUM"
    if counts.get("low", 0) > 0:
        return "LOW"
    return "INFO"


def generate_report(data: dict, output_dir: str = ".") -> str:
    """
    Render an HTML report from scan data and save it to output_dir.
    Returns the absolute path to the saved report.
    """
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("template.html")

    findings = data.get("findings", [])
    findings.sort(key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 99))
    counts = _count_by_severity(findings)
    risk = _overall_risk(counts)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    output_path = os.path.join(output_dir, filename)

    html = template.render(
        target=data.get("target", "unknown"),
        scan_date=timestamp,
        stack=data.get("stack", {}),
        executive_summary=data.get("executive_summary", ""),
        findings=findings,
        counts=counts,
        overall_risk=risk,
        severity_colors=SEVERITY_COLORS,
        recon=data.get("recon", {}),
    )

    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return os.path.abspath(output_path)


def print_terminal_summary(data: dict) -> None:
    findings = data.get("findings", [])
    counts = _count_by_severity(findings)
    risk = _overall_risk(counts)

    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Target      : {data.get('target', 'unknown')}")
    print(f"  Overall Risk: {risk}")
    print(f"  Critical    : {counts['critical']}")
    print(f"  High        : {counts['high']}")
    print(f"  Medium      : {counts['medium']}")
    print(f"  Low         : {counts['low']}")
    print("=" * 60)

    top = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")][:3]
    if top:
        print("\n  TOP FINDINGS:")
        for i, f in enumerate(top, 1):
            sev = str(f.get("severity", "")).upper()
            title = f.get("title", f.get("finding", "Unknown"))
            owasp = f.get("owasp_category", f.get("owasp", ""))
            print(f"  {i}. [{sev}] {title} ({owasp})")
    print("=" * 60 + "\n")
