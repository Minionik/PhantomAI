import os
import requests
from core.run_cmd import run_cmd

_DOH_URL = "https://dns.google/resolve"
_DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "smtp", "email",
    "mandrill", "mailchimp", "sendgrid", "amazonses",
]


def _doh_query(name: str, record_type: str) -> list[str]:
    try:
        r = requests.get(
            _DOH_URL,
            params={"name": name, "type": record_type},
            timeout=8,
            headers={"Accept": "application/dns-json"},
        )
        data = r.json()
        answers = data.get("Answer") or []
        return [a.get("data", "").strip('"') for a in answers if a.get("type")]
    except Exception:
        return []


def _spf_from_txt(txt_records: list[str]) -> str | None:
    for r in txt_records:
        if r.lower().startswith("v=spf1"):
            return r
    return None


def _dmarc_record(domain: str) -> str | None:
    records = _doh_query(f"_dmarc.{domain}", "TXT")
    for r in records:
        if "v=DMARC1" in r:
            return r
    return None


def _dkim_records(domain: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for sel in _DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        records = _doh_query(name, "TXT")
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                found[sel] = r
                break
    return found


def _zone_transfer(domain: str, ns_servers: list[str]) -> list[str]:
    results: list[str] = []
    for ns in ns_servers[:3]:
        ns_clean = ns.rstrip(".")
        lines = run_cmd(f"dig AXFR {domain} @{ns_clean}", timeout=15)
        # Zone transfer succeeded if we get actual records back (not just SOA refusal)
        records = [l for l in lines if l and not l.startswith(";") and "\t" in l]
        if len(records) > 2:
            results.extend(records)
            break
    return results


def dns_records(domain: str) -> dict:
    result: dict = {
        "ns": [],
        "mx": [],
        "txt": [],
        "a": [],
        "aaaa": [],
        "cname": [],
        "spf": None,
        "dmarc": None,
        "dkim": {},
        "zone_transfer": [],
        "security_issues": [],
    }

    result["ns"]   = _doh_query(domain, "NS")
    result["mx"]   = _doh_query(domain, "MX")
    result["txt"]  = _doh_query(domain, "TXT")
    result["a"]    = _doh_query(domain, "A")
    result["aaaa"] = _doh_query(domain, "AAAA")
    result["cname"] = _doh_query(domain, "CNAME")

    result["spf"]   = _spf_from_txt(result["txt"])
    result["dmarc"] = _dmarc_record(domain)
    result["dkim"]  = _dkim_records(domain)

    ns_bare = [ns.rstrip(".") for ns in result["ns"]]
    if ns_bare:
        result["zone_transfer"] = _zone_transfer(domain, ns_bare)

    # Security analysis
    issues = result["security_issues"]

    if not result["spf"]:
        issues.append({"issue": "No SPF record", "risk": "high",
                       "detail": "Domain is open to email spoofing (no v=spf1 policy)"})
    elif "~all" in result["spf"]:
        issues.append({"issue": "SPF soft-fail (~all)", "risk": "medium",
                       "detail": "SPF policy uses ~all (softfail) — should be -all"})
    elif "+all" in result["spf"]:
        issues.append({"issue": "SPF allows all (+all)", "risk": "critical",
                       "detail": "SPF policy +all permits any server to send as this domain"})

    if not result["dmarc"]:
        issues.append({"issue": "No DMARC record", "risk": "high",
                       "detail": "No DMARC policy; spoofed emails reach inboxes with no enforcement"})
    else:
        dmarc = result["dmarc"].lower()
        if "p=none" in dmarc:
            issues.append({"issue": "DMARC policy=none (monitor only)", "risk": "medium",
                           "detail": "DMARC is present but p=none means no enforcement action"})

    if not result["dkim"]:
        issues.append({"issue": "No DKIM selectors found", "risk": "low",
                       "detail": f"Checked selectors: {', '.join(_DKIM_SELECTORS[:8])}…"})

    if result["zone_transfer"]:
        issues.append({"issue": "Zone transfer allowed (AXFR)", "risk": "critical",
                       "detail": f"DNS zone transfer succeeded — exposes full subdomain map "
                                 f"({len(result['zone_transfer'])} records)"})

    return result
