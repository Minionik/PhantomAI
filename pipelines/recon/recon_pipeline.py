from core.run_cmd import run_cmd, dedupe


def run_recon(target: str, ai=None) -> dict:
    results = {}

    # --- Subdomain Enumeration ---
    subfinder = run_cmd(f"subfinder -d {target} -silent", timeout=120)
    assetfinder = run_cmd(f"assetfinder {target}", timeout=60)
    amass = run_cmd(f"amass enum -passive -d {target}", timeout=180)

    subs = dedupe(subfinder + assetfinder + amass)
    results["subdomains"] = subs

    # --- Live Host Detection ---
    # Write subs to temp file to avoid stdin pipe issues on Windows
    live = []
    if subs:
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(subs))
            tmp_path = tmp.name
        live = run_cmd(f"httpx -silent -l {tmp_path}", timeout=120)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    results["live_hosts"] = dedupe(live)

    # --- URL Gathering ---
    gau = run_cmd(f"gau {target}", timeout=120)
    wayback = run_cmd(f"waybackurls {target}", timeout=120)
    raw_urls = dedupe(gau + wayback)

    # --- AI URL Prioritization ---
    if ai and ai.is_available() and len(raw_urls) > 20:
        url_text = "\n".join(raw_urls)
        prompt = (
            f"Target domain: {target}\n"
            f"Discovered URLs ({len(raw_urls)} total, showing first 2000 chars):\n"
            f"{url_text[:2000]}\n\n"
            "Return the top 50 most interesting attack surface URLs. "
            "Prioritize: URLs with query parameters, admin/panel paths, API endpoints, "
            "file upload paths, authentication paths, and backup/config files. "
            "Return ONLY a newline-separated list of URLs, no commentary."
        )
        ai_response = ai.ask(prompt, model="fast")
        if ai_response:
            prioritized = [u.strip() for u in ai_response.splitlines() if u.strip().startswith("http")]
            if len(prioritized) >= 10:
                raw_urls = prioritized

    results["urls"] = raw_urls[:200]  # hard cap to avoid downstream bloat
    return results
