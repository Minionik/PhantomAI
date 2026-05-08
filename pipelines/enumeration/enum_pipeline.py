import os
import tempfile
from urllib.parse import urlparse, parse_qs
from core.run_cmd import run_cmd, dedupe

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "dirs.txt")


def run_enum(target: str, urls: list, stack: dict = None, ai=None) -> dict:
    results = {}

    # --- Directory Fuzzing ---
    wordlist = os.path.abspath(WORDLIST_PATH)

    # AI-enhanced wordlist: add stack-specific paths
    extra_paths = []
    if ai and ai.is_available() and stack:
        from core.tech_fingerprint import stack_summary
        summary = stack_summary(stack)
        if summary and summary != "unknown":
            prompt = (
                f"Target web application uses: {summary}\n"
                "List 20 directory/file paths likely to exist on this stack that a pentester should check. "
                "Examples: config files, admin panels, debug endpoints, backup files, framework-specific paths. "
                "Return ONLY a newline-separated list of paths (no leading slash, no commentary)."
            )
            ai_response = ai.ask(prompt, model="fast")
            if ai_response:
                extra_paths = [p.strip().lstrip("/") for p in ai_response.splitlines() if p.strip()]

    # Merge AI suggestions into a temp wordlist
    fuzz_wordlist = wordlist
    if extra_paths:
        try:
            with open(wordlist, "r") as base:
                base_content = base.read()
            merged = base_content.rstrip() + "\n" + "\n".join(extra_paths)
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write(merged)
            tmp.close()
            fuzz_wordlist = tmp.name
        except Exception:
            pass

    fuzz_out = run_cmd(
        f"ffuf -u http://{target}/FUZZ -w {fuzz_wordlist} -mc 200,301,302,403 -c -t 40",
        timeout=120,
    )
    results["fuzz"] = fuzz_out[:300]

    # Clean up temp wordlist
    if extra_paths and fuzz_wordlist != wordlist:
        try:
            os.unlink(fuzz_wordlist)
        except Exception:
            pass

    # --- Parameter Extraction ---
    # Extract param names AND full parameterised URLs
    param_urls = []
    param_names = set()
    for url in urls[:150]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            param_urls.append(url)
            param_names.update(qs.keys())

    results["params"] = dedupe(param_urls)
    results["param_names"] = list(param_names)

    return results
