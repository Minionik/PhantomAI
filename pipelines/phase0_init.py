from core.input.target_handler import TargetHandler
from core.validation.web_check import WebChecker
from core.validation.network_check import NetworkChecker


def run_phase0(ai=None, target_arg=None):
    handler = TargetHandler()
    web = WebChecker()
    net = NetworkChecker()

    if target_arg:
        target = handler.normalize(target_arg)
        # Auto-detect mode: if it looks like a domain/URL, use web
        mode = "a"
        print(f"[*] Target: {target} (auto mode: web)")
    else:
        print("Select mode:")
        print("  a) Web")
        print("  b) Network")
        mode = input("Choice: ").strip().lower()
        target = handler.normalize(input("Enter target: "))

    result = {
        "target": target,
        "mode": mode,
        "reachable": False,
        "details": {},
        "stack": {},
    }

    if mode == "a":
        http = web.check_http(target)
        https = web.check_https(target)
        httpx = web.check_httpx(target)

        result["details"] = {"http": http, "https": https, "httpx": httpx}

        if http or https or httpx:
            result["reachable"] = True
            # Tech fingerprinting — only if reachable
            try:
                from core.tech_fingerprint import fingerprint
                result["stack"] = fingerprint(target, ai=ai)
            except Exception:
                pass

    elif mode == "b":
        ping = net.ping(target)
        nmap = net.nmap_scan(target)

        result["details"] = {"ping": ping, "nmap": nmap}

        if ping or "open" in nmap.lower():
            result["reachable"] = True

    return result
