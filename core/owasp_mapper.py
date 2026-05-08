OWASP_2025 = {
    "A01": {
        "name": "Broken Access Control",
        "cwe": ["CWE-22", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"],
        "keywords": ["idor", "access control", "unauthorized", "privilege", "traversal", "directory listing", "forbidden bypass"],
    },
    "A02": {
        "name": "Cryptographic Failures",
        "cwe": ["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-326", "CWE-327"],
        "keywords": ["ssl", "tls", "weak cipher", "plaintext", "http only", "cleartext", "certificate", "md5", "sha1"],
    },
    "A03": {
        "name": "Injection",
        "cwe": ["CWE-20", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"],
        "keywords": ["sql", "sqli", "injection", "xss", "cross-site scripting", "ssti", "template injection", "command injection", "xxe", "ldap"],
    },
    "A04": {
        "name": "Insecure Design",
        "cwe": ["CWE-73", "CWE-183", "CWE-209", "CWE-256", "CWE-501"],
        "keywords": ["insecure design", "logic flaw", "business logic", "race condition", "mass assignment"],
    },
    "A05": {
        "name": "Security Misconfiguration",
        "cwe": ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16"],
        "keywords": ["misconfiguration", "default credentials", "debug", "stack trace", "cors", "open redirect", "exposed admin", "phpinfo", "server-status"],
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "cwe": ["CWE-937", "CWE-1035", "CWE-1104"],
        "keywords": ["outdated", "cve-", "vulnerable version", "end of life", "unpatched", "dependency"],
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "cwe": ["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-307", "CWE-521"],
        "keywords": ["brute force", "weak password", "default password", "no mfa", "session fixation", "jwt", "authentication bypass", "credential stuffing"],
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "cwe": ["CWE-345", "CWE-353", "CWE-426", "CWE-494"],
        "keywords": ["deserialization", "integrity", "supply chain", "unsigned", "cdn", "subresource integrity"],
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "cwe": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "keywords": ["no logging", "log injection", "missing log", "no monitoring"],
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "cwe": ["CWE-918"],
        "keywords": ["ssrf", "server-side request forgery", "internal", "169.254", "localhost", "metadata"],
    },
}


def map_finding(text: str) -> str:
    """Return the most likely OWASP 2025 category ID for a finding text."""
    lower = text.lower()
    for cat_id, cat in OWASP_2025.items():
        for kw in cat["keywords"]:
            if kw in lower:
                return cat_id
    return "A05"  # default to misconfiguration when unknown


def get_category(cat_id: str) -> dict:
    return OWASP_2025.get(cat_id, OWASP_2025["A05"])
