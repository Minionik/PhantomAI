import os
import json
import subprocess
import requests as _http
from dotenv import load_dotenv

load_dotenv()

# Claude model IDs
_MODEL_HAIKU  = "claude-haiku-4-5-20251001"   # fast + cheap
_MODEL_SONNET = "claude-sonnet-4-6"            # deep reasoning

# Tier constants — set AI_TIER in .env to control behaviour
TIER_FREE  = "free"         # Ollama (local models, zero API cost)
TIER_BASIC = "basic"        # Claude Haiku only (paid, but cheapest option)
TIER_PRO   = "pro"          # Claude Haiku + Sonnet (full capability)
TIER_CODE  = "claude_code"  # Claude Code CLI — bills against Pro/Max subscription

_SYSTEM_PENTEST = (
    "You are an expert penetration tester with deep knowledge of the OWASP Top 10 (2025), "
    "CVEs, CWE taxonomy, and web application security. Be precise and concise. "
    "Always return valid JSON when asked."
)


class AIEngine:
    """
    Tiered AI backend — auto-selects based on .env:

        AI_TIER=claude_code → Claude Code CLI (uses Pro/Max subscription — zero extra cost)
        AI_TIER=free        → Ollama local model (zero cost, requires Ollama running)
        AI_TIER=basic       → Claude Haiku only  (cheapest paid option)
        AI_TIER=pro         → Claude Haiku + Sonnet (highest quality, default when API key set)
        AI_TIER=auto        → claude CLI found = claude_code; API key = pro; else = free [default]
    """

    def __init__(self):
        self._claude       = None
        self._available    = False
        self._ollama_host  = os.getenv("OLLAMA_HOST",  "http://localhost:11434").rstrip("/")
        self._ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        self._tier         = self._resolve_tier()

        if self._tier == TIER_CODE:
            self._available = True  # CLI already confirmed in _resolve_tier
        elif self._tier == TIER_FREE:
            self._available = self._check_ollama()
        else:
            api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
            if api_key and api_key != "your_api_key_here":
                try:
                    import anthropic
                    self._claude    = anthropic.Anthropic(api_key=api_key)
                    self._available = True
                except ImportError:
                    print("[!] anthropic package not installed — run: pip install anthropic")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return self._available

    def tier(self) -> str:
        return self._tier

    def tier_label(self) -> str:
        if self._tier == TIER_CODE:
            return "SUBSCRIPTION (Claude Code / Pro — zero extra cost)"
        if self._tier == TIER_FREE:
            return f"FREE  (Ollama / {self._ollama_model})"
        if self._tier == TIER_BASIC:
            return "BASIC (Claude Haiku only)"
        return "PRO   (Claude Haiku + Sonnet)"

    def ask(self, prompt: str, model: str = "fast") -> str:
        """
        Send a prompt and return plain text.
        model="fast" → cheap model   (Haiku / Ollama)
        model="deep" → capable model (Sonnet / Ollama — same model in free tier)
        """
        if not self._available:
            return ""
        prompt = self._truncate(prompt, 3000)
        if self._tier == TIER_CODE:
            return self._ask_claude_code(prompt)
        if self._tier == TIER_FREE:
            return self._ask_ollama(prompt)
        return self._ask_claude(prompt, model)

    def ask_json(self, prompt: str, model: str = "fast") -> dict | list | None:
        """Send prompt, parse response as JSON. Returns None on failure."""
        raw = self.ask(prompt, model=model)
        if not raw:
            return None
        clean = raw.strip()
        # strip markdown code fences Claude/Ollama sometimes add
        if clean.startswith("```"):
            lines = clean.splitlines()
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_tier(self) -> str:
        raw = os.getenv("AI_TIER", "auto").lower().strip()
        if raw == TIER_CODE:
            return TIER_CODE if self._check_claude_code() else TIER_FREE
        if raw == TIER_FREE:
            return TIER_FREE
        if raw == TIER_BASIC:
            return TIER_BASIC
        if raw == TIER_PRO:
            return TIER_PRO
        # auto priority: claude CLI → pro (API key) → free (Ollama)
        if self._check_claude_code():
            return TIER_CODE
        key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if key and key != "your_api_key_here":
            return TIER_PRO
        return TIER_FREE

    def _check_ollama(self) -> bool:
        """Return True if Ollama is reachable and the configured model is available."""
        try:
            r = _http.get(f"{self._ollama_host}/api/tags", timeout=3)
            if r.status_code != 200:
                return False
            models = [m.get("name", "") for m in r.json().get("models", [])]
            # Accept prefix match so "llama3.2" matches "llama3.2:latest"
            found = any(m.startswith(self._ollama_model) for m in models)
            if not found:
                print(f"[!] Ollama model '{self._ollama_model}' not found locally.")
                print(f"    Pull it with: ollama pull {self._ollama_model}")
            return found
        except Exception:
            print("[!] Ollama not reachable at", self._ollama_host)
            print("    Install from https://ollama.com and run: ollama serve")
            return False

    def _check_claude_code(self) -> bool:
        """Return True if the `claude` CLI is installed and accessible."""
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _ask_claude_code(self, prompt: str) -> str:
        """Send prompt via `claude -p` — bills against the user's Pro/Max subscription."""
        full_prompt = f"{_SYSTEM_PENTEST}\n\n{prompt}"
        try:
            result = subprocess.run(
                ["claude", "-p", full_prompt],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                return result.stdout.strip()
            print(f"[!] Claude Code CLI error: {result.stderr.strip()[:200]}")
        except FileNotFoundError:
            print("[!] `claude` CLI not found — install Claude Code: https://claude.ai/code")
            self._available = False
        except subprocess.TimeoutExpired:
            print("[!] Claude Code CLI timed out")
        return ""

    def _ask_ollama(self, prompt: str) -> str:
        try:
            payload = {
                "model":    self._ollama_model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PENTEST},
                    {"role": "user",   "content": prompt},
                ],
                "stream": False,
            }
            r = _http.post(f"{self._ollama_host}/api/chat", json=payload, timeout=120)
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"[!] Ollama error: {e}")
            return ""

    def _ask_claude(self, prompt: str, model: str = "fast") -> str:
        # BASIC tier: force Haiku regardless of what caller requests
        if self._tier == TIER_BASIC:
            target_model = _MODEL_HAIKU
        else:
            target_model = _MODEL_HAIKU if model == "fast" else _MODEL_SONNET

        max_tokens = 1024 if target_model == _MODEL_HAIKU else 3000
        try:
            response = self._claude.messages.create(
                model=target_model,
                max_tokens=max_tokens,
                system=[
                    {
                        "type": "text",
                        "text": _SYSTEM_PENTEST,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text.strip()
        except Exception as e:
            return self._handle_claude_error(e, prompt)

    def _handle_claude_error(self, exc: Exception, prompt: str) -> str:
        """
        Called when a Claude API call fails.
        - Credit / billing errors  → disable Claude for the session, try Ollama fallback.
        - All other errors         → print once and return empty string.
        """
        msg = str(exc).lower()
        is_credit_error = (
            "credit balance" in msg
            or "insufficient_funds" in msg
            or "billing" in msg
            or ("400" in msg and "credit" in msg)
        )

        if is_credit_error:
            # Disable Claude for the rest of this scan — avoids printing this on every call.
            self._claude     = None
            self._available  = False

            print("\n[!] Claude API: insufficient credits.")
            print("    Your claude.ai Pro subscription does NOT include API credits.")
            print("    API credits are billed separately at console.anthropic.com\n")
            print("    Zero-cost options:")
            print("      1. Claude Code CLI (uses your Pro/Max subscription — recommended)")
            print("         Install: https://claude.ai/code  →  set AI_TIER=claude_code in .env")
            print("      2. Install Ollama → set AI_TIER=free in .env")
            print("         https://ollama.com  →  ollama pull llama3.2")
            print("      3. Run with --no-ai flag for rule-based scanning\n")

            # Auto-fallback to Ollama if it's already running
            if self._check_ollama():
                self._tier      = TIER_FREE
                self._available = True
                print("[+] Ollama detected — switching to free tier automatically\n")
                return self._ask_ollama(prompt)
        else:
            print(f"[!] Claude API error: {exc}")

        return ""

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n...[truncated]"
