import os
import json
import requests as _http
from dotenv import load_dotenv

load_dotenv()

# Claude model IDs
_MODEL_HAIKU  = "claude-haiku-4-5-20251001"   # fast + cheap
_MODEL_SONNET = "claude-sonnet-4-6"            # deep reasoning

# Tier constants — set AI_TIER in .env to control behaviour
TIER_FREE  = "free"    # Ollama (local models, zero API cost)
TIER_BASIC = "basic"   # Claude Haiku only (paid, but cheapest option)
TIER_PRO   = "pro"     # Claude Haiku + Sonnet (full capability)

_SYSTEM_PENTEST = (
    "You are an expert penetration tester with deep knowledge of the OWASP Top 10 (2025), "
    "CVEs, CWE taxonomy, and web application security. Be precise and concise. "
    "Always return valid JSON when asked."
)


class AIEngine:
    """
    Tiered AI backend — auto-selects based on .env:

        AI_TIER=free   → Ollama local model (zero cost, requires Ollama running)
        AI_TIER=basic  → Claude Haiku only  (cheapest paid option)
        AI_TIER=pro    → Claude Haiku + Sonnet (highest quality, default when API key set)
        AI_TIER=auto   → no key = free (Ollama), key present = pro  [default]
    """

    def __init__(self):
        self._claude       = None
        self._available    = False
        self._tier         = self._resolve_tier()
        self._ollama_host  = os.getenv("OLLAMA_HOST",  "http://localhost:11434").rstrip("/")
        self._ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")

        if self._tier == TIER_FREE:
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
        if self._tier == TIER_FREE:
            return f"FREE  (Ollama / {self._ollama_model})"
        if self._tier == TIER_BASIC:
            return f"BASIC (Claude Haiku only)"
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
        if raw == TIER_FREE:
            return TIER_FREE
        if raw == TIER_BASIC:
            return TIER_BASIC
        if raw == TIER_PRO:
            return TIER_PRO
        # auto: presence of a real API key → pro, otherwise → free
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
            print(f"[!] Claude API error: {e}")
            return ""

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n...[truncated]"
