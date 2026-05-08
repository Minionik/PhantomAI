import os
import json
from dotenv import load_dotenv

load_dotenv()

MODEL_FAST = "claude-haiku-4-5-20251001"   # cheap: triage, classification, scoring
MODEL_DEEP = "claude-sonnet-4-6"           # smart: payloads, report generation

_SYSTEM_PENTEST = (
    "You are an expert penetration tester with deep knowledge of the OWASP Top 10 (2025), "
    "CVEs, CWE taxonomy, and web application security. Be precise and concise. "
    "Always return valid JSON when asked."
)


class AIEngine:
    def __init__(self):
        self._client = None
        self._available = False
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
                self._available = True
            except ImportError:
                print("[!] anthropic package not installed — run: pip install anthropic")

    def is_available(self) -> bool:
        return self._available

    def ask(self, prompt: str, model: str = "fast", json_mode: bool = False) -> str:
        if not self._available:
            return ""
        target_model = MODEL_FAST if model == "fast" else MODEL_DEEP
        prompt = self._truncate(prompt, 3000)
        # Haiku responses are short (triage/classification); Sonnet needs room for full JSON reports
        max_tokens = 1024 if target_model == MODEL_FAST else 3000
        try:
            response = self._client.messages.create(
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
            print(f"[!] AI error: {e}")
            return ""

    def ask_json(self, prompt: str, model: str = "fast") -> dict | list | None:
        raw = self.ask(prompt, model=model)
        if not raw:
            return None
        # strip markdown fences if present
        clean = raw.strip()
        if clean.startswith("```"):
            lines = clean.splitlines()
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _truncate(text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n...[truncated]"
