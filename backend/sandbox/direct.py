"""
Direct Harness — sends payload directly to the victim model.

Used for direct prompt injection, system prompt leak, RCE, SQLi, SSRF, access control.
"""
import os
import logging
import requests

logger       = logging.getLogger(__name__)
OLLAMA_URL   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
VICTIM_MODEL = os.getenv("VICTIM_MODEL", "mistral")


class DirectHarness:
    def inject(self, payload: str, vuln_type: str = "") -> str:
        try:
            resp = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": VICTIM_MODEL,
                    "prompt": payload,
                    "stream": False,
                    "options": {"num_predict": 120},
                },
                timeout=60,
            )
            return resp.json().get("response", "ERROR")
        except Exception as exc:
            logger.error("DirectHarness error: %s", exc)
            return "ERROR"
