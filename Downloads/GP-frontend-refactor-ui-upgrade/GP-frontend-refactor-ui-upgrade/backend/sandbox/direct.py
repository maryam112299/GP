"""
Direct Harness — sends payload directly to the victim model.

Used for direct prompt injection, system prompt leak, RCE, SQLi, SSRF, access control.
"""
import os
import logging
import requests

logger       = logging.getLogger(__name__)
OLLAMA_URL   = os.getenv("VICTIM_BASE_URL", os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
VICTIM_MODEL = os.getenv("VICTIM_MODEL", "mistral")


class DirectHarness:
    def inject(self, payload: str, vuln_type: str = "",
               victim_url: str = "", victim_model: str = "") -> str:
        url   = victim_url   or OLLAMA_URL
        model = victim_model or VICTIM_MODEL
        try:
            resp = requests.post(
                f"{url}/api/generate",
                json={
                    "model": model,
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
