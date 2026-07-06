"""Custom (self-hosted / proxy) provider for lu77U-MobileSec."""

import base64
from typing import Any, Dict, List, Optional

import httpx

from .base_provider import BaseAIProvider
from ..utils.verbose import verbose_print

_TIMEOUT = 120.0

class CustomProvider(BaseAIProvider):
    """OpenAI-compatible custom endpoint provider."""

    name = "custom"

    def base_url(self) -> str:
        return (self.config.get("base_url") or "").rstrip("/")

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def supports_vision(self) -> bool:
        return True

    def analyze(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        images: Optional[List[bytes]] = None,
    ) -> Dict[str, Any]:
        if not self.base_url():
            return {"error": "Custom provider has no base URL configured"}
        system_message = system_message or self.default_system_message
        user_content: Any = prompt
        if images:
            user_content = [{"type": "text", "text": prompt}]
            for img in images:
                b64 = base64.b64encode(img).decode()
                user_content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}})
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_content},
            ],
        }
        try:
            resp = httpx.post(
                self.base_url() + "/chat/completions",
                headers=self._headers(),
                json=body,
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            # Return raw content; response_parser handles fenced/loose JSON.
            return {"response": content}
        except Exception as e:
            verbose_print(f"Custom provider analysis failed: {e}", self.verbose)
            return {"error": f"Custom request failed: {e}"}

    def list_models(self) -> List[str]:
        """Try the server's /models endpoint; fall back to the configured model."""
        try:
            resp = httpx.get(self.base_url() + "/models", headers=self._headers(), timeout=30.0)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            ids = [m.get("id", "") for m in data if m.get("id")]
            if ids:
                return ids
        except Exception:
            pass
        return [self.model] if self.model else []

    def validate_credentials(self) -> bool:
        if not self.base_url():
            return False
        try:
            resp = httpx.get(self.base_url() + "/models", headers=self._headers(), timeout=30.0)
            return resp.status_code < 500
        except Exception as e:
            verbose_print(f"Custom credential validation failed: {e}", self.verbose)
            return False