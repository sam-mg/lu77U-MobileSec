"""Google Gemini provider for lu77U-MobileSec."""

import base64
import json
from typing import Any, Dict, List, Optional

import httpx

from .base_provider import BaseAIProvider
from .registry import CURATED_MODELS, DEFAULT_MODELS
from .schema import coerce_to_vuln_list
from ..utils.verbose import verbose_print

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
_TIMEOUT = 120.0

class GeminiProvider(BaseAIProvider):
    """Google Gemini provider."""

    name = "gemini"

    def default_model(self) -> str:
        return DEFAULT_MODELS["gemini"]

    def base_url(self) -> str:
        return (self.config.get("base_url") or GEMINI_BASE_URL).rstrip("/")

    def supports_vision(self) -> bool:
        # Every curated Gemini 2.x model is natively multimodal.
        return True

    def analyze(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        images: Optional[List[bytes]] = None,
    ) -> Dict[str, Any]:
        system_message = system_message or self.default_system_message
        schema = schema or self.schema
        url = f"{self.base_url()}/models/{self.model}:generateContent?key={self.api_key}"
        verbose_print(f"Gemini request: {self.base_url()}/models/{self.model}:generateContent?key=***", self.verbose)
        parts: List[Dict[str, Any]] = [{"text": prompt}]
        for img in images or []:
            parts.append({"inline_data": {"mime_type": "image/png",
                                          "data": base64.b64encode(img).decode()}})
        body = {
            "system_instruction": {"parts": [{"text": system_message}]},
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": schema,
            },
        }
        try:
            resp = httpx.post(url, json=body, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            vulns = coerce_to_vuln_list(text)
            if isinstance(vulns, (list, dict)):
                return {"response": json.dumps(vulns)}
            return {"response": text}
        except Exception as e:
            verbose_print(f"Gemini analysis failed: {e}", self.verbose)
            return {"error": f"Gemini request failed: {e}"}

    def list_models(self) -> List[str]:
        return list(CURATED_MODELS["gemini"])

    def validate_credentials(self) -> bool:
        if not self.api_key:
            return False
        try:
            resp = httpx.get(
                f"{self.base_url()}/models?key={self.api_key}",
                timeout=30.0)
            return resp.status_code == 200
        except Exception as e:
            verbose_print(f"Gemini credential validation failed: {e}", self.verbose)
            return False