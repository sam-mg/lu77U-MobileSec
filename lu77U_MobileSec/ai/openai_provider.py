"""OpenAI provider for lu77U-MobileSec."""

import base64
import json
from typing import Any, Dict, List, Optional

import httpx

from .base_provider import BaseAIProvider
from .registry import CURATED_MODELS, DEFAULT_MODELS
from .schema import coerce_to_vuln_list
from ..utils.verbose import verbose_print

OPENAI_BASE_URL = "https://api.openai.com/v1"
_TIMEOUT = 120.0

class OpenAIProvider(BaseAIProvider):
    """OpenAI Chat Completions provider."""

    name = "openai"

    def default_model(self) -> str:
        return DEFAULT_MODELS["openai"]

    def base_url(self) -> str:
        return (self.config.get("base_url") or OPENAI_BASE_URL).rstrip("/")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _wrapped_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {"vulnerabilities": schema},
            "required": ["vulnerabilities"],
            "additionalProperties": False,
        }

    def supports_vision(self) -> bool:
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
        user_content: Any = prompt
        if images:
            user_content = [{"type": "text", "text": prompt}]
            for img in images:
                b64 = base64.b64encode(img).decode()
                user_content.append({"type": "image_url",
                                     "image_url": {"url": f"data:image/png;base64,{b64}"}})
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_content},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "vulnerability_report",
                    "schema": self._wrapped_schema(schema),
                },
            },
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
            vulns = coerce_to_vuln_list(content)
            if isinstance(vulns, (list, dict)):
                return {"response": json.dumps(vulns)}
            return {"response": content}
        except Exception as e:
            verbose_print(f"OpenAI analysis failed: {e}", self.verbose)
            return {"error": f"OpenAI request failed: {e}"}

    def list_models(self) -> List[str]:
        return list(CURATED_MODELS["openai"])

    def validate_credentials(self) -> bool:
        if not self.api_key:
            return False
        try:
            resp = httpx.get(self.base_url() + "/models", headers=self._headers(), timeout=30.0)
            return resp.status_code == 200
        except Exception as e:
            verbose_print(f"OpenAI credential validation failed: {e}", self.verbose)
            return False