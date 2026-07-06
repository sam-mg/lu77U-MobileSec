"""Anthropic Claude provider for lu77U-MobileSec."""

import base64
import json
from typing import Any, Dict, List, Optional

from .base_provider import BaseAIProvider
from .registry import CURATED_MODELS, DEFAULT_MODELS
from ..utils.verbose import verbose_print

_REPORT_TOOL_NAME = "report_vulnerabilities"

class ClaudeProvider(BaseAIProvider):
    """Claude (Anthropic Messages API) provider."""

    name = "claude"

    def default_model(self) -> str:
        return DEFAULT_MODELS["claude"]

    def _sdk_client(self):
        import anthropic  # lazy: only required when Claude is used
        return anthropic.Anthropic(api_key=self.api_key)

    def _tool_for(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap the array-typed vuln schema in an object tool input schema."""
        return {
            "name": _REPORT_TOOL_NAME,
            "description": "Report all security vulnerabilities found in the analyzed app.",
            "input_schema": {
                "type": "object",
                "properties": {"vulnerabilities": schema},
                "required": ["vulnerabilities"],
            },
        }

    def supports_vision(self) -> bool:
        # Every Claude 3+ model in the curated list accepts image input.
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
        content: Any = prompt
        if images:
            content = [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(img).decode()}}
                for img in images
            ]
            content.append({"type": "text", "text": prompt})
        try:
            client = self._sdk_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system_message,
                tools=[self._tool_for(schema)],
                tool_choice={"type": "tool", "name": _REPORT_TOOL_NAME},
                messages=[{"role": "user", "content": content}],
            )
            for block in response.content:
                if block.type == "tool_use" and block.name == _REPORT_TOOL_NAME:
                    vulns = block.input.get("vulnerabilities", [])
                    return {"response": json.dumps(vulns)}
            return {"error": "Claude returned no tool_use block"}
        except Exception as e:
            verbose_print(f"Claude analysis failed: {e}", self.verbose)
            return {"error": f"Claude request failed: {e}"}

    def list_models(self) -> List[str]:
        return list(CURATED_MODELS["claude"])

    def validate_credentials(self) -> bool:
        if not self.api_key:
            return False
        try:
            client = self._sdk_client()
            # Cheapest authenticated call that fails fast on a bad key.
            client.models.list()
            return True
        except Exception as e:
            verbose_print(f"Claude credential validation failed: {e}", self.verbose)
            return False