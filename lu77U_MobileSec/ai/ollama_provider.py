"""Ollama provider (local or cloud) for lu77U-MobileSec."""

import base64
import time
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime

from .base_provider import BaseAIProvider
from .registry import DEFAULT_MODELS
from ..config.settings import (
    OLLAMA_MAX_RETRIES, OLLAMA_REQUEST_TIMEOUT, OLLAMA_RETRY_DELAY,
)
from ..utils.verbose import verbose_print

DEFAULT_CLOUD_HOST = "https://api.ollama.com"
DEFAULT_LOCAL_HOST = "http://localhost:11434"

_VISION_MODEL_HINTS = (
    "llava", "vision", "-vl", "vl-", "moondream", "minicpm-v", "bakllava",
    "gemma3", "qwen2-vl", "qwen2.5vl", "pixtral", "llama3.2-vision",
)

class OllamaProvider(BaseAIProvider):
    """Ollama Cloud / local provider."""

    name = "ollama"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = self.config.get("mode", "cloud")
        if self.mode == "local":
            self.host = self.config.get("local_host", DEFAULT_LOCAL_HOST)
        else:
            self.host = self.config.get("cloud_host", DEFAULT_CLOUD_HOST)
        verbose_print(
            f"Initializing OllamaProvider (mode={self.mode}, model={self.model}, host={self.host})",
            self.verbose,
        )
        self._client = None

    def default_model(self) -> str:
        return DEFAULT_MODELS["ollama"]

    @property
    def client(self):
        """Lazily build the ollama Client (auth header only in cloud mode).

        A bounded ``timeout`` is essential: the ollama-python client defaults to
        no timeout, so a stalled cloud stream would hang the entire scan forever
        with no retry. With a timeout, a stall raises, retries (see ``analyze``),
        and — if it persists — returns an error the caller degrades gracefully.
        """
        if self._client is None:
            from ollama import Client
            try:
                import httpx
                # read/write/pool = OLLAMA_REQUEST_TIMEOUT (max gap with no data);
                # keep connect short so an unreachable host fails fast.
                timeout = httpx.Timeout(OLLAMA_REQUEST_TIMEOUT, connect=30.0)
            except Exception:
                timeout = OLLAMA_REQUEST_TIMEOUT
            headers = None
            if self.mode != "local" and self.api_key:
                headers = {"Authorization": f"Bearer {self.api_key}"}
            self._client = Client(host=self.host, headers=headers, timeout=timeout)
        return self._client

    def supports_vision(self) -> bool:
        model = (self.model or "").lower()
        return any(hint in model for hint in _VISION_MODEL_HINTS)

    def analyze(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        images: Optional[List[bytes]] = None,
    ) -> Dict[str, Any]:
        system_message = system_message or self.default_system_message
        schema = schema or self.schema

        verbose_print(
            f"Starting Ollama analysis - Prompt: {len(prompt)} chars, System: {len(system_message)} chars",
            self.verbose,
        )
        retry_delay = OLLAMA_RETRY_DELAY
        request_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for attempt in range(OLLAMA_MAX_RETRIES):
            try:
                verbose_print(f"Attempt {attempt + 1}/{OLLAMA_MAX_RETRIES}", self.verbose)
                user_message = {"role": "user", "content": prompt}
                if images:
                    user_message["images"] = [base64.b64encode(img).decode() for img in images]
                messages = [
                    {"role": "system", "content": system_message},
                    user_message,
                ]
                response_content = ""
                for part in self.client.chat(
                    self.model, messages=messages, stream=True, format=schema
                ):
                    if "message" in part and "content" in part["message"]:
                        response_content += part["message"]["content"]

                verbose_print(f"Response received: {len(response_content)} chars", self.verbose)

                if self.verbose and self.output_manager:
                    try:
                        filepath = self.output_manager.get_ollama_log_path(request_timestamp)
                        self._save_request_response_log(
                            filepath, system_message, prompt, response_content
                        )
                    except Exception as e:  # logging must never break analysis
                        verbose_print(f"Failed to save log: {e}", self.verbose)

                return {"response": response_content}

            except Exception as e:
                error_msg = str(e)
                verbose_print(f"Attempt {attempt + 1} failed: {error_msg}", self.verbose)
                if attempt < OLLAMA_MAX_RETRIES - 1:
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 1.5, 10)
                else:
                    return {"error": f"Ollama failed after {OLLAMA_MAX_RETRIES} attempts: {error_msg}"}

    def list_models(self) -> List[str]:
        from .ollama_models import list_models_for_mode
        return list_models_for_mode(self.mode, self.host, self.api_key)

    def validate_credentials(self) -> bool:
        try:
            if self.mode == "local":
                from .ollama_models import is_server_running
                return is_server_running(self.host)
            # cloud: a usable key is required; a successful list call confirms it.
            if not self.api_key:
                return False
            self.client.list()
            return True
        except Exception as e:
            verbose_print(f"Ollama credential validation failed: {e}", self.verbose)
            return False

    def analyze_with_cloud_llm(self, prompt: str, system_message: str = None) -> Dict:
        """Deprecated name kept for existing callers; routes to :meth:`analyze`."""
        return self.analyze(prompt, system_message)

    def _save_request_response_log(
        self, filepath: Path, system_message: str, user_prompt: str, response_content: str
    ):
        markdown_content = f"""# {self.apk_name} Ollama Request and Response

**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Model:** {self.model}
**Mode:** {self.mode}

---

## Request Made

### System Message
```
{system_message}
```

### User Prompt
```
{user_prompt}
```

---

## Response Received

```
{response_content}
```

---

**Note:** This log was generated in verbose mode.
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        verbose_print(f"Saved log: {filepath}", self.verbose)