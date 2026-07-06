"""Abstract base class every AI provider implements."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .schema import VULNERABILITY_SCHEMA, DEFAULT_SYSTEM_MESSAGE

class BaseAIProvider(ABC):
    """Common interface for all AI backends."""

    name: str = "base"

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        api_key: Optional[str] = None,
        verbose: bool = False,
        output_manager=None,
        apk_name: Optional[str] = None,
    ):
        self.config = config or {}
        self.api_key = api_key
        self.verbose = verbose
        self.output_manager = output_manager
        self.apk_name = apk_name or "Unknown_APK"
        self.model = self.config.get("model") or self.default_model()

    @abstractmethod
    def analyze(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        images: Optional[List[bytes]] = None,
    ) -> Dict[str, Any]:
        """Run a one-shot structured-JSON analysis.

        ``images`` is an optional list of raw image bytes (e.g. PNG screenshots)
        attached to the user message for providers/models with vision support
        (see :meth:`supports_vision`); ignored by providers that can't accept
        them. Returns ``{"response": <raw json string>}`` on success or
        ``{"error": <message>}`` on failure.
        """

    @abstractmethod
    def list_models(self) -> List[str]:
        """Return selectable model ids for this provider."""

    @abstractmethod
    def validate_credentials(self) -> bool:
        """Return True if the configured credentials/endpoint are usable."""

    def default_model(self) -> str:
        """Fallback model id when none is configured. Overridden per provider."""
        return ""

    @property
    def schema(self) -> Dict[str, Any]:
        return VULNERABILITY_SCHEMA

    @property
    def default_system_message(self) -> str:
        return DEFAULT_SYSTEM_MESSAGE

    def supports_tools(self) -> bool:
        """Whether this provider/model can do native tool calling (Phase 4)."""
        return False

    def supports_vision(self) -> bool:
        """Whether this provider/model can accept image input via ``analyze(images=...)``."""
        return False

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<{self.__class__.__name__} model={self.model!r}>"