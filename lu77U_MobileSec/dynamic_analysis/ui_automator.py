"""AI-assisted UI interaction using uiautomator2 for dynamic analysis."""

import json
import re
import time
from typing import Any, Callable, Dict, List, Optional

from ..ai.provider_factory import get_active_provider
from ..utils.cancellation import ScanCancelled
from ..utils.verbose import verbose_print

# Schema describing the next-action object we ask the model to return.
ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["tap", "input", "none"]},
        "x": {"type": "integer"},
        "y": {"type": "integer"},
        "text": {"type": "string"},
        "reason": {"type": "string"},
        "done": {"type": "boolean"},
    },
    "required": ["action"],
}

ACTION_SYSTEM = (
    "You are a mobile security analyst driving an Android app during dynamic "
    "analysis. Given the current UI hierarchy XML, choose the single next action "
    "to explore security-relevant functionality (menus, network triggers, "
    "sensitive screens, authenticated areas).\n\n"
    "If the current screen asks for input that is NOT a login username/password "
    "prompt — a credit card number, PIN, name, address, phone number, or any "
    "other form field — fill it with a plausible random/dummy value via the "
    "'input' action and continue; never skip or get stuck on these fields. Only "
    "genuine login/credential screens are paused for the user by the system "
    "separately, so you do not need to handle that case yourself.\n\n"
    "Respond with ONE JSON object only — no markdown, no prose, no <think> blocks."
)

LOGIN_KEYWORDS = [
    "sign in", "log in", "login", "username", "password",
    "forgot password", "create account", "sign up",
]

_ATTR_VALUE_RE = re.compile(r'(?:text|content-desc|resource-id|hint)="([^"]*)"')
_PASSWORD_FIELD_RE = re.compile(r'\bpassword="true"')


def _strip_thinking(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"</?think>", "", text, flags=re.IGNORECASE)
    return text.strip()


def _extract_first_json_object(text: str) -> Optional[str]:
    depth = 0
    start = -1
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return text[start:i + 1]
    return None


class UIAutomator:
    def __init__(self, adb_manager, device: str, verbose: bool = False):
        self.adb_manager = adb_manager
        self.device = device
        self.verbose = verbose
        self._u2_device = None
        verbose_print(f"UIAutomator initialized for {device}", self.verbose)

    def connect(self) -> bool:
        """Connect via uiautomator2 (a declared dependency) and health-check."""
        verbose_print(f"Connecting uiautomator2 to {self.device}", self.verbose)
        try:
            import uiautomator2 as u2
        except ImportError:
            verbose_print("uiautomator2 is not installed", self.verbose)
            return False
        try:
            self._u2_device = u2.connect(self.device)
            _ = self._u2_device.info
            verbose_print("uiautomator2 connected and healthy", self.verbose)
            return True
        except Exception as exc:
            verbose_print(f"uiautomator2 connection failed: {exc}", self.verbose)
            return False

    def dump_ui_hierarchy(self) -> Optional[str]:
        if not self._u2_device:
            return None
        try:
            xml = self._u2_device.dump_hierarchy()
            verbose_print(f"UI hierarchy dumped ({len(xml)} chars)", self.verbose)
            return xml
        except Exception as exc:
            verbose_print(f"UI dump failed: {exc}", self.verbose)
            return None

    def is_login_screen(self, ui_xml: str) -> bool:
        if _PASSWORD_FIELD_RE.search(ui_xml):
            verbose_print('Password input field present (password="true")', self.verbose)
            return True
        values = " ".join(m.group(1).lower() for m in _ATTR_VALUE_RE.finditer(ui_xml))
        for keyword in LOGIN_KEYWORDS:
            if keyword in values:
                verbose_print(f"Login keyword detected in UI text: '{keyword}'", self.verbose)
                return True
        return False

    def ask_ai_for_next_tap(self, ui_xml: str, app_package: str,
                            context: str = "") -> Optional[Dict[str, Any]]:
        """Ask the active AI provider for the next action. Returns the parsed dict."""
        verbose_print("Asking AI for next action", self.verbose)
        prompt = (
            f"App under test: {app_package}\n"
            f"Context so far: {context or 'Beginning of session'}\n\n"
            f"Current UI hierarchy (truncated):\n{ui_xml[:8000]}\n\n"
            "Respond with ONE JSON object: "
            '{"action":"tap"|"input"|"none","x":<int>,"y":<int>,'
            '"text":"<for input>","reason":"<why>","done":<bool>}'
        )
        try:
            provider = get_active_provider(verbose=self.verbose, apk_name=app_package)
            result = provider.analyze(prompt, system_message=ACTION_SYSTEM, schema=ACTION_SCHEMA)
        except Exception as exc:
            verbose_print(f"AI provider error: {exc}", self.verbose)
            return None
        if not isinstance(result, dict) or "error" in result:
            verbose_print(f"AI returned error: {result}", self.verbose)
            return None

        raw = _strip_thinking(result.get("response", "") or "")
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        try:
            return json.loads(raw)
        except Exception:
            candidate = _extract_first_json_object(raw)
            if candidate is None:
                verbose_print("Could not parse AI action JSON", self.verbose)
                return None
            try:
                return json.loads(candidate)
            except Exception:
                return None

    def execute_tap(self, x: int, y: int) -> bool:
        verbose_print(f"Tap ({x}, {y})", self.verbose)
        result = self.adb_manager.shell(self.device, f"input tap {x} {y}")
        return result.returncode == 0

    def execute_text_input(self, x: int, y: int, text: str) -> bool:
        verbose_print(f"Input at ({x}, {y}): '{text[:30]}'", self.verbose)
        self.execute_tap(x, y)
        time.sleep(0.5)
        safe_text = "'" + text.replace("'", "'\\''") + "'"
        result = self.adb_manager.shell(self.device, f"input text {safe_text}")
        return result.returncode == 0

    def run_analysis_loop(
        self,
        app_package: str,
        pause_for_login: Optional[Callable[[], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
        max_iterations: int = 20,
    ) -> List[Dict[str, Any]]:
        """Drive the app: dump → (login pause) → ask AI → act, up to ``max_iterations``."""
        verbose_print(
            f"Starting UI loop for {app_package} (max {max_iterations})", self.verbose)
        actions_taken: List[Dict[str, Any]] = []
        context_parts: List[str] = []

        for iteration in range(1, max_iterations + 1):
            if is_cancelled is not None and is_cancelled():
                verbose_print("Cancellation requested; stopping UI loop", self.verbose)
                raise ScanCancelled()
            verbose_print(f"UI loop iteration {iteration}/{max_iterations}", self.verbose)
            ui_xml = self.dump_ui_hierarchy()
            if not ui_xml:
                break

            if self.is_login_screen(ui_xml):
                if pause_for_login is not None:
                    pause_for_login()
                    if is_cancelled is not None and is_cancelled():
                        verbose_print("Cancelled while waiting for login", self.verbose)
                        raise ScanCancelled()
                    time.sleep(1)
                    ui_xml = self.dump_ui_hierarchy()
                    if not ui_xml:
                        break

            context = "; ".join(context_parts[-5:])
            suggestion = self.ask_ai_for_next_tap(ui_xml, app_package, context)

            if is_cancelled is not None and is_cancelled():
                verbose_print("Cancellation requested; stopping UI loop", self.verbose)
                raise ScanCancelled()

            if not suggestion:
                verbose_print("No AI suggestion; stopping loop", self.verbose)
                break

            action = suggestion.get("action", "none")
            x = int(suggestion.get("x", 0) or 0)
            y = int(suggestion.get("y", 0) or 0)
            reason = suggestion.get("reason", "")
            done = bool(suggestion.get("done", False))
            record: Dict[str, Any] = {
                "iteration": iteration, "action": action,
                "x": x, "y": y, "reason": reason, "success": False,
            }

            if action == "tap":
                record["success"] = self.execute_tap(x, y)
                context_parts.append(f"Tapped ({x},{y}): {reason[:40]}")
            elif action == "input":
                text = suggestion.get("text", "")
                record["text"] = text
                record["success"] = self.execute_text_input(x, y, text)
                context_parts.append(f"Typed at ({x},{y}): {reason[:40]}")
            else:
                verbose_print(f"AI action 'none': {reason[:60]}", self.verbose)

            actions_taken.append(record)

            if done:
                verbose_print("AI indicated session complete", self.verbose)
                break

            if is_cancelled is not None and is_cancelled():
                verbose_print("Cancellation requested; stopping UI loop", self.verbose)
                raise ScanCancelled()
            time.sleep(1.5)

        verbose_print(f"UI loop done; {len(actions_taken)} actions", self.verbose)
        return actions_taken