"""AI-vision verification for dynamic analysis."""

import json
import re
import time
from typing import Optional, Tuple

from ..ai.provider_factory import get_active_provider
from ..utils.verbose import verbose_print

VISUAL_CHECK_URL = "http://www.google.com"

VISUAL_CHECK_SCHEMA = {
    "type": "object",
    "properties": {
        "matches": {"type": "boolean",
                    "description": "True if the screenshot shows the expected page"},
        "description": {"type": "string",
                        "description": "One brief sentence describing what is visible on screen"},
    },
    "required": ["matches", "description"],
}

VISUAL_CHECK_SYSTEM = (
    "You are looking at a single screenshot taken from an Android device or "
    "emulator. Answer ONLY with the requested JSON object — no prose, no "
    "markdown, no <think> blocks."
)

def _extract_json_object(text: str) -> Optional[dict]:
    """Parse the first complete top-level JSON object in ``text``, tolerating
    stray text/markdown fences around it (mirrors the parsing already used in
    ``agent_loop.py``/``ui_automator.py`` for model responses)."""
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None

def run_google_visual_check(adb_manager, device: str, verbose: bool = False) -> Tuple[bool, str]:
    """Open google.com on the device and ask the active AI provider to confirm
    it rendered. Returns ``(ok, message)``; never raises.
    """
    try:
        provider = get_active_provider(verbose=verbose)
    except Exception as exc:
        verbose_print(f"Could not construct active AI provider: {exc}", verbose)
        return False, f"Could not construct the active AI provider: {exc}"

    if not provider.supports_vision():
        message = (f"Active provider/model ({provider.name}:{provider.model}) does not "
                   "support image input; visual check skipped.")
        verbose_print(message, verbose)
        return False, message

    verbose_print(f"Opening {VISUAL_CHECK_URL} in the device browser", verbose)
    if not adb_manager.open_url(device, VISUAL_CHECK_URL):
        return False, "Could not launch the browser on the device."
    time.sleep(4)  # let the page render before capturing

    screenshot = adb_manager.capture_screenshot(device)
    if not screenshot:
        return False, "Could not capture a screenshot from the device."

    prompt = (
        "This screenshot was taken from an Android device right after opening "
        f"{VISUAL_CHECK_URL} in the browser. Does it show Google's homepage or "
        "search results (search box, Google logo, etc.)? Respond with the "
        "requested JSON object."
    )
    try:
        result = provider.analyze(prompt, system_message=VISUAL_CHECK_SYSTEM, schema=VISUAL_CHECK_SCHEMA, images=[screenshot])
    except Exception as exc:
        verbose_print(f"Visual check request errored: {exc}", verbose)
        return False, f"Visual check request failed: {exc}"

    if not isinstance(result, dict) or "error" in result:
        err = result.get("error") if isinstance(result, dict) else result
        return False, f"Visual check failed: {err}"

    parsed = _extract_json_object(result.get("response", "") or "")
    if parsed is None:
        return False, "Could not parse the AI's visual-check response."

    matches = bool(parsed.get("matches"))
    description = str(parsed.get("description", "")).strip()
    message = f"AI visual check: {description}" if description else (
        "AI confirmed the expected page is visible." if matches
        else "AI did not confirm the expected page is visible.")
    verbose_print(f"Visual check result: matches={matches} — {message}", verbose)
    return matches, message