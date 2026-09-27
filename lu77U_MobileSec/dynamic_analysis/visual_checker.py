#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.visual_checker

Purpose:
    Confirm the device's network path is working and not being blocked, by loading a known page and having a vision model describe what is actually on screen.

Responsibilities:
    Drive the device browser to a reference page, capture a screenshot, and ask the model whether it rendered.

Dependencies:
    The AI provider layer, the device manager.

Implementation notes:
    Some failures are only visible on screen. A certificate warning, a captive portal or a blocked connection all leave the device apparently online while nothing the app does actually reaches its server. Looking at the screen is the only check that catches all of them.

Security considerations:
    A screenshot of the device is sent to the AI provider, and it shows whatever the browser is displaying.
"""

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
    "emulator. Answer ONLY with the requested JSON object - no prose, no "
    "markdown, no <think> blocks."
)

def _extract_json_object(text: str) -> Optional[dict]:
    """
    Purpose:
        Parse the model's verdict, tolerating a response wrapped in prose.

    Parameters:
        text: The response text.

    Returns:
        The parsed object, or None.

    Implementation notes:
        A direct parse is tried first and a greedy brace match second. The greedy match works here because the expected object is small and flat, unlike the nested action objects elsewhere in the dynamic pipeline.
    """
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
    """
    Purpose:
        Check that the device can load a known page, judged from a screenshot.

    Parameters:
        adb_manager: Device control.
        device: Device serial.
        verbose: Traces each stage.

    Returns:
        A success flag and a message.

    Side effects:
        Opens a URL on the device, captures a screenshot, and makes an AI provider request.

    Implementation notes:
        Vision support is checked before anything else, so a text-only provider skips the check with a clear message rather than sending an image that will be ignored and getting a confident answer about nothing. Failure to construct a provider is reported rather than raised, since this is a diagnostic step and should not abort the dynamic run.

    Security considerations:
        The screenshot is transmitted to the configured AI provider. It is taken immediately after loading a known reference page, so it should show only that page -- but whatever else is on screen goes with it.
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
    time.sleep(4)

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
        result = provider.analyze(prompt, system_message=VISUAL_CHECK_SYSTEM, schema=VISUAL_CHECK_SCHEMA,
                                  images=[screenshot], max_tokens=300)
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
    verbose_print(f"Visual check result: matches={matches} - {message}", verbose)
    return matches, message
