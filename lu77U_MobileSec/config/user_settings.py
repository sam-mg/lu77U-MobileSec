#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config.user_settings

Purpose:
    Persist everything the user configures -- active AI provider and its model, external tool paths, output location, feature toggles, agent budgets and prompt overrides -- in one JSON file, and serve it through typed accessors.

Responsibilities:
    Define the default settings tree, load and cache it, merge it over whatever is on disk, migrate from the legacy module on first run, expose one accessor pair per setting, and resolve the output base directory from the configured value.

Dependencies:
    json, copy, pathlib, .paths for the settings file location and the default output base.

Implementation notes:
    Reads go through a process-wide cache because settings are consulted on nearly every operation and the file is small but the disk round trip is not free. Writes always rewrite the whole document, which is simple and correct for a file of this size. Loading deep-merges the stored document over DEFAULT_SETTINGS rather than replacing it. That is what lets a new setting ship with a default and appear for existing users without a migration step, and why a partial or hand-edited file still loads. API keys are deliberately absent from this file. They live in the OS keychain via .credentials, so this document stays safe to read, copy and inspect.

Thread-safety:
    The cache is a module-global guarded by no lock. Settings are expected to be read from many threads and written from the UI thread only; concurrent writes can interleave and lose an update.

Security considerations:
    Tool paths stored here are executed later. They are operator-supplied and are not validated on the way in, so the executing code is responsible for invoking them as argument vectors rather than through a shell.
"""

import contextlib
import copy
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .paths import default_output_base, get_settings_path

PROVIDERS = (
    "ollama", "claude", "openai", "gemini", "custom",
    "claude_cli", "copilot_cli", "kimi_cli", "codex_cli", "antigravity_cli",
)

CLI_PROVIDERS = ("claude_cli", "copilot_cli", "kimi_cli", "codex_cli", "antigravity_cli")

DEFAULT_MAX_CONCURRENT_REQUESTS = 2

DEFAULT_SETTINGS: Dict[str, Any] = {
    "active_provider": "ollama",
    "providers": {
        "ollama": {
            "mode": "cloud",
            "model": "",
            "cheap_model": "",
            "cloud_host": "https://api.ollama.com",
            "local_host": "http://localhost:11434",
            "max_concurrent_requests": DEFAULT_MAX_CONCURRENT_REQUESTS,
        },
        "claude": {"model": "", "cheap_model": "",
                   "max_concurrent_requests": DEFAULT_MAX_CONCURRENT_REQUESTS},
        "openai": {"model": "", "cheap_model": "",
                   "max_concurrent_requests": DEFAULT_MAX_CONCURRENT_REQUESTS},
        "gemini": {"model": "", "cheap_model": "",
                   "max_concurrent_requests": DEFAULT_MAX_CONCURRENT_REQUESTS},
        "custom": {"model": "", "cheap_model": "", "base_url": "",
                  "max_concurrent_requests": DEFAULT_MAX_CONCURRENT_REQUESTS},
        "claude_cli": {"model": "", "binary_path": "", "max_concurrent_requests": 1},
        "copilot_cli": {"model": "", "binary_path": "", "max_concurrent_requests": 1},
        "kimi_cli": {"model": "", "binary_path": "", "max_concurrent_requests": 1},
        "codex_cli": {"model": "", "binary_path": "", "max_concurrent_requests": 1},
        "antigravity_cli": {"model": "", "binary_path": "", "max_concurrent_requests": 1},
    },
    "jadx_path": "",
    "blutter_path": "",
    "hermes_decomp_path": "",
    "rn_decompiler_path": "",
    "xamarin_decompiler_path": "",
    "output_dir": "",
    "pdf_generation": True,
    "dynamic_verification": True,
    "agent_memory": True,
    "auto_resume": True,
    "agent_budget": {
        "max_steps_per_region": 40,
        "max_minutes": 45,
    },
    "prompt_overrides": {},
}

AGENT_BUDGET_LIMITS = {
    "max_steps_per_region": (0, 500),
    "max_minutes": (0, 480),
}

MAX_CONCURRENT_REQUESTS_RANGE = (1, 20)

_cache: Optional[Dict[str, Any]] = None

def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Merge a stored settings document over the defaults, recursing into nested dicts instead of replacing them wholesale.

    Parameters:
        base: The defaults.
        override: The stored document.

    Returns:
        A new merged dict. Neither argument is mutated.

    Complexity:
        O(n) in the total number of keys.

    Implementation notes:
        Recursion happens only where both sides hold a dict; anything else is replaced. This is what preserves defaults for provider fields the user has never touched while still honouring the ones they have. base is deep-copied so the returned tree shares no mutable state with DEFAULT_SETTINGS. Without that, a caller mutating the loaded settings would corrupt the defaults for the rest of the process.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def _migrate_from_legacy() -> Dict[str, Any]:
    """
    Purpose:
        Seed a fresh settings file from the values in the legacy settings module, so that an existing installation keeps its JADX path and model choice on first upgrade.

    Returns:
        A complete settings tree.

    Implementation notes:
        Only three values are carried over -- the JADX path, the Ollama model and the Ollama host -- because those are the ones a user had to set by hand in the old module. The literal "path_goes_here" is rejected explicitly: it is the placeholder shipped in the legacy module, and importing it would present a configured-looking path that cannot work. The whole body runs under a suppressed Exception so that a missing or broken legacy module yields plain defaults rather than preventing startup; any value copied before the failure is kept, which is harmless because each one is individually valid.
    """
    seeded = copy.deepcopy(DEFAULT_SETTINGS)
    with contextlib.suppress(Exception):
        from . import settings as legacy
        jadx = getattr(legacy, "JADX_PATH", "")
        if jadx and jadx != "path_goes_here":
            seeded["jadx_path"] = jadx
        model = getattr(legacy, "AI_MODEL_OLLAMA_ID", "")
        if model:
            seeded["providers"]["ollama"]["model"] = model
        host = getattr(legacy, "OLLAMA_API_HOST", "")
        if host:
            seeded["providers"]["ollama"]["cloud_host"] = host
    return seeded

def load(force: bool = False) -> Dict[str, Any]:
    """
    Purpose:
        Return the effective settings, loading and caching them on first call.

    Parameters:
        force: Re-read from disk, discarding the cache. Used after an external change.

    Returns:
        The settings tree. This is the live cached dict, not a copy, so callers must not mutate it except through the accessors.

    Side effects:
        Reads the settings file, and on first run writes a freshly migrated one.

    Implementation notes:
        A file that fails to parse is treated as an empty document, so the merge yields defaults. A hand-edited file with a syntax error therefore reverts to defaults rather than blocking startup -- recoverable, but it does mean a typo silently discards the user's configuration until they fix the file.

    Thread-safety:
        Unsynchronised. Concurrent first calls may both read and both assign; the values are equivalent, so the race is benign.
    """
    global _cache
    if _cache is not None and not force:
        return _cache

    path = get_settings_path()
    if path.exists():
        try:
            on_disk = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            on_disk = {}
        _cache = _deep_merge(DEFAULT_SETTINGS, on_disk)
    else:
        _cache = _migrate_from_legacy()
        save(_cache)
    return _cache

def save(data: Optional[Dict[str, Any]] = None) -> None:
    """
    Purpose:
        Write settings to disk and update the cache.

    Parameters:
        data: Tree to store. When None, the current cache is written.

    Side effects:
        Rewrites the settings file and replaces the cache.

    Implementation notes:
        Written with sorted keys and indentation so that the file stays readable and diffable -- users do inspect and hand-edit it.

    Known limitations:
        The write is not atomic, so an interruption can truncate the file. The load path treats an unparseable file as empty, so the effect is a silent revert to defaults rather than a crash.
    """
    global _cache
    if data is not None:
        _cache = data
    get_settings_path().write_text(
        json.dumps(_cache, indent=2, sort_keys=True), encoding="utf-8"
    )

def get_active_provider() -> str:
    """
    Purpose:
        Report which AI provider is selected.

    Returns:
        The provider identifier, defaulting to "ollama" -- the local provider, chosen as the default because it needs no credential and sends nothing off the machine.
    """
    return load().get("active_provider", "ollama")

def set_active_provider(name: str) -> None:
    """
    Purpose:
        Select the AI provider.

    Parameters:
        name: Provider identifier.

    Raises:
        ValueError: When the name is not in PROVIDERS. Validated here because an unknown provider would otherwise fail much later, inside the factory, with a less obvious message.

    Side effects:
        Rewrites the settings file.
    """
    if name not in PROVIDERS:
        raise ValueError(f"Unknown provider: {name!r}")
    data = load()
    data["active_provider"] = name
    save(data)

def get_provider_config(name: str) -> Dict[str, Any]:
    """
    Purpose:
        Return one provider's configuration block.

    Parameters:
        name: Provider identifier.

    Returns:
        A deep copy of the block, or an empty dict for an unknown provider.

    Implementation notes:
        Deep-copied so that a caller inspecting or adjusting the result cannot mutate the cached settings tree in place and produce a change that is visible everywhere but never saved.
    """
    return copy.deepcopy(load().get("providers", {}).get(name, {}))

def set_provider_field(name: str, field: str, value: Any) -> None:
    """
    Purpose:
        Set one field of one provider's configuration.

    Parameters:
        name: Provider identifier.
        field: Field name within that provider's block.
        value: Value to store.

    Side effects:
        Rewrites the settings file, creating the provider block if absent.

    Implementation notes:
        Neither the provider name nor the field is validated, unlike set_active_provider. This is intentional -- provider blocks carry different fields and gain new ones over time -- but it means a typo stores a field nothing reads.
    """
    data = load()
    data.setdefault("providers", {}).setdefault(name, {})[field] = value
    save(data)

def get_jadx_path() -> str:
    """
    Purpose:
        Read the configured path to JADX, the Java and Kotlin decompiler.

    Returns:
        The configured path, or an empty string when the user has not set one, which the tool checkers read as "not configured".

    Side effects:
        Loads settings on first call.
    """
    return load().get("jadx_path", "")

def set_jadx_path(path: str) -> None:
    """
    Purpose:
        Record the path to JADX.

    Parameters:
        path: Filesystem path to the executable. Stored as given.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        The path is stored without validation and is later used to launch a subprocess. It is operator-supplied through the settings UI, so this is an intended capability rather than an injection route, but a caller must still pass it as an argument vector element and never through a shell.
    """
    data = load()
    data["jadx_path"] = path
    save(data)

def get_blutter_path() -> str:
    """
    Purpose:
        Read the configured path to Blutter, which reconstructs Dart from a Flutter snapshot.

    Returns:
        The configured path, or an empty string when the user has not set one, which the tool checkers read as "not configured".

    Side effects:
        Loads settings on first call.
    """
    return load().get("blutter_path", "")

def set_blutter_path(path: str) -> None:
    """
    Purpose:
        Record the path to Blutter.

    Parameters:
        path: Filesystem path to the executable. Stored as given.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        The path is stored without validation and is later used to launch a subprocess. It is operator-supplied through the settings UI, so this is an intended capability rather than an injection route, but a caller must still pass it as an argument vector element and never through a shell.
    """
    data = load()
    data["blutter_path"] = path
    save(data)

def get_hermes_decomp_path() -> str:
    """
    Purpose:
        Read the configured path to the Hermes bytecode decompiler used for React Native bundles.

    Returns:
        The configured path, or an empty string when the user has not set one, which the tool checkers read as "not configured".

    Side effects:
        Loads settings on first call.
    """
    return load().get("hermes_decomp_path", "")

def set_hermes_decomp_path(path: str) -> None:
    """
    Purpose:
        Record the path to the Hermes decompiler.

    Parameters:
        path: Filesystem path to the executable. Stored as given.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        The path is stored without validation and is later used to launch a subprocess. It is operator-supplied through the settings UI, so this is an intended capability rather than an injection route, but a caller must still pass it as an argument vector element and never through a shell.
    """
    data = load()
    data["hermes_decomp_path"] = path
    save(data)

def get_xamarin_decompiler_path() -> str:
    """
    Purpose:
        Read the configured path to the .NET decompiler used for Xamarin and MAUI assemblies.

    Returns:
        The configured path, or an empty string when the user has not set one, which the tool checkers read as "not configured".

    Side effects:
        Loads settings on first call.
    """
    return load().get("xamarin_decompiler_path", "")

def set_xamarin_decompiler_path(path: str) -> None:
    """
    Purpose:
        Record the path to the .NET decompiler.

    Parameters:
        path: Filesystem path to the executable. Stored as given.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        The path is stored without validation and is later used to launch a subprocess. It is operator-supplied through the settings UI, so this is an intended capability rather than an injection route, but a caller must still pass it as an argument vector element and never through a shell.
    """
    data = load()
    data["xamarin_decompiler_path"] = path
    save(data)

def get_rn_decompiler_path() -> str:
    """
    Purpose:
        Read the configured path to the React Native bundle decompiler.

    Returns:
        The configured path, or an empty string when the user has not set one, which the tool checkers read as "not configured".

    Side effects:
        Loads settings on first call.
    """
    return load().get("rn_decompiler_path", "")

def set_rn_decompiler_path(path: str) -> None:
    """
    Purpose:
        Record the path to the React Native decompiler.

    Parameters:
        path: Filesystem path to the executable. Stored as given.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        The path is stored without validation and is later used to launch a subprocess. It is operator-supplied through the settings UI, so this is an intended capability rather than an injection route, but a caller must still pass it as an argument vector element and never through a shell.
    """
    data = load()
    data["rn_decompiler_path"] = path
    save(data)

def get_output_dir() -> str:
    """
    Purpose:
        Read the configured base directory for scan output.

    Returns:
        The configured path, or an empty string meaning "use the default". Resolving that into a real directory is get_output_base's job.
    """
    return load().get("output_dir", "")

def get_output_base() -> Path:
    """
    Purpose:
        Resolve the base directory scans write into, honouring the user setting when one is configured.

    Returns:
        The directory as a Path, guaranteed to exist on return.

    Raises:
        OSError: When the directory cannot be created -- typically a configured path that is unwritable or on a disconnected volume.

    Side effects:
        Reads user settings and creates the directory tree.

    Implementation notes:
        This lives here rather than in .paths because it needs the stored setting, and .paths must not import this module: this module already imports .paths for the settings file location, and the reverse import formed a cycle. The configured value is expanded with expanduser so that a setting written as a tilde path behaves as the user expects. An empty or whitespace-only setting falls back to .paths.default_output_base, so clearing the field in the UI restores default behaviour rather than resolving to the current working directory.

    Security considerations:
        The configured path is operator-supplied and is used as given. It is not constrained to any root, which is intended -- the operator chooses where their own reports go -- but it means a mistyped value can create a directory anywhere the user can write.
    """
    configured = (get_output_dir() or "").strip()
    base = Path(configured).expanduser() if configured else default_output_base()
    base.mkdir(parents=True, exist_ok=True)
    return base

def set_output_dir(path: str) -> None:
    """
    Purpose:
        Set the base directory for scan output.

    Parameters:
        path: Directory path. A falsy value stores an empty string, which restores default behaviour rather than storing None.

    Side effects:
        Rewrites the settings file. The directory is not created or validated here; that happens when output is next resolved.
    """
    data = load()
    data["output_dir"] = path or ""
    save(data)

def get_pdf_generation() -> bool:
    """
    Purpose:
        Report whether PDF report generation is enabled.

    Returns:
        The stored flag, defaulting to True when unset.

    Side effects:
        Loads settings on first call.
    """
    return bool(load().get("pdf_generation", True))

def set_pdf_generation(enabled: bool) -> None:
    """
    Purpose:
        Enable or disable PDF report generation.

    Parameters:
        enabled: Coerced with bool, so any truthy value is accepted from a form post or a JSON body without the stored value drifting from a real boolean.

    Side effects:
        Rewrites the settings file.
    """
    data = load()
    data["pdf_generation"] = bool(enabled)
    save(data)

def get_auto_resume() -> bool:
    """
    Purpose:
        Report whether automatic resumption of an interrupted scan is enabled.

    Returns:
        The stored flag, defaulting to True when unset.

    Side effects:
        Loads settings on first call.
    """
    return bool(load().get("auto_resume", True))

def set_auto_resume(enabled: bool) -> None:
    """
    Purpose:
        Enable or disable automatic resumption of an interrupted scan.

    Parameters:
        enabled: Coerced with bool, so any truthy value is accepted from a form post or a JSON body without the stored value drifting from a real boolean.

    Side effects:
        Rewrites the settings file.
    """
    data = load()
    data["auto_resume"] = bool(enabled)
    save(data)

def get_dynamic_verification() -> bool:
    """
    Purpose:
        Report whether on-device verification of static findings is enabled.

    Returns:
        The stored flag, defaulting to True when unset.

    Side effects:
        Loads settings on first call.
    """
    return bool(load().get("dynamic_verification", True))

def set_dynamic_verification(enabled: bool) -> None:
    """
    Purpose:
        Enable or disable on-device verification of static findings.

    Parameters:
        enabled: Coerced with bool.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        Enabling this arms a pipeline that installs and runs the APK under analysis on a connected device, proxies its traffic and injects Frida into it. It should only be on when a disposable test device is attached.
    """
    data = load()
    data["dynamic_verification"] = bool(enabled)
    save(data)

def get_agent_memory() -> bool:
    """
    Purpose:
        Report whether the AI agent's cross-region memory is enabled.

    Returns:
        The stored flag, defaulting to True when unset.

    Side effects:
        Loads settings on first call.
    """
    return bool(load().get("agent_memory", True))

def set_agent_memory(enabled: bool) -> None:
    """
    Purpose:
        Enable or disable the AI agent's cross-region memory.

    Parameters:
        enabled: Coerced with bool, so any truthy value is accepted from a form post or a JSON body without the stored value drifting from a real boolean.

    Side effects:
        Rewrites the settings file.
    """
    data = load()
    data["agent_memory"] = bool(enabled)
    save(data)

def get_agent_budget() -> Dict[str, int]:
    """
    Purpose:
        Return the agent's execution budget, with every field guaranteed present and sane.

    Returns:
        A dict carrying every field of the default budget, each a non-negative int.

    Implementation notes:
        Each field is coerced individually and clamped at zero, with the default substituted when the stored value will not convert. A hand-edited settings file carrying a string or a negative number therefore degrades to a usable budget instead of causing the agent to fail mid-run. Iterating the default budget rather than the stored one is what guarantees completeness: a field added in a later version appears with its default for users whose file predates it.
    """
    stored = load().get("agent_budget", {}) or {}
    out: Dict[str, int] = {}
    for field, default in DEFAULT_SETTINGS["agent_budget"].items():
        try:
            out[field] = max(0, int(stored.get(field, default)))
        except (TypeError, ValueError):
            out[field] = int(default)
    return out

def set_agent_budget(field: str, value: int) -> None:
    """
    Purpose:
        Set one field of the agent's execution budget, enforcing its range.

    Parameters:
        field: Budget field name.
        value: Proposed value.

    Raises:
        ValueError: When the field is unknown, the value is not a whole number, or it falls outside the field's range in AGENT_BUDGET_LIMITS.

    Side effects:
        Rewrites the settings file when validation passes.

    Implementation notes:
        Validation is strict here and lenient on read, deliberately: the UI should reject a bad value at the point the user enters it, while a surprising value already on disk should never stop a scan.

    Security considerations:
        These bounds cap what one scan can spend. Zero is permitted and means unbounded for that dimension, so the upper bounds are the only thing limiting a runaway agent loop.
    """
    if field not in AGENT_BUDGET_LIMITS:
        raise ValueError(f"Unknown agent budget field: {field!r}")
    low, high = AGENT_BUDGET_LIMITS[field]
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a whole number")
    if not low <= number <= high:
        raise ValueError(f"{field} must be between {low} and {high}")
    data = load()
    data.setdefault("agent_budget", {})[field] = number
    save(data)

def get_prompt_override(prompt_id: str) -> Optional[str]:
    """
    Purpose:
        Return the user's replacement text for a built-in prompt, if any.

    Parameters:
        prompt_id: Identifier of the built-in prompt.

    Returns:
        The override text, or None when absent or empty.

    Implementation notes:
        An empty string is normalised to None so that clearing the textarea in the UI restores the built-in prompt instead of sending an empty prompt to the model.

    Security considerations:
        Override text is operator-supplied and becomes the system prompt for analysis. An override can weaken or redirect the analysis entirely; this is an intended power-user feature, not an input to be trusted.
    """
    text = load().get("prompt_overrides", {}).get(prompt_id)
    return text if text else None

def set_prompt_override(prompt_id: str, text: str) -> None:
    """
    Purpose:
        Store a replacement for a built-in prompt.

    Parameters:
        prompt_id: Identifier of the built-in prompt.
        text: Replacement text.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        Stored verbatim and later sent to the model as-is. See the module note on prompt overrides.
    """
    data = load()
    data.setdefault("prompt_overrides", {})[prompt_id] = text
    save(data)

def clear_prompt_override(prompt_id: str) -> None:
    """
    Purpose:
        Remove an override so the built-in prompt applies again.

    Parameters:
        prompt_id: Identifier of the built-in prompt.

    Side effects:
        Rewrites the settings file. Clearing an absent override is a no-op.
    """
    data = load()
    data.get("prompt_overrides", {}).pop(prompt_id, None)
    save(data)
