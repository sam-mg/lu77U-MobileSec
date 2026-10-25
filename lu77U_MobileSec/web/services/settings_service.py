#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.services.settings_service

Purpose:
    Implement what the settings endpoints do: validate what the client sent, persist it, and report the current configuration back with credentials masked.

Responsibilities:
    Validate URLs and numeric bounds, read and write settings and credentials, probe providers, and manage prompt overrides and user skills.

Dependencies:
    The settings and credential layers, the provider factory.

Security considerations:
    This module is where client input becomes stored configuration that the tool later acts on: URLs it will send source code to, paths it will execute, and files the agent will read. Each of those is validated here rather than at the point of use. Credentials are written to the keychain and are only ever returned masked, except through the explicit reveal path.
"""

import ipaddress
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ...ai.registry import (
    CURATED_MODELS, CUSTOM_PRESETS, DEFAULT_MODELS, PROVIDER_DISPLAY_NAMES,
    PROVIDER_VENDORS)
from ...analyzers.agent.skills_loader import (
    SKILLS_DIR, available_skills, skill_path, user_skills_dir)
from ...config import credentials, user_settings
from ...config.paths import default_output_base
from ...config.prompts import VulnerabilityPrompts
from ...tools_checker.analysis_checker import get_analysis_status
from ...utils.verbose import verbose_print

_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_SKILL_BYTES = 200_000

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _validate_base_url(url: str) -> None:
    """
    Purpose:
        Reject a provider base URL that points somewhere it should not.

    Parameters:
        url: The configured URL.

    Raises:
        ValueError: When the scheme is not HTTP or HTTPS, the host is missing, the host is loopback, or it resolves to a private address.

    Side effects:
        Performs a DNS lookup.

    Security considerations:
        This is a server-side request forgery control. A custom provider URL is a value the tool will send decompiled application source to, and without this check a user -- or anyone who reached the unauthenticated dashboard -- could point it at an internal service or a cloud metadata endpoint and have the server make requests there. The check resolves the host and tests the resulting addresses against the private ranges, rather than pattern-matching the hostname, because a public name can resolve to a private address.

    Known limitations:
        A name that resolves differently between this check and the request is not caught, so this narrows the exposure rather than closing it. A resolution failure is allowed through, so an unreachable host can be configured and simply fails later.
    """
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"base_url must use http or https, got {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("base_url must include a host")
    if host.lower() in ("localhost",):
        raise ValueError("base_url must not target localhost")
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return
    for _family, _type, _proto, _canonname, sockaddr in addrs:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        for net in _PRIVATE_NETS:
            if addr in net:
                raise ValueError(
                    f"base_url host {host!r} resolves to a private/internal address "
                    f"({addr}) - this is not allowed"
                )

def _validate_max_concurrent_requests(value: Any) -> int:
    """
    Purpose:
        Validate and coerce the per-provider concurrency setting.

    Parameters:
        value: The proposed value.

    Returns:
        The validated integer.

    Raises:
        ValueError: When the value is not a whole number or is outside the permitted range.

    Implementation notes:
        Bounded at both ends. Zero or a negative value would deadlock the request gate, and an unbounded value invites the provider to throttle the whole scan.
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError("max_concurrent_requests must be a whole number")
    low, high = user_settings.MAX_CONCURRENT_REQUESTS_RANGE
    if not low <= number <= high:
        raise ValueError(f"max_concurrent_requests must be between {low} and {high}")
    return number

def _cli_status_fields(name: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Describe whether a CLI-backed provider's binary can be found.

    Parameters:
        name: The provider identifier.
        cfg: The provider's stored configuration.

    Returns:
        The binary name, the resolved path, whether it was found and the sign-in hint.

    Implementation notes:
        Resolution follows the same rule the provider itself uses -- an explicit path when configured, a PATH lookup otherwise -- so the settings page cannot report a provider as ready that would then fail to start. The sign-in hint is carried through from the spec, so the interface tells the user how to authenticate that particular CLI rather than offering generic advice.
    """
    import shutil
    from ...ai.cli_provider import CLI_SPECS

    spec = CLI_SPECS.get(name)
    if spec is None:
        return {}
    binary_path = cfg.get("binary_path") or ""
    resolved = binary_path or shutil.which(spec.binary) or ""
    return {
        "binary_path": binary_path,
        "cli_binary": spec.binary,
        "cli_found": bool(resolved) and Path(resolved).is_file() if binary_path
                     else bool(shutil.which(spec.binary)),
        "cli_resolved_path": resolved or None,
        "signin_hint": spec.signin_hint,
    }

def get_cli_status(provider: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Purpose:
        Report whether a CLI-backed provider is installed and usable.

    Parameters:
        provider: The provider identifier.
        verbose: Enables tracing.

    Returns:
        The status fields.

    Raises:
        ValueError: When the provider is not a CLI-backed one.
    """
    from ...ai.cli_provider import CLI_SPECS
    from ...ai.provider_factory import build_provider

    spec = CLI_SPECS.get(provider)
    if spec is None:
        raise ValueError(f"Unknown CLI provider: {provider!r}")
    cfg = user_settings.get_provider_config(provider)
    fields = _cli_status_fields(provider, cfg)
    if not fields.get("cli_found"):
        return {**fields, "signed_in": False,
                "detail": f"{spec.binary} not found on PATH"}
    try:
        prov = build_provider(provider, verbose=verbose)
        signed_in = prov.validate_credentials()
    except Exception as exc:
        verbose_print(f"get_cli_status({provider!r}) probe failed: {exc}", verbose)
        return {**fields, "signed_in": False, "detail": "Could not verify sign-in status"}
    return {**fields, "signed_in": bool(signed_in),
            "detail": None if signed_in else "Installed but not signed in"}

def get_settings() -> Dict[str, Any]:
    """
    Purpose:
        Return the current configuration for the settings page.

    Returns:
        The settings, with credentials masked and provider metadata attached.

    Security considerations:
        Credentials appear only in masked form, so the settings page can show which keys exist without the response carrying key material.
    """
    providers: Dict[str, Any] = {}
    for name in user_settings.PROVIDERS:
        cfg = user_settings.get_provider_config(name)
        is_cli = name in user_settings.CLI_PROVIDERS
        entries = [] if is_cli else credentials.get_api_key_entries(name)
        providers[name] = {
            "name": name,
            "display_name": PROVIDER_DISPLAY_NAMES.get(name, name),
            "model": cfg.get("model", ""),
            "mode": cfg.get("mode"),
            "base_url": cfg.get("base_url"),
            "cloud_host": cfg.get("cloud_host"),
            "local_host": cfg.get("local_host"),
            "max_concurrent_requests": cfg.get(
                "max_concurrent_requests", user_settings.DEFAULT_MAX_CONCURRENT_REQUESTS),
            "has_api_key": bool(entries),
            "api_key_count": len(entries),
            "api_keys": [{"index": i, "masked": credentials.mask_key(entry["key"]), "label": entry["label"]}
                        for i, entry in enumerate(entries)],
            "default_model": DEFAULT_MODELS.get(name, ""),
            "needs_api_key": name != "custom" and not is_cli,
            "is_cli": is_cli,
        }
        if is_cli:
            providers[name].update(_cli_status_fields(name, cfg))
    return {
        "active_provider": user_settings.get_active_provider(),
        "providers": providers,
        "provider_order": list(user_settings.PROVIDERS),
        "vendors": [dict(v) for v in PROVIDER_VENDORS],
        "custom_presets": CUSTOM_PRESETS,
        "jadx_path": user_settings.get_jadx_path(),
        "blutter_path": user_settings.get_blutter_path(),
        "hermes_decomp_path": user_settings.get_hermes_decomp_path(),
        "rn_decompiler_path": user_settings.get_rn_decompiler_path(),
        "ghidra_path": user_settings.get_ghidra_path(),
        "output_dir": user_settings.get_output_dir(),
        "output_dir_default": str(default_output_base()),
        "dynamic_verification": user_settings.get_dynamic_verification(),
        "agent_memory": user_settings.get_agent_memory(),
        "pdf_generation": user_settings.get_pdf_generation(),
        "auto_resume": user_settings.get_auto_resume(),
        "agent_budget": user_settings.get_agent_budget(),
        "agent_budget_limits": user_settings.AGENT_BUDGET_LIMITS,
        "max_concurrent_requests_range": list(user_settings.MAX_CONCURRENT_REQUESTS_RANGE),
        "status": get_analysis_status(),
    }

def update_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Apply a settings change after validating it.

    Parameters:
        payload: The fields to change.

    Returns:
        The updated settings.

    Raises:
        ValueError: When a value fails validation.

    Side effects:
        Rewrites the settings file.

    Implementation notes:
        Only the fields present in the payload are touched, so the interface can send a single change rather than the whole tree and two open tabs do not overwrite each other's unrelated edits.

    Security considerations:
        Base URLs and concurrency values are validated before being stored, not when they are used.
    """
    if payload.get("active_provider"):
        user_settings.set_active_provider(payload["active_provider"])
    if "jadx_path" in payload:
        user_settings.set_jadx_path(payload.get("jadx_path") or "")
    if "blutter_path" in payload:
        user_settings.set_blutter_path(payload.get("blutter_path") or "")
    if "hermes_decomp_path" in payload:
        user_settings.set_hermes_decomp_path(payload.get("hermes_decomp_path") or "")
    if "rn_decompiler_path" in payload:
        user_settings.set_rn_decompiler_path(payload.get("rn_decompiler_path") or "")
    if "ghidra_path" in payload:
        user_settings.set_ghidra_path((payload.get("ghidra_path") or "").strip())
    if "output_dir" in payload:
        user_settings.set_output_dir((payload.get("output_dir") or "").strip())
    if "dynamic_verification" in payload:
        user_settings.set_dynamic_verification(bool(payload["dynamic_verification"]))
    if "agent_memory" in payload:
        user_settings.set_agent_memory(bool(payload["agent_memory"]))
    if "pdf_generation" in payload:
        user_settings.set_pdf_generation(bool(payload["pdf_generation"]))
    if "auto_resume" in payload:
        user_settings.set_auto_resume(bool(payload["auto_resume"]))
    for field, value in (payload.get("agent_budget") or {}).items():
        user_settings.set_agent_budget(field, value)
    for name, fields in (payload.get("providers") or {}).items():
        if name not in user_settings.PROVIDERS or not isinstance(fields, dict):
            continue
        for field in ("model", "mode", "base_url", "max_concurrent_requests",
                      "binary_path"):
            if field not in fields:
                continue
            value = fields[field]
            if field == "base_url":
                _validate_base_url(value or "")
            elif field == "max_concurrent_requests":
                value = _validate_max_concurrent_requests(value)
            elif field == "binary_path":
                if name not in user_settings.CLI_PROVIDERS:
                    continue
                value = (value or "").strip()
            user_settings.set_provider_field(name, field, value)
    return get_settings()

def set_credential(provider: str, api_key: Optional[str], label: Optional[str] = None) -> None:
    """
    Purpose:
        Store an API key for a provider, optionally with a label saying what it is for.

    Parameters:
        provider: The provider identifier.
        api_key: The key, or None to clear.
        label: Optional free text shown beside the key, such as the account it belongs to.

    Raises:
        ValueError: When the provider is unknown or the label is rejected.

    Side effects:
        Writes to the OS keychain or the encrypted fallback.

    Security considerations:
        The key and its label go to the credential store, never to the settings file, which stays safe to read and copy.
    """
    if provider not in user_settings.PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")
    if api_key and api_key.strip():
        credentials.add_api_key(provider, api_key.strip(), label or "")
    else:
        credentials.delete_api_key(provider)

def set_credential_label(provider: str, index: int, label: Optional[str]) -> None:
    """
    Purpose:
        Label one stored key by position, change its label, or clear it.

    Parameters:
        provider: The provider identifier.
        index: Position in the provider's key list.
        label: The new label; empty or None clears it.

    Raises:
        ValueError: When the provider is unknown, the position does not exist, or the label is rejected.

    Side effects:
        Rewrites the provider's stored keys.
    """
    if provider not in user_settings.PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")
    if not credentials.set_api_key_label(provider, index, label or ""):
        raise ValueError(f"No key at index {index} for {provider!r}")

def remove_credential(provider: str, index: int) -> None:
    """
    Purpose:
        Remove one stored key by position.

    Parameters:
        provider: The provider identifier.
        index: Position in the provider's key list.

    Side effects:
        Rewrites the provider's stored keys.
    """
    if provider not in user_settings.PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")
    credentials.remove_api_key(provider, index)

def reveal_credential(provider: str, index: int) -> str:
    """
    Purpose:
        Return one stored key in full.

    Parameters:
        provider: The provider identifier.
        index: Position in the provider's key list.

    Returns:
        The key.

    Raises:
        ValueError: When the position does not exist.

    Security considerations:
        The one path that returns key material unmasked. It exists because a user occasionally needs to confirm which key is stored, and it is reachable only over loopback. Nothing else in the settings surface returns an unmasked key.
    """
    if provider not in user_settings.PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")
    keys = credentials.get_api_keys(provider)
    if not 0 <= index < len(keys):
        raise ValueError(f"No key at index {index} for {provider!r}")
    return keys[index]

def list_models(provider: str, verbose: bool = False) -> List[str]:
    """
    Purpose:
        List the models available for a provider, for the model chooser.

    Parameters:
        provider: The provider identifier.
        verbose: Enables tracing.

    Returns:
        Model names; empty when they cannot be determined.

    Implementation notes:
        Never raises, because this runs while rendering the settings page and an unreachable provider should show the curated list (or an empty chooser) rather than an error. A listing failure is logged so the fallback to the curated list is traceable rather than silent.
    """
    from ...ai.provider_factory import build_provider

    try:
        models = build_provider(provider, verbose=verbose).list_models()
        if models:
            return models
    except Exception as exc:
        verbose_print(f"Could not list models for {provider}: {exc}", verbose)
    return CURATED_MODELS.get(provider, [])

def test_provider(provider: Optional[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """
    Purpose:
        Check that a provider is configured and reachable.

    Parameters:
        provider: The provider to test; the active one when omitted.
        verbose: Enables tracing.

    Returns:
        The outcome and a message.

    Side effects:
        Makes one request to the provider.

    Security considerations:
        The probe sends credentials but no analysis content.
    """
    from ...ai.provider_factory import build_provider, get_active_provider

    try:
        prov = (build_provider(provider, verbose=verbose) if provider
                else get_active_provider(verbose=verbose))
    except Exception as exc:
        verbose_print(f"test_provider: could not build provider {provider!r}: {exc}", verbose)
        return {"ok": False, "provider": provider, "model": None,
                "error": "Could not initialise the provider - check the saved settings."}
    try:
        ok = prov.validate_credentials()
    except Exception as exc:
        verbose_print(f"test_provider: validation raised for {prov.name}: {exc}", verbose)
        return {"ok": False, "provider": prov.name, "model": prov.model,
                "error": "Validation failed - check key/base URL/model/network."}
    return {"ok": bool(ok), "provider": prov.name, "model": prov.model,
            "error": None if ok else "Validation failed - check key/base URL/model/network."}


def list_prompts() -> List[Dict[str, Any]]:
    """
    Purpose:
        List the built-in prompts with their labels, guidance and any overrides.

    Returns:
        One entry per overridable prompt.

    Implementation notes:
        The guidance text is included because it names the structural elements an override must keep -- the action names and the vector field -- and dropping them produces output the parser cannot read.
    """
    out = []
    for prompt_id in VulnerabilityPrompts.PROMPT_IDS:
        default_text = VulnerabilityPrompts.default_prompt(prompt_id)
        override = user_settings.get_prompt_override(prompt_id)
        out.append({
            "id": prompt_id,
            "label": VulnerabilityPrompts.PROMPT_LABELS.get(prompt_id, prompt_id),
            "help": VulnerabilityPrompts.PROMPT_HELP.get(prompt_id, ""),
            "default": default_text,
            "current": override if override else default_text,
            "is_custom": bool(override),
        })
    return out

def save_prompt(prompt_id: str, text: str) -> Dict[str, Any]:
    """
    Purpose:
        Replace a built-in prompt with the user's text.

    Parameters:
        prompt_id: The prompt identifier.
        text: The replacement.

    Returns:
        The stored override.

    Raises:
        ValueError: When the identifier is unknown.

    Side effects:
        Rewrites the settings file.

    Security considerations:
        The override becomes the system prompt for analysis. It is stored verbatim and is not sanitised, so it can weaken or redirect a scan entirely -- an intended power-user capability rather than an oversight.
    """
    if prompt_id not in VulnerabilityPrompts.PROMPT_IDS:
        raise ValueError(f"Unknown prompt id: {prompt_id!r}")
    if not text or not text.strip():
        raise ValueError("Prompt text must not be empty")
    user_settings.set_prompt_override(prompt_id, text)
    return next(p for p in list_prompts() if p["id"] == prompt_id)

def reset_prompt(prompt_id: str) -> Dict[str, Any]:
    """
    Purpose:
        Discard an override so the built-in prompt applies again.

    Parameters:
        prompt_id: The prompt identifier.

    Returns:
        The restored prompt.

    Raises:
        ValueError: When the identifier is unknown.
    """
    if prompt_id not in VulnerabilityPrompts.PROMPT_IDS:
        raise ValueError(f"Unknown prompt id: {prompt_id!r}")
    user_settings.clear_prompt_override(prompt_id)
    return next(p for p in list_prompts() if p["id"] == prompt_id)

def list_skills() -> List[Dict[str, Any]]:
    """
    Purpose:
        List the analysis skills available to the agent, from both the built-in set and the user's own.

    Returns:
        One entry per skill, noting which user skills shadow a built-in.

    Implementation notes:
        Shadowing is surfaced explicitly, so a user who uploads a skill sharing a built-in's name can see that theirs is the one in use.
    """
    out = []
    for name in available_skills():
        path = skill_path(name)
        if path is None:
            continue
        out.append({
            "name": name,
            "filename": path.name,
            "size": path.stat().st_size,
            "source": "user" if path.parent == user_skills_dir() else "builtin",
        })
    return out

def save_skill(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Purpose:
        Store an uploaded analysis skill after validating it.

    Parameters:
        filename: The uploaded filename.
        content: The uploaded bytes.

    Returns:
        The stored skill's details, including whether it replaced an existing file or shadows a built-in.

    Raises:
        ValueError: When the extension is wrong, the name contains disallowed characters, the file is too large, or it is not valid text.

    Side effects:
        Writes the skill file.

    Security considerations:
        Four checks apply together and each closes a different hole. The extension is fixed, so nothing but a document can be written. The stem is matched against a strict pattern, which is what stops a filename containing separators or a traversal sequence from placing the file outside the skills directory. The size is bounded, so an upload cannot fill the disk. And the content must decode as text, so the stored file is what the agent expects to read. The destination filename is rebuilt from the validated stem rather than taken from the upload, so nothing of the client's path survives into the write.

    Implementation notes:
        Skills are instructions the analysis agent reads, so an uploaded one influences what the scan looks for -- which is why the content is required to be text and the location is tightly controlled.
    """
    stem = Path(filename or "").stem
    suffix = Path(filename or "").suffix.lower()
    if suffix != ".md":
        raise ValueError("Skill file must have a .md extension")
    if not stem or not _SKILL_NAME_RE.match(stem):
        raise ValueError(
            "Skill filename must contain only letters, numbers, '-' and '_'"
        )
    if len(content) > _MAX_SKILL_BYTES:
        raise ValueError(f"Skill file too large (max {_MAX_SKILL_BYTES // 1000} KB)")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Skill file must be valid UTF-8 text")

    dest = user_skills_dir() / f"{stem}.md"
    overwritten = dest.exists()
    dest.write_text(text, encoding="utf-8")
    return {"name": stem, "filename": dest.name, "size": dest.stat().st_size,
            "source": "user", "overwritten": overwritten,
            "shadows_builtin": (SKILLS_DIR / f"{stem}.md").is_file()}
