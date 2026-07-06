"""Settings + credentials service for the web UI."""

import ipaddress
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ...ai.registry import CURATED_MODELS, DEFAULT_MODELS, PROVIDER_DISPLAY_NAMES
from ...analyzers.agent.skills_loader import SKILLS_DIR, available_skills
from ...config import credentials, user_settings
from ...config.paths import default_output_base
from ...config.prompts import VulnerabilityPrompts
from ...tools_checker.analysis_checker import get_analysis_status

_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_SKILL_BYTES = 200_000

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _validate_base_url(url: str) -> None:
    """Raise ValueError if *url* points at a private/loopback/cloud-metadata host."""
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
        return   # unresolvable at config time — allow, will fail at request time
    for _family, _type, _proto, _canonname, sockaddr in addrs:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        for net in _PRIVATE_NETS:
            if addr in net:
                raise ValueError(
                    f"base_url host {host!r} resolves to a private/internal address "
                    f"({addr}) — this is not allowed"
                )

def get_settings() -> Dict[str, Any]:
    """Full settings snapshot for the Settings page (never includes secrets)."""
    providers: Dict[str, Any] = {}
    for name in user_settings.PROVIDERS:
        cfg = user_settings.get_provider_config(name)
        providers[name] = {
            "name": name,
            "display_name": PROVIDER_DISPLAY_NAMES.get(name, name),
            "model": cfg.get("model", ""),
            "mode": cfg.get("mode"),            # ollama only
            "base_url": cfg.get("base_url"),    # custom only
            "cloud_host": cfg.get("cloud_host"),
            "local_host": cfg.get("local_host"),
            "has_api_key": credentials.has_api_key(name),
            "default_model": DEFAULT_MODELS.get(name, ""),
            "needs_api_key": name not in ("custom",),
        }
    return {
        "active_provider": user_settings.get_active_provider(),
        "providers": providers,
        "provider_order": list(user_settings.PROVIDERS),
        "jadx_path": user_settings.get_jadx_path(),
        "output_dir": user_settings.get_output_dir(),
        "output_dir_default": str(default_output_base()),
        "dynamic_verification": user_settings.get_dynamic_verification(),
        "agent_memory": user_settings.get_agent_memory(),
        "status": get_analysis_status(),
    }

def update_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Apply a partial settings update and return the fresh snapshot."""
    if payload.get("active_provider"):
        user_settings.set_active_provider(payload["active_provider"])
    if "jadx_path" in payload:
        user_settings.set_jadx_path(payload.get("jadx_path") or "")
    if "output_dir" in payload:
        user_settings.set_output_dir((payload.get("output_dir") or "").strip())
    if "dynamic_verification" in payload:
        user_settings.set_dynamic_verification(bool(payload["dynamic_verification"]))
    if "agent_memory" in payload:
        user_settings.set_agent_memory(bool(payload["agent_memory"]))
    for name, fields in (payload.get("providers") or {}).items():
        if name not in user_settings.PROVIDERS or not isinstance(fields, dict):
            continue
        for field in ("model", "mode", "base_url"):
            if field not in fields:
                continue
            if field == "base_url":
                _validate_base_url(fields[field] or "")
            user_settings.set_provider_field(name, field, fields[field])
    return get_settings()

def set_credential(provider: str, api_key: Optional[str]) -> None:
    """Store (or, when blank, clear) a provider's API key."""
    if provider not in user_settings.PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")
    if api_key and api_key.strip():
        credentials.set_api_key(provider, api_key.strip())
    else:
        credentials.delete_api_key(provider)

def list_models(provider: str, verbose: bool = False) -> List[str]:
    """Selectable model ids for a provider (live where cheap, else curated)."""
    from ...ai.provider_factory import build_provider

    try:
        models = build_provider(provider, verbose=verbose).list_models()
        if models:
            return models
    except Exception:
        pass
    return CURATED_MODELS.get(provider, [])

def test_provider(provider: Optional[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """Live-validate a provider's credentials/endpoint."""
    from ...ai.provider_factory import build_provider, get_active_provider

    try:
        prov = (build_provider(provider, verbose=verbose) if provider
                else get_active_provider(verbose=verbose))
    except Exception as exc:
        return {"ok": False, "error": str(exc), "provider": provider, "model": None}
    try:
        ok = prov.validate_credentials()
    except Exception as exc:
        return {"ok": False, "error": str(exc), "provider": prov.name, "model": prov.model}
    return {"ok": bool(ok), "provider": prov.name, "model": prov.model,
            "error": None if ok else "Validation failed — check key/base URL/model/network."}

# --- Prompt overrides --------------------------------------------------------

def list_prompts() -> List[Dict[str, Any]]:
    """Every editable prompt with its label/help, default text, current
    (possibly overridden) text, and whether it's currently customized."""
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
    """Save a user override for ``prompt_id``. Raises ValueError for an unknown
    id or blank text."""
    if prompt_id not in VulnerabilityPrompts.PROMPT_IDS:
        raise ValueError(f"Unknown prompt id: {prompt_id!r}")
    if not text or not text.strip():
        raise ValueError("Prompt text must not be empty")
    user_settings.set_prompt_override(prompt_id, text)
    return next(p for p in list_prompts() if p["id"] == prompt_id)

def reset_prompt(prompt_id: str) -> Dict[str, Any]:
    """Revert ``prompt_id`` to its built-in default."""
    if prompt_id not in VulnerabilityPrompts.PROMPT_IDS:
        raise ValueError(f"Unknown prompt id: {prompt_id!r}")
    user_settings.clear_prompt_override(prompt_id)
    return next(p for p in list_prompts() if p["id"] == prompt_id)

def list_skills() -> List[Dict[str, Any]]:
    """Every skill file currently in ``lu77U_MobileSec/skills/``."""
    out = []
    for name in available_skills():
        path = SKILLS_DIR / f"{name}.md"
        out.append({"name": name, "filename": path.name, "size": path.stat().st_size})
    return out

def save_skill(filename: str, content: bytes) -> Dict[str, Any]:
    """Validate and write an uploaded skill markdown file into ``SKILLS_DIR``.

    Raises ValueError for a disallowed name/extension, oversized upload, or
    content that isn't valid UTF-8 text.
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

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    dest = SKILLS_DIR / f"{stem}.md"
    overwritten = dest.exists()
    dest.write_text(text, encoding="utf-8")
    return {"name": stem, "filename": dest.name, "size": dest.stat().st_size,
            "overwritten": overwritten}