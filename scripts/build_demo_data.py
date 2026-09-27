#!/usr/bin/env python3
"""
Module: build_demo_data

Purpose:
    Generate the static JSON dataset the GitHub Pages demo serves, from a curated set of real completed scans.

Responsibilities:
    Read the source scan folders, scrub local paths out of them, and write the exact shapes the single-page app already expects.

Dependencies:
    The package metadata, the provider registries and the user settings defaults, all read directly so the demo cannot drift from the real Settings page.

Usage:
    python scripts/build_demo_data.py

Implementation notes:
    Nothing here talks to a live server, a keychain or the network. Re-run it whenever the sample scans change. The demo's mock backend serves the written files verbatim in place of the real API endpoints, which is why the shapes have to match rather than merely resemble them.

Security considerations:
    Only the deliberately-vulnerable teaching app is published. It was released by its author to be broken, so naming it alongside its findings carries no disclosure weight. Every other scan folder is excluded deliberately: they cover a real commercial application, and publishing findings with code excerpts about a named third-party product is not something a public demo should do, regardless of how the tool graded it. Any local filesystem path that could leak through logs or metadata is rewritten before publishing, and the scan folder's own directory field is dropped outright.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from lu77U_MobileSec._metadata import NAME, VERSION
from lu77U_MobileSec.ai.cli_provider import CLI_SPECS
from lu77U_MobileSec.ai.registry import (
    CURATED_MODELS, CUSTOM_PRESETS, DEFAULT_MODELS, PROVIDER_DISPLAY_NAMES,
    PROVIDER_VENDORS,
)
from lu77U_MobileSec.config.user_settings import (
    AGENT_BUDGET_LIMITS, CLI_PROVIDERS, DEFAULT_MAX_CONCURRENT_REQUESTS, PROVIDERS,
)

OUT_DIR = REPO_ROOT / "lu77U_MobileSec" / "frontend" / "demo" / "public" / "demo-data"

SCANS_BASE = Path.home() / "Documents" / "lu77U-MobileSec"
SOURCE_SCANS = [
    "lu77U-MobileSec-DIVA-20260816_023931",
    "lu77U-MobileSec-DIVA-20260815_211413",
]

_HOME = str(Path.home())
_SCRUB_TO = "/Users/analyst"


def scrub(text: str) -> str:
    """
    Purpose:
        Rewrite the local home directory out of a string before it is published.

    Parameters:
        text: The text to scrub.

    Returns:
        The text with the home directory replaced by a neutral stand-in.

    Security considerations:
        The home directory names the analyst and their machine layout, which has no business in a public dataset.
    """
    return text.replace(_HOME, _SCRUB_TO)


def scrub_json(obj: Any) -> Any:
    """
    Purpose:
        Scrub every string in a nested structure.

    Parameters:
        obj: A string, list, dict or any other value.

    Returns:
        The structure with every string scrubbed and everything else unchanged.

    Implementation notes:
        Recursive rather than applied at the point of writing, because a local path can appear anywhere in a scan result, including inside log lines and nested finding fields.
    """
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, list):
        return [scrub_json(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub_json(v) for k, v in obj.items()}
    return obj


def load_meta(folder: Path) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Load one scan's metadata, skipping anything not suitable for publishing.

    Parameters:
        folder: The scan folder.

    Returns:
        The scrubbed metadata, or None when the folder has none or the scan did not complete.

    Side effects:
        Reads the metadata file and prints why a folder was skipped.

    Implementation notes:
        An incomplete scan is skipped because the demo is meant to show finished results; a partially-populated one would read as a bug in the tool rather than as an interrupted run.

    Security considerations:
        The folder's own directory field is removed rather than scrubbed, since it is a local path with no value in the published data.
    """
    meta_path = folder / "meta.json"
    if not meta_path.exists():
        print(f"  ! skip {folder.name}: no meta.json")
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("status") != "completed":
        print(f"  ! skip {folder.name}: status={meta.get('status')!r}, not completed")
        return None
    meta.pop("dir", None)
    return scrub_json(meta)


def load_result(folder: Path) -> Dict[str, Any]:
    """
    Purpose:
        Load one scan's result.

    Parameters:
        folder: The scan folder.

    Returns:
        The scrubbed result, or an empty mapping when the scan wrote none.
    """
    result_path = folder / "result.json"
    if not result_path.exists():
        return {}
    result = json.loads(result_path.read_text(encoding="utf-8"))
    return scrub_json(result)


def write_json(path: Path, data: Any) -> None:
    """
    Purpose:
        Write one JSON file, creating its parent directories.

    Parameters:
        path: Where to write.
        data: The data to serialise.

    Side effects:
        Creates directories and writes the file.

    Implementation notes:
        Non-ASCII characters are preserved rather than escaped, so the published data reads correctly for app names and findings that are not in English.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_settings() -> Dict[str, Any]:
    """
    Purpose:
        Build a settings snapshot shaped exactly like the real settings endpoint returns, with obviously fake data.

    Returns:
        The settings payload.

    Implementation notes:
        Kept in step with the real endpoint by construction rather than by hand: every field it adds is sourced from the same registries the settings service itself reads, so a provider or vendor added there needs no matching edit here. That drift is not hypothetical, it already happened once, when the real Settings page shipped a field this dataset had no equivalent for at all. A CLI-backed provider is billed against a subscription login rather than an API key, so it is given no keys here, matching how the real endpoint treats it. The CLI probe result is faked as always found and signed in, because this is a static dataset with no binary to locate.

    Security considerations:
        No real key, path or credential probe is involved. The masked key is a literal stand-in, not a redaction of anything real.
    """
    fake_masked = "sk-d…emo"
    providers: Dict[str, Any] = {}
    for name in PROVIDERS:
        is_cli = name in CLI_PROVIDERS
        providers[name] = {
            "name": name,
            "display_name": PROVIDER_DISPLAY_NAMES.get(name, name),
            "model": DEFAULT_MODELS.get(name, ""),
            "mode": "cloud" if name == "ollama" else None,
            "base_url": "https://demo.example.com/v1" if name == "custom" else None,
            "cloud_host": "https://api.ollama.com" if name == "ollama" else None,
            "local_host": "http://localhost:11434" if name == "ollama" else None,
            "max_concurrent_requests": 1 if is_cli else DEFAULT_MAX_CONCURRENT_REQUESTS,
            "has_api_key": (name != "custom") and not is_cli,
            "api_key_count": 1 if (name != "custom" and not is_cli) else 0,
            "api_keys": (
                [{"index": 0, "masked": fake_masked}]
                if (name != "custom" and not is_cli) else []
            ),
            "default_model": DEFAULT_MODELS.get(name, ""),
            "needs_api_key": name != "custom" and not is_cli,
            "is_cli": is_cli,
        }
        if is_cli:
            spec = CLI_SPECS[name]
            providers[name].update({
                "model": spec.models[0] if spec.models else "",
                "default_model": spec.models[0] if spec.models else "",
                "binary_path": "",
                "cli_binary": spec.binary,
                "cli_found": True,
                "cli_resolved_path": f"/usr/local/bin/{spec.binary}",
                "signin_hint": spec.signin_hint,
            })
    return {
        "active_provider": "ollama",
        "providers": providers,
        "provider_order": list(PROVIDERS),
        "vendors": [dict(v) for v in PROVIDER_VENDORS],
        "custom_presets": CUSTOM_PRESETS,
        "jadx_path": "/opt/homebrew/bin/jadx",
        "blutter_path": "",
        "hermes_decomp_path": "",
        "rn_decompiler_path": "",
        "pdf_generation": True,
        "auto_resume": True,
        "agent_budget": {"max_steps_per_region": 40, "max_minutes": 45},
        "agent_budget_limits": AGENT_BUDGET_LIMITS,
        "max_concurrent_requests_range": [1, 20],
        "status": {
            "jadx_configured": True,
            "ollama_configured": True,
            "blutter_configured": False,
            "hermes_decomp_configured": False,
            "rn_decompiler_configured": False,
            "ready_for_analysis": True,
        },
    }


def main() -> None:
    """
    Purpose:
        Build the whole demo dataset.

    Side effects:
        Reads the source scan folders and writes the published JSON files.

    Implementation notes:
        Scans are written newest first, matching what the real listing endpoint returns, so the demo's ordering is not subtly different from the product's. A missing or unsuitable source folder is reported and skipped rather than failing the build, since the folders are local and will not exist on every machine. A model list is written for every provider the settings page offers, including the CLI-backed ones whose models come from their spec rather than from a curated table, because a provider with a selected model and no model list renders as an empty dropdown with a value already in it.
    """
    print(f"Reading source scans from {SCANS_BASE}")
    scans_meta: List[Dict[str, Any]] = []

    for name in SOURCE_SCANS:
        folder = SCANS_BASE / name
        if not folder.is_dir():
            print(f"  ! skip {name}: folder not found")
            continue
        meta = load_meta(folder)
        if meta is None:
            continue
        scan_id = meta["id"]
        result = load_result(folder)

        write_json(OUT_DIR / "scans" / f"{scan_id}.json", {"meta": meta, "result": result or None})
        scans_meta.append(meta)
        print(f"  + {name} -> id={scan_id} findings={meta['summary'].get('total_vulnerabilities')}")

    scans_meta.sort(key=lambda m: m.get("created_at", ""), reverse=True)
    write_json(OUT_DIR / "scans.json", {"scans": scans_meta})

    write_json(OUT_DIR / "version.json", {"name": NAME, "version": VERSION})
    write_json(
        OUT_DIR / "status.json",
        {
            "jadx_configured": True,
            "ollama_configured": True,
            "blutter_configured": False,
            "hermes_decomp_configured": False,
            "rn_decompiler_configured": False,
            "ready_for_analysis": True,
        },
    )
    write_json(OUT_DIR / "settings.json", build_settings())

    for provider, models in CURATED_MODELS.items():
        write_json(OUT_DIR / "models" / f"{provider}.json", {"provider": provider, "models": models})
    write_json(
        OUT_DIR / "models" / "ollama.json",
        {"provider": "ollama", "models": [DEFAULT_MODELS["ollama"]]},
    )
    write_json(OUT_DIR / "models" / "custom.json", {"provider": "custom", "models": []})

    for name in CLI_PROVIDERS:
        spec = CLI_SPECS[name]
        write_json(OUT_DIR / "models" / f"{name}.json",
                   {"provider": name, "models": list(spec.models)})

    print(f"\nWrote {len(scans_meta)} scans to {OUT_DIR}")


if __name__ == "__main__":
    main()
