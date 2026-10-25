#!/usr/bin/env python3
"""
Module: build_demo_data

Purpose:
    Generate the static JSON dataset the GitHub Pages demo serves, from a chosen set of real completed scans, published as the tool wrote them.

Responsibilities:
    Read the source scan folders, scrub local paths out of them, and write the exact shapes the single-page app already expects.

Dependencies:
    The package metadata, the provider registries and the user settings defaults, all read directly so the demo cannot drift from the real Settings page.

Usage:
    python scripts/build_demo_data.py

Implementation notes:
    Nothing here talks to a live server, a keychain or the network. Re-run it whenever the sample scans change. A published scan is never edited beyond its name and scrubbed paths: when the tool changes, the apps are scanned again rather than old reports patched, so every report in the demo is one real run of the current code. The demo's mock backend serves the written files verbatim in place of the real API endpoints, which is why the shapes have to match rather than merely resemble them.

Security considerations:
    Only deliberately-vulnerable apps are published, each one from a public repository and named after it: DIVA, Damn Vulnerable React Native, Damn Vulnerable Flutter App, brnpl's Flutter Reverse Engineering Labs (all nine levels built from its source into one APK), and the Ghera benchmark's lean apps, vulnerable and fixed, all released by their authors to be broken. Naming them alongside their findings carries no disclosure weight. Every other scan folder is excluded deliberately: they cover a real commercial application, and publishing findings with code excerpts about a named third-party product is not something a public demo should do, regardless of how the tool graded it. Any local filesystem path that could leak through logs or metadata is rewritten before publishing, and the scan folder's own directory field is dropped outright.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from lu77U_MobileSec._metadata import NAME, VERSION
from lu77U_MobileSec.ai.cli_provider import CLI_SPECS
from lu77U_MobileSec.ai.registry import (
    CURATED_MODELS, CUSTOM_PRESETS, DEFAULT_MODELS, PROVIDER_DISPLAY_NAMES,
    PROVIDER_VENDORS,
)
from lu77U_MobileSec.config.user_settings import (
    AGENT_BUDGET_LIMITS, CLI_PROVIDERS, DEFAULT_MAX_CONCURRENT_REQUESTS, DEFAULT_SETTINGS, PROVIDERS,
)


OUT_DIR = REPO_ROOT / "lu77U_MobileSec" / "frontend" / "demo" / "public" / "demo-data"

SCANS_BASE = Path.home() / "Documents" / "lu77U-MobileSec"
SOURCE_SCANS = [
    ("lu77U-MobileSec-DIVA-20261022_145101", "github.com/payatu/diva-android/debug.apk"),
    ("lu77U-MobileSec-DVRN-C-20261022_145101", "github.com/waseeq14/Damn-Vulnerable-React-Native/release.apk"),
    ("lu77U-MobileSec-app-release-20261022_145101", "github.com/Schmiemandev/dvfa/release.apk"),
    ("lu77U-MobileSec-all-release-20261022_145101",
     "github.com/brnpl/Flutter-Reverse-Engineering-Labs/all-release.apk"),
]

GHERA_RESULTS = REPO_ROOT / "scripts" / "ghera_results.json"
GHERA_SOURCE = "bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks"

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


def build_settings(ollama_model: str = "") -> Dict[str, Any]:
    """
    Purpose:
        Build a settings snapshot shaped exactly like the real settings endpoint returns, with obviously fake data.

    Parameters:
        ollama_model: The Ollama model the published scans ran on; the registry default when empty.

    Returns:
        The settings payload.

    Implementation notes:
        The Ollama model is the one the published scans actually ran on, so the Settings page and the results agree on what produced them, and the tool paths are filled in wherever the readiness block says a tool is configured. Kept in step with the real endpoint by construction rather than by hand: every field it adds is sourced from the same registries the settings service itself reads, so a provider or vendor added there needs no matching edit here. That drift is not hypothetical, it already happened once, when the real Settings page shipped a field this dataset had no equivalent for at all. A CLI-backed provider is billed against a subscription login rather than an API key, so it is given no keys here, matching how the real endpoint treats it. The CLI probe result is faked as always found and signed in, because this is a static dataset with no binary to locate.

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
            "model": (ollama_model or DEFAULT_MODELS.get(name, "")) if name == "ollama"
                     else DEFAULT_MODELS.get(name, ""),
            "mode": "cloud" if name == "ollama" else None,
            "base_url": "https://demo.example.com/v1" if name == "custom" else None,
            "cloud_host": "https://api.ollama.com" if name == "ollama" else None,
            "local_host": "http://localhost:11434" if name == "ollama" else None,
            "max_concurrent_requests": 1 if is_cli else DEFAULT_MAX_CONCURRENT_REQUESTS,
            "has_api_key": (name != "custom") and not is_cli,
            "api_key_count": 1 if (name != "custom" and not is_cli) else 0,
            "api_keys": (
                [{"index": 0, "masked": fake_masked, "label": "demo@example.com"}]
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
        "blutter_path": f"{_SCRUB_TO}/tools/blutter/blutter.py",
        "hermes_decomp_path": f"{_SCRUB_TO}/.cargo/bin/hermes-decomp",
        "rn_decompiler_path": "",
        "ghidra_path": "/Applications/ghidra",
        "output_dir": "",
        "output_dir_default": f"{_SCRUB_TO}/Documents/{NAME}",
        "dynamic_verification": DEFAULT_SETTINGS["dynamic_verification"],
        "agent_memory": DEFAULT_SETTINGS["agent_memory"],
        "pdf_generation": DEFAULT_SETTINGS["pdf_generation"],
        "auto_resume": DEFAULT_SETTINGS["auto_resume"],
        "agent_budget": dict(DEFAULT_SETTINGS["agent_budget"]),
        "agent_budget_limits": AGENT_BUDGET_LIMITS,
        "max_concurrent_requests_range": [1, 20],
        "status": {
            "jadx_configured": True,
            "ollama_configured": True,
            "blutter_configured": True,
            "hermes_decomp_configured": True,
            "rn_decompiler_configured": False,
            "ghidra_configured": True,
            "ready_for_analysis": True,
        },
    }


def benchmark_scans(results_path: Path = GHERA_RESULTS) -> List[Tuple[str, str]]:
    """
    Purpose:
        List the scored Ghera scans to publish, each with the repository path of the APK it scanned.

    Parameters:
        results_path: The results file scripts/ghera_benchmark.py writes.

    Returns:
        (scan folder, display name) pairs in benchmark order, each benchmark's vulnerable app followed by its fixed one; empty when the benchmark has not been scored.

    Implementation notes:
        The scans published are exactly the ones the results file scored, so the demo and the recall the wiki quotes are the same scans rather than two runs that happen to share a name. Each is named the way a showcase app is, by where to get it: the benchmark's folder in the Ghera repository, then benign.apk or secure.apk, which tells a reader which benchmark it is, whether it is the vulnerable (Benign) or the fixed (Secure) app, and where to download it. The APK's own file name repeats the benchmark's and is left out: with it, every name wrapped to four or five lines in the scan list.
    """
    if not results_path.exists():
        return []
    results = json.loads(results_path.read_text(encoding="utf-8"))
    variants = {v: ((results.get("variants") or {}).get(v) or {}).get("benchmarks") or {} for v in ("Benign", "Secure")}
    out = []
    for bench in sorted(set(variants["Benign"]) | set(variants["Secure"])):
        for variant, rows in variants.items():
            row = rows.get(bench)
            if row:
                out.append((row["folder"], f"{GHERA_SOURCE}/{bench}/{variant.lower()}.apk"))
    return out


def published_scans(results_path: Path = GHERA_RESULTS) -> List[Tuple[str, str, bool]]:
    """
    Purpose:
        List every scan the demo publishes, and whether it is a showcase scan.

    Parameters:
        results_path: The results file scripts/ghera_benchmark.py writes.

    Returns:
        (scan folder, display name, showcase) triples: SOURCE_SCANS first, then the scored Ghera scans.

    Implementation notes:
        The flag decides the listing order (see listing()). Every scan, showcase or benchmark, is published as the tool wrote it, so a Ghera report in the demo is exactly the one the Benchmarks wiki page scored.
    """
    return ([(name, shown, True) for name, shown in SOURCE_SCANS]
            + [(name, shown, False) for name, shown in benchmark_scans(results_path)])


def listing(showcase: List[Dict[str, Any]], benchmarks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Purpose:
        Order the published scans for the scan list: the showcase apps newest first, then the benchmark apps.

    Parameters:
        showcase: Metadata of the SOURCE_SCANS scans.
        benchmarks: Metadata of the Ghera scans, in benchmark order.

    Returns:
        The combined list, as scans.json serves it.

    Implementation notes:
        Newest first matches what the real listing endpoint returns, and the showcase apps keep that order among themselves. The benchmark scans are kept after them even though they ran later: there are over a hundred, so newest first overall would fill the dashboard's recent-scans card and the first screens of the scan list with them and push the four showcase apps out of sight. Kept in benchmark order, each vulnerable app sits next to its fixed one.
    """
    return sorted(showcase, key=lambda m: m.get("created_at", ""), reverse=True) + list(benchmarks)


def present_as(meta: Dict[str, Any], result: Dict[str, Any], display_name: str) -> None:
    """
    Purpose:
        Name a published scan after the repository its APK was built from.

    Parameters:
        meta: The scan's metadata, updated in place.
        result: The scan's result, updated in place.
        display_name: The name to show: github.com/<owner>/<repository>/<debug|release>.apk, or a benchmark APK's path in its repository.

    Side effects:
        Rewrites the app name and file name the dashboard shows, and the target path the result records.

    Implementation notes:
        A demo reader cannot tell what DIVA.apk is, where to get it, or whether it was a debug or a release build; the public repository the APK comes from and its build type say all three, so a reader can download the same app and check the findings. The dashboard titles a scan by its app name and falls back to the file name, so both are set; the package name stays as it was, as the subtitle under it. The scan's own folder names are left alone, since they only appear in scrubbed local paths.
    """
    meta["filename"] = display_name
    summary = meta.get("summary")
    if isinstance(summary, dict):
        summary["app_name"] = display_name
    result = result or {}
    metadata = result.get("metadata")
    if isinstance(metadata, dict) and metadata.get("target"):
        metadata["target"] = display_name
    app_info = result.get("application_info")
    if isinstance(app_info, dict):
        app_info["app_name"] = display_name


def main() -> None:
    """
    Purpose:
        Build the whole demo dataset.

    Side effects:
        Reads the source scan folders and writes the published JSON files.

    Implementation notes:
        The published scans are the ones published_scans() lists, in the order listing() gives. A missing or unsuitable source folder is reported and skipped rather than failing the build, since the folders are local and will not exist on every machine. Scan files left from an earlier build are removed, so a sample dropped from SOURCE_SCANS cannot keep being served by its id. The settings snapshot names the Ollama model most of the published scans ran on. A model list is written for every provider the settings page offers, including the CLI-backed ones whose models come from their spec rather than from a curated table, because a provider with a selected model and no model list renders as an empty dropdown with a value already in it.
    """
    print(f"Reading source scans from {SCANS_BASE}")
    showcase_meta: List[Dict[str, Any]] = []
    benchmark_meta: List[Dict[str, Any]] = []
    written: List[str] = []
    models: List[str] = []

    for name, display_name, showcase in published_scans():
        folder = SCANS_BASE / name
        if not folder.is_dir():
            print(f"  ! skip {name}: folder not found")
            continue
        meta = load_meta(folder)
        if meta is None:
            continue
        scan_id = meta["id"]
        result = load_result(folder)
        model = (((result or {}).get("analyzer_details") or {}).get("llm_usage") or {}).get("model")
        if model:
            models.append(str(model))
        present_as(meta, result, display_name)

        write_json(OUT_DIR / "scans" / f"{scan_id}.json", {"meta": meta, "result": result or None})
        written.append(f"{scan_id}.json")
        (showcase_meta if showcase else benchmark_meta).append(meta)
        print(f"  + {name} as {display_name} -> id={scan_id} "
              f"findings={meta['summary'].get('total_vulnerabilities')}")

    for stale in sorted((OUT_DIR / "scans").glob("*.json")):
        if stale.name not in written:
            stale.unlink()
            print(f"  - removed {stale.name}: not in this build's scan set")

    write_json(OUT_DIR / "scans.json", {"scans": listing(showcase_meta, benchmark_meta)})

    write_json(OUT_DIR / "version.json", {"name": NAME, "version": VERSION})
    write_json(
        OUT_DIR / "status.json",
        {
            "jadx_configured": True,
            "ollama_configured": True,
            "blutter_configured": True,
            "hermes_decomp_configured": True,
            "rn_decompiler_configured": False,
            "ghidra_configured": True,
            "ready_for_analysis": True,
        },
    )
    write_json(OUT_DIR / "settings.json",
               build_settings(max(set(models), key=models.count) if models else ""))

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

    print(f"\nWrote {len(showcase_meta) + len(benchmark_meta)} scans to {OUT_DIR}")


if __name__ == "__main__":
    main()
