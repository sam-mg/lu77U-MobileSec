"""Filesystem-backed scan store under the user's configured output directory."""

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.paths import get_output_base

_FOLDER_PREFIX = "lu77U-MobileSec-"

_SCAN_ID_RE = re.compile(r"^[0-9a-f]{12}$")

_folder_cache: Dict[str, Path] = {}

def _validate_scan_id(scan_id: str) -> None:
    if not _SCAN_ID_RE.match(scan_id or ""):
        raise ValueError(f"Invalid scan id: {scan_id!r}")

def get_data_dir() -> Path:
    """Base directory scan folders live under (the configured output dir)."""
    return get_output_base()

def sanitize_filename(name: str) -> str:
    """Strip a user/upload-supplied filename down to a safe basename."""
    base = Path(name or "upload.apk").name
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip() or "upload.apk"
    if not base.lower().endswith(".apk"):
        base += ".apk"
    return base

def create_scan_folder(scan_id: str, filename: str) -> Path:
    """Create and return this scan's dedicated folder under the output base.

    Named ``lu77U-MobileSec-<apk-stem>-<timestamp>``; on a same-second name
    collision the short ``scan_id`` is appended to keep it unique.
    """
    _validate_scan_id(scan_id)
    stem = Path(sanitize_filename(filename)).stem or "app"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = get_output_base()
    folder = base / f"{_FOLDER_PREFIX}{stem}-{ts}"
    if folder.exists():
        folder = base / f"{_FOLDER_PREFIX}{stem}-{ts}-{scan_id}"
    folder.mkdir(parents=True, exist_ok=True)
    _folder_cache[scan_id] = folder
    return folder

def _folder_for(scan_id: str, dir_hint: Optional[str] = None) -> Optional[Path]:
    """Resolve a scan_id to its folder. Uses ``dir_hint`` (meta's stored ``dir``)
    or the cache when possible, else scans ``<base>/lu77U-MobileSec-*/meta.json``
    for a matching ``id``."""
    if dir_hint:
        p = Path(dir_hint)
        if p.exists():
            _folder_cache[scan_id] = p
            return p
    cached = _folder_cache.get(scan_id)
    if cached and cached.exists():
        return cached
    base = get_output_base()
    for meta_path in base.glob(f"{_FOLDER_PREFIX}*/meta.json"):
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("id") == scan_id:
            _folder_cache[scan_id] = meta_path.parent
            return meta_path.parent
    _folder_cache.pop(scan_id, None)
    return None

def save_meta(meta: Dict[str, Any]) -> None:
    scan_id = meta["id"]
    folder = _folder_for(scan_id, meta.get("dir"))
    if folder is None:
        # No folder yet (shouldn't happen: prepare_scan creates it first) — bail
        # rather than resurrect a scan in an unexpected place.
        return
    (folder / "meta.json").write_text(
        json.dumps(meta, indent=2, default=str), encoding="utf-8")

def load_meta(scan_id: str) -> Optional[Dict[str, Any]]:
    folder = _folder_for(scan_id)
    if folder is None:
        return None
    path = folder / "meta.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def list_meta() -> List[Dict[str, Any]]:
    """All scan metadata, newest first (globbed from the output base)."""
    out: List[Dict[str, Any]] = []
    base = get_output_base()
    if not base.exists():
        return out
    for meta_path in base.glob(f"{_FOLDER_PREFIX}*/meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if meta.get("id"):
            _folder_cache[meta["id"]] = meta_path.parent
            out.append(meta)
    out.sort(key=lambda m: m.get("created_at", ""), reverse=True)
    return out

def save_result(scan_id: str, result: Dict[str, Any]) -> None:
    folder = _folder_for(scan_id)
    if folder is None:
        return
    (folder / "result.json").write_text(
        json.dumps(result, indent=2, default=str), encoding="utf-8")

def load_result(scan_id: str) -> Optional[Dict[str, Any]]:
    folder = _folder_for(scan_id)
    if folder is None:
        return None
    path = folder / "result.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def delete_scan(scan_id: str) -> bool:
    """Remove a scan's entire folder. Returns True if it existed."""
    folder = _folder_for(scan_id)
    _folder_cache.pop(scan_id, None)
    if folder is not None and folder.exists():
        shutil.rmtree(folder, ignore_errors=True)
        return True
    return False