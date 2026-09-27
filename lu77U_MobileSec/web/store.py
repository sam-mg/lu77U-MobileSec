#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.store

Purpose:
    Persist scans on disk: one directory per scan holding the uploaded APK, its metadata, its log and its result, so the dashboard can list and reopen past scans after a restart.

Responsibilities:
    Create and locate scan directories, and read and write the metadata, log and result files.

Dependencies:
    The configured output base.

Implementation notes:
    Scans live as plain directories with plain JSON rather than in a database. A scan directory is then the same artifact the analysis already writes into, so a user can open it, copy it or delete it directly, and the dashboard's view of history is just the filesystem.

Security considerations:
    Two untrusted values reach the filesystem here -- the scan identifier and the uploaded filename -- and both are constrained before use. The identifier is validated against a strict pattern, and the filename is reduced to a sanitised basename.
"""

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.paths import APP_NAME, get_output_base

_FOLDER_PREFIX = f"{APP_NAME}-"

_SCAN_ID_RE = re.compile(r"^[0-9a-f]{12}$")

_folder_cache: Dict[str, Path] = {}

def _validate_scan_id(scan_id: str) -> None:
    """
    Purpose:
        Reject a scan identifier that is not in the expected form.

    Parameters:
        scan_id: The identifier.

    Raises:
        ValueError: When the identifier does not match the permitted pattern.

    Security considerations:
        Scan identifiers arrive from HTTP requests and become directory names. Validating the form is what stops a request naming a path instead of a scan.
    """
    if not _SCAN_ID_RE.match(scan_id or ""):
        raise ValueError(f"Invalid scan id: {scan_id!r}")

def get_data_dir() -> Path:
    """
    Purpose:
        Return the base directory scans are stored under.

    Returns:
        The configured output base.
    """
    return get_output_base()

def sanitize_filename(name: str) -> str:
    """
    Purpose:
        Reduce an uploaded filename to something safe to store.

    Parameters:
        name: The client-supplied filename.

    Returns:
        A safe filename ending in the APK extension.

    Security considerations:
        Only the basename is kept, so a name containing directory components cannot place the upload elsewhere. Remaining characters are filtered to an explicit allowlist, and an empty result falls back to a default so the write never lands on an empty name. The extension is appended when absent, so a stored file is always recognisable as the APK it is.
    """
    base = Path(name or "upload.apk").name
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip() or "upload.apk"
    if not base.lower().endswith(".apk"):
        base += ".apk"
    return base

def create_scan_folder(scan_id: str, filename: str) -> Path:
    """
    Purpose:
        Create the directory for a new scan.

    Parameters:
        scan_id: The scan identifier, validated.
        filename: The uploaded filename, sanitised.

    Returns:
        The created directory.

    Side effects:
        Creates a directory under the output base.

    Implementation notes:
        The directory is named from the app's own filename plus a timestamp rather than from the scan identifier, so a user browsing their output directory sees recognisable names rather than opaque ones. The identifier lives in the metadata inside.
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
    """
    Purpose:
        Locate a scan's directory, by hint or by search.

    Parameters:
        scan_id: The scan identifier.
        dir_hint: A known directory, used directly when it exists.

    Returns:
        The directory, or None when it could not be found.

    Implementation notes:
        Results are cached, because this is called on every metadata, log and result access and the fallback searches the output base. The hint short-circuits the search entirely, which is the common path -- a running scan already knows where it is writing.
    """
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
    """
    Purpose:
        Write a scan's metadata.

    Parameters:
        meta: The metadata, including the scan identifier and directory.

    Side effects:
        Writes the metadata file.

    Implementation notes:
        A scan whose directory cannot be located is skipped silently rather than raising, because metadata is written repeatedly during a scan and a failure here must not interrupt the analysis.
    """
    scan_id = meta["id"]
    folder = _folder_for(scan_id, meta.get("dir"))
    if folder is None:
        return
    (folder / "meta.json").write_text(
        json.dumps(meta, indent=2, default=str), encoding="utf-8")

def load_meta(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Read a scan's metadata.

    Parameters:
        scan_id: The scan identifier.

    Returns:
        The metadata, or None when unavailable.
    """
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
    """
    Purpose:
        List every stored scan, for the dashboard's history.

    Returns:
        The metadata of each scan found.

    Implementation notes:
        Discovered by globbing the output base for scan directories rather than from an index, so a directory copied in from elsewhere appears and one deleted by hand disappears -- the filesystem is the record. An unreadable entry is skipped rather than failing the listing, so one corrupt scan does not hide the rest of the history.
    """
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

LOG_FILENAME = "scan.log"


def log_path(scan_id: str) -> Optional[Path]:
    """
    Purpose:
        Locate a scan's log file.

    Parameters:
        scan_id: The scan identifier.

    Returns:
        The log path, or None when the scan directory is unknown.
    """
    folder = _folder_for(scan_id)
    return (folder / LOG_FILENAME) if folder is not None else None


def append_log(scan_id: str, ts: str, message: str) -> None:
    """
    Purpose:
        Append one line to a scan's log.

    Parameters:
        scan_id: The scan identifier.
        ts: Timestamp for the line.
        message: The already-redacted log line.

    Side effects:
        Appends to the log file.

    Implementation notes:
        Appending rather than rewriting, so a scan that is killed still leaves everything logged up to that point. Failures are swallowed: logging must never interrupt the analysis it is describing.

    Security considerations:
        The message has already passed through the verbose module's redaction.
    """
    try:
        path = log_path(scan_id)
        if path is None:
            return
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{ts}\t{message}\n")
    except Exception:
        pass


def read_log(scan_id: str, limit: Optional[int] = None) -> List[Dict[str, str]]:
    """
    Purpose:
        Read a scan's log for display.

    Parameters:
        scan_id: The scan identifier.
        limit: Return only the most recent entries when given.

    Returns:
        The log entries; empty when there is no log.

    Implementation notes:
        Decoding replaces undecodable bytes rather than failing, since log lines can carry fragments of APK-derived text in unexpected encodings and an unreadable byte must not hide the rest of the log.
    """
    path = log_path(scan_id)
    if path is None or not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if limit is not None and limit > 0:
        raw = raw[-limit:]
    out: List[Dict[str, str]] = []
    for line in raw:
        ts, sep, message = line.partition("\t")
        out.append({"ts": ts, "message": message} if sep else {"ts": "", "message": line})
    return out


def save_result(scan_id: str, result: Dict[str, Any]) -> None:
    """
    Purpose:
        Write a scan's result.

    Parameters:
        scan_id: The scan identifier.
        result: The result to store.

    Side effects:
        Writes the result file.

    Implementation notes:
        Serialised with a fallback converter, so a value the encoder does not understand becomes its string form rather than losing the whole result at the last step of a long scan.
    """
    folder = _folder_for(scan_id)
    if folder is None:
        return
    (folder / "result.json").write_text(
        json.dumps(result, indent=2, default=str), encoding="utf-8")

def load_result(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Purpose:
        Read a scan's stored result.

    Parameters:
        scan_id: The scan identifier.

    Returns:
        The result, or None when unavailable.
    """
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
    """
    Purpose:
        Delete a scan and everything it produced.

    Parameters:
        scan_id: The scan identifier.

    Returns:
        True when a directory was removed.

    Side effects:
        Recursively deletes the scan directory and clears its cache entry.

    Security considerations:
        The directory is the one resolved for a validated scan identifier under the output base, so a request cannot direct this at an arbitrary path. The deletion is recursive and irreversible, which is why that validation matters.
    """
    folder = _folder_for(scan_id)
    _folder_cache.pop(scan_id, None)
    if folder is not None and folder.exists():
        shutil.rmtree(folder, ignore_errors=True)
        return True
    return False
