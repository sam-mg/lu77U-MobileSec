#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.checkpoint

Purpose:
    Record how far a scan got, so that an interrupted run can resume rather than repeat the decompilation and the AI passes it already paid for.

Responsibilities:
    Track the stage reached, store per-region agent state, and persist both durably.

Dependencies:
    The scan store, for the directory layout.

Implementation notes:
    A full scan can take an hour and cost real money in model calls, so losing it to a crash, a quota pause or a restart is expensive. Checkpointing makes that recoverable. Stages are ordered, and progress only moves forward, so an out-of-order mark cannot make a resumed scan repeat work it has already done.

Security considerations:
    Region keys become filenames and are sanitised before use.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import store

STAGES = ("decompiled", "sast_done", "agents_done")


def _dir_for(scan_id: str) -> Optional[Path]:
    """
    Purpose:
        Locate a scan's checkpoint directory.

    Parameters:
        scan_id: The scan identifier.

    Returns:
        The directory, or None when the scan directory is unknown.

    Implementation notes:
        Kept inside the scan's own directory, so deleting a scan removes its checkpoint too and a copied scan directory carries its resume state with it.
    """
    folder = store._folder_for(scan_id)
    return (folder / "checkpoint") if folder is not None else None


def _read_json(path: Path) -> Optional[Any]:
    """
    Purpose:
        Read a JSON file, tolerating anything unreadable.

    Parameters:
        path: The file.

    Returns:
        The parsed data, or None.

    Implementation notes:
        Every failure yields None, so a truncated or corrupt checkpoint means starting that part fresh rather than failing the scan. A checkpoint is an optimisation, and an unusable one must never be worse than none.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, data: Any) -> None:
    """
    Purpose:
        Write a JSON file atomically.

    Parameters:
        path: The destination.
        data: The data to store.

    Side effects:
        Writes through a temporary file in the same directory and replaces the destination.

    Implementation notes:
        Atomic because a checkpoint is written repeatedly while a scan is running, which is exactly when the process is most likely to be killed. A direct write interrupted partway would leave a truncated file, and the resume path would then discard real progress. The temporary file is created in the destination's own directory so the replacement is a rename within one filesystem, which is what makes it atomic.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, default=str)
            os.replace(tmp, path)
        finally:
            Path(tmp).unlink(missing_ok=True)
    except Exception:
        pass


class ScanCheckpoint:
    """
    Purpose:
        The resume state for one scan.

    Attributes:
        scan_id: The scan identifier.
        resume: Whether this checkpoint carries usable prior progress.

    Invariants:
        The recorded stage only advances. A checkpoint with no directory silently discards writes, so an unstorable scan still runs.

    Thread-safety:
        Not synchronised. Region state is written from analysis workers, each under its own key, so concurrent writes touch separate files.
    """
    def __init__(self, scan_id: str, directory: Optional[Path], data: Dict[str, Any], resume: bool):
        """
        Purpose:
            Construct the checkpoint.

        Parameters:
            scan_id: The scan identifier.
            directory: Where state is stored, or None when it cannot be.
            data: Progress data already loaded.
            resume: Whether prior progress was found.
        """
        self.scan_id = scan_id
        self._dir = directory
        self._progress: Dict[str, Any] = data
        self.resume = resume


    @classmethod
    def fresh(cls, scan_id: str) -> "ScanCheckpoint":
        """
        Purpose:
            Start a checkpoint with no prior progress.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            A checkpoint that will not resume.
        """
        return cls(scan_id, _dir_for(scan_id), {}, resume=False)

    @classmethod
    def load(cls, scan_id: str) -> "ScanCheckpoint":
        """
        Purpose:
            Load a scan's existing checkpoint, if there is one.

        Parameters:
            scan_id: The scan identifier.

        Returns:
            The checkpoint, with resume set when usable progress was found.

        Implementation notes:
            Unreadable or absent progress yields a checkpoint that starts fresh rather than an error, so a damaged checkpoint costs the resume rather than the scan.
        """
        directory = _dir_for(scan_id)
        data: Dict[str, Any] = {}
        resume = False
        if directory is not None and directory.is_dir():
            data = _read_json(directory / "progress.json") or {}
            resume = bool(data.get("stage")) or any(directory.glob("agent-*.json"))
        return cls(scan_id, directory, data, resume=resume)


    @property
    def stage(self) -> Optional[str]:
        """
        Purpose:
            The stage this scan last reached.

        Returns:
            The stage name, or None when nothing has been recorded.
        """
        return self._progress.get("stage")

    def reached(self, stage: str) -> bool:
        """
        Purpose:
            Report whether the scan has already passed a given stage.

        Parameters:
            stage: The stage to test.

        Returns:
            True when the recorded stage is at or past it.

        Implementation notes:
            An unknown stage on either side returns False, so an unrecognised name causes the work to be redone rather than skipped. That is the safe direction: repeating a stage costs time, skipping one wrongly produces a result missing a phase.
        """
        cur = self.stage
        if cur is None or cur not in STAGES or stage not in STAGES:
            return False
        return STAGES.index(cur) >= STAGES.index(stage)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Purpose:
            Read one recorded fact.

        Parameters:
            key: The fact's name.
            default: Returned when it was not recorded.

        Returns:
            The value.
        """
        return self._progress.get(key, default)

    def mark(self, stage: str, **facts: Any) -> None:
        """
        Purpose:
            Record that a stage was reached, along with any facts the resume will need.

        Parameters:
            stage: The stage reached.
            facts: Values to record alongside it.

        Side effects:
            Persists the progress file.

        Implementation notes:
            The stage is only advanced when the new one is at or past the current one, so an out-of-order mark records its facts without rewinding progress. Facts are recorded regardless, since they are what a resumed scan needs to pick up -- paths, counts, identifiers established by the stage that just finished.
        """
        if self._dir is None:
            return
        if stage in STAGES and (self.stage is None or STAGES.index(stage) >= STAGES.index(str(self.stage))):
            self._progress["stage"] = stage
        self._progress.update(facts)
        _write_json(self._dir / "progress.json", self._progress)


    def region_state(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Purpose:
            Read the stored agent state for one code region.

        Parameters:
            key: The region key.

        Returns:
            The state, or None when nothing was stored.
        """
        if self._dir is None:
            return None
        return _read_json(self._dir / f"agent-{_safe(key)}.json")

    def save_region(self, key: str, state: Dict[str, Any]) -> None:
        """
        Purpose:
            Store the agent state for one code region.

        Parameters:
            key: The region key.
            state: The state to store.

        Side effects:
            Writes a per-region file atomically.

        Implementation notes:
            One file per region rather than one combined document, so concurrent workers do not contend and a resumed scan can skip exactly the regions that finished.

        Security considerations:
            The region key becomes part of a filename and is sanitised first.
        """
        if self._dir is None:
            return
        _write_json(self._dir / f"agent-{_safe(key)}.json", state)

    def all_region_states(self) -> Dict[str, Dict[str, Any]]:
        """
        Purpose:
            Read every stored region state, for resuming a fanned-out analysis.

        Returns:
            The states by region key.
        """
        out: Dict[str, Dict[str, Any]] = {}
        if self._dir is None or not self._dir.is_dir():
            return out
        for path in self._dir.glob("agent-*.json"):
            data = _read_json(path)
            if isinstance(data, dict) and data.get("region_key"):
                out[str(data["region_key"])] = data
        return out


    def collected_findings(self) -> List[Dict[str, Any]]:
        """
        Purpose:
            Gather the findings accumulated across every region, deduplicated, for a resumed scan to build on.

        Returns:
            The distinct findings recorded so far.

        Complexity:
            O(n) in the total number of accumulated findings.

        Implementation notes:
            Deduplicated on title, file and line, because a resumed scan can re-examine a region that had already contributed findings and would otherwise report each of them twice. Entries without a title are dropped, since they cannot be keyed and an untitled finding is not usable in a report. This is a coarse first pass, not a substitute for the validation stage's deduplication -- it only prevents a resume from duplicating its own prior output.
        """
        seen: set = set()
        out: List[Dict[str, Any]] = []
        for state in self.all_region_states().values():
            for v in state.get("accumulated") or []:
                if not isinstance(v, dict):
                    continue
                title = (v.get("title") or v.get("vulnerability_type") or "").strip().lower()
                key = (title, str(v.get("file", "")).strip(), str(v.get("line", "")).strip())
                if title and key not in seen:
                    seen.add(key)
                    out.append(v)
        return out


    def clear(self) -> None:
        """
        Purpose:
            Delete this scan's checkpoint directory.

        Side effects:
            Recursively removes the stored progress.

        Implementation notes:
            Called once a scan completes, so a finished scan does not offer to resume. Failures are swallowed, since a checkpoint left behind is harmless -- the next run over that scan would find stale progress, and the stage checks would simply redo the work.
        """
        if self._dir is None or not self._dir.exists():
            return
        try:
            import shutil

            shutil.rmtree(self._dir, ignore_errors=True)
        except Exception:
            pass


def _safe(key: str) -> str:
    """
    Purpose:
        Reduce a region key to something safe to use as a filename.

    Parameters:
        key: The region key.

    Returns:
        A bounded, filename-safe token; never empty.

    Security considerations:
        An allowlist substitution, so no separator or control character survives. Bounded in length to stay within filesystem limits, and given a fallback so an empty result cannot produce a nameless file.

    Implementation notes:
        Region keys derive from package and class names taken from the analysed APK, which is why they cannot be trusted as filenames.
    """
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(key))[:80] or "region"


def has_checkpoint(scan_id: str) -> bool:
    """
    Purpose:
        Report whether a scan has resumable progress.

    Parameters:
        scan_id: The scan identifier.

    Returns:
        True when a usable checkpoint exists.
    """
    return ScanCheckpoint.load(scan_id).resume


def clear(scan_id: str) -> None:
    """
    Purpose:
        Discard a scan's checkpoint, so the next run starts fresh.

    Parameters:
        scan_id: The scan identifier.

    Side effects:
        Removes the stored progress.
    """
    ScanCheckpoint.fresh(scan_id).clear()
