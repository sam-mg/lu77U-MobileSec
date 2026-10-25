#!/usr/bin/env python3
"""
Module: ghera_benchmark

Purpose:
    Scan the Ghera benchmark's lean apps through a running dashboard and score the scans against the answer key, so recall can be compared with published Android vulnerability tools.

Responsibilities:
    Queue every lean benchmark's Benign (vulnerable) or Secure (fixed) APK, keep a fixed number of scans in flight, resume a scan paused by an interruption, and record each scan's id in a state file; then read the finished scans from their folders, match each one's findings against the benchmark's expected classes and pattern, apply the recorded manual reviews, and write a results file the demo builder and the wiki read.

Dependencies:
    The standard library only; the dashboard's HTTP API for run, and the scan folders it writes for score.

Usage:
    python scripts/ghera_benchmark.py run --ghera etc/vulnerable-apps/ghera --state ghera_benign.json --variant Benign
    python scripts/ghera_benchmark.py run --ghera etc/vulnerable-apps/ghera --state ghera_secure.json --variant Secure
    python scripts/ghera_benchmark.py score --benign ghera_benign.json --secure ghera_secure.json

Implementation notes:
    Ghera (Mitra and Ranganath, Kansas State University) has 60 lean benchmarks, each a small app with one planted vulnerability, a Malicious app that exploits it and a Secure app with it fixed. A benchmark counts as detected when any reported finding identifies its planted issue. The automatic match is a first pass that proposes candidates by class and wording; the answer key's "review" entries are the human verdict, each with its reason, and override it in either direction. A Secure app reporting the fixed issue counts as a false positive. The answer key is for scoring only and must never be copied into a prompt, a skill or a scanner rule: the point is to measure the tool, not to teach it the benchmark.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
KEY_PATH = REPO_ROOT / "scripts" / "ghera_answer_key.json"
RESULTS_PATH = REPO_ROOT / "scripts" / "ghera_results.json"
SCANS_BASE = Path.home() / "Documents" / "lu77U-MobileSec"
CATEGORIES = ("Crypto", "ICC", "Networking", "NonAPI", "Permission", "Storage", "System", "Web")
VARIANTS = ("Benign", "Secure")
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
FINAL = ("completed", "failed", "cancelled", "no-apk")
RESUMABLE = ("user", "interrupted")


def lean_benchmarks(ghera: Path) -> List[Tuple[str, Path]]:
    """
    Purpose:
        List the lean benchmarks in a Ghera checkout, in category order.

    Parameters:
        ghera: The checkout's root.

    Returns:
        (Category/Name, directory) pairs.

    Implementation notes:
        The one fat benchmark (a full messaging app) is left out, so the denominator is the 60 lean benchmarks.
    """
    out = []
    for category in CATEGORIES:
        folder = ghera / category
        if not folder.is_dir():
            continue
        for bench in sorted(p for p in folder.iterdir() if p.is_dir() and p.name.endswith("-Lean")):
            out.append((f"{category}/{bench.name}", bench))
    return out


def apk_for(bench: Path, variant: str) -> Optional[Path]:
    """
    Purpose:
        Find the APK a benchmark ships for one variant.

    Parameters:
        bench: The benchmark's directory.
        variant: Benign or Secure.

    Returns:
        The APK path, or None when the benchmark has no such app.

    Implementation notes:
        A few benchmarks have no Secure app because the issue cannot be fixed in code (a merged library manifest, for one); those are recorded as no-apk rather than skipped silently.
    """
    folder = bench / variant
    apks = sorted(folder.glob("*.apk")) if folder.is_dir() else []
    return apks[0] if apks else None


def _api(base: str, path: str, data: Optional[bytes] = None,
         headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Purpose:
        Make one request to the dashboard and decode its JSON answer.

    Parameters:
        base: The API root, such as http://127.0.0.1:8000/api.
        path: The path below it.
        data: A request body, which makes the request a POST.
        headers: Extra request headers.

    Returns:
        The decoded answer.

    Raises:
        urllib.error.URLError: When the dashboard cannot be reached.
    """
    request = urllib.request.Request(base + path, data=data, headers=headers or {},
                                     method="POST" if data is not None else "GET")
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def _queue(base: str, apk: Path) -> str:
    """
    Purpose:
        Start a scan of a local APK by path.

    Parameters:
        base: The API root.
        apk: The APK to scan.

    Returns:
        The new scan's id.

    Implementation notes:
        Sent as a multipart form with only a path field, the same form the dashboard's own upload card uses for a file already on this machine, so the APK is not copied through the request.
    """
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n"
            f"{apk}\r\n--{boundary}--\r\n").encode()
    answer = _api(base, "/scans", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return str(answer["id"])


def pending_jobs(benches: Iterable[Tuple[str, Path]], state: Dict[str, Any]) -> List[Tuple[str, Path]]:
    """
    Purpose:
        List the benchmarks that still need a scan queued.

    Parameters:
        benches: (key, directory) pairs.
        state: The run's state, keyed by benchmark.

    Returns:
        The benchmarks with no scan id and no final status.
    """
    return [(k, b) for k, b in benches
            if not state.get(k, {}).get("id") and state.get(k, {}).get("status") not in FINAL]


def in_flight(state: Dict[str, Any]) -> List[str]:
    """
    Purpose:
        List the benchmarks whose scan is queued and not yet finished.

    Parameters:
        state: The run's state, keyed by benchmark.

    Returns:
        Their keys.
    """
    return [k for k, entry in state.items() if entry.get("id") and entry.get("status") not in FINAL]


def run(args: argparse.Namespace) -> int:
    """
    Purpose:
        Queue and follow every lean benchmark's scan for one variant until all have finished.

    Parameters:
        args: The parsed command line.

    Returns:
        The process exit status.

    Side effects:
        Starts scans on the dashboard, resumes interrupted ones, and rewrites the state file after every change.

    Implementation notes:
        The state file is the only memory, so a stopped run picks up where it left off, adopting scans already in flight. --only limits a run to named benchmarks, for a pilot or a rescan of a few. Two scans in flight overlap one app's static phases with another's device phase; the dashboard serialises the device phase itself, so a higher number gains little on one device. A scan paused for quota is left alone: the dashboard resumes it when the provider's limit resets.
    """
    state_path = Path(args.state)
    state: Dict[str, Any] = json.loads(state_path.read_text()) if state_path.exists() else {}
    benches = [(k, b) for k, b in lean_benchmarks(Path(args.ghera)) if not args.only or k in args.only]

    def save() -> None:
        """
        Purpose:
            Write the state file.

        Side effects:
            Overwrites the state file.
        """
        state_path.write_text(json.dumps(state, indent=1) + "\n")

    while True:
        flying = in_flight(state)
        todo = pending_jobs(benches, state)
        if not flying and not todo:
            print("all done", flush=True)
            return 0
        while len(flying) < args.parallel and todo:
            key, bench = todo.pop(0)
            apk = apk_for(bench, args.variant)
            if apk is None:
                state[key] = {"status": "no-apk"}
                save()
                print(f"{key}: no {args.variant} app", flush=True)
                continue
            state[key] = {"id": _queue(args.api, apk.resolve()), "apk": str(apk), "started": time.time()}
            save()
            flying.append(key)
            print(f"queued {key} -> {state[key]['id']}", flush=True)
        for key in flying:
            entry = state[key]
            try:
                meta = _api(args.api, f"/scans/{urllib.parse.quote(entry['id'])}")["meta"]
            except OSError as exc:
                print(f"poll error {key}: {exc}", flush=True)
                continue
            status = meta.get("status")
            if status in FINAL:
                entry.update(status=status, finished=time.time())
                save()
                print(f"{key}: {status} in {int(entry['finished'] - entry['started'])}s", flush=True)
            elif status == "paused" and meta.get("pause_reason") in RESUMABLE:
                _api(args.api, f"/scans/{urllib.parse.quote(entry['id'])}/resume", b"")
                print(f"{key}: resumed after {meta.get('pause_reason')}", flush=True)
        time.sleep(args.poll)


def findings_of(result: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Purpose:
        Flatten a scan result's reported findings with the severity bucket each was published under.

    Parameters:
        result: A scan's result.json.

    Returns:
        (bucket, finding) pairs; refuted findings are not reported and are not included.
    """
    groups = (result.get("vulnerability_analysis") or {}).get("vulnerabilities") or {}
    return [(bucket, f) for bucket in RANK for f in groups.get(bucket) or []]


def matches(spec: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    """
    Purpose:
        Decide whether a finding is a candidate for the benchmark's planted issue.

    Parameters:
        spec: The benchmark's answer-key entry.
        finding: One reported finding.

    Returns:
        True when the finding's class is one the issue can be filed under and its wording matches the pattern.

    Implementation notes:
        Both halves are required. Class alone would credit any exported-component note on an ICC benchmark whatever it was about; wording alone would credit "cleartext" in the targetSdk note every Ghera app gets. No answer-key class is a chain class, so a chain, which restates components reported on their own, never matches. The titles of findings merged into this one count too, since the report lists them under it. An entry may limit the fields searched ("fields"), for an issue whose wording also appears in a note every app gets: "pins no domain" in the description of the generic network-config note matched the unpinned-certificates benchmark on every app.
    """
    if str(finding.get("vuln_class") or "") not in spec["classes"]:
        return False
    fields = spec.get("fields") or ("title", "description", "code_snippet", "file")
    text = " ".join(str(finding.get(k) or "") for k in fields)
    text += " " + " ".join(str(t) for t in finding.get("duplicate_titles") or [])
    return re.search(spec["pattern"], text, re.IGNORECASE) is not None


def score_scan(spec: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Score one finished scan against its benchmark.

    Parameters:
        spec: The benchmark's answer-key entry.
        result: The scan's result.json.

    Returns:
        The candidate findings, whether any was found at any severity and at Low or above, and the finding counts.
    """
    pairs = findings_of(result)
    hits = []
    for bucket, finding in pairs:
        if matches(spec, finding):
            verification = finding.get("dynamic_verification")
            hits.append({
                "title": finding.get("title"),
                "class": finding.get("vuln_class"),
                "severity": bucket,
                "verified": verification.get("status") if isinstance(verification, dict) else None,
            })
    best = max((RANK[h["severity"]] for h in hits), default=-1)
    return {
        "hits": hits,
        "auto": best >= 0,
        "auto_low": best >= RANK["low"],
        "findings": len(pairs),
        "non_info": sum(1 for bucket, _ in pairs if bucket != "info"),
    }


def apply_review(scored: Dict[str, Any], review: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Settle a scored scan with the recorded human verdict, when there is one.

    Parameters:
        scored: The automatic score.
        review: The answer key's review for this benchmark and variant, holding "detected", optionally "low", and "why".

    Returns:
        The score with "detected", "detected_low" and, when reviewed, "review" set.

    Raises:
        ValueError: When a review gives no reason.

    Implementation notes:
        A review without a reason is refused, because an unexplained override is indistinguishable from moving the number.
    """
    out = dict(scored)
    if review is None:
        out["detected"], out["detected_low"] = scored["auto"], scored["auto_low"]
        return out
    if not str(review.get("why") or "").strip():
        raise ValueError("a review must say why")
    out["detected"] = bool(review["detected"])
    out["detected_low"] = bool(review.get("low", review["detected"] and scored["auto_low"]))
    out["review"] = review["why"]
    return out


def scan_folders(base: Path) -> Dict[str, Path]:
    """
    Purpose:
        Map every scan id under the scans folder to its folder.

    Parameters:
        base: The folder the dashboard writes scans into.

    Returns:
        Scan id to folder.
    """
    out = {}
    for meta_path in base.glob("*/meta.json"):
        try:
            out[str(json.loads(meta_path.read_text(encoding="utf-8"))["id"])] = meta_path.parent
        except (OSError, ValueError, KeyError):
            continue
    return out


def summarise(rows: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Purpose:
        Total a variant's scored benchmarks overall and per category.

    Parameters:
        rows: Scored benchmarks keyed by Category/Name.

    Returns:
        Counts of benchmarks scored, detected at any severity and at Low or above, findings and non-informational findings, overall and by category.
    """
    def total(items: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Purpose:
            Count one group of scored benchmarks.

        Parameters:
            items: The scored benchmarks.

        Returns:
            The counts.
        """
        return {
            "scored": len(items),
            "detected": sum(1 for r in items if r["detected"]),
            "detected_low": sum(1 for r in items if r["detected_low"]),
            "findings": sum(r["findings"] for r in items),
            "non_info": sum(r["non_info"] for r in items),
        }

    by_category = {c: total([r for k, r in rows.items() if k.split("/")[0] == c]) for c in CATEGORIES}
    return {"overall": total(list(rows.values())), "by_category": by_category}


def score(args: argparse.Namespace) -> int:
    """
    Purpose:
        Score every finished scan named in the state files and write the results file.

    Parameters:
        args: The parsed command line.

    Returns:
        The process exit status.

    Side effects:
        Reads scan folders and writes the results file.
    """
    key = json.loads(Path(args.key).read_text(encoding="utf-8"))
    folders = scan_folders(Path(args.scans))
    results: Dict[str, Any] = {"source": key["source"], "revision": key["revision"], "variants": {}}
    for variant, state_file in (("Benign", args.benign), ("Secure", args.secure)):
        if not state_file:
            continue
        state = json.loads(Path(state_file).read_text(encoding="utf-8"))
        rows: Dict[str, Dict[str, Any]] = {}
        for bench, entry in state.items():
            folder = folders.get(str(entry.get("id")))
            if entry.get("status") != "completed" or folder is None or not (folder / "result.json").exists():
                continue
            spec = key["benchmarks"][bench]
            scan_result = json.loads((folder / "result.json").read_text(encoding="utf-8"))
            review = (spec.get("review") or {}).get(variant)
            row = apply_review(score_scan(spec, scan_result), review)
            row.update(scan_id=entry["id"], folder=folder.name, apk=Path(str(entry.get("apk") or "")).name,
                       model=((scan_result.get("analyzer_details") or {}).get("llm_usage") or {}).get("model"))
            rows[bench] = row
        results["variants"][variant] = {"benchmarks": rows, "summary": summarise(rows)}
        overall = results["variants"][variant]["summary"]["overall"]
        print(f"{variant}: {overall['detected']}/{overall['scored']} reported at any severity, "
              f"{overall['detected_low']}/{overall['scored']} at Low or above, "
              f"{overall['findings']} findings ({overall['non_info']} above Informational)")
    Path(args.out).write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """
    Purpose:
        Parse the command line and run the chosen command.

    Parameters:
        argv: The arguments, defaulting to the process's own.

    Returns:
        The process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1].strip())
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="scan every lean benchmark of one variant")
    run_p.add_argument("--ghera", required=True, help="path to a Ghera checkout with its LFS APKs")
    run_p.add_argument("--state", required=True, help="state file to create or resume")
    run_p.add_argument("--variant", choices=VARIANTS, default="Benign")
    run_p.add_argument("--api", default="http://127.0.0.1:8000/api", help="the dashboard's API root; it prints its port at start")
    run_p.add_argument("--parallel", type=int, default=2)
    run_p.add_argument("--poll", type=float, default=20.0)
    run_p.add_argument("--only", nargs="*", default=[], help="Category/Name of the benchmarks to scan; all when omitted")
    score_p = sub.add_parser("score", help="score finished scans against the answer key")
    score_p.add_argument("--benign", help="state file of the Benign run")
    score_p.add_argument("--secure", help="state file of the Secure run")
    score_p.add_argument("--key", default=str(KEY_PATH))
    score_p.add_argument("--scans", default=str(SCANS_BASE))
    score_p.add_argument("--out", default=str(RESULTS_PATH))
    args = parser.parse_args(argv)
    return run(args) if args.command == "run" else score(args)


if __name__ == "__main__":
    sys.exit(main())
