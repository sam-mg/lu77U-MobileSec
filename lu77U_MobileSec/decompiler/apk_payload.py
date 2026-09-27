#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.apk_payload

Purpose:
    Pull the parts of an APK that a framework-specific decompiler needs -- a JavaScript bundle, native libraries, Cordova web assets -- out of the archive and onto disk safely.

Responsibilities:
    Locate a React Native bundle, identify Hermes bytecode, enumerate native ABIs, and extract members with path containment enforced.

Dependencies:
    zipfile, pathlib.

Implementation notes:
    This is the one module in the decompiler package that writes attacker-controlled content to disk, so containment is its central concern rather than an afterthought.

Security considerations:
    An APK is a zip archive and can carry entry names containing traversal sequences or absolute paths. Every write that uses an archive-supplied relative path goes through the containment check, which resolves the target and confirms it is still inside the destination before writing. Entries that escape are skipped silently rather than written outside the output directory. Nothing extracted here is executed. The files are inputs to external decompilers, which run in their own directories.
"""

import zipfile
from pathlib import Path
from typing import List, Optional

from ..utils.verbose import plural, verbose_print

HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

_BUNDLE_CANDIDATES = ("assets/index.android.bundle",)

_DEFAULT_ABIS = ("arm64-v8a",)


def find_js_bundle(apk_path: str, verbose: bool = False) -> Optional[str]:
    """
    Purpose:
        Locate the React Native JavaScript bundle inside an APK.

    Parameters:
        apk_path: Path to the APK.
        verbose: Traces a non-standard bundle name.

    Returns:
        The archive entry name, or None when no bundle was found.

    Implementation notes:
        The conventional name is tried first, then any bundle-suffixed entry under assets, sorted so the choice is deterministic between runs. Apps do rename the bundle, and failing over a name would mean not analysing the app at all. A failure to open the archive is traced and reported as no bundle, so a damaged APK costs this step rather than the scan.
    """
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = set(zf.namelist())
            for candidate in _BUNDLE_CANDIDATES:
                if candidate in names:
                    return candidate
            bundles = sorted(n for n in names
                             if n.startswith("assets/") and n.endswith(".bundle"))
            if bundles:
                verbose_print(f"No standard RN bundle name found; using {bundles[0]}", verbose)
                return bundles[0]
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not open APK to look for a JS bundle: {exc}", verbose)
    return None


def extract_member(apk_path: str, member: str, dest_dir, verbose: bool = False) -> Optional[Path]:
    """
    Purpose:
        Extract one named archive entry to a destination directory.

    Parameters:
        apk_path: Path to the APK.
        member: Exact entry name to extract.
        dest_dir: Directory to write into; created if missing.
        verbose: Traces failures.

    Returns:
        The written path, or None on any failure.

    Side effects:
        Reads the archive and writes one file.

    Security considerations:
        The destination filename is the basename of the entry, discarding any directory component, so an entry named with a traversal sequence cannot write outside the destination. This is the containment mechanism for this function -- the caller supplies the exact member name, so the path never comes from untrusted enumeration.
    """
    dest_dir = Path(dest_dir)
    try:
        with zipfile.ZipFile(apk_path) as zf:
            data = zf.read(member)
    except (zipfile.BadZipFile, KeyError, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not extract {member!r} from APK: {exc}", verbose)
        return None
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / Path(member).name
        target.write_bytes(data)
    except OSError as exc:
        verbose_print(f"Could not write extracted {member!r}: {exc}", verbose)
        return None
    return target


def is_hermes(path) -> bool:
    """
    Purpose:
        Determine whether a bundle is Hermes bytecode rather than plain JavaScript.

    Parameters:
        path: Path to the bundle file.

    Returns:
        True when the file begins with the Hermes magic bytes.

    Implementation notes:
        This decides which decompiler the React Native path uses, and the two are not interchangeable. Checking the magic bytes is reliable where the file extension is not -- both forms ship under the same bundle name. Only the first four bytes are read, so this is cheap on a large bundle. An unreadable file reads as not-Hermes, which routes it to the plain-JavaScript tool and fails there with a clearer error.
    """
    try:
        with open(path, "rb") as f:
            return f.read(4) == HERMES_MAGIC
    except OSError:
        return False


def available_native_abis(apk_path: str) -> List[str]:
    """
    Purpose:
        List the CPU architectures an APK ships native libraries for.

    Parameters:
        apk_path: Path to the APK.

    Returns:
        ABI directory names, sorted; empty when there are none or the archive could not be read.

    Implementation notes:
        Read from the archive's directory structure rather than from the libraries themselves, since the layout is fixed by the platform and parsing ELF headers would be far more work for the same answer. Sorted so that callers choosing an ABI get a deterministic result across runs.
    """
    try:
        with zipfile.ZipFile(apk_path) as zf:
            abis = set()
            for name in zf.namelist():
                parts = name.split("/")
                if len(parts) >= 3 and parts[0] == "lib" and name.endswith(".so"):
                    abis.add(parts[1])
            return sorted(abis)
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return []


_CORDOVA_WWW_PREFIX = "assets/www/"

_CORDOVA_CONFIG_CANDIDATES = ("res/xml/config.xml", "config.xml")


def _safe_extract_to(zf: zipfile.ZipFile, member: str, dest_root: Path,
                     rel: str) -> Optional[Path]:
    """
    Purpose:
        Write one archive entry to a destination, refusing any path that would escape it.

    Parameters:
        zf: The open archive.
        member: Entry name to read.
        dest_root: Directory the write must stay inside.
        rel: Relative path within that directory.

    Returns:
        The written path, or None when the target would fall outside the destination.

    Side effects:
        Creates parent directories and writes the file.

    Security considerations:
        This is the containment control for every extraction that uses an archive-derived relative path. Both the target and the root are fully resolved before comparison, so traversal sequences and symlinked parent directories are both accounted for -- a check on the unresolved string would miss both. A rejected entry returns None rather than raising, so extraction continues with the remaining entries instead of a malicious entry aborting the whole operation.
    """
    target = (dest_root / rel).resolve()
    try:
        target.relative_to(dest_root.resolve())
    except ValueError:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(zf.read(member))
    return target


def extract_cordova_www(apk_path: str, dest_dir, verbose: bool = False) -> Optional[Path]:
    """
    Purpose:
        Extract a Cordova app's web assets, which hold its actual application logic.

    Parameters:
        apk_path: Path to the APK.
        dest_dir: Directory to extract into.
        verbose: Traces the outcome.

    Returns:
        The destination directory, or None when no assets were found or extraction failed.

    Side effects:
        Creates directories and writes every web asset found.

    Implementation notes:
        The directory structure under the asset root is preserved, because Cordova code uses relative paths between its own files and a flattened tree would make the result unreadable. The Cordova configuration file is extracted alongside, from either of its conventional locations, since it declares the plugins and the allowed origins that the analysis needs. Returning None when nothing was written distinguishes an app with no web assets from one where extraction failed, both of which would otherwise look like an empty directory.

    Security considerations:
        Every entry is written through the containment check, so an entry named to escape the destination is skipped rather than written.
    """
    dest_dir = Path(dest_dir)
    written = 0
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dest_dir.mkdir(parents=True, exist_ok=True)
            names = zf.namelist()
            for name in names:
                if not name.startswith(_CORDOVA_WWW_PREFIX) or name.endswith("/"):
                    continue
                rel = name[len(_CORDOVA_WWW_PREFIX):]
                if not rel:
                    continue
                if _safe_extract_to(zf, name, dest_dir, rel) is not None:
                    written += 1
            for candidate in _CORDOVA_CONFIG_CANDIDATES:
                if candidate in names:
                    _safe_extract_to(zf, candidate, dest_dir, "config.xml")
                    break
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not extract Cordova web assets: {exc}", verbose)
        return None

    if written == 0:
        verbose_print("No assets/www/ web assets found in this APK", verbose)
        return None
    verbose_print(f"Extracted {plural(written, 'Cordova web asset')} to {dest_dir}", verbose)
    return dest_dir


def extract_native_libs(apk_path: str, dest_dir, abis=_DEFAULT_ABIS,
                        verbose: bool = False) -> Optional[Path]:
    """
    Purpose:
        Extract the native libraries for one architecture, for the Flutter path.

    Parameters:
        apk_path: Path to the APK.
        dest_dir: Directory to extract into.
        abis: Architectures to try, in order of preference.
        verbose: Traces the outcome.

    Returns:
        The destination directory, or None when no preferred ABI is present or extraction failed.

    Side effects:
        Creates the directory and writes the libraries.

    Implementation notes:
        One architecture is chosen rather than extracting all of them. An APK commonly ships the same libraries for four ABIs, and the decompiler only needs one; extracting all four would quadruple the disk cost and the decompilation time. The preference order is the caller's, defaulting to the modern 64-bit ABI, which is what current devices use and what Blutter handles best. When no preferred ABI is present the message names what was actually found, so a user can see whether to widen the request rather than just being told it failed.

    Security considerations:
        Each file is written under the basename of its entry, discarding directory components, so an entry named to escape cannot.
    """
    present = set(available_native_abis(apk_path))
    abi = next((a for a in abis if a in present), None)
    if abi is None:
        verbose_print(
            f"None of the requested ABIs {list(abis)} are present in this "
            f"APK (found: {present or 'none'})", verbose)
        return None

    dest_dir = Path(dest_dir)
    extracted = 0
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dest_dir.mkdir(parents=True, exist_ok=True)
            prefix = f"lib/{abi}/"
            for name in zf.namelist():
                if name.startswith(prefix) and name.endswith(".so"):
                    (dest_dir / Path(name).name).write_bytes(zf.read(name))
                    extracted += 1
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not extract native libraries: {exc}", verbose)
        return None

    if extracted == 0:
        return None
    verbose_print(
        f"Extracted {extracted} native librar{'y' if extracted == 1 else 'ies'} "
        f"for {abi} to {dest_dir}", verbose)
    return dest_dir
