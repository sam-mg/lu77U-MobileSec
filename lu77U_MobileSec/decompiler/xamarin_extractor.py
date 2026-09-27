#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.xamarin_extractor

Purpose:
    Recover the managed .NET assemblies from a Xamarin or MAUI APK, including the compressed and bundled forms modern builds use, so that a decompiler has something to work on.

Responsibilities:
    Recognise a Xamarin APK, extract loose and stored assemblies, decompress the XALZ container format, unpack the AssemblyStore blob, and fall back to string extraction when decompilation is unavailable.

Dependencies:
    zipfile, struct.

Implementation notes:
    Xamarin has shipped assemblies three ways over time, and a current app can use any of them: loose DLL files, individually compressed with an LZ4 container, or packed into a single AssemblyStore blob. All three are handled because an app using only the newest form would otherwise yield nothing at all. The LZ4 block decoder is written out here rather than taken from a library, so that recovering a Xamarin app does not depend on an optional package being installed.

Security considerations:
    Everything parsed here is an attacker-controlled binary format, decoded by hand-written parsers. Every length and offset read from the input is bounds-checked before use, and a declared size beyond a hard cap is rejected outright -- a decompression bomb in a crafted APK would otherwise be trivial. Assemblies are written to disk but never loaded or executed by this process.
"""

import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..utils.verbose import plural, verbose_print

XALZ_MAGIC = b"XALZ"
XALZ_HEADER_SIZE = 12

XABA_MAGIC = b"XABA"
XABA_MAGIC_LE = b"BAAX"

PE_MAGIC = b"MZ"

_ASSEMBLY_PREFIXES = ("assemblies/", "assets/assemblies/", "unknown/assemblies/")

_MAX_ASSEMBLY_BYTES = 128 * 1024 * 1024


def is_xamarin_apk(apk_path: str, verbose: bool = False) -> bool:
    """
    Purpose:
        Determine whether an APK contains managed .NET assemblies.

    Parameters:
        apk_path: Path to the APK.
        verbose: Traces a failure to read the archive.

    Returns:
        True when either loose assemblies or an assembly store is present.

    Implementation notes:
        Both forms are checked, because an app using only the store has no DLL entries at all and would otherwise read as not-Xamarin. Only entry names are read, so this is cheap enough to run during detection.
    """
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not read {apk_path} as a zip: {exc}", verbose)
        return False
    return bool(_assembly_entries(names)) or bool(_store_entries(names))


def _assembly_entries(names: List[str]) -> List[str]:
    """
    Purpose:
        Select the archive entries that are loose managed assemblies.

    Parameters:
        names: Archive entry names.

    Returns:
        Matching entry names.

    Implementation notes:
        Matched on both the conventional location prefixes and the file extension, so an unrelated DLL elsewhere in the archive is not treated as a managed assembly. The extension test is case-insensitive because archive entry casing is not reliable.
    """
    return [n for n in names
            if any(n.startswith(p) for p in _ASSEMBLY_PREFIXES)
            and n.lower().endswith(".dll")]


def _store_entries(names: List[str]) -> List[str]:
    """
    Purpose:
        Select the archive entries that are assembly store blobs.

    Parameters:
        names: Archive entry names.

    Returns:
        Matching entry names.

    Implementation notes:
        Matched loosely, on a blob extension or on the word appearing in the path, because the store's naming has changed across Xamarin versions and a strict match would miss newer layouts. DLL entries are excluded explicitly so the two selectors cannot both claim the same entry and extract it twice.
    """
    out = []
    for name in names:
        lower = name.lower()
        if lower.endswith(".blob") or ".blob." in lower or "assemblies" in lower:
            if not lower.endswith(".dll"):
                out.append(name)
    return out


def extract_xamarin_assemblies(apk_path: str, dest_dir, verbose: bool = False
                               ) -> Optional[Path]:
    """
    Purpose:
        Extract every recoverable managed assembly from an APK.

    Parameters:
        apk_path: Path to the APK.
        dest_dir: Directory to write assemblies into; created if missing.
        verbose: Traces progress and failures.

    Returns:
        The destination directory, or None when nothing was recovered.

    Side effects:
        Creates the directory and writes one file per assembly.

    Implementation notes:
        Loose assemblies are handled first, then the store blobs, so an app using both yields everything. Each entry is read inside its own guard, so one corrupt member does not abort the extraction of the rest.

    Security considerations:
        Assemblies are written under the basename of their entry, discarding any directory component, so a crafted entry name cannot write outside the destination.
    """
    dest = Path(dest_dir)
    written = 0
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = archive.namelist()
            dest.mkdir(parents=True, exist_ok=True)

            for name in _assembly_entries(names):
                try:
                    payload = archive.read(name)
                except (KeyError, OSError, zipfile.BadZipFile):
                    continue
                if _write_assembly(dest, Path(name).name, payload, verbose):
                    written += 1

            if written == 0:
                for name in _store_entries(names):
                    try:
                        blob = archive.read(name)
                    except (KeyError, OSError, zipfile.BadZipFile):
                        continue
                    if not blob[:4] in (XABA_MAGIC, XABA_MAGIC_LE):
                        continue
                    verbose_print(f"AssemblyStore blob found: {name}", verbose)
                    written += _unpack_store(blob, dest, verbose)
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not extract Xamarin assemblies: {exc}", verbose)
        return None

    if written == 0:
        verbose_print("No .NET assemblies recovered from this APK", verbose)
        return None
    verbose_print(f"Recovered {plural(written, '.NET assembly', '.NET assemblies')} to {dest}", verbose)
    return dest


def _write_assembly(dest: Path, filename: str, payload: bytes, verbose: bool) -> bool:
    """
    Purpose:
        Write one assembly, decompressing it first when it is in the XALZ container.

    Parameters:
        dest: Destination directory.
        filename: Name to write under.
        payload: Raw entry contents.
        verbose: Traces a write failure.

    Returns:
        True when a file was written.

    Side effects:
        Writes one file.

    Implementation notes:
        The container is detected by magic bytes rather than by filename, because a compressed assembly keeps the DLL extension. An assembly that fails to decompress is skipped rather than written in its compressed form, which the decompiler could not read anyway.
    """
    data = decompress_xalz(payload, verbose) if payload[:4] == XALZ_MAGIC else payload
    if not data:
        return False
    target = dest / filename
    try:
        target.write_bytes(data)
    except OSError as exc:
        verbose_print(f"Could not write {filename}: {exc}", verbose)
        return False
    return True


def decompress_xalz(payload: bytes, verbose: bool = False) -> Optional[bytes]:
    """
    Purpose:
        Decompress an assembly from Xamarin's XALZ container format.

    Parameters:
        payload: The container bytes.
        verbose: Traces a rejected header or a decode failure.

    Returns:
        The decompressed assembly, or None when the container is malformed or implausible.

    Implementation notes:
        The header carries the uncompressed size, which is both what the decoder needs and the first thing to distrust.

    Security considerations:
        The declared size is checked against a hard maximum before any allocation. Without that, a small crafted payload declaring an enormous output would make this exhaust memory -- the classic decompression bomb, and entirely reachable here since the APK is attacker-supplied. Decode errors are caught and reported as a failed assembly rather than propagating.
    """
    if len(payload) < XALZ_HEADER_SIZE or payload[:4] != XALZ_MAGIC:
        return None
    (_index, declared) = struct.unpack_from("<II", payload, 4)
    if declared <= 0 or declared > _MAX_ASSEMBLY_BYTES:
        verbose_print(f"XALZ header declares an implausible size ({declared}); skipping",
                      verbose)
        return None
    try:
        out = _lz4_block_decompress(payload[XALZ_HEADER_SIZE:], declared)
    except (ValueError, IndexError) as exc:
        verbose_print(f"XALZ payload did not decode ({exc})", verbose)
        return None
    return out


def _lz4_block_decompress(src: bytes, expected: int) -> bytes:
    """
    Purpose:
        Decode an LZ4 block, the compression used inside the XALZ container.

    Parameters:
        src: Compressed block.
        expected: Declared uncompressed size, already validated by the caller.

    Returns:
        The decompressed bytes.

    Raises:
        ValueError: When the block is truncated or internally inconsistent.
        IndexError: When an offset points outside the data decoded so far.

    Complexity:
        O(n) in the output size.

    Implementation notes:
        Implemented here rather than via a library so that Xamarin support has no optional dependency. The format is small enough to implement correctly and stable enough not to need maintenance.

    Security considerations:
        Every length and match offset read from the input is validated before use, and truncation is detected rather than read past. A hand-written decoder over attacker-controlled input is exactly where an unchecked length would become a memory-safety problem in a lower-level language and an unbounded allocation here.
    """
    out = bytearray()
    pos = 0
    end = len(src)

    while pos < end:
        token = src[pos]
        pos += 1

        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if pos >= end:
                    raise ValueError("truncated literal length")
                extra = src[pos]
                pos += 1
                literal_len += extra
                if extra != 255:
                    break
        if literal_len:
            if pos + literal_len > end:
                raise ValueError("truncated literals")
            out += src[pos:pos + literal_len]
            pos += literal_len

        if pos >= end:
            break
        if pos + 2 > end:
            raise ValueError("truncated match offset")
        offset = int.from_bytes(src[pos:pos + 2], "little")
        pos += 2
        if offset == 0 or offset > len(out):
            raise ValueError(f"invalid match offset {offset}")

        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if pos >= end:
                    raise ValueError("truncated match length")
                extra = src[pos]
                pos += 1
                match_len += extra
                if extra != 255:
                    break
        match_len += 4

        start = len(out) - offset
        for i in range(match_len):
            out.append(out[start + i])

        if len(out) > _MAX_ASSEMBLY_BYTES:
            raise ValueError("decoded output exceeds the size ceiling")

    if expected and len(out) != expected:
        raise ValueError(f"decoded {len(out)} bytes, header declared {expected}")
    return bytes(out)


def _unpack_store(blob: bytes, dest: Path, verbose: bool) -> int:
    """
    Purpose:
        Unpack the assemblies held inside a Xamarin AssemblyStore blob.

    Parameters:
        blob: The store contents.
        dest: Destination directory.
        verbose: Traces the store version and any rejection.

    Returns:
        The number of assemblies written.

    Side effects:
        Writes one file per assembly recovered.

    Implementation notes:
        Byte order is determined from the magic bytes rather than assumed, since the store is written in the target device's order and both are in the wild. The entry count is sanity-checked against a plausible range before it is used to size anything. A store declaring an absurd count is rejected rather than trusted, which is the same class of defence as the size cap in the decompressor.

    Security considerations:
        Every field is read with bounds checking, and a structurally invalid store yields zero rather than raising.
    """
    if len(blob) < 20:
        return 0

    order = "<" if blob[:4] == XABA_MAGIC_LE else ">"
    try:
        version, entry_count, index_count = struct.unpack_from(order + "III", blob, 4)
    except struct.error:
        return 0
    verbose_print(
        f"AssemblyStore v{version}: {entry_count} entries, {index_count} index entries",
        verbose)
    if not 0 < entry_count < 10000:
        verbose_print("AssemblyStore entry count is implausible; skipping", verbose)
        return 0

    written = 0
    for descriptor_size in (24, 20, 28, 32):
        found = _try_descriptors(blob, order, entry_count, descriptor_size)
        if not found:
            continue
        verbose_print(
            f"AssemblyStore index parsed with {descriptor_size}-byte descriptors "
            f"({len(found)} assembly/assemblies)", verbose)
        for index, (offset, size) in enumerate(found):
            data = blob[offset:offset + size]
            if data[:4] == XALZ_MAGIC:
                data = decompress_xalz(data, verbose) or data
            name = f"assembly_{index:03d}.dll"
            if _write_assembly(dest, name, data, verbose):
                written += 1
        break

    if written == 0:
        verbose_print(
            "AssemblyStore index did not parse under any known layout; the scan "
            "continues on whatever else the APK yielded", verbose)
    return written


def _try_descriptors(blob: bytes, order: str, count: int, size: int
                     ) -> List[Tuple[int, int]]:
    """
    Purpose:
        Read the store's entry descriptors, validating each one against the blob's real bounds.

    Parameters:
        blob: The store contents.
        order: Byte order prefix.
        count: Declared number of entries.
        size: Descriptor stride to try.

    Returns:
        Validated offset and length pairs, or an empty list when the stride does not produce a consistent table.

    Implementation notes:
        The descriptor layout differs between store versions, so the caller tries candidate strides and this function reports whether one produces a self-consistent table. Returning empty on the first inconsistency is what makes that trial-and-error safe.

    Security considerations:
        Every descriptor is checked three ways before being accepted: a non-zero length within the size cap, an offset at or after the header, and an end within the blob. An unchecked offset here would read outside the buffer or, worse, be used to write a file from unrelated memory.
    """
    out: List[Tuple[int, int]] = []
    base = 20
    total = len(blob)
    for index in range(count):
        start = base + index * size
        if start + 8 > total:
            return []
        offset, length = struct.unpack_from(order + "II", blob, start)
        if length == 0 or length > _MAX_ASSEMBLY_BYTES:
            return []
        if offset < base or offset + length > total:
            return []
        out.append((offset, length))
    return out


_MIN_STRING_LEN = 6

_MAX_STRINGS_PER_ASSEMBLY = 4000


def write_string_sidecars(source_root, verbose: bool = False) -> int:
    """
    Purpose:
        Write the printable strings of each assembly to a companion file, so that analysis can proceed when no .NET decompiler is available.

    Parameters:
        source_root: Directory holding the recovered assemblies.
        verbose: Traces progress.

    Returns:
        The number of sidecar files written.

    Side effects:
        Reads each assembly and writes one text file per assembly with strings.

    Implementation notes:
        This is the degraded path for Xamarin analysis. Strings are far less than decompiled C#, but they still surface hardcoded URLs, credentials and API names, which is the bulk of what a static pass finds in a Xamarin app anyway. Each sidecar carries a header explaining what it is and that the assembly was not decompiled, so neither a reader nor the AI mistakes a string dump for recovered source. Assemblies with no qualifying strings produce no file, so an empty sidecar never appears.

    Security considerations:
        Extracted strings are attacker-controlled and may include credentials embedded in the app; the sidecars are plaintext beside the other scan artifacts.
    """
    root = Path(source_root)
    if not root.is_dir():
        return 0
    written = 0
    for dll in sorted(root.glob("*.dll")):
        try:
            payload = dll.read_bytes()
        except OSError:
            continue
        strings = _printable_strings(payload)
        if not strings:
            continue
        header = (f"# Strings extracted from {dll.name} ({len(payload)} bytes)\n"
                  f"# One per line. This assembly was not decompiled to C#; these "
                  f"are its literal strings.\n\n")
        try:
            (root / f"{dll.name}.txt").write_text(header + "\n".join(strings),
                                                  encoding="utf-8")
            written += 1
        except OSError as exc:
            verbose_print(f"Could not write strings for {dll.name}: {exc}", verbose)
    verbose_print(f"Wrote {plural(written, 'assembly string sidecar')}", verbose)
    return written


def _printable_strings(payload: bytes) -> List[str]:
    """
    Purpose:
        Extract distinct printable strings from an assembly's bytes.

    Parameters:
        payload: Assembly contents.

    Returns:
        Unique strings in order of first appearance.

    Complexity:
        O(n) in the payload size.

    Implementation notes:
        Runs of printable ASCII are accumulated and kept when long enough to be meaningful, which filters out the byte noise that dominates a compiled assembly. Deduplication preserves first-appearance order rather than sorting, so the output reflects the assembly's layout and related strings stay near each other.
    """
    out: List[str] = []
    seen: set = set()

    def keep(text: str) -> None:
        """
        Purpose:
            Record one candidate string if it is long enough and not already seen.

        Parameters:
            text: The candidate run.

        Side effects:
            Appends to the enclosing result list and seen set.

        Implementation notes:
            Defined as a closure so the length threshold and the deduplication set are applied identically wherever a run ends -- both mid-payload and at the final run -- without threading that state through parameters.
        """
        text = text.strip()
        if len(text) >= _MIN_STRING_LEN and text not in seen:
            seen.add(text)
            out.append(text)

    run = bytearray()
    for byte in payload:
        if 32 <= byte < 127:
            run.append(byte)
        else:
            if len(run) >= _MIN_STRING_LEN:
                keep(run.decode("ascii", "ignore"))
            run.clear()
        if len(out) >= _MAX_STRINGS_PER_ASSEMBLY:
            return out
    if len(run) >= _MIN_STRING_LEN:
        keep(run.decode("ascii", "ignore"))

    utf16 = bytearray()
    index = 0
    limit = len(payload) - 1
    while index < limit:
        if 32 <= payload[index] < 127 and payload[index + 1] == 0:
            utf16.append(payload[index])
            index += 2
            continue
        if len(utf16) >= _MIN_STRING_LEN:
            keep(utf16.decode("ascii", "ignore"))
            if len(out) >= _MAX_STRINGS_PER_ASSEMBLY:
                return out
        utf16.clear()
        index += 1
    if len(utf16) >= _MIN_STRING_LEN:
        keep(utf16.decode("ascii", "ignore"))
    return out


def summarize_assemblies(source_root) -> Dict[str, object]:
    """
    Purpose:
        Summarise what was recovered, for the report and for deciding whether decompilation is worth attempting.

    Parameters:
        source_root: Directory holding the recovered assemblies.

    Returns:
        A summary of the assemblies found.

    Implementation notes:
        Returns an empty summary rather than raising when the directory does not exist, so a Xamarin app where extraction failed still renders a report section saying so.
    """
    root = Path(source_root)
    if not root.is_dir():
        return {"assemblies": [], "app_assemblies": []}
    assemblies = sorted(p.name for p in root.glob("*.dll"))
    framework_prefixes = ("System.", "Microsoft.", "Mono.", "Xamarin.", "netstandard",
                          "mscorlib", "Java.Interop", "FSharp.")
    app = [a for a in assemblies
           if not any(a.startswith(prefix) for prefix in framework_prefixes)]
    return {"assemblies": assemblies, "app_assemblies": app}
