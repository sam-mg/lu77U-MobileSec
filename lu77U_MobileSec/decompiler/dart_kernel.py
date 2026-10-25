#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.dart_kernel

Purpose:
    Recover the original Dart source of a debug-mode Flutter app from the kernel snapshot it ships, so it can be analysed as source instead of being rejected for having no AOT library.

Responsibilities:
    Recognise a debug build, pull the source table out of kernel_blob.bin, sort each file into app code, a third-party package or the SDK, and write the app and package sources to disk with path containment enforced.

Dependencies:
    zipfile, re, pathlib.

Implementation notes:
    A debug build carries kernel_blob.bin instead of libapp.so. The kernel binary keeps a source table so the VM can show source in stack traces and for hot reload, and each entry is a length-prefixed URI followed by the length-prefixed UTF-8 text of that file, comments included. Rather than parse the whole kernel format, whose surrounding fields change between Dart releases, this scans for that one stable shape: a URI whose preceding bytes are its own length in the kernel's variable-length integer encoding, followed by a length and that many bytes of valid UTF-8. The Flutter and Dart SDK sources are dropped because they are the same for every app and would bury the app's own code; third-party packages are kept apart from the app because a plugin's code is still in scope but is not what the developer wrote.

Security considerations:
    Both the kernel and the URIs inside it are attacker-controlled. Every output path is rebuilt from sanitised components and checked to resolve inside the destination before anything is written, the input size is capped before it is read into memory, and no recovered text is ever executed.
"""

import hmac
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..utils.verbose import plural, verbose_print

KERNEL_MEMBER = "assets/flutter_assets/kernel_blob.bin"
MAX_KERNEL_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024

APP_DIR = "dart_source"
PACKAGES_DIR = "dart_packages"

_URI_RE = re.compile(rb"(?:file|org-dartlang-[a-z-]+):[\x21-\x7e]{1,512}?\.dart")
_PUB_CACHE_RE = re.compile(r"/\.pub-cache/(?:hosted/[^/]+|git)/([A-Za-z0-9_]+)-([^/]+)/(.*)$")
_SDK_PATH_MARKERS = (
    "/packages/flutter/", 
    "/packages/flutter_", 
    "/bin/cache/", 
    "/flutter/bin/",
    "/sky_engine/", 
    "/dart-sdk/", 
    "/third_party/dart/",
)
_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class DartSource:
    """
    Purpose:
        One source file recovered from the kernel, with where it belongs.

    Attributes:
        uri: The URI the kernel records for the file.
        text: The file's source text.
        kind: "app", "package" or "sdk".
        package: The pub package name for a third-party file, empty otherwise.
        version: The pub package version for a third-party file, empty otherwise.
        rel_path: Where the file is written, relative to the output directory; empty for SDK files, which are not written.
    """
    uri: str
    text: str
    kind: str
    package: str = ""
    version: str = ""
    rel_path: str = ""


@dataclass
class KernelExtraction:
    """
    Purpose:
        What was recovered from one debug build.

    Attributes:
        out_dir: The directory the sources were written under.
        app_files: The app's own files, as paths relative to out_dir.
        package_files: Third-party package files, as paths relative to out_dir.
        packages: Third-party package name to version.
        sdk_files: How many Flutter/Dart SDK files were recognised and skipped.
    """
    out_dir: Path
    app_files: List[str] = field(default_factory=list)
    package_files: List[str] = field(default_factory=list)
    packages: Dict[str, str] = field(default_factory=dict)
    sdk_files: int = 0


def is_debug_build(apk_path) -> bool:
    """
    Purpose:
        Report whether an APK is a debug-mode Flutter build.

    Parameters:
        apk_path: Path to the APK.

    Returns:
        True when the archive carries a kernel snapshot.

    Implementation notes:
        kernel_blob.bin and libapp.so are mutually exclusive in practice: debug builds ship the kernel for the JIT, profile and release builds ship the AOT library. The kernel's presence is therefore the deciding test, and an unreadable archive answers False rather than raising.
    """
    try:
        with zipfile.ZipFile(apk_path) as zf:
            return KERNEL_MEMBER in zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def _read_uint(data: bytes, pos: int) -> Tuple[int, int]:
    """
    Purpose:
        Decode one kernel variable-length unsigned integer.

    Parameters:
        data: The kernel bytes.
        pos: Where the integer starts.

    Returns:
        The value and the number of bytes it occupied.

    Raises:
        IndexError: When the integer runs past the end of the data.

    Implementation notes:
        The kernel format packs a UInt into one byte below 0x80, two bytes when the top bits are 10, and four bytes when they are 11, big-endian with the tag bits masked off.
    """
    first = data[pos]
    if first < 0x80:
        return first, 1
    if first >> 6 == 2:
        return ((first & 0x3F) << 8) | data[pos + 1], 2
    return (((first & 0x3F) << 24) | (data[pos + 1] << 16)
            | (data[pos + 2] << 8) | data[pos + 3]), 4


def _encode_uint(value: int) -> bytes:
    """
    Purpose:
        Encode an integer in the kernel's variable-length format.

    Parameters:
        value: A non-negative integer below 2**30.

    Returns:
        One, two or four bytes.
    """
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    return bytes([0xC0 | ((value >> 24) & 0x3F), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _length_prefixed(data: bytes, start: int, length: int) -> bool:
    """
    Purpose:
        Check that the bytes just before a URI encode that URI's own length.

    Parameters:
        data: The kernel bytes.
        start: Where the URI starts.
        length: The URI's length in bytes.

    Returns:
        True when the kernel encoding of length ends exactly at start.

    Implementation notes:
        This is what separates a source-table entry from the same URI appearing anywhere else in the kernel, such as in an import or a string literal. The prefix is compared as encoded bytes with a constant-time comparison, so no byte of the archive is compared field by field.
    """
    prefix = _encode_uint(length)
    if start < len(prefix):
        return False
    return hmac.compare_digest(data[start - len(prefix):start], prefix)


def parse_kernel_sources(data: bytes) -> List[Tuple[str, str]]:
    """
    Purpose:
        Find every source-table entry in a kernel binary.

    Parameters:
        data: The kernel bytes.

    Returns:
        (uri, source text) pairs in the order they appear, each URI once.

    Complexity:
        O(n) in the kernel size.

    Implementation notes:
        A candidate is accepted only when its URI is length-prefixed, a further length follows it, and that many bytes decode as strict UTF-8 holding no NUL and at least one ; or {, which any real Dart file has. Only file: and org-dartlang- URIs are considered, because those are how the source table names files; a package: URI with the same shape is an import alias whose payload is not source. A kernel_blob.bin can hold several concatenated components and the same file can appear in more than one, so the first occurrence of a URI wins. Entries with empty text, which the kernel writes for files it references but does not embed, are skipped.
    """
    seen = set()
    out: List[Tuple[str, str]] = []
    for match in _URI_RE.finditer(data):
        start, end = match.start(), match.end()
        uri_bytes = match.group()
        if not _length_prefixed(data, start, end - start):
            continue
        uri = uri_bytes.decode("ascii")
        if uri in seen:
            continue
        try:
            length, width = _read_uint(data, end)
        except IndexError:
            continue
        if not length or length > MAX_SOURCE_BYTES:
            continue
        raw = data[end + width:end + width + length]
        if len(raw) < length or raw.count(0) or not (raw.count(b";") or raw.count(b"{")):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        seen.add(uri)
        out.append((uri, text))
    return out


def _safe_parts(path: str) -> List[str]:
    """
    Purpose:
        Reduce a recovered path to components that are safe to create on disk.

    Parameters:
        path: A slash-separated path taken from a kernel URI.

    Returns:
        The cleaned components, with empty, "." and ".." components dropped.

    Security considerations:
        The path is attacker-chosen. Dropping traversal components and replacing every character outside a small safe set is what keeps a crafted URI from naming a location outside the output directory or a device name on Windows.
    """
    parts = []
    for raw in path.split("/"):
        if raw in ("", ".", ".."):
            continue
        cleaned = _SAFE_COMPONENT_RE.sub("_", raw)[:120].lstrip(".") or "_"
        parts.append(cleaned)
    return parts


def classify_uri(uri: str) -> DartSource:
    """
    Purpose:
        Decide whether a recovered file is app code, a third-party package or SDK code, and where it should be written.

    Parameters:
        uri: The URI the kernel recorded.

    Returns:
        A DartSource with every field but the text filled in.

    Implementation notes:
        Pub packages are recognised by their location in the pub cache, which also yields the package's name and version for the dependency inventory. Flutter and Dart SDK files are recognised by the SDK's own directory layout or the org-dartlang-sdk scheme. Other org-dartlang- schemes are the multi-root aliases build tools use for the app itself, so they are classified by path like a file URI. Everything else under a file URI is the app, written relative to its project root, taken as the part of the path before the first lib/ so that lib/main.dart stays lib/main.dart.
    """
    if uri.startswith("org-dartlang-sdk:"):
        return DartSource(uri=uri, text="", kind="sdk")
    path = uri.split(":", 1)[1].lstrip("/")
    path = "/" + path
    pub = _PUB_CACHE_RE.search(path)
    if pub:
        name, version, rest = pub.group(1), pub.group(2), pub.group(3)
        rel = "/".join(_safe_parts(rest))
        return DartSource(uri=uri, text="", kind="package", package=name, version=version,
                          rel_path=f"{PACKAGES_DIR}/{'/'.join(_safe_parts(name))}/{rel}")
    if any(marker in path for marker in _SDK_PATH_MARKERS):
        return DartSource(uri=uri, text="", kind="sdk")
    idx = path.find("/lib/")
    tail = path[idx + 1:] if idx >= 0 else "/".join(path.split("/")[-3:])
    rel = "/".join(_safe_parts(tail))
    return DartSource(uri=uri, text="", kind="app", rel_path=f"{APP_DIR}/{rel}")


def _write_contained(out_dir: Path, rel_path: str, text: str) -> bool:
    """
    Purpose:
        Write one recovered file, refusing anything that would land outside the output directory.

    Parameters:
        out_dir: The output root.
        rel_path: The sanitised relative path.
        text: The file's contents.

    Returns:
        True when the file was written.

    Security considerations:
        The target is resolved and compared against the resolved root before writing, as a second line of defence behind the component sanitising.
    """
    root = out_dir.resolve()
    target = (out_dir / rel_path).resolve()
    if root != target and root not in target.parents:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return True


def extract_kernel_sources(apk_path, out_dir, verbose: bool = False) -> Optional[KernelExtraction]:
    """
    Purpose:
        Recover a debug build's Dart source onto disk.

    Parameters:
        apk_path: Path to the APK.
        out_dir: Directory to write into; created if missing.
        verbose: Traces what was found.

    Returns:
        The extraction summary, or None when the APK has no kernel, the kernel is too large, or no app source could be recovered.

    Side effects:
        Reads the kernel into memory and writes the app and package sources under out_dir.

    Implementation notes:
        A kernel with package sources but no app source still counts as a failure, because the app's own code is what the analysis needs and reporting success without it would send the agent to read only dependencies.
    """
    out_dir = Path(out_dir)
    try:
        with zipfile.ZipFile(apk_path) as zf:
            info = zf.getinfo(KERNEL_MEMBER)
            if info.file_size > MAX_KERNEL_BYTES:
                verbose_print(f"kernel_blob.bin is {info.file_size} bytes, over the limit", verbose)
                return None
            data = zf.read(info)
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        verbose_print(f"No readable kernel_blob.bin: {exc}", verbose)
        return None

    result = KernelExtraction(out_dir=out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for uri, text in parse_kernel_sources(data):
        source = classify_uri(uri)
        if source.kind == "sdk":
            result.sdk_files += 1
            continue
        if not source.rel_path or not _write_contained(out_dir, source.rel_path, text):
            continue
        if source.kind == "app":
            result.app_files.append(source.rel_path)
        else:
            result.package_files.append(source.rel_path)
            if source.package and source.package not in result.packages:
                result.packages[source.package] = source.version

    verbose_print(
        f"Kernel source recovery: {plural(len(result.app_files), 'app file')}, "
        f"{plural(len(result.packages), 'package')} ({plural(len(result.package_files), 'file')}), "
        f"{plural(result.sdk_files, 'SDK file')} skipped", verbose)
    if not result.app_files:
        return None
    return result
