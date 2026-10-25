#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.dart_snapshot

Purpose:
    Recover what a Flutter release build's Dart snapshot gives up without a disassembler: the strings libapp.so carries.

Responsibilities:
    Pick the architecture slice that holds libapp.so, extract its printable strings, keep the ones a security reviewer needs, and write both lists into the analysis root.

Dependencies:
    The shared secret and endpoint patterns.

Implementation notes:
    Blutter disassembles arm64-v8a only, and only for Dart versions it can build. An APK pulled from an x86_64 emulator carries just the x86_64 slice, and a new Dart release can outrun Blutter, so a release build sometimes cannot be disassembled at all. A general disassembler is no substitute: libapp.so exports five symbols, two of them instruction blobs with no function boundaries, and Dart's calling convention reaches every constant through the object-pool register, so Ghidra or objdump output for it names nothing a reader can tie to a screen. The isolate snapshot keeps its strings as plain bytes, though, and those carry what most findings about a Flutter app rest on: endpoints, keys, SQL, channel names, the app's own package. Those are recovered here so the analysis degrades to strings instead of stopping.

Security considerations:
    The strings are the app's own content and are written beside the other recovered artifacts, inside the analysis root the agent is sandboxed to.
"""

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..analyzers.agent.patterns import API_ENDPOINT_RE, classify_secret
from ..utils.verbose import plural, verbose_print

SNAPSHOT_DIR = "snapshot_strings"
ALL_STRINGS_NAME = "libapp_strings.txt"
KEY_STRINGS_NAME = "libapp_key_strings.txt"
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
MIN_STRING_LENGTH = 6
MAX_STRING_CHARS = 400
MAX_STRINGS = 200000
MAX_KEY_STRINGS = 2000

_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH)

_FRAMEWORK_PREFIXES = (
    "dart:", "package:", "flutter/", "dev.flutter/", "UIKeyInput",
    "PlatformConfigurationNativeApi::", "vm:", "Internal_", "impl.",
)

_FRAMEWORK_HOSTS = ("flutter.dev", "dart.dev", "pub.dev", "github.com/flutter",
                    "goo.gl", "material.io", "unicode.org", "w3.org", "dartlang.org")

_DART_PRIVATE_NAME_RE = re.compile(r"@\d{3,}")

_FRAMEWORK_FRAGMENTS = ("dev.flutter/", "NoSuchMethodError", "brieflyShowPassword")

_KEYBOARD_KEY_RE = re.compile(r"^(PinP|Key|Numpad|GameButton|Launch|Media)[A-Z0-9]")

_SQL_RE = re.compile(
    r"(?i)\b(select\s.+\sfrom\s|insert\s+into\s|update\s+\w+\s+set\s|delete\s+from\s|"
    r"create\s+table\s|drop\s+table\s)")

CHANNEL_RE = re.compile(r"^[a-z][\w-]*(?:\.[\w-]+)+/[\w./-]+$")

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_DIGEST_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_REPEATED_RUN_RE = re.compile(r"(.)\1{5}")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_NATIVE_LIB_RE = re.compile(r"\blib[\w.-]+\.so\b")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_SENSITIVE_WORDS = frozenset((
    "password", "passwd", "passcode", "secret", "token", "apikey", "bearer",
    "authorization", "credential", "credentials", "private", "admin", "premium", "vip",
    "unlock", "license", "otp", "pin", "flag", "jailbreak", "rooted", "frida",
    "emulator", "tamper",
))


@dataclass
class SnapshotStrings:
    """
    Purpose:
        What was recovered from one libapp.so.

    Attributes:
        abi: The architecture slice the library came from.
        all_path: The file listing every string, one per line.
        key_path: The file listing only the strings worth reading, one per line.
        total: How many distinct strings were found.
        key: How many of them were kept as key strings.
    """
    abi: str
    all_path: Path
    key_path: Path
    total: int
    key: int


def libapp_abi(apk_path: str) -> Optional[str]:
    """
    Purpose:
        Choose the architecture slice whose libapp.so to read.

    Parameters:
        apk_path: Path to the APK.

    Returns:
        The first ABI in ABI_ORDER that carries a libapp.so, or None when no slice does.

    Implementation notes:
        Every slice holds the same Dart program compiled for a different CPU, and the strings are identical across them, so any slice will do; arm64 is preferred only because it is the one a real device most often ships.
    """
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return None
    return next((abi for abi in ABI_ORDER if f"lib/{abi}/libapp.so" in names), None)


def snapshot_strings(data: bytes) -> List[str]:
    """
    Purpose:
        List the distinct printable strings in a binary, in the order they first appear.

    Parameters:
        data: The binary's bytes.

    Returns:
        The strings, each cut to MAX_STRING_CHARS, at most MAX_STRINGS of them.

    Implementation notes:
        Only printable ASCII runs are taken. A Dart one-byte string is stored as plain Latin-1 bytes, which covers URLs, keys, SQL and identifiers; a two-byte string is user-facing text in another script, which carries no secret worth the noise. First-appearance order is kept because the snapshot lays a library's strings out together, so neighbouring lines tend to belong to the same code.
    """
    seen = set()
    out: List[str] = []
    for match in _PRINTABLE_RUN_RE.finditer(data):
        text = match.group().decode("ascii")[:MAX_STRING_CHARS].strip()
        if len(text) < MIN_STRING_LENGTH or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= MAX_STRINGS:
            break
    return out


def _words(text: str) -> List[str]:
    """
    Purpose:
        Split a string into lowercase words, breaking identifiers at camel case and separators.

    Parameters:
        text: The string.

    Returns:
        The words.
    """
    return [w for w in re.split(r"[^a-z0-9]+", _CAMEL_RE.sub(" ", text).lower()) if w]


def is_key_string(text: str, package: str = "") -> bool:
    """
    Purpose:
        Decide whether a snapshot string is worth a reviewer's attention.

    Parameters:
        text: The string.
        package: The app's package name, whose appearance marks the app's own identifiers.

    Returns:
        True for credentials, endpoints, SQL, channel names, native libraries and strings naming something security-sensitive; False for framework vocabulary.

    Implementation notes:
        The snapshot is mostly the Flutter framework and the Dart core libraries: key names, error messages, private member names tagged with a library hash ("_foo@1234567"). Those are dropped first, along with the engine's keyboard key names ("PinPToggle") and a few framework identifiers, so a sensitive word inside one ("_checkLoaded", "UIKeyInputF10") cannot keep it. Package URIs are file names rather than data and are dropped too. A hex string is kept only at a digest's length (MD5, SHA-1, SHA-256) and without a long repeated run: crypto packages ship elliptic-curve constants by the dozen, and their runs of "ffffffff" are what set them apart from a hash the app compares against. Crypto vocabulary (cipher, aes, hmac) is left out of the word list for the same reason - it matched every class name in pointycastle and nothing the app wrote. A whole-word match on the remaining vocabulary, split at camel case, keeps "adminPin" and "api_token" without keeping "pinned" or "tokenizer".
    """
    if (text.startswith(_FRAMEWORK_PREFIXES) or _DART_PRIVATE_NAME_RE.search(text)
            or _KEYBOARD_KEY_RE.match(text)
            or any(fragment in text for fragment in _FRAMEWORK_FRAGMENTS)):
        return False
    if package and package in text:
        return True
    if classify_secret(text) is not None:
        return True
    endpoint = API_ENDPOINT_RE.search(text)
    if endpoint and not any(host in endpoint.group() for host in _FRAMEWORK_HOSTS):
        return True
    if (_SQL_RE.search(text) or CHANNEL_RE.match(text) or _JWT_RE.search(text)
            or _EMAIL_RE.search(text) or _NATIVE_LIB_RE.search(text)):
        return True
    if _DIGEST_HEX_RE.match(text):
        return not _REPEATED_RUN_RE.search(text)
    return bool(_SENSITIVE_WORDS.intersection(_words(text)))


def write_snapshot_strings(apk_path: str, out_root, package: str = "",
                           verbose: bool = False) -> Optional[SnapshotStrings]:
    """
    Purpose:
        Recover libapp.so's strings into the analysis root.

    Parameters:
        apk_path: Path to the APK.
        out_root: The analysis root; the lists are written under SNAPSHOT_DIR inside it.
        package: The app's package name, used to keep the app's own identifiers.
        verbose: Traces what was recovered.

    Returns:
        What was written, or None when the APK has no libapp.so or nothing could be read from it.

    Side effects:
        Reads the library out of the archive and writes two text files.

    Implementation notes:
        The library is read straight from the archive rather than extracted first, since only its bytes are needed. The key list is what the overview quotes and the file review reads; the full list stays searchable for anything the filter dropped.
    """
    abi = libapp_abi(apk_path)
    if abi is None:
        verbose_print("No libapp.so in any architecture slice of this APK", verbose)
        return None
    try:
        with zipfile.ZipFile(apk_path) as zf:
            data = zf.read(f"lib/{abi}/libapp.so")
    except (zipfile.BadZipFile, KeyError, FileNotFoundError, OSError) as exc:
        verbose_print(f"Could not read libapp.so ({abi}) from the APK: {exc}", verbose)
        return None
    strings = snapshot_strings(data)
    if not strings:
        verbose_print(f"No strings could be read from libapp.so ({abi})", verbose)
        return None
    key = [s for s in strings if is_key_string(s, package)][:MAX_KEY_STRINGS]
    target = Path(out_root) / SNAPSHOT_DIR
    try:
        target.mkdir(parents=True, exist_ok=True)
        all_path = target / ALL_STRINGS_NAME
        key_path = target / KEY_STRINGS_NAME
        all_path.write_text("\n".join(strings) + "\n", encoding="utf-8")
        key_path.write_text("\n".join(key) + "\n" if key else "", encoding="utf-8")
    except OSError as exc:
        verbose_print(f"Could not write the libapp.so strings: {exc}", verbose)
        return None
    verbose_print(f"Recovered {plural(len(strings), 'string')} from libapp.so ({abi}), "
                  f"{len(key)} kept as key strings", verbose)
    return SnapshotStrings(abi=abi, all_path=all_path, key_path=key_path,
                           total=len(strings), key=len(key))
