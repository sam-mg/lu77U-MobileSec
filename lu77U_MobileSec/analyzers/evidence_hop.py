#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.evidence_hop

Purpose:
    Find the code one step away from a finding's citation that a claim about it rests on: the method the cited lines sit in, the bodies of the app methods they call, the code using a field or variable they declare, and, for a cited resource value, the code that reads it.

Responsibilities:
    Resolve calls on the cited lines to their definitions in the decompiled Java/Kotlin tree, find the uses of a declared name and the references to a cited res/values entry, and report the claim vocabulary that code contains.

Dependencies:
    The claim-term catalogue.

Implementation notes:
    Models cite where a value is declared or where a helper is called, and the claim names what happens next. A Ghera app's agent reported "Hardcoded AES encryption key and IV" twice: once at the strings.xml entries holding them, once at the call Util.Encrypt.encryptGrade(R.string.secret, R.string.IV, ...). Both were refuted, because neither the resource file nor the call line contains Cipher or IvParameterSpec; the helper's body two files away does. Only one step is taken, and only the vocabulary is recorded, never the code, so the claim gate can see what the cited code reaches without the evidence growing into the whole app.

Known limitations:
    A call is resolved only when it is unqualified (a method of the same file) or qualified by the class's full name, as JADX writes static calls; a call through a variable is not followed. Brace matching ignores braces inside string literals.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence

from ..validation.claim_terms import aliases_present, api_terms, names_present

MAX_CALLEES = 8
MAX_BODY_LINES = 200
MAX_RESOURCE_NAMES = 5
MAX_REFERENCES = 3
MAX_FILES_SCANNED = 3000
REFERENCE_PAD = 3

_CALL_RE = re.compile(r"((?:[A-Za-z_$][\w$]*\.)*)([A-Za-z_$][\w$]*)\s*\(")
_RESOURCE_NAME_RE = re.compile(r'\bname\s*=\s*"([\w.]+)"')
_JAVA_FIELD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|transient|volatile)\s+)*"
    r"(?!(?:return|throw|new|else|case)\b)[\w.$<>\[\]]+\s+([A-Za-z_$][\w$]*)\s*=[^=]")
_KOTLIN_FIELD_RE = re.compile(
    r"^\s*(?:(?:private|public|internal|protected|const|override|lateinit)\s+)*(?:val|var)\s+([A-Za-z_]\w*)\s*(?::[^=]+)?=")
_NOT_CALLS = frozenset(("if", "for", "while", "switch", "catch", "synchronized", "return", "new",
                        "super", "this", "throw", "assert", "when", "try"))
_SELF = frozenset(("", "this", "super"))
_SOURCE_SUFFIXES = (".java", ".kt")
_LIBRARY_DIRS = frozenset(("android", "androidx", "kotlin", "kotlinx", "java", "javax", "dalvik"))


_ANY_NAME = r"[A-Za-z_$][\w$]*"
MAX_ENCLOSING_SEARCH = 400


def _definition_re(name: str) -> re.Pattern:
    """
    Purpose:
        Build the pattern that matches the line defining a method of the given name, in JADX's Java or in Kotlin.

    Parameters:
        name: The method name, or _ANY_NAME for any.

    Returns:
        The compiled pattern.

    Implementation notes:
        A statement such as "return foo(x);" has the same shape as a typed signature, so return, throw, new, else and case are refused in the type position, and the caller also refuses a line ending in a semicolon.
    """
    n = name if name == _ANY_NAME else re.escape(name)
    modifiers = r"(?:(?:public|private|protected|internal|static|final|synchronized|abstract|native|override|open|suspend|inline)\s+)*"
    return re.compile(
        rf"^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*{modifiers}"
        rf"(?:fun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?{n}\s*\(|(?!(?:return|throw|new|else|case)\b)[\w.$<>\[\]?, ]+?\s+{n}\s*\()")


def _body_end(lines: Sequence[str], index: int) -> Optional[int]:
    """
    Purpose:
        Find the closing line of the definition that starts at a line.

    Parameters:
        lines: The file's lines.
        index: The definition's first line, 0-based.

    Returns:
        The 0-based index of the line that closes the body, or None when the definition has no body within three lines.
    """
    opened = next((i for i in range(index, min(index + 3, len(lines))) if "{" in lines[i]), None)
    if opened is None:
        return None
    depth = 0
    for i in range(opened, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0:
            return i
    return len(lines) - 1


def enclosing_body(lines: Sequence[str], start: int) -> List[str]:
    """
    Purpose:
        Return the method that contains a cited line.

    Parameters:
        lines: The file's lines.
        start: The cited line, 1-based.

    Returns:
        The method's lines, cut to MAX_BODY_LINES around the citation; empty when the line is in no method.

    Implementation notes:
        A finding cited "keyStore.store(fos, null)" as an AES key stored without a password; the KeyGenerator.getInstance("AES") that made the key sat twelve lines up in the same method, outside the context window, and the finding was refuted. The nearest definition above the line whose body spans it is the enclosing method; a nested anonymous class's method is found first, which is the narrower scope.
    """
    pattern = _definition_re(_ANY_NAME)
    cited = start - 1
    for index in range(min(cited, len(lines) - 1), max(-1, cited - MAX_ENCLOSING_SEARCH), -1):
        line = lines[index]
        if not pattern.match(line) or line.rstrip().endswith(";"):
            continue
        end = _body_end(lines, index)
        if end is not None and end >= cited:
            low = max(index, cited - MAX_BODY_LINES // 2)
            return list(lines[low:min(end + 1, low + MAX_BODY_LINES)])
    return []


def method_body(lines: Sequence[str], name: str) -> List[str]:
    """
    Purpose:
        Return the bodies of every method of the given name defined in a file.

    Parameters:
        lines: The file's lines.
        name: The method name.

    Returns:
        The lines of each definition, from its signature to its closing brace, concatenated; empty when there is none.

    Implementation notes:
        Overloads are all returned, since which one a call reaches is not decided here. A declaration with no body within three lines (abstract, interface, native) contributes nothing. Each body is cut at MAX_BODY_LINES.
    """
    pattern = _definition_re(name)
    out: List[str] = []
    for index, line in enumerate(lines):
        if not pattern.match(line) or line.rstrip().endswith(";"):
            continue
        opened = next((i for i in range(index, min(index + 3, len(lines))) if "{" in lines[i]), None)
        if opened is None:
            continue
        depth = 0
        for i in range(index, min(len(lines), index + MAX_BODY_LINES)):
            out.append(lines[i])
            if i >= opened:
                depth += lines[i].count("{") - lines[i].count("}")
                if depth <= 0:
                    break
    return out


def _class_file(source_root: Path, parts: Sequence[str]) -> Optional[Path]:
    """
    Purpose:
        Find the source file of a fully qualified class.

    Parameters:
        source_root: Root of the decompiled tree.
        parts: The dotted name's parts, possibly ending in nested class names.

    Returns:
        The file, or None.

    Implementation notes:
        Prefixes are tried longest first, so edu.x.Util.Encrypt resolves to Util/Encrypt.java when Util is a package and to Util.java when Encrypt is a nested class. Both the tree root and its sources directory are tried, since JADX writes sources/ under the output directory the analyzers pass as the root.
    """
    for k in range(len(parts), 0, -1):
        rel = Path(*parts[:k])
        for base in (source_root / "sources", source_root):
            for suffix in _SOURCE_SUFFIXES:
                candidate = base / rel.with_suffix(suffix)
                if candidate.is_file():
                    return candidate
    return None


def _read_lines(path: Path, cache: Dict[Path, List[str]]) -> List[str]:
    """
    Purpose:
        Read a source file's lines once per evidence lookup.

    Parameters:
        path: The file.
        cache: Lines already read, keyed by path.

    Returns:
        The lines, or an empty list when the file cannot be read.
    """
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            cache[path] = []
    return cache[path]


def callee_bodies(source_root: Path, source_path: Path, source_lines: Sequence[str], cited: Sequence[str],
                  cache: Optional[Dict[Path, List[str]]] = None) -> List[str]:
    """
    Purpose:
        Collect the bodies of the app methods the cited lines call.

    Parameters:
        source_root: Root of the decompiled tree.
        source_path: The cited file.
        source_lines: The cited file's lines.
        cited: The cited lines.
        cache: Lines already read, keyed by path.

    Returns:
        The callee bodies' lines, concatenated; empty when nothing resolves.
    """
    cache = {} if cache is None else cache
    cache.setdefault(source_path, list(source_lines))
    out: List[str] = []
    seen = set()
    for line in cited:
        for match in _CALL_RE.finditer(line):
            qualifier, name = match.group(1).rstrip("."), match.group(2)
            if name in _NOT_CALLS or (qualifier, name) in seen or len(seen) >= MAX_CALLEES:
                continue
            seen.add((qualifier, name))
            if qualifier in _SELF:
                target: Optional[Path] = source_path
            elif qualifier.split(".")[0] in _LIBRARY_DIRS:
                continue
            else:
                target = _class_file(source_root, qualifier.split("."))
            if target is not None:
                out.extend(method_body(_read_lines(target, cache), name))
    return out


def _app_sources(source_root: Path) -> Iterator[Path]:
    """
    Purpose:
        Walk the decompiled app's source files, skipping platform libraries and generated R classes.

    Parameters:
        source_root: Root of the decompiled tree.

    Returns:
        An iterator over at most MAX_FILES_SCANNED files.
    """
    base = source_root / "sources" if (source_root / "sources").is_dir() else source_root
    count = 0
    for path in sorted(base.rglob("*")):
        if path.suffix not in _SOURCE_SUFFIXES or path.stem == "R" or not path.is_file():
            continue
        rel = path.relative_to(base).parts
        if rel and rel[0] in _LIBRARY_DIRS:
            continue
        count += 1
        if count > MAX_FILES_SCANNED:
            return
        yield path


def resource_usages(source_root: Path, cited: Sequence[str],
                    cache: Optional[Dict[Path, List[str]]] = None) -> List[str]:
    """
    Purpose:
        Collect the code that reads the resource values a citation of res/values declares.

    Parameters:
        source_root: Root of the decompiled tree.
        cited: The cited lines of the resource file.
        cache: Lines already read, keyed by path.

    Returns:
        The lines around each reference to R.<type>.<name>, with the bodies of the methods those lines call; empty when nothing reads them.

    Implementation notes:
        Only the first MAX_RESOURCE_NAMES names and MAX_REFERENCES references to each are followed, so a citation spanning a whole strings.xml stays cheap.
    """
    cache = {} if cache is None else cache
    names = []
    for line in cited:
        names.extend(n for n in _RESOURCE_NAME_RE.findall(line) if n not in names)
    names = names[:MAX_RESOURCE_NAMES]
    if not names:
        return []
    patterns = {n: re.compile(rf"\bR\.\w+\.{re.escape(n)}\b") for n in names}
    found = {n: 0 for n in names}
    out: List[str] = []
    for path in _app_sources(source_root):
        if all(count >= MAX_REFERENCES for count in found.values()):
            break
        lines = _read_lines(path, cache)
        for index, line in enumerate(lines):
            for name, pattern in patterns.items():
                if found[name] >= MAX_REFERENCES or not pattern.search(line):
                    continue
                found[name] += 1
                out.extend(lines[max(0, index - REFERENCE_PAD):index + REFERENCE_PAD + 1])
                out.extend(callee_bodies(source_root, path, lines, [line], cache))
    return out


def field_usages(source_root: Path, source_path: Path, source_lines: Sequence[str], cited: Sequence[str],
                 cache: Optional[Dict[Path, List[str]]] = None) -> List[str]:
    """
    Purpose:
        Collect the code that uses the fields or variables the cited lines declare.

    Parameters:
        source_root: Root of the decompiled tree.
        source_path: The cited file.
        source_lines: The cited file's lines.
        cited: The cited lines.
        cache: Lines already read, keyed by path.

    Returns:
        The lines around each use - in the cited file by bare name, elsewhere as ClassName.NAME - with the bodies of the methods those lines call; empty when nothing declared is used.

    Implementation notes:
        A model cites a key where it is declared, "static final byte[] SECRET_KEY = ...", while the SecretKeySpec that makes it an AES key is twenty lines further down, and a Ghera finding was refuted for it. Only the first MAX_REFERENCES uses of each of the first MAX_RESOURCE_NAMES names are followed.
    """
    cache = {} if cache is None else cache
    names: List[str] = []
    for line in cited:
        match = _JAVA_FIELD_RE.match(line) or _KOTLIN_FIELD_RE.match(line)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    names = names[:MAX_RESOURCE_NAMES]
    if not names:
        return []
    cited_set = set(cited)
    out: List[str] = []
    for name in names:
        local = re.compile(rf"(?<![\w$.]){re.escape(name)}\b")
        remote = re.compile(rf"\b{re.escape(source_path.stem)}\.{re.escape(name)}\b")
        uses = 0
        others = ((other, remote) for other in _app_sources(source_root) if other != source_path)
        for path, pattern in itertools.chain([(source_path, local)], others):
            lines = list(source_lines) if path == source_path else _read_lines(path, cache)
            for index, line in enumerate(lines):
                if uses >= MAX_REFERENCES:
                    break
                if line in cited_set and path == source_path:
                    continue
                if pattern.search(line) or (path == source_path and remote.search(line)):
                    uses += 1
                    out.extend(lines[max(0, index - REFERENCE_PAD):index + REFERENCE_PAD + 1])
                    out.extend(callee_bodies(source_root, path, lines, [line], cache))
            if uses >= MAX_REFERENCES:
                break
    return out


def hop_terms(source_root: Path, source_path: Path, source_lines: Sequence[str], start: int, end: int,
              finding: Dict) -> List[str]:
    """
    Purpose:
        Report the claim vocabulary in the code one step from a finding's citation.

    Parameters:
        source_root: Root of the decompiled tree.
        source_path: The cited file.
        source_lines: The cited file's lines.
        start: First cited line, 1-based.
        end: Last cited line, 1-based.
        finding: The finding, whose title supplies the API names worth looking for.

    Returns:
        The claim-table aliases, and the APIs the title names, that the reached code contains; empty when nothing is reached.
    """
    cited = list(source_lines[max(0, start - 1):max(start, end)])
    if source_path.suffix == ".xml" and source_path.parent.name.startswith("values"):
        reached = resource_usages(Path(source_root), cited)
    elif source_path.suffix in _SOURCE_SUFFIXES:
        reached = (enclosing_body(source_lines, start)
                   + callee_bodies(Path(source_root), source_path, source_lines, cited)
                   + field_usages(Path(source_root), source_path, source_lines, cited))
    else:
        return []
    if not reached:
        return []
    text = "\n".join(reached)
    names = api_terms(f"{finding.get('title', '')} {finding.get('vulnerability_type', '')}")
    return aliases_present(text) + names_present(text, names)
