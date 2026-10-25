#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.decompiler.ghidra_runner

Purpose:
    Decompile an Android native library to C with headless Ghidra, so the agent can read the logic behind a JNI method instead of only its symbol table.

Responsibilities:
    Resolve the configured launcher, run analyzeHeadless with the bundled export script, parse its JSON, annotate JNI function-table calls with their names, and cache the result per library.

Dependencies:
    subprocess, tempfile, threading, ..tools_checker.ghidra_checker, the ExportNativeDecompilation.java post-script shipped in ghidra_scripts/.

Implementation notes:
    Ghidra runs on demand, the first time the agent inspects a library, rather than eagerly after JADX: most libraries in an app are third-party runtimes nobody needs decompiled, and a large one costs minutes. Results, including failures, are cached in-process by content hash, so several regions inspecting the same library pay once and a library that timed out is not retried for every region. Runs are serialised because each one is a JVM taking a gigabyte or more. The export is a Java GhidraScript rather than a Python one because Java scripts run in every Ghidra install with no extra package, while Python needs PyGhidra set up beside it.

Security considerations:
    The library comes from an untrusted APK. It is copied into a fresh temporary directory under a sanitised name before Ghidra sees it, so nothing taken from the archive reaches the command line, and the launcher is invoked as an argument vector with no shell. On Windows the launcher is a batch file, which is exactly why no APK-derived string may appear among its arguments. Ghidra parses the file in its own process; a parser bug there is contained to that process and its timeout.
"""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from ..tools_checker.ghidra_checker import resolve_analyze_headless
from ..utils.verbose import verbose_print

SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra_scripts"
SCRIPT_NAME = "ExportNativeDecompilation.java"

ANALYSIS_TIMEOUT = 240
DECOMPILE_BUDGET = 240
PER_FUNCTION_TIMEOUT = 30
MAX_FUNCTIONS = 4000
PROCESS_TIMEOUT = 720
MAX_LIBRARY_BYTES = 64 * 1024 * 1024

RUNTIME_LIBRARIES = frozenset((
    "libflutter.so", "libapp.so", "libhermes.so", "libhermes-executor-release.so",
    "libjsc.so", "libreactnativejni.so", "libjsi.so", "libfbjni.so", "libc++_shared.so",
    "libmonosgen-2.0.so", "libmonodroid.so", "libxamarin-app.so", "libunity.so",
    "libUE4.so", "libmain.so",
))

_VALUE_TYPES = ("Object", "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double")
_PRIMITIVE_TYPES = _VALUE_TYPES[1:]

def _call_family(prefix: str) -> List[str]:
    """
    Purpose:
        Expand one of the JNI Call...Method families into its thirty table entries.

    Parameters:
        prefix: "Call", "CallNonvirtual" or "CallStatic".

    Returns:
        The entry names in table order.

    Implementation notes:
        Each return type has a varargs, a va_list and a jvalue-array form, in that order, and the types run Object through Double and then Void, which is the order jni.h declares them in.
    """
    out: List[str] = []
    for kind in _VALUE_TYPES + ("Void",):
        out += [f"{prefix}{kind}Method", f"{prefix}{kind}MethodV", f"{prefix}{kind}MethodA"]
    return out

def _build_jni_env_table() -> Tuple[str, ...]:
    """
    Purpose:
        Build the JNINativeInterface function table, indexed as the struct lays it out.

    Returns:
        The 233 entry names, index 0 first.

    Implementation notes:
        Generated from the families rather than listed literally so that an off-by-one in a 233-line literal cannot silently shift every name after it. Tests pin known offsets such as GetStringUTFChars at 169 and RegisterNatives at 215 to keep the generation honest.
    """
    table = [
        "reserved0", "reserved1", "reserved2", "reserved3",
        "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod",
        "FromReflectedField", "ToReflectedMethod", "GetSuperclass",
        "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew",
        "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError",
        "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef",
        "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity",
        "AllocObject", "NewObject", "NewObjectV", "NewObjectA",
        "GetObjectClass", "IsInstanceOf", "GetMethodID",
    ]
    table += _call_family("Call")
    table += _call_family("CallNonvirtual")
    table += ["GetFieldID"] + [f"Get{t}Field" for t in _VALUE_TYPES] + [f"Set{t}Field" for t in _VALUE_TYPES]
    table += ["GetStaticMethodID"] + _call_family("CallStatic")
    table += (["GetStaticFieldID"] + [f"GetStatic{t}Field" for t in _VALUE_TYPES]
              + [f"SetStatic{t}Field" for t in _VALUE_TYPES])
    table += [
        "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars",
        "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars",
        "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
    ]
    for pattern in ("New{}Array", "Get{}ArrayElements", "Release{}ArrayElements",
                    "Get{}ArrayRegion", "Set{}ArrayRegion"):
        table += [pattern.format(t) for t in _PRIMITIVE_TYPES]
    table += [
        "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM",
        "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical",
        "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical",
        "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer",
        "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType",
    ]
    return tuple(table)

JNI_ENV_TABLE = _build_jni_env_table()

JAVA_VM_TABLE = (
    "reserved0", "reserved1", "reserved2", "DestroyJavaVM", "AttachCurrentThread",
    "DetachCurrentThread", "GetEnv", "AttachCurrentThreadAsDaemon",
)

_TABLE_CALL_RE = re.compile(r"\(\*([A-Za-z_]\w*) \+ 0x([0-9a-fA-F]+)\)")
_SIGNATURE_RE = re.compile(r"\(([^()]*)\)\s*\{", re.S)
_IDENTIFIER_RE = re.compile(r"([A-Za-z_]\w*)\s*$")

@dataclass
class NativeFunction:
    """
    Purpose:
        One decompiled function of a native library.

    Attributes:
        name: The symbol name, or Ghidra's FUN_<address> placeholder for a stripped one.
        entry: The entry address as Ghidra prints it.
        size: The number of bytes in the function body.
        calls: The external (imported) functions it calls, sorted.
        code: The decompiled C, annotated with JNI table names; empty when decompilation failed.
    """
    name: str
    entry: str
    size: int
    calls: List[str]
    code: str

@dataclass
class NativeDecompilation:
    """
    Purpose:
        The decompiled view of one native library, or the reason there is none.

    Attributes:
        language: Ghidra's language id, such as AARCH64:LE:64:v8A.
        pointer_size: The target's pointer width in bytes.
        functions: The decompiled functions, in address order.
        function_count: How many functions the library defines, including any not decompiled.
        truncated: True when the function cap or the time budget stopped decompilation early.
        error: Why decompilation did not happen; empty on success.

    Invariants:
        Exactly one of functions and error carries the outcome: a failed run has an error and no functions.
    """
    language: str = ""
    pointer_size: int = 0
    functions: List[NativeFunction] = field(default_factory=list)
    function_count: int = 0
    truncated: bool = False
    error: str = ""

_cache: Dict[str, NativeDecompilation] = {}
_run_lock = threading.Lock()

def _parameter_names(code: str) -> List[str]:
    """
    Purpose:
        Read the parameter names off a decompiled function's signature.

    Parameters:
        code: The decompiled C of one function.

    Returns:
        The names in order; empty for a void parameter list or an unparseable signature.
    """
    match = _SIGNATURE_RE.search(code)
    if not match:
        return []
    names = []
    for part in match.group(1).split(","):
        found = _IDENTIFIER_RE.search(part.strip())
        if found and found.group(1) != "void":
            names.append(found.group(1))
    return names

def annotate_jni_calls(name: str, code: str, pointer_size: int) -> str:
    """
    Purpose:
        Label each call through the JNIEnv or JavaVM function table with the JNI function it reaches.

    Parameters:
        name: The function's name, which decides what its first parameter is.
        code: The decompiled C.
        pointer_size: The target's pointer width, which turns a table offset into an index.

    Returns:
        The code with a trailing comment naming the JNI function on each line that calls one.

    Implementation notes:
        Ghidra knows nothing of jni.h, so a JNI call reads as an indirect call through an offset, like (*param_1 + 0x548). That is GetStringUTFChars, and naming it is what lets the agent see that a Java string flows into the call on the next line. Labelling is restricted to bases known to be JNI pointers: the first parameter of a Java_ export, which the JNI calling convention makes the JNIEnv; the first parameter of JNI_OnLoad, which is the JavaVM; and a variable whose address JNI_OnLoad passes to GetEnv or AttachCurrentThread, which receives a JNIEnv. Any other base is left alone, because a C++ virtual call has exactly the same shape and labelling it as JNI would mislead.
    """
    if pointer_size <= 0 or not code:
        return code
    params = _parameter_names(code)
    env_names = set()
    vm_names = set()
    if name.startswith("Java_") and params:
        env_names.add(params[0])
    if name == "JNI_OnLoad" and params:
        vm = params[0]
        vm_names.add(vm)
        get_env = re.compile(
            r"\(\*" + re.escape(vm) + r" \+ 0x([0-9a-fA-F]+)\)\)\s*\(\s*" + re.escape(vm)
            + r"\s*,\s*\(?[^,]*?&([A-Za-z_]\w*)")
        for offset, var in get_env.findall(code):
            index = int(offset, 16) // pointer_size
            if index < len(JAVA_VM_TABLE) and JAVA_VM_TABLE[index] in (
                    "GetEnv", "AttachCurrentThread", "AttachCurrentThreadAsDaemon"):
                env_names.add(var)
    if not env_names and not vm_names:
        return code

    out = []
    for line in code.split("\n"):
        labels = []
        for base, offset in _TABLE_CALL_RE.findall(line):
            value = int(offset, 16)
            if value % pointer_size:
                continue
            index = value // pointer_size
            label = ""
            if base in env_names and index < len(JNI_ENV_TABLE):
                label = f"JNIEnv->{JNI_ENV_TABLE[index]}"
            elif base in vm_names and index < len(JAVA_VM_TABLE):
                label = f"JavaVM->{JAVA_VM_TABLE[index]}"
            if label and label not in labels:
                labels.append(label)
        if labels:
            line = f"{line}  /* {', '.join(labels)} */"
        out.append(line)
    return "\n".join(out)

def parse_export(document: dict) -> NativeDecompilation:
    """
    Purpose:
        Turn the export script's JSON into a NativeDecompilation, annotating JNI calls on the way.

    Parameters:
        document: The parsed JSON the export script wrote.

    Returns:
        The decompilation.

    Implementation notes:
        Every field is read defensively and coerced, because the document comes from a separate process that may have been cut off by its budget, and a malformed entry should cost that entry rather than the library.
    """
    pointer_size = int(document.get("pointer_size") or 0)
    functions = []
    for raw in document.get("functions") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        code = str(raw.get("c") or "")
        functions.append(NativeFunction(
            name=name,
            entry=str(raw.get("entry") or ""),
            size=int(raw.get("size") or 0),
            calls=sorted(str(c) for c in (raw.get("calls") or [])),
            code=annotate_jni_calls(name, code.strip("\n"), pointer_size),
        ))
    return NativeDecompilation(
        language=str(document.get("language") or ""),
        pointer_size=pointer_size,
        functions=functions,
        function_count=int(document.get("function_count") or len(functions)),
        truncated=bool(document.get("truncated")),
    )

def _safe_name(name: str) -> str:
    """
    Purpose:
        Reduce a library file name to characters that are inert on any command line.

    Parameters:
        name: The file name from the APK.

    Returns:
        The sanitised name, always ending in .so.

    Security considerations:
        The name is attacker-chosen. Stripping it to letters, digits, dot, dash and underscore is what keeps it from being interpreted by cmd.exe when the launcher is a batch file.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80].lstrip(".-") or "library"
    return cleaned if cleaned.endswith(".so") else cleaned + ".so"

def _run(cmd: List[str], timeout: int) -> Tuple[int, str]:
    """
    Purpose:
        Run the launcher, killing its whole process tree if it overruns.

    Parameters:
        cmd: The argument vector.
        timeout: Seconds to allow.

    Returns:
        The exit status and the combined output; status -1 on timeout.

    Raises:
        OSError: When the launcher cannot be started.

    Implementation notes:
        analyzeHeadless is a shell script that starts Java as a child rather than exec-ing it, so killing the script on timeout would leave the JVM running. The launcher is therefore started in its own session and the whole group is killed. Windows has no process groups in this sense, so there only the direct child is killed. Standard input is closed because Ghidra's launcher prompts for a JDK path when it finds none, and a prompt would otherwise hang the scan until the timeout.
    """
    kwargs = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                  stderr=subprocess.STDOUT, text=True, errors="replace")
    if os.name != "nt":
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **kwargs)
    try:
        output, _ = proc.communicate(timeout=timeout)
        return proc.returncode, output or ""
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
        else:
            proc.kill()
        proc.communicate()
        return -1, ""

def _decompile_uncached(library: Path, launcher: Path, verbose: bool) -> NativeDecompilation:
    """
    Purpose:
        Run Ghidra once over one library and parse what it exported.

    Parameters:
        library: The native library.
        launcher: The analyzeHeadless launcher.
        verbose: Traces the command and the outcome.

    Returns:
        The decompilation, or one carrying the error.

    Side effects:
        Creates and removes a temporary directory holding a copy of the library and a throwaway Ghidra project, and spawns Ghidra.

    Implementation notes:
        Success is judged by the JSON the script wrote, not by the exit status: Ghidra can exit non-zero over an unrelated warning after the export finished, and can exit zero having never run the script. The project is deleted by Ghidra itself and the directory removed afterwards regardless, so repeated scans leave nothing behind.
    """
    work = Path(tempfile.mkdtemp(prefix="lu77u-ghidra-"))
    try:
        target = work / "input" / _safe_name(library.name)
        target.parent.mkdir()
        shutil.copyfile(library, target)
        project = work / "project"
        project.mkdir()
        out_json = work / "export.json"
        cmd = [
            str(launcher), str(project), "lu77u",
            "-import", str(target),
            "-deleteProject",
            "-analysisTimeoutPerFile", str(ANALYSIS_TIMEOUT),
            "-scriptPath", str(SCRIPT_DIR),
            "-postScript", SCRIPT_NAME, str(out_json),
            str(MAX_FUNCTIONS), str(PER_FUNCTION_TIMEOUT), str(DECOMPILE_BUDGET),
        ]
        verbose_print(f"Ghidra: decompiling {library.name}", verbose)
        try:
            status, output = _run(cmd, PROCESS_TIMEOUT)
        except OSError as exc:
            return NativeDecompilation(error=f"Ghidra could not be started: {exc}")
        if status == -1:
            return NativeDecompilation(error=f"Ghidra timed out after {PROCESS_TIMEOUT}s")
        if not out_json.is_file():
            tail = " ".join(output.strip().splitlines()[-3:])[:300]
            verbose_print(f"Ghidra produced no export (status {status}): {tail}", verbose)
            return NativeDecompilation(
                error=f"Ghidra exited with status {status} without exporting any functions")
        try:
            document = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            return NativeDecompilation(error=f"Ghidra's export could not be parsed: {exc}")
        result = parse_export(document)
        verbose_print(
            f"Ghidra: {len(result.functions)} of {result.function_count} functions decompiled "
            f"from {library.name}", verbose)
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)

def decompile_native_library(library, verbose: bool = False) -> NativeDecompilation:
    """
    Purpose:
        Return the decompiled view of a native library, running Ghidra on first request.

    Parameters:
        library: Path to the .so file.
        verbose: Traces the run.

    Returns:
        The decompilation, or one whose error says why there is none: Ghidra not configured, a known runtime library, too large, or a failed run.

    Side effects:
        May spawn Ghidra, and populates the in-process cache.

    Implementation notes:
        The cache key is the content hash, so the same library extracted for several ABIs or regions is decompiled once per distinct file, and the key stays valid however the tree is moved. Known framework runtimes are refused by name before any work: their code is the framework's, not the app's, and some of them take longer to analyse than a whole scan should. The lock is held across the run, so a second request for the same library waits for the first rather than starting another JVM.

    Thread-safety:
        Safe to call from several agent regions at once; runs are serialised.
    """
    library = Path(library)
    launcher = resolve_analyze_headless()
    if launcher is None:
        return NativeDecompilation(error="Ghidra is not configured (set ghidra_path in Settings)")
    if library.name in RUNTIME_LIBRARIES:
        return NativeDecompilation(
            error=f"{library.name} is a framework runtime, not app code - decompilation skipped")
    try:
        size = library.stat().st_size
        digest = hashlib.sha256(library.read_bytes()).hexdigest()
    except OSError as exc:
        return NativeDecompilation(error=f"could not read the library: {exc}")
    if size > MAX_LIBRARY_BYTES:
        return NativeDecompilation(
            error=f"library is {size // (1024 * 1024)} MB, over the "
                  f"{MAX_LIBRARY_BYTES // (1024 * 1024)} MB decompilation limit")

    with _run_lock:
        cached = _cache.get(digest)
        if cached is not None:
            return cached
        result = _decompile_uncached(library, launcher, verbose)
        _cache[digest] = result
        return result
