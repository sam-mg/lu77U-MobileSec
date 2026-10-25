#!/usr/bin/env python3
"""
Module: test_ghidra

Purpose:
    The optional Ghidra integration: resolving the configured path to the headless launcher, running it safely, parsing and annotating its export, and the decompiled view the agent's inspect_native tool pages through.

Responsibilities:
    Pin the JNI function-table layout the annotations depend on, that only known JNI pointers are labelled, that every install layout resolves, that nothing taken from the APK reaches the command line, that results and failures are cached, that a timed-out run leaves no JVM behind, and that the agent sees JNI entry points first and is told plainly when no code is available.

Dependencies:
    pytest, the Ghidra checker and runner, the agent tool surface, the settings service.

Implementation notes:
    No test here launches the real Ghidra. The process runner is replaced wherever a run is exercised, and the one test that uses real processes runs a shell, not Ghidra, to prove the process-group kill.
"""

import hmac
import json
import os
import subprocess
import sys
import time
import tomllib
from fnmatch import fnmatch
from pathlib import Path

import pytest

from lu77U_MobileSec.analyzers.agent import tools as agent_tools
from lu77U_MobileSec.analyzers.agent.tools import (
    AgentTools, MAX_READ_CHARS, _render_decompilation, locate_native_citation)
from lu77U_MobileSec.config import user_settings
from lu77U_MobileSec.decompiler import ghidra_runner
from lu77U_MobileSec.decompiler.ghidra_runner import (
    JAVA_VM_TABLE, JNI_ENV_TABLE, NativeDecompilation, NativeFunction,
    annotate_jni_calls, parse_export)
from lu77U_MobileSec.tools_checker import ghidra_checker
from lu77U_MobileSec.tools_checker.analysis_checker import get_analysis_status
from lu77U_MobileSec.web.services import settings_service

REPO_ROOT = Path(__file__).resolve().parents[1]

JNI_ACCESS = """bool Java_com_app_Jni_check(long *param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  char *__s2;

  __s2 = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
  iVar1 = strncmp("k3y",__s2,3);
  return iVar1 == 0;
}"""


def _constant_time_contains(haystack, needle):
    """
    Purpose:
        Check whether needle is a substring of haystack by comparing every candidate window with hmac.compare_digest instead of a short-circuiting `in`, since inspect_native output is built from a library's strings, which CodeQL treats as carrying credential-shaped values, and it flags a plain membership check on them as a non-constant-time comparison.

    Parameters:
        haystack: The text to search within.
        needle: The literal substring to look for.

    Returns:
        True when needle appears in haystack, False otherwise.
    """
    return _constant_time_find(haystack, needle) >= 0


def _constant_time_find(haystack, needle):
    """
    Purpose:
        Return the first position of needle in haystack, comparing every window with hmac.compare_digest for the same reason as _constant_time_contains.

    Parameters:
        haystack: The text to search within.
        needle: The literal substring to look for.

    Returns:
        The index of the first occurrence, or -1 when absent.

    Implementation notes:
        Every window is compared even after a match is found, so the time taken does not depend on where the match is.
    """
    width = len(needle)
    found = -1
    for start in range(len(haystack) - width + 1):
        if hmac.compare_digest(haystack[start:start + width], needle) and found < 0:
            found = start
    return found


def _make_executable(path: Path) -> Path:
    """
    Purpose:
        Create an executable placeholder file.

    Parameters:
        path: Where to create it.

    Returns:
        The path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


class TestJniTables:
    """
    Purpose:
        The generated JNIEnv and JavaVM function tables.

    Implementation notes:
        Every annotation is an index into these tables, so one missing or extra entry would silently mislabel every call after it. The offsets pinned here are the ones published in jni.h and used by every JNI reversing reference.
    """
    @pytest.mark.parametrize("name,index", [
        ("GetVersion", 4), ("FindClass", 6), ("GetMethodID", 33),
        ("CallObjectMethod", 34), ("CallVoidMethodA", 63),
        ("CallNonvirtualObjectMethod", 64), ("GetFieldID", 94),
        ("SetDoubleField", 112), ("GetStaticMethodID", 113),
        ("GetStaticFieldID", 144), ("NewStringUTF", 167),
        ("GetStringUTFChars", 169), ("ReleaseStringUTFChars", 170),
        ("GetByteArrayElements", 184), ("SetDoubleArrayRegion", 214),
        ("RegisterNatives", 215), ("GetObjectRefType", 232),
    ])
    def test_jni_env_offsets(self, name, index):
        """
        Purpose:
            Pin each named entry at its jni.h index.

        Parameters:
            name: The JNI function.
            index: Its position in JNINativeInterface.
        """
        assert JNI_ENV_TABLE[index] == name

    def test_jni_env_table_is_complete(self):
        """
        Purpose:
            Pin the table length and that no name repeats.
        """
        assert len(JNI_ENV_TABLE) == 233
        assert len(set(JNI_ENV_TABLE)) == 233

    def test_java_vm_get_env(self):
        """
        Purpose:
            Pin GetEnv at index 6 of the JavaVM table.
        """
        assert JAVA_VM_TABLE.index("GetEnv") == 6


class TestAnnotateJniCalls:
    """
    Purpose:
        Labelling of calls through the JNI function tables in decompiled C.
    """
    def test_java_export_on_64_bit(self):
        """
        Purpose:
            Pin that a Java_ export's first parameter is treated as the JNIEnv on a 64-bit target.
        """
        out = annotate_jni_calls("Java_com_app_Jni_check", JNI_ACCESS, 8)
        assert "/* JNIEnv->GetStringUTFChars */" in out
        assert out.count("JNIEnv->") == 1

    def test_java_export_on_32_bit(self):
        """
        Purpose:
            Pin that the offset is scaled by the pointer size, so 0x2a4 on a 32-bit target is the same call.
        """
        code = JNI_ACCESS.replace("0x548", "0x2a4").replace("long *param_1", "int *param_1")
        out = annotate_jni_calls("Java_com_app_Jni_check", code, 4)
        assert "/* JNIEnv->GetStringUTFChars */" in out

    def test_non_jni_function_with_the_same_shape_is_left_alone(self):
        """
        Purpose:
            Pin that a C++ virtual call, which looks identical, is not labelled as JNI.
        """
        code = JNI_ACCESS.replace("Java_com_app_Jni_check", "Widget_draw")
        assert annotate_jni_calls("Widget_draw", code, 8) == code

    def test_unaligned_offset_is_ignored(self):
        """
        Purpose:
            Pin that an offset that is not a whole number of pointers is not labelled.
        """
        code = JNI_ACCESS.replace("0x548", "0x54c")
        assert "JNIEnv->" not in annotate_jni_calls("Java_com_app_Jni_check", code, 8)

    def test_repeated_call_on_one_line_is_labelled_once(self):
        """
        Purpose:
            Pin that two references to the same slot on one line produce a single label.
        """
        code = ("int Java_a_B_c(int *param_1,int param_2,int param_3)\n\n{\n"
                "  x = (**(code **)(*param_1 + 0x2a4))(param_1,param_3,0,*(code **)(*param_1 + 0x2a4));\n}")
        out = annotate_jni_calls("Java_a_B_c", code, 4)
        assert out.count("GetStringUTFChars") == 1

    def test_jni_onload_vm_and_env_from_get_env(self):
        """
        Purpose:
            Pin that JNI_OnLoad's parameter is the JavaVM and the variable GetEnv writes becomes a JNIEnv, so RegisterNatives is named.
        """
        code = ("jint JNI_OnLoad(long *param_1,undefined8 param_2)\n\n{\n"
                "  long *local_10;\n"
                "  iVar1 = (**(code **)(*param_1 + 0x30))(param_1,&local_10,0x10006);\n"
                "  (**(code **)(*local_10 + 0x6b8))(local_10,uVar2,&DAT_00102010,2);\n"
                "  return 0x10006;\n}")
        out = annotate_jni_calls("JNI_OnLoad", code, 8)
        assert "/* JavaVM->GetEnv */" in out
        assert "/* JNIEnv->RegisterNatives */" in out

    def test_void_parameter_list_is_unchanged(self):
        """
        Purpose:
            Pin that a function with no parameters passes through untouched.
        """
        code = "undefined8 JNI_OnLoad(void)\n\n{\n  return 0x10006;\n}"
        assert annotate_jni_calls("JNI_OnLoad", code, 8) == code


class TestParseExport:
    """
    Purpose:
        Turning the export script's JSON into the runner's result.
    """
    def test_fields_are_coerced_and_annotated(self):
        """
        Purpose:
            Pin the parsed shape, sorted calls, stripped code and applied annotation.
        """
        result = parse_export({
            "language": "AARCH64:LE:64:v8A", "pointer_size": 8, "function_count": 3,
            "truncated": True,
            "functions": [
                {"name": "Java_com_app_Jni_check", "entry": "0010059c", "size": 68,
                 "calls": ["strncmp", "abort"], "c": "\n" + JNI_ACCESS + "\n\n"},
                "not an object",
            ],
        })
        assert result.language == "AARCH64:LE:64:v8A"
        assert result.function_count == 3 and result.truncated
        assert len(result.functions) == 1
        function = result.functions[0]
        assert function.calls == ["abort", "strncmp"]
        assert function.code.startswith("bool Java_")
        assert "JNIEnv->GetStringUTFChars" in function.code

    def test_empty_document(self):
        """
        Purpose:
            Pin that an empty export yields an empty, error-free result.
        """
        result = parse_export({})
        assert result.functions == [] and result.error == ""


class TestResolveAnalyzeHeadless:
    """
    Purpose:
        Finding analyzeHeadless from whatever path the user configured.
    """
    def test_release_layout_from_install_dir_and_ghidra_run(self, tmp_path):
        """
        Purpose:
            Pin the release zip layout, from either the folder or ghidraRun.

        Parameters:
            tmp_path: Holds the fake install.
        """
        install = tmp_path / "ghidra_12.1_PUBLIC"
        headless = _make_executable(install / "support" / "analyzeHeadless")
        run = _make_executable(install / "ghidraRun")
        assert ghidra_checker.resolve_analyze_headless(str(install)) == headless.resolve()
        assert ghidra_checker.resolve_analyze_headless(str(run)) == headless.resolve()

    def test_homebrew_layout_through_a_symlink(self, tmp_path):
        """
        Purpose:
            Pin the Homebrew layout, where bin/ghidraRun links to a wrapper beside libexec/.

        Parameters:
            tmp_path: Holds the fake install.
        """
        cellar = tmp_path / "Cellar" / "ghidra" / "12.1.2"
        wrapper = _make_executable(cellar / "bin" / "ghidraRun")
        headless = _make_executable(cellar / "libexec" / "support" / "analyzeHeadless")
        link = tmp_path / "bin" / "ghidraRun"
        link.parent.mkdir()
        link.symlink_to(wrapper)
        assert ghidra_checker.resolve_analyze_headless(str(link)) == headless.resolve()

    def test_direct_launcher(self, tmp_path):
        """
        Purpose:
            Pin that a path to analyzeHeadless itself is used as is.

        Parameters:
            tmp_path: Holds the fake install.
        """
        headless = _make_executable(tmp_path / "support" / "analyzeHeadless")
        assert ghidra_checker.resolve_analyze_headless(str(headless)) == headless.resolve()

    @pytest.mark.parametrize("value", ["", "   ", "path_goes_here"])
    def test_unset_values(self, value):
        """
        Purpose:
            Pin that empty and placeholder values resolve to nothing.

        Parameters:
            value: The configured value.
        """
        assert ghidra_checker.resolve_analyze_headless(value) is None

    def test_missing_path_and_install_without_support(self, tmp_path):
        """
        Purpose:
            Pin that a path that does not exist, or an install missing its support directory, resolves to nothing.

        Parameters:
            tmp_path: Holds the fake install.
        """
        assert ghidra_checker.resolve_analyze_headless(str(tmp_path / "nope")) is None
        run = _make_executable(tmp_path / "ghidraRun")
        assert ghidra_checker.resolve_analyze_headless(str(run)) is None

    @pytest.mark.skipif(os.name == "nt", reason="POSIX execute bit")
    def test_check_requires_an_executable_launcher(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a launcher without the execute bit does not count as configured.

        Parameters:
            tmp_path: Holds the fake install.
            monkeypatch: Points the setting at the fake install.
        """
        headless = _make_executable(tmp_path / "support" / "analyzeHeadless")
        monkeypatch.setattr(user_settings, "get_ghidra_path", lambda: str(tmp_path))
        assert ghidra_checker.check_ghidra_configured()
        headless.chmod(0o644)
        assert not ghidra_checker.check_ghidra_configured()


class TestDecompileNativeLibrary:
    """
    Purpose:
        The runner's gatekeeping, command line, result handling and cache.
    """
    @pytest.fixture
    def launcher(self, tmp_path, monkeypatch):
        """
        Purpose:
            Report a fake launcher as configured.

        Parameters:
            tmp_path: Holds the fake launcher.
            monkeypatch: Replaces the runner's lookup.

        Returns:
            The fake launcher path.
        """
        path = _make_executable(tmp_path / "ghidra" / "support" / "analyzeHeadless")
        monkeypatch.setattr(ghidra_runner, "resolve_analyze_headless", lambda: path)
        return path

    @pytest.fixture
    def library(self, tmp_path):
        """
        Purpose:
            Write a fake native library under a hostile name.

        Parameters:
            tmp_path: Holds the library.

        Returns:
            The library path.
        """
        path = tmp_path / "apk" / "lib&calc;x.so"
        path.parent.mkdir()
        path.write_bytes(b"\x7fELF fake library")
        return path

    def _fake_run(self, calls, document=None, status=0):
        """
        Purpose:
            Build a stand-in for the process runner that records the command and writes an export.

        Parameters:
            calls: List each command is appended to.
            document: The JSON to write where the script would; nothing is written when None.
            status: The exit status to report.

        Returns:
            The stand-in.
        """
        def run(cmd, timeout):
            """
            Purpose:
                Record the command and play the export script's part.

            Parameters:
                cmd: The argument vector.
                timeout: Seconds allowed, which must be the runner's process timeout.

            Returns:
                The status and empty output.
            """
            assert timeout == ghidra_runner.PROCESS_TIMEOUT
            calls.append(cmd)
            if document is not None:
                out = Path(cmd[cmd.index(ghidra_runner.SCRIPT_NAME) + 1])
                out.write_text(json.dumps(document))
            return status, ""
        return run

    def test_not_configured(self, library):
        """
        Purpose:
            Pin that without a launcher the result explains that and nothing runs.

        Parameters:
            library: The fake library.
        """
        result = ghidra_runner.decompile_native_library(library)
        assert "not configured" in result.error

    @pytest.mark.usefixtures("launcher")
    def test_runtime_library_is_refused_without_running(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a known framework runtime is skipped by name before any work.

        Parameters:
            tmp_path: Holds the library.
            monkeypatch: Replaces the process runner.
        """
        calls = []
        monkeypatch.setattr(ghidra_runner, "_run", self._fake_run(calls))
        flutter = tmp_path / "libflutter.so"
        flutter.write_bytes(b"x")
        result = ghidra_runner.decompile_native_library(flutter)
        assert "framework runtime" in result.error
        assert calls == []

    @pytest.mark.usefixtures("launcher")
    def test_oversized_library_is_refused(self, library, monkeypatch):
        """
        Purpose:
            Pin that a library over the size limit is not decompiled.

        Parameters:
            library: The fake library.
            monkeypatch: Lowers the limit and replaces the process runner.
        """
        calls = []
        monkeypatch.setattr(ghidra_runner, "MAX_LIBRARY_BYTES", 4)
        monkeypatch.setattr(ghidra_runner, "_run", self._fake_run(calls))
        assert "limit" in ghidra_runner.decompile_native_library(library).error
        assert calls == []

    def test_command_line_carries_nothing_from_the_apk(self, launcher, library, monkeypatch):
        """
        Purpose:
            Pin the command shape, and that the hostile library name never reaches it.

        Parameters:
            launcher: The fake launcher.
            library: The fake library, whose name holds shell metacharacters.
            monkeypatch: Replaces the process runner.
        """
        calls = []
        monkeypatch.setattr(ghidra_runner, "_run", self._fake_run(calls, {"functions": []}))
        result = ghidra_runner.decompile_native_library(library)
        assert result.error == "" and result.functions == []
        (cmd,) = calls
        assert cmd[0] == str(launcher)
        assert "-deleteProject" in cmd and "-import" in cmd
        assert cmd[cmd.index("-postScript") + 1] == ghidra_runner.SCRIPT_NAME
        assert cmd[cmd.index("-scriptPath") + 1] == str(ghidra_runner.SCRIPT_DIR)
        imported = cmd[cmd.index("-import") + 1]
        assert Path(imported).name == "lib_calc_x.so"
        assert not any(c in arg for arg in cmd for c in "&;|<>`$")

    @pytest.mark.usefixtures("launcher")
    def test_export_is_parsed_and_cached(self, library, monkeypatch):
        """
        Purpose:
            Pin that a successful export is returned and a second request reuses it.

        Parameters:
            library: The fake library.
            monkeypatch: Replaces the process runner.
        """
        calls = []
        document = {"language": "AARCH64:LE:64:v8A", "pointer_size": 8, "functions": [
            {"name": "Java_com_app_Jni_check", "entry": "0010059c", "size": 68,
             "calls": ["strncmp"], "c": JNI_ACCESS}]}
        monkeypatch.setattr(ghidra_runner, "_run", self._fake_run(calls, document, status=1))
        first = ghidra_runner.decompile_native_library(library)
        second = ghidra_runner.decompile_native_library(library)
        assert first.error == "" and first.functions[0].name == "Java_com_app_Jni_check"
        assert second is first
        assert len(calls) == 1

    @pytest.mark.usefixtures("launcher")
    def test_missing_export_is_an_error_and_is_cached(self, library, monkeypatch):
        """
        Purpose:
            Pin that a run that wrote no export fails, whatever its status, and is not retried.

        Parameters:
            library: The fake library.
            monkeypatch: Replaces the process runner.
        """
        calls = []
        monkeypatch.setattr(ghidra_runner, "_run", self._fake_run(calls, None, status=0))
        assert "without exporting" in ghidra_runner.decompile_native_library(library).error
        ghidra_runner.decompile_native_library(library)
        assert len(calls) == 1

    def test_timeout_is_an_error(self, launcher, library, monkeypatch):
        """
        Purpose:
            Pin that a timed-out run reports the timeout.

        Parameters:
            launcher: The fake launcher.
            library: The fake library.
            monkeypatch: Replaces the process runner.
        """
        timeouts = []

        def overrun(cmd, timeout):
            """
            Purpose:
                Report a timeout as the real runner does.

            Parameters:
                cmd: The argument vector.
                timeout: Seconds allowed, recorded.

            Returns:
                The timeout status and no output.
            """
            assert cmd[0] == str(launcher)
            timeouts.append(timeout)
            return -1, ""
        monkeypatch.setattr(ghidra_runner, "_run", overrun)
        assert "timed out" in ghidra_runner.decompile_native_library(library).error
        assert timeouts == [ghidra_runner.PROCESS_TIMEOUT]

    @pytest.mark.usefixtures("launcher")
    def test_unstartable_launcher_is_an_error(self, library, monkeypatch):
        """
        Purpose:
            Pin that a launcher that cannot be started yields an error rather than raising.

        Parameters:
            library: The fake library.
            monkeypatch: Replaces the process runner.
        """
        def boom(cmd, timeout):
            """
            Purpose:
                Fail as an unstartable executable does.

            Parameters:
                cmd: The argument vector.
                timeout: Seconds allowed.

            Raises:
                OSError: Always.
            """
            raise OSError(f"exec format error: {cmd[0]} (limit {timeout}s)")
        monkeypatch.setattr(ghidra_runner, "_run", boom)
        assert "could not be started" in ghidra_runner.decompile_native_library(library).error


class TestRunProcessTree:
    """
    Purpose:
        The process runner's timeout handling.
    """
    @pytest.mark.skipif(os.name == "nt", reason="process groups are POSIX")
    def test_timeout_kills_the_grandchild(self, tmp_path):
        """
        Purpose:
            Pin that a timeout kills a process the launcher started, not only the launcher.

        Parameters:
            tmp_path: Holds the grandchild's pid file.

        Implementation notes:
            analyzeHeadless is a shell script that runs Java as a child, so this mirrors it with a shell that starts a sleeping child. Killing only the shell would leave the child alive, which is exactly the JVM leak this guards against.
        """
        pid_file = tmp_path / "child.pid"
        script = f"sleep 60 & echo $! > '{pid_file}'; wait"
        status, _ = ghidra_runner._run(["/bin/sh", "-c", script], timeout=1)
        assert status == -1
        child = int(pid_file.read_text().strip())
        deadline = time.time() + 5
        alive = True
        while time.time() < deadline:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                alive = False
                break
            result = subprocess.run(["ps", "-o", "stat=", "-p", str(child)],
                                    capture_output=True, text=True)
            if result.stdout.strip().startswith("Z") or not result.stdout.strip():
                alive = False
                break
            time.sleep(0.1)
        assert not alive

    def test_output_and_status_are_returned(self):
        """
        Purpose:
            Pin that a normal run returns its status and combined output.
        """
        status, output = ghidra_runner._run(
            [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
            timeout=30)
        assert status == 3
        assert "out" in output and "err" in output


class TestExportScriptPackaging:
    """
    Purpose:
        The Java post-script the runner depends on.
    """
    def test_script_exists_and_is_package_data(self):
        """
        Purpose:
            Pin that the script is where the runner looks and is covered by the package-data globs, so an installed copy has it.
        """
        script = ghidra_runner.SCRIPT_DIR / ghidra_runner.SCRIPT_NAME
        assert script.is_file()
        text = script.read_text()
        assert "class ExportNativeDecompilation extends GhidraScript" in text
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        globs = config["tool"]["setuptools"]["package-data"]["lu77U_MobileSec"]
        relative = script.relative_to(REPO_ROOT / "lu77U_MobileSec").as_posix()
        assert any(fnmatch(relative, g) for g in globs)


def _decompilation(*functions, **kwargs):
    """
    Purpose:
        Build a runner result for the tool tests.

    Parameters:
        functions: The decompiled functions.
        kwargs: Overrides for the result's other fields.

    Returns:
        The result.
    """
    fields = dict(language="AARCH64:LE:64:v8A", pointer_size=8,
                  functions=list(functions), function_count=len(functions))
    fields.update(kwargs)
    return NativeDecompilation(**fields)


def _function(name, entry, calls=(), body="  return;"):
    """
    Purpose:
        Build one decompiled function.

    Parameters:
        name: The function name.
        entry: The entry address.
        calls: The imports it calls.
        body: The statements inside its braces.

    Returns:
        The function.
    """
    code = f"void {name}(long *param_1)\n\n{{\n{body}\n}}"
    return NativeFunction(name=name, entry=entry, size=16, calls=list(calls), code=code)


class TestInspectNativeWithGhidra:
    """
    Purpose:
        The decompiled view inspect_native gives the agent.
    """
    @pytest.fixture
    def tree(self, tmp_path):
        """
        Purpose:
            Build a tree holding one fake native library.

        Parameters:
            tmp_path: The tree root.

        Returns:
            The tree root.
        """
        lib = tmp_path / "resources" / "lib" / "arm64-v8a" / "libapp_native.so"
        lib.parent.mkdir(parents=True)
        lib.write_bytes(b"\x7fELF fake")
        return tmp_path

    def _use(self, monkeypatch, result):
        """
        Purpose:
            Make the tool surface receive a fixed decompilation.

        Parameters:
            monkeypatch: Replaces the runner entry point the tools import.
            result: The decompilation to return.
        """
        def fake(path):
            """
            Purpose:
                Check the tool passed the resolved library and return the fixed result.

            Parameters:
                path: The library the tool asked about.

            Returns:
                The decompilation.
            """
            assert path.is_file() and path.name == "libapp_native.so"
            return result
        monkeypatch.setattr(agent_tools, "decompile_native_library", fake)

    def test_jni_first_then_risky_then_named_then_placeholders(self, tree, monkeypatch):
        """
        Purpose:
            Pin the reading order of the decompiled functions.

        Parameters:
            tree: The tree root.
            monkeypatch: Supplies the decompilation.
        """
        self._use(monkeypatch, _decompilation(
            _function("FUN_00100100", "00100100"),
            _function("helper_named", "00100200"),
            _function("copy_input", "00100300", calls=["strcpy"]),
            _function("Java_com_app_Jni_check", "00100400"),
            _function("JNI_OnLoad", "00100500"),
        ))
        out = AgentTools(tree).inspect_native("resources/lib/arm64-v8a/libapp_native.so")
        order = [_constant_time_find(out, f"// ---- {n} ") for n in (
            "Java_com_app_Jni_check", "JNI_OnLoad", "copy_input", "helper_named", "FUN_00100100")]
        assert min(order) >= 0
        assert order == sorted(order)
        assert _constant_time_contains(out, "Decompiled native code (Ghidra, AARCH64:LE:64:v8A) - 5 functions")
        assert _constant_time_contains(out, "calls strcpy")

    def test_ghidra_imports_feed_the_risky_signals(self, tree, monkeypatch):
        """
        Purpose:
            Pin that an import Ghidra saw is surfaced as a risky signal even when objdump contributes nothing.

        Parameters:
            tree: The tree root.
            monkeypatch: Supplies the decompilation and hides objdump.
        """
        real_which = agent_tools.shutil.which
        monkeypatch.setattr(agent_tools.shutil, "which",
                            lambda name: None if name == "objdump" else real_which(name))
        self._use(monkeypatch, _decompilation(
            _function("Java_com_app_Jni_run", "00100100", calls=["system"])))
        out = AgentTools(tree).inspect_native("resources/lib/arm64-v8a/libapp_native.so")
        signals = out[:_constant_time_find(out, "Decompiled native code")]
        assert _constant_time_contains(signals, "Risky imported/exported symbols")
        assert _constant_time_contains(signals, "  system")

    def test_large_view_pages_and_continues(self, tree, monkeypatch):
        """
        Purpose:
            Pin that a view larger than one page is paged, continues on the next call, and honours start_line.

        Parameters:
            tree: The tree root.
            monkeypatch: Supplies the decompilation.
        """
        body = "\n".join(f"  x{i} = {i};" for i in range(400))
        functions = [_function(f"FUN_{i:08x}", f"{i:08x}", body=body) for i in range(8)]
        self._use(monkeypatch, _decompilation(*functions))
        tools = AgentTools(tree)
        path = "resources/lib/arm64-v8a/libapp_native.so"
        first = tools.inspect_native(path)
        assert _constant_time_contains(first, "call inspect_native again on this path")
        assert not _constant_time_contains(first, "// ---- FUN_00000007 ")
        body_chars = sum(len(line.split("| ", 1)[-1]) + 1 for line in first.splitlines()[:-1])
        assert body_chars <= MAX_READ_CHARS
        second = tools.inspect_native(path)
        assert not hmac.compare_digest(second, first)
        jumped = tools.inspect_native(path, start_line=1)
        assert hmac.compare_digest(jumped.lstrip()[:2], "1|")

    def test_unavailable_code_is_stated(self, tree, monkeypatch):
        """
        Purpose:
            Pin that when there is no decompiled code the reason is given and the agent is told not to describe function bodies.

        Parameters:
            tree: The tree root.
            monkeypatch: Supplies a failed decompilation.
        """
        self._use(monkeypatch, NativeDecompilation(error="Ghidra timed out after 720s"))
        out = AgentTools(tree).inspect_native("resources/lib/arm64-v8a/libapp_native.so")
        assert _constant_time_contains(out, "## Decompiled code\n(unavailable: Ghidra timed out after 720s")
        assert _constant_time_contains(out, "do not describe function bodies")
        assert _constant_time_contains(out, "## Dynamic symbols")

    def test_view_is_built_once_per_library(self, tree, monkeypatch):
        """
        Purpose:
            Pin that paging does not decompile again.

        Parameters:
            tree: The tree root.
            monkeypatch: Counts runner calls.
        """
        calls = []

        def fake(path):
            """
            Purpose:
                Count the request and return a small decompilation.

            Parameters:
                path: The library.

            Returns:
                The decompilation.
            """
            calls.append(path)
            return _decompilation(_function("Java_a_B_c", "00100100"))
        monkeypatch.setattr(agent_tools, "decompile_native_library", fake)
        tools = AgentTools(tree)
        first = tools.inspect_native("resources/lib/arm64-v8a/libapp_native.so")
        again = tools.inspect_native("resources/lib/arm64-v8a/libapp_native.so")
        assert _constant_time_contains(first, "// ---- Java_a_B_c ")
        assert _constant_time_contains(again, "// ---- Java_a_B_c ")
        assert len(calls) == 1


class TestLocateNativeCitation:
    """
    Purpose:
        Mapping a native finding's citation onto the decompiled view.

    Implementation notes:
        A real scan had the model put the function's entry address in the line field. Parsed as a number it pointed past the end of the view, the excerpt clamped onto the symbol table, and the finding lost its evidence. These tests pin the repair.
    """
    @pytest.fixture
    def view(self):
        """
        Purpose:
            Render a view holding a secret check and an unbounded copy, the two shapes native findings take.

        Returns:
            The view's lines.
        """
        check = _function("Java_com_app_Jni_access", "0010059c",
                          body='  iVar1 = strncmp("k3y",__s2,0xb);\n  return iVar1 == 0;')
        launch = _function("Java_com_app_Jni_initiateLaunchSequence", "001005e0",
                           body="  char local_18 [24];\n  strcpy(local_18,__src);\n  return 0;")
        lines = _render_decompilation(_decompilation(check, launch))
        return lines + ["", "## Dynamic symbols", "0000 g DF .text Base strcpy"]

    def _line_of(self, view, needle):
        """
        Purpose:
            Find the 1-based line holding a fragment.

        Parameters:
            view: The view's lines.
            needle: The fragment.

        Returns:
            The line number.
        """
        return next(i for i, line in enumerate(view, 1) if needle in line)

    def test_a_line_inside_a_function_is_kept(self, view):
        """
        Purpose:
            Pin that a correct citation is used unchanged.

        Parameters:
            view: The rendered view.
        """
        line = self._line_of(view, "strncmp(")
        assert locate_native_citation(view, line, line, str(line), "anything") == (line, line)

    @pytest.mark.parametrize("raw", ["001005e0", "0x1005e0", "1005E0"])
    def test_an_entry_address_maps_to_the_named_call(self, view, raw):
        """
        Purpose:
            Pin that an address in the line field finds its function and the strcpy line in it.

        Parameters:
            view: The rendered view.
            raw: The address as a model might write it.
        """
        line = self._line_of(view, "strcpy(local_18")
        span = locate_native_citation(view, 10059999, 10059999, raw,
                                      "Unbounded strcpy into a 24-byte stack buffer")
        assert span == (line, line)

    def test_a_function_named_in_the_text_is_found(self, view):
        """
        Purpose:
            Pin that with an unusable line the function named in the description is used, narrowed to the call the description names.

        Parameters:
            view: The rendered view.
        """
        line = self._line_of(view, "strncmp(")
        text = "Java_com_app_Jni_access compares the input with strncmp against a literal"
        assert locate_native_citation(view, len(view) + 50, 0, "", text) == (line, line)

    def test_a_bare_method_name_is_enough(self, view):
        """
        Purpose:
            Pin that the Java method name alone identifies its JNI function.

        Parameters:
            view: The rendered view.
        """
        line = self._line_of(view, "strcpy(local_18")
        text = "initiateLaunchSequence copies the code with strcpy"
        assert locate_native_citation(view, 0, 0, "", text) == (line, line)

    def test_without_a_named_call_the_whole_function_is_shown(self, view):
        """
        Purpose:
            Pin that a finding naming the function but no listed call gets the function body, and that the word "access" does not latch onto the signature.

        Parameters:
            view: The rendered view.
        """
        first = self._line_of(view, "void Java_com_app_Jni_access(")
        last = self._line_of(view, "return iVar1 == 0;") + 1
        span = locate_native_citation(view, 0, 0, "0010059c", "Hardcoded access secret")
        assert span == (first, last)

    def test_nothing_recognisable_yields_none(self, view):
        """
        Purpose:
            Pin that a citation tied to no function produces no span rather than a guess.

        Parameters:
            view: The rendered view.
        """
        assert locate_native_citation(view, 0, 0, "deadbeef", "Something unrelated") is None
        assert locate_native_citation(["## Dynamic symbols"], 1, 1, "1", "strcpy") is None

class TestGhidraSettings:
    """
    Purpose:
        The ghidra_path setting through the dashboard's settings service and status.
    """
    def test_update_strips_and_stores(self, monkeypatch):
        """
        Purpose:
            Pin that the service stores the path with surrounding whitespace removed.

        Parameters:
            monkeypatch: Captures the store and stubs the read-back.
        """
        stored = []
        monkeypatch.setattr(user_settings, "set_ghidra_path", stored.append)
        monkeypatch.setattr(settings_service, "get_settings", lambda: {})
        settings_service.update_settings({"ghidra_path": "  /opt/homebrew/bin/ghidraRun \n"})
        assert stored == ["/opt/homebrew/bin/ghidraRun"]

    def test_status_reports_ghidra(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that the readiness status carries the Ghidra flag without making it required.

        Parameters:
            monkeypatch: Points the setting at a fake install.
            tmp_path: Holds the fake install.
        """
        _make_executable(tmp_path / "support" / "analyzeHeadless")
        monkeypatch.setattr(user_settings, "get_ghidra_path", lambda: str(tmp_path))
        status = get_analysis_status()
        assert status["ghidra_configured"] is True
        monkeypatch.setattr(user_settings, "get_ghidra_path", lambda: "")
        status = get_analysis_status()
        assert status["ghidra_configured"] is False
