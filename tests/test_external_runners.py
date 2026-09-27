#!/usr/bin/env python3
"""
Module: test_external_runners

Purpose:
    The wrappers around the three external decompilers this package shells out to.

Responsibilities:
    Pin the exact command line each one builds, that success is judged by the files produced rather than by the exit status, and that every failure mode yields nothing rather than raising.

Dependencies:
    pytest, the three decompiler runner modules and the user settings they read their paths from.

Implementation notes:
    The process runner is replaced throughout, so no real external tool is ever invoked. Judging success by artifacts rather than exit status is the load-bearing decision here: two of these tools exit non-zero on partial failures while still producing usable output, and one exits zero having produced nothing.
"""

import subprocess

import pytest

from lu77U_MobileSec.decompiler import blutter_runner, hermes_runner, rn_bundle_decompiler

class FakeCompleted:
    """
    Purpose:
        A completed process result shaped like the real one.

    Attributes:
        returncode: The exit status.
        stdout: The standard output.
        stderr: The standard error output.
    """
    def __init__(self, returncode=0, stdout="", stderr=""):
        """
        Purpose:
            Build the result.

        Parameters:
            returncode: The exit status.
            stdout: The standard output.
            stderr: The standard error output.
        """
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestBlutterRunner:
    """
    Purpose:
        The wrapper around the Flutter disassembler.
    """
    def test_no_path_configured_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that with no path configured the runner yields nothing without attempting to run anything.

        Parameters:
            monkeypatch: Reports the path as unconfigured.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(blutter_runner.user_settings, "get_blutter_path", lambda: "")
        assert blutter_runner.run_blutter(tmp_path / "lib", tmp_path / "out") is None

    def test_exact_argv(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin the exact command line built, including the interpreter the script is run under.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.

        Implementation notes:
            The tool is a script rather than an executable, so it is run through this process's own interpreter instead of being invoked directly, which is the part of the command line most easily broken.
        """
        monkeypatch.setattr(blutter_runner.user_settings, "get_blutter_path",
                            lambda: "/opt/blutter/blutter.py")
        captured = {}

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Record the command line and produce the artifact the runner looks for.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A successful completed process.

            Side effects:
                Records the command line and writes the expected output file.
            """
            captured["cmd"] = cmd
            out = tmp_path / "out"
            out.mkdir(parents=True, exist_ok=True)
            (out / "pp.txt").write_text("ok")
            return FakeCompleted(returncode=0)

        monkeypatch.setattr(blutter_runner.subprocess, "run", fake_run)
        lib_dir = tmp_path / "lib"
        out_dir = tmp_path / "out"
        result = blutter_runner.run_blutter(lib_dir, out_dir)
        assert captured["cmd"] == [
            blutter_runner.sys.executable, "/opt/blutter/blutter.py", str(lib_dir), str(out_dir)]
        assert result == out_dir

    def test_success_judged_by_artifacts_not_returncode(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a non-zero exit with real output present is treated as success.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.

        Implementation notes:
            This tool exits non-zero when any single class fails to disassemble, which happens on almost every real application while the rest of the output is perfectly usable.
        """
        monkeypatch.setattr(blutter_runner.user_settings, "get_blutter_path", lambda: "/x/blutter.py")

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Produce disassembly output and report a non-zero exit.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A completed process reporting failure.

            Side effects:
                Writes the expected output files.
            """
            out = tmp_path / "out"
            out.mkdir(parents=True, exist_ok=True)
            (out / "asm").mkdir()
            (out / "asm" / "Foo.asm").write_text("void foo(){}")
            return FakeCompleted(returncode=1)

        monkeypatch.setattr(blutter_runner.subprocess, "run", fake_run)
        result = blutter_runner.run_blutter(tmp_path / "lib", tmp_path / "out")
        assert result == tmp_path / "out"

    def test_no_output_artifacts_is_failure_even_with_zero_returncode(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a clean exit with no output produced is treated as failure.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(blutter_runner.user_settings, "get_blutter_path", lambda: "/x/blutter.py")
        monkeypatch.setattr(blutter_runner.subprocess, "run",
                            lambda cmd, **kw: FakeCompleted(returncode=0))
        assert blutter_runner.run_blutter(tmp_path / "lib", tmp_path / "out") is None

    def test_missing_executable_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a configured path with nothing behind it yields nothing rather than raising.

        Parameters:
            monkeypatch: Reports a configured path and makes the process runner report the file missing.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(blutter_runner.user_settings, "get_blutter_path", lambda: "/x/blutter.py")

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Report the executable as missing.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Raises:
                FileNotFoundError: Always.
            """
            raise FileNotFoundError("no such file")

        monkeypatch.setattr(blutter_runner.subprocess, "run", fake_run)
        assert blutter_runner.run_blutter(tmp_path / "lib", tmp_path / "out") is None

    def test_timeout_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a run that exceeded its time limit yields nothing rather than raising.

        Parameters:
            monkeypatch: Reports a configured path and makes the process runner time out.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(blutter_runner.user_settings, "get_blutter_path", lambda: "/x/blutter.py")

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Report the run as having exceeded its time limit.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Raises:
                subprocess.TimeoutExpired: Always.
            """
            raise subprocess.TimeoutExpired(cmd="blutter", timeout=1)

        monkeypatch.setattr(blutter_runner.subprocess, "run", fake_run)
        assert blutter_runner.run_blutter(tmp_path / "lib", tmp_path / "out") is None


class TestHermesRunner:
    """
    Purpose:
        The wrapper around the compiled-bundle decompiler.
    """
    def test_no_path_configured_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that with no path configured the runner yields nothing without attempting to run anything.

        Parameters:
            monkeypatch: Reports the path as unconfigured.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(hermes_runner.user_settings, "get_hermes_decomp_path", lambda: "")
        assert hermes_runner.decompile_hbc(tmp_path / "b.hbc", tmp_path / "out") is None

    def test_exact_argv_and_output_path(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin the exact command line of the main call and that the decompiled file is returned with its contents.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.

        Implementation notes:
            Only the first call is asserted, because the runner makes further best-effort calls for extra material afterwards and those are the subject of their own test.
        """
        monkeypatch.setattr(hermes_runner.user_settings, "get_hermes_decomp_path",
                            lambda: "/usr/local/bin/hermes-decomp")
        calls = []

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Record every call and write the decompiled file for the main one.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A successful completed process.

            Side effects:
                Records the command line and writes the output file for the main call only.
            """
            calls.append(cmd)
            if cmd[1] == "decompile":
                out_file = tmp_path / "out" / "bundle.js"
                out_file.parent.mkdir(parents=True, exist_ok=True)
                out_file.write_text("function main(){}")
            return FakeCompleted(returncode=0)

        monkeypatch.setattr(hermes_runner.subprocess, "run", fake_run)
        bundle = tmp_path / "b.hbc"
        result = hermes_runner.decompile_hbc(bundle, tmp_path / "out")
        assert calls[0] == [
            "/usr/local/bin/hermes-decomp", "decompile", str(bundle),
            "-o", str(tmp_path / "out" / "bundle.js")]
        assert result == tmp_path / "out" / "bundle.js"
        assert result.read_text() == "function main(){}"

    def test_empty_output_file_is_failure(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a clean exit that produced no decompiled file is treated as failure.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(hermes_runner.user_settings, "get_hermes_decomp_path", lambda: "/x/hd")

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Report success without producing anything.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A successful completed process.
            """
            return FakeCompleted(returncode=0)

        monkeypatch.setattr(hermes_runner.subprocess, "run", fake_run)
        assert hermes_runner.decompile_hbc(tmp_path / "b.hbc", tmp_path / "out") is None

    def test_missing_extras_subcommand_does_not_fail_the_decompile(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a build of the tool lacking the extra subcommands still yields a successful decompile.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.

        Implementation notes:
            The module listing and string extraction are best effort and were added to the tool later, so an older build without them must not make an otherwise successful decompile look like a failure.
        """
        monkeypatch.setattr(hermes_runner.user_settings, "get_hermes_decomp_path", lambda: "/x/hd")
        calls = []

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Succeed for the main call and report every other subcommand as missing.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A successful completed process, for the main call.

            Raises:
                FileNotFoundError: For any subcommand but the main one.

            Side effects:
                Records the command line and writes the output file for the main call.
            """
            calls.append(cmd)
            if cmd[1] == "decompile":
                out_file = tmp_path / "out" / "bundle.js"
                out_file.parent.mkdir(parents=True, exist_ok=True)
                out_file.write_text("ok")
                return FakeCompleted(returncode=0)
            raise FileNotFoundError("no such subcommand")

        monkeypatch.setattr(hermes_runner.subprocess, "run", fake_run)
        result = hermes_runner.decompile_hbc(tmp_path / "b.hbc", tmp_path / "out")
        assert result is not None
        assert not (tmp_path / "out" / "modules.txt").exists()

    def test_missing_executable_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a configured path with nothing behind it yields nothing rather than raising.

        Parameters:
            monkeypatch: Reports a configured path and makes the process runner report the file missing.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(hermes_runner.user_settings, "get_hermes_decomp_path", lambda: "/x/hd")
        monkeypatch.setattr(hermes_runner.subprocess, "run",
                            lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError()))
        assert hermes_runner.decompile_hbc(tmp_path / "b.hbc", tmp_path / "out") is None


class TestRnBundleDecompiler:
    """
    Purpose:
        The wrapper around the React Native bundle decompiler.
    """
    def test_no_path_configured_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that with no path configured the runner yields nothing without attempting to run anything.

        Parameters:
            monkeypatch: Reports the path as unconfigured.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(rn_bundle_decompiler.user_settings, "get_rn_decompiler_path", lambda: "")
        assert rn_bundle_decompiler.decompile_js_bundle(tmp_path / "b.js", tmp_path / "out") is None

    def test_exact_argv_includes_no_eslint(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin the exact command line built, including the flag that disables the tool's own linting pass.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.

        Implementation notes:
            The linting pass reformats the output and takes longer than the decompilation itself, and nothing downstream reads formatted code, so it is turned off deliberately rather than by oversight.
        """
        monkeypatch.setattr(rn_bundle_decompiler.user_settings, "get_rn_decompiler_path",
                            lambda: "/usr/local/bin/react-native-decompiler")
        captured = {}

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Record the command line and produce one decompiled module.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A successful completed process.

            Side effects:
                Records the command line and writes an output file.
            """
            captured["cmd"] = cmd
            out = tmp_path / "out"
            out.mkdir(parents=True, exist_ok=True)
            (out / "0.js").write_text("module.exports = {};")
            return FakeCompleted(returncode=0)

        monkeypatch.setattr(rn_bundle_decompiler.subprocess, "run", fake_run)
        bundle = tmp_path / "b.js"
        out_dir = tmp_path / "out"
        result = rn_bundle_decompiler.decompile_js_bundle(bundle, out_dir)
        assert captured["cmd"] == [
            "/usr/local/bin/react-native-decompiler", "-i", str(bundle), "-o", str(out_dir),
            "--noEslint"]
        assert result == out_dir

    def test_no_output_files_is_failure(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a clean exit with no modules produced is treated as failure.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(rn_bundle_decompiler.user_settings, "get_rn_decompiler_path", lambda: "/x/rnd")
        monkeypatch.setattr(rn_bundle_decompiler.subprocess, "run",
                            lambda cmd, **kw: FakeCompleted(returncode=0))
        assert rn_bundle_decompiler.decompile_js_bundle(tmp_path / "b.js", tmp_path / "out") is None

    def test_nonzero_returncode_with_partial_output_still_succeeds(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a non-zero exit with some modules produced is treated as success.

        Parameters:
            monkeypatch: Reports a configured path and replaces the process runner.
            tmp_path: Temporary directory for the input and output paths.

        Implementation notes:
            A bundle holds thousands of modules and this tool exits non-zero if any one of them fails, so discarding the run over that would throw away nearly all of a usable decompile.
        """
        monkeypatch.setattr(rn_bundle_decompiler.user_settings, "get_rn_decompiler_path", lambda: "/x/rnd")

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Produce one module and report a non-zero exit.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Returns:
                A completed process reporting failure.

            Side effects:
                Writes an output file.
            """
            out = tmp_path / "out"
            out.mkdir(parents=True, exist_ok=True)
            (out / "0.js").write_text("// one module failed, others ok")
            return FakeCompleted(returncode=1)

        monkeypatch.setattr(rn_bundle_decompiler.subprocess, "run", fake_run)
        result = rn_bundle_decompiler.decompile_js_bundle(tmp_path / "b.js", tmp_path / "out")
        assert result == tmp_path / "out"

    def test_timeout_returns_none(self, monkeypatch, tmp_path):
        """
        Purpose:
            Pin that a run that exceeded its time limit yields nothing rather than raising.

        Parameters:
            monkeypatch: Reports a configured path and makes the process runner time out.
            tmp_path: Temporary directory for the input and output paths.
        """
        monkeypatch.setattr(rn_bundle_decompiler.user_settings, "get_rn_decompiler_path", lambda: "/x/rnd")

        def fake_run(cmd, **kwargs):
            """
            Purpose:
                Report the run as having exceeded its time limit.

            Parameters:
                cmd: The command line the runner built.
                kwargs: The call options, unused here.

            Raises:
                subprocess.TimeoutExpired: Always.
            """
            raise subprocess.TimeoutExpired(cmd="rnd", timeout=1)

        monkeypatch.setattr(rn_bundle_decompiler.subprocess, "run", fake_run)
        assert rn_bundle_decompiler.decompile_js_bundle(tmp_path / "b.js", tmp_path / "out") is None
