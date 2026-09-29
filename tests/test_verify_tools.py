#!/usr/bin/env python3
"""
Module: test_verify_tools

Purpose:
    The phase-2 device tool surface: the allowlist that stands between the model and a connected device.

Responsibilities:
    Pin the package validation done at construction, the commands the allowlist permits and how it rewrites them, every shape it must refuse, and the sandboxing on the remaining tools.

Dependencies:
    pytest and the verification tool surface, with fakes standing in for the device bridge and the instrumentation runner.

Security considerations:
    Every command here originates from the model. The allowlist is what keeps a prompt-driven verification step from reaching another application's data, changing device settings, or running arbitrary shell on the device, so each refusal case is asserted both by the error returned and by nothing reaching the bridge at all.
"""

import pytest

from lu77U_MobileSec.dynamic_analysis.verify_tools import VerifyTools

PACKAGE = "com.example.target"

class FakeResult:
    """
    Purpose:
        A completed command result shaped like the device bridge returns.

    Attributes:
        stdout: The command's output.
        stderr: The command's error output.
        returncode: The command's exit status.
    """
    def __init__(self, stdout="ok", stderr="", returncode=0):
        """
        Purpose:
            Build the result.

        Parameters:
            stdout: The command's output.
            stderr: The command's error output.
            returncode: The command's exit status.
        """
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode

class FakeADB:
    """
    Purpose:
        A device bridge that records the shell commands it is asked to run instead of running them.

    Attributes:
        commands: The commands recorded, in order.

    Implementation notes:
        Recording rather than running is what lets a refusal be asserted as nothing having reached the device, which is the property that actually matters here.
    """
    def __init__(self):
        """
        Purpose:
            Build the bridge with an empty record.
        """
        self.commands = []

    def shell(self, _, command, **__):
        """
        Purpose:
            Record one shell command and return a successful result.

        Parameters:
            _: The device serial, ignored.
            command: The command as it would be sent to the device.
            __: The keyword options the real bridge accepts, such as the timeout, ignored.

        Returns:
            A successful result.

        Side effects:
            Appends the command to the record.
        """
        self.commands.append(command)
        return FakeResult()

class FakeFrida:
    """
    Purpose:
        An instrumentation runner that reports success without touching a device.
    """
    def run_script(self, *_):
        """
        Purpose:
            Pretend to run an instrumentation script.

        Parameters:
            _: The positional arguments the real runner takes (the device bridge, the device serial, the target package and the script text), ignored.

        Returns:
            A success flag and a fixed output string.
        """
        return True, "script output"

@pytest.fixture
def adb():
    """
    Purpose:
        Provide a fresh recording device bridge.

    Returns:
        The bridge.
    """
    return FakeADB()

@pytest.fixture
def tools(adb, tmp_path):
    """
    Purpose:
        Build the tool surface over the recording bridge, scoped to the target package.

    Parameters:
        adb: The recording device bridge.
        tmp_path: The source sandbox root.

    Returns:
        The tool surface.
    """
    return VerifyTools(adb, FakeFrida(), "emulator-5554", PACKAGE, tmp_path)

def test_invalid_package_is_rejected_at_construction(tmp_path):
    """
    Purpose:
        Pin that an empty, malformed, too-short or traversing package name is refused before any tool exists.

    Parameters:
        tmp_path: The source sandbox root.

    Security considerations:
        The package name is interpolated into the commands sent to the device, so validating it once at construction is what keeps every later command scoped to one application.
    """
    for bad in ("", "not a package", "com", "../etc/passwd"):
        with pytest.raises(ValueError):
            VerifyTools(FakeADB(), FakeFrida(), "emulator-5554", bad, tmp_path)

class TestAllowedCommands:
    """
    Purpose:
        The commands the allowlist permits, and how it rewrites them before they reach the device.
    """
    def test_prefixes_are_stripped(self, tools, adb):
        """
        Purpose:
            Pin that a command written with the full bridge invocation in front of it is reduced to the bare device command.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.

        Implementation notes:
            The model writes commands the way they appear in documentation, so accepting the prefixed form and normalising it avoids refusing a command that is otherwise allowed.
        """
        tools.adb_command(f"adb -s emulator-5554 shell pidof {PACKAGE}")
        assert adb.commands == [f"pidof {PACKAGE}"]

    def test_logcat_is_scoped_to_the_app_pid(self, tools, adb):
        """
        Purpose:
            Pin that a log request is rewritten to follow only the target application's process.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.

        Security considerations:
            An unscoped log stream carries every application's output, including other applications' tokens and notification contents, into the model's context.
        """
        tools.adb_command("logcat")
        assert f"--pid=$(pidof -s {PACKAGE}" in adb.commands[0]

    def test_run_as_with_allowed_subcommand(self, tools, adb):
        """
        Purpose:
            Pin that running as the target application is permitted for an allowed subcommand.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
        """
        tools.adb_command(f"run-as {PACKAGE} ls /data/data/{PACKAGE}/shared_prefs")
        assert adb.commands[0].startswith(f"run-as {PACKAGE} ls ")

    def test_input_tap(self, tools, adb):
        """
        Purpose:
            Pin that a tap with well-formed coordinates is passed through unchanged.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
        """
        tools.adb_command("input tap 100 200")
        assert adb.commands == ["input tap 100 200"]

    def test_getprop_is_quoted(self, tools, adb):
        """
        Purpose:
            Pin that a property read reaches the device intact.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
        """
        tools.adb_command("getprop ro.build.version.release")
        assert adb.commands == ["getprop ro.build.version.release"]

class TestRefusedCommands:
    """
    Purpose:
        Every command shape the allowlist must refuse.

    Implementation notes:
        Each case asserts both the error returned and that the bridge recorded nothing, because a command that is reported as refused after already being sent is not refused at all.
    """
    @pytest.mark.parametrize("command", [
        "rm -rf /data",
        "su -c id",
        "pm uninstall com.other.app",
        "settings put global http_proxy 1.2.3.4:8080",
        "reboot",
        "",
    ])
    def test_unknown_verbs(self, tools, adb, command):
        """
        Purpose:
            Pin that destructive, privilege-seeking, device-wide and empty commands are all refused.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
            command: The command that must be refused.

        Security considerations:
            These are the shapes with consequences beyond the target application: deleting data, escalating to root, uninstalling another application, redirecting all device traffic through a proxy, and restarting the device.
        """
        assert tools.adb_command(command).startswith("ERROR")
        assert adb.commands == []

    @pytest.mark.parametrize("command", [
        "run-as com.other.app cat /data/data/com.other.app/f",
        f"dumpsys package com.other.app",
        "pm path com.other.app",
        "pm dump com.other.app",
        "pidof com.other.app",
    ])
    def test_other_packages(self, tools, adb, command):
        """
        Purpose:
            Pin that an otherwise-allowed verb aimed at a different package is refused.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
            command: The command naming another package.

        Security considerations:
            The verb being allowed is not enough; scope is what confines the run to the application under test, and without it the model could read another application's private data through a permitted command.
        """
        assert tools.adb_command(command).startswith("ERROR")
        assert adb.commands == []

    def test_run_as_rejects_traversal(self, tools, adb):
        """
        Purpose:
            Pin that a traversal out of the application's private directory is refused.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.

        Security considerations:
            Running as the application is already inside its data directory, so a relative path climbing out of it reaches the wider filesystem with that application's identity.
        """
        out = tools.adb_command(f"run-as {PACKAGE} cat ../../../../etc/hosts")
        assert out.startswith("ERROR")
        assert adb.commands == []

    def test_run_as_rejects_arbitrary_subcommands(self, tools, adb):
        """
        Purpose:
            Pin that running as the application cannot be used to start a shell.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.

        Security considerations:
            A shell behind an allowed verb makes the rest of the allowlist irrelevant, since every refused command can then be issued through it.
        """
        assert tools.adb_command(f"run-as {PACKAGE} sh -c id").startswith("ERROR")
        assert adb.commands == []

    def test_am_must_target_the_app(self, tools, adb):
        """
        Purpose:
            Pin that an activity command naming another application, or naming nothing at all, is refused.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
        """
        assert tools.adb_command("am start -n com.other/.Main").startswith("ERROR")
        assert tools.adb_command("am force-stop").startswith("ERROR")
        assert adb.commands == []

    def test_am_accepts_a_scoped_component(self, tools, adb):
        """
        Purpose:
            Pin that an activity command naming a component of the target application is permitted.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.

        Implementation notes:
            Present so the refusals above are known to be scope checks rather than a blanket ban on the verb.
        """
        tools.adb_command(f"am start -n {PACKAGE}/.MainActivity")
        assert adb.commands[0].startswith("am start ")

    def test_input_arguments_are_validated(self, tools, adb):
        """
        Purpose:
            Pin that an input command with too few, non-numeric or unsupported arguments is refused.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
        """
        assert tools.adb_command("input tap 100").startswith("ERROR")
        assert tools.adb_command("input tap x y").startswith("ERROR")
        assert tools.adb_command("input keyevent BACK").startswith("ERROR")
        assert adb.commands == []

    def test_unbalanced_quotes_do_not_raise(self, tools):
        """
        Purpose:
            Pin that a command with an unterminated quote is refused rather than raising out of the parser.

        Parameters:
            tools: The tool surface.

        Implementation notes:
            The command text comes from a model and is not guaranteed to be well formed, so a parse failure has to arrive as a refusal the agent can read rather than as an exception that ends the verification phase.
        """
        assert tools.adb_command('run-as ' + PACKAGE + ' cat "unterminated').startswith("ERROR")

class TestOtherTools:
    """
    Purpose:
        The tools beside the device commands: reading source and running an instrumentation script.
    """
    def test_read_source_uses_the_sandbox(self, tools):
        """
        Purpose:
            Pin that a source read cannot escape the sandbox root.

        Parameters:
            tools: The tool surface.

        Security considerations:
            The path comes from the model, so this is what keeps a read confined to the decompiled tree rather than reaching the analyst's own filesystem.
        """
        assert tools.read_source("../../etc/passwd").startswith("ERROR")

    def test_empty_frida_script(self, tools):
        """
        Purpose:
            Pin that an empty instrumentation script is refused rather than run.

        Parameters:
            tools: The tool surface.
        """
        assert tools.frida_script("  ").startswith("ERROR")

    def test_frida_script_output_is_returned(self, tools):
        """
        Purpose:
            Pin that a script's output is handed back to the agent.

        Parameters:
            tools: The tool surface.
        """
        assert tools.frida_script("send(1)") == "script output"
