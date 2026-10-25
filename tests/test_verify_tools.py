#!/usr/bin/env python3
"""
Module: test_verify_tools

Purpose:
    The phase-2 device tool surface: the allowlist that stands between the model and a connected device.

Responsibilities:
    Pin the package validation done at construction, the commands the allowlist permits and how it rewrites them, every shape it must refuse, the sandboxing on the remaining tools, and that a hook's trigger runs while the hook is loaded.

Dependencies:
    pytest and the verification tool surface, with fakes standing in for the device bridge and the instrumentation runner.

Security considerations:
    Every command here originates from the model. The allowlist is what keeps a prompt-driven verification step from reaching another application's data, changing device settings, or running arbitrary shell on the device, so each refusal case is asserted both by the error returned and by nothing reaching the bridge at all.
"""

import sys
import types

import pytest

from lu77U_MobileSec.dynamic_analysis import frida_manager
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
        An instrumentation runner that reports success without touching a device, running the trigger where the real runner does: after the script loads.
    """
    def run_script(self, *_, after_load=None):
        """
        Purpose:
            Pretend to run an instrumentation script, calling the trigger as the real runner does.

        Parameters:
            _: The positional arguments the real runner takes (the device bridge, the device serial, the target package and the script text), ignored.
            after_load: The trigger to run once the script is loaded, or None.

        Returns:
            A success flag and a fixed output string, preceded by the trigger's output when there was one.
        """
        if after_load is None:
            return True, "script output"
        return True, f"trigger ->\n{after_load()}\n\nscript output:\nscript output"

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
        assert adb.commands[-1].startswith("am start ")

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

class ProviderADB(FakeADB):
    """
    Purpose:
        A recording bridge whose `dumpsys package` lists one provider of the app under test and one of another app.
    """
    def shell(self, _, command, **__):
        """
        Purpose:
            Record the command, answering a package dump with provider authorities.

        Parameters:
            _: The device serial, ignored.
            command: The command as it would be sent to the device.
            __: Keyword options, ignored.

        Returns:
            The package dump for a dumpsys command, otherwise a plain success.
        """
        self.commands.append(command)
        if command.startswith("dumpsys package"):
            return FakeResult(stdout=(
                "  ContentProvider Authorities:\n"
                f"    [{PACKAGE}.notes]:\n      Provider{{4f0d6a5 {PACKAGE}/.NotesProvider}}\n"
                "    [com.other.app.files]:\n      Provider{1a2b3c4 com.other.app/.FileProvider}\n"))
        return FakeResult()


class TestSequencesAndProviders:
    """
    Purpose:
        Chained commands and content provider commands.
    """
    def test_a_chain_runs_in_order_and_each_part_is_checked(self, tools, adb):
        """
        Purpose:
            Pin that && runs each command in turn, stripping the bridge prefix from each, and that a refused part stops the chain before it reaches the device.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
        """
        out = tools.adb_command(f"adb shell am start -n {PACKAGE}/.LogActivity && adb shell input text 1234 && input tap 5 9")
        assert [c.split()[0] for c in adb.commands if c != "id -u"] == ["am", "input", "input"]
        assert out.count("$ ") == 3
        adb.commands.clear()
        out = tools.adb_command(f"am start -n {PACKAGE}/.A && su -c id && input tap 1 2")
        assert len(adb.commands) == 1 and "ERROR" in out

    @pytest.mark.parametrize("command", ["logcat | grep pw", f"am start -n {PACKAGE}/.A &", "logcat > /sdcard/x"])
    def test_pipes_and_redirection_are_refused(self, tools, adb, command):
        """
        Purpose:
            Pin that a pipe, a background job or a redirection is refused whole.

        Parameters:
            tools: The tool surface.
            adb: The recording bridge.
            command: The refused command.
        """
        assert tools.adb_command(command).startswith("ERROR")
        assert adb.commands == []

    def test_content_reaches_only_the_apps_own_providers(self, tmp_path):
        """
        Purpose:
            Pin that a content query to the app's provider is sent with its arguments quoted, and one to another app's provider is refused.

        Parameters:
            tmp_path: The source sandbox root.
        """
        bridge = ProviderADB()
        tools = VerifyTools(bridge, FakeFrida(), "emulator-5554", PACKAGE, tmp_path)
        tools.adb_command(f'content query --uri content://{PACKAGE}.notes/notes --where "1=1"')
        assert bridge.commands[-1] == f"content query --uri content://{PACKAGE}.notes/notes --where 1=1"
        assert tools.adb_command("content query --uri content://com.other.app.files/x").startswith("ERROR")
        assert tools.adb_command("content query").startswith("ERROR")
        assert not any(c.startswith("content") and "com.other.app" in c for c in bridge.commands)


class RootShellADB(FakeADB):
    """
    Purpose:
        A bridge whose adb shell is root and whose su takes the AOSP form, as on many emulators.
    """
    def shell(self, _, command, **__):
        """
        Purpose:
            Record the command, answering the identity probes as a root shell would.

        Parameters:
            _: The device serial, ignored.
            command: The command.
            __: Keyword options, ignored.

        Returns:
            "0" for `id -u`, a shell identity for `su 2000 id`, otherwise a plain success.
        """
        self.commands.append(command)
        if command == "id -u":
            return FakeResult(stdout="0")
        if command == "su 2000 id":
            return FakeResult(stdout="uid=2000(shell) gid=2000(shell)")
        return FakeResult()


def test_on_a_root_shell_intents_are_sent_as_an_unprivileged_user(tmp_path):
    """
    Purpose:
        Pin that when adb's shell is root, am and content commands run as uid 2000, so the device refuses them what it refuses another app, and that the probe runs once.

    Parameters:
        tmp_path: The source sandbox root.

    Implementation notes:
        As root, a Ghera fixed app's receiver was triggered with a protected broadcast no app can send, and a false positive was confirmed.
    """
    bridge = RootShellADB()
    tools = VerifyTools(bridge, FakeFrida(), "emulator-5554", PACKAGE, tmp_path)
    tools.adb_command(f"am broadcast -n {PACKAGE}/.Receiver")
    tools.adb_command(f"am start -n {PACKAGE}/.Main")
    assert bridge.commands == ["id -u", "su 2000 id", f"su 2000 am broadcast -n {PACKAGE}/.Receiver",
                               f"su 2000 am start -n {PACKAGE}/.Main"]


class TestUiDump:
    """
    Purpose:
        Listing the app's on-screen elements so the agent taps what is there.
    """
    def test_only_the_apps_own_elements_are_listed_with_tap_points(self, tmp_path):
        """
        Purpose:
            Pin that the dump lists the target app's field and button with the centre to tap, leaves out the system UI, and refuses any other uiautomator subcommand.

        Parameters:
            tmp_path: The source sandbox root.
        """
        class DumpADB(FakeADB):
            """
            Purpose:
                A bridge answering the dump with two app elements and one system element.
            """
            def shell(self, _, command, **__):
                """
                Purpose:
                    Record the command and return a UI hierarchy.

                Parameters:
                    _: The device serial, ignored.
                    command: The command.
                    __: Keyword options, ignored.

                Returns:
                    The hierarchy.
                """
                self.commands.append(command)
                return FakeResult(stdout=(
                    '<hierarchy><node text="" class="android.widget.FrameLayout" package="com.android.systemui" '
                    'clickable="true" bounds="[0,0][1080,80]"/>'
                    f'<node text="" resource-id="{PACKAGE}:id/user" class="android.widget.EditText" package="{PACKAGE}" '
                    'clickable="true" bounds="[42,300][1038,420]"/>'
                    f'<node text="SEARCH" resource-id="{PACKAGE}:id/go" class="android.widget.Button" package="{PACKAGE}" '
                    'clickable="true" bounds="[42,450][1038,570]"/></hierarchy>'))

        bridge = DumpADB()
        tools = VerifyTools(bridge, FakeFrida(), "emulator-5554", PACKAGE, tmp_path)
        out = tools.adb_command("uiautomator dump")
        assert out.splitlines() == ["EditText id=user text='' tap=(540,360) editable clickable",
                                    "Button id=go text='SEARCH' tap=(540,510) clickable"]
        assert tools.adb_command("uiautomator runtest x.jar").startswith("ERROR")
        assert len(bridge.commands) == 1
        assert bridge.commands[0].startswith("pkill -f 'com.wetest.uia2.Mai[n]'; uiautomator dump ")
        assert "com.wetest.uia2.Main" not in bridge.commands[0]


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

    def test_a_trigger_runs_while_the_hooks_are_loaded(self, tools, adb):
        """
        Purpose:
            Pin that a trigger reaches the device through the adb allowlist, inside the script's run, and that its output comes back with the script's.

        Parameters:
            tools: The tool surface.
            adb: The recording device bridge.

        Implementation notes:
            A hook sees only the calls made while it is loaded; a Ghera scan ran every hook first and the am start that would have fired it as the next step, and spent its whole budget on hooks that never fired.
        """
        out = tools.frida_script("send(1)", trigger=f"am start -n {PACKAGE}/.MainActivity")
        assert adb.commands and adb.commands[-1].startswith("am start ")
        assert out.startswith("trigger ->") and out.endswith("script output")

    def test_a_trigger_is_held_to_the_adb_allowlist(self, tools, adb):
        """
        Purpose:
            Pin that a trigger can do nothing an adb action could not.

        Parameters:
            tools: The tool surface.
            adb: The recording device bridge.

        Security considerations:
            The trigger is model-written device input like any adb command; a second path to the device that skipped the allowlist would undo every refusal above.
        """
        out = tools.frida_script("send(1)", trigger="am start -n com.other/.Main")
        assert "ERROR" in out
        assert adb.commands == []


def test_the_runner_fires_the_trigger_between_load_and_unload(monkeypatch):
    """
    Purpose:
        Pin the order the real runner uses: the script is loaded, the trigger runs and the hooks then listen, and only after that is the script unloaded.

    Parameters:
        monkeypatch: Installs a stand-in frida module and removes the wait.
    """
    events = []

    class _Script:
        """
        Purpose:
            A script that records its lifecycle and reports one message once loaded.
        """
        def on(self, unused_kind, callback):
            """
            Purpose:
                Keep the message callback.

            Parameters:
                unused_kind: The event name, unused.
                callback: The message callback.
            """
            self.callback = callback

        def load(self):
            """
            Purpose:
                Record the load.
            """
            events.append("load")

        def unload(self):
            """
            Purpose:
                Record the unload.
            """
            events.append("unload")

    script = _Script()

    class _Session:
        """
        Purpose:
            A session that hands out the recording script.
        """
        def create_script(self, unused_source):
            """
            Purpose:
                Return the recording script.

            Parameters:
                unused_source: The script source, unused.

            Returns:
                The script.
            """
            return script

        def detach(self):
            """
            Purpose:
                Nothing to release.
            """

    class _Device:
        """
        Purpose:
            A device whose app is already running.
        """
        def attach(self, unused_package):
            """
            Purpose:
                Attach to the running app.

            Parameters:
                unused_package: The package, unused.

            Returns:
                A session.
            """
            return _Session()

    manager = types.SimpleNamespace(add_remote_device=lambda _: _Device(), remove_remote_device=lambda _: None)
    monkeypatch.setitem(sys.modules, "frida", types.SimpleNamespace(get_device_manager=lambda: manager))
    monkeypatch.setattr(frida_manager.time, "sleep", lambda _: events.append("listen"))
    runner = frida_manager.FridaManager()
    monkeypatch.setattr(runner, "is_server_running", lambda *_: True)
    adb = types.SimpleNamespace(run_adb=lambda *_, **__: types.SimpleNamespace(returncode=0, stderr=""))

    def trigger():
        """
        Purpose:
            Stand in for the am start that runs the hooked code, which then reports through the hook.

        Returns:
            The command's output.
        """
        events.append("trigger")
        script.callback({"type": "send", "payload": "hooked call seen"}, None)
        return "Starting: Intent { cmp=x/.Main }"

    ok, output = runner.run_script(adb, "emulator-5554", PACKAGE, "send(1)", after_load=trigger)
    assert ok
    assert events == ["load", "trigger", "listen", "unload"]
    assert output == "trigger ->\nStarting: Intent { cmp=x/.Main }\n\nscript output:\nhooked call seen"
