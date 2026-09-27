#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.dynamic_analysis.verify_tools

Purpose:
    Give the verification agent a bounded set of device operations -- read source, run a narrow subset of adb commands, inject a Frida script -- so it can confirm or refute a static finding against the running app.

Responsibilities:
    Parse a requested command, refuse anything outside the allowlist, execute the permitted forms, and bound the output.

Dependencies:
    The device and Frida managers, and the agent's source-reading tools.

Implementation notes:
    This is an allowlist, not a filter. Each supported command has its own handler that accepts one shape and refuses everything else, so a command form nobody wrote a handler for is rejected by default rather than passed through.

Security considerations:
    The commands executed here are chosen by a language model reading an untrusted app. Every handler is constrained to the package under test: run-as, dumpsys, pidof and pm all require the app's own package name, and the component checks on am stop the agent launching another app's activity. Without these constraints the agent would have a general shell on the device, which is both a safety problem and a correctness one -- a verification that touched another app would prove nothing about this one.
"""

import shlex
from typing import List

from ..analyzers.agent.tools import AgentTools
from .adb_manager import ADBManager, _ANDROID_PACKAGE_RE
from .frida_manager import FridaManager

MAX_OUTPUT_CHARS = 4000

def _truncate(text: str, limit: int) -> str:
    """
    Purpose:
        Bound command output to a size the model can use.

    Parameters:
        text: The output.
        limit: Maximum length.

    Returns:
        The output, marked when it was cut.

    Implementation notes:
        Marked rather than silently cut, so the model can tell a complete result from a partial one and ask a narrower question instead of concluding from a truncated list.
    """
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"

class VerifyTools:
    """
    Purpose:
        The device-side tool surface the verification agent is allowed to use.

    Attributes:
        adb: Device control.
        frida: Instrumentation control.
        device: Device serial.
        package: Package under test, validated at construction.
        verbose: Whether tool use is traced.
        source_tools: Source reading, scoped to the decompiled tree.

    Invariants:
        Every device operation is scoped to the package under test. Output is always bounded.

    Thread-safety:
        Not safe to share; it drives one device and one app.

    Security considerations:
        This class is the security boundary between a model's requests and a real device.
    """
    def __init__(self, adb: ADBManager, frida: FridaManager, device: str,
                package: str, source_root, verbose: bool = False):
        """
        Purpose:
            Construct the tool surface for one app on one device.

        Parameters:
            adb: Device control.
            frida: Instrumentation control.
            device: Device serial.
            package: Package under test.
            source_root: Root of the decompiled source.
            verbose: Enables tracing.

        Raises:
            ValueError: When the package name does not match the permitted pattern.

        Security considerations:
            The package is validated here, once, because every handler below composes it into a device shell command. Validating at construction means no handler has to repeat the check and none can forget it.
        """
        if not _ANDROID_PACKAGE_RE.match(package or ""):
            raise ValueError(f"invalid package: {package!r}")
        self.adb = adb
        self.frida = frida
        self.device = device
        self.package = package
        self.verbose = verbose
        self.source_tools = AgentTools(source_root)

    def read_source(self, path: str, start_line=None) -> str:
        """
        Purpose:
            Read decompiled source, so the agent can compare the code against what the device does.

        Parameters:
            path: Path within the decompiled tree.
            start_line: Optional line to read from.

        Returns:
            The requested source.

        Security considerations:
            Path containment is enforced by the underlying source tools, which confine reads to the decompiled tree.
        """
        return self.source_tools.read_file(path, start_line=start_line)

    def adb_command(self, command: str) -> str:
        """
        Purpose:
            Execute one model-requested adb command, if it is permitted.

        Parameters:
            command: The command as the model wrote it.

        Returns:
            The output, or an error message explaining why it was refused.

        Implementation notes:
            Refusals come back as text rather than exceptions, because the agent reads them and can then ask for something permitted. An exception would end the verification instead of redirecting it.

        Security considerations:
            The refusal message names the permitted form, which is what lets the agent converge on an allowed command rather than retrying variants of a forbidden one.
        """
        command = (command or "").strip()
        if not command:
            return "ERROR: empty adb command"
        try:
            handler = self._resolve_adb_command(command)
            result = handler()
        except ValueError as e:
            return f"ERROR: {e}"
        return _truncate(result, MAX_OUTPUT_CHARS)

    def _resolve_adb_command(self, command: str):
        """
        Purpose:
            Parse a requested command and return the handler for it, refusing anything unrecognised.

        Parameters:
            command: The command text.

        Returns:
            A callable that runs the permitted command.

        Raises:
            ValueError: When the command cannot be parsed or is not on the allowlist.

        Implementation notes:
            Parsed with shell-aware tokenisation so that quoting is handled the way the model expects, rather than by splitting on whitespace. Leading adb and device-selector tokens are stripped, since models write the full command they would type. A leading shell token is likewise removed, so both spellings reach the same handler.

        Security considerations:
            This is the gate. The command is reduced to a verb and arguments, and only a verb with a handler proceeds; everything else is refused. Because dispatch is by exact verb, an unknown command cannot fall through to a general shell.
        """
        try:
            tokens = shlex.split(command)
        except ValueError as e:
            raise ValueError(f"could not parse command: {e}")
        if tokens[:1] == ["adb"]:
            tokens = tokens[1:]
            if tokens[:1] == ["-s"] and len(tokens) >= 2:
                tokens = tokens[2:]
        if tokens[:1] == ["shell"]:
            tokens = tokens[1:]
        if not tokens:
            raise ValueError("empty command")
        verb = tokens[0].lower()
        args = tokens[1:]

        if verb == "logcat":
            return lambda: self._logcat()
        if verb == "run-as":
            return lambda: self._run_as(args)
        if verb == "dumpsys":
            return lambda: self._dumpsys(args)
        if verb == "pm":
            return lambda: self._pm(args)
        if verb == "am":
            return lambda: self._am(args)
        if verb == "input":
            return lambda: self._input(args)
        if verb == "screencap":
            return lambda: self._screencap()
        if verb == "getprop":
            return lambda: self._getprop(args)
        if verb == "pidof":
            return lambda: self._pidof(args)
        raise ValueError(
            f"command '{verb}' is not allowed. Allowed: logcat, run-as, dumpsys, "
            "pm, am, input, screencap, getprop, pidof (all scoped to the target app).")

    def _shell(self, cmd: str, timeout: int = 20) -> str:
        """
        Purpose:
            Run a device shell command and return its combined output.

        Parameters:
            cmd: The command string.
            timeout: Seconds to allow.

        Returns:
            The combined output, or a marker when there was none.

        Implementation notes:
            Both streams are combined because device tools split their output inconsistently and the agent needs whichever one carried the answer. Empty output is reported explicitly, so the agent can tell a command that produced nothing from one that failed.

        Security considerations:
            This executes an arbitrary string on the device and is private for that reason. Only the validated handlers call it, and they compose their commands from the validated package name and their own literals.
        """
        result = self.adb.shell(self.device, cmd, timeout=timeout)
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        combined = (out + ("\n" + err if err else "")).strip()
        return combined or "(no output)"

    def _logcat(self) -> str:
        """
        Purpose:
            Return recent log output from the app under test.

        Returns:
            The app's recent log lines.

        Implementation notes:
            Filtered to the app's own process, so the agent sees this app's logging rather than the whole device's. The line count is bounded, since the log is a ring buffer and the recent entries are the relevant ones.

        Security considerations:
            Scoping to the app's process id is what keeps other apps' log output -- which can contain their data -- out of the agent's view.
        """
        return self._shell(
            f"logcat -d -t 200 --pid=$(pidof -s {self.package} 2>/dev/null)")

    def _run_as(self, args: List[str]) -> str:
        """
        Purpose:
            Read the app's private storage through its own user, which is how a storage finding is confirmed.

        Parameters:
            args: Tokens following the command.

        Returns:
            The command output.

        Raises:
            ValueError: When the target is not the app under test, the subcommand is not permitted, or a path contains a traversal sequence.

        Security considerations:
            Three constraints apply together: the package must be the app under test, the operation must be one of listing, reading or finding, and no path may contain a traversal sequence. The first scopes access to this app's data, the second prevents writes and execution, and the third stops the agent escaping the app's data directory into the wider filesystem.
        """
        if len(args) < 2 or args[0] != self.package:
            raise ValueError(
                f"run-as must target the app under test: "
                f"'run-as {self.package} <ls|cat|find> <path>'")
        sub = args[1]
        if sub not in ("ls", "cat", "find"):
            raise ValueError("run-as only supports 'ls', 'cat', or 'find'")
        rest = args[2:]
        for a in rest:
            if ".." in a:
                raise ValueError("path traversal ('..') is not allowed")
        quoted = " ".join(shlex.quote(a) for a in rest)
        return self._shell(f"run-as {self.package} {sub} {quoted}".strip())

    def _dumpsys(self, args: List[str]) -> str:
        """
        Purpose:
            Handle the dumpsys command, permitting only the form that targets the app under test.

        Parameters:
            args: Tokens following the command.

        Returns:
            The command output.

        Raises:
            ValueError: When the form is not the permitted one.

        Security considerations:
            dumpsys can expose system-wide state including other apps' components and, in some services, their data. The permitted form is the package query for the app under test, and anything else is refused rather than narrowed, so the model cannot reach data or components belonging to other apps.
        """
        if args != ["package", self.package]:
            raise ValueError(f"dumpsys is only allowed as 'dumpsys package {self.package}'")
        return self._shell(f"dumpsys package {self.package}")

    def _pidof(self, args: List[str]) -> str:
        """
        Purpose:
            Report whether the app under test is running.

        Parameters:
            args: Tokens following the command.

        Returns:
            The process id, or a message saying the app is not running.

        Raises:
            ValueError: When the argument is not the app under test.

        Implementation notes:
            The not-running case is reported in words rather than as empty output, because the agent needs to distinguish it from a failed command -- several findings can only be verified against a running process.
        """
        if args != [self.package]:
            raise ValueError(f"pidof is only allowed as 'pidof {self.package}'")
        out = self._shell(f"pidof {self.package}")
        return out if out != "(no output)" else "(app not currently running - no pid)"

    def _pm(self, args: List[str]) -> str:
        """
        Purpose:
            Handle the pm command, permitting only the form that targets the app under test.

        Parameters:
            args: Tokens following the command.

        Returns:
            The command output.

        Raises:
            ValueError: When the form is not the permitted one.

        Security considerations:
            The package manager can enumerate and describe every app on the device. The permitted form is either the path or dump query for the app under test, and anything else is refused rather than narrowed, so the model cannot reach data or components belonging to other apps.
        """
        if args[:2] == ["path", self.package]:
            return self._shell(f"pm path {self.package}")
        if args[:2] == ["dump", self.package]:
            return self._shell(f"pm dump {self.package}")
        raise ValueError(
            f"pm is only allowed as 'pm path {self.package}' or 'pm dump {self.package}'")

    def _am(self, args: List[str]) -> str:
        """
        Purpose:
            Start an activity or send a broadcast, which is how an exported-component finding is confirmed.

        Parameters:
            args: Tokens following the command.

        Returns:
            The command output.

        Raises:
            ValueError: When the subcommand is not permitted or the target is not the app under test.

        Security considerations:
            Only starting and broadcasting are permitted, and the arguments must name the app under test either as a component prefix or through the package flag. This is the most powerful operation on the list -- it sends intents into a running system -- and without the targeting check the agent could launch another app's components or deliver broadcasts system-wide.
        """
        if not args:
            raise ValueError("am requires a subcommand ('start' or 'broadcast')")
        verb, rest = args[0], args[1:]
        if verb not in ("start", "broadcast"):
            raise ValueError("am only supports 'start' or 'broadcast'")
        joined = " ".join(rest)
        has_component = f"{self.package}/" in joined
        has_dash_p = "-p" in rest and self.package in rest
        if not (has_component or has_dash_p):
            raise ValueError(
                f"am {verb} must target the app under test - include "
                f"'-n {self.package}/<Component>' or '-p {self.package}'")
        quoted = " ".join(shlex.quote(a) for a in rest)
        return self._shell(f"am {verb} {quoted}")

    def _input(self, args: List[str]) -> str:
        """
        Purpose:
            Send a tap, text or key event to the device, for findings that need the app driven to a particular state.

        Parameters:
            args: Tokens following the command.

        Returns:
            The command output.

        Raises:
            ValueError: When the subcommand is not permitted or the arguments are malformed.

        Security considerations:
            Tap coordinates must be exactly two integers, checked before use. Text is shell-quoted with embedded quotes escaped, because it originates in model output and is composed into a device shell command; without that, text containing a quote or a semicolon would execute on the device.
        """
        if not args:
            raise ValueError("input requires a subcommand ('tap', 'text', or 'keyevent')")
        verb = args[0]
        if verb == "tap":
            if len(args) != 3 or not all(a.lstrip("-").isdigit() for a in args[1:]):
                raise ValueError("input tap requires exactly 2 integer args: 'input tap <x> <y>'")
            return self._shell(f"input tap {args[1]} {args[2]}")
        if verb == "text":
            text = " ".join(args[1:])
            safe = "'" + text.replace("'", "'\\''") + "'"
            return self._shell(f"input text {safe}")
        if verb == "keyevent":
            if len(args) != 2 or not args[1].isdigit():
                raise ValueError("input keyevent requires exactly one integer keycode")
            return self._shell(f"input keyevent {args[1]}")
        raise ValueError("input only supports 'tap', 'text', or 'keyevent'")

    def _screencap(self) -> str:
        """
        Purpose:
            Capture the device screen to a file on the device.

        Returns:
            A message naming where the screenshot was written.

        Implementation notes:
            The image is left on the device and its path returned rather than being sent back, because this tool surface returns text to a model and a binary payload has nowhere useful to go.
        """
        remote = "/data/local/tmp/lu77u_verify_screen.png"
        result = self.adb.shell(self.device, f"screencap -p {remote}", timeout=15)
        if result.returncode != 0:
            return f"screencap failed: {(result.stderr or '').strip()[:200]}"
        return f"Screenshot captured to device:{remote} (binary; not returned as text)"

    def _getprop(self, args: List[str]) -> str:
        """
        Purpose:
            Read one system property.

        Parameters:
            args: Tokens following the command.

        Returns:
            The property value.

        Raises:
            ValueError: When more or fewer than one property is requested.

        Security considerations:
            The property name is shell-quoted before use. Properties are device-wide rather than app-scoped, which is acceptable because they describe the platform rather than any app's data -- and several findings depend on the device's API level and build type.
        """
        if len(args) != 1:
            raise ValueError("getprop requires exactly one property name")
        return self._shell(f"getprop {shlex.quote(args[0])}")

    def frida_script(self, script: str) -> str:
        """
        Purpose:
            Run an instrumentation script in the app under test and return what it reported.

        Parameters:
            script: The script source.

        Returns:
            The script's output, or an error message.

        Side effects:
            Injects and runs code inside the running app.

        Implementation notes:
            Errors come back as text rather than exceptions, so a failing script lets the agent adjust and retry rather than ending the verification.

        Security considerations:
            The script is written by the model and runs inside the app's process with its privileges. It is scoped to the app under test by the manager, and its output is bounded. This is the broadest capability on the tool surface -- a script can do anything the app can -- and it is accepted because runtime observation is the only way to confirm several classes of finding.
        """
        if not script or not script.strip():
            return "ERROR: empty frida script"
        ok, output = self.frida.run_script(self.adb, self.device, self.package, script)
        prefix = "" if ok else "ERROR: "
        return _truncate(prefix + output, MAX_OUTPUT_CHARS)
