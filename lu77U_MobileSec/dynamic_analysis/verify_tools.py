"""Sandboxed tool surface for the dynamic-verification agent loop."""

import shlex
from typing import List

from ..analyzers.agent.tools import AgentTools
from .adb_manager import ADBManager, _ANDROID_PACKAGE_RE
from .frida_manager import FridaManager

MAX_OUTPUT_CHARS = 4000

def _truncate(text: str, limit: int) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"

class VerifyTools:
    """adb / Frida / source-read tools scoped to one device + one target app."""

    def __init__(self, adb: ADBManager, frida: FridaManager, device: str,
                package: str, jadx_output_dir, verbose: bool = False):
        if not _ANDROID_PACKAGE_RE.match(package or ""):
            raise ValueError(f"invalid package: {package!r}")
        self.adb = adb
        self.frida = frida
        self.device = device
        self.package = package
        self.verbose = verbose
        self.source_tools = AgentTools(jadx_output_dir)

    def read_source(self, path: str, start_line=None) -> str:
        """Same paged reader Phase 1 uses: a file bigger than one call's
        budget is shown a page at a time, and a repeat read of the same path
        auto-continues from where the last read left off instead of
        re-showing (or truncating away) the same content."""
        return self.source_tools.read_file(path, start_line=start_line)

    def adb_command(self, command: str) -> str:
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
        """Return a zero-arg callable performing the requested (validated)
        operation, or raise ``ValueError`` if the command isn't recognized or
        isn't scoped to ``self.package``."""
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
        result = self.adb.shell(self.device, cmd, timeout=timeout)
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        combined = (out + ("\n" + err if err else "")).strip()
        return combined or "(no output)"

    def _logcat(self) -> str:
        return self._shell(
            f"logcat -d -t 200 --pid=$(pidof -s {self.package} 2>/dev/null)")

    def _run_as(self, args: List[str]) -> str:
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
        if args != ["package", self.package]:
            raise ValueError(f"dumpsys is only allowed as 'dumpsys package {self.package}'")
        return self._shell(f"dumpsys package {self.package}")

    def _pidof(self, args: List[str]) -> str:
        if args != [self.package]:
            raise ValueError(f"pidof is only allowed as 'pidof {self.package}'")
        out = self._shell(f"pidof {self.package}")
        return out if out != "(no output)" else "(app not currently running — no pid)"

    def _pm(self, args: List[str]) -> str:
        if args[:2] == ["path", self.package]:
            return self._shell(f"pm path {self.package}")
        if args[:2] == ["dump", self.package]:
            return self._shell(f"pm dump {self.package}")
        raise ValueError(
            f"pm is only allowed as 'pm path {self.package}' or 'pm dump {self.package}'")

    def _am(self, args: List[str]) -> str:
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
                f"am {verb} must target the app under test — include "
                f"'-n {self.package}/<Component>' or '-p {self.package}'")
        quoted = " ".join(shlex.quote(a) for a in rest)
        return self._shell(f"am {verb} {quoted}")

    def _input(self, args: List[str]) -> str:
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
        remote = "/data/local/tmp/lu77u_verify_screen.png"
        result = self.adb.shell(self.device, f"screencap -p {remote}", timeout=15)
        if result.returncode != 0:
            return f"screencap failed: {(result.stderr or '').strip()[:200]}"
        return f"Screenshot captured to device:{remote} (binary; not returned as text)"

    def _getprop(self, args: List[str]) -> str:
        if len(args) != 1:
            raise ValueError("getprop requires exactly one property name")
        return self._shell(f"getprop {shlex.quote(args[0])}")

    def frida_script(self, script: str) -> str:
        if not script or not script.strip():
            return "ERROR: empty frida script"
        ok, output = self.frida.run_script(self.adb, self.device, self.package, script)
        prefix = "" if ok else "ERROR: "
        return _truncate(prefix + output, MAX_OUTPUT_CHARS)