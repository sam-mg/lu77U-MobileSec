#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.ollama_lifecycle

Purpose:
    Manage a local Ollama server for the duration of a scan: start one if none is running, let the user pick a model, and shut down only what this process started.

Responsibilities:
    Detect the binary and the running server, launch and wait for readiness, present the model chooser, and stop cleanly.

Dependencies:
    shutil, subprocess, .ollama_models for the health probe, ..config.user_settings, ..ui.colors.

Implementation notes:
    Ownership is tracked explicitly: a server that was already running belongs to the user and is never stopped, while one this process launched is always stopped. Getting that wrong would kill a server the user was relying on for something else.

Security considerations:
    Launches a subprocess with a fixed argument list and no shell. The server binds locally and is not exposed beyond what Ollama itself does.
"""

import contextlib
import shutil
import subprocess
import time
from typing import Optional

from . import ollama_models
from ..config import user_settings
from ..ui.colors import Colors
from ..utils.verbose import verbose_print

LOCAL_HOST = "http://localhost:11434"
_START_TIMEOUT = 30.0
_POLL_INTERVAL = 0.5

class OllamaLifecycle:
    """
    Purpose:
        Owns a local Ollama server for the duration of a scan.

    Attributes:
        verbose: Whether lifecycle activity is traced.
        host: Local server URL from settings.
        _started_by_us: Whether this object launched the server, which decides whether it may stop it.
        _proc: The launched process handle, or None.

    Invariants:
        The server is stopped only when this object started it. A server found already running is left alone on exit.

    Thread-safety:
        Not synchronised. Intended to be driven from one thread, typically the interactive setup flow.
    """
    def __init__(self, verbose: bool = False):
        """
        Purpose:
            Create a lifecycle manager bound to the configured local host.

        Parameters:
            verbose: Enables tracing.

        Side effects:
            Reads user settings.

        Postconditions:
            No server has been started and no process is owned.
        """
        self.verbose = verbose
        self.host = user_settings.get_provider_config("ollama").get("local_host", LOCAL_HOST)
        self._started_by_us = False
        self._proc: Optional[subprocess.Popen] = None

    def binary_installed(self) -> bool:
        """
        Purpose:
            Check whether the ollama executable is on PATH.

        Returns:
            True when the binary can be found.

        Implementation notes:
            Resolved through PATH rather than a fixed location, since Ollama installs to different places per platform and package manager.
        """
        return shutil.which("ollama") is not None

    def server_running(self) -> bool:
        """
        Purpose:
            Check whether a local Ollama server is already answering.

        Returns:
            True when the host responds.

        Side effects:
            Makes a short-timeout HTTP request.
        """
        return ollama_models.is_server_running(self.host)

    def ensure_server(self) -> bool:
        """
        Purpose:
            Guarantee a local Ollama server is available, starting one if necessary.

        Returns:
            True when a server is ready to serve requests.

        Side effects:
            May launch a subprocess, prints user-facing status, and stops the process it started if readiness times out.

        Postconditions:
            On a True return a server is answering. On False nothing this function started is left running.

        Implementation notes:
            An already-running server short-circuits immediately and is explicitly not adopted for shutdown. The server is launched with its output discarded, because Ollama logs continuously and would otherwise flood the terminal the user is reading scan progress in. Readiness is polled rather than assumed after launch: the process exists long before the port accepts connections, and issuing requests in that window fails confusingly. A timeout stops the process that was started, so a failed launch does not leave an orphan holding the port.

        Security considerations:
            The argument vector is a fixed literal; nothing user-supplied reaches the process launch.
        """
        if self.server_running():
            verbose_print("Local Ollama server already running - leaving it alone", self.verbose)
            return True

        if not self.binary_installed():
            print(f"{Colors.ERROR}[!] The 'ollama' binary is not installed.{Colors.RESET}")
            print(f"{Colors.INFO}    Install it from https://ollama.com/download, "
                  f"or switch to another provider / Ollama Cloud in Settings.{Colors.RESET}")
            return False

        print(f"{Colors.INFO}Starting local Ollama server...{Colors.RESET}")
        try:
            self._proc = subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._started_by_us = True
        except Exception as e:
            print(f"{Colors.ERROR}[!] Failed to launch 'ollama serve': {e}{Colors.RESET}")
            return False

        deadline = time.time() + _START_TIMEOUT
        while time.time() < deadline:
            if self.server_running():
                print(f"{Colors.SUCCESS}Local Ollama server is ready ({self.host}).{Colors.RESET}")
                return True
            time.sleep(_POLL_INTERVAL)

        print(f"{Colors.ERROR}[!] Ollama server did not become ready within "
              f"{int(_START_TIMEOUT)}s.{Colors.RESET}")
        self.stop()
        return False

    def local_models(self):
        """
        Purpose:
            List the models installed on the local server.

        Returns:
            Model names, empty when the server is unreachable or has none.
        """
        return ollama_models.list_local_models(self.host)

    def select_model(self, menu_system) -> Optional[str]:
        """
        Purpose:
            Let the user choose a local model, defaulting to the one they chose last time.

        Parameters:
            menu_system: Provides the input prompt, injected so this module does not depend on the terminal UI.

        Returns:
            The selected model name, or None when there are no models or the choice was invalid.

        Side effects:
            Prints a menu, reads input, and persists the choice to settings.

        Implementation notes:
            A remembered model that is still installed becomes the Enter-key default, which makes re-running a scan a single keypress. An empty model list is a guidance case rather than an error: the message names a concrete pull command, because "no models found" alone leaves a new user stuck. An invalid selection returns None rather than re-prompting, leaving loop control to the caller. Non-numeric input is treated exactly like an out-of-range number: the conversion error is suppressed and falls through to the same invalid-selection message.
        """
        models = self.local_models()
        remembered = user_settings.get_provider_config("ollama").get("model")

        if not models:
            print(f"{Colors.WARNING}No local Ollama models found.{Colors.RESET}")
            print(f"{Colors.INFO}    Pull one with e.g.  ollama pull llama3.1:8b  "
                  f"then re-run, or use Ollama Cloud in Settings.{Colors.RESET}")
            return None

        print(f"\n{Colors.CYAN}Local Ollama models:{Colors.RESET}")
        print(f"╭{'─' * 40}╮")
        for idx, name in enumerate(models, 1):
            marker = "  (current)" if name == remembered else ""
            label = f"{name}{marker}"
            print(f"│ {Colors.WHITE}{idx}. {label}{Colors.RESET}".ljust(50) + "│")
        print(f"╰{'─' * 40}╯")

        if remembered in models:
            prompt = f"Select model (Enter to keep '{remembered}')"
        else:
            prompt = "Select model"
        choice = menu_system.get_user_input(prompt)

        if not choice and remembered in models:
            return remembered
        with contextlib.suppress(ValueError, TypeError):
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                chosen = models[idx]
                user_settings.set_provider_field("ollama", "model", chosen)
                return chosen
        print(f"{Colors.ERROR}Invalid selection.{Colors.RESET}")
        return None

    def stop(self):
        """
        Purpose:
            Stop the server, but only if this object started it.

        Side effects:
            Terminates and, if necessary, kills the child process.

        Postconditions:
            Ownership is released, so a second call is a no-op.

        Implementation notes:
            Terminate first with a bounded wait, then kill. Ollama unloads model weights on a clean shutdown, so giving it a few seconds avoids leaving several gigabytes resident. Ownership is cleared in a finally block, so a failure to stop does not leave this object believing it still owns a process it can no longer control.
        """
        if self._started_by_us and self._proc is not None:
            verbose_print("Stopping the Ollama server this process started", self.verbose)
            try:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            except Exception as e:
                verbose_print(f"Error stopping ollama serve: {e}", self.verbose)
            finally:
                self._proc = None
                self._started_by_us = False

    def __enter__(self):
        """
        Purpose:
            Enter the context manager.

        Returns:
            This lifecycle object.
        """
        return self

    def __exit__(self, exc_type_unused, exc_unused, tb_unused):
        """
        Purpose:
            Stop the owned server on leaving the context.

        Parameters:
            exc_type_unused: Exception type, if the block raised; unused, since cleanup does not branch on the error.
            exc_unused: Exception instance, if the block raised; unused, since cleanup does not branch on the error.
            tb_unused: Traceback, if the block raised; unused, since cleanup does not branch on the error.

        Returns:
            False, so an exception in the block propagates. Cleanup must not swallow the error that triggered it.

        Side effects:
            Stops the server this object started.
        """
        self.stop()
        return False

def prepare_ollama_local(menu_system, verbose: bool = False) -> Optional["OllamaLifecycle"]:
    """
    Purpose:
        Bring the local Ollama path fully online -- server running and model chosen -- in one call.

    Parameters:
        menu_system: Provides the model-selection prompt.
        verbose: Enables tracing.

    Returns:
        The lifecycle object, still owning the server, or None when setup failed.

    Side effects:
        May start a server, prompt the user, and persist the chosen model.

    Postconditions:
        On None, any server this call started has been stopped. On success the caller owns the returned lifecycle and must stop it.

    Implementation notes:
        The cleanup on a failed model selection is what makes the None return safe: without it, abandoning the chooser would leave a server running that nothing would ever stop.
    """
    lifecycle = OllamaLifecycle(verbose=verbose)
    if not lifecycle.ensure_server():
        return None
    model = lifecycle.select_model(menu_system)
    if not model:
        lifecycle.stop()
        return None
    return lifecycle
