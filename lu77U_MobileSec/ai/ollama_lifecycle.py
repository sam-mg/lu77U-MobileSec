"""First-class local Ollama lifecycle"""

import shutil
import subprocess
import time
from typing import Optional

from . import ollama_models
from ..config import user_settings, credentials
from ..ui.colors import Colors
from ..utils.verbose import verbose_print

LOCAL_HOST = "http://localhost:11434"
_START_TIMEOUT = 30.0  # seconds to wait for `ollama serve` to come up
_POLL_INTERVAL = 0.5

class OllamaLifecycle:
    """Detect / start / select / stop a local Ollama server for one run."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.host = user_settings.get_provider_config("ollama").get("local_host", LOCAL_HOST)
        self._started_by_us = False
        self._proc: Optional[subprocess.Popen] = None

    def binary_installed(self) -> bool:
        return shutil.which("ollama") is not None

    def server_running(self) -> bool:
        return ollama_models.is_server_running(self.host)

    def ensure_server(self) -> bool:
        """Ensure a local server is reachable. Returns True if usable.

        Starts ``ollama serve`` only if nothing is already listening; records
        whether we started it so :meth:`stop` won't touch a pre-existing one.
        """
        if self.server_running():
            verbose_print("Local Ollama server already running — leaving it alone", self.verbose)
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
        self.stop()  # tear down the one we started but that never came up
        return False

    def local_models(self):
        return ollama_models.list_local_models(self.host)

    def select_model(self, menu_system) -> Optional[str]:
        """Let the user pick a local model (or reuse the remembered one).

        Returns the chosen model name, or None to fall back to Cloud / cancel.
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
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                chosen = models[idx]
                user_settings.set_provider_field("ollama", "model", chosen)
                return chosen
        except (ValueError, TypeError):
            pass
        print(f"{Colors.ERROR}Invalid selection.{Colors.RESET}")
        return None

    def stop(self):
        """Stop the server only if this process started it."""
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
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

def prepare_ollama_local(menu_system, verbose: bool = False) -> Optional["OllamaLifecycle"]:
    """Convenience: ensure the server is up and a model is selected.

    Returns a live :class:`OllamaLifecycle` (caller must ``stop()`` it when the
    run finishes), or None if local Ollama couldn't be prepared.
    """
    lifecycle = OllamaLifecycle(verbose=verbose)
    if not lifecycle.ensure_server():
        return None
    model = lifecycle.select_model(menu_system)
    if not model:
        lifecycle.stop()
        return None
    return lifecycle