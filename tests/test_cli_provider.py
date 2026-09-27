#!/usr/bin/env python3
"""
Module: test_cli_provider

Purpose:
    The providers backed by a subscription CLI rather than an API key: how the prompt is delivered, how schemas are wrapped and unwrapped, how errors are classified, and how concurrency is capped.

Responsibilities:
    Pin that the prompt travels on standard input and never on the command line, that an array-rooted schema is wrapped for the CLI and unwrapped on the way back while an object-rooted one passes through untouched, that each error shape is classified correctly and trips or spares the circuit breaker accordingly, and that every CLI specification is registered and capped at one call in flight.

Dependencies:
    pytest, the CLI provider module, the error classifier, the finding schema, the provider factory and the user settings defaults.

Implementation notes:
    No real CLI is invoked and nothing here reaches the network or a live account. Two levels of fake are used deliberately: a stub executable on disk for the argument and standard input contract, which only a real process spawn exercises honestly, and a replaced process runner for the schema and error logic, which needs no process at all.

Security considerations:
    The prompt carries decompiled application source and can run to tens of kilobytes. Anything on a command line is readable by every other process on the machine through the process table, which is why the delivery channel is asserted from both directions rather than assumed.
"""

import json
import stat
import subprocess
import sys
import textwrap

import pytest

from lu77U_MobileSec.ai.cli_provider import (
    CLI_SPECS,
    CLIBackedProvider,
    CLIProcessError,
    _make_provider_class,
)
from lu77U_MobileSec.ai.errors import classify, ErrorClass
from lu77U_MobileSec.ai.schema import VULNERABILITY_SCHEMA


def _provider(spec_key: str, tmp_path, binary_path=None, **config_overrides):
    """
    Purpose:
        Build one CLI-backed provider from its specification, with a configuration the test controls.

    Parameters:
        spec_key: The key naming which CLI specification to build from.
        tmp_path: Temporary directory, accepted so every call site reads the same.
        binary_path: An explicit path to the executable, or empty to let the provider look one up.
        config_overrides: Configuration entries replacing the defaults, such as the concurrency cap.

    Returns:
        The constructed provider.
    """
    spec = CLI_SPECS[spec_key]
    cls = _make_provider_class(spec)
    config = {"model": "", "binary_path": binary_path or "", "max_concurrent_requests": 1}
    config.update(config_overrides)
    return cls(config=config, verbose=False)


def _write_stub(tmp_path, name: str, body: str):
    """
    Purpose:
        Write a small executable script to stand in for the real CLI binary.

    Parameters:
        tmp_path: Directory the script is written into.
        name: The script's filename.
        body: The script body, dedented before writing so it can be indented at the call site.

    Returns:
        The path to the script, as a string.

    Side effects:
        Writes the file and marks it executable.
    """
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


class TestStdinDiscipline:
    """
    Purpose:
        How the prompt reaches the CLI process.

    Security considerations:
        The prompt must never appear in the command line. It holds decompiled source and can be tens of kilobytes, and the command line of any process is visible to every other process on the machine.
    """
    def test_prompt_arrives_on_stdin_not_argv(self, tmp_path):
        """
        Purpose:
            Pin that the prompt reaches a real spawned process on standard input.

        Parameters:
            tmp_path: Directory the stub executable is written into.

        Implementation notes:
            The stub echoes its command line to standard error and returns what it read from standard input as its result, so the prompt coming back proves it arrived through a genuine process spawn rather than through a replaced runner.
        """
        binary = _write_stub(tmp_path, "fake_claude.py", """
            import sys, json
            sys.stderr.write(" ".join(sys.argv[1:]))
            stdin_text = sys.stdin.read()
            print(json.dumps({
                "is_error": False, "result": stdin_text,
                "usage": {"input_tokens": 3, "output_tokens": 5},
            }))
        """)
        p = _provider("claude_cli", tmp_path, binary_path=binary)
        needle = "SECRET-LOOKING-PROMPT-MARKER-" + ("x" * 200)
        result = p.analyze(needle, system_message="sys", schema={"type": "object"})
        assert "error" not in result
        assert result["response"] == needle

    def test_argv_never_contains_the_prompt_text(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin the negative: the prompt appears in what was written to standard input and in no part of the command line.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Replaces the process runner with a recorder.

        Security considerations:
            This is the assertion that would fail if the prompt were ever moved to a command line argument, which would expose decompiled source to every process on the machine.
        """
        captured = {}

        def fake_run(argv, input=None, capture_output=True, text=True,
                     timeout=None, cwd=None):
            """
            Purpose:
                Record the command line and standard input instead of spawning anything.

            Parameters:
                argv: The command line the provider assembled.
                input: The text the provider wrote to standard input.
                capture_output: Whether output is captured, unused here.
                text: Whether output is decoded, unused here.
                timeout: The call timeout.
                cwd: The working directory, unused here.

            Returns:
                A completed process carrying an empty successful envelope.

            Side effects:
                Records the command line and the standard input text.
            """
            captured["argv"] = argv
            captured["stdin"] = input
            return subprocess.CompletedProcess(
                argv, 0,
                stdout=json.dumps({"is_error": False, "result": "{}"}),
                stderr="")

        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.subprocess.run", fake_run)
        p = _provider("claude_cli", tmp_path, binary_path="/usr/bin/true")
        needle = "PROMPT-MARKER-" + ("y" * 500)
        p.analyze(needle, system_message="sys", schema={"type": "object"})
        assert needle in captured["stdin"]
        assert not any(needle in str(a) for a in captured["argv"])


class TestSchemaWrapUnwrap:
    """
    Purpose:
        The reshaping a schema needs before a schema-enforcing CLI will accept it, and the unwrapping of what comes back.

    Implementation notes:
        The finding schema is rooted at an array, and a schema-enforcing CLI requires an object root, which was confirmed against the real tool. Every other schema in this codebase is already object-rooted and must pass through untouched: wrapping the agent loop's next-action schema as well would turn a decision about what to do next into what reads like a finished report.
    """
    def _run_with_stub_result(self, tmp_path, monkeypatch, result_obj):
        """
        Purpose:
            Build a provider whose process runner returns one fixed structured result.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Replaces the process runner.
            result_obj: The structured result the stubbed CLI returns.

        Returns:
            The provider, ready to analyse.
        """
        def fake_run(argv, input=None, capture_output=True, text=True,
                     timeout=None, cwd=None):
            """
            Purpose:
                Return the fixed structured result without spawning anything.

            Parameters:
                argv: The command line the provider assembled.
                input: The text the provider wrote to standard input.
                capture_output: Whether output is captured, unused here.
                text: Whether output is decoded, unused here.
                timeout: The call timeout.
                cwd: The working directory, unused here.

            Returns:
                A completed process carrying the fixed result in a successful envelope.
            """
            return subprocess.CompletedProcess(
                argv, 0,
                stdout=json.dumps({
                    "is_error": False,
                    "structured_output": result_obj,
                }),
                stderr="")
        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.subprocess.run", fake_run)
        return _provider("claude_cli", tmp_path, binary_path="/usr/bin/true")

    def test_array_rooted_schema_is_wrapped_and_unwrapped(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that the array-rooted finding schema is wrapped for the CLI and the response is unwrapped back to a list.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Replaces the process runner.

        Implementation notes:
            The fake returns the wrapped shape a CLI given the wrapped schema would actually return, rather than the bare list, so the test fails if the wrap is removed on either side instead of passing because both sides were skipped.
        """
        finding = {"title": "x", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                   "file": "f.java", "line": "1", "description": "d",
                   "recommendation": "r", "cwe": "CWE-798", "owasp_mobile": "M1"}
        p = self._run_with_stub_result(tmp_path, monkeypatch, {"vulnerabilities": [finding]})
        result = p.analyze("find bugs", system_message="s", schema=VULNERABILITY_SCHEMA)
        assert "error" not in result
        parsed = json.loads(result["response"])
        assert isinstance(parsed, list)
        assert parsed == [finding]

    def test_object_rooted_schema_passes_through_unwrapped(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that an object-rooted schema is neither wrapped on the way out nor unwrapped on the way back.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Replaces the process runner.

        Implementation notes:
            A wrapped next-action response would be read as a report, so the returned value is asserted to be the same mapping rather than merely to be non-empty.
        """
        action = {"action": "list_files", "path": "."}
        p = self._run_with_stub_result(tmp_path, monkeypatch, action)
        object_schema = {"type": "object", "properties": {"action": {"type": "string"}},
                          "required": ["action"]}
        result = p.analyze("what next", system_message="s", schema=object_schema)
        assert "error" not in result
        parsed = json.loads(result["response"])
        assert isinstance(parsed, dict)
        assert parsed == action


class TestErrorClassification:
    """
    Purpose:
        How each failure shape is classified, and whether it opens the provider's circuit breaker.
    """
    def test_binary_not_found_trips_fatal_auth_without_spawning(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a missing binary is a fatal configuration failure reported without spawning anything.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Removes the executable from the lookup path and records any spawn attempt.

        Implementation notes:
            Spawning is asserted not to have happened, because a missing binary is known before the call and attempting it anyway would produce an operating system error the classifier would have to guess at.
        """
        called = []
        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.subprocess.run",
            lambda *a, **k: called.append(1))
        p = _provider("claude_cli", tmp_path, binary_path="")
        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.shutil.which", lambda name: None)
        result = p.analyze("hi")
        assert result.get("fatal") is True
        assert result.get("error_class") == "fatal_auth"
        assert p.unavailable is not None
        assert not called

    def test_quota_message_trips_the_circuit(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a spent subscription quota is fatal and that the next call short-circuits instead of spawning again.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Replaces the process runner, first with a quota response and then with a spawn recorder.

        Implementation notes:
            The second half is the point of the circuit breaker: without it every remaining region of a scan spends a full-size prompt to be told the same thing.
        """
        def fake_run(argv, input=None, capture_output=True, text=True,
                     timeout=None, cwd=None):
            """
            Purpose:
                Return a spent-quota error envelope without spawning anything.

            Parameters:
                argv: The command line the provider assembled.
                input: The text the provider wrote to standard input.
                capture_output: Whether output is captured, unused here.
                text: Whether output is decoded, unused here.
                timeout: The call timeout.
                cwd: The working directory, unused here.

            Returns:
                A completed process carrying the quota error envelope.
            """
            return subprocess.CompletedProcess(
                argv, 0,
                stdout=json.dumps({
                    "is_error": True, "api_error_status": 429,
                    "result": "Claude usage limit reached. Your limit will reset at 8pm.",
                }),
                stderr="")
        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.subprocess.run", fake_run)
        p = _provider("claude_cli", tmp_path, binary_path="/usr/bin/true")
        result = p.analyze("hi")
        assert result.get("error_class") == "fatal_quota"
        assert p.unavailable is not None

        calls = []
        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.subprocess.run",
            lambda *a, **k: calls.append(1))
        result2 = p.analyze("hi again")
        assert result2.get("short_circuited") is True
        assert not calls

    def test_timeout_is_transient_not_fatal(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a call that timed out is transient and leaves the circuit closed.

        Parameters:
            tmp_path: Temporary directory.
            monkeypatch: Makes the process runner raise a timeout.

        Implementation notes:
            One hung call is an ordinary event on a long prompt, and treating it as fatal would abandon the rest of a scan over a single slow turn.
        """
        def fake_run(argv, input=None, capture_output=True, text=True,
                     timeout=None, cwd=None):
            """
            Purpose:
                Raise a timeout instead of spawning anything.

            Parameters:
                argv: The command line the provider assembled.
                input: The text the provider wrote to standard input.
                capture_output: Whether output is captured, unused here.
                text: Whether output is decoded, unused here.
                timeout: The call timeout.
                cwd: The working directory, unused here.

            Raises:
                subprocess.TimeoutExpired: Always, standing in for a call that hung.
            """
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)
        monkeypatch.setattr(
            "lu77U_MobileSec.ai.cli_provider.subprocess.run", fake_run)
        p = _provider("claude_cli", tmp_path, binary_path="/usr/bin/true")
        result = p.analyze("hi")
        assert result.get("fatal") is not True
        assert p.unavailable is None


class TestConcurrencyDefaults:
    """
    Purpose:
        The concurrency cap on CLI-backed providers and their registration in the factory.
    """
    def test_default_settings_pin_cli_providers_to_one_in_flight_call(self):
        """
        Purpose:
            Pin that every CLI-backed provider ships capped at a single call in flight.

        Implementation notes:
            Each call is a process, and a subscription CLI is rate limited against the account rather than against a key, so running several at once buys no throughput and reaches the limit sooner.
        """
        from lu77U_MobileSec.config import user_settings

        for name in user_settings.CLI_PROVIDERS:
            cfg = user_settings.DEFAULT_SETTINGS["providers"][name]
            assert cfg["max_concurrent_requests"] == 1

    def test_provider_honors_the_max_concurrent_requests_config(self, tmp_path):
        """
        Purpose:
            Pin that a CLI-backed provider reads its concurrency cap from its configuration.

        Parameters:
            tmp_path: Temporary directory.

        Implementation notes:
            The gate itself is inherited from the base provider unmodified; what is checked here is that the inherited wiring still reads a CLI provider's configuration the same way.
        """
        p = _provider("claude_cli", tmp_path, binary_path="/usr/bin/true",
                       max_concurrent_requests=1)
        assert p._gate_width == 1

    def test_every_cli_spec_is_registered_in_the_factory(self):
        """
        Purpose:
            Pin that every CLI specification has a class registered in the factory under its own key.

        Implementation notes:
            A specification with no registered class is a provider the settings page offers and the factory cannot build, which fails only once the user selects it.
        """
        from lu77U_MobileSec.ai.provider_factory import PROVIDER_CLASSES

        for key in CLI_SPECS:
            assert key in PROVIDER_CLASSES
            assert PROVIDER_CLASSES[key].name == key
