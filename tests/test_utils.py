#!/usr/bin/env python3
"""
Module: test_utils

Purpose:
    Verbose-log redaction, the curation that decides what reaches the scan log, and the string helpers that feed reports.

Responsibilities:
    Pin that secrets never survive into a log line, that URL extraction and truncation behave, and that the scan log carries the narrative of a run without the engine's internal chatter and without ever swallowing a problem.

Dependencies:
    pytest and the verbose and string helper modules.

Security considerations:
    The redaction cases are the control that keeps API keys, bearer tokens and passwords out of the log file and the live log, both of which are written to disk and shown in the browser. A gap here leaks a real credential from the user's own configuration.
"""

import hmac

import pytest

from lu77U_MobileSec.utils.string_utils import extract_urls_from_text, truncate_text
from lu77U_MobileSec.utils.verbose import redact


def _contains_constant_time(haystack, needle):
    """
    Purpose:
        Decide whether needle occurs anywhere in haystack by comparing every window with hmac.compare_digest and combining the results without short-circuiting, rather than relying on the interpreter's own substring search, since what this checks for is a credential that redaction is supposed to have removed.

    Parameters:
        haystack: The text to search.
        needle: The text to look for inside it.

    Returns:
        Whether needle occurs anywhere in haystack.
    """
    width = len(needle)
    if width == 0:
        return True
    found = False
    for start in range(len(haystack) - width + 1):
        found |= hmac.compare_digest(haystack[start:start + width], needle)
    return found


class TestRedact:
    """
    Purpose:
        Masking of secrets in log lines.
    """
    @pytest.mark.parametrize("text,secret", [
        ("GET https://x/models?key=AIzaSyABCDEF123 failed", "AIzaSyABCDEF123"),
        ("POST /v1?api_key=sk-live-9999 ->500", "sk-live-9999"),
        ("Authorization: Bearer sk-ant-api03-abc.def", "sk-ant-api03-abc.def"),
        ('{"api_key": "sk-12345", "model": "x"}', "sk-12345"),
        ("password=hunter2&next=/", "hunter2"),
    ])
    def test_secrets_are_masked(self, text, secret):
        """
        Purpose:
            Pin that each shape a credential arrives in is masked out of the line.

        Parameters:
            text: A log line carrying a secret.
            secret: The substring that must not survive.

        Implementation notes:
            The cases cover a query parameter, a request body, an authorization header and a form field, because a log line is assembled from whichever of these the failing call happened to use.

        Security considerations:
            The values here are invented and match no real credential. Both halves are asserted, that the secret is gone and that a mask is present, so a redaction that dropped the line entirely instead of masking it would still be caught.
        """
        out = redact(text)
        assert not _contains_constant_time(out, secret)
        assert "***" in out

    def test_surrounding_text_survives(self):
        """
        Purpose:
            Pin that redaction masks only the secret and leaves the rest of the line readable.

        Implementation notes:
            A redaction that blanked the whole line would be safe and useless: the line exists to say which call failed.
        """
        assert redact("GET https://x/models?key=AAA failed").startswith("GET https://x/models?key=")

    def test_plain_messages_are_untouched(self):
        """
        Purpose:
            Pin that a line holding no secret passes through unchanged.
        """
        message = "Decompiling APK with JADX (4231 files)"
        assert redact(message) == message

    def test_non_string_input(self):
        """
        Purpose:
            Pin that a non-string argument is coerced rather than raising.

        Implementation notes:
            Redaction sits in the logging path, so raising there would turn a diagnostic line into a crash.
        """
        assert redact(42) == "42"

class TestExtractUrls:
    """
    Purpose:
        Pulling URLs out of free text.
    """
    def test_full_url_including_path_and_query(self):
        """
        Purpose:
            Pin that a URL is extracted whole, with its path and query intact.
        """
        urls = extract_urls_from_text("see https://a.example.com/p?q=1&r=2 now")
        assert urls == ["https://a.example.com/p?q=1&r=2"]

    def test_trailing_sentence_punctuation_is_dropped(self):
        """
        Purpose:
            Pin that a full stop ending the sentence is not taken as part of the URL.
        """
        assert extract_urls_from_text("go to http://b.test/x.") == ["http://b.test/x"]

    def test_character_class_is_not_an_accidental_range(self):
        """
        Purpose:
            Pin that text with no link in it yields nothing, including an email address.

        Implementation notes:
            The original pattern wrote a character class whose hyphen formed a range spanning most of ASCII, so it matched almost any text. These two cases fail loudly if that shape comes back.
        """
        assert extract_urls_from_text("mailto:someone@example.com") == []
        assert extract_urls_from_text("no links here") == []

    def test_results_are_deduplicated(self):
        """
        Purpose:
            Pin that a URL appearing twice is reported once.
        """
        text = "https://a.test/x and again https://a.test/x"
        assert extract_urls_from_text(text) == ["https://a.test/x"]

    def test_empty_input(self):
        """
        Purpose:
            Pin that empty text yields no URLs.
        """
        assert extract_urls_from_text("") == []

class TestTruncate:
    """
    Purpose:
        Shortening text to a length budget.
    """
    def test_short_text_is_returned_as_is(self):
        """
        Purpose:
            Pin that text already within the budget is returned unchanged.
        """
        assert truncate_text("abc", max_length=10) == "abc"

    def test_long_text_keeps_the_length_budget(self):
        """
        Purpose:
            Pin that truncated text fits the budget including its ellipsis rather than exceeding it by three characters.
        """
        out = truncate_text("x" * 100, max_length=20)
        assert len(out) == 20 and out.endswith("...")


class TestScanLogIsCurated:
    """
    Purpose:
        That the scan log carries the narrative of a run and not the engine's internal chatter.

    Attributes:
        KEEP: One line of each shape the scan log is supposed to carry.
        DROP: One line of each kind of chatter that made a real scan log unreadable.

    Implementation notes:
        A real run emits around 1500 lines to say what 90 lines say better, which does not dilute the signal so much as bury it. The terminal still receives everything under the verbose flag; this is only about what reaches the live log and the log file.
    """
    KEEP = [
        "BasicInfoExtractor initializing",
        "Androguard available: True",
        "Java/Kotlin APK detected with 1 DEX files",
        "JavaDetector indicators: ['DEX files: 1 found']",
        "Java detection confirmed",
        "Found 7 native libraries",
        "Loading APK with androguard",
        "APK loaded successfully",
        "Package name: jakhar.aseem.diva",
        "Resolved app name: Diva",
        "Version: 1.0 (code: 1)",
        "SDK versions - Min: 15, Target: 23",
        "Extracting application components",
        "Found 17 activities",
        "Found 1 providers",
        "Primary framework (dict): Java",
        "JADX path configured as: /opt/homebrew/bin/jadx",
        "Listing ADB devices",
        "Running: adb devices",
        "adb rc=0",
        "Total devices: 0",
        "Starting Java/Kotlin APK Analysis...",
        "Creating output directory structure for: /tmp/x/DIVA.apk",
        "Generated timestamp: 20260815_211420",
        "APK name: DIVA",
        "Initializing OllamaProvider (mode=cloud, model=x, host=y)",
        "Decompiling APK...",
        "Decompiled output directory: /tmp/x_jadx_output",
        "Code graph built: 19 app classes, 20 flagged files",
        "Running agentic (tool-using) analysis...",
        "Fan-out: 5 region agents - region-1-a(110)",
        "Partitioning 360 flagged nodes over 6696 call edges from 8 entry points",
        "Starting Ollama analysis - Prompt: 36554 chars, System: 135651 chars",
        "The LLM is requesting to read `sources/a/B.java`.",
        "Giving read access to `sources/a/B.java` (283 lines sent to the LLM).",
        "Processing response text",
        "Successfully parsed as direct JSON",
        "Parsed JSON is a list with 1 items",
        "Validating vulnerability keys: ['title', 'file']",
        "Normalizing vulnerability result.",
        "Agent step 2: recorded 1 new finding",
        "Agent finished at step 8 with 13 findings",
        "Agentic analysis produced 32 findings",
        "SAST manifest: 12 findings",
        "SAST: 15 deterministic findings total",
        "Deterministic scanners produced 15 findings",
        "Total time taken: 1462.25 seconds",
        "Gates: 7/47 findings adjusted by the mechanical checks",
        "Verifying rule findings: batch 1/1 (3 findings)",
        "Chains: 153 candidates, evaluating the top 24 (priority chains first)",
        "Chains: 0 confirmed of 24 candidates",
        "JSONExporter initialized",
        "Starting JSON export",
        "JSON Saved in /tmp/x.json",
    ]

    DROP = [
        "is_framework_layout_file called for: HardcodeActivity.java",
        "Layout HardcodeActivity.java is app-specific",
        "Attempt 1/3",
        "parse_json_response start",
        "Response is already a dict, extracting 'response' field",
        "Split text into 4 blocks for pattern matching",
        "Pattern matched for key 'file': A.java",
        "Normalized vulnerability result: {'file': 'A.java'}",
        "    Severity: Medium",
        "    File: AndroidManifest.xml",
        "    Line: 12",
        "Starting score: 100.0",
        "After critical (2): 60.0",
        "Final security score (clamped): 0.0",
        "Getting primary framework name",
        "Frameworks sorted by confidence: [('Java', 0.8)]",
        "setup_androguard_logging called",
        "ANDROGUARD_LOGGING setting: True",
        "Ollama log path computed for request timestamp 2026: /tmp/x.md",
        "File size: 1502294 bytes = 1.43 MB",
    ]

    @pytest.mark.parametrize("message", KEEP)
    def test_narrative_lines_are_kept(self, message):
        """
        Purpose:
            Pin that each shape of narrative line is treated as a milestone.

        Parameters:
            message: A log line the scan log is supposed to carry.
        """
        from lu77U_MobileSec.utils.verbose import is_milestone

        assert is_milestone(message)

    @pytest.mark.parametrize("message", DROP)
    def test_internal_chatter_is_dropped(self, message):
        """
        Purpose:
            Pin that each kind of internal chatter is not treated as a milestone.

        Parameters:
            message: A log line the scan log is supposed to drop.
        """
        from lu77U_MobileSec.utils.verbose import is_milestone

        assert not is_milestone(message)

    @pytest.mark.parametrize("message", [
        "Could not read /x/y.java: permission denied",
        "JADX decompilation failed",
        "Semgrep: timed out after 600s; skipping",
        "WARNING: provider returned no findings",
        "Scan stopped by user",
        "ilspycmd is not configured or on PATH",
    ])
    def test_problems_are_never_filtered_out(self, message):
        """
        Purpose:
            Pin that failures, warnings and refusals always reach the log whatever else is filtered.

        Parameters:
            message: A line reporting a problem.

        Implementation notes:
            An allowlist that swallows errors turns a quiet log into a lying one, which is worse than a noisy one because the user reads a scan that hid its failures as a scan that found nothing.
        """
        from lu77U_MobileSec.utils.verbose import is_milestone

        assert is_milestone(message)

    def test_the_sink_only_receives_milestones(self):
        """
        Purpose:
            Pin end to end that a registered sink receives the narrative lines and neither of the chatter lines.

        Side effects:
            Registers a sink for the duration of the test and removes it afterwards.

        Implementation notes:
            Asserted through the real registration path rather than by calling the filter directly, because the filter being right and the sink being fed unfiltered are two different bugs.
        """
        from lu77U_MobileSec.utils import verbose as vmod

        seen = []
        vmod.register_sink(seen.append)
        try:
            vmod.verbose_print("Package name: com.example")
            vmod.verbose_print("is_framework_layout_file called for: A.java")
            vmod.verbose_print("    Severity: Medium")
            vmod.verbose_print("Decompilation failed: no output")
        finally:
            vmod.unregister_sink(seen.append)
        assert seen == ["Package name: com.example",
                        "Decompilation failed: no output"]

    def test_the_terminal_still_receives_everything(self, capsys):
        """
        Purpose:
            Pin that the verbose flag puts chatter on the terminal even though it never reaches the log.

        Parameters:
            capsys: Captures what was printed.

        Implementation notes:
            The terminal is the debugging channel and keeps the detail; curation applies to the log the user reads, not to the output a developer turned on deliberately.
        """
        from lu77U_MobileSec.utils import verbose as vmod

        vmod.verbose_print("is_framework_layout_file called for: A.java", verbose=True)
        assert "is_framework_layout_file" in capsys.readouterr().out

    def test_redaction_still_applies_to_what_survives(self):
        """
        Purpose:
            Pin that a line which passes curation is still redacted before it reaches the sink.

        Side effects:
            Registers a sink for the duration of the test and removes it afterwards.

        Security considerations:
            Curation and redaction are separate steps, and a line that qualifies as a milestone can carry a credential in a command it is reporting. This pins that surviving the filter does not mean bypassing the mask.
        """
        from lu77U_MobileSec.utils import verbose as vmod

        seen = []
        vmod.register_sink(seen.append)
        try:
            vmod.verbose_print("Running: adb shell curl 'https://x/?api_key=SECRETVALUE'")
        finally:
            vmod.unregister_sink(seen.append)
        assert seen and "SECRETVALUE" not in seen[0]
