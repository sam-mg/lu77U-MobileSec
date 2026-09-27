#!/usr/bin/env python3
"""
Module: test_xamarin

Purpose:
    Xamarin and .NET MAUI support: recovering assemblies out of the APK, mining strings from them, and building a code map when C# is available.

Responsibilities:
    Pin the compression decoder against both valid and corrupt input, the detection of every container layout, the extraction and its failure modes, the string sidecars, the assembly inventory, the code graph, and the analyzer's wiring to the external decompiler.

Dependencies:
    pytest, the Xamarin extractor, the Xamarin graph builder, the analyzer, the decompiler runner and the user settings.

Implementation notes:
    No real Xamarin application was available when this was written, so the container formats are exercised against fixtures built here, including a genuine compression round trip. That round trip is the one part of the pipeline that could silently produce plausible-looking rubbish instead of failing, which is why it is tested against real encoded blocks rather than a stub. The behaviour that carries the most weight is that a Xamarin scan degrades rather than fails: with no external decompiler there is no C# at all, and the whole scan then rests on the string sidecars written beside each recovered assembly, which is why several tests here exist only to hold that path open.

Security considerations:
    Every declared size and entry count in these containers comes from the file being analysed, so the refusal cases are what stop a crafted or corrupt application from driving an enormous allocation during a scan. The credentials and keys in the fixtures are invented and match nothing real.
"""

import struct
import zipfile
from pathlib import Path

import pytest

from lu77U_MobileSec.decompiler.xamarin_extractor import (
    XABA_MAGIC_LE, XALZ_MAGIC, decompress_xalz, extract_xamarin_assemblies,
    is_xamarin_apk, summarize_assemblies, write_string_sidecars)


def _lz4_literals_only(payload: bytes) -> bytes:
    """
    Purpose:
        Encode a payload as a compressed block holding only literals and no back-references.

    Parameters:
        payload: The bytes to encode.

    Returns:
        The encoded block.

    Implementation notes:
        A literals-only block is valid and is what a real compressor emits for incompressible input, so it exercises the decoder's literal path and its length extension without adding a compressor dependency to the test suite.
    """
    out = bytearray()
    length = len(payload)
    token = (15 << 4) if length >= 15 else (length << 4)
    out.append(token)
    if length >= 15:
        remaining = length - 15
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    out += payload
    return bytes(out)


def _lz4_with_match(prefix: bytes, repeats: int) -> tuple:
    """
    Purpose:
        Encode a block that emits a prefix and then repeats it through a back-reference.

    Parameters:
        prefix: The literal bytes emitted first, which must be shorter than the token's inline length limit.
        repeats: How many further copies the back-reference produces.

    Returns:
        The encoded block and the bytes it must decode to.

    Implementation notes:
        A match copy may overlap the write cursor, which is how runs are encoded, so a decoder that takes a slice instead of copying byte by byte produces wrong output here rather than raising.
    """
    out = bytearray()
    literal_len = len(prefix)
    assert literal_len < 15
    match_len = len(prefix) * repeats
    encoded_match = match_len - 4
    token_low = 15 if encoded_match >= 15 else encoded_match
    out.append((literal_len << 4) | token_low)
    out += prefix
    out += (len(prefix)).to_bytes(2, "little")
    if encoded_match >= 15:
        remaining = encoded_match - 15
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    return bytes(out), prefix + prefix * repeats


def _xalz(payload: bytes, block: bytes = None) -> bytes:
    """
    Purpose:
        Wrap a compressed block in the container header the extractor reads.

    Parameters:
        payload: The uncompressed bytes, used for the declared size.
        block: An encoded block to use, or None to encode the payload as literals.

    Returns:
        The complete container bytes.
    """
    block = block if block is not None else _lz4_literals_only(payload)
    return XALZ_MAGIC + struct.pack("<II", 0, len(payload)) + block


def _pe(body: bytes = b"") -> bytes:
    """
    Purpose:
        Build something executable-shaped enough for the extractor to accept.

    Parameters:
        body: Bytes appended after the header, used to make one fixture distinguishable from another.

    Returns:
        The fixture bytes.
    """
    return b"MZ\x90\x00" + b"\x00" * 60 + body


class TestLz4Decoder:
    """
    Purpose:
        The compression decoder, against valid blocks and against every way a block can be malformed.
    """
    def test_literals_only_round_trip(self):
        """
        Purpose:
            Pin that a literals-only block decodes back to exactly what was encoded.
        """
        payload = b"https://api.internal.example/v1/session?token=abc123" * 3
        assert decompress_xalz(_xalz(payload)) == payload

    def test_overlapping_match_is_copied_byte_by_byte(self):
        """
        Purpose:
            Pin that a back-reference overlapping the write cursor produces the repeated run.

        Implementation notes:
            This is the failure that does not announce itself: slicing instead of copying yields output of the right length and the wrong contents, which would flow into the string mining as plausible rubbish.
        """
        block, expected = _lz4_with_match(b"abcd", repeats=6)
        assert decompress_xalz(_xalz(expected, block)) == expected

    def test_long_literal_length_extension(self):
        """
        Purpose:
            Pin that a literal run long enough to need chained length bytes decodes correctly.
        """
        payload = bytes(range(256)) * 4
        assert decompress_xalz(_xalz(payload)) == payload

    def test_short_payload_returns_none(self):
        """
        Purpose:
            Pin that input too short to hold a header is refused.
        """
        assert decompress_xalz(b"XAL") is None

    def test_wrong_magic_returns_none(self):
        """
        Purpose:
            Pin that input with the wrong signature is refused.
        """
        assert decompress_xalz(b"NOPE" + b"\x00" * 20) is None

    def test_implausible_declared_size_is_refused(self):
        """
        Purpose:
            Pin that a header declaring an enormous uncompressed size is refused.

        Security considerations:
            The declared size comes from the file being analysed, so honouring it would let a crafted application drive a multi-gigabyte allocation in the middle of a scan.
        """
        blob = XALZ_MAGIC + struct.pack("<II", 0, 2 ** 31) + b"\x00" * 8
        assert decompress_xalz(blob) is None

    def test_size_mismatch_is_rejected(self):
        """
        Purpose:
            Pin that a block decoding to a different length than its header declares is refused.
        """
        payload = b"A" * 40
        lying = XALZ_MAGIC + struct.pack("<II", 0, 999) + _lz4_literals_only(payload)
        assert decompress_xalz(lying) is None

    def test_invalid_back_offset_is_rejected(self):
        """
        Purpose:
            Pin that a back-reference pointing before the start of the output is refused.
        """
        block = bytes([0x1F]) + b"a" + (99).to_bytes(2, "little") + bytes([0])
        assert decompress_xalz(XALZ_MAGIC + struct.pack("<II", 0, 10) + block) is None

    def test_truncated_block_is_rejected(self):
        """
        Purpose:
            Pin that a block cut short mid-payload is refused rather than decoded partially.
        """
        payload = b"B" * 40
        full = _lz4_literals_only(payload)
        blob = XALZ_MAGIC + struct.pack("<II", 0, len(payload)) + full[:10]
        assert decompress_xalz(blob) is None


def _apk(tmp_path: Path, entries: dict) -> str:
    """
    Purpose:
        Build an APK holding the given archive entries.

    Parameters:
        tmp_path: Directory the archive is written into.
        entries: A mapping of entry name to contents.

    Returns:
        The path to the archive, as a string.
    """
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return str(path)


class TestDetection:
    """
    Purpose:
        Recognising an application as Xamarin or MAUI from what its archive contains.
    """
    def test_plain_assemblies_are_detected(self, tmp_path):
        """
        Purpose:
            Pin that an archive holding uncompressed assemblies is detected.

        Parameters:
            tmp_path: Directory the fixture archive is written into.
        """
        apk = _apk(tmp_path, {"assemblies/MyApp.dll": _pe()})
        assert is_xamarin_apk(apk)

    def test_maui_blob_disguised_as_a_native_library_is_detected(self, tmp_path):
        """
        Purpose:
            Pin that a MAUI assembly store named like a native library is still detected.

        Parameters:
            tmp_path: Directory the fixture archive is written into.

        Implementation notes:
            Recent MAUI names the store with a native library extension, so a check based on the filename sees an ordinary native library and misses the framework entirely, which sends the whole application down the Java analysis path.
        """
        apk = _apk(tmp_path, {
            "lib/arm64-v8a/libassemblies.arm64-v8a.blob.so": XABA_MAGIC_LE + b"\x00" * 32})
        assert is_xamarin_apk(apk)

    def test_a_plain_java_apk_is_not_detected(self, tmp_path):
        """
        Purpose:
            Pin that an ordinary Java application is not mistaken for a Xamarin one.

        Parameters:
            tmp_path: Directory the fixture archive is written into.
        """
        apk = _apk(tmp_path, {"classes.dex": b"dex\n035\x00", "AndroidManifest.xml": b"x"})
        assert not is_xamarin_apk(apk)

    def test_a_corrupt_file_is_not_detected(self, tmp_path):
        """
        Purpose:
            Pin that a file that is not an archive is reported as not detected rather than raising.

        Parameters:
            tmp_path: Directory the corrupt file is written into.

        Implementation notes:
            Detection runs over every candidate before the scan starts, so raising there would fail the run on a file the user may not even have meant to analyse.
        """
        bad = tmp_path / "bad.apk"
        bad.write_bytes(b"not a zip")
        assert not is_xamarin_apk(str(bad))

    def test_a_missing_file_is_not_detected(self, tmp_path):
        """
        Purpose:
            Pin that a path that does not exist is reported as not detected rather than raising.

        Parameters:
            tmp_path: Directory the missing path is named under.
        """
        assert not is_xamarin_apk(str(tmp_path / "nope.apk"))


class TestExtraction:
    """
    Purpose:
        Recovering the assemblies out of an archive, in each layout and against each way the recovery can fail.
    """
    def test_plain_assemblies_are_written_out(self, tmp_path):
        """
        Purpose:
            Pin that uncompressed assemblies are written to the output directory under their own names.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = _apk(tmp_path, {"assemblies/MyApp.dll": _pe(b"secret-ish"),
                              "assemblies/System.Core.dll": _pe()})
        out = extract_xamarin_assemblies(apk, tmp_path / "out")
        assert out is not None
        assert {p.name for p in out.glob("*.dll")} == {"MyApp.dll", "System.Core.dll"}

    def test_compressed_assemblies_are_decompressed(self, tmp_path):
        """
        Purpose:
            Pin that a compressed assembly is written out decompressed and byte-identical to the original.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        body = _pe(b"https://api.example/v1/login")
        apk = _apk(tmp_path, {"assemblies/MyApp.dll": _xalz(body)})
        out = extract_xamarin_assemblies(apk, tmp_path / "out")
        assert (out / "MyApp.dll").read_bytes() == body

    @pytest.mark.parametrize("prefix", [
        "assemblies/", "assets/assemblies/", "unknown/assemblies/"])
    def test_assemblies_are_found_under_every_known_prefix(self, tmp_path, prefix):
        """
        Purpose:
            Pin that assemblies are recovered from each archive location they are known to appear under.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
            prefix: The archive path the assemblies sit under.

        Implementation notes:
            The location differs by toolchain version, and looking in only one of them produces a scan that recovers nothing while reporting no error.
        """
        archive = tmp_path / "app.apk"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(f"{prefix}App.dll", _pe())
        assert extract_xamarin_assemblies(str(archive), tmp_path / "out") is not None

    def test_a_non_xamarin_apk_yields_none(self, tmp_path):
        """
        Purpose:
            Pin that an archive with no assemblies in it yields nothing rather than an empty output directory.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.
        """
        apk = _apk(tmp_path, {"classes.dex": b"dex\n035\x00"})
        assert extract_xamarin_assemblies(apk, tmp_path / "out") is None

    def test_a_corrupt_assembly_does_not_lose_the_others(self, tmp_path):
        """
        Purpose:
            Pin that one unreadable assembly does not cost the recovery of the rest.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Implementation notes:
            Partial recovery is the whole point here: an application ships dozens of assemblies and abandoning all of them over one corrupt entry turns a mostly-successful scan into no scan.
        """
        apk = _apk(tmp_path, {
            "assemblies/Good.dll": _pe(b"fine"),
            "assemblies/Broken.dll": XALZ_MAGIC + struct.pack("<II", 0, 500) + b"\xff\xff",
        })
        out = extract_xamarin_assemblies(apk, tmp_path / "out")
        assert out is not None
        assert (out / "Good.dll").exists()
        assert not (out / "Broken.dll").exists()

    def test_a_corrupt_store_index_is_survivable(self, tmp_path):
        """
        Purpose:
            Pin that a store layout the parser does not understand yields nothing rather than a directory of garbage.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Implementation notes:
            Files of rubbish would be mined for strings and reported as findings, which is worse than recovering nothing, because nothing recovered is visible to the user and rubbish recovered is not.
        """
        blob = XABA_MAGIC_LE + struct.pack("<III", 1, 3, 3) + b"\xff" * 200
        apk = _apk(tmp_path, {"assemblies/assemblies.blob": blob})
        assert extract_xamarin_assemblies(apk, tmp_path / "out") is None

    def test_an_implausible_entry_count_is_refused(self, tmp_path):
        """
        Purpose:
            Pin that a store header declaring an enormous number of entries is refused.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Security considerations:
            The count comes from the file being analysed and is used to size the index read, so trusting it would let a crafted application exhaust memory during a scan.
        """
        blob = XABA_MAGIC_LE + struct.pack("<III", 1, 10 ** 9, 1) + b"\x00" * 64
        apk = _apk(tmp_path, {"assemblies/assemblies.blob": blob})
        assert extract_xamarin_assemblies(apk, tmp_path / "out") is None

    def test_a_wellformed_store_is_unpacked(self, tmp_path):
        """
        Purpose:
            Pin that a correctly-formed assembly store is unpacked into its individual assemblies.

        Parameters:
            tmp_path: Directory holding the fixture archive and the output.

        Implementation notes:
            The fixture reproduces the real header layout, where four bytes of padding sit between the three header fields and the first descriptor, so a parser reading descriptors from the wrong offset fails here rather than passing on a fixture built to match its own mistake.
        """
        first, second = _pe(b"first-assembly"), _pe(b"second-assembly")
        header_size = 20
        descriptor_size = 24
        data_start = header_size + descriptor_size * 2
        index = b"".join([
            struct.pack("<II", data_start, len(first)) + b"\x00" * (descriptor_size - 8),
            struct.pack("<II", data_start + len(first), len(second))
            + b"\x00" * (descriptor_size - 8),
        ])
        blob = (XABA_MAGIC_LE + struct.pack("<III", 1, 2, 2) + b"\x00" * 4
                + index + first + second)
        apk = _apk(tmp_path, {"assemblies/assemblies.blob": blob})
        out = extract_xamarin_assemblies(apk, tmp_path / "out")
        assert out is not None
        recovered = sorted(p.read_bytes() for p in out.glob("*.dll"))
        assert sorted([first, second]) == recovered


class TestStringSidecars:
    """
    Purpose:
        The text files written beside each recovered assembly, which are the entire scan when no decompiler is available.
    """
    def test_ascii_strings_are_recovered(self, tmp_path):
        """
        Purpose:
            Pin that a single-byte-encoded run is recovered into the sidecar.

        Parameters:
            tmp_path: Directory holding the assembly and its sidecar.
        """
        (tmp_path / "App.dll").write_bytes(
            b"\x00\x01" + b"https://api.example/v1/login" + b"\x00\xff")
        assert write_string_sidecars(tmp_path) == 1
        assert "https://api.example/v1/login" in (tmp_path / "App.dll.txt").read_text()

    def test_utf16_strings_are_recovered(self, tmp_path):
        """
        Purpose:
            Pin that a wide-encoded run is recovered into the sidecar.

        Parameters:
            tmp_path: Directory holding the assembly and its sidecar.

        Implementation notes:
            The runtime stores user strings in a two-byte encoding, so a scan that only looks for single-byte runs misses most of what is actually in an assembly, including the connection strings and endpoints a reviewer is looking for.

        Security considerations:
            The connection string in the fixture is invented and matches no real host or password.
        """
        literal = "Server=db.internal;Password=hunter2"
        (tmp_path / "App.dll").write_bytes(b"\x00" + literal.encode("utf-16-le"))
        write_string_sidecars(tmp_path)
        assert literal in (tmp_path / "App.dll.txt").read_text()

    def test_short_runs_are_dropped(self, tmp_path):
        """
        Purpose:
            Pin that runs too short to be meaningful are not written to the sidecar.

        Parameters:
            tmp_path: Directory holding the assembly and its sidecar.

        Implementation notes:
            A binary is full of two- and three-byte runs that happen to be printable, and including them would bury the real strings in noise the agent then pays to read.
        """
        (tmp_path / "App.dll").write_bytes(b"\x00ab\x00cd\x00ef\x00")
        assert write_string_sidecars(tmp_path) == 0

    def test_duplicates_are_collapsed(self, tmp_path):
        """
        Purpose:
            Pin that a string appearing many times is written once.

        Parameters:
            tmp_path: Directory holding the assembly and its sidecar.
        """
        (tmp_path / "App.dll").write_bytes(b"\x00" + b"repeated-string\x00" * 5)
        write_string_sidecars(tmp_path)
        body = (tmp_path / "App.dll.txt").read_text()
        assert body.count("repeated-string") == 1

    def test_a_missing_directory_is_survivable(self, tmp_path):
        """
        Purpose:
            Pin that pointing the mining at a directory that does not exist reports nothing written rather than raising.

        Parameters:
            tmp_path: Directory the missing path is named under.
        """
        assert write_string_sidecars(tmp_path / "nope") == 0

    def test_sidecars_are_readable_by_the_xamarin_profile(self, tmp_path):
        """
        Purpose:
            Pin that the sidecar's extension is one the Xamarin profile counts as source.

        Parameters:
            tmp_path: Directory holding the assembly and its sidecar.

        Implementation notes:
            When no decompiler is present the sidecar is the only thing the agent can read, so a profile that does not list its extension turns the degraded path into no path at all.
        """
        from lu77U_MobileSec.analyzers.agent.profiles import XAMARIN

        (tmp_path / "App.dll").write_bytes(b"\x00" + b"https://api.example/x" + b"\x00")
        write_string_sidecars(tmp_path)
        sidecar = tmp_path / "App.dll.txt"
        assert sidecar.suffix in XAMARIN.source_exts


class TestInventory:
    """
    Purpose:
        The summary that separates the application's own assemblies from the framework's.
    """
    def test_app_assemblies_are_separated_from_the_framework(self, tmp_path):
        """
        Purpose:
            Pin that only the application's assemblies are listed as such while all of them are counted.

        Parameters:
            tmp_path: Directory holding the assemblies.

        Implementation notes:
            An application ships far more framework assemblies than its own, and decompiling or reading them spends the agent's budget on code the developer never wrote.
        """
        for name in ("MyApp.dll", "MyApp.Core.dll", "System.Linq.dll",
                     "Xamarin.Forms.Core.dll", "mscorlib.dll"):
            (tmp_path / name).write_bytes(_pe())
        inventory = summarize_assemblies(tmp_path)
        assert set(inventory["app_assemblies"]) == {"MyApp.dll", "MyApp.Core.dll"}
        assert len(inventory["assemblies"]) == 5

    def test_a_missing_directory_yields_empty_lists(self, tmp_path):
        """
        Purpose:
            Pin that summarising a directory that does not exist yields empty lists rather than raising.

        Parameters:
            tmp_path: Directory the missing path is named under.
        """
        assert summarize_assemblies(tmp_path / "nope") == {
            "assemblies": [], "app_assemblies": []}


class TestGraph:
    """
    Purpose:
        The code map built from recovered C#, when there is any.
    """
    def _write(self, root: Path, name: str, body: str) -> None:
        """
        Purpose:
            Write one source file into the tree being graphed.

        Parameters:
            root: The directory to write into.
            name: The file's name.
            body: The file's contents.

        Side effects:
            Writes the file.
        """
        (root / name).write_text(body, encoding="utf-8")

    def test_no_csharp_means_no_graph(self, tmp_path):
        """
        Purpose:
            Pin that a tree holding only string dumps yields no graph.

        Parameters:
            tmp_path: Directory holding the sidecar.

        Implementation notes:
            With no source there is no structure to map, and inventing a graph from string dumps would tell the agent it has more to work with than it does, which costs steps on nodes that lead nowhere.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        (tmp_path / "App.dll.txt").write_text("some strings")
        assert build_xamarin_graph(tmp_path) is None

    def test_tls_bypass_is_flagged(self, tmp_path):
        """
        Purpose:
            Pin that a certificate validation callback returning unconditional acceptance is flagged alongside the network signal.

        Parameters:
            tmp_path: Directory holding the source file.

        Security considerations:
            That callback disables certificate checking for the whole process, so it is one of the highest-value things the graph can point the agent at.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        self._write(tmp_path, "Api.cs",
                    "public class Api {\n"
                    "  void Setup() {\n"
                    "    ServicePointManager.ServerCertificateValidationCallback = "
                    "(s, c, ch, e) => true;\n"
                    "    var client = new HttpClient();\n"
                    "  }\n}")
        graph = build_xamarin_graph(tmp_path)
        node = graph.nodes["Api.cs"]
        assert "tls" in node.signals and "network" in node.signals
        assert node.cls == "Api"

    def test_exported_activity_attribute_becomes_a_role(self, tmp_path):
        """
        Purpose:
            Pin that an activity attribute declaring the component exported becomes a role on the node.

        Parameters:
            tmp_path: Directory holding the source file.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        self._write(tmp_path, "Main.cs",
                    '[Activity(Label = "App", Exported = true)]\n'
                    "public class MainActivity : Activity { }")
        graph = build_xamarin_graph(tmp_path)
        assert graph.nodes["Main.cs"].role == "exported-activity"
        assert graph.nodes["Main.cs"].exported

    def test_intent_filter_implies_exported(self, tmp_path):
        """
        Purpose:
            Pin that an intent filter makes a component exported even with no explicit declaration, and that its actions are recorded.

        Parameters:
            tmp_path: Directory holding the source file.

        Security considerations:
            A filter exports the component implicitly, so reading only the explicit declaration would report a deep-link entry point as unreachable from outside the application.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        self._write(tmp_path, "Deep.cs",
                    '[Activity(Label = "Deep")]\n'
                    '[IntentFilter(new[] { Intent.ActionView },\n'
                    '  DataScheme = "myapp")]\n'
                    "public class DeepActivity : Activity { }")
        node = build_xamarin_graph(tmp_path).nodes["Deep.cs"]
        assert node.role == "exported-activity"
        assert node.intent_actions == ["ActionView"]

    def test_framework_types_are_excluded(self, tmp_path):
        """
        Purpose:
            Pin that framework source is left out of the graph while the application's own is kept.

        Parameters:
            tmp_path: Directory holding both trees.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        (tmp_path / "System.Net").mkdir()
        self._write(tmp_path / "System.Net", "Http.cs", "public class Http { }")
        self._write(tmp_path, "App.cs", "public class App { var c = new HttpClient(); }")
        graph = build_xamarin_graph(tmp_path)
        assert set(graph.nodes) == {"App.cs"}

    def test_hardcoded_secrets_become_node_strings(self, tmp_path):
        """
        Purpose:
            Pin that a key embedded in source is carried on the node as a string.

        Parameters:
            tmp_path: Directory holding the source file.

        Security considerations:
            The key in the fixture is invented and matches no real credential.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        self._write(tmp_path, "Conf.cs",
                    'public class Conf { const string ApiKey = '
                    '"AIzaSyA1234567890abcdefghijklmnopqrstuv"; }')
        assert build_xamarin_graph(tmp_path).nodes["Conf.cs"].strings

    def test_a_missing_root_yields_none(self, tmp_path):
        """
        Purpose:
            Pin that graphing a directory that does not exist yields nothing rather than raising.

        Parameters:
            tmp_path: Directory the missing path is named under.
        """
        from lu77U_MobileSec.analyzers.xamarin.graph import build_xamarin_graph

        assert build_xamarin_graph(tmp_path / "nope") is None


class TestAnalyzerWiring:
    """
    Purpose:
        How the analyzer is wired to the optional external decompiler.
    """
    def test_preflight_always_passes(self):
        """
        Purpose:
            Pin that a Xamarin scan is always runnable.

        Implementation notes:
            Extraction and string mining need nothing beyond the standard library, so refusing to start without the external decompiler would turn a scan that works into no scan at all.
        """
        from lu77U_MobileSec.analyzers.xamarin_analyzer import XamarinAnalyzer

        ready, reason = XamarinAnalyzer().preflight()
        assert ready and reason == ""

    def test_ilspy_absence_is_reported_not_raised(self, monkeypatch):
        """
        Purpose:
            Pin that an absent decompiler yields nothing rather than raising.

        Parameters:
            monkeypatch: Reports the decompiler as unresolvable.
        """
        from lu77U_MobileSec.decompiler import ilspy_runner

        monkeypatch.setattr(ilspy_runner, "resolve_ilspy", lambda: None)
        assert ilspy_runner.decompile_assemblies("/nope", "/nope") is None

    def test_framework_assemblies_are_not_decompiled(self, tmp_path):
        """
        Purpose:
            Pin that only the application's own assemblies are handed to the decompiler.

        Parameters:
            tmp_path: Directory holding the assemblies.

        Implementation notes:
            Decompiling the framework costs minutes per assembly and produces source the developer never wrote, which then has to be filtered out of the graph anyway.
        """
        from lu77U_MobileSec.decompiler.ilspy_runner import app_assemblies

        for name in ("MyApp.dll", "System.Linq.dll", "Xamarin.Forms.Core.dll",
                     "Newtonsoft.Json.dll"):
            (tmp_path / name).write_bytes(b"MZ")
        assert [p.name for p in app_assemblies(tmp_path)] == ["MyApp.dll"]

    def test_the_configured_path_wins_over_path_lookup(self, tmp_path, monkeypatch):
        """
        Purpose:
            Pin that a decompiler path the user configured is preferred over whatever is on the lookup path.

        Parameters:
            tmp_path: Directory holding the configured executable.
            monkeypatch: Reports the configured path as the user's setting.
        """
        from lu77U_MobileSec.config import user_settings
        from lu77U_MobileSec.decompiler import ilspy_runner

        configured = tmp_path / "ilspycmd"
        configured.write_text("#!/bin/sh\n")
        monkeypatch.setattr(user_settings, "get_xamarin_decompiler_path",
                            lambda: str(configured))
        assert ilspy_runner.resolve_ilspy() == str(configured)

    def test_a_stale_configured_path_falls_back(self, monkeypatch):
        """
        Purpose:
            Pin that a configured path that no longer exists falls back to the lookup path rather than failing.

        Parameters:
            monkeypatch: Reports a non-existent configured path and a resolvable one on the lookup path.

        Implementation notes:
            A configured path goes stale whenever the tool is upgraded or moved, and failing on it would make the user reconfigure a setting they did not change.
        """
        from lu77U_MobileSec.config import user_settings
        from lu77U_MobileSec.decompiler import ilspy_runner

        monkeypatch.setattr(user_settings, "get_xamarin_decompiler_path",
                            lambda: "/does/not/exist/ilspycmd")
        monkeypatch.setattr(ilspy_runner.shutil, "which", lambda _: "/usr/bin/ilspycmd")
        assert ilspy_runner.resolve_ilspy() == "/usr/bin/ilspycmd"
