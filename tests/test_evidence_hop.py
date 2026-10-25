#!/usr/bin/env python3
"""
Module: test_evidence_hop

Purpose:
    The claim vocabulary one step from a citation: a called helper's body, and the code reading a cited resource value.

Responsibilities:
    Pin that a cited line reaches the method it sits in, how calls resolve to definitions (qualified by package, nested class, same file), that statements are not mistaken for definitions and library calls are not followed, that a cited declaration reaches the code using it and a cited res/values entry the code that reads it, and that the claim gate accepts what the reached code supports and still refutes what it does not.

Dependencies:
    pytest, the evidence-hop module and the claim gate.

Implementation notes:
    Modelled on a Ghera app whose agent cited strings.xml and the call Util.Encrypt.encryptGrade(R.string.secret, R.string.IV, ...) for a hardcoded AES key and IV; both findings were refuted while the helper held Cipher and IvParameterSpec.
"""

from lu77U_MobileSec.analyzers.evidence_hop import hop_terms, method_body
from lu77U_MobileSec.validation.gates import check_claim_evidence

PROVIDER = """package edu.x;

public class GradesProvider {
    public void insert(String key) {
        String g = edu.x.Util.Encrypt.encryptGrade(getContext().getResources().getString(edu.x.R.string.secret), key);
        String h = edu.x.Plain.join(key, key);
        java.lang.String s = java.lang.String.valueOf(1);
        record(key);
    }

    private void record(String key) {
        android.util.Log.d("tag", key);
    }

    public String wrap(String k) {
        return record2(k);
    }
}
"""

ENCRYPT = """package edu.x.Util;

public class Encrypt {
    public static java.lang.String encryptGrade(java.lang.String key, java.lang.String grade) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5PADDING");
            javax.crypto.spec.IvParameterSpec iv = new javax.crypto.spec.IvParameterSpec(key.getBytes());
            return grade;
        } catch (Exception e) {
            return null;
        }
    }
}
"""

PLAIN = """package edu.x;

public class Plain {
    public static class Inner {
    }

    public static java.lang.String join(java.lang.String a, java.lang.String b) {
        return a + b;
    }
}
"""

STRINGS = """<resources>
    <string name="app_name">Benign</string>
    <string name="secret">njkwjkRsd^Hruu*2</string>
</resources>
"""


def _tree(tmp_path):
    """
    Purpose:
        Lay out a JADX-shaped output directory with the provider, its helpers and its strings.

    Parameters:
        tmp_path: pytest fixture.

    Returns:
        The output root.
    """
    root = tmp_path / "jadx"
    files = {
        "sources/edu/x/GradesProvider.java": PROVIDER,
        "sources/edu/x/Util/Encrypt.java": ENCRYPT,
        "sources/edu/x/Plain.java": PLAIN,
        "sources/edu/x/R.java": "package edu.x;\npublic final class R { }\n",
        "resources/res/values/strings.xml": STRINGS,
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _terms(root, rel, line, title="Hardcoded AES key and IV"):
    """
    Purpose:
        Compute the hop vocabulary for a one-line citation.

    Parameters:
        root: The output root.
        rel: The cited file, relative to the root.
        line: The cited line, 1-based.
        title: The finding's title.

    Returns:
        The vocabulary.
    """
    path = root / rel
    return hop_terms(root, path, path.read_text().splitlines(), line, line, {"title": title})


class TestResolution:
    """
    Purpose:
        Which calls on the cited lines reach a definition.
    """

    def test_a_call_qualified_by_its_package_reaches_the_helper(self, tmp_path):
        """
        Purpose:
            The JADX-style fully qualified static call resolves to Util/Encrypt.java and brings in its crypto API.

        Parameters:
            tmp_path: pytest fixture.
        """
        terms = _terms(_tree(tmp_path), "sources/edu/x/GradesProvider.java", 5)
        assert {"cipher.getinstance", "ivparameterspec", "javax.crypto"} <= set(terms)

    def test_a_helper_with_no_crypto_brings_none(self, tmp_path):
        """
        Purpose:
            A resolved helper contributes only what it contains; Plain.join, reached through a file that also has a nested class, holds no crypto.

        Parameters:
            tmp_path: pytest fixture.
        """
        terms = _terms(_tree(tmp_path), "sources/edu/x/GradesProvider.java", 6)
        assert "javax.crypto" not in terms and "cipher.getinstance" not in terms

    def test_a_same_file_call_reaches_its_definition_and_a_library_call_is_not_followed(self, tmp_path):
        """
        Purpose:
            An unqualified call is looked up in the cited file; java.lang is never followed.

        Parameters:
            tmp_path: pytest fixture.
        """
        root = _tree(tmp_path)
        assert "log.d" in _terms(root, "sources/edu/x/GradesProvider.java", 8, title="Token written to the log")
        assert _terms(root, "sources/edu/x/GradesProvider.java", 7) == []

    def test_a_return_statement_is_not_a_definition(self):
        """
        Purpose:
            "return record2(k);" has the shape of a typed signature and must not be read as one.
        """
        lines = PROVIDER.splitlines()
        assert method_body(lines, "record2") == []
        assert method_body(lines, "record")[0].strip().startswith("private void record(")


class TestEnclosingMethod:
    """
    Purpose:
        A citation reaching the rest of the method it sits in.
    """

    STORE = """package a;
public class Main {
    void save() {
        try {
            javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
            javax.crypto.SecretKey secretKey = keyGen.generateKey();
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("BKS");
            keyStore.setEntry("K", new java.security.KeyStore.SecretKeyEntry(secretKey), null);
            java.io.FileOutputStream fos = new java.io.FileOutputStream("x");
            keyStore.store(fos, null);
        } catch (Exception e) {
        }
    }

    void other() {
        int x = 1;
    }
}
"""

    def test_the_method_holding_the_key_generator_supports_the_store_line(self, tmp_path):
        """
        Purpose:
            "keyStore.store(fos, null)" reaches the KeyGenerator five lines up in its method; a line in another method does not.

        Parameters:
            tmp_path: pytest fixture.
        """
        path = tmp_path / "jadx/sources/a/Main.java"
        path.parent.mkdir(parents=True)
        path.write_text(self.STORE)
        root = tmp_path / "jadx"
        assert "keygenerator" in _terms(root, "sources/a/Main.java", 10)
        assert "keygenerator" not in _terms(root, "sources/a/Main.java", 16)


class TestResourceCitation:
    """
    Purpose:
        A citation of a res/values entry reaching the code that reads it.
    """

    def test_the_declared_value_reaches_its_reader_and_the_readers_callee(self, tmp_path):
        """
        Purpose:
            The strings.xml entry named secret is read in GradesProvider, whose call reaches the helper's crypto API.

        Parameters:
            tmp_path: pytest fixture.
        """
        terms = _terms(_tree(tmp_path), "resources/res/values/strings.xml", 3)
        assert {"cipher.getinstance", "ivparameterspec"} <= set(terms)

    def test_an_unread_value_reaches_nothing(self, tmp_path):
        """
        Purpose:
            A string no code reads contributes no vocabulary.

        Parameters:
            tmp_path: pytest fixture.
        """
        assert _terms(_tree(tmp_path), "resources/res/values/strings.xml", 2) == []


class TestDeclarationCitation:
    """
    Purpose:
        A citation of a field's declaration reaching the code that uses it.
    """

    def test_a_declared_key_reaches_its_use_in_the_same_file_and_elsewhere(self, tmp_path):
        """
        Purpose:
            The constant is used twenty lines down in its own file and as Holder.SECRET_KEY in another, and both uses' vocabulary is found.

        Parameters:
            tmp_path: pytest fixture.
        """
        root = tmp_path / "jadx"
        holder = root / "sources/a/Holder.java"
        other = root / "sources/a/Other.java"
        holder.parent.mkdir(parents=True)
        holder.write_text("package a;\npublic class Holder {\n    static final byte[] SECRET_KEY = \"0123\".getBytes();\n"
                          + "\n" * 20 + "    void f() { Object k = new javax.crypto.spec.SecretKeySpec(SECRET_KEY, \"AES\"); }\n}\n")
        other.write_text("package a;\npublic class Other {\n    void g() { javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(\"AES\"); byte[] k = a.Holder.SECRET_KEY; }\n}\n")
        terms = _terms(root, "sources/a/Holder.java", 3)
        assert {"secretkeyspec", "cipher.getinstance"} <= set(terms)

    def test_an_unused_declaration_reaches_nothing(self, tmp_path):
        """
        Purpose:
            A constant nothing reads contributes no vocabulary.

        Parameters:
            tmp_path: pytest fixture.
        """
        root = tmp_path / "jadx"
        holder = root / "sources/a/Holder.java"
        holder.parent.mkdir(parents=True)
        holder.write_text("package a;\npublic class Holder {\n    static final String NAME = \"x\";\n    void f() { javax.crypto.Cipher c = null; }\n}\n")
        assert _terms(root, "sources/a/Holder.java", 3) == []


class TestClaimGate:
    """
    Purpose:
        The claim gate with and without the hop vocabulary.
    """

    def _finding(self, hop):
        """
        Purpose:
            Build the refuted Ghera finding, citing the helper's call line.

        Parameters:
            hop: The hop vocabulary to attach, or None.

        Returns:
            The finding.
        """
        line = PROVIDER.splitlines()[4]
        context = {"lines": [line]}
        if hop is not None:
            context["hop_terms"] = hop
        return {"title": "Hardcoded AES encryption key and IV", "vuln_class": "CRYPTO-02", "source": "agent",
                "file": "sources/edu/x/GradesProvider.java", "line": 5, "code_snippet": line,
                "code_context": context}

    def test_the_reached_helper_supports_the_claim(self, tmp_path):
        """
        Purpose:
            Refuted on the call line alone, supported once the helper's vocabulary is attached.

        Parameters:
            tmp_path: pytest fixture.
        """
        assert check_claim_evidence(self._finding(None)) is not None
        hop = _terms(_tree(tmp_path), "sources/edu/x/GradesProvider.java", 5)
        assert check_claim_evidence(self._finding(hop)) is None

    def test_a_helper_without_the_api_still_leaves_the_claim_refuted(self, tmp_path):
        """
        Purpose:
            The hop widens the evidence to what the cited code reaches, not to anything; an AES claim at a call to a string-joining helper is still refuted.

        Parameters:
            tmp_path: pytest fixture.
        """
        hop = _terms(_tree(tmp_path), "sources/edu/x/GradesProvider.java", 6)
        finding = self._finding(hop)
        finding["code_snippet"] = PROVIDER.splitlines()[5]
        finding["code_context"]["lines"] = [finding["code_snippet"]]
        assert check_claim_evidence(finding) is not None
