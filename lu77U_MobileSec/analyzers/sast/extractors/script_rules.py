#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.script_rules

Purpose:
    Rule checks for the app logic a React Native or Flutter app keeps outside Java: storage, logging, SQL, keys, cleartext endpoints, dynamic code and WebView settings in the recovered JavaScript modules and Dart disassembly.

Responsibilities:
    Read a React Native app's own recovered modules and a Flutter app's own Dart disassembly, match each against a small set of patterns that are reliable in the recovered form, and emit findings at the call or literal that shows the issue.

Dependencies:
    re, pathlib, the Flutter recovery helpers (digest and package split), the kernel extractor's directory name.

Implementation notes:
    Benchmark scans of both frameworks missed issues that are plain to read once the code is recovered - a token written to AsyncStorage, a PIN interpolated into print(), an SQL string interpolated into rawQuery, an AES key passed as a literal - because the agent never reached the file or read past the line. The Java rules cannot see any of it. These rules give each such issue a rule-backed finding the agent and the validation stage can confirm or refute, the same role the Java extractors play. Patterns are matched on the recovered form rather than on source idioms: Hermes output names the method and the literal arguments, and the Dart digest keeps every string load and resolved call at its real line, so a key literal followed by a SharedPreferences setter in the same function is the store, wherever the source put it. Only the app's own code is read - React Native's app_modules and the Flutter app's own packages - and a sensitive name is matched by whole word, so "spinner" is not a PIN and "mapping" is not a password.

Security considerations:
    Everything read here is decompiled from an untrusted APK. It is matched as text with bounded expressions; nothing is executed.
"""

import re
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_JS_DIR = "app_modules"
_MAX_FILE_BYTES = 2_000_000
_SENSITIVE_WORDS = frozenset((
    "pin", "pincode", "password", "passwd", "pwd", "passcode", "secret", "token", "accesstoken",
    "refreshtoken", "idtoken", "session", "sessionid", "auth", "authtoken", "credential",
    "credentials", "otp", "cvv", "jwt", "apikey", "privatekey",
))
_SECURE_STORE_MARKERS = ("EncryptedStorage", "SecureStore", "Keychain", "encryptedStorage", "secureStorage")
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_CLEARTEXT_RE = re.compile(r"\"(http://([A-Za-z0-9.-]+)(?::\d+)?(?:/[^\"\s]*)?)\"")
_NAMESPACE_HOSTS = ("schemas.android.com", "www.w3.org", "w3.org", "ns.adobe.com", "xml.org",
                    "apache.org", "schemas.xmlsoap.org", "purl.org", "xmlpull.org", "json-schema.org",
                    "example.com", "example.org", "localhost")
_PRIVATE_HOST_RE = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0$)")

_JS_SET_ITEM_RE = re.compile(r"\bsetItem\(\s*\"([^\"]{1,80})\"")
_JS_LOG_RE = re.compile(r"\bconsole\.(?:log|info|warn|debug|error)\((.*)\)")
_JS_DYNAMIC_RE = re.compile(r"\bnew\s+Function\(([^;]*)\)|\beval\(([^;)]*)\)")
_JS_STRING_ONLY_RE = re.compile(r"^\s*\"(?:[^\"\\]|\\.)*\"\s*$")
_JS_AES_RE = re.compile(r"\bAES\.(?:encrypt|decrypt)\(\s*[^,()]+,\s*(\"[^\"]{4,}\"|[A-Za-z_$][\w$]*)")
_JS_ON_MESSAGE_RE = re.compile(r"\bonMessage=\{")
_JS_WEBVIEW_PROPS = (
    (re.compile(r"\ballowUniversalAccessFromFileURLs(?:=\{true\}|(?=[\s/>]))"), "allowUniversalAccessFromFileURLs",
     "PLATFORM-05", "High",
     "lets a page loaded from a file:// URL read any other file:// URL and any web origin"),
    (re.compile(r"\ballowFileAccessFromFileURLs(?:=\{true\}|(?=[\s/>]))"), "allowFileAccessFromFileURLs",
     "PLATFORM-05", "Medium", "lets a page loaded from a file:// URL read other local files"),
    (re.compile(r"\boriginWhitelist=\{\[\s*\"\*\"\s*\]\}"), "originWhitelist [\"*\"]",
     "PLATFORM-06", "Medium", "lets the WebView navigate to and load any origin"),
    (re.compile(r"\bmixedContentMode=\"always\""), "mixedContentMode=\"always\"",
     "PLATFORM-06", "Medium", "lets an HTTPS page load scripts and frames over plain HTTP"),
)

_DART_ROW_RE = re.compile(r"^(\d+): (.*)$")
_DART_PREFS_SET_RE = re.compile(r"SharedPreferences(?:Async)?::(?:_setValue|setString|setBool|setInt|setDouble|setStringList)\b")
_DART_LOG_RE = re.compile(r"^call (?:::print|::debugPrint|DebugPrint)\b|^call ::log \(dart:developer\)")
_DART_SQL_RE = re.compile(r"^\"\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b", re.IGNORECASE)
_DART_RAW_SQL_RE = re.compile(r"::(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute)\b")
_DART_KEY_ALLOC_RE = re.compile(r"^call (Key|IV)\(\)$")
_DART_FROM_LITERAL_RE = re.compile(r"\.from(?:Utf8|Base64|Base16)\b")
_DART_REQUEST_RE = re.compile(r"Uri::parse|\((?:http|dio|http_client)\)|HttpClient")
_DART_WINDOW = 6
_DART_PINNED_CONTEXT_RE = re.compile(r"SecurityContext::(?:setTrustedCertificates(?:Bytes)?|useCertificateChain(?:Bytes)?)\b")
_DART_HTTP_CLIENT_RE = re.compile(r"^call _?HttpClient(?:\(\)|::_?HttpClient)")
_DART_PINNING_RE = re.compile(
    r"HttpCertificatePinning::check|CertificatePinningInterceptor|SecureHttpClient::build|"
    r"SecurityContext::setTrustedCertificates(?:Bytes)?")
_DART_HASH_RE = re.compile(r"^call (?:Hash::convert|::sha(?:1|256|512)|::md5)\b")
_DART_HEX_DIGEST_RE = re.compile(r'^"[0-9a-fA-F]{32,128}"$')


def sensitive_words(text: str) -> List[str]:
    """
    Purpose:
        Pick out the credential-like words in a name or a string.

    Parameters:
        text: A key name, identifier or literal.

    Returns:
        The sensitive words found, lowercased, in order.

    Implementation notes:
        Splitting on punctuation and camel case before matching is what keeps this precise: "authToken" yields auth and token, while "spinner", "shipping" and "mapping" yield nothing. A chunk whose camel-case words match nothing is tried whole, so an all-lowercase "authtoken" still counts.
    """
    found: List[str] = []
    for chunk in _WORD_SPLIT_RE.split(text):
        hits = [w.lower() for w in _CAMEL_RE.findall(chunk) if w.lower() in _SENSITIVE_WORDS]
        if not hits and chunk.lower() in _SENSITIVE_WORDS:
            hits = [chunk.lower()]
        for word in hits:
            if word not in found:
                found.append(word)
    return found


def _is_request_host(host: str) -> bool:
    """
    Purpose:
        Decide whether an http:// host is a real network endpoint.

    Parameters:
        host: The URL's host.

    Returns:
        False for namespace and documentation hosts, loopback and private addresses; True otherwise.

    Implementation notes:
        A private or loopback address is a development setup - the emulator's host alias among them - rather than traffic that crosses the internet, and namespace hosts are identifiers in XML and schemas, never requested.
    """
    host = host.lower().rstrip(".")
    if _PRIVATE_HOST_RE.match(host):
        return False
    return not any(host == known or host.endswith("." + known) for known in _NAMESPACE_HOSTS)


def _read(path: Path) -> Optional[str]:
    """
    Purpose:
        Read one recovered file, skipping anything implausibly large.

    Parameters:
        path: The file.

    Returns:
        The text, or None when it is too large or unreadable.
    """
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _js_findings(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Apply the JavaScript rules to one recovered React Native module.

    Parameters:
        rel: The module's path, relative to the analysis root.
        text: Its contents.

    Returns:
        The findings.

    Implementation notes:
        Each rule fires at most once per module and key, so a module that stores the same token in three places reads as one issue. A setItem call is treated as plain storage unless the module names an encrypting store, since AsyncStorage is the only common store with that method name that writes plaintext. The onMessage rule looks at the handler's own lines and stays quiet when they read the message's url, which is the origin check that makes a bridge safe.
    """
    out: List[SastFinding] = []
    lines = text.splitlines()
    secure_store = any(marker in text for marker in _SECURE_STORE_MARKERS)
    seen = set()
    for number, line in enumerate(lines, 1):
        for match in _JS_SET_ITEM_RE.finditer(line):
            key = match.group(1)
            words = sensitive_words(key)
            if secure_store or not words or ("store", key) in seen:
                continue
            seen.add(("store", key))
            out.append(SastFinding(
                title=f"Sensitive value '{key}' stored with setItem in unencrypted storage",
                severity="Medium", vuln_class="STORAGE-01", file=rel, line=number, detector="script-rules",
                confidence="MEDIUM",
                description=(f"The app writes a value under the key '{key}' with setItem, the AsyncStorage API. "
                             "AsyncStorage keeps values as plain text in the app's data directory."),
                impact=("Anyone with a backup of the app data, root on the device, or a debuggable build "
                        "reads the value directly."),
                recommendation=("Keep tokens and credentials in the Android Keystore through an encrypting "
                                "store such as react-native-keychain or EncryptedStorage."),
                cwe="CWE-312", owasp_mobile="M9: Insecure Data Storage"))
        log = _JS_LOG_RE.search(line)
        if log and "log" not in seen:
            words = sensitive_words(log.group(1))
            if words:
                seen.add("log")
                out.append(SastFinding(
                    title="Sensitive value written to the log with console.log",
                    severity="Low", vuln_class="SECRET-02", file=rel, line=number, detector="script-rules",
                    confidence="MEDIUM",
                    description=(f"A console call logs values named {', '.join(words)}. React Native forwards "
                                 "console output to logcat in release builds unless it is stripped."),
                    impact="Other tools with log access, crash reporters and bug reports capture the value.",
                    recommendation="Remove the call or strip console output from release bundles.",
                    cwe="CWE-532", owasp_mobile="M9: Insecure Data Storage"))
        dynamic = _JS_DYNAMIC_RE.search(line)
        if dynamic and "dynamic" not in seen:
            args = dynamic.group(1) if dynamic.group(1) is not None else dynamic.group(2)
            last = args.rsplit(",", 1)[-1] if args else ""
            if last.strip() and not _JS_STRING_ONLY_RE.match(last):
                seen.add("dynamic")
                out.append(SastFinding(
                    title="Dynamic code execution with a runtime string (new Function or eval)",
                    severity="High", vuln_class="CODE-02", file=rel, line=number, detector="script-rules",
                    confidence="MEDIUM",
                    description=("The module builds and runs code from a string that is not a literal, so "
                                 "whatever supplies that string decides what the app executes."),
                    impact=("If the string comes from the network or storage, whoever controls that source "
                            "runs code inside the app with all of its data and native modules."),
                    recommendation="Remove the dynamic evaluation; ship behaviour in the signed bundle.",
                    cwe="CWE-95", owasp_mobile="M4: Insufficient Input/Output Validation"))
        aes = _JS_AES_RE.search(line)
        if aes and "aes" not in seen:
            key = aes.group(1)
            literal = key if key.startswith('"') else _js_literal_of(text, key)
            if literal:
                seen.add("aes")
                out.append(SastFinding(
                    title="Hardcoded encryption key passed to AES.encrypt or AES.decrypt",
                    severity="Medium", vuln_class="CRYPTO-02", file=rel, line=number, detector="script-rules",
                    confidence="MEDIUM",
                    description=(f"The AES key is the literal {literal[:60]}, shipped in the bundle."),
                    impact="Anyone who unpacks the app decrypts whatever this key protects.",
                    recommendation="Generate the key on the device in the Android Keystore, or derive it from a user secret.",
                    cwe="CWE-321", owasp_mobile="M10: Insufficient Cryptography"))
        on_message = _JS_ON_MESSAGE_RE.search(line)
        if on_message and "onmessage" not in seen:
            handler = "\n".join([line[on_message.start():], *lines[number:number + 12]])
            if "nativeEvent" in handler and ".url" not in handler and "origin" not in handler:
                seen.add("onmessage")
                out.append(SastFinding(
                    title="WebView onMessage handler acts on messages from any origin",
                    severity="Medium", vuln_class="PLATFORM-04", file=rel, line=number, detector="script-rules",
                    confidence="MEDIUM",
                    description=("The WebView's onMessage handler parses nativeEvent.data and acts on it without "
                                 "reading nativeEvent.url, so any page the WebView shows can send it commands."),
                    impact=("A page reached through a link, a redirect or injected content drives whatever "
                            "actions the handler performs."),
                    recommendation="Check nativeEvent.url against the expected origin before acting on a message.",
                    cwe="CWE-346", owasp_mobile="M4: Insufficient Input/Output Validation"))
        if "<WebView" in line or "WebView " in line:
            for pattern, name, vuln_class, severity, effect in _JS_WEBVIEW_PROPS:
                if pattern.search(line) and ("prop", name) not in seen:
                    seen.add(("prop", name))
                    out.append(SastFinding(
                        title=f"WebView sets {name}",
                        severity=severity, vuln_class=vuln_class, file=rel, line=number, detector="script-rules",
                        confidence="MEDIUM",
                        description=f"A WebView in the app's own code sets {name}, which {effect}.",
                        impact="Content the WebView loads gets more reach than a web page should have.",
                        recommendation=f"Remove {name} unless the WebView only ever shows bundled, trusted content.",
                        cwe="CWE-16", owasp_mobile="M8: Security Misconfiguration"))
    out += _cleartext_findings(rel, lines, "script-rules")
    return out


def _js_literal_of(text: str, name: str) -> str:
    """
    Purpose:
        Find the string literal a module assigns to a name, directly or through a parse call.

    Parameters:
        text: The module.
        name: The identifier.

    Returns:
        The quoted literal, or "" when the name is not assigned one.

    Implementation notes:
        CryptoJS keys are usually built once at module level, as Utf8.parse("...") or a bare literal, and passed by name, so the call site alone never shows the key.
    """
    match = re.search(r"\b" + re.escape(name) + r"\s*=\s*(?:[\w$.]*parse\()?(\"[^\"]{4,}\")", text)
    return match.group(1) if match else ""


def _cleartext_findings(rel: str, lines: Sequence[str], detector: str,
                        request_lines: Optional[Sequence[int]] = None) -> List[SastFinding]:
    """
    Purpose:
        Report plain-HTTP endpoints written into app code.

    Parameters:
        rel: The file's path.
        lines: Its lines, or digest rows for compiled Dart.
        detector: The reporting detector's name.
        request_lines: For compiled Dart, the indexes of literals followed by a request call; None to accept every literal.

    Returns:
        One finding per distinct host.

    Implementation notes:
        The URL literal is cited, so the attached code shows the http:// endpoint, which is what the cleartext gate asks for before treating such a finding as more than a configuration note.
    """
    out: List[SastFinding] = []
    hosts = set()
    for index, line in enumerate(lines):
        if request_lines is not None and index not in request_lines:
            continue
        for match in _CLEARTEXT_RE.finditer(line):
            url, host = match.group(1), match.group(2)
            if host in hosts or not _is_request_host(host):
                continue
            hosts.add(host)
            number = index + 1
            if request_lines is not None:
                row = _DART_ROW_RE.match(line)
                number = int(row.group(1)) if row else number
            out.append(SastFinding(
                title=f"App code uses a plain-HTTP endpoint ({host})",
                severity="Medium", vuln_class="NETWORK-02", file=rel, line=number, detector=detector,
                confidence="MEDIUM",
                description=(f"The app's own code holds the endpoint {url[:120]}, which is requested over "
                             "unencrypted HTTP."),
                impact=("Anyone on the network path - shared Wi-Fi, a hostile access point - reads and "
                        "changes the requests and responses."),
                recommendation="Serve the endpoint over HTTPS and stop permitting cleartext traffic.",
                cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))
    return out


def _dart_rows(text: str) -> List[Tuple[int, str]]:
    """
    Purpose:
        Turn a Dart disassembly into digest rows.

    Parameters:
        text: The disassembly.

    Returns:
        (line, text) pairs in file order.
    """
    from ...flutter.recovered import digest_disassembly
    rows: List[Tuple[int, str]] = []
    for row in digest_disassembly(text).splitlines():
        match = _DART_ROW_RE.match(row)
        if match:
            rows.append((int(match.group(1)), match.group(2)))
    return rows


def _window(rows: Sequence[Tuple[int, str]], index: int, back: int) -> List[str]:
    """
    Purpose:
        Collect the rows just before a call, within the same function.

    Parameters:
        rows: The digest rows.
        index: The call's position.
        back: How many rows to look back.

    Returns:
        The rows' texts, nearest last.

    Implementation notes:
        A function declaration ends the window, so a literal from the previous function is never read as an argument.
    """
    out: List[str] = []
    for _line, text in reversed(rows[max(0, index - back):index]):
        if text.startswith(("fn ", "class ")):
            break
        out.append(text)
    return list(reversed(out))


def _dart_findings(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Apply the Dart rules to one of the app's own disassembly files.

    Parameters:
        rel: The file's path, relative to the analysis root.
        text: The disassembly.

    Returns:
        The findings.

    Implementation notes:
        Arguments in compiled Dart are loaded into registers just before the call, so the string literals in the few digest rows before a call are its literal arguments. A setter is reported once per sensitive key, a log call once per file, an interpolated SQL statement once per file. A Key or IV built from a literal is reported at the literal, so the cited line shows the value rather than the conversion call after it, and a cleartext URL only when a request call follows it, since a URL shown as text is not a request. A hash call followed shortly by a hex-digest literal is a credential check against a constant, reported at the digest. A function that builds a pinned SecurityContext and whose exception handler then creates a plain HttpClient fails open, reported at the handler; pinning itself is noted once per file at Informational, as the client-side control it is.
    """
    out: List[SastFinding] = []
    rows = _dart_rows(text)
    seen = set()
    request_lines = set()
    for index, (line, row) in enumerate(rows):
        before = _window(rows, index, _DART_WINDOW)
        literals = [r for r in before if r.startswith('"')]
        if _DART_PREFS_SET_RE.search(row):
            for literal in literals[-2:]:
                key = literal.strip('"')
                if sensitive_words(key) and ("prefs", key) not in seen:
                    seen.add(("prefs", key))
                    out.append(SastFinding(
                        title=f"Sensitive value '{key}' stored in plain SharedPreferences",
                        severity="Medium", vuln_class="STORAGE-01", file=rel, line=line,
                        detector="script-rules", confidence="MEDIUM",
                        description=(f"The app writes a value under the key '{key}' through SharedPreferences, "
                                     "which keeps it as plain text in the app's shared_prefs XML file."),
                        impact=("Anyone with a backup of the app data, root on the device, or a debuggable "
                                "build reads the value directly."),
                        recommendation="Store credentials with flutter_secure_storage, backed by the Android Keystore.",
                        cwe="CWE-312", owasp_mobile="M9: Insecure Data Storage"))
        if _DART_LOG_RE.search(row) and "log" not in seen:
            words = [w for literal in literals for w in sensitive_words(literal)]
            if words:
                seen.add("log")
                out.append(SastFinding(
                    title="Sensitive value written to the log with print()",
                    severity="Low", vuln_class="SECRET-02", file=rel, line=line, detector="script-rules",
                    confidence="MEDIUM",
                    description=(f"A print or debugPrint call logs a message mentioning {', '.join(sorted(set(words)))}. "
                                 "print() reaches logcat in release builds."),
                    impact="Other tools with log access, crash reporters and bug reports capture the value.",
                    recommendation="Remove the call, or guard it with kDebugMode.",
                    cwe="CWE-532", owasp_mobile="M9: Insecure Data Storage"))
        if _DART_RAW_SQL_RE.search(row) and "sql" not in seen:
            window = _window(rows, index, _DART_WINDOW * 2)
            if any(_DART_SQL_RE.match(r) for r in window) and any("_interpolate" in r for r in window):
                seen.add("sql")
                out.append(SastFinding(
                    title="SQL statement built by string interpolation and run as a raw query",
                    severity="Medium", vuln_class="CODE-01", file=rel, line=line, detector="script-rules",
                    confidence="MEDIUM",
                    description=("An SQL statement literal is joined with runtime values by string interpolation "
                                 "and passed to a raw query call, so a value containing a quote changes the statement."),
                    impact=("Whoever controls the interpolated value reads or changes rows the query was not "
                            "meant to reach."),
                    recommendation="Pass values as arguments with ? placeholders instead of interpolating them.",
                    cwe="CWE-89", owasp_mobile="M4: Insufficient Input/Output Validation"))
        key_alloc = _DART_KEY_ALLOC_RE.match(row)
        if key_alloc and ("key", key_alloc.group(1)) not in seen:
            ahead = [r for _l, r in rows[index + 1:index + 4]]
            converted = next((i for i, r in enumerate(ahead) if _DART_FROM_LITERAL_RE.search(r)), None)
            literal = next((k for k, r in enumerate(ahead[:converted or 0]) if r.startswith('"')), None)
            if converted is not None and literal is not None:
                kind = key_alloc.group(1)
                seen.add(("key", kind))
                is_key = kind == "Key"
                cwe = "CWE-321"
                if not is_key:
                    cwe = "CWE-329"
                out.append(SastFinding(
                    title="Hardcoded encryption key in the app's Dart code" if is_key
                    else "Hardcoded initialisation vector in the app's Dart code",
                    severity="High" if is_key else "Medium", vuln_class="CRYPTO-02", file=rel,
                    line=rows[index + 1 + literal][0], detector="script-rules", confidence="MEDIUM",
                    description=(f"{'A' if is_key else 'An'} {kind} object is built from the string literal on "
                                 "the cited line, which is compiled into the app."),
                    impact=("Anyone who unpacks the app recovers the value and decrypts what it protects."
                            if is_key else "A fixed IV makes equal plaintexts encrypt to equal ciphertexts."),
                    recommendation="Generate keys in the Android Keystore and a fresh random IV for every encryption.",
                    cwe=cwe, owasp_mobile="M10: Insufficient Cryptography"))
        if _DART_HASH_RE.match(row) and "hash" not in seen:
            ahead = [(l, r) for l, r in rows[index + 1:index + 1 + _DART_WINDOW * 2]]
            digest_row = next(((l, r) for l, r in ahead if _DART_HEX_DIGEST_RE.match(r)), None)
            if digest_row is not None:
                seen.add("hash")
                out.append(SastFinding(
                    title="Input hash compared against a hardcoded hash",
                    severity="Medium", vuln_class="AUTH-04", file=rel, line=digest_row[0],
                    detector="script-rules", confidence="MEDIUM",
                    description=("The app hashes a value - typically an entered PIN or password - and compares the "
                                 "result with a hex digest compiled into the app, so the check is decided on the "
                                 "device against a constant."),
                    impact=("The digest ships with the app; a short PIN or password behind it is recovered by "
                            "hashing every candidate offline, and the comparison is one hook from always passing."),
                    recommendation="Verify credentials on a server, or derive a key from them with a slow KDF.",
                    cwe="CWE-798", owasp_mobile="M1: Improper Credential Usage"))
        if _DART_PINNING_RE.search(row) and "pinned" not in seen:
            seen.add("pinned")
            out.append(SastFinding(
                title="Certificate pinning is enforced in the app's own code",
                severity="Informational", vuln_class="BUILD-04", file=rel, line=line,
                detector="script-rules", confidence="MEDIUM",
                description=("The app pins the server certificate in its own Dart code. Pinning is a client-side "
                             "control: it raises the cost of intercepting traffic, and a hook on this call removes it."),
                impact="Context for the network findings: interception for testing needs this check bypassed first.",
                recommendation="Keep pinning, and make sure every client that carries credentials goes through it.",
                cwe="CWE-295", owasp_mobile="M7: Insufficient Binary Protections"))
        if row.startswith("catch:") and "pinning" not in seen:
            body = _window(rows, index, 40)
            after = [r for _l, r in rows[index + 1:index + 1 + _DART_WINDOW]]
            if any(_DART_PINNED_CONTEXT_RE.search(r) for r in body) and any(
                    _DART_HTTP_CLIENT_RE.match(r) for r in after):
                seen.add("pinning")
                out.append(SastFinding(
                    title="Certificate pinning falls back to an unpinned client on setup failure",
                    severity="Low", vuln_class="NETWORK-03", file=rel, line=line,
                    detector="script-rules", confidence="MEDIUM",
                    description=("The function builds a SecurityContext trusting only a pinned certificate, but its "
                                 "exception handler returns a plain HttpClient that trusts every system CA, so any "
                                 "failure in the pinning setup silently removes the pin."),
                    impact=("When the fallback is taken, an attacker with a CA the device trusts - a user-installed "
                            "one, or a mis-issued certificate - can intercept the traffic the pin was meant to protect."),
                    recommendation="Fail closed: when the pinned context cannot be built, refuse the connection.",
                    cwe="CWE-636", owasp_mobile="M5: Insecure Communication"))
        if row.startswith('"http://'):
            ahead = [r for _l, r in rows[index + 1:index + 1 + _DART_WINDOW]]
            if any(_DART_REQUEST_RE.search(r) for r in ahead):
                request_lines.add(index)
    digest_lines = [f"{line}: {row}" for line, row in rows]
    out += _cleartext_findings(rel, digest_lines, "script-rules", request_lines=request_lines)
    return out


def _app_scripts(root: Path) -> Iterator[Tuple[Path, str]]:
    """
    Purpose:
        List the app's own recovered scripts with their kind.

    Parameters:
        root: The analysis root.

    Returns:
        (path, "js" or "dart") pairs.

    Implementation notes:
        Flutter's package split is imported here rather than at module load, because the rule engine is imported while the analyzers package is still initialising. Recovered Dart source from a debug build is not read: the patterns here are written for the disassembly digest.
    """
    js_dir = root / _JS_DIR
    if js_dir.is_dir():
        for path in sorted(js_dir.rglob("*.js")):
            yield path, "js"
    asm_dir = root / "asm"
    if asm_dir.is_dir():
        from ...flutter import recovered
        groups = recovered.asm_packages(asm_dir)
        for package in sorted(recovered.find_app_packages(groups)):
            for path in sorted(groups.get(package, [])):
                yield path, "dart"


def analyze_script_rules(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Run the JavaScript and Dart rules over a cross-platform app's own recovered code.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the result.

    Returns:
        The findings.
    """
    root = Path(source_root)
    out: List[SastFinding] = []
    for path, kind in _app_scripts(root):
        text = _read(path)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix()
        out += _js_findings(rel, text) if kind == "js" else _dart_findings(rel, text)
    verbose_print(f"SAST script rules: {plural(len(out), 'finding')}", verbose)
    return out
