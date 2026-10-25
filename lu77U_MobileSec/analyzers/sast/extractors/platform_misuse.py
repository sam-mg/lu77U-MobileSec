#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.platform_misuse

Purpose:
    Find Android API misuse in the app's own Java that opens a door other rules do not cover: archive extraction without a path check, Java deserialization, a PreferenceActivity that accepts any fragment, intent:// URLs launched as given, WebView remote debugging left on, secrets copied to the clipboard, permission checks that test the app's own identity instead of the caller's, an ordered broadcast's result trusted in onReceive(), a file read back from shared external storage, an implicit Intent on an app-defined action carrying extras, a mutable PendingIntent around an implicit base Intent, a provider with separate read and write permissions whose call() writes, and an exported unguarded component using an API one of the app's permissions guards.

Responsibilities:
    Match each shape in the app's own code, skip the cases that carry the recognised guard, and emit one finding per site with the class, severity and remediation for it.

Dependencies:
    re, the app-code walker.

Implementation notes:
    Each rule pairs the risky call with the guard that makes it safe, because the call alone is common and usually fine: unzipping is safe with a canonical-path check, Intent.parseUri is safe once the component and selector are cleared, remote debugging is safe behind a debug-build check. Where the guard is a property of a whole file rather than one line -- the canonical-path check in an extraction loop -- the file is the unit, which can miss a second, unguarded extraction in a file that also has a guarded one. Severity is the rule's starting point; the agent and the review pass weigh reachability.
"""

import re
from typing import Dict, List, Set, Tuple
from xml.etree import ElementTree

from .app_java import call_args, excerpt, iter_app_java, line_of
from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_GET_NAME_RE = re.compile(r"\.\s*getName\s*\(\s*\)")
_ASSIGNED_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*[^=;]{0,200}\.\s*getName\s*\(\s*\)")
_NAME_FLOW_LINES = 6
_FILE_WRITE_RE = re.compile(r"new\s+(?:java\.io\.)?(?:File|FileOutputStream)\s*\(")
_PATH_GUARDS = ("getCanonicalPath", "getCanonicalFile", "toRealPath", "normalize()", "\"..\"")
_OBJECT_STREAM_RE = re.compile(r"new\s+(?:java\.io\.)?ObjectInputStream\s*\(")
_DEEP_COPY_RE = re.compile(r"\s*new\s+(?:java\.io\.)?ByteArrayInputStream\s*\(\s*\w+\s*\.\s*toByteArray\s*\(\s*\)")
_VALID_FRAGMENT_RE = re.compile(
    r"boolean\s+isValidFragment\s*\(\s*(?:final\s+)?(?:java\.lang\.)?String\s+\w+\s*\)\s*\{\s*return\s+true\s*;")
_PARSE_URI_RE = re.compile(r"\bIntent\s*\.\s*parseUri\s*\(")
_INTENT_GUARDS = ("setComponent(null)", "setSelector(null)")
_DEBUGGING_RE = re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)")
_DEBUG_GUARDS = ("BuildConfig.DEBUG", "FLAG_DEBUGGABLE", "isDebuggable", "DEBUG)")
_CLIP_RE = re.compile(r"ClipData\s*\.\s*newPlainText\s*\(")
_OR_SELF_RE = re.compile(r"\b((?:check|enforce)CallingOrSelf(?:Uri)?Permission)\s*\(")
_PID_CHECK_RE = re.compile(r"\b((?:check|enforce)Permission)\s*\([^;]*?\bBinder\s*\.\s*getCallingPid\s*\(\s*\)")
_METHOD_RE = re.compile(r"^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)*"
                        r"[\w.$<>\[\]]+\s+(\w+)\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$")
_NON_BINDER_CALLBACKS = frozenset(("onStartCommand", "onHandleIntent", "onReceive", "onCreate", "onStart",
                                   "onNewIntent", "onResume", "handleMessage", "run"))
_ORDERED_RESULT_RE = re.compile(r"\bgetResult(?:Data|Extras)\s*\(")
_EXTERNAL_FILE_RE = re.compile(
    r"\b(?:getExternalFilesDir|getExternalCacheDir|getExternalStorageDirectory|getExternalStoragePublicDirectory)\s*\(")
_FILE_READ_RE = re.compile(
    r"new\s+(?:java\.io\.)?(?:FileInputStream|FileReader|RandomAccessFile)\s*\(|new\s+(?:java\.util\.)?Scanner\s*\(\s*\w+\s*\)"
    r"|\bFiles\s*\.\s*read\w*\s*\(")
_CUSTOM_ACTION_RE = re.compile(r"(?:\.setAction\s*\(|new\s+(?:android\.content\.)?Intent\s*\()\s*\"([\w.$]+)\"\s*\)")
_START_RE = re.compile(r"\b(?:startActivity|startActivityForResult|startService|startForegroundService)\s*\(")
_EXPLICIT_RE = re.compile(r"\.\s*(?:setPackage|setComponent|setClass|setClassName)\s*\(")
_INTENT_WINDOW = 8
_PENDING_RE = re.compile(r"\bPendingIntent\s*\.\s*get(?:Activity|Activities|Service|ForegroundService|Broadcast)\s*\(")
_NEW_INTENT_RE = re.compile(r"^new\s+(?:android\.content\.)?Intent\s*\(")
_IMMUTABLE_FLAGS = ("FLAG_IMMUTABLE", "67108864", "0x04000000")
_BASE_LOOKBACK = 15
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_CALL_METHOD_RE = re.compile(r"public\s+(?:android\.os\.)?Bundle\s+call\s*\([^)]*\)[^{;]*\{")
_WRITE_RE = re.compile(
    r"new\s+(?:java\.io\.)?(?:FileOutputStream|FileWriter)\s*\(|\bopenFileOutput\s*\(|\bexecSQL\s*\("
    r"|\.\s*(?:insert|update|delete|replace)\w*\s*\(|\.\s*edit\s*\(\s*\)|\bFiles\s*\.\s*write\w*\s*\(")
_CALL_GUARD_RE = re.compile(r"\b(?:enforce|check)Calling\w*Permission\s*\(|\bgetCallingPackage\s*\(|\bgetCallingUid\s*\(")
_GUARDED_APIS: Tuple[Tuple[str, str, str], ...] = (
    ("android.permission.SEND_SMS", r"\bsend(?:Text|MultipartText|Data)Message\s*\(", "High"),
    ("android.permission.CALL_PHONE", r"\bACTION_CALL\b|\"android\.intent\.action\.CALL\"", "High"),
    ("android.permission.RECORD_AUDIO", r"new\s+(?:android\.media\.)?AudioRecord\s*\(|\.\s*setAudioSource\s*\(", "High"),
    ("android.permission.CAMERA", r"\bCamera\s*\.\s*open\s*\(|\.\s*openCamera\s*\(", "High"),
    ("android.permission.ACCESS_FINE_LOCATION", r"\.\s*(?:requestLocationUpdates|getLastKnownLocation|getCurrentLocation)\s*\(", "Medium"),
    ("android.permission.READ_CONTACTS", r"\bContactsContract\b", "Medium"),
    ("android.permission.READ_SMS", r"\bTelephony\s*\.\s*Sms\b|content://sms", "Medium"),
    ("android.permission.READ_PHONE_STATE", r"\.\s*(?:getDeviceId|getImei|getLine1Number|getSubscriberId)\s*\(", "Medium"),
    ("android.permission.DISABLE_KEYGUARD", r"\.\s*(?:disableKeyguard|newKeyguardLock)\s*\(", "Medium"),
    ("android.permission.WAKE_LOCK", r"\.\s*newWakeLock\s*\(", "Low"),
)
_SENSITIVE_RE = re.compile(r"(?i)pass(?:word|wd|code)|\bpin\b|\botp\b|token|secret|cvv|card.?number|mnemonic|seed.?phrase")


def _finding(rel: str, text: str, line: int, **fields) -> SastFinding:
    """
    Purpose:
        Build a finding with the shared detector, location and evidence.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.
        line: The 1-based line of the match.
        fields: The rule-specific SastFinding fields.

    Returns:
        The finding.
    """
    return SastFinding(file=rel, line=line, detector="platform-misuse", evidence=excerpt(text, line), **fields)


def _entry_name_written(lines: List[str], index: int) -> bool:
    """
    Purpose:
        Decide whether an entry name read on one line is used to build an output file.

    Parameters:
        lines: The file's lines.
        index: The 0-based line holding the getName() call.

    Returns:
        True when the name reaches a File or FileOutputStream construction on the same line, or through the variable it is assigned to within the next few lines.

    Implementation notes:
        Reading an entry's name is common and harmless -- the Flutter embedding's native-library loader matches entry names against a pattern and never writes them -- so a finding needs the name to become part of a path. A rule that only checked the file for both calls reported that loader in every Flutter app.
    """
    line = lines[index]
    if _FILE_WRITE_RE.search(line):
        return True
    assigned = _ASSIGNED_NAME_RE.search(line)
    if not assigned:
        return False
    use = re.compile(r"\b" + re.escape(assigned.group(1)) + r"\b")
    for later in lines[index + 1:index + 1 + _NAME_FLOW_LINES]:
        call = _FILE_WRITE_RE.search(later)
        if call and use.search(later[call.end():]):
            return True
    return False


def _zip_slip(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report archive entry names used to build output files with no path check in the file.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        At most one finding for the file.
    """
    if "ZipEntry" not in text or not _FILE_WRITE_RE.search(text):
        return []
    if any(guard in text for guard in _PATH_GUARDS):
        return []
    lines = text.splitlines()
    first = line_of(text, text.index("ZipEntry")) - 1
    hit = next((i for i in range(first, len(lines))
                if _GET_NAME_RE.search(lines[i]) and _entry_name_written(lines, i)), None)
    if hit is None:
        return []
    return [_finding(
        rel, text, hit + 1,
        title="Archive entries are extracted without a path check (Zip Slip)",
        severity="Medium", vuln_class="CODE-04", confidence="MEDIUM",
        description=("Entry names from a ZIP archive are used to build output files, and nothing in this "
                     "file canonicalises the path or rejects '..' segments."),
        impact=("An archive with an entry named ../../shared_prefs/x.xml or ../lib/libfoo.so writes outside the "
                "extraction directory: overwriting preferences, databases or native code the app later loads."),
        recommendation=("Resolve each output file with getCanonicalPath() and refuse any entry whose path does "
                        "not start with the canonical extraction directory."),
        cwe="CWE-22", owasp_mobile="M4: Insufficient Input/Output Validation")]


def _deserialization(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report Java object deserialization from a stream.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        At most one finding for the file.

    Implementation notes:
        A stream built straight from a ByteArrayOutputStream's bytes is the deep-copy idiom -- serialise an object and read it back -- which never sees outside data; a real app's copy helper was reported until it was skipped.
    """
    if ".readObject(" not in text:
        return []
    match = next((m for m in _OBJECT_STREAM_RE.finditer(text)
                  if not _DEEP_COPY_RE.match(text, m.end())), None)
    if match is None:
        return []
    return [_finding(
        rel, text, line_of(text, match.start()),
        title="Java objects deserialized from a stream with ObjectInputStream",
        severity="Medium", vuln_class="CODE-03", confidence="LOW",
        description=("An ObjectInputStream reads objects with readObject(). Whether this is exploitable depends "
                     "on where the bytes come from: a file another app can write, a network response, an Intent."),
        impact=("Deserializing attacker-supplied bytes instantiates attacker-chosen classes, which with a usable "
                "gadget on the classpath runs code in the app's process."),
        recommendation=("Use a data format such as JSON with explicit types, or filter classes with "
                        "ObjectInputFilter before readObject()."),
        cwe="CWE-502", owasp_mobile="M4: Insufficient Input/Output Validation")]


def _fragment_injection(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report a PreferenceActivity whose isValidFragment accepts every fragment.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.
    """
    return [_finding(
        rel, text, line_of(text, match.start()),
        title="PreferenceActivity accepts any fragment (isValidFragment returns true)",
        severity="High", vuln_class="PLATFORM-02", confidence="HIGH",
        description=("isValidFragment() returns true for every class name, so the :android:show_fragment extra "
                     "of an Intent chooses which fragment the activity instantiates."),
        impact=("If the activity is exported, any app opens it with an arbitrary fragment class from the app, "
                "including screens meant to sit behind a login."),
        recommendation="Return true only for the fragment classes this activity is meant to host.",
        cwe="CWE-470", owasp_mobile="M8: Security Misconfiguration")
        for match in _VALID_FRAGMENT_RE.finditer(text)]


def _intent_scheme(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report intent:// URLs parsed and launched without clearing the component and selector.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        At most one finding for the file.
    """
    match = _PARSE_URI_RE.search(text)
    if not match or "startActivity" not in text:
        return []
    if all(guard in text.replace(" ", "") for guard in _INTENT_GUARDS):
        return []
    return [_finding(
        rel, text, line_of(text, match.start()),
        title="intent:// URL launched without clearing its component and selector",
        severity="High", vuln_class="PLATFORM-03", confidence="MEDIUM",
        description=("Intent.parseUri() turns a URL into an Intent that is then started, and this file does not "
                     "call both setComponent(null) and setSelector(null) on it."),
        impact=("A web page or link that reaches this code names any activity in the app - exported or not - "
                "with extras of its choosing, the classic WebView-to-private-component jump."),
        recommendation=("After parseUri(), call setComponent(null), setSelector(null) and addCategory(BROWSABLE), "
                        "or launch only intents whose target is on an allowlist."),
        cwe="CWE-940", owasp_mobile="M8: Security Misconfiguration")]


def _webview_debugging(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report WebView remote debugging switched on outside a debug-build check.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.
    """
    out = []
    lines = text.splitlines()
    for match in _DEBUGGING_RE.finditer(text):
        line = line_of(text, match.start())
        context = "\n".join(lines[max(0, line - 4):line])
        if any(guard in context for guard in _DEBUG_GUARDS):
            continue
        out.append(_finding(
            rel, text, line,
            title="WebView remote debugging is enabled in the release build",
            severity="Low", vuln_class="PLATFORM-06", confidence="MEDIUM",
            description=("WebView.setWebContentsDebuggingEnabled(true) is called with no debug-build check in the "
                         "lines before it, so every WebView in the release app can be inspected over chrome://inspect."),
            impact=("Anyone with USB access to an unlocked device with developer options reads and drives the "
                    "WebViews' pages, cookies and JavaScript bridges."),
            recommendation="Enable it only when BuildConfig.DEBUG is true, or when the app is debuggable.",
            cwe="CWE-489", owasp_mobile="M8: Security Misconfiguration"))
    return out


def _clipboard(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report a sensitive-looking value copied to the clipboard.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.

    Implementation notes:
        The value's sensitivity is read from names in the call and the two lines above it -- the label, the variable, the field -- since the value itself is runtime data.
    """
    out = []
    lines = text.splitlines()
    for match in _CLIP_RE.finditer(text):
        line = line_of(text, match.start())
        context = "\n".join(lines[max(0, line - 3):line])
        if not _SENSITIVE_RE.search(context):
            continue
        out.append(_finding(
            rel, text, line,
            title="Sensitive value is copied to the clipboard",
            severity="Medium", vuln_class="STORAGE-02", confidence="LOW",
            description=("ClipData.newPlainText() is built where the surrounding names suggest a password, token, "
                         "PIN, OTP or card value, and the clipboard is readable outside the app."),
            impact=("A keyboard, an accessibility service, or any app in the foreground reads the clipboard, and on "
                    "Android 13 and earlier no flag hides it from the clipboard preview."),
            recommendation=("Do not copy secrets. If the feature needs it, mark the ClipDescription with "
                            "EXTRA_IS_SENSITIVE (Android 13+) and clear the clipboard after a short timeout."),
            cwe="CWE-200", owasp_mobile="M9: Insecure Data Storage"))
    return out


def _enclosing_method(lines: List[str], line: int) -> str:
    """
    Purpose:
        Name the method a line sits in.

    Parameters:
        lines: The file's lines.
        line: The 1-based line.

    Returns:
        The nearest method name declared above the line, or an empty string.
    """
    for index in range(min(line, len(lines)) - 1, -1, -1):
        match = _METHOD_RE.match(lines[index])
        if match:
            return match.group(1)
    return ""


def _self_permission_checks(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report permission checks that test the app's own identity instead of its caller's.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.

    Implementation notes:
        Android documents both shapes. checkCallingOrSelfPermission and its enforce and Uri forms pass when either the caller or the app itself holds the permission, so a component guarded by a permission the app requests lets every caller through. checkPermission or enforcePermission given Binder.getCallingPid() checks the caller only inside a binder transaction - in onStartCommand, onHandleIntent, onReceive and the other callbacks a Service, receiver or activity is started through, there is no transaction and the pid is the app's own. Four Ghera benchmarks plant these; the agents reported the exported service and blamed a normal-level permission, or nothing. Each finding names its fact, so deduplication keeps it apart from the manifest's "exported service has no permission protection" for the same service, which it was folded into by class and subject. The same call in an AIDL method is the correct use and is not reported, and neither is checkPermission(perm, Process.myPid(), Process.myUid()), which is how an app asks whether it holds a permission itself.
    """
    out = []
    lines = text.splitlines()
    for match in _OR_SELF_RE.finditer(text):
        line = line_of(text, match.start())
        out.append(_finding(
            rel, text, line,
            title=f"{match.group(1)}() also passes for the app itself",
            severity="Medium", vuln_class="PLATFORM-01", confidence="MEDIUM",
            extra={"fact_key": f"permission-check:{match.group(1)}"},
            description=(f"{match.group(1)}() succeeds when either the caller or this app holds the permission, "
                         "so where the app holds it - by requesting it, or by declaring it - every caller passes."),
            impact="Any app can invoke whatever this check was meant to reserve for holders of the permission.",
            recommendation=("Use checkCallingPermission()/enforceCallingPermission() inside a binder call, or "
                            "guard the component itself with android:permission in the manifest."),
            cwe="CWE-285", owasp_mobile="M3: Insecure Authentication/Authorization"))
    for match in _PID_CHECK_RE.finditer(text):
        line = line_of(text, match.start())
        method = _enclosing_method(lines, line)
        if method not in _NON_BINDER_CALLBACKS:
            continue
        where = f"reads Binder.getCallingPid() in {method}(), outside any binder call"
        out.append(_finding(
            rel, text, line,
            title="Permission check reads the app's own identity, not the caller's",
            severity="Medium", vuln_class="PLATFORM-01", confidence="MEDIUM",
            extra={"fact_key": f"permission-check:{match.group(1)}-calling-pid"},
            description=(f"{match.group(1)}() {where}, so it checks this app's own permissions rather than "
                         "those of whoever started the component."),
            impact="Every caller passes the check whenever the app itself holds the permission.",
            recommendation=("Guard the component with android:permission in the manifest; check a caller's "
                            "permission with checkCallingPermission() only inside a binder call."),
            cwe="CWE-285", owasp_mobile="M3: Insecure Authentication/Authorization"))
    return out


def _ordered_result(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report a receiver that trusts the result an earlier receiver of an ordered broadcast left.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.

    Implementation notes:
        Ordered broadcasts run their receivers one after another by priority, and each can rewrite the result with setResultData() or setResultExtras(). A receiver reading getResultData() or getResultExtras() in onReceive() is reading what any app registering the same action at a higher priority chose to leave there. Ghera plants this; the agent read the receiver and reported only that it was exported.
    """
    out = []
    lines = text.splitlines()
    for match in _ORDERED_RESULT_RE.finditer(text):
        line = line_of(text, match.start())
        if _enclosing_method(lines, line) != "onReceive":
            continue
        out.append(_finding(
            rel, text, line,
            title="Ordered broadcast result is trusted in onReceive()",
            severity="Low", vuln_class="PLATFORM-02", confidence="LOW",
            description=("onReceive() reads the result of an ordered broadcast (getResultData() or getResultExtras()), "
                         "which every earlier receiver can rewrite; an app registering the same action at a higher "
                         "priority runs first and decides what this receiver gets."),
            impact="Another app injects the data this receiver acts on or passes along.",
            recommendation=("Treat the result as untrusted input: validate it, or take the value from the "
                            "original Intent, which earlier receivers cannot change."),
            cwe="CWE-345", owasp_mobile="M4: Insufficient Input/Output Validation"))
        break
    return out


def _external_read(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Note a file that locates a file on shared external storage and reads files.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        At most one Informational finding, at the first external-storage location.

    Implementation notes:
        Shared storage, the app's own Android/data directory included, is writable by other apps holding the storage permission on Android 10 and lower, so a file read back from there is attacker input. The file, not the method, is the unit, because the read is usually a helper the click handler passes the File to; that makes this a note for the agent and the reader to weigh, not a graded finding. A Ghera app reading a text file from its external files directory and showing it was missed by both earlier runs.
    """
    location = _EXTERNAL_FILE_RE.search(text)
    if not location or not _FILE_READ_RE.search(text):
        return []
    return [_finding(
        rel, text, line_of(text, location.start()),
        title="File on shared external storage is read back",
        severity="Informational", vuln_class="STORAGE-02", confidence="LOW",
        description=("This file locates a file on external storage and reads files; on Android 10 and lower any app "
                     "holding the storage permission can replace what is read there."),
        impact="Content another app planted is parsed, shown or executed as if the app had written it.",
        recommendation="Keep files the app reads back in internal storage (getFilesDir()), or verify them before use.",
        cwe="CWE-345", owasp_mobile="M4: Insufficient Input/Output Validation")]


def _intent_has_target(construction: str) -> bool:
    """
    Purpose:
        Say whether a new Intent(...) expression names its target.

    Parameters:
        construction: The expression, starting with "new Intent(".

    Returns:
        True when it is given a class or a context and a class; False for no arguments or an action string alone.
    """
    args = call_args(construction, _NEW_INTENT_RE.match(construction).end())
    return len(args) >= 2 or any(".class" in a or "ComponentName" in a for a in args)


def _implicit_pending_intent(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report a mutable PendingIntent whose base Intent names no target.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.

    Implementation notes:
        Android's PendingIntent guidance: whoever receives a mutable PendingIntent can fill in what its base Intent left open and send it with the app's identity and permissions, so a base with no component - empty, or an action alone - is the vulnerable shape. Mutable means FLAG_IMMUTABLE is absent; before targetSdkVersion 31 that is the default. The base is read where the call builds it, or, for a variable, from its construction in the preceding lines, and a setComponent, setClass, setClassName or setPackage on it in between makes it explicit. Two Ghera benchmarks plant this, an empty base and an action-only one; the agent reported both in two runs and neither in the third. The Ghera fix for the empty base adds only an action, which is still implicit by this definition and is reported.
    """
    out = []
    lines = text.splitlines()
    for match in _PENDING_RE.finditer(text):
        args = call_args(text, match.end())
        if len(args) < 3 or any(flag in (args[3] if len(args) > 3 else "") for flag in _IMMUTABLE_FLAGS):
            continue
        line = line_of(text, match.start())
        base = args[2].strip()
        if _NEW_INTENT_RE.match(base):
            if _intent_has_target(base):
                continue
        elif re.fullmatch(r"[A-Za-z_]\w*", base):
            window = lines[max(0, line - 1 - _BASE_LOOKBACK):line]
            built = next((w for w in reversed(window) if re.search(rf"\b{base}\s*=\s*new\s+(?:android\.content\.)?Intent\s*\(", w)), None)
            if built is None:
                continue
            construction = built[re.search(r"new\s+(?:android\.content\.)?Intent\s*\(", built).start():]
            after = window[window.index(built):]
            if _intent_has_target(construction) or any(
                    re.search(rf"\b{base}\s*\.\s*(?:setComponent|setClass|setClassName|setPackage)\s*\(", w) for w in after):
                continue
        else:
            continue
        out.append(_finding(
            rel, text, line,
            title="Mutable PendingIntent wraps an implicit Intent",
            severity="High", vuln_class="PLATFORM-08", confidence="MEDIUM",
            description=("A PendingIntent is created without FLAG_IMMUTABLE around a base Intent that names no "
                         "component, so whoever receives it can choose where it goes and what it carries."),
            impact="The receiving app sends the Intent with this app's identity and permissions, reaching its unexported components.",
            recommendation=("Give the base Intent an explicit component and add FLAG_IMMUTABLE; use FLAG_MUTABLE only "
                            "where the receiver must fill in extras, and then still with an explicit component."),
            cwe="CWE-927", owasp_mobile="M8: Security Misconfiguration"))
    return out


def _implicit_custom_action(rel: str, text: str) -> List[SastFinding]:
    """
    Purpose:
        Report an implicit Intent built on an app-defined action that carries extras to an activity or service.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.

    Returns:
        The findings.

    Implementation notes:
        An action the app made up names its own component, so sending it implicitly lets any app that declares the same action - at a higher priority, or chosen by the user - receive the extras and stand in for the screen. Platform actions (android.*, com.android.*) are meant to reach other apps and are left alone, as is an Intent given a package, component or class within the next lines. Ghera plants this (a picture handed to the app's editor through a custom action); one run's agent reported it and the next did not.
    """
    out = []
    lines = text.splitlines()
    for match in _CUSTOM_ACTION_RE.finditer(text):
        action = match.group(1)
        if action.startswith(("android.", "com.android.")) or "." not in action:
            continue
        line = line_of(text, match.start())
        window = "\n".join(lines[line - 1:line - 1 + _INTENT_WINDOW])
        if "putExtra" not in window or not _START_RE.search(window) or _EXPLICIT_RE.search(window):
            continue
        out.append(_finding(
            rel, text, line,
            title="Implicit Intent with an app-defined action carries extras",
            severity="Low", vuln_class="PLATFORM-07", confidence="LOW",
            description=(f"An Intent with the app's own action \"{action}\" and extras is started without a package "
                         "or component, so any app declaring that action can receive it."),
            impact="Another app intercepts the extras and can show its own screen in place of the app's.",
            recommendation="Make the Intent explicit with setClass(), setComponent() or setPackage().",
            cwe="CWE-927", owasp_mobile="M8: Security Misconfiguration"))
    return out


_RULES = (_zip_slip, _deserialization, _fragment_injection, _intent_scheme, _webview_debugging, _clipboard,
          _self_permission_checks, _ordered_result, _external_read, _implicit_custom_action, _implicit_pending_intent)
_MARKERS = (b"ZipEntry", b"ObjectInputStream", b"isValidFragment", b"parseUri",
            b"setWebContentsDebuggingEnabled", b"newPlainText", b"OrSelf", b"Permission(", b"getResult",
            b"getExternal", b"setAction", b"Intent(\"", b"PendingIntent")


def split_guarded_providers(source_root) -> Set[str]:
    """
    Purpose:
        Name the content providers guarded by a separate read or write permission and no overall one.

    Parameters:
        source_root: The analysis root.

    Returns:
        Fully qualified class names of exported providers that declare readPermission or writePermission but not permission.

    Implementation notes:
        Read from the decoded manifest the manifest scanner also reads; a relative name is resolved against the package. An unreadable or missing manifest gives an empty set, which turns the call() rule off rather than guessing.
    """
    from .manifest import find_manifest
    manifest = find_manifest(source_root)
    if manifest is None:
        return set()
    try:
        root = ElementTree.parse(manifest).getroot()
    except (ElementTree.ParseError, OSError):
        return set()
    package = root.get("package") or ""
    out = set()
    for provider in root.iter("provider"):
        attr = lambda name: provider.get(_ANDROID_NS + name)
        if (attr("readPermission") or attr("writePermission")) and not attr("permission") \
                and attr("exported") != "false":
            name = attr("name") or ""
            out.add(package + name if name.startswith(".") else name)
    return out


def _launcher_only(el) -> bool:
    """
    Purpose:
        Say whether an activity is exported only as the app's launcher entry.

    Parameters:
        el: The activity element.

    Returns:
        True when it has intent-filters and every one is MAIN with launcher or default categories and no data.
    """
    filters = el.findall("intent-filter")
    if not filters:
        return False
    for f in filters:
        actions = {a.get(_ANDROID_NS + "name") for a in f.findall("action")}
        categories = {c.get(_ANDROID_NS + "name") for c in f.findall("category")}
        if actions != {"android.intent.action.MAIN"} or f.find("data") is not None:
            return False
        if not categories <= {"android.intent.category.LAUNCHER", "android.intent.category.DEFAULT",
                              "android.intent.category.LEANBACK_LAUNCHER"}:
            return False
    return True


def unguarded_components(source_root) -> Tuple[Set[str], Dict[str, str]]:
    """
    Purpose:
        Read the permissions the app requests and its exported components that declare no permission.

    Parameters:
        source_root: The analysis root.

    Returns:
        (requested permission names, fully qualified component class to its kind).

    Implementation notes:
        A component counts as exported when it says so, or, without the attribute, when it has an intent-filter, which made it exported below targetSdkVersion 31. An activity exported only as the launcher entry is left out, as the manifest scanner leaves it out: opening it does what the user's taps do, and two Ghera launcher activities that place a call or read the device ID on a button press were reported as handing those permissions to any app. Merged library manifests are already part of the decoded manifest, which is how a library's exported service shows up here. An unreadable manifest gives empty results.
    """
    from .manifest import find_manifest
    manifest = find_manifest(source_root)
    if manifest is None:
        return set(), {}
    try:
        root = ElementTree.parse(manifest).getroot()
    except (ElementTree.ParseError, OSError):
        return set(), {}
    package = root.get("package") or ""
    requested = {el.get(_ANDROID_NS + "name") or "" for el in root.iter("uses-permission")}
    components: Dict[str, str] = {}
    app = root.find("application")
    for kind in ("activity", "service", "receiver", "provider"):
        for el in (app.iter(kind) if app is not None else ()):
            exported = el.get(_ANDROID_NS + "exported")
            if el.get(_ANDROID_NS + "permission") or exported == "false":
                continue
            if exported != "true" and el.find("intent-filter") is None:
                continue
            if kind == "activity" and _launcher_only(el):
                continue
            name = el.get(_ANDROID_NS + "name") or ""
            components[package + name if name.startswith(".") else name] = kind
    return requested, components


def _permission_redelegation(rel: str, text: str, requested: Set[str], components: Dict[str, str]) -> List[SastFinding]:
    """
    Purpose:
        Report an exported, unguarded component whose own code uses an API one of the app's permissions guards.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.
        requested: Permissions the app requests.
        components: Exported unguarded component classes, from unguarded_components.

    Returns:
        The findings, one per permission.

    Implementation notes:
        Permission re-delegation: Android checks the permission against the app that holds it, so an exported component that sends SMS, opens the camera or takes a wake lock does it for whoever starts it, and an app that never asked for the permission gets its effect. Only the component's own file is read, and only permissions the app requests count, since without the permission the API fails. Ghera plants this twice - an unused WAKE_LOCK exercised by a library's exported service, and SMS sent by an exported receiver - and the scans reported the exported component without saying which permission it hands out.
    """
    qualified = re.sub(r"\.java$", "", rel.replace("\\", "/")).split("sources/", 1)[-1].replace("/", ".")
    kind = components.get(qualified)
    if not kind:
        return []
    out = []
    short = qualified.rsplit(".", 1)[-1]
    for permission, api, severity in _GUARDED_APIS:
        match = re.search(api, text)
        if permission not in requested or not match:
            continue
        name = permission.rsplit(".", 1)[-1]
        out.append(_finding(
            rel, text, line_of(text, match.start()),
            title=f"Exported {kind} {short} uses {name} for any app",
            severity=severity, vuln_class="PLATFORM-01", confidence="MEDIUM",
            extra={"fact_key": f"redelegation:{qualified}:{name}"},
            description=(f"{short} is exported without a permission and uses an API guarded by {permission}, which "
                         "the app holds, so any app that starts it gets that permission's effect without asking for it."),
            impact=f"An app with no {name} permission makes this app do what {name} allows.",
            recommendation=(f"Guard {short} with a signature-level android:permission, or stop exporting it; and drop "
                            f"{name} if the app itself does not need it."),
            cwe="CWE-441", owasp_mobile="M8: Security Misconfiguration"))
    return out


def _provider_call_writes(rel: str, text: str, split: Set[str]) -> List[SastFinding]:
    """
    Purpose:
        Report a provider guarded by separate read and write permissions whose call() writes.

    Parameters:
        rel: The file, relative to the analysis root.
        text: The file's text.
        split: Classes with a separate read or write permission and no overall one, from split_guarded_providers.

    Returns:
        The findings.

    Implementation notes:
        Android checks nothing on ContentProvider.call() beyond the caller being able to read from the provider, so writePermission does not cover it: an app that can read - anyone, when only writePermission is declared - runs call(), and a call() that writes files or data writes them past the write permission. A check inside call() on the caller (enforceCallingPermission and the like, or the calling package or uid) counts as its own guard. The class is matched by the file's path. Ghera plants this, and its fix guards the provider with one permission for both; the agent found it in two runs out of three.
    """
    match = _CALL_METHOD_RE.search(text)
    if not match or not split:
        return []
    qualified = re.sub(r"\.java$", "", rel.replace("\\", "/")).split("sources/", 1)[-1].replace("/", ".")
    if qualified not in split:
        return []
    depth, end = 1, match.end()
    while end < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[end], 0)
        end += 1
    body = text[match.end():end]
    if not _WRITE_RE.search(body) or _CALL_GUARD_RE.search(body):
        return []
    return [_finding(
        rel, text, line_of(text, match.start()),
        title="ContentProvider.call() writes past the write permission",
        severity="Medium", vuln_class="PLATFORM-01", confidence="MEDIUM",
        description=("The provider guards reads and writes separately, and Android checks only read access for "
                     "call(), so any app that can read invokes call(), which writes."),
        impact="An app without the write permission changes the files or data call() writes.",
        recommendation=("Guard the provider with android:permission or writePermission, or check the caller's "
                        "permission inside call() with enforceCallingPermission()."),
        cwe="CWE-285", owasp_mobile="M8: Security Misconfiguration")]


def analyze_platform_misuse(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Run every platform-misuse rule over the app's own Java.

    Parameters:
        source_root: The analysis root.
        verbose: Traces the outcome.

    Returns:
        The findings.

    Side effects:
        Reads the app's Java files.
    """
    out: List[SastFinding] = []
    split = split_guarded_providers(source_root)
    requested, components = unguarded_components(source_root)
    markers = _MARKERS + (b"Bundle call(",) + ((b"",) if components else ())
    for rel, text in iter_app_java(source_root, markers):
        for rule in _RULES:
            out += rule(rel, text)
        out += _provider_call_writes(rel, text, split)
        out += _permission_redelegation(rel, text, requested, components)
    verbose_print(f"SAST platform-misuse: {plural(len(out), 'finding')}", verbose)
    return out
