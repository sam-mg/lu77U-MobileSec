#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.manifest

Purpose:
    Derive findings from what the app declares about itself: exported components, application flags, SDK levels, permissions and task affinities.

Responsibilities:
    Locate and parse the manifest, decide what is genuinely exported, and emit findings for the declarations that matter.

Dependencies:
    The XML parser, androguard for reading a binary manifest from an APK.

Implementation notes:
    Export status is the central judgement here, and it is not simply the attribute's value. Below a certain target SDK, a component with an intent filter is exported by default; above it, the attribute is mandatory. Getting that wrong either invents exposure or misses it, so the target SDK is read first and the decision made explicitly.

Security considerations:
    Every value comes from an attacker-declared manifest. Several of these findings are the weak classes the gates later demote, and they are emitted as facts here because the context needed to judge them lives downstream.
"""

from pathlib import Path
from typing import List, Optional, Tuple
from xml.etree import ElementTree

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_ANDROID = "{http://schemas.android.com/apk/res/android}"

_COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}

DANGEROUS_PERMISSIONS = {
    "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CALL_LOG",
    "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP", "BODY_SENSORS",
    "ACTIVITY_RECOGNITION", "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
    "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS",
    "NEARBY_WIFI_DEVICES", "BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE",
    "BLUETOOTH_CONNECT", "UWB_RANGING", "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
}


def _attr(el, name: str, default=None):
    """
    Purpose:
        Read a namespaced Android attribute from an element.

    Parameters:
        el: The element.
        name: The attribute's local name.
        default: Returned when the attribute is absent.

    Returns:
        The attribute value, or the default.

    Implementation notes:
        The Android namespace is applied explicitly, because a bare local-name lookup silently returns nothing for a namespaced attribute -- which reads as "not set" and would make every component look unexported.
    """
    return el.get(_ANDROID + name, default)


def _int_or_none(value) -> Optional[int]:
    """
    Purpose:
        Parse a manifest value as an integer.

    Parameters:
        value: The declared value.

    Returns:
        The integer, or None when it is absent or unparseable.

    Implementation notes:
        None is distinct from zero here: an absent SDK level means the platform default applies, which is a different judgement from a declared zero.
    """
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def find_manifest(source_root) -> Optional[Path]:
    """
    Purpose:
        Locate the manifest within a decompiled tree.

    Parameters:
        source_root: Root of the decompiled source.

    Returns:
        The manifest path, or None.
    """
    root = Path(source_root)
    for candidate in (root / "resources" / "AndroidManifest.xml",
                      root / "AndroidManifest.xml"):
        if candidate.is_file():
            return candidate
    return next(root.rglob("AndroidManifest.xml"), None)


def _manifest_root_from_apk(apk_path, verbose: bool = False):
    """
    Purpose:
        Read the manifest directly from an APK when the decompiled tree has none.

    Parameters:
        apk_path: Path to the APK.
        verbose: Traces failures.

    Returns:
        The parsed manifest root, or None.

    Implementation notes:
        Needed because decompilation can fail or be skipped while the manifest remains perfectly readable from the archive. Falling back to it means manifest findings survive a failed decompilation, which is exactly when the rest of the analysis has least to say.
    """
    if not apk_path:
        return None
    try:
        from loguru import logger
        logger.disable("androguard")
        try:
            from androguard.core.apk import APK
            return APK(str(apk_path)).get_android_manifest_xml()
        finally:
            logger.enable("androguard")
    except Exception as exc:
        verbose_print(f"SAST manifest: could not decode manifest from APK: {exc}", verbose)
        return None


def _determine_exported(el, target_sdk: Optional[int]) -> Tuple[bool, bool, str]:
    """
    Purpose:
        Decide whether a component is actually reachable by other apps.

    Parameters:
        el: The component element.
        target_sdk: The app's declared target SDK.

    Returns:
        Whether it is exported, whether that was implicit, and how the conclusion was reached.

    Implementation notes:
        An explicit attribute is decisive. Without one, the default depends on both the component kind and the target SDK: a component with an intent filter was exported by default below API 31, and above that the attribute is required. The reasoning is returned alongside the verdict because it goes into the finding. A reader judging an exported-component finding needs to know whether the app said so or whether the platform default made it so.

    Security considerations:
        This decides which components are attack surface. Treating an implicit export as private would hide real exposure; the reverse would fill a report with components nothing can reach.
    """
    raw = _attr(el, "exported")
    has_filter = el.find("intent-filter") is not None
    if raw is not None:
        exported = str(raw).lower() == "true"
        return exported, True, f'android:exported="{raw}"'
    if has_filter:
        if target_sdk is not None and target_sdk >= 31:
            return True, False, (
                "Has an intent-filter but no explicit android:exported, which "
                "targetSdk >= 31 requires; treated as exported for analysis")
        return True, False, "Has an intent-filter and no explicit android:exported (implicitly exported)"
    return False, False, "No intent-filter and no android:exported"


def analyze_manifest(source_root, apk_path=None, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Derive all manifest findings for an app.

    Parameters:
        source_root: Root of the decompiled source.
        apk_path: Path to the APK, used when the tree has no manifest.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads the manifest from disk or from the archive.

    Implementation notes:
        The SDK levels are read before anything else, since several of the judgements below depend on them. A manifest that cannot be read yields no findings rather than raising, because the rest of the scan is still worth completing.
    """
    root = None
    manifest = find_manifest(source_root)
    if manifest is not None:
        try:
            root = ElementTree.parse(manifest).getroot()
        except (ElementTree.ParseError, OSError) as exc:
            verbose_print(f"SAST manifest: could not parse {manifest}: {exc}", verbose)
            return []
    else:
        root = _manifest_root_from_apk(apk_path, verbose)
        if root is None:
            verbose_print("SAST manifest: no AndroidManifest.xml available", verbose)
            return []

    rel = "AndroidManifest.xml"
    out: List[SastFinding] = []
    package = root.get("package") or ""

    uses_sdk = root.find("uses-sdk")
    target_sdk = min_sdk = None
    if uses_sdk is not None:
        target_sdk = _int_or_none(_attr(uses_sdk, "targetSdkVersion"))
        min_sdk = _int_or_none(_attr(uses_sdk, "minSdkVersion"))

    app = root.find("application")
    if app is not None:
        out += _application_flags(app, rel)
    out += _sdk_findings(target_sdk, min_sdk, rel)
    out += _permission_findings(root, rel)
    if app is not None:
        out += _component_findings(app, rel, target_sdk)
        out += _task_affinity_findings(app, rel, package)

    verbose_print(f"SAST manifest: {plural(len(out), 'finding')} from {manifest}", verbose)
    return out


def _application_flags(app, rel: str) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for the application-level security flags.

    Parameters:
        app: The application element.
        rel: The manifest's path, for the finding location.

    Returns:
        The findings.

    Implementation notes:
        Backup, cleartext and debuggable are all reported here, and all three are weak classes the gates later demote or require a chain for. They are emitted as facts because this extractor can see the declaration but not what would be in the backup or what actually travels over HTTP -- the judgement needs context this layer does not have.
    """
    out: List[SastFinding] = []
    debuggable = str(_attr(app, "debuggable", "false")).lower() == "true"
    allow_backup_raw = _attr(app, "allowBackup")
    allow_backup = allow_backup_raw is None or str(allow_backup_raw).lower() == "true"
    cleartext_raw = _attr(app, "usesCleartextTraffic")
    nsc = _attr(app, "networkSecurityConfig")

    if debuggable:
        out.append(SastFinding(
            title="Application is debuggable in this build",
            severity="Critical", vuln_class="BUILD-01", file=rel,
            detector="manifest",
            description=(
                'android:debuggable="true" lets any user with adb attach a debugger to the '
                "process, read and modify memory, and inspect application data."),
            impact="Full runtime access to the app's process and data on any device with adb.",
            recommendation='Remove android:debuggable or set it to "false" for release builds.',
            cwe="CWE-489", owasp_mobile="M8: Security Misconfiguration"))

    if allow_backup:
        out.append(SastFinding(
            title="Application data is backup-enabled",
            severity="Medium", vuln_class="STORAGE-04", file=rel,
            detector="manifest", confidence="HIGH",
            description=(
                'android:allowBackup is ' +
                ("absent, which defaults to true" if allow_backup_raw is None else '"true"') +
                ", so app data can be extracted with adb backup on devices that allow it."),
            impact="Any locally stored credentials or PII become extractable over USB.",
            recommendation='Set android:allowBackup="false", or exclude sensitive files '
                           "with android:fullBackupContent.",
            cwe="CWE-530", owasp_mobile="M9: Insecure Data Storage"))

    if str(cleartext_raw).lower() == "true":
        out.append(SastFinding(
            title="Cleartext HTTP traffic is permitted app-wide",
            severity="High", vuln_class="NETWORK-02", file=rel, detector="manifest",
            description='android:usesCleartextTraffic="true" allows unencrypted HTTP '
                        "connections from anywhere in the app.",
            impact="Traffic can be read and modified by anyone on the network path.",
            recommendation="Remove the attribute and declare per-domain exceptions in a "
                           "network security config if any are genuinely needed.",
            cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))
    elif cleartext_raw is None and not nsc:
        out.append(SastFinding(
            title="No network security config declared",
            severity="Low", vuln_class="NETWORK-03", file=rel, detector="manifest",
            description="The app declares neither android:networkSecurityConfig nor "
                        "usesCleartextTraffic, so it relies entirely on platform defaults.",
            impact="On API < 28 cleartext is permitted by default.",
            recommendation="Declare a network security config that disables cleartext and "
                           "pins the domains that carry sensitive traffic.",
            cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))
    return out


def _sdk_findings(target_sdk, min_sdk, rel: str) -> List[SastFinding]:
    """
    Purpose:
        Emit findings about the declared SDK range.

    Parameters:
        target_sdk: The declared target SDK.
        min_sdk: The declared minimum SDK.
        rel: The manifest's path.

    Returns:
        The findings.

    Implementation notes:
        An SDK level is context rather than a defect, which is why these are low-severity and chain-eligible. A low minimum means the app runs on versions where several platform protections behave differently, and that matters only in combination with a finding that depends on one of them.
    """
    out: List[SastFinding] = []
    if target_sdk is not None:
        if target_sdk < 28:
            out.append(SastFinding(
                title=f"targetSdkVersion {target_sdk} permits cleartext traffic by default",
                severity="High", vuln_class="NETWORK-02", file=rel, detector="manifest",
                description=f"targetSdk {target_sdk} predates API 28, where cleartext HTTP "
                            "became opt-in.",
                recommendation="Raise targetSdkVersion to 28 or above.",
                cwe="CWE-319", owasp_mobile="M5: Insecure Communication"))
        if target_sdk < 31:
            out.append(SastFinding(
                title=f"targetSdkVersion {target_sdk} allows implicit component export",
                severity="Medium", vuln_class="BUILD-02", file=rel, detector="manifest",
                description=f"On targetSdk {target_sdk}, any component with an intent-filter "
                            "is exported unless it says otherwise.",
                recommendation="Raise targetSdkVersion to 31+ and declare android:exported "
                               "explicitly on every filtered component.",
                cwe="CWE-926", owasp_mobile="M8: Security Misconfiguration"))
        if target_sdk < 24:
            out.append(SastFinding(
                title=f"targetSdkVersion {target_sdk} trusts user-installed CA certificates",
                severity="High", vuln_class="NETWORK-01", file=rel, detector="manifest",
                description=f"Below API 24 the app trusts the user CA store, so a user-installed "
                            "certificate can intercept HTTPS.",
                recommendation="Raise targetSdkVersion to 24+.",
                cwe="CWE-295", owasp_mobile="M5: Insecure Communication"))
    if min_sdk is not None and min_sdk < 21:
        out.append(SastFinding(
            title=f"minSdkVersion {min_sdk} supports Android versions without modern protections",
            severity="Low", vuln_class="BUILD-02", file=rel, detector="manifest",
            description=f"minSdk {min_sdk} keeps the app installable on releases that lack "
                        "network security config enforcement and modern platform hardening.",
            recommendation="Raise minSdkVersion where the user base allows."))
    return out


def _permission_findings(root, rel: str) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for the permissions the app requests.

    Parameters:
        root: The manifest root.
        rel: The manifest's path.

    Returns:
        The findings.

    Implementation notes:
        A requested permission describes what the app could do with a vulnerability, not that it has one, so these are inventory rather than defects. They earn their place by widening the impact of another finding, which is what the chaining stage uses them for.
    """
    out: List[SastFinding] = []
    requested = []
    for el in root.iter("uses-permission"):
        name = _attr(el, "name") or ""
        short = name.rsplit(".", 1)[-1]
        if short in DANGEROUS_PERMISSIONS:
            requested.append(short)
    if requested:
        listed = ", ".join(sorted(set(requested))[:12])
        out.append(SastFinding(
            title=f"App requests {plural(len(set(requested)), 'dangerous permission')}",
            severity="Informational", vuln_class="BUILD-03", file=rel, detector="manifest",
            description=f"Runtime permissions requested: {listed}.",
            impact="Context for other findings - a component that leaks data is worse when "
                   "the app holds sensitive permissions.",
            recommendation="Drop permissions the app does not need."))

    for el in root.iter("permission"):
        level = str(_attr(el, "protectionLevel", "normal")).lower()
        name = _attr(el, "name") or "(unnamed)"
        if level in ("normal", "dangerous"):
            out.append(SastFinding(
                title=f"Custom permission {name.rsplit('.', 1)[-1]} is weakly protected",
                severity="Medium", vuln_class="PLATFORM-01", file=rel, detector="manifest",
                description=f'Custom permission "{name}" uses protectionLevel="{level}", so any '
                            "installed app can request and be granted it.",
                recommendation='Use protectionLevel="signature" for permissions guarding '
                               "internal components.",
                cwe="CWE-280", owasp_mobile="M3: Insecure Authentication/Authorization"))
    return out


def _task_affinity_findings(app, rel: str, package: str) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for activities whose task affinity allows task hijacking.

    Parameters:
        app: The application element.
        rel: The manifest's path.
        package: The app's package, for comparison.

    Returns:
        The findings.

    Implementation notes:
        An affinity matching the package is the default and is not a finding. What matters is an activity with an empty or foreign affinity, which allows another app to insert itself into the task -- and it matters far more for a login screen than for a settings page, which is why the finding names the activity.
    """
    out: List[SastFinding] = []
    app_affinity = _attr(app, "taskAffinity")
    if app_affinity and app_affinity != package:
        out.append(SastFinding(
            title="Application task affinity is not the package name",
            severity="Medium", vuln_class="PLATFORM-09", file=rel,
            detector="manifest",
            description=f'The <application> declares android:taskAffinity="{app_affinity}" '
                        f'rather than the package "{package}". Every Activity inherits it.',
            impact="Another app declaring the same affinity can have this app's activities "
                   "launched into a task it controls, and stage a convincing overlay or "
                   "phishing screen around them.",
            recommendation='Leave taskAffinity unset so it defaults to the package name, or '
                           'set android:taskAffinity="" on activities that should stand alone.',
            cwe="CWE-1021", owasp_mobile="M4: Insufficient Input/Output Validation"))

    for el in app.iter("activity"):
        affinity = _attr(el, "taskAffinity")
        if affinity is None or affinity == "" or affinity == package:
            continue
        if affinity == app_affinity:
            continue
        short = (_attr(el, "name") or "(unnamed)").rsplit(".", 1)[-1]
        out.append(SastFinding(
            title=f"Activity {short} declares a foreign task affinity",
            severity="Medium", vuln_class="PLATFORM-09", file=rel,
            detector="manifest",
            description=f'{short} sets android:taskAffinity="{affinity}", which is neither '
                        f'the package name nor empty.',
            impact="A malicious app that declares the same affinity can have this activity "
                   "reparented into its task and surround it with attacker-controlled UI.",
            recommendation='Remove the attribute to inherit the package name, or set it to '
                           '"" to isolate the activity in its own task.',
            cwe="CWE-1021", owasp_mobile="M4: Insufficient Input/Output Validation"))
    return out


def _component_findings(app, rel: str, target_sdk: Optional[int]) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for exported components lacking a permission guard.

    Parameters:
        app: The application element.
        rel: The manifest's path.
        target_sdk: The declared target SDK.

    Returns:
        The findings.

    Implementation notes:
        Export is decided by the explicit rule rather than by the attribute alone, and a component guarded by a permission is not reported -- the guard is the mitigation. The finding records how export was established, so a reader can tell a deliberate export from one the platform default created.

    Security considerations:
        These are the entry points the rest of the analysis reasons about: an exported component is where attacker-controlled data enters the app, and most serious chains start at one.
    """
    out: List[SastFinding] = []
    for tag, kind in _COMPONENT_TAGS.items():
        for el in app.iter(tag):
            name = _attr(el, "name") or "(unnamed)"
            short = name.rsplit(".", 1)[-1]
            exported, explicit, reason = _determine_exported(el, target_sdk)
            if not exported:
                continue

            permission = (_attr(el, "permission") or _attr(el, "readPermission")
                          or _attr(el, "writePermission"))
            actions = [a.get(_ANDROID + "name", "") for a in el.iter("action")]
            schemes = [d.get(_ANDROID + "scheme", "") for d in el.iter("data")
                       if d.get(_ANDROID + "scheme")]

            if kind == "provider" and str(_attr(el, "grantUriPermissions", "false")).lower() == "true" \
                    and not permission:
                out.append(SastFinding(
                    title=f"Exported content provider {short} grants URI permissions without protection",
                    severity="Critical", vuln_class="PLATFORM-01", file=rel, detector="manifest",
                    description=f'Provider "{name}" is exported ({reason}), sets '
                                "grantUriPermissions=true and declares no permission.",
                    impact="Any installed app can obtain URI grants and read or write the "
                           "provider's data.",
                    recommendation="Set android:exported=\"false\", or require a signature-level "
                                   "permission.",
                    cwe="CWE-926", owasp_mobile="M4: Insufficient Input/Output Validation"))
                continue

            if not permission:
                severity = "High" if kind in ("provider", "service") else "Medium"
                detail = f" It handles {', '.join(a.rsplit('.', 1)[-1] for a in actions[:4])}." if actions else ""
                scheme_note = (f" Deep-link schemes: {', '.join(sorted(set(schemes))[:4])}."
                               if schemes else "")
                out.append(SastFinding(
                    title=f"Exported {kind} {short} has no permission protection",
                    severity=severity,
                    vuln_class="PLATFORM-02" if schemes else "PLATFORM-01",
                    file=rel, detector="manifest",
                    description=f'{kind.capitalize()} "{name}" is reachable by any app on the '
                                f"device ({reason}) and declares no permission.{detail}{scheme_note}",
                    impact="Any installed app can invoke this component and whatever it does "
                           "with the data it is handed.",
                    recommendation='Set android:exported="false" if it is internal, or guard it '
                                   "with a signature-level permission and validate all input.",
                    cwe="CWE-926", owasp_mobile="M4: Insufficient Input/Output Validation",
                    extra={"component": name, "component_type": kind,
                           "intent_actions": actions[:8], "schemes": sorted(set(schemes))[:8]}))
            elif not explicit and target_sdk is not None and target_sdk >= 31:
                out.append(SastFinding(
                    title=f"{kind.capitalize()} {short} is missing an explicit android:exported",
                    severity="Low", vuln_class="PLATFORM-01", file=rel, detector="manifest",
                    description=f'"{name}" declares an intent-filter but no android:exported, '
                                f"which targetSdk {target_sdk} requires.",
                    recommendation="Declare android:exported explicitly."))
    return out
