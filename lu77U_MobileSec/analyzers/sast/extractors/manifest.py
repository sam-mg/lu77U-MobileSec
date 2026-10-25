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

import re
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


_COMPONENT_NAME_RE = re.compile(r'"([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)+)"')
_MANIFEST_ANCHORS = (
    ("network security config", "<application"),
    ("backup", "android:allowBackup"), ("backup", "<application"),
    ("targetsdkversion", "targetSdkVersion"), ("minsdkversion", "minSdkVersion"),
    ("debuggable", "android:debuggable"), ("testonly", "android:testOnly"),
    ("taskaffinity", "taskAffinity"), ("cleartext", "usesCleartextTraffic"),
    ("permission", "<uses-permission"),
)


def _attach_lines(findings: List[SastFinding], manifest: Path) -> None:
    """
    Purpose:
        Point manifest findings at the line of the manifest they are about.

    Parameters:
        findings: The manifest findings, updated in place.
        manifest: The decoded manifest file.

    Side effects:
        Sets line and line_end on findings that have none and whose subject is found.

    Implementation notes:
        Every manifest finding used to be reported at line 0, so the report showed no XML for it, while the agent's copy of the same fact showed the element. A finding naming a component (its quoted dotted name) is placed on that component's name; an application-wide one on the attribute it reports, or on the application element when the point is that an attribute is missing. The backup and network notes mention the target SDK, so their anchors are tried before the SDK ones; the backup note once cited targetSdkVersion. The title is searched before the description, since a description mentions other settings in passing: the minSdkVersion note was placed on the application element because its description named the network security config, and the claim gate then refuted it for citing a line without minSdkVersion. Nothing is moved when the subject cannot be found, and a manifest read from the archive has no text to search.
    """
    try:
        lines = manifest.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return

    def first(needle: str) -> int:
        """
        Purpose:
            Find the first manifest line containing a string.

        Parameters:
            needle: The text to look for.

        Returns:
            The 1-based line number, or 0 when absent.
        """
        return next((i for i, line in enumerate(lines, 1) if needle in line), 0)

    for finding in findings:
        if finding.line or Path(finding.file).name != "AndroidManifest.xml":
            continue
        line = 0
        named = _COMPONENT_NAME_RE.search(finding.description or "")
        if named:
            name = named.group(1)
            line = first(f'"{name}"') or first(f'".{name.rsplit(".", 1)[-1]}"')
        for text in (finding.title.lower(), f"{finding.title} {finding.description}".lower()):
            for key, anchor in _MANIFEST_ANCHORS if not line else ():
                if key in text:
                    line = first(anchor)
                    if line:
                        break
        if line:
            finding.line = finding.line_end = line


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
        out += _application_flags(app, rel, target_sdk)
    out += _sdk_findings(target_sdk, min_sdk, rel)
    out += _permission_findings(root, rel)
    if app is not None:
        out += _component_findings(app, rel, target_sdk,
                                   {_attr(el, "name") for el in root.iter("permission")} - {None})
        out += _task_affinity_findings(app, rel, package, min_sdk)
        out += _test_only_findings(app, rel)
        if manifest is not None:
            out += _file_provider_findings(app, manifest.parent / "res", source_root)

    if manifest is not None:
        _attach_lines(out, Path(manifest))
    verbose_print(f"SAST manifest: {plural(len(out), 'finding')} from {manifest}", verbose)
    return out


def _application_flags(app, rel: str, target_sdk: Optional[int] = None) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for the application-level security flags.

    Parameters:
        app: The application element.
        rel: The manifest's path, for the finding location.
        target_sdk: The declared targetSdkVersion, which decides what the platform defaults are.

    Returns:
        The findings.

    Implementation notes:
        The backup note says what backup actually reaches for the declared target: below targetSdkVersion 31, or in a debuggable build, adb backup copies the app's data over USB; from 31, Android 12 and later leave it out of adb backup while cloud backup and device-to-device transfer still carry it - the note used to claim adb extraction for apps targeting 36. The missing-network-config note states the defaults the declared targetSdkVersion actually gets: from 28 cleartext is already off and only system CAs are trusted, so what is missing is pinning; it once said "on API < 28 cleartext is permitted", which is about the target, not the device. Backup, cleartext and debuggable are all reported here, and all three are weak classes the gates later demote or require a chain for. They are emitted as facts because this extractor can see the declaration but not what would be in the backup or what actually travels over HTTP -- the judgement needs context this layer does not have.
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
        state = ("absent, which defaults to true" if allow_backup_raw is None else '"true"')
        rules = _attr(app, "dataExtractionRules") or _attr(app, "fullBackupContent")
        adb_backup = debuggable or target_sdk is None or target_sdk < 31
        if adb_backup:
            reach = ("so `adb backup` copies the app's private data off the device over USB, "
                     "without root.")
            impact = "Any locally stored credentials or PII become extractable over USB."
        else:
            reach = ("so the app's data goes into cloud backups and device-to-device transfers. "
                     f"With targetSdkVersion {target_sdk}, Android 12 and later leave it out of "
                     "`adb backup`, so USB extraction needs a device older than Android 12.")
            impact = ("Locally stored credentials or PII travel with the user's cloud backup and to a "
                      "new device, and are extractable over USB on devices older than Android 12.")
        if rules:
            reach += " Backup rules are declared; what they exclude decides what is copied."
        out.append(SastFinding(
            title="Application data is backup-enabled",
            severity="Medium", vuln_class="STORAGE-04", file=rel,
            detector="manifest", confidence="HIGH",
            description=f"android:allowBackup is {state}, {reach}",
            impact=impact,
            recommendation='Set android:allowBackup="false", or exclude sensitive files '
                           "with android:dataExtractionRules (android:fullBackupContent below Android 12).",
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
            description=("The app declares neither android:networkSecurityConfig nor "
                         "usesCleartextTraffic, so it relies on platform defaults and pins no domain. "
                         + ("With targetSdkVersion %d those defaults block cleartext HTTP and trust "
                            "only system CAs." % target_sdk if target_sdk is not None and target_sdk >= 28
                            else "With targetSdkVersion %s those defaults still permit cleartext HTTP "
                                 "(see the cleartext finding)." % (target_sdk if target_sdk is not None
                                                                   else "unset"))),
            impact="Without pinning, anyone who gets a CA trusted on the device can read and alter "
                   "the app's TLS traffic.",
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
                severity="Medium", vuln_class="NETWORK-05", file=rel, detector="manifest",
                description=f"Below API 24 the app trusts the user CA store, so a user-installed "
                            "certificate can intercept HTTPS. The attacker first has to get a CA "
                            "installed on the victim's device, which is why this is not graded as a "
                            "trust-all TLS bypass.",
                cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
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


_WEAK_LEVELS = {
    "normal": ("Medium", "any installed app that asks for it in its manifest is granted it at install, "
                         "without the user being asked."),
    "dangerous": ("Low", "any installed app can request it, and gets it once the user accepts one "
                         "permission prompt (at install time on Android 5.1 and lower)."),
}


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
        A requested permission describes what the app could do with a vulnerability, not that it has one, so these are inventory rather than defects. They earn their place by widening the impact of another finding, which is what the chaining stage uses them for. A custom permission the app declares is different: it guards the app's own components, and only signature level keeps other apps out. A normal one is handed to any app that lists it, so it is Medium; a dangerous one also needs the user to accept a prompt, so it is Low. Both used to be Medium with the normal level's wording, which told a reader a dangerous-level permission was granted to any app without the user being asked.
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
        if level in _WEAK_LEVELS:
            severity, granted = _WEAK_LEVELS[level]
            out.append(SastFinding(
                title=f"Custom permission {name.rsplit('.', 1)[-1]} is weakly protected",
                severity=severity, vuln_class="PLATFORM-01", file=rel, detector="manifest",
                description=f'Custom permission "{name}" uses protectionLevel="{level}": {granted}',
                recommendation='Use protectionLevel="signature" for permissions guarding '
                               "internal components.",
                cwe="CWE-280", owasp_mobile="M3: Insecure Authentication/Authorization"))
    return out


def _test_only_findings(app, rel: str) -> List[SastFinding]:
    """
    Purpose:
        Emit a finding when the application is marked as a test-only build.

    Parameters:
        app: The application element.
        rel: The manifest's path.

    Returns:
        The finding, or nothing.

    Implementation notes:
        android:testOnly is set by tooling for builds installed from an IDE; an APK carrying it was not built for release, which usually means debug endpoints and checks are still in it. It is filed with the other build-process notes.
    """
    if str(_attr(app, "testOnly", "false")).lower() != "true":
        return []
    return [SastFinding(
        title="Application is marked as a test-only build (android:testOnly)",
        severity="Medium", vuln_class="BUILD-01", file=rel, detector="manifest",
        description=('android:testOnly="true" is set, which IDE tooling adds to builds meant for local '
                     "testing; such a build was not produced by the release pipeline."),
        impact=("Test builds commonly keep debug endpoints, verbose logging and relaxed checks, and the flag "
                "itself shows the APK did not come from a release build."),
        recommendation="Ship APKs built by the release task, which never sets testOnly.",
        cwe="CWE-489", owasp_mobile="M8: Security Misconfiguration")]


_PROVIDER_PATHS_META = "android.support.FILE_PROVIDER_PATHS"
_WHOLE_DIR_PATHS = ("", ".", "/", "./")


def _file_provider_findings(app, res_dir: Path, source_root) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for FileProvider path files that share far more than the app means to.

    Parameters:
        app: The application element.
        res_dir: The decoded resources directory beside the manifest.
        source_root: Root of the decompiled source, for the finding's relative path.

    Returns:
        The findings.

    Implementation notes:
        A FileProvider can only hand out what its paths file allows. A root-path entry allows every file on the device the app can read -- its own databases and preferences included -- so one URI built from attacker-influenced input, or granted too broadly, exposes any of them. A files-path or cache-path entry with an empty or "." path shares the whole directory rather than a subfolder. The paths file is read from the decoded resources; a manifest recovered straight from the APK has no such tree beside it, and nothing is reported.
    """
    out: List[SastFinding] = []
    for provider in app.findall("provider"):
        for meta in provider.findall("meta-data"):
            if _attr(meta, "name") != _PROVIDER_PATHS_META:
                continue
            resource = str(_attr(meta, "resource") or "")
            if not resource.startswith("@xml/"):
                continue
            paths_file = res_dir / "xml" / f"{resource[len('@xml/'):]}.xml"
            try:
                paths = ElementTree.parse(paths_file).getroot()
            except (ElementTree.ParseError, OSError):
                continue
            try:
                rel = paths_file.relative_to(Path(source_root)).as_posix()
            except ValueError:
                rel = paths_file.name
            provider_name = str(_attr(provider, "name") or "FileProvider").rsplit(".", 1)[-1]
            for entry in paths:
                tag = entry.tag
                path_value = str(entry.get("path", "")).strip()
                if tag == "root-path":
                    out.append(SastFinding(
                        title=f"{provider_name} shares the entire filesystem (root-path)",
                        severity="Medium", vuln_class="PLATFORM-11", file=rel, detector="manifest",
                        description=(f"The {provider_name} paths file declares a root-path, so a content URI "
                                     "from this provider can name any file the app can read."),
                        impact=("Wherever the app builds a URI from a path an attacker influences, or grants "
                                "one too broadly, the app's own databases and shared preferences go with it."),
                        recommendation=("Replace root-path with files-path or cache-path entries naming the "
                                        "specific subdirectories the app shares."),
                        cwe="CWE-22", owasp_mobile="M8: Security Misconfiguration"))
                elif tag in ("files-path", "cache-path") and path_value in _WHOLE_DIR_PATHS:
                    out.append(SastFinding(
                        title=f"{provider_name} shares the whole {tag.split('-')[0]} directory",
                        severity="Low", vuln_class="PLATFORM-11", file=rel, detector="manifest",
                        description=(f'A {tag} entry with path="{path_value}" shares the whole directory '
                                     "rather than a subfolder created for sharing."),
                        impact="Any file the app keeps there can be named by a URI from this provider.",
                        recommendation="Point the entry at a dedicated subdirectory that holds only shareable files.",
                        cwe="CWE-22", owasp_mobile="M8: Security Misconfiguration"))
    return out


STRANDHOGG_FIXED_SDK = 30


def _task_affinity_findings(app, rel: str, package: str, min_sdk: Optional[int] = None) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for task affinities that allow task hijacking.

    Parameters:
        app: The application element.
        rel: The manifest's path.
        package: The app's package, for comparison.
        min_sdk: The declared minSdkVersion, or None when it is not declared.

    Returns:
        The findings.

    Implementation notes:
        A foreign affinity on an activity lets another app declaring the same value take it into its task, and it matters far more for a login screen than for a settings page, which is why the finding names the activity. The default affinity, the package name, is what the StrandHogg attack claims: another app gives one of its activities this app's package as its affinity and lands in this app's task. Android 11 (API 30) fixed that in the OS, so the note is raised only when minSdkVersion lets the app run below it and the application has not set an empty affinity, the configuration that partly mitigates the original attack. It is Informational because the fix is the platform's and the app can only reduce it. Two Ghera benchmarks (a launcher activity phished, and phishing and denial of service through reparenting) plant exactly this default; the app-level recommendation used to advise leaving the affinity unset, which is that default.
    """
    out: List[SastFinding] = []
    app_affinity = _attr(app, "taskAffinity")
    if app_affinity != "" and (min_sdk is None or min_sdk < STRANDHOGG_FIXED_SDK):
        shown = f'"{app_affinity}"' if app_affinity else f'its package name "{package}"'
        out.append(SastFinding(
            title="Task hijacking (StrandHogg) possible on Android 10 and lower",
            severity="Informational", vuln_class="PLATFORM-09", file=rel,
            detector="manifest",
            description=f"minSdkVersion {min_sdk if min_sdk is not None else '(not declared)'} lets the app run "
                        f"on Android versions before 11, and its task affinity is {shown}. There, another "
                        "app can declare the same affinity, with allowTaskReparenting, and have its own "
                        "activity shown in this app's task.",
            impact="On a device running Android 10 or lower, a malicious app can put a look-alike "
                   "screen on top of this app's task, phishing credentials or keeping the real app "
                   "from being shown.",
            recommendation='Raise minSdkVersion to 30, where Android fixed this. Until then, '
                           'android:taskAffinity="" on the <application> mitigates the original '
                           'attack, though not its runtime variant on unpatched Android 9 and lower.',
            cwe="CWE-1021", owasp_mobile="M4: Insufficient Input/Output Validation"))
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
            recommendation='Set android:taskAffinity="" so no other app can declare the same task; '
                           'removing the attribute falls back to the package name, which other apps '
                           'can still claim on Android 10 and lower.',
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


_MAIN_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATEGORIES = ("android.intent.category.LAUNCHER", "android.intent.category.LEANBACK_LAUNCHER")


def _is_launcher_only(el, actions: List[str], schemes: List[str]) -> bool:
    """
    Purpose:
        Recognise an activity whose only reason to be exported is being the app's launcher entry.

    Parameters:
        el: The activity element.
        actions: The intent-filter actions it declares.
        schemes: The data schemes it declares.

    Returns:
        True when every action is MAIN, a launcher category is present, and no data scheme is declared.

    Implementation notes:
        A launcher activity that also declares a VIEW filter or a scheme is a deep-link target and is not launcher-only; neither is one with any other action, since that action is an entry point another app can aim at.
    """
    if not actions or schemes or any(action != _MAIN_ACTION for action in actions):
        return False
    categories = {c.get(_ANDROID + "name", "") for c in el.iter("category")}
    return any(category in categories for category in _LAUNCHER_CATEGORIES)


_VIEW_ACTION = "android.intent.action.VIEW"
_BROWSABLE = "android.intent.category.BROWSABLE"


def _is_browsable_link_entry(el, actions: List[str], schemes: List[str]) -> bool:
    """
    Purpose:
        Recognise an activity whose only external entry is a browsable deep link, besides possibly being the launcher.

    Parameters:
        el: The activity element.
        actions: The intent-filter actions it declares.
        schemes: The data schemes it declares.

    Returns:
        True when it declares a scheme, is BROWSABLE, and handles nothing but VIEW and MAIN.

    Implementation notes:
        Such an activity is public by design - a link from a web page has to reach it - so "no permission protection" describes nothing the developer could change. Any other action is an entry point another app can aim at, and keeps the ordinary finding.
    """
    if not schemes or any(action not in (_VIEW_ACTION, _MAIN_ACTION) for action in actions):
        return False
    return any(c.get(_ANDROID + "name", "") == _BROWSABLE for c in el.iter("category"))


_PLATFORM_PERMISSION_PREFIXES = ("android.", "com.android.", "com.google.android.")


def _component_findings(app, rel: str, target_sdk: Optional[int],
                        declared: Optional[set] = None) -> List[SastFinding]:
    """
    Purpose:
        Emit findings for exported components lacking a permission guard.

    Parameters:
        app: The application element.
        rel: The manifest's path.
        target_sdk: The declared target SDK.
        declared: The custom permissions this manifest declares; None skips the check that a guard is declared.

    Returns:
        The findings.

    Implementation notes:
        Export is decided by the explicit rule rather than by the attribute alone, and a component guarded by a permission is not reported -- the guard is the mitigation, provided the permission exists. One the app names but never declares, and the platform does not define, is no guard: whichever app declares it first owns it, so any app can declare it at normal level and hold it. Two of Ghera's fixed apps guard their component with a permission one name off the one they declare, and that is reported as a separate finding, keyed apart from the missing-permission one. The finding records how export was established, so a reader can tell a deliberate export from one the platform default created. An activity reachable only as the launcher entry is not reported: every app has one, it is exported so the home screen can start it, and a finding on it was the commonest noise item in benchmark reports. What such an activity does with its Intent is still examined by the agent and the review pass, which is where a real flaw in it would show. An activity reached only through BROWSABLE VIEW links (and possibly as the launcher) is listed as an Informational deep-link entry instead of a missing-permission finding, for the same reason: it is public by design, and the flaw, if any, is in its handler.

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
                    cwe="CWE-926", owasp_mobile="M8: Security Misconfiguration"))
                continue

            if not permission and kind == "activity" and _is_launcher_only(el, actions, schemes):
                continue

            if not permission and kind == "activity" and _is_browsable_link_entry(el, actions, schemes):
                out.append(SastFinding(
                    title=f"Activity {short} receives deep links ({', '.join(sorted(set(schemes))[:4])})",
                    severity="Informational", vuln_class="PLATFORM-02", file=rel, detector="manifest",
                    description=(f'Activity "{name}" accepts BROWSABLE VIEW links, so any web page, '
                                 "message or QR code can open it with a URL of its choosing. That is its "
                                 "purpose and no permission can guard it; whether it is a vulnerability "
                                 "depends on what its handler does with the link."),
                    impact="An entry point every remote attacker can reach with one tap from the victim.",
                    recommendation=("Treat every value in the link as untrusted, and require the user to "
                                    "confirm before the link changes data or starts a payment."),
                    cwe="CWE-939", owasp_mobile="M4: Insufficient Input/Output Validation",
                    extra={"component": name, "component_type": kind,
                           "intent_actions": actions[:8], "schemes": sorted(set(schemes))[:8]}))
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
                    cwe="CWE-926", owasp_mobile="M8: Security Misconfiguration",
                    extra={"component": name, "component_type": kind, "fact_key": f"exported:{name}",
                           "intent_actions": actions[:8], "schemes": sorted(set(schemes))[:8]}))
            elif not explicit and target_sdk is not None and target_sdk >= 31:
                out.append(SastFinding(
                    title=f"{kind.capitalize()} {short} is missing an explicit android:exported",
                    severity="Low", vuln_class="PLATFORM-01", file=rel, detector="manifest",
                    description=f'"{name}" declares an intent-filter but no android:exported, '
                                f"which targetSdk {target_sdk} requires.",
                    recommendation="Declare android:exported explicitly."))
            guards = [g for g in (_attr(el, "permission"), _attr(el, "readPermission"),
                                  _attr(el, "writePermission")) if g]
            for guard in dict.fromkeys(guards) if declared is not None else ():
                if guard in declared or guard.startswith(_PLATFORM_PERMISSION_PREFIXES):
                    continue
                out.append(SastFinding(
                    title=f"Exported {kind} {short} is guarded by a permission the app never declares",
                    severity="High" if kind in ("provider", "service") else "Medium",
                    vuln_class="PLATFORM-01", file=rel, detector="manifest",
                    description=(f'{kind.capitalize()} "{name}" is reachable by other apps ({reason}) and '
                                 f'requires "{guard}", but this manifest declares no such permission. '
                                 "Whichever installed app declares a permission first owns it, so any app "
                                 f'can declare "{guard}" itself and be granted it, and the guard stops nothing.'),
                    impact="Any installed app can invoke this component, as if it had no permission at all.",
                    recommendation=('Declare the permission in this manifest with protectionLevel="signature", '
                                    "or guard the component with one the app already declares."),
                    cwe="CWE-926", owasp_mobile="M8: Security Misconfiguration",
                    extra={"component": name, "component_type": kind, "permission": guard,
                           "fact_key": f"undeclared-guard:{name}:{guard}"}))
    return out


def app_code_packages(source_root) -> List[str]:
    """
    Purpose:
        Name the Java packages that hold the app's own platform code.

    Parameters:
        source_root: Root of the decompiled source.

    Returns:
        The manifest package, then the package of each launcher activity when it differs; empty when no manifest can be read.

    Implementation notes:
        The launcher activity is always the app's own class, and its package is the one place a namespace that differs from the application ID shows up, so both are taken. Other components are not used, since plugins declare their own activities and services in the merged manifest.
    """
    manifest = find_manifest(source_root)
    if manifest is None:
        return []
    try:
        root = ElementTree.parse(manifest).getroot()
    except (ElementTree.ParseError, OSError):
        return []
    package = root.get("package") or ""
    packages = [package] if package else []
    app = root.find("application")
    for el in (app.iter("activity") if app is not None else []):
        categories = {c.get(_ANDROID + "name", "") for c in el.iter("category")}
        if not any(category in categories for category in _LAUNCHER_CATEGORIES):
            continue
        name = _attr(el, "name") or ""
        if name.startswith("."):
            name = package + name
        owner = name.rsplit(".", 1)[0] if "." in name else ""
        if owner and owner not in packages:
            packages.append(owner)
    return packages


def summarise_manifest(manifest_path, max_components: int = 10) -> List[str]:
    """
    Purpose:
        Describe a manifest in a few lines: the app's flags and its externally reachable components.

    Parameters:
        manifest_path: The decoded AndroidManifest.xml.
        max_components: How many exported components to list.

    Returns:
        The summary lines, or an empty list when the manifest cannot be read.

    Side effects:
        Reads and parses the manifest.

    Implementation notes:
        Used for the Flutter overview, whose opening context replaces the manifest summary a Java scan gets; without it an agent spent its first steps grepping the manifest one attribute at a time. Export status comes from _determine_exported, so this summary and the manifest findings never disagree about what is reachable. Each component carries its intent-filter actions and data schemes, because a scheme is a deep link and that is the usual way into a Flutter app from outside.
    """
    try:
        root = ElementTree.parse(manifest_path).getroot()
    except (ElementTree.ParseError, OSError):
        return []
    app = root.find("application")
    uses_sdk = root.find("uses-sdk")
    target_sdk = _int_or_none(_attr(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None
    flags = [f"package {root.get('package') or '?'}"]
    if target_sdk is not None:
        flags.append(f"targetSdk {target_sdk}")
    if app is not None:
        flags.append(f"debuggable={_attr(app, 'debuggable', 'false')}")
        flags.append(f"allowBackup={_attr(app, 'allowBackup', 'true (default)')}")
    lines = ["Manifest: " + ", ".join(flags)]
    exported = []
    for el in (list(app) if app is not None else []):
        kind = _COMPONENT_TAGS.get(el.tag)
        if not kind:
            continue
        is_exported, _explicit, _reason = _determine_exported(el, target_sdk)
        if not is_exported:
            continue
        actions = sorted({_attr(a, "name", "") for f in el.findall("intent-filter")
                          for a in f.findall("action")} - {""})
        schemes = sorted({_attr(d, "scheme", "") for f in el.findall("intent-filter")
                          for d in f.findall("data")} - {""})
        detail = ""
        if actions:
            detail += " actions: " + ", ".join(a.rsplit(".", 1)[-1] for a in actions[:3])
        if schemes:
            detail += " schemes: " + ", ".join(schemes[:3])
        permission = _attr(el, "permission")
        if permission:
            detail += f" (permission {permission})"
        exported.append(f"  exported {kind} {_attr(el, 'name', '?')}{detail}")
    if exported:
        lines += exported[:max_components]
        if len(exported) > max_components:
            lines.append(f"  ... (+{len(exported) - max_components} more exported components)")
    else:
        lines.append("  no exported components")
    return lines
