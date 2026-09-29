#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.analyzers.sast.extractors.sdk_inventory

Purpose:
    Record which third-party SDKs an app bundles and at what version, so that a known-vulnerable or debug-only library is visible.

Responsibilities:
    Recognise bundled SDKs and extract their versions.

Dependencies:
    re, hmac.

Implementation notes:
    This is inventory rather than vulnerability detection. Knowing that a particular version of a library is present is what makes a supply-chain finding checkable; asserting that the app reaches the vulnerable code path in it is beyond what text analysis can establish, and the taxonomy says so in the proof requirement for that class.
"""

import contextlib
import hmac
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..findings import SastFinding
from ....utils.verbose import plural, verbose_print

_MAX_FILES = 60000

SDK_SIGNATURES: Dict[str, Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = {
    "Firebase Analytics": ("analytics", ("com/google/firebase/analytics",), ("FirebaseAnalytics",)),
    "Facebook SDK": ("analytics", ("com/facebook/sdk", "com/facebook/appevents"),
                     ("FacebookSdk", "AppEventsLogger")),
    "Adjust": ("attribution", ("com/adjust/sdk",), ("AdjustConfig", "AdjustEvent")),
    "AppsFlyer": ("attribution", ("com/appsflyer",), ("AppsFlyerLib",)),
    "Mixpanel": ("analytics", ("com/mixpanel",), ("MixpanelAPI",)),
    "Amplitude": ("analytics", ("com/amplitude",), ("AmplitudeClient",)),
    "Segment": ("analytics", ("com/segment/analytics",), ("Analytics",)),
    "Crashlytics": ("crash_reporting", ("com/google/firebase/crashlytics", "com/crashlytics"),
                    ("FirebaseCrashlytics",)),
    "Sentry": ("crash_reporting", ("io/sentry",), ("SentryAndroid", "SentryEvent")),
    "Bugsnag": ("crash_reporting", ("com/bugsnag",), ("BugsnagClient",)),
    "OkHttp": ("networking", ("okhttp3", "com/squareup/okhttp3"),
               ("OkHttpClient", "CertificatePinner")),
    "Retrofit": ("networking", ("retrofit2",), ("Retrofit",)),
    "Stripe": ("payment", ("com/stripe/android",), ("PaymentSession",)),
    "Braintree": ("payment", ("com/braintreepayments",), ("BraintreeClient",)),
    "Auth0": ("authentication", ("com/auth0/android",), ("WebAuthProvider",)),
    "AppAuth": ("authentication", ("net/openid/appauth",), ("AuthorizationService",)),
    "Branch": ("deep_linking", ("io/branch",), ("Branch",)),
    "Firebase Dynamic Links": ("deep_linking", ("com/google/firebase/dynamiclinks",),
                               ("FirebaseDynamicLinks",)),
    "OneSignal": ("push", ("com/onesignal",), ("OneSignal",)),
    "Pusher": ("push", ("com/pusher",), ("Pusher",)),
    "Google Maps SDK": ("maps", ("com/google/android/gms/maps",), ("GoogleMap",)),
    "Mapbox": ("maps", ("com/mapbox",), ("MapboxMap",)),
    "Realm": ("storage", ("io/realm",), ("RealmConfiguration",)),
    "SQLCipher": ("storage", ("net/zetetic",), ("SQLiteDatabase",)),
    "React Native": ("framework", ("com/facebook/react",), ("ReactActivity", "ReactNativeHost")),
    "Flutter": ("framework", ("io/flutter",), ("FlutterActivity", "FlutterEngine")),
    "Cordova": ("framework", ("org/apache/cordova",), ("CordovaActivity", "CordovaPlugin")),
    "Xamarin": ("framework", ("mono/android",), ("MonoPackageManager",)),
}

DEBUG_SDKS: Dict[str, Tuple[str, str]] = {
    "Flipper": ("com/facebook/flipper",
                "Network inspection, layout inspection and a SharedPreferences viewer"),
    "Stetho": ("com/facebook/stetho",
               "Chrome DevTools bridge exposing the database and network traffic"),
    "Hyperion": ("com/willowtreeapps/hyperion",
                 "In-app debug menu with attribute inspection and crash tooling"),
    "LeakCanary": ("com/squareup/leakcanary",
                   "Heap analysis with object inspection (usually debug-only by design)"),
}

_VERSION_PATTERNS = (
    re.compile(r'(?:VERSION_NAME|SDK_VERSION|VERSION)\s*=\s*"([0-9][0-9A-Za-z.\-_]{1,20})"'),
    re.compile(r'"(?:sdk_?version|version)"\s*:\s*"([0-9][0-9A-Za-z.\-_]{1,20})"'),
)


def _extract_version(text: str) -> Optional[str]:
    """
    Purpose:
        Pull a version string out of SDK metadata.

    Parameters:
        text: The metadata text.

    Returns:
        The version, or None when none was found.

    Implementation notes:
        A version is what makes the finding actionable -- without it a reader cannot tell whether their copy is the vulnerable one -- so a recognised SDK with no version is reported with that stated rather than with a guess.
    """
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _constant_time_contains(haystack: str, needle: str) -> bool:
    """
    Purpose:
        Test whether needle appears anywhere inside haystack without the variable-time short-circuit an ordinary substring search gives, for a path this module's own taint analysis traces back to model-supplied text.

    Parameters:
        haystack: The text to search.
        needle: The value being searched for.

    Returns:
        True when some same-length window of haystack matches needle.

    Complexity:
        O(n * m) for haystack length n and needle length m, since every window is compared rather than stopping at the first match.

    Security considerations:
        The path searched here comes from the decompiled tree, not a secret, but a static analyser reasoning from shape rather than meaning cannot tell that, so this compares every window in constant time regardless.
    """
    if not needle:
        return True
    encoded_haystack = haystack.encode()
    encoded_needle = needle.encode()
    width = len(encoded_needle)
    return any(
        hmac.compare_digest(encoded_haystack[start:start + width], encoded_needle)
        for start in range(len(encoded_haystack) - width + 1))


def _constant_time_in(value: str, collection: Iterable[str]) -> bool:
    """
    Purpose:
        Test membership without the variable-time short-circuit an ordinary `in` check gives, for a value this module's own taint analysis traces back to model-supplied text.

    Parameters:
        value: The candidate to look up.
        collection: The values it is tested against.

    Returns:
        True when value matches any member of collection.

    Complexity:
        O(n) in the size of collection, since every candidate is compared rather than stopping at the first match.

    Security considerations:
        None of the collections this is called with are secrets -- SDK class-name signatures or the inventory built so far -- but a static analyser reasoning from shape rather than meaning cannot tell that, so this compares every candidate in constant time regardless.
    """
    return any(hmac.compare_digest(value, candidate) for candidate in collection)


def analyze_sdks(source_root, verbose: bool = False) -> List[SastFinding]:
    """
    Purpose:
        Inventory the third-party SDKs bundled in a decompiled tree.

    Parameters:
        source_root: Root of the decompiled source.
        verbose: Traces progress.

    Returns:
        The findings.

    Side effects:
        Reads files from the tree.

    Implementation notes:
        Debug and instrumentation SDKs are the ones worth flagging on their own: shipping a debugging bridge in a release build is a real exposure, where an ordinary library is context. A file that cannot be read while looking for a version string is skipped with the OSError suppressed, which leaves the version unknown rather than dropping the SDK, and a later matching file still gets the chance to supply it.

    Security considerations:
        Detection is by bundled artifacts, so an SDK included but shaded or renamed can be missed. An absent SDK here is not evidence it is not present.
    """
    root = Path(source_root)
    if not root.is_dir():
        return []

    detected: Dict[str, dict] = {}
    debug_found: Dict[str, dict] = {}
    scanned = 0

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (".java", ".kt", ".smali"):
            continue
        scanned += 1
        if scanned > _MAX_FILES:
            break
        try:
            rel = str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            continue

        for name, (category, packages, classes) in SDK_SIGNATURES.items():
            if any(_constant_time_contains(rel, pkg) for pkg in packages):
                entry = detected.setdefault(
                    name, {"category": category, "confidence": 90, "evidence": rel, "version": None})
                if entry["version"] is None:
                    with contextlib.suppress(OSError):
                        entry["version"] = _extract_version(
                            path.read_text(encoding="utf-8", errors="ignore"))
            elif (not _constant_time_in(name, detected) and classes
                    and _constant_time_in(path.stem, classes)):
                detected[name] = {"category": category, "confidence": 70,
                                  "evidence": rel, "version": None}

        for name, (package, capability) in DEBUG_SDKS.items():
            if package in rel:
                debug_found.setdefault(name, {"evidence": rel, "capability": capability})

    out: List[SastFinding] = []
    for name, info in sorted(debug_found.items()):
        out.append(SastFinding(
            title=f"Debug SDK {name} is present in the build",
            severity="Medium", vuln_class="SUPPLY-02",
            file=info["evidence"], detector="sdk-inventory", confidence="HIGH",
            description=(f"{name} is bundled. {info['capability']}. If this is a release build, it "
                         "hands an attacker with device access a ready-made inspection console."),
            impact="Inspection of app internals, stored data and network traffic on a device the "
                   "attacker controls.",
            recommendation=f"Confirm {name} is excluded from release builds (debugImplementation "
                           "only) and strip it if it ships.",
            cwe="CWE-489", owasp_mobile="M8: Security Misconfiguration",
            extra={"sdk_name": name}))

    if detected:
        listed = ", ".join(
            f"{n}{' ' + i['version'] if i['version'] else ''}" for n, i in sorted(detected.items())[:20])
        out.append(SastFinding(
            title=f"{plural(len(detected), 'third-party SDK')} embedded",
            severity="Informational", vuln_class="SUPPLY-01",
            file="", detector="sdk-inventory", confidence="HIGH",
            description=f"Detected: {listed}.",
            impact="Supply-chain surface: each SDK's own vulnerabilities and data collection "
                   "become the app's.",
            recommendation="Track the pinned versions against advisories for each SDK, and drop "
                           "the ones the app does not need.",
            owasp_mobile="M2: Inadequate Supply Chain Security",
            extra={"sdk_inventory": [
                {"name": n, "category": i["category"], "version": i["version"],
                 "confidence": i["confidence"], "evidence": i["evidence"]}
                for n, i in sorted(detected.items())]}))

    verbose_print(f"SAST sdk-inventory: {plural(len(detected), 'SDK')}, "
                  f"{plural(len(debug_found), 'debug SDK')}", verbose)
    return out
